//! The sans-io datapath core. It owns flow state and policy decisions; it owns
//! no socket, no clock, and no task. Time enters as an `Instant` argument,
//! packets as borrowed slices, and transmission as an owned value polled out.
//!
//! Invalid states excluded by construction:
//! - a fragment never yields a flow action; reassembled datagrams are re-parsed
//!   from scratch before planning, so a flow's plan always derives from a whole
//!   packet's real header;
//! - a flow exists only after `plan_flow` has succeeded, so `FlowState.plan`
//!   is always a valid plan for the current configuration;
//! - per-flow datagram buffers are bounded at flow creation and `send_datagram`
//!   drops rather than waits.

use std::{collections::VecDeque, num::NonZeroUsize, time::Instant};

use crate::{
    DatagramBuffer, EgressCapabilities, FilterPolicy, FlowPlan, FlowTableError, Fragment,
    IngressAction, IngressPacket, InternalEndpoint, Mtu, PacketError, PlanError, PushOutcome,
    Reassembler, Replan, SendOutcome, SteeringReason, Transport, TransportPath, UdpFlowTable,
    clamp_mss, plan_flow, replan, route_ingress,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transmit {
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowEvent {
    StreamOpened(InternalEndpoint),
    DatagramOpened(InternalEndpoint),
    DatagramDropped(InternalEndpoint),
    ReassemblyDiscarded,
    Resteered(SteeringReason),
    FlowTornDown(InternalEndpoint),
}

#[derive(Debug, PartialEq, Eq)]
pub enum DatapathError {
    Malformed(PacketError),
    Plan(PlanError),
    FlowTable(FlowTableError),
}

impl std::fmt::Display for DatapathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(error) => write!(f, "malformed packet: {error}"),
            Self::Plan(error) => write!(f, "planning failed: {error}"),
            Self::FlowTable(error) => write!(f, "flow table rejected the configuration: {error}"),
        }
    }
}

impl std::error::Error for DatapathError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Malformed(error) => Some(error),
            Self::Plan(error) => Some(error),
            Self::FlowTable(error) => Some(error),
        }
    }
}

impl From<PacketError> for DatapathError {
    fn from(error: PacketError) -> Self {
        Self::Malformed(error)
    }
}

impl From<PlanError> for DatapathError {
    fn from(error: PlanError) -> Self {
        Self::Plan(error)
    }
}

impl From<FlowTableError> for DatapathError {
    fn from(error: FlowTableError) -> Self {
        Self::FlowTable(error)
    }
}

struct FlowState {
    plan: FlowPlan,
    // ponytail: owned `Vec<u8>` datagrams, not pooled slices. The buffers are
    // never drained today, so refcounted pool handles have no consumer; add
    // the shared pool with the first drain path (P8's runtime shell).
    buffer: DatagramBuffer<Vec<u8>>,
}

pub struct Datapath {
    filter: FilterPolicy,
    egress: EgressCapabilities,
    path_mtu: Mtu,
    datagram_buffer_capacity: NonZeroUsize,
    reassembler: Reassembler,
    flows: UdpFlowTable<FlowState>,
    events: VecDeque<FlowEvent>,
    transmits: VecDeque<Transmit>,
}

impl Datapath {
    pub fn new(
        filter: FilterPolicy,
        egress: EgressCapabilities,
        path_mtu: Mtu,
        reassembly_timeout: std::time::Duration,
        max_pending_reassemblies: NonZeroUsize,
        flow_idle_timeout: std::time::Duration,
        datagram_buffer_capacity: NonZeroUsize,
    ) -> Result<Self, DatapathError> {
        Ok(Self {
            filter,
            egress,
            path_mtu,
            datagram_buffer_capacity,
            reassembler: Reassembler::new(reassembly_timeout, max_pending_reassemblies),
            flows: UdpFlowTable::new(flow_idle_timeout, Instant::now())?,
            events: VecDeque::new(),
            transmits: VecDeque::new(),
        })
    }

    pub fn on_tun_packet(&mut self, buf: &[u8], now: Instant) -> Result<(), DatapathError> {
        let packet = IngressPacket::parse(buf)?;
        self.dispatch(packet, buf, now)
    }

    pub fn on_egress_packet(&mut self, buf: &[u8], now: Instant) -> Result<(), DatapathError> {
        let packet = IngressPacket::parse(buf)?;
        // Fragments arriving from the egress side are pathological: the peer's
        // stack reassembles before we do, so anything still fragmented here
        // cannot match a flow.
        if packet.transport == Transport::Fragment {
            self.events.push_back(FlowEvent::ReassemblyDiscarded);
            return Ok(());
        }
        self.dispatch(packet, buf, now)
    }

    fn dispatch(
        &mut self,
        packet: IngressPacket,
        buf: &[u8],
        now: Instant,
    ) -> Result<(), DatapathError> {
        match route_ingress(packet, self.filter, self.egress, self.path_mtu)? {
            IngressAction::Reassemble => self.on_fragment(buf, now),
            IngressAction::ForwardPacket(plan) => {
                let mut bytes = buf.to_vec();
                if let TransportPath::PacketFastPath { inner_mtu } = plan.transport {
                    // The clamp is the only mechanism that reaches a terminated
                    // path's segment size; on non-SYN packets it is a no-op.
                    let _ = clamp_mss(&mut bytes, inner_mtu);
                }
                self.transmits.push_back(Transmit { bytes });
                Ok(())
            }
            IngressAction::OpenStream(plan) => {
                let endpoint = endpoint_of(packet);
                if self.open_flow(endpoint, plan, now)? {
                    self.events.push_back(FlowEvent::StreamOpened(endpoint));
                }
                Ok(())
            }
            IngressAction::OpenDatagram(plan) => {
                let endpoint = endpoint_of(packet);
                if self.open_flow(endpoint, plan, now)? {
                    self.events.push_back(FlowEvent::DatagramOpened(endpoint));
                }
                Ok(())
            }
            IngressAction::HandleIcmp(_) => {
                // PTB generation toward the client is deferred to the effect
                // shell; the packet itself is forwarded unchanged.
                self.transmits.push_back(Transmit {
                    bytes: buf.to_vec(),
                });
                Ok(())
            }
            IngressAction::DropUnsupported => Ok(()),
        }
    }

    fn on_fragment(&mut self, buf: &[u8], now: Instant) -> Result<(), DatapathError> {
        let Some(fragment) = Fragment::parse(buf)? else {
            return Ok(());
        };
        match self.reassembler.push(fragment, now) {
            PushOutcome::Pending => Ok(()),
            PushOutcome::Discarded => {
                self.events.push_back(FlowEvent::ReassemblyDiscarded);
                Ok(())
            }
            PushOutcome::Complete(datagram) => {
                // A completed datagram re-enters dispatch as a fresh packet: a
                // flow is planned from its real header, never admitted from the
                // fragment boundary alone.
                let packet = IngressPacket::parse(&datagram)?;
                self.dispatch(packet, &datagram, now)
            }
        }
    }

    /// Returns whether the flow was newly created. Refreshes of a live flow
    /// are silent: an open event per packet would make the event stream
    /// O(packets), which is the defect P7 exists to remove.
    fn open_flow(
        &mut self,
        endpoint: InternalEndpoint,
        plan: FlowPlan,
        now: Instant,
    ) -> Result<bool, DatapathError> {
        let existed = self.flows.contains(&endpoint);
        let capacity = self.datagram_buffer_capacity;
        self.flows.get_or_insert_with(endpoint, now, || FlowState {
            plan,
            buffer: DatagramBuffer::new(capacity),
        })?;
        Ok(!existed)
    }

    pub fn send_datagram(
        &mut self,
        endpoint: InternalEndpoint,
        datagram: Vec<u8>,
        now: Instant,
    ) -> Result<SendOutcome, DatapathError> {
        let capacity = self.datagram_buffer_capacity;
        let flow = self.flows.get_or_insert_with(endpoint, now, || FlowState {
            plan: plan_flow(self.filter, self.egress, self.path_mtu)
                .expect("the configured plan was validated at construction"),
            buffer: DatagramBuffer::new(capacity),
        })?;
        let outcome = flow.buffer.try_send(datagram);
        if outcome == SendOutcome::Dropped {
            self.events.push_back(FlowEvent::DatagramDropped(endpoint));
        }
        Ok(outcome)
    }

    /// Re-plans every live flow after the egress reports a capability change.
    pub fn on_capability_change(&mut self, next: EgressCapabilities) {
        self.egress = next;
        let mut events = Vec::new();
        self.flows.retain(|endpoint, state| {
            match replan(&state.plan, self.filter, next, self.path_mtu) {
                Ok(Replan::Unchanged) => true,
                Ok(Replan::Resteer(reason)) => {
                    // A survivable replan re-plans cleanly by definition.
                    if let Ok(plan) = plan_flow(self.filter, next, self.path_mtu) {
                        state.plan = plan;
                    }
                    events.push(FlowEvent::Resteered(reason));
                    true
                }
                Ok(Replan::Teardown) | Err(_) => {
                    events.push(FlowEvent::FlowTornDown(*endpoint));
                    false
                }
            }
        });
        self.events.extend(events);
    }

    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.transmits.pop_front()
    }

    pub fn poll_event(&mut self) -> Option<FlowEvent> {
        self.events.pop_front()
    }

    pub fn on_timeout(&mut self, now: Instant) {
        let _ = self.reassembler.expire(now);
        let _ = self.flows.expire(now);
    }
}

fn endpoint_of(packet: IngressPacket) -> InternalEndpoint {
    InternalEndpoint {
        address: packet.source,
        port: match packet.transport {
            Transport::Tcp { source_port, .. } | Transport::Udp { source_port, .. } => source_port,
            Transport::Icmp | Transport::Other | Transport::Fragment => 0,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::Duration,
    };

    fn egress(fidelity: crate::DatagramFidelity) -> EgressCapabilities {
        EgressCapabilities {
            accepts: crate::Accepts::Flows,
            datagram_fidelity: fidelity,
            overhead_bytes: 60,
            max_datagram_size: Some(1500),
            preserves_ecn: true,
            nat_behavior: crate::NatBehavior::EndpointIndependent,
        }
    }

    fn datapath(fidelity: crate::DatagramFidelity) -> Datapath {
        Datapath::new(
            FilterPolicy::PassThrough,
            egress(fidelity),
            Mtu::new(1500).unwrap(),
            Duration::from_secs(30),
            NonZeroUsize::new(8).unwrap(),
            Duration::from_secs(120),
            NonZeroUsize::new(64).unwrap(),
        )
        .unwrap()
    }

    fn udp_packet() -> [u8; 28] {
        [
            0x45, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2, 0x04,
            0xd2, 0x00, 0x35, 0x00, 0x08, 0, 0,
        ]
    }

    #[test]
    fn fragment_quarantine_then_reassembled_admission() {
        let mut path = datapath(crate::DatagramFidelity::Native);
        let now = Instant::now();

        // A lone fragment is quarantined and produces no flow event.
        let mut first = udp_packet();
        first[6] = 0x20; // more fragments, offset 0
        path.on_tun_packet(&first, now).unwrap();
        assert_eq!(path.poll_event(), None);

        // A complete datagram opens a datagram flow exactly once.
        path.on_tun_packet(&udp_packet(), now).unwrap();
        assert_eq!(
            path.poll_event(),
            Some(FlowEvent::DatagramOpened(InternalEndpoint {
                address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                port: 1234,
            }))
        );
        assert_eq!(path.poll_event(), None);
    }

    #[test]
    fn fidelity_downgrade_resteers_without_dropping_flows() {
        let mut path = datapath(crate::DatagramFidelity::Native);
        let now = Instant::now();
        path.on_tun_packet(&udp_packet(), now).unwrap();
        assert!(matches!(
            path.poll_event(),
            Some(FlowEvent::DatagramOpened(_))
        ));

        // MASQUE's QUIC-to-HTTP/2 fallback: fidelity drops, the flow lives.
        path.on_capability_change(egress(crate::DatagramFidelity::Emulated));
        assert_eq!(
            path.poll_event(),
            Some(FlowEvent::Resteered(SteeringReason::DatagramFidelity))
        );
        assert_eq!(path.poll_event(), None);

        // The flow still answers traffic: its buffer still exists.
        let endpoint = InternalEndpoint {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            port: 1234,
        };
        assert_eq!(
            path.send_datagram(endpoint, vec![1], now),
            Ok(SendOutcome::Buffered)
        );
    }

    #[test]
    fn layer_loss_tears_down_flows() {
        // Open a flow, then the egress stops accepting the flow's layer.
        let now = Instant::now();
        let mut path = datapath(crate::DatagramFidelity::Native);
        path.on_tun_packet(&udp_packet(), now).unwrap();
        let _ = path.poll_event();

        let mut packets_only = egress(crate::DatagramFidelity::Native);
        packets_only.accepts = crate::Accepts::IpPackets;
        path.on_capability_change(packets_only);
        assert!(matches!(
            path.poll_event(),
            Some(FlowEvent::FlowTornDown(_))
        ));
    }

    #[test]
    fn egress_fragments_are_pathological_and_dropped() {
        let mut path = datapath(crate::DatagramFidelity::Native);
        let now = Instant::now();
        let mut fragment = udp_packet();
        fragment[6] = 0x20;
        path.on_egress_packet(&fragment, now).unwrap();
        assert_eq!(path.poll_event(), Some(FlowEvent::ReassemblyDiscarded));
    }

    #[test]
    fn timeout_expires_flow_state() {
        let mut path = datapath(crate::DatagramFidelity::Native);
        let now = Instant::now();
        path.on_tun_packet(&udp_packet(), now).unwrap();
        let _ = path.poll_event();

        path.on_timeout(now + Duration::from_secs(121));
        let endpoint = InternalEndpoint {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            port: 1234,
        };
        // The flow is gone; a fresh send re-creates it and emits a new event.
        assert!(path.flows.is_empty());
        let _ = path.send_datagram(endpoint, vec![1], now + Duration::from_secs(122));
    }
}
