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
//!   drops rather than waits;
//! - the configuration is planned once at construction, so `FlowPlan` derivation
//!   for a flow the core creates itself is total rather than optimistic.

use std::{collections::VecDeque, num::NonZeroUsize, time::Instant};

use crate::{
    DatagramBuffer, EgressCapabilities, FilterPolicy, FlowPlan, FlowTableError, Fragment,
    IngressAction, IngressPacket, InternalEndpoint, Mtu, PacketError, PlanError, Pooled,
    PushOutcome, Reassembler, Replan, SendOutcome, SteeringReason, Transport, TransportPath,
    UdpFlowTable, clamp_mss, plan_flow, replan, route_ingress,
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
    /// Payload bytes live in the shared `BufferPool`, so queue memory is one
    /// global budget rather than `flows x depth x MTU`. The per-flow capacity
    /// remains the fairness bound: no single flow can spend the whole pool.
    ///
    /// ponytail: nothing consumes these yet. The egress that drains them is
    /// P10; until then an idle queue is reclaimed when its flow expires, and
    /// the pool's budget is what keeps that bounded.
    buffer: DatagramBuffer<Pooled>,
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
        // Parse, do not validate: a `Datapath` exists only for a configuration
        // that plans. Every later `plan_flow` on this configuration is then a
        // proof-carrying repeat rather than a fresh gamble.
        plan_flow(filter, egress, path_mtu)?;

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

    /// Queues a datagram for `endpoint`, creating the flow when the producer
    /// is the first to name it. Never waits: a full per-flow queue is a drop,
    /// and dropping the `Pooled` handle returns its bytes to the pool.
    pub fn send_datagram(
        &mut self,
        endpoint: InternalEndpoint,
        datagram: Pooled,
        now: Instant,
    ) -> Result<SendOutcome, DatapathError> {
        // Planned before the closure so a configuration the current egress
        // cannot serve surfaces as `DatapathError::Plan`, never as a panic.
        let plan = plan_flow(self.filter, self.egress, self.path_mtu)?;
        let capacity = self.datagram_buffer_capacity;
        let flow = self.flows.get_or_insert_with(endpoint, now, || FlowState {
            plan,
            buffer: DatagramBuffer::new(capacity),
        })?;
        let outcome = flow.buffer.try_send(datagram);
        if outcome == SendOutcome::Dropped {
            self.events.push_back(FlowEvent::DatagramDropped(endpoint));
        }
        Ok(outcome)
    }

    /// Re-plans every live flow after the egress reports a capability change.
    ///
    /// O(live flows), one `replan` per flow and no intermediate event buffer:
    /// destructuring `self` borrows the flow table and the event queue as the
    /// disjoint fields they are, which matters at the 10,000-flow target.
    pub fn on_capability_change(&mut self, next: EgressCapabilities) {
        self.egress = next;
        let Self {
            filter,
            path_mtu,
            flows,
            events,
            ..
        } = self;
        let (filter, path_mtu) = (*filter, *path_mtu);

        flows.retain(
            |endpoint, state| match replan(&state.plan, filter, next, path_mtu) {
                Ok(Replan::Unchanged) => true,
                // The replacement plan travels with the verdict, so a resteered
                // flow cannot end up running on its stale plan.
                Ok(Replan::Resteer { reason, plan }) => {
                    state.plan = plan;
                    events.push_back(FlowEvent::Resteered(reason));
                    true
                }
                Ok(Replan::Teardown) | Err(_) => {
                    events.push_back(FlowEvent::FlowTornDown(*endpoint));
                    false
                }
            },
        );
    }

    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.transmits.pop_front()
    }

    pub fn poll_event(&mut self) -> Option<FlowEvent> {
        self.events.pop_front()
    }

    /// The earliest instant a state machine may need `on_timeout`. The shell
    /// re-arms one timer against this; there is never a timer per flow.
    pub fn poll_timeout(&self) -> Option<Instant> {
        [self.reassembler.next_deadline(), self.flows.next_deadline()]
            .into_iter()
            .flatten()
            .min()
    }

    /// Advances both state machines. Expired flows are dropped here, which is
    /// what returns their queued `Pooled` payloads to the shared pool.
    pub fn on_timeout(&mut self, now: Instant) {
        let _ = self.reassembler.expire(now);
        drop(self.flows.expire(now));
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
    use crate::BufferPool;
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::Arc,
        time::Duration,
    };

    /// A pool large enough that nothing in these tests hits its budget, so a
    /// `None` here would be a defect rather than the exhaustion path.
    fn pool() -> Arc<BufferPool> {
        BufferPool::new(
            NonZeroUsize::new(1500).unwrap(),
            NonZeroUsize::new(64).unwrap(),
        )
    }

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
        let pool = pool();
        assert_eq!(
            path.send_datagram(endpoint, pool.take(b"\x01").unwrap(), now),
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
        let pool = pool();
        let _ = path.send_datagram(
            endpoint,
            pool.take(b"\x01").unwrap(),
            now + Duration::from_secs(122),
        );
    }

    #[test]
    fn an_unplannable_configuration_is_refused_at_construction() {
        // Overhead exceeding the path leaves no inner MTU, so no flow on this
        // configuration could ever plan. Rejecting it here is what makes every
        // later `plan_flow` on the stored configuration a proof-carrying
        // repeat rather than a panic waiting to happen.
        let mut starved = egress(crate::DatagramFidelity::Native);
        starved.accepts = crate::Accepts::IpPackets;
        starved.overhead_bytes = 400;
        assert_eq!(
            Datapath::new(
                FilterPolicy::PassThrough,
                starved,
                Mtu::new(1500).unwrap(),
                Duration::from_secs(30),
                NonZeroUsize::new(8).unwrap(),
                Duration::from_secs(120),
                NonZeroUsize::new(64).unwrap(),
            )
            .err(),
            Some(DatapathError::Plan(PlanError::InnerMtu(
                crate::MtuError::BelowMinimum(1100)
            )))
        );
    }

    #[test]
    fn a_full_queue_drops_and_returns_its_bytes_to_the_pool() {
        // Two bounds act here, and the per-flow one binds first by design: it
        // is the fairness bound, so no single flow can spend the shared budget.
        let queue_depth = NonZeroUsize::new(2).unwrap();
        let mut path = Datapath::new(
            FilterPolicy::PassThrough,
            egress(crate::DatagramFidelity::Native),
            Mtu::new(1500).unwrap(),
            Duration::from_secs(30),
            NonZeroUsize::new(8).unwrap(),
            Duration::from_secs(120),
            queue_depth,
        )
        .unwrap();
        let now = Instant::now();
        let pool = BufferPool::new(
            NonZeroUsize::new(1500).unwrap(),
            NonZeroUsize::new(8).unwrap(),
        );
        let endpoint = InternalEndpoint {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            port: 1234,
        };

        let send = |path: &mut Datapath, pool: &Arc<BufferPool>| {
            path.send_datagram(endpoint, pool.take(b"payload").unwrap(), now)
        };
        assert_eq!(send(&mut path, &pool), Ok(SendOutcome::Buffered));
        assert_eq!(send(&mut path, &pool), Ok(SendOutcome::Buffered));
        assert_eq!(pool.available(), 6, "queued payloads hold the budget");

        // A third datagram exceeds the per-flow capacity while the pool still
        // has room. The core drops it, and dropping the refused handle hands
        // its buffer straight back rather than leaking the budget.
        assert_eq!(send(&mut path, &pool), Ok(SendOutcome::Dropped));
        assert_eq!(pool.available(), 6, "the refused buffer was returned");
        assert_eq!(
            path.poll_event(),
            Some(FlowEvent::DatagramDropped(endpoint))
        );

        // Expiring the flow releases its whole queue at once: `Drop` is the
        // release, so there is no separate reclamation step to forget.
        path.on_timeout(now + Duration::from_secs(121));
        assert!(path.flows.is_empty());
        assert_eq!(pool.available(), 8);
    }
}
