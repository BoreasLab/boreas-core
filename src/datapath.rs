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
//! - the configuration is planned once at construction and re-planned only when
//!   it changes, so classification is total rather than optimistic and no
//!   packet pays for a decision that cannot have moved since the last one;
//! - a `Transmit` names the side it is bound for, so the shell cannot send a
//!   fast-path packet back down the interface it arrived on.

use std::{collections::VecDeque, num::NonZeroUsize, sync::Arc, time::Instant};

use crate::{
    Accepts, Admission, BufferPool, DatagramBuffer, DnsPolicy, EgressCapabilities, FilterPolicy,
    FlowPlan, FlowTableError, Fragment, IngressAction, IngressPacket, InternalEndpoint, Mtu,
    PacketError, PlanError, Pooled, PushOutcome, Reassembler, Replan, SendOutcome, SteeringReason,
    Transport, TransportPath, UdpFlowTable, WriteError, admit, clamp_mss, plan_flow, replan,
    route_planned, udp_datagram_len, write_udp,
};

/// One of the two sides the datapath sits between: the client's TUN and the
/// configured egress.
///
/// It names both the side a packet arrived on and the side a transmit is bound
/// for, because every forwarding decision the core makes is exactly the
/// crossing between them. [`Side::across`] is that crossing and is its own
/// inverse.
///
/// Before this type existed, [`Transmit`] carried bytes and nothing else, so
/// the shell had to guess the destination — and the only guess available, the
/// device, sends a fast-path packet straight back at the client instead of
/// encapsulating it. The destination is a fact the core knows and the shell
/// cannot re-derive, so the core states it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Tunnel,
    Egress,
}

impl Side {
    /// The other side. `s.across().across() == s`.
    pub fn across(self) -> Self {
        match self {
            Self::Tunnel => Self::Egress,
            Self::Egress => Self::Tunnel,
        }
    }
}

/// One packet the core has decided to forward, and the side it belongs on.
///
/// The payload is a [`Pooled`] buffer rather than an owned `Vec`: the
/// engineering plan's per-packet budget puts a heap allocation at ~100 ns and
/// forbids one per packet, and the pool already exists for exactly this. Not
/// `Clone`, because `Pooled` is affine.
#[derive(Debug, PartialEq, Eq)]
pub struct Transmit {
    pub to: Side,
    pub bytes: Pooled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowEvent {
    StreamOpened(InternalEndpoint),
    DatagramOpened(InternalEndpoint),
    DatagramDropped(InternalEndpoint),
    ReassemblyDiscarded,
    Resteered(SteeringReason),
    FlowTornDown(InternalEndpoint),
    /// A packet the core planned to forward but could not hold: the shared
    /// pool's budget was spent, or the packet exceeded a pool slice. Per
    /// packet under congestion, so the shell folds it into a counter rather
    /// than forwarding one message per occurrence.
    TransmitDropped,
}

/// The tuning knobs of a [`Datapath`], grouped so the constructor reads as
/// configuration rather than position. All four are bounds on memory or time;
/// none of them changes policy.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub reassembly_timeout: std::time::Duration,
    pub max_pending_reassemblies: NonZeroUsize,
    /// RFC 4787 REQ-5 forbids going below two minutes; the flow table enforces
    /// that floor.
    pub flow_idle_timeout: std::time::Duration,
    /// Per-flow datagram queue depth: the fairness bound under the shared
    /// pool's global budget.
    pub datagram_buffer_capacity: NonZeroUsize,
}

/// One intercepted DNS query, waiting for the shell to resolve it.
///
/// The payload is a pooled buffer, which is also the bound: pending queries
/// cannot outgrow the shared budget, and a flood of them is a counted drop
/// like any other congestion rather than unbounded growth.
#[derive(Debug, PartialEq, Eq)]
pub struct DnsQuery {
    /// The client that asked.
    pub client: InternalEndpoint,
    /// The resolver address it addressed. A stub resolver discards a reply
    /// whose source is not the address it sent to, so the answer must be
    /// written *from* here, which is why it travels with the query.
    pub resolver: InternalEndpoint,
    /// The DNS message, without its IP and UDP headers.
    pub payload: Pooled,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DatapathError {
    Malformed(PacketError),
    Plan(PlanError),
    FlowTable(FlowTableError),
    /// A synthesized packet could not be written. Distinct from `Malformed`,
    /// which describes input: this one describes something this datapath tried
    /// to originate.
    Write(WriteError),
}

impl std::fmt::Display for DatapathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(error) => write!(f, "malformed packet: {error}"),
            Self::Plan(error) => write!(f, "planning failed: {error}"),
            Self::FlowTable(error) => write!(f, "flow table rejected the configuration: {error}"),
            Self::Write(error) => write!(f, "could not write a synthesized packet: {error}"),
        }
    }
}

impl std::error::Error for DatapathError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Malformed(error) => Some(error),
            Self::Plan(error) => Some(error),
            Self::FlowTable(error) => Some(error),
            Self::Write(error) => Some(error),
        }
    }
}

impl From<WriteError> for DatapathError {
    fn from(error: WriteError) -> Self {
        Self::Write(error)
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
    /// ponytail: the drain is the first *stream* egress (SOCKS5, P17). A
    /// packet egress consumes whole packets and never these queues. Until
    /// then an idle queue is reclaimed when its flow expires, and the pool's
    /// budget is what keeps that bounded.
    buffer: DatagramBuffer<Pooled>,
}

pub struct Datapath {
    filter: FilterPolicy,
    dns: DnsPolicy,
    /// The layer the configured egress accepts. Separate from the capability
    /// claim because the layer is a property of the implementation variant,
    /// established by the caller from [`crate::Egress`] and unable to drift
    /// from it there.
    accepts: Accepts,
    egress: EgressCapabilities,
    path_mtu: Mtu,
    /// The planning decision for the current configuration, memoized.
    ///
    /// Every input to `plan_flow` — filter policy, accepted layer, capability
    /// claim, path MTU — is a session property, so the answer moves only when
    /// the configuration does. Deriving it per packet was both wasted work on
    /// the hot path and a fallible call in a place with no interesting failure;
    /// holding the `Result` keeps the failing configuration's behavior exactly
    /// as it was (every packet counted and refused) while making the succeeding
    /// case a field read.
    plan: Result<FlowPlan, PlanError>,
    /// Payload storage for forwarded packets and queued datagrams alike. One
    /// budget, `capacity x slice_size`, for everything the core holds.
    pool: Arc<BufferPool>,
    datagram_buffer_capacity: NonZeroUsize,
    reassembler: Reassembler,
    flows: UdpFlowTable<FlowState>,
    events: VecDeque<FlowEvent>,
    transmits: VecDeque<Transmit>,
    queries: VecDeque<DnsQuery>,
}

impl Datapath {
    /// `pool` must admit at least `path_mtu` bytes per slice; a packet larger
    /// than a slice cannot be held and is dropped and counted like any other
    /// exhaustion.
    pub fn new(
        filter: FilterPolicy,
        dns: DnsPolicy,
        accepts: Accepts,
        egress: EgressCapabilities,
        path_mtu: Mtu,
        limits: Limits,
        pool: Arc<BufferPool>,
    ) -> Result<Self, DatapathError> {
        // Parse, do not validate: a `Datapath` exists only for a configuration
        // that plans, and the proof is kept rather than recomputed.
        let plan = plan_flow(filter, accepts, egress, path_mtu)?;

        Ok(Self {
            filter,
            dns,
            accepts,
            egress,
            path_mtu,
            plan: Ok(plan),
            pool,
            datagram_buffer_capacity: limits.datagram_buffer_capacity,
            reassembler: Reassembler::new(
                limits.reassembly_timeout,
                limits.max_pending_reassemblies,
            ),
            flows: UdpFlowTable::new(limits.flow_idle_timeout, Instant::now())?,
            events: VecDeque::new(),
            transmits: VecDeque::new(),
            queries: VecDeque::new(),
        })
    }

    /// A packet from the client's TUN. Whatever it produces is bound for the
    /// egress, because that is the side it did not come from.
    pub fn on_tun_packet(&mut self, buf: &[u8], now: Instant) -> Result<(), DatapathError> {
        let packet = IngressPacket::parse(buf)?;
        self.dispatch(packet, buf, Side::Tunnel, now)
    }

    /// A decapsulated packet from the egress, bound for the client.
    pub fn on_egress_packet(&mut self, buf: &[u8], now: Instant) -> Result<(), DatapathError> {
        let packet = IngressPacket::parse(buf)?;
        // Fragments arriving from the egress side are pathological: the peer's
        // stack reassembles before we do, so anything still fragmented here
        // cannot match a flow.
        if packet.transport == Transport::Fragment {
            self.events.push_back(FlowEvent::ReassemblyDiscarded);
            return Ok(());
        }
        self.dispatch(packet, buf, Side::Egress, now)
    }

    fn dispatch(
        &mut self,
        packet: IngressPacket,
        buf: &[u8],
        from: Side,
        now: Instant,
    ) -> Result<(), DatapathError> {
        // `admit` settles everything no egress capability could change, which
        // is also everything that must keep working under a configuration that
        // cannot plan at all: reassembly, unsupported protocols, and DNS.
        let action = match admit(packet.transport, self.dns) {
            Admission::Settled(action) => action,
            Admission::Planned => route_planned(packet.transport, self.plan?),
        };
        match action {
            IngressAction::Reassemble => self.on_fragment(buf, from, now),
            IngressAction::ResolveDns => {
                self.intercept_dns(packet, buf);
                Ok(())
            }
            IngressAction::ForwardPacket(plan) => {
                let clamp = match plan.transport {
                    // The clamp is the only mechanism that reaches a terminated
                    // path's segment size; on non-SYN packets it is a no-op.
                    TransportPath::PacketFastPath { inner_mtu } => Some(inner_mtu),
                    TransportPath::LocalTermination => None,
                };
                self.forward(buf, from.across(), clamp);
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
                self.forward(buf, from.across(), None);
                Ok(())
            }
            IngressAction::DropUnsupported => Ok(()),
        }
    }

    /// Captures one DNS query for the shell to resolve.
    ///
    /// The datapath cannot resolve anything — that needs an upstream, a
    /// socket, and a clock — so it keeps the two endpoints and the message and
    /// hands them across the seam. A query whose payload will not fit the
    /// shared budget is a counted drop, and the client's stub resolver
    /// retries, which is exactly what it does for a lost datagram.
    fn intercept_dns(&mut self, packet: IngressPacket, buf: &[u8]) {
        let Transport::Udp {
            source_port,
            destination_port,
        } = packet.transport
        else {
            return;
        };
        let Some(payload) = packet.payload(buf).and_then(|bytes| self.pool.take(bytes)) else {
            self.events.push_back(FlowEvent::TransmitDropped);
            return;
        };
        self.queries.push_back(DnsQuery {
            client: InternalEndpoint {
                address: packet.source,
                port: source_port,
            },
            resolver: InternalEndpoint {
                address: packet.destination,
                port: destination_port,
            },
            payload,
        });
    }

    /// The next intercepted query, if any.
    pub fn poll_query(&mut self) -> Option<DnsQuery> {
        self.queries.pop_front()
    }

    /// Queues the answer to an intercepted query, addressed back to the client
    /// from the resolver address it asked.
    ///
    /// This is the one place the datapath originates a packet rather than
    /// forwarding one, so it writes both checksums in full; there is no
    /// predecessor to adjust from.
    pub fn answer_dns(
        &mut self,
        client: InternalEndpoint,
        resolver: InternalEndpoint,
        response: &[u8],
    ) -> Result<(), DatapathError> {
        let len = udp_datagram_len(resolver.address, response.len());
        let Some(mut bytes) = self.pool.take_zeroed(len) else {
            self.events.push_back(FlowEvent::TransmitDropped);
            return Ok(());
        };
        write_udp(&mut bytes, resolver, client, response)?;
        self.transmits.push_back(Transmit {
            to: Side::Tunnel,
            bytes,
        });
        Ok(())
    }

    /// Copies one packet into a pooled buffer and queues it for `to`.
    ///
    /// Exhaustion is a counted drop, never a wait and never an allocation: the
    /// pool's budget is the bound on how many packets the core can hold at
    /// once, and a packet that does not fit it is exactly the congestion the
    /// budget exists to express.
    fn forward(&mut self, buf: &[u8], to: Side, clamp: Option<Mtu>) {
        let Some(mut bytes) = self.pool.take(buf) else {
            self.events.push_back(FlowEvent::TransmitDropped);
            return;
        };
        if let Some(inner_mtu) = clamp {
            let _ = clamp_mss(&mut bytes, inner_mtu);
        }
        self.transmits.push_back(Transmit { to, bytes });
    }

    fn on_fragment(&mut self, buf: &[u8], from: Side, now: Instant) -> Result<(), DatapathError> {
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
                // fragment boundary alone. It keeps the side it arrived on, so
                // reassembly cannot reverse a packet's direction.
                let packet = IngressPacket::parse(&datagram)?;
                self.dispatch(packet, &datagram, from, now)
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
        // The memoized plan, so a configuration the current egress cannot
        // serve surfaces as `DatapathError::Plan` before the flow exists,
        // never as a panic inside the closure.
        let plan = self.plan?;
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
    pub fn on_capability_change(&mut self, accepts: Accepts, next: EgressCapabilities) {
        self.accepts = accepts;
        self.egress = next;
        // The memoized decision moves with the configuration it describes. An
        // unplannable capability is kept as the `Err` it is: every subsequent
        // packet is refused and counted, which is what the caller already saw
        // when planning happened per packet.
        self.plan = plan_flow(self.filter, accepts, next, self.path_mtu);
        let Self {
            filter,
            path_mtu,
            flows,
            events,
            ..
        } = self;
        let (filter, path_mtu) = (*filter, *path_mtu);

        flows.retain(|endpoint, state| {
            match replan(&state.plan, filter, accepts, next, path_mtu) {
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
            }
        });
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
    use crate::{BufferPool, Limits};
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

    fn limits(queue_depth: usize) -> Limits {
        Limits {
            reassembly_timeout: Duration::from_secs(30),
            max_pending_reassemblies: NonZeroUsize::new(8).unwrap(),
            flow_idle_timeout: Duration::from_secs(120),
            datagram_buffer_capacity: NonZeroUsize::new(queue_depth).unwrap(),
        }
    }

    fn egress(fidelity: crate::DatagramFidelity) -> EgressCapabilities {
        EgressCapabilities {
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
            DnsPolicy::Forward,
            Accepts::Flows,
            egress(fidelity),
            Mtu::new(1500).unwrap(),
            limits(64),
            pool(),
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
        path.on_capability_change(Accepts::Flows, egress(crate::DatagramFidelity::Emulated));
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

        let packets_only = egress(crate::DatagramFidelity::Native);
        path.on_capability_change(Accepts::IpPackets, packets_only);
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
    fn a_transmit_always_leaves_by_the_side_it_did_not_arrive_on() {
        // The law the `Side` type exists to state: forwarding crosses the
        // datapath. A tun-side packet is bound for the egress and an egress-
        // side packet is bound for the tunnel, and `across` is the involution
        // that says so.
        assert_eq!(Side::Tunnel.across(), Side::Egress);
        assert_eq!(Side::Egress.across(), Side::Tunnel);
        for side in [Side::Tunnel, Side::Egress] {
            assert_eq!(side.across().across(), side);
        }

        let mut path = Datapath::new(
            FilterPolicy::PassThrough,
            DnsPolicy::Forward,
            Accepts::IpPackets,
            egress(crate::DatagramFidelity::Native),
            Mtu::new(1500).unwrap(),
            limits(8),
            pool(),
        )
        .unwrap();
        let now = Instant::now();

        path.on_tun_packet(&udp_packet(), now).unwrap();
        let transmit = path.poll_transmit().expect("the fast path forwards");
        assert_eq!(transmit.to, Side::Egress, "a tun packet is bound outward");
        assert_eq!(*transmit.bytes, udp_packet()[..]);

        path.on_egress_packet(&udp_packet(), now).unwrap();
        let transmit = path.poll_transmit().expect("the fast path forwards");
        assert_eq!(transmit.to, Side::Tunnel, "a tunnel packet is bound inward");
    }

    #[test]
    fn an_exhausted_pool_drops_and_counts_rather_than_allocating() {
        // The forward path holds no bytes of its own. When the shared budget
        // is spent the packet is a counted drop, which is the same discipline
        // the per-flow queues already follow.
        let pool = BufferPool::new(
            NonZeroUsize::new(1500).unwrap(),
            NonZeroUsize::new(1).unwrap(),
        );
        let mut path = Datapath::new(
            FilterPolicy::PassThrough,
            DnsPolicy::Forward,
            Accepts::IpPackets,
            egress(crate::DatagramFidelity::Native),
            Mtu::new(1500).unwrap(),
            limits(8),
            Arc::clone(&pool),
        )
        .unwrap();
        let now = Instant::now();

        path.on_tun_packet(&udp_packet(), now).unwrap();
        let held = path.poll_transmit().expect("the first packet fits");
        assert_eq!(pool.available(), 0);

        path.on_tun_packet(&udp_packet(), now).unwrap();
        assert!(path.poll_transmit().is_none(), "nothing was allocated");
        assert_eq!(path.poll_event(), Some(FlowEvent::TransmitDropped));
        assert_eq!(pool.exhausted(), 1);

        // Draining the first transmit returns the budget, and forwarding works
        // again: the drop was congestion, not a broken datapath.
        drop(held);
        path.on_tun_packet(&udp_packet(), now).unwrap();
        assert!(path.poll_transmit().is_some());
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
        let starved = egress(crate::DatagramFidelity::Native);
        let starved = EgressCapabilities {
            overhead_bytes: 400,
            ..starved
        };
        assert_eq!(
            Datapath::new(
                FilterPolicy::PassThrough,
                DnsPolicy::Forward,
                Accepts::IpPackets,
                starved,
                Mtu::new(1500).unwrap(),
                limits(64),
                pool(),
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
        let pool = BufferPool::new(
            NonZeroUsize::new(1500).unwrap(),
            NonZeroUsize::new(8).unwrap(),
        );
        let mut path = Datapath::new(
            FilterPolicy::PassThrough,
            DnsPolicy::Forward,
            Accepts::Flows,
            egress(crate::DatagramFidelity::Native),
            Mtu::new(1500).unwrap(),
            limits(2),
            Arc::clone(&pool),
        )
        .unwrap();
        let now = Instant::now();
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
