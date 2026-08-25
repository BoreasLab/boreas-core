//! The sans-io datapath core owns flow state and policy decisions, but no socket,
//! clock, or task. Fragments are reassembled before planning, flows are created
//! only after planning succeeds, queues are bounded, and each transmit names its
//! destination side.

use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    Accepts, Admission, Backstop, BufferPool, DatagramBuffer, DnsPolicy, FilterPolicy, FlowPlan,
    FlowTableError, Fragment, IcmpClass, IngressAction, IngressPacket, Inspection,
    InternalEndpoint, Mtu, OriginationPorts, PacketError, PathProperties, PlanError, Pooled,
    PushOutcome, Reassembler, Replan, SendOutcome, SteeringReason, Transport, TransportPath,
    UdpFlowTable, WriteError, admit, clamp_mss, forbids_fragmentation, plan_flow, replan,
    route_planned, udp_datagram_len, write_too_big, write_udp,
};

/// Packet source or transmit destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Tunnel,
    Egress,
}

impl Side {
    /// Returns the other side.
    pub fn across(self) -> Self {
        match self {
            Self::Tunnel => Self::Egress,
            Self::Egress => Self::Tunnel,
        }
    }
}

/// One packet the core has decided to forward and its destination side.
///
/// [`Pooled`] avoids a heap allocation per packet and is affine, so this type is
/// intentionally not `Clone`.
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
    /// A planned packet could not fit the shared pool.
    TransmitDropped,
    /// A QUIC attempt was dropped by the steering backstop.
    QuicSteered,
    /// An over-sized packet was answered with an ICMP Packet Too Big for this MTU.
    PathReported(Mtu),
}

/// Resolved addresses of inspected hosts and their expiry deadlines.
///
/// One hash probe serves both QUIC backstop and TCP candidacy. The bounded set
/// is small, so a `HashMap` gives expected O(1) packet probes; `earliest` avoids
/// scanning it on every reactor wakeup.
struct InspectedAddresses {
    window: Duration,
    capacity: NonZeroUsize,
    until: HashMap<IpAddr, Instant>,
    /// The minimum deadline, maintained on insert and recomputed during expiry.
    earliest: Option<Instant>,
}

impl InspectedAddresses {
    fn new(window: Duration, capacity: NonZeroUsize) -> Self {
        Self {
            window,
            capacity,
            until: HashMap::new(),
            earliest: None,
        }
    }

    /// Opens or extends the window and returns addresses refused at capacity.
    fn admit(&mut self, addresses: &[IpAddr], now: Instant) -> usize {
        let Some(deadline) = now.checked_add(self.window) else {
            return addresses.len();
        };
        let mut refused = 0;
        for address in addresses {
            if !self.until.contains_key(address) && self.until.len() >= self.capacity.get() {
                refused += 1;
                continue;
            }
            self.until.insert(*address, deadline);
            self.earliest = Some(
                self.earliest
                    .map_or(deadline, |soonest| soonest.min(deadline)),
            );
        }
        refused
    }

    /// Whether this address is live. The deadline is checked even before a sweep.
    fn live(&self, address: &IpAddr, now: Instant) -> bool {
        self.until
            .get(address)
            .is_some_and(|deadline| *deadline > now)
    }

    /// Expires entries when the earliest deadline has arrived.
    fn expire(&mut self, now: Instant) {
        if self.earliest.is_none_or(|earliest| earliest > now) {
            return;
        }
        self.until.retain(|_, deadline| *deadline > now);
        self.earliest = self.until.values().copied().min();
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.earliest
    }
}

/// Memory and time bounds for a [`Datapath`].
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub reassembly_timeout: std::time::Duration,
    pub max_pending_reassemblies: NonZeroUsize,
    /// RFC 4787 REQ-5 minimum idle timeout.
    pub flow_idle_timeout: std::time::Duration,
    /// Per-flow datagram queue depth and fairness bound.
    pub datagram_buffer_capacity: NonZeroUsize,
    /// Lifetime of inspected addresses for QUIC backstop and TCP candidacy.
    pub inspection_window: Duration,
    /// Maximum number of addresses admitted from network input.
    pub max_inspected_addresses: NonZeroUsize,
    /// TCP ports shared with the local stack's listener set. A mismatch sends a
    /// terminated flow to an unserved port and produces a reset.
    pub inspected_ports: &'static [u16],
    /// Source ports reserved for local re-origination. Excluding them prevents
    /// a re-originated connection from being inspected again.
    ///
    /// `None` when the proxy performs re-origination.
    pub origination_ports: Option<OriginationPorts>,
}

/// The ports HTTP interception serves.
pub const DEFAULT_INSPECTED_PORTS: &[u16] = &[80, 443];

/// One intercepted DNS query waiting for the shell to resolve it.
///
/// Its pooled payload keeps pending queries within the shared memory budget.
#[derive(Debug, PartialEq, Eq)]
pub struct DnsQuery {
    /// The client endpoint.
    pub client: InternalEndpoint,
    /// The resolver endpoint, which must be the reply source.
    pub resolver: InternalEndpoint,
    /// The DNS message, without its IP and UDP headers.
    pub payload: Pooled,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DatapathError {
    Malformed(PacketError),
    Plan(PlanError),
    FlowTable(FlowTableError),
    /// A synthesized packet could not be written.
    Write(WriteError),
    /// Inspection cannot produce candidates because DNS is forwarded on a packet egress.
    Vacuous,
}

impl std::fmt::Display for DatapathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(error) => write!(f, "malformed packet: {error}"),
            Self::Plan(error) => write!(f, "planning failed: {error}"),
            Self::FlowTable(error) => write!(f, "flow table rejected the configuration: {error}"),
            Self::Write(error) => write!(f, "could not write a synthesized packet: {error}"),
            Self::Vacuous => f.write_str(
                "inspection is enabled on a packet egress that forwards DNS, \
                 so no flow can ever be selected for it",
            ),
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
            Self::Vacuous => None,
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

/// One datagram of a terminated flow, including its target.
///
/// The target belongs to each datagram because RFC 4787 endpoint-independent
/// mappings let one unconnected UDP port talk to multiple peers.
#[derive(Debug, PartialEq, Eq)]
pub struct Outbound {
    /// The client mapping for the egress association.
    pub client: InternalEndpoint,
    /// The peer addressed by this datagram.
    pub target: std::net::SocketAddr,
    pub payload: Pooled,
}

struct FlowState {
    plan: FlowPlan,
    /// Client datagrams waiting for the egress. Storage is pooled globally, with
    /// a per-flow capacity preserving fairness. Replies bypass this queue and
    /// become tunnel-bound transmits because the reactor drains them synchronously.
    buffer: DatagramBuffer<(std::net::SocketAddr, Pooled)>,
}

pub struct Datapath {
    filter: FilterPolicy,
    dns: DnsPolicy,
    /// The layer accepted by the configured egress.
    accepts: Accepts,
    egress: PathProperties,
    path_mtu: Mtu,
    /// One planned result per [`Inspection`] verdict. The two-element array
    /// avoids a cache key and preserves planning errors on the packet path.
    plans: [Result<FlowPlan, PlanError>; 2],
    /// Sorted interception ports, queried by binary search.
    inspected_ports: Box<[u16]>,
    /// Source ports reserved for this session's re-originated connections.
    origination_ports: Option<OriginationPorts>,
    /// Shared payload storage for forwarded packets and queued datagrams.
    pool: Arc<BufferPool>,
    datagram_buffer_capacity: NonZeroUsize,
    reassembler: Reassembler,
    inspected: InspectedAddresses,
    flows: UdpFlowTable<FlowState>,
    events: VecDeque<FlowEvent>,
    transmits: VecDeque<Transmit>,
    queries: VecDeque<DnsQuery>,
    /// Packets of terminated flows waiting for the shell's local TCP stack.
    terminate: VecDeque<Pooled>,
    /// Non-empty flows in round-robin order. One pop, receive, and requeue is
    /// amortized O(1), avoiding an O(live flows) sweep per datagram. Expired
    /// flows leave stale entries, which are skipped.
    ready: VecDeque<InternalEndpoint>,
}

impl Datapath {
    /// `pool` must admit at least `path_mtu` bytes per slice; a packet larger
    /// than a slice cannot be held and is dropped and counted like any other
    /// exhaustion.
    pub fn new(
        filter: FilterPolicy,
        dns: DnsPolicy,
        accepts: Accepts,
        egress: PathProperties,
        path_mtu: Mtu,
        limits: Limits,
        pool: Arc<BufferPool>,
    ) -> Result<Self, DatapathError> {
        // Forwarded DNS cannot populate the candidacy index for packet egress.
        if filter == FilterPolicy::InspectHttp
            && dns == DnsPolicy::Forward
            && accepts == Accepts::IpPackets
        {
            return Err(DatapathError::Vacuous);
        }
        // Retain one plan for each inspection verdict.
        let plans = Inspection::ALL
            .map(|inspection| plan_flow(filter, inspection, accepts, egress, path_mtu));
        // A flow cannot enter with an unserviceable plan.
        for plan in &plans {
            (*plan)?;
        }
        let mut inspected_ports = limits.inspected_ports.to_vec();
        inspected_ports.sort_unstable();
        inspected_ports.dedup();

        Ok(Self {
            filter,
            dns,
            accepts,
            egress,
            path_mtu,
            plans,
            inspected_ports: inspected_ports.into_boxed_slice(),
            origination_ports: limits.origination_ports,
            pool,
            datagram_buffer_capacity: limits.datagram_buffer_capacity,
            reassembler: Reassembler::new(
                limits.reassembly_timeout,
                limits.max_pending_reassemblies,
            ),
            inspected: InspectedAddresses::new(
                limits.inspection_window,
                limits.max_inspected_addresses,
            ),
            flows: UdpFlowTable::new(limits.flow_idle_timeout, Instant::now())?,
            events: VecDeque::new(),
            transmits: VecDeque::new(),
            queries: VecDeque::new(),
            terminate: VecDeque::new(),
            ready: VecDeque::new(),
        })
    }

    /// Returns the cached plan for a verdict.
    fn plan(&self, inspection: Inspection) -> Result<FlowPlan, PlanError> {
        self.plans[inspection.index()]
    }

    /// Whether this TCP packet is a local-inspection candidate.
    fn inspection(&self, packet: IngressPacket, from: Side, now: Instant) -> Inspection {
        let Transport::Tcp {
            source_port,
            destination_port,
        } = packet.transport
        else {
            return Inspection::Excluded;
        };
        // Exclude this session's own re-originated connections to prevent recursion.
        if self
            .origination_ports
            .is_some_and(|ports| ports.contains(source_port))
        {
            return Inspection::Excluded;
        }
        if from != Side::Tunnel
            || self.filter != FilterPolicy::InspectHttp
            || self
                .inspected_ports
                .binary_search(&destination_port)
                .is_err()
            || !self.inspected.live(&packet.destination, now)
        {
            return Inspection::Excluded;
        }
        Inspection::Candidate
    }

    /// Handles a packet from the client's TUN.
    pub fn on_tun_packet(&mut self, buf: &[u8], now: Instant) -> Result<(), DatapathError> {
        let packet = IngressPacket::parse(buf)?;
        self.dispatch(packet, buf, Side::Tunnel, now)
    }

    /// Handles a decapsulated packet from the egress.
    pub fn on_egress_packet(&mut self, buf: &[u8], now: Instant) -> Result<(), DatapathError> {
        let packet = IngressPacket::parse(buf)?;
        // Egress fragments should already have been reassembled by the peer.
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
        // Steering applies to outbound attempts, not inbound responses.
        let backstop = match from {
            Side::Tunnel if self.inspected.live(&packet.destination, now) => Backstop::Active,
            Side::Tunnel | Side::Egress => Backstop::Lapsed,
        };
        // Settle actions independent of the egress path before planning.
        let action = match admit(packet.transport, self.dns, backstop) {
            Admission::Settled(action) => action,
            Admission::Planned => {
                let inspection = self.inspection(packet, from, now);
                route_planned(packet.transport, self.plan(inspection)?)
            }
        };
        match action {
            IngressAction::Reassemble => self.on_fragment(buf, from, now),
            IngressAction::ResolveDns => {
                self.intercept_dns(packet, buf);
                Ok(())
            }
            IngressAction::DropSteered => {
                self.events.push_back(FlowEvent::QuicSteered);
                Ok(())
            }
            IngressAction::ForwardPacket(plan) => {
                let clamp = match plan.transport {
                    // MSS clamping affects the initial SYN only.
                    TransportPath::PacketFastPath { inner_mtu } => {
                        // Report oversized DF packets locally so the sender can
                        // discover the inner MTU. RFC 1122 §3.2.2 and RFC 4443
                        // §2.4 (e) prohibit answering ICMP errors with errors.
                        if from == Side::Tunnel
                            && packet.transport != Transport::Icmp(IcmpClass::Error)
                            && buf.len() > usize::from(inner_mtu.get())
                            && forbids_fragmentation(buf)
                        {
                            self.report_too_big(buf, inner_mtu);
                            return Ok(());
                        }
                        Some(inner_mtu)
                    }
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
                // The shell owns the local TCP stack; capture only the client side.
                if from == Side::Tunnel {
                    self.capture_for_termination(buf);
                }
                Ok(())
            }
            IngressAction::OpenDatagram(plan) => {
                let endpoint = endpoint_of(packet);
                if self.open_flow(endpoint, plan, now)? {
                    self.events.push_back(FlowEvent::DatagramOpened(endpoint));
                }
                // Capture client datagrams; replies return through the association.
                if from == Side::Tunnel {
                    self.capture_datagram(packet, buf, endpoint);
                }
                Ok(())
            }
            IngressAction::HandleIcmp(_) => {
                // The effect shell generates any client-facing PTB.
                self.forward(buf, from.across(), None);
                Ok(())
            }
            IngressAction::DropUnsupported => Ok(()),
        }
    }

    /// Captures a DNS query for the shell; the pooled payload bounds pending work.
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

    pub fn poll_query(&mut self) -> Option<DnsQuery> {
        self.queries.pop_front()
    }

    /// Returns the shared payload pool used by the core and resolver.
    pub fn pool(&self) -> &Arc<BufferPool> {
        &self.pool
    }

    /// Captures a whole packet for the local TCP stack; pool exhaustion is counted.
    fn capture_for_termination(&mut self, buf: &[u8]) {
        match self.pool.take(buf) {
            Some(packet) => self.terminate.push_back(packet),
            None => self.events.push_back(FlowEvent::TransmitDropped),
        }
    }

    /// Queues a client datagram with its peer for the egress association.
    fn capture_datagram(&mut self, packet: IngressPacket, buf: &[u8], client: InternalEndpoint) {
        let Transport::Udp {
            destination_port, ..
        } = packet.transport
        else {
            return;
        };
        let target = std::net::SocketAddr::new(packet.destination, destination_port);
        let Some(payload) = packet.payload(buf).and_then(|bytes| self.pool.take(bytes)) else {
            self.events.push_back(FlowEvent::TransmitDropped);
            return;
        };
        // The flow should have been created immediately above; drop on expiry.
        let Some(flow) = self.flows.get_mut(&client) else {
            self.events.push_back(FlowEvent::TransmitDropped);
            return;
        };
        // One ready-list entry per empty-to-non-empty transition.
        let was_idle = flow.buffer.is_empty();
        if flow.buffer.try_send((target, payload)) == SendOutcome::Dropped {
            self.events.push_back(FlowEvent::DatagramDropped(client));
            return;
        }
        if was_idle {
            self.ready.push_back(client);
        }
    }

    /// Returns one queued datagram in round-robin order, if any. Amortized O(1).
    pub fn poll_datagram(&mut self) -> Option<Outbound> {
        while let Some(client) = self.ready.pop_front() {
            let Some(flow) = self.flows.get_mut(&client) else {
                continue; // The flow expired with its queue.
            };
            let Some((target, payload)) = flow.buffer.recv() else {
                continue; // Another turn drained the queue.
            };
            if !flow.buffer.is_empty() {
                self.ready.push_back(client);
            }
            return Some(Outbound {
                client,
                target,
                payload,
            });
        }
        None
    }

    /// Delivers an egress datagram as a synthesized packet for its client.
    /// RFC 4787 REQ-6 requires refreshing the mapping in this direction too.
    pub fn deliver_datagram(
        &mut self,
        client: InternalEndpoint,
        peer: InternalEndpoint,
        payload: &[u8],
        now: Instant,
    ) -> Result<SendOutcome, DatapathError> {
        if !self.flows.contains(&client) {
            return Ok(SendOutcome::Dropped);
        }
        let plan = self.plan(Inspection::Excluded)?;
        let capacity = self.datagram_buffer_capacity;
        self.flows.get_or_insert_with(client, now, || FlowState {
            plan,
            buffer: DatagramBuffer::new(capacity),
        })?;

        let len = udp_datagram_len(peer.address, payload.len());
        let Some(mut bytes) = self.pool.take_zeroed(len) else {
            self.events.push_back(FlowEvent::TransmitDropped);
            return Ok(SendOutcome::Dropped);
        };
        write_udp(&mut bytes, peer, client, payload)?;
        self.transmits.push_back(Transmit {
            to: Side::Tunnel,
            bytes,
        });
        Ok(SendOutcome::Buffered)
    }

    /// Returns the next packet for the local TCP stack, if any.
    pub fn poll_terminate(&mut self) -> Option<Pooled> {
        self.terminate.pop_front()
    }

    /// Records resolved addresses used for QUIC backstop and TCP candidacy.
    pub fn inspect_addresses(&mut self, addresses: &[IpAddr], now: Instant) {
        for _ in 0..self.inspected.admit(addresses, now) {
            self.events.push_back(FlowEvent::TransmitDropped);
        }
    }

    /// Queues a DNS answer from the requested resolver address.
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

    /// Copies one packet into the shared pool and queues it for `to`.
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

    /// Answers an over-sized packet with a client-facing ICMP Packet Too Big.
    fn report_too_big(&mut self, buf: &[u8], inner_mtu: Mtu) {
        let Some(mut reply) = self.pool.take_zeroed(self.pool.slice_size().get()) else {
            self.events.push_back(FlowEvent::TransmitDropped);
            return;
        };
        match write_too_big(&mut reply, buf, inner_mtu.get()) {
            Ok(len) => {
                // The ICMP message is shorter than a full pool slice.
                let shrunk = reply.resize(len);
                debug_assert!(shrunk, "an ICMP error is shorter than a slice");
                self.transmits.push_back(Transmit {
                    to: Side::Tunnel,
                    bytes: reply,
                });
                self.events.push_back(FlowEvent::PathReported(inner_mtu));
            }
            // A failed report is counted; the sender can retry the packet.
            Err(_) => self.events.push_back(FlowEvent::TransmitDropped),
        }
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
                // Re-parse the complete datagram so planning uses its real header.
                let packet = IngressPacket::parse(&datagram)?;
                self.dispatch(packet, &datagram, from, now)
            }
        }
    }

    /// Opens or refreshes a flow and reports whether it was newly created.
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

    /// Re-plans every live flow after an egress path change. O(live flows).
    pub fn on_path_change(&mut self, accepts: Accepts, next: PathProperties) {
        self.accepts = accepts;
        self.egress = next;
        // Keep planning errors so later packets receive the same refusal.
        self.plans = Inspection::ALL
            .map(|inspection| plan_flow(self.filter, inspection, accepts, next, self.path_mtu));
        let Self {
            filter,
            path_mtu,
            flows,
            events,
            ..
        } = self;
        let (filter, path_mtu) = (*filter, *path_mtu);

        flows.retain(|endpoint, state| {
            match replan(
                &state.plan,
                filter,
                Inspection::Excluded,
                accepts,
                next,
                path_mtu,
            ) {
                Ok(Replan::Unchanged) => true,
                // Replace the plan with the one matching the new verdict.
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

    /// Returns the earliest deadline for the shell's single timer.
    pub fn poll_timeout(&self) -> Option<Instant> {
        [
            self.reassembler.next_deadline(),
            self.flows.next_deadline(),
            self.inspected.next_deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Expires reassembly, inspection, and flow state.
    pub fn on_timeout(&mut self, now: Instant) {
        let _ = self.reassembler.expire(now);
        self.inspected.expire(now);
        drop(self.flows.expire(now));
    }
}

fn endpoint_of(packet: IngressPacket) -> InternalEndpoint {
    InternalEndpoint {
        address: packet.source,
        port: match packet.transport {
            Transport::Tcp { source_port, .. } | Transport::Udp { source_port, .. } => source_port,
            Transport::Icmp(_) | Transport::Other | Transport::Fragment => 0,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BufferPool, Limits};
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        sync::Arc,
        time::Duration,
    };

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
            inspection_window: Duration::from_secs(60),
            max_inspected_addresses: NonZeroUsize::new(256).unwrap(),
            inspected_ports: crate::DEFAULT_INSPECTED_PORTS,
            origination_ports: None,
        }
    }

    fn egress(fidelity: crate::DatagramFidelity) -> PathProperties {
        PathProperties {
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

    /// A wire-valid IPv4 TCP SYN to port 443.
    fn tcp_syn() -> [u8; 40] {
        let mut packet = [0u8; 40];
        packet[0] = 0x45; // IPv4, 5-word header
        packet[2..4].copy_from_slice(&40u16.to_be_bytes()); // total length
        packet[8] = 64; // TTL
        packet[9] = 6; // TCP
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
        packet[20..22].copy_from_slice(&49152u16.to_be_bytes()); // source port
        packet[22..24].copy_from_slice(&443u16.to_be_bytes()); // destination
        packet[32] = 0x50; // data offset: 5 words
        packet[33] = 0x02; // SYN
        packet
    }

    fn udp_packet() -> [u8; 28] {
        [
            0x45, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2, 0x04,
            0xd2, 0x00, 0x35, 0x00, 0x08, 0, 0,
        ]
    }

    /// A wire-valid IPv4 packet with the given destination, protocol, and port.
    fn ipv4(protocol: u8, destination: [u8; 4], destination_port: u16) -> [u8; 40] {
        let mut packet = [0u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&destination);
        packet[20..22].copy_from_slice(&49152u16.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        if protocol == 6 {
            packet[32] = 0x50; // data offset: 5 words
            packet[33] = 0x02; // SYN
        } else {
            packet[24..26].copy_from_slice(&20u16.to_be_bytes()); // UDP length
        }
        packet
    }

    /// Only TCP to a resolved inspected address on an intercepted port terminates.
    #[test]
    fn only_a_flow_selected_for_inspection_leaves_the_packet_fast_path() {
        const INSPECTED: [u8; 4] = [198, 51, 100, 2];
        const ELSEWHERE: [u8; 4] = [203, 0, 113, 9];

        let mut path = Datapath::new(
            FilterPolicy::InspectHttp,
            DnsPolicy::Intercept,
            Accepts::IpPackets,
            egress(crate::DatagramFidelity::Native),
            Mtu::new(1500).unwrap(),
            limits(8),
            pool(),
        )
        .unwrap();
        let now = Instant::now();

        // Before resolution, the address is not inspected.
        path.on_tun_packet(&ipv4(6, INSPECTED, 443), now).unwrap();
        assert_eq!(
            path.poll_transmit().map(|transmit| transmit.to),
            Some(Side::Egress),
            "an address no answer has named is not inspected"
        );
        assert!(path.poll_terminate().is_none());

        // Resolution makes TCP/443 to the address terminate.
        path.inspect_addresses(&[IpAddr::V4(Ipv4Addr::from(INSPECTED))], now);
        path.on_tun_packet(&ipv4(6, INSPECTED, 443), now).unwrap();
        assert!(
            path.poll_transmit().is_none(),
            "an inspected flow is consumed by the local stack, not forwarded"
        );
        assert!(path.poll_terminate().is_some());

        // Other hosts, ports, and transports retain the packet path.
        for (label, packet) in [
            ("another host on the same port", ipv4(6, ELSEWHERE, 443)),
            ("the same host on another port", ipv4(6, INSPECTED, 22)),
            ("a datagram to the same host", ipv4(17, INSPECTED, 51_820)),
        ] {
            path.on_tun_packet(&packet, now).unwrap();
            assert_eq!(
                path.poll_transmit().map(|transmit| transmit.to),
                Some(Side::Egress),
                "{label} must keep the fast path"
            );
            assert!(path.poll_terminate().is_none(), "{label}");
        }

        // After the window lapses, the flow returns to the packet path.
        path.on_timeout(now + Duration::from_secs(61));
        path.on_tun_packet(&ipv4(6, INSPECTED, 443), now + Duration::from_secs(61))
            .unwrap();
        assert_eq!(
            path.poll_transmit().map(|transmit| transmit.to),
            Some(Side::Egress)
        );
    }

    /// Re-originated connections are excluded from inspection by source port.
    #[test]
    fn this_session_s_own_re_originated_connections_are_never_inspected() {
        const INSPECTED: [u8; 4] = [198, 51, 100, 2];
        let ports = crate::OriginationPorts::new(45_000, 45_010).unwrap();

        let mut path = Datapath::new(
            FilterPolicy::InspectHttp,
            DnsPolicy::Intercept,
            Accepts::IpPackets,
            egress(crate::DatagramFidelity::Native),
            Mtu::new(1500).unwrap(),
            Limits {
                origination_ports: Some(ports),
                ..limits(8)
            },
            pool(),
        )
        .unwrap();
        let now = Instant::now();
        path.inspect_addresses(&[IpAddr::V4(Ipv4Addr::from(INSPECTED))], now);

        // A client connection terminates.
        let mut client = ipv4(6, INSPECTED, 443);
        client[20..22].copy_from_slice(&49_152u16.to_be_bytes());
        path.on_tun_packet(&client, now).unwrap();
        assert!(path.poll_terminate().is_some(), "the client flow is taken");

        // The session's connection uses a reserved source port and crosses as a packet.
        for port in [45_000u16, 45_005, 45_009] {
            let mut originated = ipv4(6, INSPECTED, 443);
            originated[20..22].copy_from_slice(&port.to_be_bytes());
            path.on_tun_packet(&originated, now).unwrap();
            assert_eq!(
                path.poll_transmit().map(|transmit| transmit.to),
                Some(Side::Egress),
                "port {port} must take the fast path"
            );
            assert!(path.poll_terminate().is_none(), "port {port}");
        }

        // A port outside the range is inspected normally.
        let mut outside = ipv4(6, INSPECTED, 443);
        outside[20..22].copy_from_slice(&45_010u16.to_be_bytes());
        path.on_tun_packet(&outside, now).unwrap();
        assert!(
            path.poll_terminate().is_some(),
            "the exclusion must be exactly the range the dialer binds"
        );
    }

    /// Forwarded DNS cannot populate inspection candidacy for packet egress.
    #[test]
    fn a_configuration_that_could_never_inspect_is_refused() {
        assert_eq!(
            Datapath::new(
                FilterPolicy::InspectHttp,
                DnsPolicy::Forward,
                Accepts::IpPackets,
                egress(crate::DatagramFidelity::Native),
                Mtu::new(1500).unwrap(),
                limits(8),
                pool(),
            )
            .err(),
            Some(DatapathError::Vacuous)
        );

        // A stream egress decides through its own termination path.
        assert!(
            Datapath::new(
                FilterPolicy::InspectHttp,
                DnsPolicy::Forward,
                Accepts::Flows,
                egress(crate::DatagramFidelity::Native),
                Mtu::new(1500).unwrap(),
                limits(8),
                pool(),
            )
            .is_ok()
        );
    }

    /// A completed reassembly re-enters dispatch as a full IP packet.
    #[test]
    fn a_reassembled_datagram_re_enters_dispatch_as_a_packet() {
        let mut path = datapath(crate::DatagramFidelity::Native);
        let now = Instant::now();

        // Split the UDP datagram at the IPv4 fragment offset unit.
        let mut head = [0u8; 28];
        head[0] = 0x45;
        head[2..4].copy_from_slice(&28u16.to_be_bytes());
        head[4..6].copy_from_slice(&0xbeefu16.to_be_bytes());
        head[6..8].copy_from_slice(&0x2000u16.to_be_bytes()); // more fragments
        head[8] = 64;
        head[9] = 17;
        head[12..16].copy_from_slice(&[192, 0, 2, 1]);
        head[16..20].copy_from_slice(&[198, 51, 100, 2]);
        head[20..22].copy_from_slice(&1234u16.to_be_bytes());
        head[22..24].copy_from_slice(&53u16.to_be_bytes());
        head[24..26].copy_from_slice(&16u16.to_be_bytes()); // UDP length

        let mut tail = head;
        tail[6..8].copy_from_slice(&1u16.to_be_bytes()); // last fragment, at 8
        tail[20..28].copy_from_slice(b"payload!");

        path.on_tun_packet(&head, now).unwrap();
        assert_eq!(path.poll_event(), None, "one fragment opens nothing");

        path.on_tun_packet(&tail, now)
            .expect("a reassembled datagram is a packet, not a parse failure");
        assert_eq!(
            path.poll_event(),
            Some(FlowEvent::DatagramOpened(InternalEndpoint {
                address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                port: 1234,
            })),
            "the flow is planned from the datagram's own header"
        );
        // The egress receives the whole datagram.
        let datagram = path.poll_datagram().expect("the payload was forwarded");
        assert!(
            datagram.payload.ends_with(b"payload!"),
            "the reassembled payload reached the egress"
        );
    }

    #[test]
    fn fragment_quarantine_then_reassembled_admission() {
        let mut path = datapath(crate::DatagramFidelity::Native);
        let now = Instant::now();

        // A lone fragment is quarantined.
        let mut first = udp_packet();
        first[6] = 0x20; // more fragments, offset 0
        path.on_tun_packet(&first, now).unwrap();
        assert_eq!(path.poll_event(), None);

        // A complete datagram opens one flow.
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

        // MASQUE's QUIC-to-HTTP/2 fallback preserves the flow.
        path.on_path_change(Accepts::Flows, egress(crate::DatagramFidelity::Emulated));
        assert_eq!(
            path.poll_event(),
            Some(FlowEvent::Resteered(SteeringReason::DatagramFidelity))
        );
        assert_eq!(path.poll_event(), None);

        // Traffic continues on the existing mapping.
        path.on_tun_packet(&udp_packet(), now).unwrap();
        assert_eq!(path.poll_event(), None, "a live flow re-opens nothing");
        assert!(path.poll_datagram().is_some());
    }

    #[test]
    fn layer_loss_tears_down_flows() {
        // Open a flow, then remove its accepted layer.
        let now = Instant::now();
        let mut path = datapath(crate::DatagramFidelity::Native);
        path.on_tun_packet(&udp_packet(), now).unwrap();
        let _ = path.poll_event();

        let packets_only = egress(crate::DatagramFidelity::Native);
        path.on_path_change(Accepts::IpPackets, packets_only);
        assert!(matches!(
            path.poll_event(),
            Some(FlowEvent::FlowTornDown(_))
        ));
    }

    #[test]
    fn a_terminated_flow_hands_its_packets_to_the_local_stack() {
        // Terminated TCP packets go to the local stack whole, not to transmit.
        let mut path = datapath(crate::DatagramFidelity::Native);
        let now = Instant::now();
        let syn = tcp_syn();

        path.on_tun_packet(&syn, now).unwrap();
        assert!(matches!(
            path.poll_event(),
            Some(FlowEvent::StreamOpened(_))
        ));
        assert!(
            path.poll_transmit().is_none(),
            "a terminated packet is consumed, not forwarded"
        );
        let captured = path.poll_terminate().expect("the packet was captured");
        assert_eq!(
            *captured,
            syn[..],
            "the whole packet travels, headers and all"
        );
        assert!(path.poll_terminate().is_none(), "exactly one capture");
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
        // Forwarding always crosses the datapath.
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
        // Exhaustion is counted rather than allocated or blocked.
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

        // Releasing the first transmit restores capacity.
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
        // A fresh packet recreates the flow and emits a new event.
        assert!(path.flows.is_empty());
        path.on_tun_packet(&udp_packet(), now + Duration::from_secs(122))
            .unwrap();
        assert!(matches!(
            path.poll_event(),
            Some(FlowEvent::DatagramOpened(_))
        ));
    }

    #[test]
    fn an_unplannable_configuration_is_refused_at_construction() {
        // Excessive overhead leaves no valid inner MTU, so construction fails.
        let starved = egress(crate::DatagramFidelity::Native);
        let starved = PathProperties {
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
        // The per-flow bound preserves fairness before the shared pool fills.
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

        // Fill the per-flow queue.
        path.on_tun_packet(&udp_packet(), now).unwrap();
        let _ = path.poll_event();
        path.on_tun_packet(&udp_packet(), now).unwrap();
        assert_eq!(pool.available(), 6, "queued payloads hold the budget");

        // The third datagram exceeds queue capacity while pool space remains.
        path.on_tun_packet(&udp_packet(), now).unwrap();
        assert_eq!(pool.available(), 6, "the refused buffer was returned");
        assert_eq!(
            path.poll_event(),
            Some(FlowEvent::DatagramDropped(endpoint))
        );

        // Expiry releases the queued buffers through `Drop`.
        path.on_timeout(now + Duration::from_secs(121));
        assert!(path.flows.is_empty());
        assert_eq!(pool.available(), 8);
    }

    /// A flow egress preserves each datagram's target and synthesizes replies.
    #[test]
    fn a_client_datagram_carries_its_target_out_and_its_reply_back() {
        let mut path = datapath(crate::DatagramFidelity::Native);
        let now = Instant::now();
        let client = InternalEndpoint {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            port: 1234,
        };

        path.on_tun_packet(&udp_packet(), now).unwrap();
        let out = path.poll_datagram().expect("the payload was captured");
        assert_eq!(out.client, client);
        assert_eq!(
            out.target,
            std::net::SocketAddr::from(([198, 51, 100, 2], 53)),
            "the destination the client addressed travels with the datagram"
        );
        assert_eq!(&*out.payload, &udp_packet()[28..]);
        assert!(path.poll_datagram().is_none(), "exactly one datagram");

        // The reply is a whole IP packet from the peer to the client.
        let peer = InternalEndpoint {
            address: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            port: 53,
        };
        assert_eq!(
            path.deliver_datagram(client, peer, b"reply", now),
            Ok(SendOutcome::Buffered)
        );
        let transmit = path.poll_transmit().expect("a reply packet");
        assert_eq!(transmit.to, Side::Tunnel);
        let parsed = IngressPacket::parse(&transmit.bytes).expect("a wire-valid packet");
        assert_eq!(parsed.source, peer.address);
        assert_eq!(parsed.destination, client.address);
        assert_eq!(
            parsed.transport,
            Transport::Udp {
                source_port: 53,
                destination_port: 1234
            }
        );
        assert_eq!(parsed.payload(&transmit.bytes), Some(&b"reply"[..]));

        // An expired mapping has no client to receive a reply.
        path.on_timeout(now + Duration::from_secs(121));
        assert_eq!(
            path.deliver_datagram(client, peer, b"late", now + Duration::from_secs(121)),
            Ok(SendOutcome::Dropped)
        );
    }

    /// Round-robin draining prevents one source from starving another.
    #[test]
    fn queued_datagrams_drain_fairly_across_flows() {
        let mut path = datapath(crate::DatagramFidelity::Native);
        let now = Instant::now();

        // Interleave two datagrams from each flow.
        let from = |port: u16| {
            let mut packet = udp_packet();
            packet[20..22].copy_from_slice(&port.to_be_bytes());
            packet
        };
        for _ in 0..2 {
            for port in [1234u16, 5678] {
                path.on_tun_packet(&from(port), now).unwrap();
            }
        }

        let order: Vec<u16> = std::iter::from_fn(|| path.poll_datagram())
            .map(|out| out.client.port)
            .collect();
        assert_eq!(
            order,
            vec![1234, 5678, 1234, 5678],
            "one datagram per flow per turn"
        );
    }

    /// A wire-valid IPv4 ICMP packet between two hosts, carrying `kind`/`code`
    /// and `body`. One builder for both directions, so a test states only the
    /// direction it is about.
    fn icmpv4(source: [u8; 4], destination: [u8; 4], kind: u8, body: &[u8]) -> Vec<u8> {
        let total = 28 + body.len();
        let mut packet = vec![0u8; total];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 1; // ICMP
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet[20] = kind;
        packet[24..26].copy_from_slice(&1u16.to_be_bytes()); // identifier
        packet[28..].copy_from_slice(body);
        packet
    }

    /// A UDP datagram of exactly `total` bytes, with the Don't Fragment bit set
    /// or clear. QUIC is the sender this stands in for: it sets DF and expects
    /// to be told when a packet does not fit.
    fn sized_udp(total: usize, dont_fragment: bool) -> Vec<u8> {
        let mut packet = vec![0u8; total];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        if dont_fragment {
            packet[6] = 0x40;
        }
        packet[8] = 64;
        packet[9] = 17; // UDP
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
        packet[20..22].copy_from_slice(&49152u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        packet[24..26].copy_from_slice(&((total - 20) as u16).to_be_bytes());
        packet
    }

    /// A session over an egress that carries whole IP packets. The fast path is
    /// the case ICMP has to work on, because it is the only one where the
    /// client's own stack is the other end of the conversation.
    fn fast_path() -> Datapath {
        Datapath::new(
            FilterPolicy::PassThrough,
            DnsPolicy::Forward,
            Accepts::IpPackets,
            egress(crate::DatagramFidelity::Native),
            Mtu::new(1500).unwrap(),
            limits(64),
            pool(),
        )
        .unwrap()
    }

    /// **ICMP is not a special case for a packet egress; it is one more
    /// protocol that crosses.** Ping and traceroute work through the tunnel for
    /// exactly this reason, and nothing but a test says so — the forwarding arm
    /// names no transport, so a future refinement of the classifier could
    /// silently stop reaching it.
    #[test]
    fn icmp_crosses_a_packet_egress_in_both_directions() {
        let mut path = fast_path();
        let now = Instant::now();

        let request = icmpv4([192, 0, 2, 1], [198, 51, 100, 2], 8, b"ping payload");
        path.on_tun_packet(&request, now).unwrap();
        let out = path.poll_transmit().expect("the echo request is forwarded");
        assert_eq!(out.to, Side::Egress);
        assert_eq!(&out.bytes[..], &request[..], "whole, byte for byte");

        let reply = icmpv4([198, 51, 100, 2], [192, 0, 2, 1], 0, b"ping payload");
        path.on_egress_packet(&reply, now).unwrap();
        let back = path.poll_transmit().expect("the echo reply is forwarded");
        assert_eq!(back.to, Side::Tunnel);
        assert_eq!(&back.bytes[..], &reply[..]);
    }

    /// **The one error this crate originates.** The client's TUN is 1500 and
    /// the tunnel is 1440, so a 1500-byte QUIC datagram is one the client may
    /// legitimately send and this session cannot carry. Forwarding it to be
    /// fragmented or dropped downstream is a black hole; the sender is told
    /// instead, and learns its path from the answer.
    #[test]
    fn an_oversized_packet_that_forbids_fragmentation_is_answered_not_dropped() {
        let mut path = fast_path();
        let oversized = sized_udp(1500, true);
        path.on_tun_packet(&oversized, Instant::now()).unwrap();

        let reply = path.poll_transmit().expect("the sender is answered");
        assert_eq!(reply.to, Side::Tunnel, "back to the sender, not onward");

        let parsed = IngressPacket::parse(&reply.bytes).unwrap();
        assert_eq!(parsed.source, oversized_destination());
        assert_eq!(parsed.destination, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(reply.bytes[20], 3, "Destination Unreachable");
        assert_eq!(reply.bytes[21], 4, "Fragmentation Needed");
        assert_eq!(
            u16::from_be_bytes([reply.bytes[26], reply.bytes[27]]),
            1440,
            "and it offers the tunnel's real budget"
        );
        assert_eq!(
            &reply.bytes[28..48],
            &oversized[..20],
            "quoting the packet, which is what makes the report credible"
        );
        assert!(
            path.poll_transmit().is_none(),
            "the packet itself does not also go on"
        );
        assert_eq!(
            path.poll_event(),
            Some(FlowEvent::PathReported(Mtu::new(1440).unwrap()))
        );
    }

    fn oversized_destination() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))
    }

    /// The report is for senders who said they cannot fragment. A packet that
    /// permits fragmentation gets the ordinary path, and a packet that fits
    /// was never anyone's problem.
    #[test]
    fn a_packet_that_fits_or_permits_fragmenting_is_forwarded_as_before() {
        let now = Instant::now();
        for (label, packet) in [
            ("fits the tunnel", sized_udp(1400, true)),
            ("permits fragmenting", sized_udp(1500, false)),
        ] {
            let mut path = fast_path();
            path.on_tun_packet(&packet, now).unwrap();
            let out = path.poll_transmit().unwrap_or_else(|| panic!("{label}"));
            assert_eq!(out.to, Side::Egress, "{label} must still cross");
            assert!(
                !matches!(path.poll_event(), Some(FlowEvent::PathReported(_))),
                "{label} is not something to report"
            );
        }
    }

    /// A report is generated for the client's own packets and never for what
    /// arrives from the egress: an over-sized packet coming inward is the
    /// far side's path problem, and answering it would send an ICMP error to a
    /// host that is not this session's sender.
    #[test]
    fn nothing_arriving_from_the_egress_is_reported_on() {
        let mut path = fast_path();
        path.on_egress_packet(&sized_udp(1500, true), Instant::now())
            .unwrap();
        assert_eq!(
            path.poll_transmit().map(|out| out.to),
            Some(Side::Tunnel),
            "forwarded, as every inbound packet is"
        );
        assert!(!matches!(
            path.poll_event(),
            Some(FlowEvent::PathReported(_))
        ));
    }

    /// A UDP datagram over IPv6 of exactly `total` bytes. There is no DF bit to
    /// set: RFC 8200 §4.5 removed in-network fragmentation, so every IPv6
    /// packet is one its sender forbade fragmenting.
    fn sized_udp_v6(total: usize) -> Vec<u8> {
        let mut packet = vec![0u8; total];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((total - 40) as u16).to_be_bytes());
        packet[6] = 17; // UDP
        packet[7] = 64;
        packet[8..24].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
        packet[24..40].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).octets());
        packet[40..42].copy_from_slice(&49152u16.to_be_bytes());
        packet[42..44].copy_from_slice(&443u16.to_be_bytes());
        packet[44..46].copy_from_slice(&((total - 40) as u16).to_be_bytes());
        packet
    }

    /// **IPv6 reports the same fact with a different message, and getting the
    /// two confused is silent.** A v4 report is Destination Unreachable /
    /// Fragmentation Needed with a `u16` MTU in the second header word; a v6
    /// report is Packet Too Big, its own type, with a `u32` MTU one word
    /// earlier. A v4-shaped message on a v6 packet parses as something else
    /// entirely and no stack complains — it just never learns its path.
    #[test]
    fn an_ipv6_report_is_packet_too_big_not_fragmentation_needed() {
        let mut path = fast_path();
        let oversized = sized_udp_v6(1500);
        path.on_tun_packet(&oversized, Instant::now()).unwrap();

        let reply = path.poll_transmit().expect("the sender is answered");
        assert_eq!(reply.to, Side::Tunnel);
        assert_eq!(reply.bytes[6], 58, "next header is ICMPv6, not ICMPv4's 1");
        assert_eq!(reply.bytes[40], 2, "Packet Too Big (RFC 4443 §3.2)");
        assert_eq!(reply.bytes[41], 0, "which has exactly one code");
        assert_eq!(
            u32::from_be_bytes(reply.bytes[44..48].try_into().unwrap()),
            1440,
            "a 32-bit MTU one word earlier than IPv4 puts its 16-bit one"
        );
        assert_eq!(
            &reply.bytes[48..88],
            &oversized[..40],
            "quoting the packet that did not fit"
        );
        assert!(
            reply.bytes.len() <= 1280,
            "RFC 4443 §2.4 (c): an ICMPv6 error never exceeds the IPv6 minimum \
             MTU, or the report itself needs a report"
        );
    }

    /// The ICMPv6 checksum covers a pseudo-header of the IPv6 addresses, the
    /// payload length, and the next-header value; ICMPv4's covers the ICMP
    /// message alone. A v6 message checksummed the v4 way is discarded by every
    /// receiver, and a test that only ever built v4 would never notice.
    #[test]
    fn both_families_checksum_the_way_their_own_rfc_says() {
        let now = Instant::now();
        for (label, oversized) in [
            ("ipv4", sized_udp(1500, true)),
            ("ipv6", sized_udp_v6(1500)),
        ] {
            let mut path = fast_path();
            path.on_tun_packet(&oversized, now).unwrap();
            let reply = path.poll_transmit().unwrap_or_else(|| panic!("{label}"));
            // `from_ip` verifies nothing, so the checksum is recomputed over
            // what was written and compared with what was written.
            let sliced = etherparse::SlicedPacket::from_ip(&reply.bytes)
                .unwrap_or_else(|error| panic!("{label}: {error:?}"));
            let ok = match sliced.transport {
                Some(etherparse::TransportSlice::Icmpv4(icmp)) => {
                    icmp.header().icmp_type.calc_checksum(icmp.payload()) == icmp.header().checksum
                }
                Some(etherparse::TransportSlice::Icmpv6(icmp)) => {
                    let source = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).octets();
                    let destination = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets();
                    icmp.header()
                        .icmp_type
                        .calc_checksum(source, destination, icmp.payload())
                        == Ok(icmp.header().checksum)
                }
                other => panic!("{label}: not an ICMP reply: {other:?}"),
            };
            assert!(ok, "{label}: the checksum does not verify");
        }
    }

    /// RFC 1122 §3.2.2 and RFC 4443 §2.4 (e): an error is never answered with
    /// an error, or two hosts each reporting the other's report never stop.
    /// **The classification differs by family and that is the whole hazard** —
    /// IPv6 says "type below 128", IPv4 says "one of these five", and IPv6's
    /// rule applied to IPv4 would read Echo Request (type 8) as an error and
    /// stop answering the one probe a person can run by hand.
    #[test]
    fn an_oversized_icmp_error_is_not_answered_but_an_oversized_echo_is() {
        let now = Instant::now();
        let mut body = vec![0u8; 1472];
        body[0] = 0x45; // whatever an error would be quoting

        for (label, kind, answered) in [
            ("v4 destination unreachable", 3, false),
            ("v4 time exceeded", 11, false),
            ("v4 redirect", 5, false),
            // **Type 8 is the whole point.** IPv4 calls it Echo Request and
            // answers it; IPv6 has nothing there and, being below 128, calls
            // it an error and stays quiet. One number, two verdicts.
            ("v4 echo request", 8, true),
        ] {
            let mut path = fast_path();
            let packet = {
                let mut packet = icmpv4([192, 0, 2, 1], [198, 51, 100, 2], kind, &body);
                packet[6] = 0x40; // Don't Fragment
                packet
            };
            assert_eq!(packet.len(), 1500, "{label}");
            path.on_tun_packet(&packet, now).unwrap();
            let out = path.poll_transmit().unwrap_or_else(|| panic!("{label}"));
            assert_eq!(
                out.to,
                if answered { Side::Tunnel } else { Side::Egress },
                "{label}"
            );
        }

        for (label, kind, answered) in [
            ("v6 packet too big", 2, false),
            ("v6 type 8, which IPv4 would have answered", 8, false),
            ("v6 echo request", 128, true),
            ("v6 neighbor solicitation", 135, true),
        ] {
            let mut path = fast_path();
            let mut packet = sized_udp_v6(1500);
            packet[6] = 58; // ICMPv6
            packet[40] = kind;
            packet[41] = 0;
            path.on_tun_packet(&packet, now).unwrap();
            let out = path.poll_transmit().unwrap_or_else(|| panic!("{label}"));
            assert_eq!(
                out.to,
                if answered { Side::Tunnel } else { Side::Egress },
                "{label}"
            );
        }
    }
}
