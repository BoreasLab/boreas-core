//! Sans-IO datapath state and policy. It owns no socket, clock, or task.
//! Fragments are reassembled before planning, flows open only after a valid
//! plan, queues are bounded, and every transmit names its destination side.

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

/// Packet source or transmit destination side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Tunnel,
    Egress,
}

impl Side {
    pub fn across(self) -> Self {
        match self {
            Self::Tunnel => Self::Egress,
            Self::Egress => Self::Tunnel,
        }
    }
}

/// A packet queued for one side of the datapath.
///
/// [`Pooled`] owns a pool slot, so a transmit is intentionally not `Clone`.
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
    /// The shared pool could not hold a planned packet.
    TransmitDropped,
    /// The QUIC backstop dropped an attempt.
    QuicSteered,
    /// An oversized packet received an ICMP Packet Too Big for this MTU.
    PathReported(Mtu),
}

/// Resolved inspection addresses and expiry deadlines.
///
/// The bounded map serves QUIC backstop and TCP candidacy; `earliest` avoids a
/// scan on every timer wakeup.
struct InspectedAddresses {
    window: Duration,
    capacity: NonZeroUsize,
    until: HashMap<IpAddr, Instant>,
    /// Earliest stored deadline.
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

    /// Opens or extends the window; returns addresses refused at capacity.
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

    /// Whether the address is live, even before expiry runs.
    fn live(&self, address: &IpAddr, now: Instant) -> bool {
        self.until
            .get(address)
            .is_some_and(|deadline| *deadline > now)
    }

    /// Removes entries whose deadlines have arrived.
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

/// Resource and lifetime bounds for a [`Datapath`].
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub reassembly_timeout: std::time::Duration,
    pub max_pending_reassemblies: NonZeroUsize,
    /// RFC 4787 REQ-5 minimum mapping lifetime.
    pub flow_idle_timeout: std::time::Duration,
    /// Per-flow datagram queue capacity and fairness bound.
    pub datagram_buffer_capacity: NonZeroUsize,
    /// Inspection-address lifetime for QUIC backstop and TCP candidacy.
    pub inspection_window: Duration,
    /// Maximum addresses admitted from network input.
    pub max_inspected_addresses: NonZeroUsize,
    /// TCP ports served by the local stack. A mismatch produces a reset.
    pub inspected_ports: &'static [u16],
    /// Source ports reserved for local re-origination. They prevent recursive
    /// inspection of re-originated connections.
    ///
    /// `None` when the proxy owns re-origination.
    pub origination_ports: Option<OriginationPorts>,
}

pub const DEFAULT_INSPECTED_PORTS: &[u16] = &[80, 443];

/// An intercepted DNS query waiting for shell resolution.
#[derive(Debug, PartialEq, Eq)]
pub struct DnsQuery {
    /// Querying client endpoint.
    pub client: InternalEndpoint,
    /// Resolver endpoint; replies must use it as their source.
    pub resolver: InternalEndpoint,
    /// DNS message without IP or UDP headers.
    pub payload: Pooled,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DatapathError {
    Malformed(PacketError),
    Plan(PlanError),
    FlowTable(FlowTableError),
    /// A synthesized packet could not be encoded.
    Write(WriteError),
    /// Packet egress forwards DNS, so inspection has no candidates.
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

/// One terminated-flow datagram and its remote target.
///
/// RFC 4787 endpoint-independent mapping lets one local UDP port reach many
/// peers, so each datagram carries its target.
#[derive(Debug, PartialEq, Eq)]
pub struct Outbound {
    /// Client mapping for the egress association.
    pub client: InternalEndpoint,
    /// Peer addressed by this datagram.
    pub target: std::net::SocketAddr,
    pub payload: Pooled,
}

struct FlowState {
    plan: FlowPlan,
    /// Client datagrams waiting for egress. Storage is globally pooled and
    /// bounded per flow; replies become synchronous tunnel-bound transmits.
    buffer: DatagramBuffer<(std::net::SocketAddr, Pooled)>,
}

pub struct Datapath {
    filter: FilterPolicy,
    dns: DnsPolicy,
    /// Layer accepted by the configured egress.
    accepts: Accepts,
    egress: PathProperties,
    path_mtu: Mtu,
    /// Cached plan for each [`Inspection`] verdict. The array preserves errors
    /// on the packet path without a separate cache key.
    plans: [Result<FlowPlan, PlanError>; 2],
    /// Sorted interception ports for binary search.
    inspected_ports: Box<[u16]>,
    /// Source ports reserved by this session's re-originated connections.
    origination_ports: Option<OriginationPorts>,
    /// Shared storage for forwarded packets and queued datagrams.
    pool: Arc<BufferPool>,
    datagram_buffer_capacity: NonZeroUsize,
    reassembler: Reassembler,
    inspected: InspectedAddresses,
    flows: UdpFlowTable<FlowState>,
    events: VecDeque<FlowEvent>,
    transmits: VecDeque<Transmit>,
    queries: VecDeque<DnsQuery>,
    /// Terminated-flow packets waiting for the shell's TCP stack.
    terminate: VecDeque<Pooled>,
    /// Non-empty flows in round-robin order. Stale entries are skipped; each
    /// receive and requeue is amortized O(1).
    ready: VecDeque<InternalEndpoint>,
}

impl Datapath {
    /// `pool` must provide slices at least as large as `path_mtu`; larger
    /// packets are dropped and counted when no slice can hold them.
    pub fn new(
        filter: FilterPolicy,
        dns: DnsPolicy,
        accepts: Accepts,
        egress: PathProperties,
        path_mtu: Mtu,
        limits: Limits,
        pool: Arc<BufferPool>,
    ) -> Result<Self, DatapathError> {
        // Forwarded DNS cannot populate inspection candidacy on packet egress.
        if filter == FilterPolicy::InspectHttp
            && dns == DnsPolicy::Forward
            && accepts == Accepts::IpPackets
        {
            return Err(DatapathError::Vacuous);
        }
        let plans = Inspection::ALL
            .map(|inspection| plan_flow(filter, inspection, accepts, egress, path_mtu));
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

    fn plan(&self, inspection: Inspection) -> Result<FlowPlan, PlanError> {
        self.plans[inspection.index()]
    }

    fn inspection(&self, packet: IngressPacket, from: Side, now: Instant) -> Inspection {
        let Transport::Tcp {
            source_port,
            destination_port,
        } = packet.transport
        else {
            return Inspection::Excluded;
        };
        // Do not inspect connections originated by this session.
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

    pub fn on_tun_packet(&mut self, buf: &[u8], now: Instant) -> Result<(), DatapathError> {
        let packet = IngressPacket::parse(buf)?;
        self.dispatch(packet, buf, Side::Tunnel, now)
    }

    pub fn on_egress_packet(&mut self, buf: &[u8], now: Instant) -> Result<(), DatapathError> {
        let packet = IngressPacket::parse(buf)?;
        // Egress input must already be reassembled.
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
        // Apply steering only to outbound attempts.
        let backstop = match from {
            Side::Tunnel if self.inspected.live(&packet.destination, now) => Backstop::Active,
            Side::Tunnel | Side::Egress => Backstop::Lapsed,
        };
        // Resolve path-independent admission before planning.
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
                    // MSS clamping applies only to the initial SYN.
                    TransportPath::PacketFastPath { inner_mtu } => {
                        // Report oversized DF packets locally so the sender learns
                        // the inner MTU. RFC 1122 Sec. 3.2.2 and RFC 4443 Sec. 2.4(e)
                        // prohibit answering ICMP errors with errors.
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
                // The shell owns TCP; capture only the client-facing packet.
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
                // Capture client datagrams; replies use the association.
                if from == Side::Tunnel {
                    self.capture_datagram(packet, buf, endpoint);
                }
                Ok(())
            }
            IngressAction::HandleIcmp(_) => {
                // The effect shell owns client-facing PTB generation.
                self.forward(buf, from.across(), None);
                Ok(())
            }
            IngressAction::DropUnsupported => Ok(()),
        }
    }

    /// Captures a DNS query for the shell within the shared pool budget.
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

    pub fn pool(&self) -> &Arc<BufferPool> {
        &self.pool
    }

    fn capture_for_termination(&mut self, buf: &[u8]) {
        match self.pool.take(buf) {
            Some(packet) => self.terminate.push_back(packet),
            None => self.events.push_back(FlowEvent::TransmitDropped),
        }
    }

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
        // Admission and capture can cross flow expiry.
        let Some(flow) = self.flows.get_mut(&client) else {
            self.events.push_back(FlowEvent::TransmitDropped);
            return;
        };
        // Add one ready-list entry per empty-to-non-empty transition.
        let was_idle = flow.buffer.is_empty();
        if flow.buffer.try_send((target, payload)) == SendOutcome::Dropped {
            self.events.push_back(FlowEvent::DatagramDropped(client));
            return;
        }
        if was_idle {
            self.ready.push_back(client);
        }
    }

    /// Returns one queued datagram in round-robin order. Amortized O(1).
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

    /// Delivers an egress datagram as a packet for its client.
    /// RFC 4787 REQ-6 also refreshes the mapping.
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

    pub fn poll_terminate(&mut self) -> Option<Pooled> {
        self.terminate.pop_front()
    }

    /// Records resolved addresses for QUIC backstop and TCP candidacy.
    pub fn inspect_addresses(&mut self, addresses: &[IpAddr], now: Instant) {
        for _ in 0..self.inspected.admit(addresses, now) {
            self.events.push_back(FlowEvent::TransmitDropped);
        }
    }

    /// Queues a DNS answer sourced from the requested resolver.
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

    /// Answers an oversized packet with a client-facing ICMP Packet Too Big.
    fn report_too_big(&mut self, buf: &[u8], inner_mtu: Mtu) {
        let Some(mut reply) = self.pool.take_zeroed(self.pool.slice_size().get()) else {
            self.events.push_back(FlowEvent::TransmitDropped);
            return;
        };
        match write_too_big(&mut reply, buf, inner_mtu.get()) {
            Ok(len) => {
                // ICMP output is shorter than a full pool slice.
                let shrunk = reply.resize(len);
                debug_assert!(shrunk, "an ICMP error is shorter than a slice");
                self.transmits.push_back(Transmit {
                    to: Side::Tunnel,
                    bytes: reply,
                });
                self.events.push_back(FlowEvent::PathReported(inner_mtu));
            }
            // Count a failed report; the sender can retry.
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
                // Plan from the completed datagram's actual header.
                let packet = IngressPacket::parse(&datagram)?;
                self.dispatch(packet, &datagram, from, now)
            }
        }
    }

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

    /// Re-plans live flows after an egress path change. O(live flows).
    pub fn on_path_change(&mut self, accepts: Accepts, next: PathProperties) {
        self.accepts = accepts;
        self.egress = next;
        // Preserve planning errors for later packet refusals.
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
                // Store the plan for the new verdict.
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

    /// Returns the earliest deadline for the shell's shared timer.
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

    fn tcp_syn() -> [u8; 40] {
        let mut packet = [0u8; 40];
        packet[0] = 0x45; // IPv4 with a five-word header
        packet[2..4].copy_from_slice(&40u16.to_be_bytes()); // total length
        packet[8] = 64; // time to live
        packet[9] = 6; // TCP protocol
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
        packet[20..22].copy_from_slice(&49152u16.to_be_bytes()); // source port
        packet[22..24].copy_from_slice(&443u16.to_be_bytes()); // destination port
        packet[32] = 0x50; // five-word TCP header
        packet[33] = 0x02; // SYN flag
        packet
    }

    fn udp_packet() -> [u8; 28] {
        [
            0x45, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2, 0x04,
            0xd2, 0x00, 0x35, 0x00, 0x08, 0, 0,
        ]
    }

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
            packet[32] = 0x50; // five-word TCP header
            packet[33] = 0x02; // SYN flag
        } else {
            packet[24..26].copy_from_slice(&20u16.to_be_bytes()); // UDP length
        }
        packet
    }

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

        // An address is not inspected before resolution.
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

        // Other hosts, ports, and transports retain packet forwarding.
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

        // Expiry returns the flow to packet forwarding.
        path.on_timeout(now + Duration::from_secs(61));
        path.on_tun_packet(&ipv4(6, INSPECTED, 443), now + Duration::from_secs(61))
            .unwrap();
        assert_eq!(
            path.poll_transmit().map(|transmit| transmit.to),
            Some(Side::Egress)
        );
    }

    /// Re-originated connections are excluded by source port.
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

        // The client connection terminates.
        let mut client = ipv4(6, INSPECTED, 443);
        client[20..22].copy_from_slice(&49_152u16.to_be_bytes());
        path.on_tun_packet(&client, now).unwrap();
        assert!(path.poll_terminate().is_some(), "the client flow is taken");

        // Reserved source ports take the packet path.
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

        let mut outside = ipv4(6, INSPECTED, 443);
        outside[20..22].copy_from_slice(&45_010u16.to_be_bytes());
        path.on_tun_packet(&outside, now).unwrap();
        assert!(
            path.poll_terminate().is_some(),
            "the exclusion must be exactly the range the dialer binds"
        );
    }

    /// Forwarded DNS cannot create inspection candidates for packet egress.
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

    /// Completed reassembly re-enters dispatch as a full IP packet.
    #[test]
    fn a_reassembled_datagram_re_enters_dispatch_as_a_packet() {
        let mut path = datapath(crate::DatagramFidelity::Native);
        let now = Instant::now();

        // Split the UDP datagram at an IPv4 fragment-offset boundary.
        let mut head = [0u8; 28];
        head[0] = 0x45;
        head[2..4].copy_from_slice(&28u16.to_be_bytes());
        head[4..6].copy_from_slice(&0xbeefu16.to_be_bytes());
        head[6..8].copy_from_slice(&0x2000u16.to_be_bytes()); // more fragments
        head[8] = 64; // time to live
        head[9] = 17; // UDP protocol
        head[12..16].copy_from_slice(&[192, 0, 2, 1]);
        head[16..20].copy_from_slice(&[198, 51, 100, 2]);
        head[20..22].copy_from_slice(&1234u16.to_be_bytes());
        head[22..24].copy_from_slice(&53u16.to_be_bytes());
        head[24..26].copy_from_slice(&16u16.to_be_bytes()); // UDP length

        let mut tail = head;
        tail[6..8].copy_from_slice(&1u16.to_be_bytes()); // final fragment at offset 8
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

        let mut first = udp_packet();
        first[6] = 0x20; // more fragments, offset 0
        path.on_tun_packet(&first, now).unwrap();
        assert_eq!(path.poll_event(), None);

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

        path.on_path_change(Accepts::Flows, egress(crate::DatagramFidelity::Emulated));
        assert_eq!(
            path.poll_event(),
            Some(FlowEvent::Resteered(SteeringReason::DatagramFidelity))
        );
        assert_eq!(path.poll_event(), None);

        path.on_tun_packet(&udp_packet(), now).unwrap();
        assert_eq!(path.poll_event(), None, "a live flow re-opens nothing");
        assert!(path.poll_datagram().is_some());
    }

    #[test]
    fn layer_loss_tears_down_flows() {
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

        path.on_tun_packet(&udp_packet(), now).unwrap();
        let _ = path.poll_event();
        path.on_tun_packet(&udp_packet(), now).unwrap();
        assert_eq!(pool.available(), 6, "queued payloads hold the budget");

        path.on_tun_packet(&udp_packet(), now).unwrap();
        assert_eq!(pool.available(), 6, "the refused buffer was returned");
        assert_eq!(
            path.poll_event(),
            Some(FlowEvent::DatagramDropped(endpoint))
        );

        path.on_timeout(now + Duration::from_secs(121));
        assert!(path.flows.is_empty());
        assert_eq!(pool.available(), 8);
    }

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

        path.on_timeout(now + Duration::from_secs(121));
        assert_eq!(
            path.deliver_datagram(client, peer, b"late", now + Duration::from_secs(121)),
            Ok(SendOutcome::Dropped)
        );
    }

    #[test]
    fn queued_datagrams_drain_fairly_across_flows() {
        let mut path = datapath(crate::DatagramFidelity::Native);
        let now = Instant::now();

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

    fn icmpv4(source: [u8; 4], destination: [u8; 4], kind: u8, body: &[u8]) -> Vec<u8> {
        let total = 28 + body.len();
        let mut packet = vec![0u8; total];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 1; // ICMP protocol
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet[20] = kind;
        packet[24..26].copy_from_slice(&1u16.to_be_bytes()); // identifier
        packet[28..].copy_from_slice(body);
        packet
    }

    fn sized_udp(total: usize, dont_fragment: bool) -> Vec<u8> {
        let mut packet = vec![0u8; total];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        if dont_fragment {
            packet[6] = 0x40;
        }
        packet[8] = 64;
        packet[9] = 17; // UDP protocol
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
        packet[20..22].copy_from_slice(&49152u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        packet[24..26].copy_from_slice(&((total - 20) as u16).to_be_bytes());
        packet
    }

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

    /// Builds an IPv6 UDP datagram of exactly `total` bytes.
    /// RFC 8200 Sec. 4.5 provides no in-network fragmentation bit.
    fn sized_udp_v6(total: usize) -> Vec<u8> {
        let mut packet = vec![0u8; total];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((total - 40) as u16).to_be_bytes());
        packet[6] = 17; // UDP next header
        packet[7] = 64;
        packet[8..24].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
        packet[24..40].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).octets());
        packet[40..42].copy_from_slice(&49152u16.to_be_bytes());
        packet[42..44].copy_from_slice(&443u16.to_be_bytes());
        packet[44..46].copy_from_slice(&((total - 40) as u16).to_be_bytes());
        packet
    }

    /// IPv6 uses Packet Too Big with a 32-bit MTU field, not IPv4's
    /// Fragmentation Needed message and 16-bit field.
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

    /// ICMPv6 includes the IPv6 pseudo-header in its checksum; ICMPv4 does not.
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

    /// RFC 1122 Sec. 3.2.2 and RFC 4443 Sec. 2.4(e) prohibit error replies to
    /// errors. IPv4 and IPv6 classify ICMP errors differently.
    #[test]
    fn an_oversized_icmp_error_is_not_answered_but_an_oversized_echo_is() {
        let now = Instant::now();
        let mut body = vec![0u8; 1472];
            body[0] = 0x45; // quoted IPv4 header marker

        for (label, kind, answered) in [
            ("v4 destination unreachable", 3, false),
            ("v4 time exceeded", 11, false),
            ("v4 redirect", 5, false),
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
            packet[6] = 58; // ICMPv6 next header
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
