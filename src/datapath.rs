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
    /// A QUIC attempt dropped by the steering backstop. Per packet while a
    /// browser retries, so folded into a counter; the count is the
    /// convergence signal [Filtering](../docs/filtering.md) asks for.
    QuicSteered,
    /// An over-sized packet was answered with an ICMP Packet Too Big naming
    /// this MTU. Per over-sized packet until the sender's path discovery
    /// converges, so the shell folds it into a counter — a count that stays
    /// high is a client whose link MTU was configured wider than the tunnel.
    PathReported(Mtu),
}

/// The addresses an inspected host was seen to resolve to, and until when.
///
/// **One index, two facts, one probe.** An address lands here because the
/// resolver rewrote an answer for a host this session inspects, and that single
/// fact decides both of the things the datapath needs to know about a packet
/// bound for it:
///
/// - a QUIC attempt to it is refused ([`Backstop::Active`]), because DNS
///   steering alone only stops a browser with no cached Alt-Svc entry, and
/// - a TCP flow to it on an intercepted port is a candidate for local
///   termination ([`Inspection::Candidate`]), because there is no other signal
///   available before the connection this session has not yet terminated.
///
/// Deriving both from one entry is what keeps them from disagreeing: an
/// address whose QUIC is being refused so that the browser re-races to TCP,
/// but whose TCP is then forwarded past the interceptor, is a steering that
/// achieves nothing.
///
/// A `HashMap` and not a timer wheel. The set is bounded by the inspected
/// hosts on a deliberately small allowlist times their addresses, so it holds
/// tens of entries: an O(1) probe per packet is what the hot path needs, and a
/// timer wheel over tens of entries would be a segment tree where a prefix sum
/// suffices. The earliest deadline is kept rather than searched, because the
/// reactor reads it once per wakeup and wakeups are what the performance budget
/// is written against.
struct InspectedAddresses {
    window: Duration,
    capacity: NonZeroUsize,
    until: HashMap<IpAddr, Instant>,
    /// The minimum of `until`'s values, maintained on insert in O(1) and
    /// recomputed on the sweep that empties them in O(entries).
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

    /// Opens or extends the window for each address. Returns how many were
    /// refused because the index is full — a bound on state fed by network
    /// input, like every other queue in this crate.
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

    /// Whether this address still belongs to an inspected host. O(1), and the
    /// real deadline governs, so an entry the sweep has not reached yet still
    /// lapses on time.
    fn live(&self, address: &IpAddr, now: Instant) -> bool {
        self.until
            .get(address)
            .is_some_and(|deadline| *deadline > now)
    }

    /// O(entries), and only when the earliest deadline has arrived.
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
    /// How long an inspected host's addresses stay in the index after the
    /// answer that named them.
    ///
    /// It governs both facts the index carries: how long QUIC to those
    /// addresses is refused, and how long a TCP flow to them is a candidate for
    /// termination. It must outlast a browser's cached Alt-Svc entry for the
    /// origin, which is what the DNS rewrite alone cannot reach, and it costs
    /// nothing when no host is inspected. Convergence within one window is the
    /// P13 gate, so this is configuration rather than a constant.
    pub inspection_window: Duration,
    /// How many addresses the index may hold. A bound on state fed by network
    /// input; the inspected allowlist is deliberately small.
    pub max_inspected_addresses: NonZeroUsize,
    /// The TCP ports interception serves.
    ///
    /// **This must be the same set the local TCP stack listens on.** A flow
    /// routed to termination on a port nothing listens for is answered with a
    /// RST, so the two disagreeing is a refused connection rather than an
    /// unfiltered one — which is why the number lives in configuration both
    /// halves read rather than being written twice.
    pub inspected_ports: &'static [u16],
    /// The local source ports a re-originated connection binds, when this
    /// session re-originates through its own tunnel.
    ///
    /// **Excluding them is what stops an infinite regress.** A re-originated
    /// connection is TCP to the very address and port that made the original
    /// flow a candidate for inspection, so without this it would be selected
    /// too, terminated again, and re-originated again — spending the socket
    /// ceiling on one page load. The value comes from
    /// [`TunnelledDialer::ports`](crate::TunnelledDialer::ports), so the range
    /// the dialer binds and the range this excludes are one value rather than
    /// two that must be kept equal.
    ///
    /// `None` for a session whose egress accepts flows: nothing is
    /// re-originated locally there, because the proxy does it.
    pub origination_ports: Option<OriginationPorts>,
}

/// The ports HTTP interception serves: HTTPS, and cleartext HTTP for the
/// redirects that lead to it.
pub const DEFAULT_INSPECTED_PORTS: &[u16] = &[80, 443];

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
    /// Inspection is enabled on a packet egress whose DNS is forwarded, so no
    /// flow could ever become a candidate for it. Refused at construction
    /// rather than discovered as an absence of filtering months later.
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

/// One datagram of a terminated flow, on its way out to the egress.
///
/// **The target belongs to the datagram, not to the flow.** A UDP socket is
/// unconnected: one client source port talks to as many peers as it likes, and
/// that is exactly what RFC 4787's endpoint-independent mapping promises to
/// preserve. Keying the flow by the client and carrying the peer per datagram
/// is what makes that promise expressible; a queue of bare payloads, which is
/// what this used to be, has already thrown the destination away.
#[derive(Debug, PartialEq, Eq)]
pub struct Outbound {
    /// The client mapping this belongs to. It names the association to send
    /// through, and it is what a reply will be addressed back to.
    pub client: InternalEndpoint,
    /// Where the client addressed this datagram.
    pub target: std::net::SocketAddr,
    pub payload: Pooled,
}

struct FlowState {
    plan: FlowPlan,
    /// Client datagrams waiting for the egress to take them.
    ///
    /// Payload bytes live in the shared `BufferPool`, so queue memory is one
    /// global budget rather than `flows x depth x MTU`. The per-flow capacity
    /// remains the fairness bound: no single flow can spend the whole pool.
    ///
    /// The *return* direction has no queue at all, and deliberately: a reply is
    /// written straight through as a tunnel-bound transmit, because the only
    /// consumer is the device the reactor drains synchronously. Queueing there
    /// would add latency without adding a bound the pool does not already give.
    buffer: DatagramBuffer<(std::net::SocketAddr, Pooled)>,
}

pub struct Datapath {
    filter: FilterPolicy,
    dns: DnsPolicy,
    /// The layer the configured egress accepts. Separate from the path
    /// properties because the layer belongs to the implementation variant,
    /// established by the caller from [`crate::Egress`] and unable to drift
    /// from it there.
    accepts: Accepts,
    egress: PathProperties,
    path_mtu: Mtu,
    /// The planning decision for the current configuration, memoized — one per
    /// [`Inspection`] verdict, indexed by [`Inspection::index`].
    ///
    /// Every *other* input to `plan_flow` — filter policy, accepted layer,
    /// path properties, path MTU — is a session property, so the answer moves
    /// only when the configuration does. The verdict is the one per-flow input,
    /// and it ranges over a two-element closed sum, so memoizing the whole
    /// function is a two-element array rather than a cache: there is no key to
    /// miss and nothing to evict. Holding the `Result` keeps a failing
    /// configuration's behavior exactly as it was — every packet counted and
    /// refused — while making the succeeding case an array read.
    plans: [Result<FlowPlan, PlanError>; 2],
    /// The ports interception serves, sorted so membership is a binary search.
    /// A handful of entries in practice, so the search is not the point; the
    /// sort is, because it makes the set canonical.
    inspected_ports: Box<[u16]>,
    /// The source ports this session's own re-originated connections bind, and
    /// which must therefore never be selected for inspection.
    origination_ports: Option<OriginationPorts>,
    /// Payload storage for forwarded packets and queued datagrams alike. One
    /// budget, `capacity x slice_size`, for everything the core holds.
    pool: Arc<BufferPool>,
    datagram_buffer_capacity: NonZeroUsize,
    reassembler: Reassembler,
    inspected: InspectedAddresses,
    flows: UdpFlowTable<FlowState>,
    events: VecDeque<FlowEvent>,
    transmits: VecDeque<Transmit>,
    queries: VecDeque<DnsQuery>,
    /// Packets of terminated flows, waiting for the shell's local TCP stack.
    /// Pooled, so pending termination cannot outgrow the shared budget.
    terminate: VecDeque<Pooled>,
    /// Flows with at least one queued datagram, in the order they became
    /// non-empty.
    ///
    /// **A ready-list, so draining is round-robin and O(1).** Sweeping the flow
    /// table for work would be O(live flows) per datagram at the 10,000-flow
    /// target, and taking a flow's whole queue before moving on would let one
    /// noisy source starve every other. Popping the front flow, taking one
    /// datagram, and re-queueing it behind the others is both, in constant
    /// time. An entry can outlive its flow — expiry does not scan this — so a
    /// pop that finds nothing is skipped rather than trusted, which is the same
    /// discipline the timer wheel's stale slots already use.
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
        // **A configuration that can never inspect anything is refused here.**
        // Candidacy is read out of an index only the local resolver fills, so a
        // packet-egress session that forwards DNS would enable inspection and
        // then never find a flow to inspect — silently, and for the life of the
        // session. Parse, do not validate: the combination is rejected where it
        // is stated rather than diagnosed later from an absence of traffic.
        if filter == FilterPolicy::InspectHttp
            && dns == DnsPolicy::Forward
            && accepts == Accepts::IpPackets
        {
            return Err(DatapathError::Vacuous);
        }
        // Parse, do not validate: a `Datapath` exists only for a configuration
        // that plans, and the proof is kept rather than recomputed.
        let plans = Inspection::ALL
            .map(|inspection| plan_flow(filter, inspection, accepts, egress, path_mtu));
        // Every verdict must plan, or a flow could be admitted into a
        // configuration that cannot serve it.
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

    /// The plan for a flow with this verdict. An array read on the hot path.
    fn plan(&self, inspection: Inspection) -> Result<FlowPlan, PlanError> {
        self.plans[inspection.index()]
    }

    /// Whether the packet in front of us belongs to a flow this session must
    /// terminate to inspect.
    ///
    /// One hash probe and one membership test on a handful of ports, and only
    /// for TCP: there is no UDP interception, so a datagram is never a
    /// candidate however inspected its destination is. Packets arriving from
    /// the egress are never candidates either — a terminated flow's upstream
    /// leg is originated by the terminator, so nothing inbound belongs to one.
    fn inspection(&self, packet: IngressPacket, from: Side, now: Instant) -> Inspection {
        let Transport::Tcp {
            source_port,
            destination_port,
        } = packet.transport
        else {
            return Inspection::Excluded;
        };
        // **This session's own re-originated connections are never inspected.**
        // Each is TCP to exactly the address and port that selected the flow it
        // re-originates, so without this it would be terminated and
        // re-originated forever — a regress that spends the socket ceiling on a
        // single page load. The range is the dialer's own, so the exclusion and
        // the binding cannot disagree.
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
        // The backstop applies only outward: an inbound packet to port 443 is
        // a response, and steering acts on attempts. Passing `Lapsed` for the
        // egress side makes that a property of the call rather than a check
        // inside the classifier.
        let backstop = match from {
            Side::Tunnel if self.inspected.live(&packet.destination, now) => Backstop::Active,
            Side::Tunnel | Side::Egress => Backstop::Lapsed,
        };
        // `admit` settles everything no path properties could change, which
        // is also everything that must keep working under a configuration that
        // cannot plan at all: reassembly, unsupported protocols, DNS, and the
        // steering backstop.
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
                    // The clamp is the only mechanism that reaches a terminated
                    // path's segment size; on non-SYN packets it is a no-op.
                    TransportPath::PacketFastPath { inner_mtu } => {
                        // **The client's link is wider than the tunnel, and
                        // something has to say so.** The TUN is `path_mtu`
                        // wide; the tunnel is narrower by the egress's
                        // overhead. TCP never reaches this — its MSS was
                        // clamped on the SYN — so what does is QUIC, which
                        // sets DF and learns its path from exactly this
                        // message. Forwarding it to be fragmented or dropped
                        // downstream is a black hole the sender cannot see.
                        //
                        // An ICMP *error* is the one thing never answered: RFC
                        // 1122 §3.2.2 and RFC 4443 §2.4 (e) both forbid it,
                        // because two hosts each reporting the other's report
                        // is a loop. An echo is fair game — `ping -M do` is how
                        // a person discovers a path MTU by hand.
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
                // A terminated flow's packets belong to the local TCP stack,
                // which lives in the shell: the core owns no socket and cannot
                // run a state machine that must answer with segments of its
                // own. Only the client's side is captured — the terminator
                // originates its own upstream connection, so nothing arrives
                // for this flow from the egress.
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
                // A terminated datagram flow's payload belongs to the egress's
                // association, exactly as a terminated stream's packets belong
                // to the local TCP stack. Only the client's side is captured:
                // a reply arrives through the association and re-enters as a
                // synthesized packet, never as an egress-side IP packet.
                if from == Side::Tunnel {
                    self.capture_datagram(packet, buf, endpoint);
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

    /// The budget every payload this core holds is drawn from.
    ///
    /// Exposed so the shell's resolver builds its answers on the same one:
    /// a response that lives in its own `Vec` is memory nothing accounts for,
    /// and under a query flood that is exactly the memory that matters.
    pub fn pool(&self) -> &Arc<BufferPool> {
        &self.pool
    }

    /// Copies one packet of a terminated flow for the local TCP stack.
    ///
    /// The whole IP packet travels, not its payload: the terminator is a real
    /// stack that parses headers, computes checksums, and answers with
    /// segments of its own. A packet that will not fit the shared budget is a
    /// counted drop, and TCP retransmits — which is the same discipline the
    /// forward path already applies to congestion.
    fn capture_for_termination(&mut self, buf: &[u8]) {
        match self.pool.take(buf) {
            Some(packet) => self.terminate.push_back(packet),
            None => self.events.push_back(FlowEvent::TransmitDropped),
        }
    }

    /// Queues one client datagram for the egress's association.
    ///
    /// The peer travels with the payload rather than with the flow, because one
    /// client port talks to many peers; see [`Outbound`]. A payload that will
    /// not fit the shared budget, or a flow whose queue is full, is a counted
    /// drop — which is what a UDP source already expects and what a stub
    /// resolver, a QUIC stack, and a video codec all recover from.
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
        // The flow was created or refreshed by `open_flow` immediately above,
        // so this lookup cannot miss; a miss would mean the datagram had
        // nowhere to be fair against, and dropping is the answer that cannot
        // be wrong.
        let Some(flow) = self.flows.get_mut(&client) else {
            self.events.push_back(FlowEvent::TransmitDropped);
            return;
        };
        // The ready-list gets one entry per empty-to-non-empty transition, so
        // a flood of datagrams on one flow adds no scheduling state.
        let was_idle = flow.buffer.is_empty();
        if flow.buffer.try_send((target, payload)) == SendOutcome::Dropped {
            self.events.push_back(FlowEvent::DatagramDropped(client));
            return;
        }
        if was_idle {
            self.ready.push_back(client);
        }
    }

    /// The next client datagram bound for the egress, if any.
    ///
    /// Round-robin across flows with work, one datagram per turn. O(1)
    /// amortised: each pop either yields a datagram or retires a stale entry,
    /// and stale entries are bounded by the number of flows that have ever had
    /// work.
    pub fn poll_datagram(&mut self) -> Option<Outbound> {
        while let Some(client) = self.ready.pop_front() {
            let Some(flow) = self.flows.get_mut(&client) else {
                continue; // the flow expired; its queue went with it
            };
            let Some((target, payload)) = flow.buffer.recv() else {
                continue; // drained by an earlier turn
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

    /// Delivers one datagram from the egress back to the client that owns the
    /// mapping, as a synthesized IP packet.
    ///
    /// **The mapping is refreshed here as well as on the outbound side**, which
    /// is what RFC 4787 REQ-6 requires: a mapping kept alive only by outbound
    /// traffic expires under a long-lived download, and the peer's datagrams
    /// then arrive with nowhere to go.
    ///
    /// `peer` is where the datagram came from, and it becomes the packet's
    /// source, because a client that sent to one address and heard from another
    /// discards the reply.
    pub fn deliver_datagram(
        &mut self,
        client: InternalEndpoint,
        peer: InternalEndpoint,
        payload: &[u8],
        now: Instant,
    ) -> Result<SendOutcome, DatapathError> {
        // A datagram for a mapping this core does not hold is a datagram whose
        // flow has expired: there is no client left expecting it.
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

    /// The next packet bound for the local TCP stack, if any.
    ///
    /// The dual of [`poll_transmit`](Self::poll_transmit) for terminated flows:
    /// those packets are not forwarded anywhere, they are *consumed* by a stack
    /// the shell owns, and whatever it answers re-enters as an ordinary
    /// tunnel-bound write.
    pub fn poll_terminate(&mut self) -> Option<Pooled> {
        self.terminate.pop_front()
    }

    /// Records the addresses an inspected host just resolved to.
    ///
    /// Called by the shell after a resolution whose policy steers; the core
    /// never learns an address any other way, which is what keeps the index
    /// exactly as large as the inspected allowlist made it. From this moment
    /// both facts hold for those addresses: QUIC to them is refused, and TCP to
    /// them on an intercepted port is a candidate for termination.
    ///
    /// O(addresses), with a hash insert each.
    pub fn inspect_addresses(&mut self, addresses: &[IpAddr], now: Instant) {
        for _ in 0..self.inspected.admit(addresses, now) {
            self.events.push_back(FlowEvent::TransmitDropped);
        }
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

    /// Answers an over-sized packet with the ICMP Packet Too Big its sender
    /// needs, on the same budget every other payload draws from.
    ///
    /// The reply goes back to the tunnel, which is where the sender is; it is
    /// never forwarded on, because the packet it reports on was not.
    ///
    /// O(quoted length), bounded by the family's ICMP ceiling.
    fn report_too_big(&mut self, buf: &[u8], inner_mtu: Mtu) {
        let Some(mut reply) = self.pool.take_zeroed(self.pool.slice_size().get()) else {
            self.events.push_back(FlowEvent::TransmitDropped);
            return;
        };
        match write_too_big(&mut reply, buf, inner_mtu.get()) {
            Ok(len) => {
                // The buffer came from this pool at its full slice size and
                // the message is shorter, so the shrink cannot be refused.
                let shrunk = reply.resize(len);
                debug_assert!(shrunk, "an ICMP error is shorter than a slice");
                self.transmits.push_back(Transmit {
                    to: Side::Tunnel,
                    bytes: reply,
                });
                self.events.push_back(FlowEvent::PathReported(inner_mtu));
            }
            // Unreachable for a packet that parsed once already, and a counted
            // drop rather than an error: the sender retries, which is what it
            // would do for the packet this could not answer.
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

    /// Re-plans every live flow after the egress reports a path change.
    ///
    /// O(live flows), one `replan` per flow and no intermediate event buffer:
    /// destructuring `self` borrows the flow table and the event queue as the
    /// disjoint fields they are, which matters at the 10,000-flow target.
    pub fn on_path_change(&mut self, accepts: Accepts, next: PathProperties) {
        self.accepts = accepts;
        self.egress = next;
        // The memoized decisions move with the configuration they describe. An
        // unplannable path is kept as the `Err` it is: every subsequent
        // packet is refused and counted, which is what the caller already saw
        // when planning happened per packet.
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

        // Every live flow in this table is a datagram flow, and a datagram is
        // never inspected; a terminated TCP flow's state lives in the local
        // stack, not here.
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
        [
            self.reassembler.next_deadline(),
            self.flows.next_deadline(),
            self.inspected.next_deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Advances both state machines. Expired flows are dropped here, which is
    /// what returns their queued `Pooled` payloads to the shared pool.
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
            // Long enough to outlast a browser's cached Alt-Svc entry for
            // an origin, which is what the DNS rewrite alone cannot reach.
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

    /// A minimal wire-valid IPv4 TCP SYN to port 443, which a session
    /// configured for termination routes to the local stack.
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

    /// A wire-valid IPv4 packet to `destination`, carrying `protocol` and the
    /// given ports. One builder, so a test states only the field it is about.
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

    /// **The defect this scoping exists to remove.** Enabling inspection used
    /// to route every flow through local termination, so a session that
    /// inspected one host paid termination for its SSH, its DNS-over-TLS, its
    /// video calls, and every TCP flow to every host nobody asked to inspect —
    /// which is the opposite of the architecture's packet-native default, and
    /// for protocols the local stack does not listen for it is a refused
    /// connection rather than a slow one.
    ///
    /// Only one shape terminates: TCP, to an address an inspected host
    /// resolved to, on a port interception serves.
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

        // Before any answer names it, nothing is inspected: every flow takes
        // the fast path, which is what a session that has just started is.
        path.on_tun_packet(&ipv4(6, INSPECTED, 443), now).unwrap();
        assert_eq!(
            path.poll_transmit().map(|transmit| transmit.to),
            Some(Side::Egress),
            "an address no answer has named is not inspected"
        );
        assert!(path.poll_terminate().is_none());

        // The resolver names it. From here TCP/443 to that address terminates.
        path.inspect_addresses(&[IpAddr::V4(Ipv4Addr::from(INSPECTED))], now);
        path.on_tun_packet(&ipv4(6, INSPECTED, 443), now).unwrap();
        assert!(
            path.poll_transmit().is_none(),
            "an inspected flow is consumed by the local stack, not forwarded"
        );
        assert!(path.poll_terminate().is_some());

        // And nothing else moves with it. Each of these is one packet that
        // must still cross as a packet.
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

        // The window lapses with the answer that opened it, and the flow is
        // packet-native again rather than terminated forever.
        path.on_timeout(now + Duration::from_secs(61));
        path.on_tun_packet(&ipv4(6, INSPECTED, 443), now + Duration::from_secs(61))
            .unwrap();
        assert_eq!(
            path.poll_transmit().map(|transmit| transmit.to),
            Some(Side::Egress)
        );
    }

    /// **The regress guard.** A re-originated connection is TCP to the very
    /// address and port that selected the flow it re-originates, so without the
    /// source-port exclusion it would be selected too, terminated again, and
    /// re-originated again — spending the socket ceiling on a single page load.
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

        // A client's connection to the inspected host terminates.
        let mut client = ipv4(6, INSPECTED, 443);
        client[20..22].copy_from_slice(&49_152u16.to_be_bytes());
        path.on_tun_packet(&client, now).unwrap();
        assert!(path.poll_terminate().is_some(), "the client flow is taken");

        // The connection this session then opens to serve it is identical
        // except for its source port, and must cross as a packet.
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

        // A port just outside the range is an ordinary client again.
        let mut outside = ipv4(6, INSPECTED, 443);
        outside[20..22].copy_from_slice(&45_010u16.to_be_bytes());
        path.on_tun_packet(&outside, now).unwrap();
        assert!(
            path.poll_terminate().is_some(),
            "the exclusion must be exactly the range the dialer binds"
        );
    }

    /// Inspection candidacy is read out of an index only the local resolver
    /// fills, so a packet-egress session that forwards DNS could enable
    /// inspection and then never find a flow to inspect. Refusing it at
    /// construction is what turns a silent absence of filtering into a
    /// configuration error.
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

        // A stream egress terminates everything anyway, and the SNI decides
        // there, so the same filter policy is admissible without local DNS.
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
        path.on_path_change(Accepts::Flows, egress(crate::DatagramFidelity::Emulated));
        assert_eq!(
            path.poll_event(),
            Some(FlowEvent::Resteered(SteeringReason::DatagramFidelity))
        );
        assert_eq!(path.poll_event(), None);

        // The flow still answers traffic: another client datagram queues on
        // the same mapping rather than opening a second one.
        path.on_tun_packet(&udp_packet(), now).unwrap();
        assert_eq!(path.poll_event(), None, "a live flow re-opens nothing");
        assert!(path.poll_datagram().is_some());
    }

    #[test]
    fn layer_loss_tears_down_flows() {
        // Open a flow, then the egress stops accepting the flow's layer.
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
        // On a terminated path a TCP packet is not forwarded anywhere: it is
        // consumed by the local stack the shell owns. The core captures it
        // whole — headers included, because the terminator is a real stack —
        // and emits no transmit for it.
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
        // The flow is gone; a fresh packet re-creates it and emits a new event.
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
        // Overhead exceeding the path leaves no inner MTU, so no flow on this
        // configuration could ever plan. Rejecting it here is what makes every
        // later `plan_flow` on the stored configuration a proof-carrying
        // repeat rather than a panic waiting to happen.
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

        // Two client datagrams fill the per-flow queue.
        path.on_tun_packet(&udp_packet(), now).unwrap();
        let _ = path.poll_event();
        path.on_tun_packet(&udp_packet(), now).unwrap();
        assert_eq!(pool.available(), 6, "queued payloads hold the budget");

        // A third exceeds the per-flow capacity while the pool still has room.
        // The core drops it, and dropping the refused handle hands its buffer
        // straight back rather than leaking the budget.
        path.on_tun_packet(&udp_packet(), now).unwrap();
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

    /// **The L4 datagram path, end to end through the core.** A client
    /// datagram on a flow egress is queued *with the target it was addressed
    /// to*, drained in round-robin order, and its reply is synthesized back as
    /// an IP packet from that same peer. Before this, `OpenDatagram` created
    /// flow state and the payload was discarded.
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

        // The reply comes back attributed to the peer, and becomes a whole IP
        // packet addressed to the client — which is what a client that sent to
        // that address will accept.
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

        // A reply for a mapping that has expired has no client to receive it.
        path.on_timeout(now + Duration::from_secs(121));
        assert_eq!(
            path.deliver_datagram(client, peer, b"late", now + Duration::from_secs(121)),
            Ok(SendOutcome::Dropped)
        );
    }

    /// Draining is round-robin, so one noisy source cannot starve another.
    #[test]
    fn queued_datagrams_drain_fairly_across_flows() {
        let mut path = datapath(crate::DatagramFidelity::Native);
        let now = Instant::now();

        // Two flows, two datagrams each, interleaved on arrival.
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
