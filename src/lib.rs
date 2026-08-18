pub mod api;
mod bridge;
mod ca;
mod datapath;
mod deadline;
mod demote;
mod device;
mod dns;
mod egress;
mod exchange;
mod filter;
mod hysteria2;
mod masque;
mod mirror;
mod mitm;
mod origin;
mod packet;
mod path;
mod platform;
mod pool;
mod quic;
mod reassembly;
mod relay;
mod rewrite;
mod rules;
mod sansio;
mod session;
mod shadowsocks;
mod shell;
mod socks5;
mod stream;
mod terminate;
#[cfg(test)]
pub(crate) mod testing;
mod transport;
mod udp;
mod upstream;
mod varint;
mod vless;

use std::{error::Error, fmt};

pub use bridge::BridgedStream;
pub use ca::{CaError, CaKeys, CaMaterial, CertificateAuthority, MitmResolver, Trust};
pub use datapath::{
    DEFAULT_INSPECTED_PORTS, Datapath, DatapathError, DnsQuery, FlowEvent, Limits, Outbound, Side,
    Transmit,
};
pub use deadline::{Wait, within};
pub use demote::{Demotion, Demotions, Leg, Standing, Tier, classify};
pub use device::{Device, Harness, SimDevice};
pub use dns::{
    AlpnOutcome, AlpnPolicy, AnswerPolicy, Answers, DNS_PORT, DnsError, EchOutcome, EchPolicy,
    HostPolicy, HostVerdict, Judgment, Message, Name, Provenance, QueryPlan, Question, Rcode,
    Rdata, RecordType, Resolution, ResourceRecord, Rewritten, RuleCounts, SVCPARAM_ALPN,
    SVCPARAM_ECH, SVCPARAM_NO_DEFAULT_ALPN, SvcParam, SvcParams, Upstream, alpn_policy,
    answer_addresses, answer_policy, ech_param, ech_policy, h3_alpn_param, plan_query, svc_params,
    write_failure, write_refusal, write_response,
};
pub use egress::{
    Association, AsyncStream, BoxFuture, DatagramSink, DatagramSource, DirectEgress, DomainName,
    DomainNameError, Egress, EgressEmit, EgressError, Either, PacketEgress, Prefixed, StreamEgress,
    Target, WIREGUARD_OVERHEAD_BYTES, WireGuardConfig, WireGuardEgress,
};
pub use exchange::{
    AllowAll, AltSvc, FilterVerdict, ProxyBody, RequestFilter, run_exchange, steer_alt_svc,
};
pub use filter::{Deferrals, Deferred, ListReport, Rule, RuleError, parse_rule};
pub use hysteria2::{
    Hysteria2Config, Hysteria2Egress, QuicConfigFactory, TcpResponse, decode_tcp_response,
    encode_tcp_request,
};
pub use masque::{
    CloseReason, MASQUE_OVERHEAD_BYTES, MasqueConfig, MasqueEgress, TunnelState,
    decode_ip_datagram, encode_ip_datagram,
};
pub use mirror::{
    ClientProfile, H2Profile, HandshakeFailure, Hello, MirrorError, Offer, Opaque, Originator,
    Refusal, alpn_list, read_hello,
};
pub use mitm::{InterceptDecision, InterceptPolicy, Interceptor, VersionCrossings, Wire};
pub use origin::{
    Assembly, DEFAULT_ORIGINATION_PORTS, NoPacketEgress, OriginationPorts, PortRangeError,
    TunnelledDialer, assemble,
};
pub use packet::{
    IcmpClass, IngressPacket, PacketError, Transport, WriteError, forbids_fragmentation,
    udp_datagram_len, write_too_big, write_udp,
};
pub use path::{PathUpdate, clamp_mss, validate_ptb};
#[cfg(unix)]
pub use platform::AndroidTun;
#[cfg(windows)]
pub use platform::WintunDevice;
pub use pool::{BufferPool, Pooled};
pub use quic::{H3Response, Handshake, QuicConnection, client_config};
pub use reassembly::{Fragment, PushOutcome, Reassembler};
pub use relay::{Inbound, Relay, RelayCounts, RelayLimits, run_relay};
pub use rewrite::{
    Coding, CosmeticSource, HidingRules, InlineStyle, NoCosmetics, NotRewritable, Rewritable,
    RewriteFailures, Rewriting, RewritingBody, StreamBudget, Truncated, Undecodable,
    permit_inline_style, rewritable,
};
pub use rules::RuleEngine;
pub use sansio::{Codec, Decode, Decoded, Framed, Negotiation, Writes, negotiate};
pub use session::{
    Handling, Introduction, SessionError, SessionLimits, Sessions, SpliceReason, introduce,
    run_sessions, serve_session,
};
pub use shadowsocks::{KeyError, Method, PreSharedKey, ShadowsocksConfig, ShadowsocksEgress};
pub use shell::{AsyncDevice, AsyncNetwork, Control, Session, Shell, Telemetry, Termination};
pub use socks5::{
    Credentials, CredentialsError, ProxyError, Reply, Socks5Config, Socks5Egress, decode_address,
    decode_datagram, encode_address, encode_datagram,
};
pub use stream::{LocalStack, StreamError, StreamId, Terminated, TerminationLimits};
pub use terminate::{Accepted, TerminatedStream, run_terminator};
pub use upstream::{
    DEFAULT_UPSTREAM_TIMEOUT, DOT_PORT, DirectSockets, DnsUpstream, Do53Upstream, DohUpstream,
    DoqUpstream, DotUpstream, TunnelBypass, UpstreamError,
};

pub use transport::{
    GrpcConfig, GrpcTransport, HttpConfig, HttpHeaders, HttpTransport, HttpUpgradeConfig,
    HttpUpgradeTransport, PlainTransport, ProxyTransport, QuicTransport, QuicTransportConfig,
    TlsConfig, TlsTransport, WebSocketConfig, WebSocketTransport,
};
pub use vless::{
    UserId, UserIdError, VlessConfig, VlessEgress, decode_addr_port, decode_response,
    encode_addr_port, encode_request,
};

pub use udp::{DatagramBuffer, FlowTableError, InternalEndpoint, SendOutcome, UdpFlowTable};

pub const MIN_QUIC_MTU: u16 = 1200;

/// The port QUIC and HTTPS share. The transient steering backstop acts on
/// UDP here and nowhere else: TCP on this port is the destination steering is
/// trying to reach.
pub const HTTPS_PORT: u16 = 443;

/// RFC 8200 requires every link carrying IPv6 to have an MTU of at least 1280
/// bytes. Boreas is dual-stack and configures its own TUN MTU, so this is an
/// admission rule on our own tunnel rather than a guess about the outside path:
/// an inner MTU below 1280 cannot carry IPv6 at all.
///
/// RFC 791's 68-byte IPv4 link minimum is deliberately not used. It governs
/// what a router must forward without fragmenting, not what a tunnel must
/// offer, and no dual-stack tunnel is usable there.
pub const MIN_IPV6_MTU: u16 = 1280;

/// A byte count that a dual-stack IP tunnel can actually carry. The invariant is
/// established once here so that no later arithmetic has to re-check it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Mtu(u16);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MtuError {
    BelowMinimum(u16),
}

impl Mtu {
    pub fn new(bytes: u16) -> Result<Self, MtuError> {
        (bytes >= MIN_IPV6_MTU)
            .then_some(Self(bytes))
            .ok_or(MtuError::BelowMinimum(bytes))
    }

    pub fn get(self) -> u16 {
        self.0
    }

    /// QUIC pads initial packets to 1200 bytes and forbids IP fragmentation, so
    /// a path below that floor cannot complete a handshake.
    pub fn admits_quic(self) -> bool {
        self.0 >= MIN_QUIC_MTU
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Accepts {
    IpPackets,
    Flows,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DatagramFidelity {
    None,
    Emulated,
    Native,
}

/// The live path properties of one egress. There is deliberately no
/// `accepts` field: the accepted layer is a property of the implementation
/// variant (`Egress::Packet` vs `Egress::Stream`), so a claim can no longer
/// disagree with the thing it describes. Callers receive the layer alongside
/// this struct, derived from that variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathProperties {
    pub datagram_fidelity: DatagramFidelity,
    pub overhead_bytes: u16,
    pub max_datagram_size: Option<u16>,
    pub preserves_ecn: bool,
    pub nat_behavior: NatBehavior,
}

/// RFC 4787 mapping behavior of a NAT or UDP-relaying egress. Endpoint-
/// independent mapping is the only behavior that keeps QUIC, WebRTC, and VoIP
/// working unchanged; anything weaker is a property of the egress, not a
/// defect to engineer around here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NatBehavior {
    AddressAndPortDependent,
    AddressDependent,
    EndpointIndependent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainError {
    MixedLayers,
    OverheadOverflow,
}

impl PathProperties {
    /// The weakest-link composition of two claims. Layer agreement is not
    /// checked here: it is a property of the implementations and is enforced
    /// by [`Egress::chain`], the only place two implementations meet.
    pub fn chain(self, next: Self) -> Result<Self, ChainError> {
        Ok(Self {
            datagram_fidelity: self.datagram_fidelity.min(next.datagram_fidelity),
            overhead_bytes: self
                .overhead_bytes
                .checked_add(next.overhead_bytes)
                .ok_or(ChainError::OverheadOverflow)?,
            max_datagram_size: match (self.max_datagram_size, next.max_datagram_size) {
                (Some(left), Some(right)) => Some(left.min(right)),
                (size, None) | (None, size) => size,
            },
            preserves_ecn: self.preserves_ecn && next.preserves_ecn,
            nat_behavior: self.nat_behavior.min(next.nat_behavior),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilterPolicy {
    PassThrough,
    InspectHttp,
}

/// Whether *this flow* is one the session must terminate in order to inspect
/// it.
///
/// **A session property and a flow property are different things, and
/// collapsing them is what cost the packet fast path.** [`FilterPolicy`] says
/// whether inspection is enabled at all; this says whether the flow in front of
/// us is a candidate for it. Enabling inspection used to route *every* flow —
/// every UDP datagram, every SSH and IMAP connection, every TCP flow to a host
/// nobody asked to inspect — through local termination, which is both the
/// opposite of the architecture's ">90 percent packet-native" claim and, for
/// the protocols the local stack does not listen for, a connection refused.
///
/// Like [`Backstop`], it is computed by the caller against live state rather
/// than inside [`plan_flow`], because it is a lookup and not a property of the
/// configuration: keeping it a value keeps the planner a total function of
/// values. The state it is looked up in is the set of addresses the resolver
/// saw an inspected host resolve to — which is exactly what
/// [Filtering](../docs/filtering.md) means by "DNS is the durable
/// no-decryption policy signal", and the only signal available before a
/// connection this session has not yet terminated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inspection {
    /// A TCP flow to an address of an inspected host, on a port interception
    /// serves. The only shape that can require termination on its own.
    Candidate,
    /// Everything else, which is nearly everything.
    Excluded,
}

impl Inspection {
    /// Every verdict. The sum is closed at two, so a caller can memoize a
    /// function of it as an array and there is no key to miss.
    pub const ALL: [Self; 2] = [Self::Candidate, Self::Excluded];

    /// This verdict's position in [`Self::ALL`].
    pub const fn index(self) -> usize {
        match self {
            Self::Candidate => 0,
            Self::Excluded => 1,
        }
    }
}

/// Whether this session answers DNS itself.
///
/// A session property like [`FilterPolicy`], and deliberately separate from
/// it: DNS filtering is the enforcement tier that reaches every application on
/// the device, including the ones that reject the Boreas CA and can therefore
/// never be intercepted at TLS, so it is on or off independently of whether
/// anything is being inspected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsPolicy {
    /// Queries to [`DNS_PORT`] are answered by the local resolver.
    Intercept,
    /// Queries cross like any other datagram.
    Forward,
}

/// A packet path carries whole IP packets, so it has a meaningful per-packet
/// budget. A terminated path re-originates a byte stream upstream, where the
/// client's packet size stops existing and local MSS clamping governs instead.
/// Attaching the MTU to the variant that owns it keeps the other one from being
/// consulted for a number that has no meaning there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportPath {
    PacketFastPath { inner_mtu: Mtu },
    LocalTermination,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuicPolicy {
    PassThrough,
    SteerToHttp2(SteeringReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SteeringReason {
    InspectionRequired,
    DatagramFidelity,
    MtuBelowMinimum,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowPlan {
    pub transport: TransportPath,
    pub quic: QuicPolicy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanError {
    OverheadExceedsPathMtu,
    InnerMtu(MtuError),
}

/// The result of re-planning a live flow after an egress reports new path
/// properties. Established flows are never dropped silently: a downgrade yields
/// `Resteer`, and `Teardown` is reserved for a change no live flow can
/// survive (the egress no longer accepts the layer the flow runs on, or its
/// remaining MTU cannot carry IPv6 at all).
///
/// `Resteer` carries the plan the flow must adopt. A re-steer without a
/// replacement plan is not a state this type can express, so no caller has to
/// re-derive one and none can silently keep the stale one when that fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Replan {
    Unchanged,
    Resteer {
        reason: SteeringReason,
        plan: FlowPlan,
    },
    Teardown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngressAction {
    Reassemble,
    /// A DNS query this session answers itself. It opens no flow and consults
    /// no egress: the answer is synthesized locally, and a refused name never
    /// leaves the device at all.
    ResolveDns,
    /// A QUIC attempt toward a host this session must inspect, dropped while
    /// its steering window is open.
    ///
    /// Not a block: the browser races QUIC against TCP and takes whichever
    /// answers first, so refusing the QUIC half makes the race resolve to TCP
    /// within the browser's own 300-to-500 ms window. The user sees the site;
    /// the session sees a connection it can inspect.
    DropSteered,
    ForwardPacket(FlowPlan),
    OpenStream(FlowPlan),
    OpenDatagram(FlowPlan),
    HandleIcmp(FlowPlan),
    DropUnsupported,
}

/// Whether the transient UDP/443 steering backstop applies to a packet.
///
/// Computed by the caller rather than by [`admit`], because it is a lookup
/// against live state and not a property of the packet: keeping it a value
/// keeps the classifier a total function of values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backstop {
    /// Nothing to steer: the destination is not a steered address, its window
    /// has closed, or the packet is arriving from the egress side rather than
    /// leaving for it.
    Lapsed,
    /// The destination belongs to a host this session must inspect and its
    /// window is open.
    Active,
}

/// What can be settled about a packet before its plan is consulted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Decided. No egress's path properties could have changed this.
    Settled(IngressAction),
    /// A whole packet of a carried protocol; [`route_planned`] finishes it.
    Planned,
}

/// The part of ingress classification that no egress path properties can change.
///
/// A fragment must be reassembled before L4 can observe it, a protocol this
/// datapath does not carry must be dropped, and an intercepted DNS query must
/// be answered locally — whatever the egress can or cannot do. Separating
/// these is what lets all three still work under a configuration that cannot
/// plan a flow at all, and it is why the caller never pays for a plan it does
/// not need.
///
/// O(1): a match on a closed sum.
pub fn admit(transport: Transport, dns: DnsPolicy, backstop: Backstop) -> Admission {
    match transport {
        Transport::Fragment => Admission::Settled(IngressAction::Reassemble),
        Transport::Other => Admission::Settled(IngressAction::DropUnsupported),
        Transport::Udp {
            destination_port: DNS_PORT,
            ..
        } if dns == DnsPolicy::Intercept => Admission::Settled(IngressAction::ResolveDns),
        Transport::Udp {
            destination_port: HTTPS_PORT,
            ..
        } if backstop == Backstop::Active => Admission::Settled(IngressAction::DropSteered),
        Transport::Tcp { .. } | Transport::Udp { .. } | Transport::Icmp(_) => Admission::Planned,
    }
}

/// Classifies a whole packet of a carried protocol against its plan.
///
/// Total by construction: possessing a [`FlowPlan`] *is* the proof that the
/// configuration plans, so there is no error left to return and no caller
/// handles one per packet.
///
/// O(1).
pub fn route_planned(transport: Transport, plan: FlowPlan) -> IngressAction {
    if matches!(plan.transport, TransportPath::PacketFastPath { .. }) {
        return IngressAction::ForwardPacket(plan);
    }

    match transport {
        Transport::Tcp { .. } => IngressAction::OpenStream(plan),
        Transport::Udp { .. } => IngressAction::OpenDatagram(plan),
        Transport::Icmp(_) => IngressAction::HandleIcmp(plan),
        // Both were settled by `admit`; reaching them here means a caller
        // bypassed it, and dropping is the answer that cannot be wrong.
        Transport::Other | Transport::Fragment => IngressAction::DropUnsupported,
    }
}

/// Plans one flow.
///
/// Three facts decide the transport path, and they are read in exactly this
/// order:
///
/// 1. a flow this session must inspect is terminated locally, whatever the
///    egress accepts — that is what inspection *is*;
/// 2. an egress that accepts only flows terminates everything, because there is
///    no packet to forward;
/// 3. everything else takes the packet fast path, which is the case the
///    architecture expects to cover more than nine flows in ten.
pub fn plan_flow(
    filter: FilterPolicy,
    inspection: Inspection,
    accepts: Accepts,
    egress: PathProperties,
    path_mtu: Mtu,
) -> Result<FlowPlan, PlanError> {
    let inspected = filter == FilterPolicy::InspectHttp && inspection == Inspection::Candidate;
    let transport = match (inspected, accepts) {
        (false, Accepts::IpPackets) => {
            let inner_mtu = path_mtu
                .get()
                .checked_sub(egress.overhead_bytes)
                .ok_or(PlanError::OverheadExceedsPathMtu)
                .and_then(|bytes| Mtu::new(bytes).map_err(PlanError::InnerMtu))?;
            TransportPath::PacketFastPath { inner_mtu }
        }
        (true, _) | (false, Accepts::Flows) => TransportPath::LocalTermination,
    };

    // RFC 9000 requires a 1200-byte datagram end to end. On the packet path that
    // budget is the inner MTU. On a terminated path the client's MTU is gone, so
    // the egress's own datagram ceiling governs; an egress that does not declare
    // one cannot be shown to clear the floor, and steering beats a black hole.
    let datagram_budget = match transport {
        TransportPath::PacketFastPath { inner_mtu } => Some(inner_mtu),
        TransportPath::LocalTermination => egress
            .max_datagram_size
            .and_then(|bytes| Mtu::new(bytes).ok()),
    };

    // Steering is per flow for the same reason termination is: an inspected
    // host reached over h3 is a host whose interception silently never fires,
    // and a host nobody inspects has no reason to lose HTTP/3 at all.
    let quic = if inspected {
        QuicPolicy::SteerToHttp2(SteeringReason::InspectionRequired)
    } else if egress.datagram_fidelity != DatagramFidelity::Native {
        QuicPolicy::SteerToHttp2(SteeringReason::DatagramFidelity)
    } else if !datagram_budget.is_some_and(Mtu::admits_quic) {
        QuicPolicy::SteerToHttp2(SteeringReason::MtuBelowMinimum)
    } else {
        QuicPolicy::PassThrough
    };

    Ok(FlowPlan { transport, quic })
}

/// Re-plans a live flow after its egress reports a path change (MASQUE's
/// QUIC-to-HTTP/2 fallback is the driving case). The filter policy and path
/// MTU are session properties and pass through unchanged; only the egress
/// moved. Errors only when the new path properties cannot support the flow's layer
/// or leaves a packet path below the IPv6 floor, and the caller answers those
/// with `Teardown`.
pub fn replan(
    current: &FlowPlan,
    filter: FilterPolicy,
    inspection: Inspection,
    accepts: Accepts,
    next: PathProperties,
    path_mtu: Mtu,
) -> Result<Replan, PlanError> {
    // A terminated flow does not prove the egress accepts only flows: under
    // inspection a packet egress terminates too. So the layer a flow needs is
    // read from its plan *and* from why it got that plan, and a flow the egress
    // can still carry is not torn down for a layer it never depended on.
    let inspected = filter == FilterPolicy::InspectHttp && inspection == Inspection::Candidate;
    let flow_layer = match current.transport {
        TransportPath::PacketFastPath { .. } => Accepts::IpPackets,
        TransportPath::LocalTermination if inspected => accepts,
        TransportPath::LocalTermination => Accepts::Flows,
    };
    if accepts != flow_layer {
        return Ok(Replan::Teardown);
    }

    let next_plan = plan_flow(filter, inspection, accepts, next, path_mtu)?;
    // Crossing the transport boundary re-originates the flow's bytes; no live
    // flow survives it. A PacketFastPath whose inner MTU merely moved is the
    // same transport with a new budget, handled by MTU machinery, not teardown.
    if std::mem::discriminant(&next_plan.transport) != std::mem::discriminant(&current.transport) {
        return Ok(Replan::Teardown);
    }

    Ok(match (current.quic, next_plan.quic) {
        // A PassThrough flow whose new plan steers must move to HTTP/2.
        (QuicPolicy::PassThrough, QuicPolicy::SteerToHttp2(reason)) => Replan::Resteer {
            reason,
            plan: next_plan,
        },
        // Identical policies, a recovery from steering to pass-through, and a
        // change of steering reason on an already-steered flow all need no
        // action.
        (_, _) => Replan::Unchanged,
    })
}

/// Classifies one whole packet: [`admit`], then [`route_planned`].
///
/// The plan is a session property — filter policy, egress path properties, and path
/// MTU — so deriving it once per configuration change instead of once per
/// packet is both cheaper and the reason this function is total.
///
/// O(1).
pub fn route_ingress(
    transport: Transport,
    plan: FlowPlan,
    dns: DnsPolicy,
    backstop: Backstop,
) -> IngressAction {
    match admit(transport, dns, backstop) {
        Admission::Settled(action) => action,
        Admission::Planned => route_planned(transport, plan),
    }
}

impl fmt::Display for MtuError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BelowMinimum(bytes) => write!(
                f,
                "MTU {bytes} is below the {MIN_IPV6_MTU}-byte IPv6 minimum"
            ),
        }
    }
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OverheadExceedsPathMtu => f.write_str("egress overhead exceeds the path MTU"),
            Self::InnerMtu(error) => write!(f, "inner {error}"),
        }
    }
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MixedLayers => f.write_str("chained egresses accept different layers"),
            Self::OverheadOverflow => f.write_str("chained egress overhead overflows"),
        }
    }
}

impl Error for MtuError {}

impl Error for PlanError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InnerMtu(error) => Some(error),
            Self::OverheadExceedsPathMtu => None,
        }
    }
}

impl Error for ChainError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn egress(fidelity: DatagramFidelity, overhead_bytes: u16) -> PathProperties {
        PathProperties {
            datagram_fidelity: fidelity,
            overhead_bytes,
            max_datagram_size: None,
            preserves_ecn: true,
            nat_behavior: NatBehavior::EndpointIndependent,
        }
    }

    fn mtu(bytes: u16) -> Mtu {
        Mtu::new(bytes).expect("test MTU is valid")
    }

    // The P3 gate asks for properties, not examples, so these tests iterate
    // the full product of the domains that drive each law instead of naming
    // one case per law.
    const FIDELITIES: [DatagramFidelity; 3] = [
        DatagramFidelity::None,
        DatagramFidelity::Emulated,
        DatagramFidelity::Native,
    ];
    const NAT_BEHAVIORS: [NatBehavior; 3] = [
        NatBehavior::AddressAndPortDependent,
        NatBehavior::AddressDependent,
        NatBehavior::EndpointIndependent,
    ];
    const MTUS: [u16; 6] = [1280, 1300, 1400, 1500, 4000, u16::MAX];
    const OVERHEADS: [u16; 4] = [0, 40, 60, 1000];

    #[test]
    fn chain_fidelity_is_monotone_non_increasing() {
        for left in FIDELITIES {
            for right in FIDELITIES {
                for left_nat in NAT_BEHAVIORS {
                    for right_nat in NAT_BEHAVIORS {
                        let first = PathProperties {
                            nat_behavior: left_nat,
                            ..egress(left, 0)
                        };
                        let second = PathProperties {
                            nat_behavior: right_nat,
                            ..egress(right, 0)
                        };
                        let chained = first.chain(second).unwrap();
                        assert_eq!(chained.datagram_fidelity, left.min(right));
                        assert_eq!(chained.nat_behavior, left_nat.min(right_nat));
                    }
                }
            }
        }
    }

    #[test]
    fn plan_flow_never_passes_quic_below_native_or_below_floor() {
        for fidelity in FIDELITIES {
            for &overhead in &OVERHEADS {
                for &path in &MTUS {
                    for max_datagram_size in [None, Some(1199), Some(1200), Some(1500)] {
                        let properties = PathProperties {
                            max_datagram_size,
                            ..egress(fidelity, overhead)
                        };
                        let Ok(plan) = plan_flow(
                            FilterPolicy::PassThrough,
                            Inspection::Excluded,
                            Accepts::IpPackets,
                            properties,
                            mtu(path),
                        ) else {
                            continue; // overhead exceeded the path; not admitted
                        };
                        if fidelity != DatagramFidelity::Native {
                            assert_ne!(
                                plan.quic,
                                QuicPolicy::PassThrough,
                                "fidelity {fidelity:?} must steer"
                            );
                        }
                        let budget = match plan.transport {
                            TransportPath::PacketFastPath { inner_mtu } => Some(inner_mtu.get()),
                            TransportPath::LocalTermination => max_datagram_size,
                        };
                        if budget.is_none_or(|bytes| bytes < MIN_QUIC_MTU) {
                            assert_ne!(
                                plan.quic,
                                QuicPolicy::PassThrough,
                                "budget {budget:?} must steer"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn every_native_to_emulated_transition_resteers() {
        for fidelity in FIDELITIES {
            let live = plan_flow(
                FilterPolicy::PassThrough,
                Inspection::Excluded,
                Accepts::Flows,
                PathProperties {
                    max_datagram_size: Some(1500),
                    ..egress(DatagramFidelity::Native, 0)
                },
                mtu(1500),
            )
            .unwrap();
            let next = PathProperties {
                max_datagram_size: Some(1500),
                ..egress(fidelity, 0)
            };
            let result = replan(
                &live,
                FilterPolicy::PassThrough,
                Inspection::Excluded,
                Accepts::Flows,
                next,
                mtu(1500),
            );
            if fidelity == DatagramFidelity::Native {
                assert_eq!(result, Ok(Replan::Unchanged));
            } else {
                // The verdict carries the plan the flow must adopt, and that
                // plan is exactly what planning the new egress from scratch
                // yields. This is the law that lets the caller assign it
                // without a second, fallible derivation.
                assert_eq!(
                    result,
                    Ok(Replan::Resteer {
                        reason: SteeringReason::DatagramFidelity,
                        plan: plan_flow(
                            FilterPolicy::PassThrough,
                            Inspection::Excluded,
                            Accepts::Flows,
                            next,
                            mtu(1500),
                        )
                        .unwrap(),
                    }),
                    "Native to {fidelity:?} must re-steer, never drop"
                );
            }
        }
    }

    #[test]
    fn replan_tears_down_only_unsurvivable_changes() {
        let packet_plan = plan_flow(
            FilterPolicy::PassThrough,
            Inspection::Excluded,
            Accepts::IpPackets,
            egress(DatagramFidelity::Native, 60),
            mtu(1500),
        )
        .unwrap();

        // The layer the flow runs on is gone: no live flow survives.
        assert_eq!(
            replan(
                &packet_plan,
                FilterPolicy::PassThrough,
                Inspection::Excluded,
                Accepts::Flows,
                egress(DatagramFidelity::Native, 60),
                mtu(1500),
            ),
            Ok(Replan::Teardown)
        );

        // Overhead growth that pushes the inner MTU below 1280 is an error
        // from plan_flow, which the caller answers with Teardown.
        assert_eq!(
            replan(
                &packet_plan,
                FilterPolicy::PassThrough,
                Inspection::Excluded,
                Accepts::IpPackets,
                egress(DatagramFidelity::Native, 300),
                mtu(1500),
            ),
            Err(PlanError::InnerMtu(MtuError::BelowMinimum(1200)))
        );

        // A shrunk datagram ceiling on a packet path does not move the plan.
        assert_eq!(
            replan(
                &packet_plan,
                FilterPolicy::PassThrough,
                Inspection::Excluded,
                Accepts::IpPackets,
                egress(DatagramFidelity::Native, 100),
                mtu(1500),
            ),
            Ok(Replan::Unchanged)
        );
    }

    #[test]
    fn fragments_never_reach_l4_admission() {
        let native_l3_plan = plan_flow(
            FilterPolicy::PassThrough,
            Inspection::Excluded,
            Accepts::IpPackets,
            egress(DatagramFidelity::Native, 0),
            mtu(1500),
        )
        .unwrap();
        let ipv4_udp = [
            0x45, 0x03, 0x00, 0x1c, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2, 0x04,
            0xd2, 0x00, 0x35, 0x00, 0x08, 0, 0,
        ];

        // Every wire-expressible IPv4 fragment boundary (offset unit or the
        // more-fragments flag) routes to Reassemble and nothing else.
        for offset_units in [0_u16, 1, 8, 256, 0x1fff] {
            for more_fragments in [true, false] {
                let mut packet = ipv4_udp;
                if offset_units == 0 && !more_fragments {
                    continue; // not a fragment at all
                }
                let flags_offset = offset_units | if more_fragments { 0x2000 } else { 0 };
                packet[6..8].copy_from_slice(&flags_offset.to_be_bytes());
                let parsed = IngressPacket::parse(&packet).expect("wire-valid packet");
                assert_eq!(parsed.transport, Transport::Fragment);
                assert_eq!(
                    route_ingress(
                        parsed.transport,
                        native_l3_plan,
                        DnsPolicy::Forward,
                        Backstop::Lapsed
                    ),
                    IngressAction::Reassemble,
                    "offset {offset_units}, more_fragments {more_fragments}"
                );
            }
        }

        // An IPv6 Fragment header is source-only fragmentation (RFC 8200
        // section 4.5), but we are the destination, so reassembly is
        // mandatory; it routes to Reassemble like IPv4.
        let mut ipv6_fragment = [0_u8; 56];
        ipv6_fragment[0] = 0x60;
        ipv6_fragment[4..6].copy_from_slice(&16_u16.to_be_bytes());
        ipv6_fragment[6] = 44;
        ipv6_fragment[7] = 64;
        ipv6_fragment[40] = 6; // fragment header: next is TCP
        ipv6_fragment[43] = 0x01; // offset 0, more fragments
        let parsed = IngressPacket::parse(&ipv6_fragment).expect("wire-valid packet");
        assert_eq!(parsed.transport, Transport::Fragment);
        assert_eq!(
            route_ingress(
                parsed.transport,
                native_l3_plan,
                DnsPolicy::Forward,
                Backstop::Lapsed
            ),
            IngressAction::Reassemble
        );
    }

    #[test]
    fn the_backstop_refuses_quic_only_outward_and_only_while_open() {
        let plan = plan_flow(
            FilterPolicy::PassThrough,
            Inspection::Excluded,
            Accepts::IpPackets,
            egress(DatagramFidelity::Native, 0),
            mtu(1500),
        )
        .unwrap();
        let quic = Transport::Udp {
            source_port: 50_000,
            destination_port: MIN_QUIC_MTU.wrapping_sub(757), // 443
        };
        assert_eq!(
            quic,
            Transport::Udp {
                source_port: 50_000,
                destination_port: HTTPS_PORT
            }
        );

        // Open: the attempt is refused so the browser's race resolves to TCP.
        assert_eq!(
            route_ingress(quic, plan, DnsPolicy::Intercept, Backstop::Active),
            IngressAction::DropSteered
        );
        // Closed: ordinary traffic, whatever the DNS policy.
        for dns in [DnsPolicy::Intercept, DnsPolicy::Forward] {
            assert_eq!(
                route_ingress(quic, plan, dns, Backstop::Lapsed),
                IngressAction::ForwardPacket(plan)
            );
        }
        // TCP to the same port is the destination steering aims at, so the
        // backstop must never touch it.
        let https = Transport::Tcp {
            source_port: 50_000,
            destination_port: HTTPS_PORT,
        };
        assert_eq!(
            route_ingress(https, plan, DnsPolicy::Intercept, Backstop::Active),
            IngressAction::ForwardPacket(plan)
        );
        // And a query to the resolver still wins over the backstop, because
        // the two act on different ports and cannot both apply.
        let query = Transport::Udp {
            source_port: 50_000,
            destination_port: DNS_PORT,
        };
        assert_eq!(
            route_ingress(query, plan, DnsPolicy::Intercept, Backstop::Active),
            IngressAction::ResolveDns
        );
    }

    #[test]
    fn mtu_rejects_paths_that_cannot_carry_ipv6() {
        assert_eq!(Mtu::new(0), Err(MtuError::BelowMinimum(0)));
        // RFC 791's 68-byte IPv4 link minimum is not a usable tunnel MTU.
        assert_eq!(Mtu::new(68), Err(MtuError::BelowMinimum(68)));
        assert_eq!(
            Mtu::new(MIN_IPV6_MTU - 1),
            Err(MtuError::BelowMinimum(MIN_IPV6_MTU - 1))
        );
        assert_eq!(Mtu::new(MIN_IPV6_MTU).map(Mtu::get), Ok(MIN_IPV6_MTU));

        // The IPv6 floor sits above the QUIC floor, so every admitted MTU clears
        // 1200 and steering for MTU can only come from an egress datagram
        // ceiling, never from an admitted packet path.
        const { assert!(MIN_IPV6_MTU > MIN_QUIC_MTU) };
        assert!(mtu(MIN_IPV6_MTU).admits_quic());
    }

    #[test]
    fn flow_planning_enforces_fast_path_and_quic_invariants() {
        let native_l3 = egress(DatagramFidelity::Native, 60);
        assert_eq!(
            plan_flow(
                FilterPolicy::PassThrough,
                Inspection::Excluded,
                Accepts::IpPackets,
                native_l3,
                mtu(1500)
            ),
            Ok(FlowPlan {
                transport: TransportPath::PacketFastPath {
                    inner_mtu: mtu(1440)
                },
                quic: QuicPolicy::PassThrough,
            })
        );

        // **Inspection is a property of the flow, not of the session.** A
        // candidate terminates and loses QUIC; every other flow on the same
        // inspecting session keeps the packet fast path and keeps HTTP/3.
        assert_eq!(
            plan_flow(
                FilterPolicy::InspectHttp,
                Inspection::Candidate,
                Accepts::IpPackets,
                native_l3,
                mtu(1500)
            ),
            Ok(FlowPlan {
                transport: TransportPath::LocalTermination,
                quic: QuicPolicy::SteerToHttp2(SteeringReason::InspectionRequired),
            })
        );
        assert_eq!(
            plan_flow(
                FilterPolicy::InspectHttp,
                Inspection::Excluded,
                Accepts::IpPackets,
                native_l3,
                mtu(1500)
            ),
            Ok(FlowPlan {
                transport: TransportPath::PacketFastPath {
                    inner_mtu: mtu(1440)
                },
                quic: QuicPolicy::PassThrough,
            }),
            "a flow nobody asked to inspect must not pay for inspection"
        );
        assert_eq!(
            plan_flow(
                FilterPolicy::PassThrough,
                Inspection::Excluded,
                Accepts::Flows,
                egress(DatagramFidelity::Emulated, 60),
                mtu(1500),
            )
            .map(|plan| (plan.transport, plan.quic)),
            Ok((
                TransportPath::LocalTermination,
                QuicPolicy::SteerToHttp2(SteeringReason::DatagramFidelity),
            ))
        );

        // On a terminated path the client's MTU is gone, so the egress's own
        // datagram ceiling decides whether QUIC clears RFC 9000's 1200 floor.
        let native_l4 = egress(DatagramFidelity::Native, 0);
        assert_eq!(
            plan_flow(
                FilterPolicy::PassThrough,
                Inspection::Excluded,
                Accepts::Flows,
                native_l4,
                mtu(1500)
            )
            .map(|plan| plan.quic),
            Ok(QuicPolicy::SteerToHttp2(SteeringReason::MtuBelowMinimum)),
            "an undeclared datagram ceiling cannot be shown to clear the floor"
        );
        assert_eq!(
            plan_flow(
                FilterPolicy::PassThrough,
                Inspection::Excluded,
                Accepts::Flows,
                PathProperties {
                    max_datagram_size: Some(1000),
                    ..native_l4
                },
                mtu(1500),
            )
            .map(|plan| plan.quic),
            Ok(QuicPolicy::SteerToHttp2(SteeringReason::MtuBelowMinimum))
        );
        assert_eq!(
            plan_flow(
                FilterPolicy::PassThrough,
                Inspection::Excluded,
                Accepts::Flows,
                PathProperties {
                    max_datagram_size: Some(1400),
                    ..native_l4
                },
                mtu(1500),
            )
            .map(|plan| plan.quic),
            Ok(QuicPolicy::PassThrough)
        );

        // An inner MTU that cannot carry IPv6 is a rejected chain, not a
        // degraded mode. Distinguish it from overhead exceeding the path.
        assert_eq!(
            plan_flow(
                FilterPolicy::PassThrough,
                Inspection::Excluded,
                Accepts::IpPackets,
                native_l3,
                mtu(1300)
            ),
            Err(PlanError::InnerMtu(MtuError::BelowMinimum(1240)))
        );
        assert_eq!(
            plan_flow(
                FilterPolicy::PassThrough,
                Inspection::Excluded,
                Accepts::IpPackets,
                egress(DatagramFidelity::Native, 60_000),
                mtu(1500),
            ),
            Err(PlanError::OverheadExceedsPathMtu)
        );
    }

    #[test]
    fn errors_render_without_the_debug_formatter() {
        assert_eq!(
            PlanError::InnerMtu(MtuError::BelowMinimum(1240)).to_string(),
            "inner MTU 1240 is below the 1280-byte IPv6 minimum"
        );
        assert_eq!(
            PlanError::OverheadExceedsPathMtu.to_string(),
            "egress overhead exceeds the path MTU"
        );
        assert_eq!(
            ChainError::MixedLayers.to_string(),
            "chained egresses accept different layers"
        );
        assert!(
            Error::source(&PlanError::InnerMtu(MtuError::BelowMinimum(1240)))
                .is_some_and(|source| source.to_string().contains("below the 1280-byte"))
        );
    }

    #[test]
    fn chaining_uses_the_weakest_property() {
        let first = PathProperties {
            max_datagram_size: Some(1400),
            ..egress(DatagramFidelity::Native, 40)
        };
        let second = PathProperties {
            max_datagram_size: Some(1300),
            preserves_ecn: false,
            ..egress(DatagramFidelity::Emulated, 20)
        };

        assert_eq!(
            first.chain(second),
            Ok(PathProperties {
                datagram_fidelity: DatagramFidelity::Emulated,
                overhead_bytes: 60,
                max_datagram_size: Some(1300),
                preserves_ecn: false,
                nat_behavior: NatBehavior::EndpointIndependent,
            })
        );

        // Layer agreement is checked where two implementations meet, not
        // between two bare claims; the `Egress::chain` conflict path is
        // covered in `egress.rs`.
    }

    #[test]
    fn ingress_routing_keeps_effects_explicit() {
        let packet = IngressPacket {
            source: "192.0.2.1".parse().unwrap(),
            destination: "198.51.100.2".parse().unwrap(),
            ecn: etherparse::IpEcn::NotEct,
            transport: Transport::Udp {
                source_port: 1234,
                destination_port: 443,
            },
            payload_at: 0,
            payload_len: 0,
        };
        let native_l3 = egress(DatagramFidelity::Native, 60);
        let packet_plan = plan_flow(
            FilterPolicy::PassThrough,
            Inspection::Excluded,
            Accepts::IpPackets,
            native_l3,
            mtu(1500),
        )
        .unwrap();
        let flow_plan = plan_flow(
            FilterPolicy::PassThrough,
            Inspection::Excluded,
            Accepts::Flows,
            native_l3,
            mtu(1500),
        )
        .unwrap();

        assert!(matches!(
            route_ingress(
                packet.transport,
                packet_plan,
                DnsPolicy::Forward,
                Backstop::Lapsed
            ),
            IngressAction::ForwardPacket(_)
        ));
        assert!(matches!(
            route_ingress(
                packet.transport,
                flow_plan,
                DnsPolicy::Forward,
                Backstop::Lapsed
            ),
            IngressAction::OpenDatagram(_)
        ));

        // A fragment is classified without consulting the plan at all, which
        // is what lets the datapath quarantine one under a configuration that
        // could not plan a flow. The plan passed here is irrelevant, and that
        // is the point.
        assert_eq!(
            route_ingress(
                Transport::Fragment,
                flow_plan,
                DnsPolicy::Forward,
                Backstop::Lapsed
            ),
            IngressAction::Reassemble
        );
        assert_eq!(
            route_ingress(
                Transport::Other,
                packet_plan,
                DnsPolicy::Forward,
                Backstop::Lapsed
            ),
            IngressAction::DropUnsupported
        );
    }
}
