//! Crate root for the layered packet, transport, policy, interception, and
//! egress core.
//!
//! [`l3`], [`l4`], [`policy`], [`intercept`], and [`egress`] follow a packet's
//! path. [`host`] supplies runtime handles; [`datapath`], [`wire`],
//! [`sansio`], and [`bridge`] are shared vocabulary and coordination layers.
//! Public types are re-exported here so callers do not depend on that layout.

pub mod api;

mod egress;
mod host;
mod intercept;
mod l3;
mod l4;
mod policy;

mod bridge;
mod datapath;
mod deadline;
mod pool;
mod sansio;
#[cfg(test)]
pub(crate) mod testing;
mod wire;

use std::{
    error::Error,
    fmt,
    sync::{Mutex, MutexGuard, PoisonError},
};


/// Takes a lock and recovers from poisoning.
///
/// These mutexes guard maps, queues, and options whose updates are whole
/// insertions or removals. The panic is accounted for at the task boundary;
/// poisoning must not silently disable the subsystem that owns the lock.
pub(crate) fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub use bridge::BridgedStream;
pub use datapath::{
    DEFAULT_INSPECTED_PORTS, Datapath, DatapathError, DnsQuery, FlowEvent, Limits, Outbound, Side,
    Transmit,
};
pub use deadline::{Wait, within};
pub use egress::hysteria2::{
    Hysteria2Config, Hysteria2Egress, QuicConfigFactory, TcpResponse, decode_tcp_response,
    encode_tcp_request,
};
pub use egress::masque::{
    CloseReason, MASQUE_OVERHEAD_BYTES, MasqueConfig, MasqueEgress, TunnelState,
    decode_ip_datagram, encode_ip_datagram,
};
pub use egress::origin::{
    Assembly, DEFAULT_ORIGINATION_PORTS, NoPacketEgress, OriginationPorts, PortRangeError,
    TunnelledDialer, assemble,
};
pub use egress::quic::{H3Response, Handshake, QuicConnection, client_config};
pub use egress::shadowsocks::{
    KeyError, Method, PreSharedKey, ShadowsocksConfig, ShadowsocksEgress,
};
pub use egress::socks5::{
    Credentials, CredentialsError, ProxyError, Reply, Socks5Config, Socks5Egress, decode_address,
    decode_datagram, encode_address, encode_datagram,
};
pub use egress::{
    Association, AsyncStream, BoxFuture, DatagramSink, DatagramSource, DirectEgress, DomainName,
    DomainNameError, Egress, EgressEmit, EgressError, Either, PacketEgress, Prefixed, StreamEgress,
    Target, WIREGUARD_OVERHEAD_BYTES, WireGuardConfig, WireGuardEgress,
};
pub use host::device::{Device, Harness, SimDevice};
#[cfg(unix)]
pub use host::platform::AndroidTun;
#[cfg(windows)]
pub use host::platform::WintunDevice;
pub use host::shell::{
    AsyncDevice, AsyncNetwork, Control, Panics, Session, Shell, Supervision, Telemetry, Termination,
};
pub use intercept::ca::{CaError, CaKeys, CaMaterial, CertificateAuthority, MitmResolver, Trust};
pub use intercept::exchange::{
    AllowAll, AltSvc, FilterVerdict, ProxyBody, RequestFilter, run_exchange, steer_alt_svc,
};
pub use intercept::mirror::{
    ClientProfile, H2Profile, HandshakeFailure, Hello, MirrorError, Offer, Opaque, Originator,
    Refusal, alpn_list, read_hello,
};
pub use intercept::mitm::{
    InterceptDecision, InterceptPolicy, Interceptor, VersionCrossings, Wire,
};
pub use intercept::rewrite::{
    BudgetError, Coding, CosmeticSource, HidingRules, InlineStyle, NoCosmetics, NotRewritable,
    Rewritable, RewriteFailures, Rewriting, RewritingBody, StreamBudget, Truncated, Undecodable,
    permit_inline_style, rewritable,
};
pub use intercept::session::{
    Handling, Introduction, SessionError, SessionLimits, Sessions, SpliceReason, introduce,
    run_sessions, serve_session,
};
pub use l3::packet::{
    IcmpClass, IngressPacket, PacketError, Transport, WriteError, forbids_fragmentation,
    udp_datagram_len, write_too_big, write_udp,
};
pub use l3::path::{PathUpdate, clamp_mss, validate_ptb};
pub use l3::reassembly::{Fragment, PushOutcome, ReassembledPacket, Reassembler};
pub use l4::relay::{Inbound, Relay, RelayCounts, RelayLimits, run_relay};
pub use l4::stream::{
    LocalStack, StreamError, StreamId, Terminated, TerminationError, TerminationLimits,
};
pub use l4::terminate::{Accepted, TerminatedStream, run_terminator};
pub use policy::demote::{Demotion, Demotions, InterceptedTier, Leg, Standing, Tier, classify};
pub use policy::dns::{
    AlpnOutcome, AlpnPolicy, AnswerPolicy, Answers, DNS_PORT, DnsError, EchOutcome, EchPolicy,
    HostPolicy, HostVerdict, Judgment, Message, Name, Provenance, QueryPlan, Question, Rcode,
    Rdata, RecordType, Resolution, ResourceRecord, Rewritten, RuleCounts, SVCPARAM_ALPN,
    SVCPARAM_ECH, SVCPARAM_NO_DEFAULT_ALPN, SvcParam, SvcParams, Upstream, alpn_policy,
    answer_addresses, answer_policy, ech_param, ech_policy, h3_alpn_param, plan_query, svc_params,
    write_failure, write_refusal, write_response,
};
pub use policy::filter::{Deferrals, Deferred, ListReport, Rule, RuleError, parse_rule};
pub use policy::rules::RuleEngine;
pub use policy::upstream::{
    DEFAULT_UPSTREAM_TIMEOUT, DOT_PORT, DirectSockets, DnsUpstream, Do53Upstream, DohUpstream,
    DoqUpstream, DotUpstream, TunnelBypass, UpstreamError,
};
pub use pool::{BufferPool, Pooled};
pub use sansio::{Codec, Decode, Decoded, Framed, Negotiation, Writes, negotiate};

pub use egress::transport::{
    GrpcConfig, GrpcTransport, HttpConfig, HttpHeaders, HttpTransport, HttpUpgradeConfig,
    HttpUpgradeTransport, PlainTransport, ProxyTransport, QuicTransport, QuicTransportConfig,
    TlsConfig, TlsTransport, WebSocketConfig, WebSocketTransport,
};
pub use egress::vless::{
    UserId, UserIdError, VlessConfig, VlessEgress, decode_addr_port, decode_response,
    encode_addr_port, encode_request,
};

pub use l3::udp::{DatagramBuffer, FlowTableError, InternalEndpoint, SendOutcome, UdpFlowTable};

pub const MIN_QUIC_MTU: u16 = 1200;

/// Port shared by HTTPS and QUIC.
///
/// The transient steering backstop applies to UDP on this port only.
pub const HTTPS_PORT: u16 = 443;

/// Minimum dual-stack tunnel MTU.
///
/// RFC 8200 requires 1280 bytes for an IPv6 link. RFC 791's 68-byte IPv4
/// forwarding minimum is not sufficient for a tunnel that also carries IPv6.
pub const MIN_IPV6_MTU: u16 = 1280;

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

    /// Whether the MTU can carry QUIC's minimum datagram.
    pub fn admits_quic(self) -> bool {
        self.quic_budget().is_some()
    }

    /// Returns the QUIC datagram budget afforded by this MTU.
    pub fn quic_budget(self) -> Option<QuicBudget> {
        QuicBudget::new(self.0)
    }
}

/// Validated datagram ceiling for QUIC.
///
/// This is separate from [`Mtu`]: RFC 9000 requires 1200 bytes for a QUIC
/// datagram, while RFC 8200 requires 1280 bytes for an IPv6 link. A flow path
/// may therefore have a QUIC-valid ceiling below the IPv6 link minimum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuicBudget(u16);

impl QuicBudget {
    /// Validates the QUIC minimum datagram size.
    pub fn new(bytes: u16) -> Option<Self> {
        (bytes >= MIN_QUIC_MTU).then_some(Self(bytes))
    }

    pub fn get(self) -> u16 {
        self.0
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

/// Live properties reported by one egress.
///
/// The accepted layer is derived from the egress implementation variant and is
/// checked where implementations are chained, so this claim cannot disagree
/// with the implementation that supplies it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathProperties {
    pub datagram_fidelity: DatagramFidelity,
    pub overhead_bytes: u16,
    pub max_datagram_size: Option<u16>,
    pub preserves_ecn: bool,
    pub nat_behavior: NatBehavior,
}

/// RFC 4787 NAT or UDP-relay mapping behavior.
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
    /// Composes two property claims using the weaker value in each dimension.
    /// Layer agreement is checked by [`Egress::chain`], where implementations
    /// are available.
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

/// Whether this flow requires local termination for inspection.
///
/// [`FilterPolicy`] enables inspection for the session; this value identifies
/// the individual flow. It is computed from resolver state by the caller so
/// [`plan_flow`] remains a total function of its value arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inspection {
    /// TCP flow matching an inspected address and interception port.
    Candidate,
    /// Flow outside the inspection set.
    Excluded,
}

impl Inspection {
    /// All possible verdicts in index order.
    pub const ALL: [Self; 2] = [Self::Candidate, Self::Excluded];

    /// Index into [`Self::ALL`].
    pub const fn index(self) -> usize {
        match self {
            Self::Candidate => 0,
            Self::Excluded => 1,
        }
    }
}

/// Whether this session answers DNS locally.
///
/// Independent of [`FilterPolicy`], because DNS enforcement also covers
/// applications that cannot be intercepted at TLS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsPolicy {
    /// Answer queries to [`DNS_PORT`] locally.
    Intercept,
    /// Forward queries as ordinary datagrams.
    Forward,
}

/// Transport path selected for a flow.
///
/// Only a packet path has an inner packet MTU. Local termination re-originates
/// a byte stream and uses stream-specific sizing instead.
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
    /// DNS query answered locally without opening a flow.
    ResolveDns,
    /// QUIC attempt dropped while steering an inspected host to HTTP/2.
    DropSteered,
    ForwardPacket(FlowPlan),
    OpenStream(FlowPlan),
    OpenDatagram(FlowPlan),
    HandleIcmp(FlowPlan),
    DropUnsupported,
}

/// Whether transient UDP/443 steering applies.
///
/// The caller resolves this live-state lookup; [`admit`] only classifies values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backstop {
    /// No active steering window applies.
    Lapsed,
    /// The destination is actively steered.
    Active,
}

/// Ingress decision before or after flow planning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Decision independent of egress properties.
    Settled(IngressAction),
    /// Carried protocol awaiting [`route_planned`].
    Planned,
}

/// Classifies decisions independent of egress path properties.
///
/// Fragments are reassembled, unsupported protocols are dropped, and local
/// DNS is answered before a flow plan is consulted. O(1).
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

/// Routes a carried packet using an existing plan.
///
/// A [`FlowPlan`] proves planning succeeded, so this operation is total. O(1).
pub fn route_planned(transport: Transport, plan: FlowPlan) -> IngressAction {
    if matches!(plan.transport, TransportPath::PacketFastPath { .. }) {
        return IngressAction::ForwardPacket(plan);
    }

    match transport {
        Transport::Tcp { .. } => IngressAction::OpenStream(plan),
        Transport::Udp { .. } => IngressAction::OpenDatagram(plan),
        Transport::Icmp(_) => IngressAction::HandleIcmp(plan),
        // These variants should have been settled by `admit`.
        Transport::Other | Transport::Fragment => IngressAction::DropUnsupported,
    }
}

/// Plans transport and QUIC handling for one flow.
///
/// Inspection forces local termination. An egress that accepts only flows does
/// the same for every flow; other compatible flows use the packet fast path.
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

    // QUIC's floor is measured against the packet path's inner MTU or the
    // terminated egress's declared datagram ceiling.
    let datagram_budget = match transport {
        TransportPath::PacketFastPath { inner_mtu } => inner_mtu.quic_budget(),
        // This is a datagram ceiling, so use QUIC's floor rather than IPv6's.
        TransportPath::LocalTermination => egress.max_datagram_size.and_then(QuicBudget::new),
    };

    // Steer only the flows that need it; unrelated flows retain HTTP/3.
    let quic = if inspected {
        QuicPolicy::SteerToHttp2(SteeringReason::InspectionRequired)
    } else if egress.datagram_fidelity != DatagramFidelity::Native {
        QuicPolicy::SteerToHttp2(SteeringReason::DatagramFidelity)
    } else if datagram_budget.is_none() {
        QuicPolicy::SteerToHttp2(SteeringReason::MtuBelowMinimum)
    } else {
        QuicPolicy::PassThrough
    };

    Ok(FlowPlan { transport, quic })
}

/// Re-plans a live flow after its egress properties change.
///
/// A layer change or an invalid packet-path MTU returns an error for the caller
/// to handle as teardown. A QUIC downgrade returns a replacement plan instead.
pub fn replan(
    current: &FlowPlan,
    filter: FilterPolicy,
    inspection: Inspection,
    accepts: Accepts,
    next: PathProperties,
    path_mtu: Mtu,
) -> Result<Replan, PlanError> {
    // Inspection can terminate a packet-capable egress, so recover the required
    // layer from both the plan and the reason for local termination.
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
    // Crossing transport paths loses the live byte or packet state. An MTU-only
    // change stays on the packet path and does not require teardown.
    if std::mem::discriminant(&next_plan.transport) != std::mem::discriminant(&current.transport) {
        return Ok(Replan::Teardown);
    }

    Ok(match (current.quic, next_plan.quic) {
        // A newly steered flow needs the replacement plan.
        (QuicPolicy::PassThrough, QuicPolicy::SteerToHttp2(reason)) => Replan::Resteer {
            reason,
            plan: next_plan,
        },
        // Existing steering and recovery require no live-flow action here.
        (_, _) => Replan::Unchanged,
    })
}

/// Classifies a packet with [`admit`] and then [`route_planned`].
///
/// The plan is derived per session configuration, not per packet. O(1).
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
        // Cover both directions, transports, and datagram ceilings so every
        // planning branch is exercised.
        for fidelity in FIDELITIES {
            for &overhead in &OVERHEADS {
                for &path in &MTUS {
                    for accepts in [Accepts::IpPackets, Accepts::Flows] {
                        for max_datagram_size in
                            [None, Some(1199), Some(1200), Some(1279), Some(1500)]
                        {
                            let properties = PathProperties {
                                max_datagram_size,
                                ..egress(fidelity, overhead)
                            };
                            let Ok(plan) = plan_flow(
                                FilterPolicy::PassThrough,
                                Inspection::Excluded,
                                accepts,
                                properties,
                                mtu(path),
                            ) else {
                                continue; // This path cannot be admitted.
                            };
                            if fidelity != DatagramFidelity::Native {
                                assert_ne!(
                                    plan.quic,
                                    QuicPolicy::PassThrough,
                                    "fidelity {fidelity:?} must steer"
                                );
                                continue;
                            }
                            let budget = match plan.transport {
                                TransportPath::PacketFastPath { inner_mtu } => {
                                    Some(inner_mtu.get())
                                }
                                TransportPath::LocalTermination => max_datagram_size,
                            };
                            let fits = budget.is_some_and(|bytes| bytes >= MIN_QUIC_MTU);
                            assert_eq!(
                                plan.quic == QuicPolicy::PassThrough,
                                fits,
                                "budget {budget:?} over {accepts:?}: QUIC passes exactly when \
                                 RFC 9000's floor is met"
                            );
                        }
                    }
                }
            }
        }
    }

    /// The eighty bytes between RFC 9000's floor and RFC 8200's. An egress
    /// declaring a ceiling in this range can carry QUIC and used to be steered
    /// off it, because its datagram size was parsed against the IPv6 minimum
    /// link MTU rather than against QUIC's own floor.
    #[test]
    fn a_datagram_ceiling_between_the_two_floors_still_carries_quic() {
        for bytes in [MIN_QUIC_MTU, 1234, MIN_IPV6_MTU - 1] {
            assert!(QuicBudget::new(bytes).is_some(), "{bytes} clears RFC 9000");
            assert!(Mtu::new(bytes).is_err(), "{bytes} is below RFC 8200");
            let plan = plan_flow(
                FilterPolicy::PassThrough,
                Inspection::Excluded,
                Accepts::Flows,
                PathProperties {
                    max_datagram_size: Some(bytes),
                    ..egress(DatagramFidelity::Native, 0)
                },
                mtu(1500),
            )
            .unwrap();
            assert_eq!(plan.quic, QuicPolicy::PassThrough, "{bytes} must pass");
        }
        assert!(QuicBudget::new(MIN_QUIC_MTU - 1).is_none());
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
                // Resteer carries the replacement plan, so callers do not
                // derive it again.
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

        for offset_units in [0_u16, 1, 8, 256, 0x1fff] {
            for more_fragments in [true, false] {
                let mut packet = ipv4_udp;
                    if offset_units == 0 && !more_fragments {
                    continue; // This is an unfragmented packet.
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

        // RFC 8200 section 4.5 requires reassembly for this destination.
        let mut ipv6_fragment = [0_u8; 56];
        ipv6_fragment[0] = 0x60;
        ipv6_fragment[4..6].copy_from_slice(&16_u16.to_be_bytes());
        ipv6_fragment[6] = 44;
        ipv6_fragment[7] = 64;
        ipv6_fragment[40] = 6; // Next header is TCP.
        ipv6_fragment[43] = 0x01; // Offset zero, more fragments.
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

        assert_eq!(
            route_ingress(quic, plan, DnsPolicy::Intercept, Backstop::Active),
            IngressAction::DropSteered
        );
        for dns in [DnsPolicy::Intercept, DnsPolicy::Forward] {
            assert_eq!(
                route_ingress(quic, plan, dns, Backstop::Lapsed),
                IngressAction::ForwardPacket(plan)
            );
        }
        let https = Transport::Tcp {
            source_port: 50_000,
            destination_port: HTTPS_PORT,
        };
        assert_eq!(
            route_ingress(https, plan, DnsPolicy::Intercept, Backstop::Active),
            IngressAction::ForwardPacket(plan)
        );
        // DNS interception remains independent because it uses another port.
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
        assert_eq!(Mtu::new(68), Err(MtuError::BelowMinimum(68)));
        assert_eq!(
            Mtu::new(MIN_IPV6_MTU - 1),
            Err(MtuError::BelowMinimum(MIN_IPV6_MTU - 1))
        );
        assert_eq!(Mtu::new(MIN_IPV6_MTU).map(Mtu::get), Ok(MIN_IPV6_MTU));

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

        // Inspection affects only the matching flow.
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

        // Terminated flows use the egress datagram ceiling for QUIC.
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

        // Separate an invalid inner MTU from path-overhead overflow.
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

        // Fragments are settled before the plan is consulted.
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
