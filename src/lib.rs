mod datapath;
mod device;
mod packet;
mod path;
mod reassembly;
mod shell;
mod udp;

use std::{error::Error, fmt};

pub use datapath::{Datapath, DatapathError, FlowEvent, Transmit};
pub use device::{Device, Harness, SimDevice};
pub use packet::{IngressPacket, PacketError, Transport};
pub use path::{PathUpdate, clamp_mss, validate_ptb};
pub use reassembly::{Fragment, PushOutcome, Reassembler};
pub use shell::{AsyncDevice, BufferPool, Control, Pooled, Shell, Telemetry};

pub use udp::{DatagramBuffer, FlowTableError, InternalEndpoint, SendOutcome, UdpFlowTable};

pub const MIN_QUIC_MTU: u16 = 1200;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EgressCapabilities {
    pub accepts: Accepts,
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
pub enum CapabilityError {
    MixedLayers,
    OverheadOverflow,
}

impl EgressCapabilities {
    pub fn chain(self, next: Self) -> Result<Self, CapabilityError> {
        if self.accepts != next.accepts {
            return Err(CapabilityError::MixedLayers);
        }

        Ok(Self {
            accepts: self.accepts,
            datagram_fidelity: self.datagram_fidelity.min(next.datagram_fidelity),
            overhead_bytes: self
                .overhead_bytes
                .checked_add(next.overhead_bytes)
                .ok_or(CapabilityError::OverheadOverflow)?,
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

/// The result of re-planning a live flow after an egress reports a capability
/// change. Established flows are never dropped silently: a downgrade yields
/// `Resteer`, and `Teardown` is reserved for a change no live flow can
/// survive (the egress no longer accepts the layer the flow runs on, or its
/// remaining MTU cannot carry IPv6 at all).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Replan {
    Unchanged,
    Resteer(SteeringReason),
    Teardown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngressAction {
    Reassemble,
    ForwardPacket(FlowPlan),
    OpenStream(FlowPlan),
    OpenDatagram(FlowPlan),
    HandleIcmp(FlowPlan),
    DropUnsupported,
}

pub fn plan_flow(
    filter: FilterPolicy,
    egress: EgressCapabilities,
    path_mtu: Mtu,
) -> Result<FlowPlan, PlanError> {
    let transport = match (filter, egress.accepts) {
        (FilterPolicy::PassThrough, Accepts::IpPackets) => {
            let inner_mtu = path_mtu
                .get()
                .checked_sub(egress.overhead_bytes)
                .ok_or(PlanError::OverheadExceedsPathMtu)
                .and_then(|bytes| Mtu::new(bytes).map_err(PlanError::InnerMtu))?;
            TransportPath::PacketFastPath { inner_mtu }
        }
        _ => TransportPath::LocalTermination,
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

    let quic = if filter == FilterPolicy::InspectHttp {
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

/// Re-plans a live flow after its egress reports a capability change (MASQUE's
/// QUIC-to-HTTP/2 fallback is the driving case). The filter policy and path
/// MTU are session properties and pass through unchanged; only the egress
/// moved. Errors only when the new capability cannot support the flow's layer
/// or leaves a packet path below the IPv6 floor, and the caller answers those
/// with `Teardown`.
pub fn replan(
    current: &FlowPlan,
    filter: FilterPolicy,
    next: EgressCapabilities,
    path_mtu: Mtu,
) -> Result<Replan, PlanError> {
    let accepts = match current.transport {
        TransportPath::PacketFastPath { .. } => Accepts::IpPackets,
        TransportPath::LocalTermination => Accepts::Flows,
    };
    if next.accepts != accepts {
        return Ok(Replan::Teardown);
    }

    let next_plan = plan_flow(filter, next, path_mtu)?;
    // Crossing the transport boundary re-originates the flow's bytes; no live
    // flow survives it. A PacketFastPath whose inner MTU merely moved is the
    // same transport with a new budget, handled by MTU machinery, not teardown.
    if std::mem::discriminant(&next_plan.transport) != std::mem::discriminant(&current.transport) {
        return Ok(Replan::Teardown);
    }

    Ok(match (current.quic, next_plan.quic) {
        // A PassThrough flow whose new plan steers must move to HTTP/2.
        (QuicPolicy::PassThrough, QuicPolicy::SteerToHttp2(reason)) => Replan::Resteer(reason),
        // Identical policies, a recovery from steering to pass-through, and a
        // change of steering reason on an already-steered flow all need no
        // action.
        (_, _) => Replan::Unchanged,
    })
}

pub fn route_ingress(
    packet: IngressPacket,
    filter: FilterPolicy,
    egress: EgressCapabilities,
    path_mtu: Mtu,
) -> Result<IngressAction, PlanError> {
    match packet.transport {
        Transport::Fragment => return Ok(IngressAction::Reassemble),
        Transport::Other => return Ok(IngressAction::DropUnsupported),
        Transport::Tcp { .. } | Transport::Udp { .. } | Transport::Icmp => {}
    }

    let plan = plan_flow(filter, egress, path_mtu)?;
    if matches!(plan.transport, TransportPath::PacketFastPath { .. }) {
        return Ok(IngressAction::ForwardPacket(plan));
    }

    Ok(match packet.transport {
        Transport::Tcp { .. } => IngressAction::OpenStream(plan),
        Transport::Udp { .. } => IngressAction::OpenDatagram(plan),
        Transport::Icmp => IngressAction::HandleIcmp(plan),
        Transport::Other | Transport::Fragment => IngressAction::DropUnsupported,
    })
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

impl fmt::Display for CapabilityError {
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

impl Error for CapabilityError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn egress(
        accepts: Accepts,
        fidelity: DatagramFidelity,
        overhead_bytes: u16,
    ) -> EgressCapabilities {
        EgressCapabilities {
            accepts,
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
                        let first = EgressCapabilities {
                            nat_behavior: left_nat,
                            ..egress(Accepts::Flows, left, 0)
                        };
                        let second = EgressCapabilities {
                            nat_behavior: right_nat,
                            ..egress(Accepts::Flows, right, 0)
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
                        let capabilities = EgressCapabilities {
                            max_datagram_size,
                            ..egress(Accepts::IpPackets, fidelity, overhead)
                        };
                        let Ok(plan) =
                            plan_flow(FilterPolicy::PassThrough, capabilities, mtu(path))
                        else {
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
                EgressCapabilities {
                    max_datagram_size: Some(1500),
                    ..egress(Accepts::Flows, DatagramFidelity::Native, 0)
                },
                mtu(1500),
            )
            .unwrap();
            let next = EgressCapabilities {
                max_datagram_size: Some(1500),
                ..egress(Accepts::Flows, fidelity, 0)
            };
            let result = replan(&live, FilterPolicy::PassThrough, next, mtu(1500));
            if fidelity == DatagramFidelity::Native {
                assert_eq!(result, Ok(Replan::Unchanged));
            } else {
                assert_eq!(
                    result,
                    Ok(Replan::Resteer(SteeringReason::DatagramFidelity)),
                    "Native to {fidelity:?} must re-steer, never drop"
                );
            }
        }
    }

    #[test]
    fn replan_tears_down_only_unsurvivable_changes() {
        let packet_plan = plan_flow(
            FilterPolicy::PassThrough,
            egress(Accepts::IpPackets, DatagramFidelity::Native, 60),
            mtu(1500),
        )
        .unwrap();

        // The layer the flow runs on is gone: no live flow survives.
        assert_eq!(
            replan(
                &packet_plan,
                FilterPolicy::PassThrough,
                egress(Accepts::Flows, DatagramFidelity::Native, 60),
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
                egress(Accepts::IpPackets, DatagramFidelity::Native, 300),
                mtu(1500),
            ),
            Err(PlanError::InnerMtu(MtuError::BelowMinimum(1200)))
        );

        // A shrunk datagram ceiling on a packet path does not move the plan.
        assert_eq!(
            replan(
                &packet_plan,
                FilterPolicy::PassThrough,
                egress(Accepts::IpPackets, DatagramFidelity::Native, 100),
                mtu(1500),
            ),
            Ok(Replan::Unchanged)
        );
    }

    #[test]
    fn fragments_never_reach_l4_admission() {
        let native_l3 = egress(Accepts::IpPackets, DatagramFidelity::Native, 0);
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
                    route_ingress(parsed, FilterPolicy::PassThrough, native_l3, mtu(1500)),
                    Ok(IngressAction::Reassemble),
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
            route_ingress(parsed, FilterPolicy::PassThrough, native_l3, mtu(1500)),
            Ok(IngressAction::Reassemble)
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
        let native_l3 = egress(Accepts::IpPackets, DatagramFidelity::Native, 60);
        assert_eq!(
            plan_flow(FilterPolicy::PassThrough, native_l3, mtu(1500)),
            Ok(FlowPlan {
                transport: TransportPath::PacketFastPath {
                    inner_mtu: mtu(1440)
                },
                quic: QuicPolicy::PassThrough,
            })
        );

        assert_eq!(
            plan_flow(FilterPolicy::InspectHttp, native_l3, mtu(1500)).map(|plan| plan.quic),
            Ok(QuicPolicy::SteerToHttp2(SteeringReason::InspectionRequired))
        );
        assert_eq!(
            plan_flow(
                FilterPolicy::PassThrough,
                egress(Accepts::Flows, DatagramFidelity::Emulated, 60),
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
        let native_l4 = egress(Accepts::Flows, DatagramFidelity::Native, 0);
        assert_eq!(
            plan_flow(FilterPolicy::PassThrough, native_l4, mtu(1500)).map(|plan| plan.quic),
            Ok(QuicPolicy::SteerToHttp2(SteeringReason::MtuBelowMinimum)),
            "an undeclared datagram ceiling cannot be shown to clear the floor"
        );
        assert_eq!(
            plan_flow(
                FilterPolicy::PassThrough,
                EgressCapabilities {
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
                EgressCapabilities {
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
            plan_flow(FilterPolicy::PassThrough, native_l3, mtu(1300)),
            Err(PlanError::InnerMtu(MtuError::BelowMinimum(1240)))
        );
        assert_eq!(
            plan_flow(
                FilterPolicy::PassThrough,
                egress(Accepts::IpPackets, DatagramFidelity::Native, 60_000),
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
            CapabilityError::MixedLayers.to_string(),
            "chained egresses accept different layers"
        );
        assert!(
            Error::source(&PlanError::InnerMtu(MtuError::BelowMinimum(1240)))
                .is_some_and(|source| source.to_string().contains("below the 1280-byte"))
        );
    }

    #[test]
    fn chaining_uses_the_weakest_capability() {
        let first = EgressCapabilities {
            max_datagram_size: Some(1400),
            ..egress(Accepts::IpPackets, DatagramFidelity::Native, 40)
        };
        let second = EgressCapabilities {
            max_datagram_size: Some(1300),
            preserves_ecn: false,
            ..egress(Accepts::IpPackets, DatagramFidelity::Emulated, 20)
        };

        assert_eq!(
            first.chain(second),
            Ok(EgressCapabilities {
                accepts: Accepts::IpPackets,
                datagram_fidelity: DatagramFidelity::Emulated,
                overhead_bytes: 60,
                max_datagram_size: Some(1300),
                preserves_ecn: false,
                nat_behavior: NatBehavior::EndpointIndependent,
            })
        );
        assert_eq!(
            first.chain(egress(Accepts::Flows, DatagramFidelity::Native, 0)),
            Err(CapabilityError::MixedLayers)
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
        };
        let native_l3 = egress(Accepts::IpPackets, DatagramFidelity::Native, 60);
        assert!(matches!(
            route_ingress(packet, FilterPolicy::PassThrough, native_l3, mtu(1500)),
            Ok(IngressAction::ForwardPacket(_))
        ));
        assert!(matches!(
            route_ingress(
                packet,
                FilterPolicy::PassThrough,
                egress(Accepts::Flows, DatagramFidelity::Native, 60),
                mtu(1500),
            ),
            Ok(IngressAction::OpenDatagram(_))
        ));

        // A fragment short-circuits ahead of planning, so it is admitted even
        // on a chain whose overhead would fail to plan.
        let fragment = IngressPacket {
            transport: Transport::Fragment,
            ..packet
        };
        assert_eq!(
            route_ingress(
                fragment,
                FilterPolicy::InspectHttp,
                egress(Accepts::IpPackets, DatagramFidelity::Native, 60_000),
                mtu(1500),
            ),
            Ok(IngressAction::Reassemble)
        );
    }
}
