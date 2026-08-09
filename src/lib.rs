pub const MIN_QUIC_MTU: u16 = 1200;

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
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilterPolicy {
    PassThrough,
    InspectHttp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportPath {
    PacketFastPath,
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
    pub inner_mtu: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanError {
    OverheadExceedsPathMtu,
}

pub fn plan_flow(
    filter: FilterPolicy,
    egress: EgressCapabilities,
    path_mtu: u16,
) -> Result<FlowPlan, PlanError> {
    let inner_mtu = path_mtu
        .checked_sub(egress.overhead_bytes)
        .filter(|mtu| *mtu > 0)
        .ok_or(PlanError::OverheadExceedsPathMtu)?;

    let transport = match (filter, egress.accepts) {
        (FilterPolicy::PassThrough, Accepts::IpPackets) => TransportPath::PacketFastPath,
        _ => TransportPath::LocalTermination,
    };

    let quic = if filter == FilterPolicy::InspectHttp {
        QuicPolicy::SteerToHttp2(SteeringReason::InspectionRequired)
    } else if egress.datagram_fidelity != DatagramFidelity::Native {
        QuicPolicy::SteerToHttp2(SteeringReason::DatagramFidelity)
    } else if inner_mtu < MIN_QUIC_MTU {
        QuicPolicy::SteerToHttp2(SteeringReason::MtuBelowMinimum)
    } else {
        QuicPolicy::PassThrough
    };

    Ok(FlowPlan {
        transport,
        quic,
        inner_mtu,
    })
}

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
        }
    }

    #[test]
    fn flow_planning_enforces_fast_path_and_quic_invariants() {
        let native_l3 = egress(Accepts::IpPackets, DatagramFidelity::Native, 60);
        assert_eq!(
            plan_flow(FilterPolicy::PassThrough, native_l3, 1500),
            Ok(FlowPlan {
                transport: TransportPath::PacketFastPath,
                quic: QuicPolicy::PassThrough,
                inner_mtu: 1440,
            })
        );

        assert_eq!(
            plan_flow(FilterPolicy::InspectHttp, native_l3, 1500).map(|plan| plan.quic),
            Ok(QuicPolicy::SteerToHttp2(SteeringReason::InspectionRequired))
        );
        assert_eq!(
            plan_flow(
                FilterPolicy::PassThrough,
                egress(Accepts::Flows, DatagramFidelity::Emulated, 60),
                1500,
            )
            .map(|plan| (plan.transport, plan.quic)),
            Ok((
                TransportPath::LocalTermination,
                QuicPolicy::SteerToHttp2(SteeringReason::DatagramFidelity),
            ))
        );
        assert_eq!(
            plan_flow(FilterPolicy::PassThrough, native_l3, 1259).map(|plan| plan.quic),
            Ok(QuicPolicy::SteerToHttp2(SteeringReason::MtuBelowMinimum))
        );
        assert_eq!(
            plan_flow(FilterPolicy::PassThrough, native_l3, 60),
            Err(PlanError::OverheadExceedsPathMtu)
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
            })
        );
        assert_eq!(
            first.chain(egress(Accepts::Flows, DatagramFidelity::Native, 0)),
            Err(CapabilityError::MixedLayers)
        );
    }
}
