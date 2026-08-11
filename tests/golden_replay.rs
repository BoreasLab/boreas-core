//! The P4 gate: a scripted packet trace drives the datapath, and every emitted
//! transmit and event is asserted byte-exact and in order. Deterministic
//! because the only inputs are bytes and a synthetic clock.

use std::{
    net::{IpAddr, Ipv4Addr},
    num::NonZeroUsize,
    time::{Duration, Instant},
};

use boreas_core::{
    Accepts, DatagramFidelity, Datapath, EgressCapabilities, FilterPolicy, FlowEvent,
    InternalEndpoint, Mtu, NatBehavior, SendOutcome, SteeringReason,
};

const NOW: Duration = Duration::from_secs(1_000);

fn egress(fidelity: DatagramFidelity) -> EgressCapabilities {
    EgressCapabilities {
        accepts: Accepts::Flows,
        datagram_fidelity: fidelity,
        overhead_bytes: 60,
        max_datagram_size: Some(1500),
        preserves_ecn: true,
        nat_behavior: NatBehavior::EndpointIndependent,
    }
}

fn udp_frame() -> Vec<u8> {
    vec![
        0x45, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2, 0x04,
        0xd2, 0x00, 0x35, 0x00, 0x08, 0, 0,
    ]
}

#[test]
fn golden_replay_is_byte_exact() {
    let mut path = Datapath::new(
        FilterPolicy::PassThrough,
        egress(DatagramFidelity::Native),
        Mtu::new(1500).unwrap(),
        Duration::from_secs(30),
        NonZeroUsize::new(8).unwrap(),
        Duration::from_secs(120),
        NonZeroUsize::new(2).unwrap(),
    )
    .unwrap();
    let start = Instant::now() + NOW;
    let endpoint = InternalEndpoint {
        address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        port: 1234,
    };

    // 1. A whole datagram opens a flow; no transmit on the terminated path.
    path.on_tun_packet(&udp_frame(), start).unwrap();
    assert_eq!(
        path.poll_event(),
        Some(FlowEvent::DatagramOpened(endpoint)),
        "step 1 event"
    );
    assert_eq!(path.poll_transmit(), None, "step 1 transmit");

    // 2. Two datagrams buffer; the third drops and reports.
    assert_eq!(
        path.send_datagram(endpoint, vec![1], start),
        Ok(SendOutcome::Buffered)
    );
    assert_eq!(
        path.send_datagram(endpoint, vec![2], start),
        Ok(SendOutcome::Buffered)
    );
    assert_eq!(
        path.send_datagram(endpoint, vec![3], start),
        Ok(SendOutcome::Dropped)
    );
    assert_eq!(
        path.poll_event(),
        Some(FlowEvent::DatagramDropped(endpoint)),
        "step 2 event"
    );

    // 3. A fidelity downgrade re-steers; the flow and its buffered data live.
    path.on_capability_change(egress(DatagramFidelity::Emulated));
    assert_eq!(
        path.poll_event(),
        Some(FlowEvent::Resteered(SteeringReason::DatagramFidelity)),
        "step 3 event"
    );

    // 4. Idle timeout evicts the flow; nothing else fires.
    path.on_timeout(start + Duration::from_secs(121));
    assert_eq!(path.poll_event(), None, "step 4 event");
    assert_eq!(path.poll_transmit(), None, "step 4 transmit");
}
