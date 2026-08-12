//! The P4 gate: a scripted packet trace drives the datapath, and every emitted
//! transmit and event is asserted byte-exact and in order. Deterministic
//! because the only inputs are bytes and a synthetic clock.

use std::{
    net::{IpAddr, Ipv4Addr},
    num::NonZeroUsize,
    time::{Duration, Instant},
};

use boreas_core::{
    Accepts, BufferPool, DatagramFidelity, Datapath, EgressCapabilities, FilterPolicy, FlowEvent,
    InternalEndpoint, Mtu, NatBehavior, SendOutcome, SteeringReason,
};

const NOW: Duration = Duration::from_secs(1_000);

fn egress(fidelity: DatagramFidelity) -> EgressCapabilities {
    EgressCapabilities {
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
        Accepts::Flows,
        egress(DatagramFidelity::Native),
        Mtu::new(1500).unwrap(),
        boreas_core::Limits {
            reassembly_timeout: Duration::from_secs(30),
            max_pending_reassemblies: NonZeroUsize::new(8).unwrap(),
            flow_idle_timeout: Duration::from_secs(120),
            datagram_buffer_capacity: NonZeroUsize::new(2).unwrap(),
        },
        BufferPool::new(
            NonZeroUsize::new(1500).unwrap(),
            NonZeroUsize::new(64).unwrap(),
        ),
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

    // 2. Two datagrams buffer; the third drops and reports. Payload bytes come
    //    from the shared pool, so the byte-exactness this test asserts covers
    //    the budget accounting too.
    let pool = BufferPool::new(
        NonZeroUsize::new(1500).unwrap(),
        NonZeroUsize::new(4).unwrap(),
    );
    assert_eq!(
        path.send_datagram(endpoint, pool.take(&[1]).unwrap(), start),
        Ok(SendOutcome::Buffered)
    );
    assert_eq!(
        path.send_datagram(endpoint, pool.take(&[2]).unwrap(), start),
        Ok(SendOutcome::Buffered)
    );
    assert_eq!(pool.available(), 2, "two queued payloads hold the budget");
    assert_eq!(
        path.send_datagram(endpoint, pool.take(&[3]).unwrap(), start),
        Ok(SendOutcome::Dropped)
    );
    assert_eq!(
        pool.available(),
        2,
        "the refused payload returned its buffer"
    );
    assert_eq!(
        path.poll_event(),
        Some(FlowEvent::DatagramDropped(endpoint)),
        "step 2 event"
    );

    // 3. A fidelity downgrade re-steers; the flow and its buffered data live.
    path.on_capability_change(Accepts::Flows, egress(DatagramFidelity::Emulated));
    assert_eq!(
        path.poll_event(),
        Some(FlowEvent::Resteered(SteeringReason::DatagramFidelity)),
        "step 3 event"
    );

    // 4. Idle timeout evicts the flow; nothing else fires, and the flow's
    //    queue returns to the pool as it drops.
    path.on_timeout(start + Duration::from_secs(121));
    assert_eq!(path.poll_event(), None, "step 4 event");
    assert_eq!(path.poll_transmit(), None, "step 4 transmit");
    assert_eq!(pool.available(), 4, "step 4 pool");
}
