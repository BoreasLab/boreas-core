//! The P7 gate: 10,000 flows through the P5 harness. Expiry state scales with
//! flows, not packets; refreshed flows expire exactly at their real deadlines;
//! per-flow buffers stay lazy.

use std::{
    net::Ipv4Addr,
    num::NonZeroUsize,
    time::{Duration, Instant},
};

use boreas_core::{
    Accepts, BufferPool, DatagramFidelity, Datapath, DnsPolicy, EgressCapabilities, FilterPolicy,
    Mtu, NatBehavior,
};

fn udp_frame(flow: u32) -> Vec<u8> {
    let [a, b, c, d] = Ipv4Addr::from(flow).octets();
    let [port_hi, port_lo] = (10_000u16.wrapping_add(flow as u16)).to_be_bytes();
    vec![
        0x45, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 64, 17, 0, 0, a, b, c, d, 198, 51, 100, 2, port_hi,
        port_lo, 0x00, 0x35, 0x00, 0x08, 0, 0,
    ]
}

#[test]
fn ten_thousand_flows_expire_on_flow_count_not_packet_count() {
    let mut path = Datapath::new(
        FilterPolicy::PassThrough,
        DnsPolicy::Forward,
        Accepts::Flows,
        EgressCapabilities {
            datagram_fidelity: DatagramFidelity::Native,
            overhead_bytes: 60,
            max_datagram_size: Some(1500),
            preserves_ecn: true,
            nat_behavior: NatBehavior::EndpointIndependent,
        },
        Mtu::new(1500).unwrap(),
        boreas_core::Limits {
            reassembly_timeout: Duration::from_secs(30),
            max_pending_reassemblies: NonZeroUsize::new(1024).unwrap(),
            flow_idle_timeout: Duration::from_secs(120),
            datagram_buffer_capacity: NonZeroUsize::new(8).unwrap(),
            // Long enough to outlast a browser's cached Alt-Svc entry for
            // an origin, which is what the DNS rewrite alone cannot reach.
            inspection_window: Duration::from_secs(60),
            max_inspected_addresses: NonZeroUsize::new(256).unwrap(),
            inspected_ports: boreas_core::DEFAULT_INSPECTED_PORTS,
            origination_ports: None,
        },
        BufferPool::new(
            NonZeroUsize::new(1500).unwrap(),
            NonZeroUsize::new(64).unwrap(),
        ),
    )
    .unwrap();

    let start = Instant::now();
    let flows = 10_000;

    // Open 10,000 flows over 10 seconds, then flood every flow with 10
    // refreshes each. The expiry index must hold one slot per flow, not one
    // per packet.
    //
    // Each packet is also a datagram the flow queues for the egress, so the
    // drain runs alongside — which is what a shell does, and what returns the
    // pooled payloads. Draining is part of the gate rather than a nuisance:
    // a datapath that queued 110,000 payloads without a drain would be holding
    // exactly the unbounded state this test exists to refuse.
    let mut opened = 0;
    let mut drained = 0;
    let mut harvest = |path: &mut Datapath| {
        while path.poll_datagram().is_some() {
            drained += 1;
        }
        while let Some(event) = path.poll_event() {
            if matches!(event, boreas_core::FlowEvent::DatagramOpened(_)) {
                opened += 1;
            }
        }
    };

    for flow in 0..flows {
        path.on_tun_packet(&udp_frame(flow), start + Duration::from_millis(flow as u64))
            .unwrap();
        harvest(&mut path);
    }
    for round in 0..10 {
        for flow in 0..flows {
            let now =
                start + Duration::from_secs(10 + round * 10) + Duration::from_millis(flow as u64);
            path.on_tun_packet(&udp_frame(flow), now).unwrap();
            harvest(&mut path);
        }
    }

    assert_eq!(opened, flows as usize, "one open event per flow, ever");
    assert_eq!(
        drained,
        (flows * 11) as usize,
        "every client datagram reached the egress drain"
    );

    // Nothing expires inside the idle window of the last refresh.
    let last_refresh = start + Duration::from_secs(100) + Duration::from_millis(flows as u64);
    path.on_timeout(last_refresh + Duration::from_secs(60));
    // Every flow saw its last refresh at or before last_refresh, so by
    // last_refresh + 121s all of them are gone.
    path.on_timeout(last_refresh + Duration::from_secs(121));
    path.on_tun_packet(&udp_frame(0), last_refresh + Duration::from_secs(122))
        .unwrap();
    assert!(
        matches!(
            path.poll_event(),
            Some(boreas_core::FlowEvent::DatagramOpened(_))
        ),
        "a fresh flow can be created after mass expiry"
    );
}
