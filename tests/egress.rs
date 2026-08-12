//! The P10 gate, exercised in-process: the scripted harness drives packets
//! through the datapath's packet fast path into a real WireGuard egress, a
//! second egress terminates the tunnel, and the decapsulated packet re-enters
//! the datapath's egress side byte-identical. No sockets, no real devices —
//! those belong to the M1 product gate, which this environment cannot run.

use std::{net::Ipv4Addr, num::NonZeroUsize, sync::Arc, time::Duration};

use boreas_core::{
    Accepts, BufferPool, DatagramFidelity, Datapath, DnsPolicy, Egress, EgressCapabilities,
    EgressEmit, FilterPolicy, Harness, Limits, Mtu, NatBehavior, SimDevice, WireGuardConfig,
    WireGuardEgress,
};

/// Slices large enough for an encapsulated 1420-byte packet, and a budget
/// nothing here approaches: an exhaustion in this test would be a defect, not
/// the congestion path (`src/egress.rs` covers that one).
fn pool() -> Arc<BufferPool> {
    BufferPool::new(
        NonZeroUsize::new(2048).unwrap(),
        NonZeroUsize::new(64).unwrap(),
    )
}

fn udp_frame(source: Ipv4Addr, source_port: u16) -> Vec<u8> {
    let [a, b, c, d] = source.octets();
    let [hi, lo] = source_port.to_be_bytes();
    vec![
        0x45, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 64, 17, 0, 0, a, b, c, d, 198, 51, 100, 2, hi, lo,
        0x00, 0x35, 0x00, 0x08, 0, 0,
    ]
}

fn packet_datapath(pool: Arc<BufferPool>) -> Datapath {
    // The egress's real capabilities drive the plan, exactly as the shell
    // would derive them from the `Egress` sum.
    let egress = Egress::Packet(Box::new(client_egress(Arc::clone(&pool))));
    let capabilities = egress.capabilities();
    assert_eq!(egress.accepts(), Accepts::IpPackets);
    Datapath::new(
        FilterPolicy::PassThrough,
        DnsPolicy::Forward,
        egress.accepts(),
        capabilities,
        Mtu::new(1500).unwrap(),
        Limits {
            reassembly_timeout: Duration::from_secs(30),
            max_pending_reassemblies: NonZeroUsize::new(8).unwrap(),
            flow_idle_timeout: Duration::from_secs(120),
            datagram_buffer_capacity: NonZeroUsize::new(8).unwrap(),
            // Long enough to outlast a browser's cached Alt-Svc entry for
            // an origin, which is what the DNS rewrite alone cannot reach.
            steering_backstop: Duration::from_secs(60),
            max_steered_addresses: NonZeroUsize::new(256).unwrap(),
        },
        pool,
    )
    .expect("a WireGuard capability set plans the packet fast path")
}

fn client_egress(pool: Arc<BufferPool>) -> WireGuardEgress {
    WireGuardEgress::new(
        WireGuardConfig {
            private_key: [1; 32],
            peer_public_key: server_public_key(),
            preshared_key: None,
            persistent_keepalive: None,
            inner_mtu: Mtu::new(1420).unwrap(),
        },
        pool,
    )
}

fn server_egress(pool: Arc<BufferPool>) -> WireGuardEgress {
    WireGuardEgress::new(
        WireGuardConfig {
            private_key: [2; 32],
            peer_public_key: client_public_key(),
            preshared_key: None,
            persistent_keepalive: None,
            inner_mtu: Mtu::new(1420).unwrap(),
        },
        pool,
    )
}

fn client_public_key() -> [u8; 32] {
    public_key_of([1; 32])
}

fn server_public_key() -> [u8; 32] {
    public_key_of([2; 32])
}

fn public_key_of(private: [u8; 32]) -> [u8; 32] {
    let secret = gotatun::x25519::StaticSecret::from(private);
    gotatun::x25519::PublicKey::from(&secret).to_bytes()
}

/// Pumps network-bound emits from one egress into the other until the
/// exchange settles, returning everything either end wrote to its tunnel.
fn pump(
    client: &mut WireGuardEgress,
    server: &mut WireGuardEgress,
    initial: Vec<EgressEmit>,
) -> Vec<Vec<u8>> {
    use boreas_core::PacketEgress;

    fn deliver(
        target: &mut WireGuardEgress,
        incoming: &mut Vec<EgressEmit>,
        outgoing: &mut Vec<EgressEmit>,
        tunnelled: &mut Vec<Vec<u8>>,
    ) {
        for emit in incoming.drain(..) {
            match emit {
                EgressEmit::ToNetwork(datagram) => target
                    .handle_network_packet(&datagram, outgoing)
                    .expect("in-band WireGuard exchange"),
                EgressEmit::ToTunnel(packet) => tunnelled.push(packet.to_vec()),
            }
        }
    }

    let mut tunnelled = Vec::new();
    let (mut to_server, mut to_client) = (initial, Vec::new());
    while !to_server.is_empty() || !to_client.is_empty() {
        deliver(server, &mut to_server, &mut to_client, &mut tunnelled);
        deliver(client, &mut to_client, &mut to_server, &mut tunnelled);
    }
    tunnelled
}

#[test]
fn tun_to_wireguard_and_back_is_byte_exact() {
    use boreas_core::PacketEgress;

    let frame = udp_frame(Ipv4Addr::new(192, 0, 2, 1), 1234);
    let base = std::time::Instant::now();
    let pool = pool();

    // The device offers the packet; the harness runs the datapath over it.
    let mut device = SimDevice::new(Mtu::new(1500).unwrap(), 7);
    device.inject(&frame, 0);
    let mut harness = Harness::new(device, packet_datapath(Arc::clone(&pool)), base);
    harness.step(0).expect("device is scripted, not lossy");

    // The packet path forwarded the packet untouched, toward the egress and
    // not back down the device it arrived on, and planned no flow: a
    // packet-path flow is local termination, and the fast-path counter on the
    // egress is what proves none of this entered smoltcp.
    assert_eq!(
        harness.to_egress(),
        std::slice::from_ref(&frame),
        "forwarded unmodified"
    );
    assert!(
        harness.device.sent().is_empty(),
        "a tun-side packet never returns down the tun"
    );
    assert!(
        harness.datapath.poll_event().is_none(),
        "the packet path opens no flows"
    );

    // The forwarded packet enters the WireGuard egress; the first packet also
    // triggers the handshake, which the loopback exchange completes.
    let mut client = client_egress(Arc::clone(&pool));
    let mut server = server_egress(Arc::clone(&pool));
    let mut first = Vec::new();
    client
        .handle_tun_packet(&harness.to_egress()[0], &mut first)
        .expect("within the pool budget");
    let tunnelled = pump(&mut client, &mut server, first);
    assert_eq!(tunnelled, vec![frame.clone()], "wire payload survives");
    assert_eq!(client.fast_path_packets(), 1);

    // The decapsulated packet re-enters the datapath's egress side and is
    // forwarded back toward the client byte-identically, on the tunnel side.
    harness
        .datapath
        .on_egress_packet(&tunnelled[0], base)
        .expect("a whole IP packet from the tunnel");
    let returning: Vec<(boreas_core::Side, Vec<u8>)> =
        std::iter::from_fn(|| harness.datapath.poll_transmit())
            .map(|transmit| (transmit.to, transmit.bytes.to_vec()))
            .collect();
    assert_eq!(returning, vec![(boreas_core::Side::Tunnel, frame)]);
}

#[test]
fn wireguard_capabilities_plan_the_packet_fast_path() {
    let plan = boreas_core::plan_flow(
        FilterPolicy::PassThrough,
        Accepts::IpPackets,
        EgressCapabilities {
            datagram_fidelity: DatagramFidelity::Native,
            overhead_bytes: boreas_core::WIREGUARD_OVERHEAD_BYTES,
            max_datagram_size: None,
            preserves_ecn: false,
            nat_behavior: NatBehavior::EndpointIndependent,
        },
        Mtu::new(1500).unwrap(),
    )
    .expect("WireGuard capabilities plan");

    // 1500 - 80 leaves 1420, the conventional WireGuard MTU, and QUIC clears
    // the 1200-byte floor with headroom.
    assert_eq!(
        plan,
        boreas_core::FlowPlan {
            transport: boreas_core::TransportPath::PacketFastPath {
                inner_mtu: Mtu::new(1420).unwrap(),
            },
            quic: boreas_core::QuicPolicy::PassThrough,
        }
    );
}
