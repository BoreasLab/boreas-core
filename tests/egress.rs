//! P10 packet fast-path gate, exercised in-process. A scripted harness drives
//! packets through two WireGuard egresses and checks byte-exact re-entry.
//! Sockets and real devices belong to the M1 product gate.

use std::{net::Ipv4Addr, num::NonZeroUsize, sync::Arc, time::Duration};

use boreas_core::{
    Accepts, BufferPool, DatagramFidelity, Datapath, DnsPolicy, Egress, EgressEmit, FilterPolicy,
    Harness, Limits, Mtu, NatBehavior, PathProperties, SimDevice, WireGuardConfig, WireGuardEgress,
};

/// Pool sized for encapsulated 1420-byte packets; exhaustion here would be a
/// test defect rather than the congestion path in `src/egress/mod.rs`.
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
    // The shell derives the plan from the egress's live path properties.
    let egress = Egress::Packet(Box::new(client_egress(Arc::clone(&pool))));
    let properties = egress.properties();
    assert_eq!(egress.accepts(), Accepts::IpPackets);
    Datapath::new(
        FilterPolicy::PassThrough,
        DnsPolicy::Forward,
        egress.accepts(),
        properties,
        Mtu::new(1500).unwrap(),
        Limits {
            reassembly_timeout: Duration::from_secs(30),
            max_pending_reassemblies: NonZeroUsize::new(8).unwrap(),
            flow_idle_timeout: Duration::from_secs(120),
            datagram_buffer_capacity: NonZeroUsize::new(8).unwrap(),
            // Covers a browser's cached Alt-Svc window.
            inspection_window: Duration::from_secs(60),
            max_inspected_addresses: NonZeroUsize::new(256).unwrap(),
            inspected_ports: boreas_core::DEFAULT_INSPECTED_PORTS,
            origination_ports: None,
        },
        pool,
    )
    .expect("WireGuard path properties plan the packet fast path")
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

/// Delivers network emits between egresses until the exchange settles.
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

    let mut device = SimDevice::new(Mtu::new(1500).unwrap(), 7);
    device.inject(&frame, 0);
    let mut harness = Harness::new(device, packet_datapath(Arc::clone(&pool)), base);
    harness.step(0).expect("device is scripted, not lossy");

    // Fast path preserves bytes, targets egress, and opens no smoltcp flow.
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

    // The first packet triggers the handshake, which the loopback exchange
    // completes.
    let mut client = client_egress(Arc::clone(&pool));
    let mut server = server_egress(Arc::clone(&pool));
    let mut first = Vec::new();
    client
        .handle_tun_packet(&harness.to_egress()[0], &mut first)
        .expect("within the pool budget");
    let tunnelled = pump(&mut client, &mut server, first);
    assert_eq!(tunnelled, vec![frame.clone()], "wire payload survives");
    assert_eq!(client.fast_path_packets(), 1);

    // Decapsulation re-enters the datapath and returns the packet byte-identically
    // on the tunnel side.
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
fn wireguard_properties_plan_the_packet_fast_path() {
    let plan = boreas_core::plan_flow(
        FilterPolicy::PassThrough,
        boreas_core::Inspection::Excluded,
        Accepts::IpPackets,
        PathProperties {
            datagram_fidelity: DatagramFidelity::Native,
            overhead_bytes: boreas_core::WIREGUARD_OVERHEAD_BYTES,
            max_datagram_size: None,
            preserves_ecn: false,
            nat_behavior: NatBehavior::EndpointIndependent,
        },
        Mtu::new(1500).unwrap(),
    )
    .expect("WireGuard path properties plan");

    // 1500 - 80 leaves the conventional 1420-byte WireGuard MTU and clears
    // QUIC's 1200-byte floor.
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
