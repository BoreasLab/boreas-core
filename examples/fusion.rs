//! The fusion benchmark: the full fused path — device, datapath, WireGuard
//! encapsulation, decapsulation at the peer, and back — inside one process.
//!
//! The engineering plan's performance budget says the datapath has roughly one
//! microsecond of CPU per packet at 100 Mbps, and that syscalls and wakeups,
//! not compute, are what threaten it. This example measures the compute part
//! end to end and reports nanoseconds per packet; wakeups and context switches
//! are kernel-visible and belong to the on-device run.
//!
//! The two-process baseline the M1 gate compares against needs two real
//! devices joined by a socket pair; this environment has neither, so the
//! baseline figure is recorded as outstanding in docs/verification.md rather
//! than fabricated here.
//!
//! Run it with `cargo run --release --example fusion`. Debug numbers are shown
//! but are not evidence.

use std::{num::NonZeroUsize, time::Duration};

use boreas_core::{
    Datapath, Egress, EgressEmit, FilterPolicy, Harness, Limits, Mtu, SimDevice, WireGuardConfig,
    WireGuardEgress,
};

const PACKETS: usize = 10_000;

fn udp_frame(index: u32) -> Vec<u8> {
    let [a, b, c, d] = std::net::Ipv4Addr::from(index).octets();
    let [hi, lo] = (10_000u16.wrapping_add(index as u16)).to_be_bytes();
    vec![
        0x45, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 64, 17, 0, 0, a, b, c, d, 198, 51, 100, 2, hi, lo,
        0x00, 0x35, 0x00, 0x08, 0, 0,
    ]
}

fn egress(private_key: [u8; 32], peer_public_key: [u8; 32]) -> WireGuardEgress {
    WireGuardEgress::new(WireGuardConfig {
        private_key,
        peer_public_key,
        preshared_key: None,
        persistent_keepalive: None,
        inner_mtu: Mtu::new(1420).unwrap(),
    })
}

fn public_key_of(private: [u8; 32]) -> [u8; 32] {
    let secret = gotatun::x25519::StaticSecret::from(private);
    gotatun::x25519::PublicKey::from(&secret).to_bytes()
}

fn packet_datapath() -> Datapath {
    let egress = Egress::Packet(Box::new(egress([1; 32], public_key_of([2; 32]))));
    Datapath::new(
        FilterPolicy::PassThrough,
        egress.accepts(),
        egress.capabilities(),
        Mtu::new(1500).unwrap(),
        Limits {
            reassembly_timeout: Duration::from_secs(30),
            max_pending_reassemblies: NonZeroUsize::new(8).unwrap(),
            flow_idle_timeout: Duration::from_secs(120),
            datagram_buffer_capacity: NonZeroUsize::new(8).unwrap(),
        },
    )
    .expect("a WireGuard capability set plans")
}

/// Drives the exchange between the two tunnel ends until it settles,
/// returning everything decapsulated, in order.
fn pump(
    client: &mut WireGuardEgress,
    server: &mut WireGuardEgress,
    initial: Vec<EgressEmit>,
) -> Vec<Vec<u8>> {
    fn deliver(
        target: &mut WireGuardEgress,
        incoming: &mut Vec<EgressEmit>,
        outgoing: &mut Vec<EgressEmit>,
        tunnelled: &mut Vec<Vec<u8>>,
    ) {
        for emit in incoming.drain(..) {
            match emit {
                EgressEmit::ToNetwork(datagram) => outgoing.extend(
                    target
                        .handle_network_packet(&datagram)
                        .expect("in-band WireGuard exchange"),
                ),
                EgressEmit::ToTunnel(packet) => tunnelled.push(packet),
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

fn main() {
    let base = std::time::Instant::now();
    let device = SimDevice::new(Mtu::new(1500).unwrap(), 7);
    let mut harness = Harness::new(device, packet_datapath(), base);
    let mut client = egress([1; 32], public_key_of([2; 32]));
    let mut server = egress([2; 32], public_key_of([1; 32]));
    // Packets the harness drained into the device, consumed by cursor.
    let mut sent_cursor = 0;

    // Warmup: the handshake, so the timed section measures steady state.
    harness.device.inject(&udp_frame(0), 0);
    harness.step(0).expect("scripted device");
    let warmup = harness.device.sent()[sent_cursor..].to_vec();
    sent_cursor = harness.device.sent().len();
    for packet in &warmup {
        let first = client.handle_tun_packet(packet);
        let tunnelled = pump(&mut client, &mut server, first);
        assert_eq!(tunnelled, vec![udp_frame(0)], "handshake warmup");
    }

    let started = std::time::Instant::now();
    for index in 1..=PACKETS as u32 {
        harness.device.inject(&udp_frame(index), 0);
        harness.step(0).expect("scripted device");
        let sent = harness.device.sent()[sent_cursor..].to_vec();
        sent_cursor = harness.device.sent().len();
        for packet in &sent {
            let emits = client.handle_tun_packet(packet);
            let tunnelled = pump(&mut client, &mut server, emits);
            for returned in tunnelled {
                harness
                    .datapath
                    .on_egress_packet(&returned, base)
                    .expect("whole packet from the tunnel");
            }
        }
        while harness.datapath.poll_transmit().is_some() {}
    }
    let elapsed = started.elapsed();

    // The datapath alone, same device script, no egress: this isolates the
    // core's parse-and-forward cost from WireGuard's AEAD, which is the split
    // the performance budget's per-packet allowance is written against.
    let mut core_only = Harness::new(
        SimDevice::new(Mtu::new(1500).unwrap(), 7),
        packet_datapath(),
        base,
    );
    let core_started = std::time::Instant::now();
    for index in 1..=PACKETS as u32 {
        core_only.device.inject(&udp_frame(index), 0);
        core_only.step(0).expect("scripted device");
    }
    let core_elapsed = core_started.elapsed();

    let per_packet = elapsed.as_nanos() as f64 / PACKETS as f64;
    let core_per_packet = core_elapsed.as_nanos() as f64 / PACKETS as f64;
    println!("fusion benchmark: {PACKETS} packets, tun -> wireguard -> peer -> back");
    println!("  total:        {elapsed:?}");
    println!("  per packet:   {per_packet:.0} ns end to end");
    println!(
        "  throughput:   {:.0} packets/s",
        PACKETS as f64 / elapsed.as_secs_f64()
    );
    println!(
        "  fast path:    {} packets encapsulated",
        client.fast_path_packets()
    );
    println!("  core only:    {core_per_packet:.0} ns/packet (no egress crypto)");
    println!(
        "  crypto cost:  {:.0} ns/packet (end to end minus core)",
        per_packet - core_per_packet
    );
    // The ~1 us allowance in docs/engineering-plan.md covers the datapath
    // compute the core performs, which the core-only figure measures. AEAD on
    // every payload is a separate, unavoidable cost of the tunnel itself.
    println!(
        "  budget:       core is {} the ~1 us per-packet allowance",
        if core_per_packet < 1_000.0 {
            "within"
        } else {
            "OVER"
        }
    );
}
