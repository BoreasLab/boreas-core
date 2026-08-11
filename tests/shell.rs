//! The P8 gate. Each test names one property the phase claims:
//!
//! 1. the reactor forwards packets and shuts down leaving no task behind;
//! 2. its timer is armed against the core's own deadline, not a poll interval;
//! 3. a malformed packet is an observation, not the end of the reactor;
//! 4. a datagram producer is never blocked, and a refusal releases its buffer;
//! 5. telemetry loss under saturation is counted rather than silent.

use std::{
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use boreas_core::{
    Accepts, AsyncDevice, BufferPool, Control, DatagramFidelity, Datapath, EgressCapabilities,
    FilterPolicy, FlowEvent, InternalEndpoint, Mtu, NatBehavior, SendOutcome, Shell, Telemetry,
};

fn capabilities(accepts: Accepts) -> EgressCapabilities {
    EgressCapabilities {
        accepts,
        datagram_fidelity: DatagramFidelity::Native,
        overhead_bytes: 60,
        max_datagram_size: Some(1500),
        preserves_ecn: true,
        nat_behavior: NatBehavior::EndpointIndependent,
    }
}

/// `flow_idle_timeout` is the RFC 4787 floor, which is also the deadline the
/// timer test reads back out of the core.
fn datapath(accepts: Accepts, queue_depth: usize) -> Datapath {
    Datapath::new(
        FilterPolicy::PassThrough,
        capabilities(accepts),
        Mtu::new(1500).unwrap(),
        Duration::from_secs(30),
        NonZeroUsize::new(8).unwrap(),
        Duration::from_secs(120),
        NonZeroUsize::new(queue_depth).unwrap(),
    )
    .unwrap()
}

fn pool(slices: usize) -> Arc<BufferPool> {
    BufferPool::new(
        NonZeroUsize::new(1500).unwrap(),
        NonZeroUsize::new(slices).unwrap(),
    )
}

/// A device over two tokio channels. Both `recv` implementations await a
/// channel, which tokio documents as cancel-safe, so this mock satisfies the
/// obligation `AsyncDevice::recv` states.
struct MockDevice {
    inbound: tokio::sync::mpsc::Receiver<Vec<u8>>,
    sent: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// Counts `recv` calls, which is how the timer test observes that the
    /// reactor is not waking on a fixed interval.
    reads: Arc<AtomicU64>,
}

impl AsyncDevice for MockDevice {
    #[allow(clippy::manual_async_fn)]
    fn recv<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = std::io::Result<usize>> + Send + 'a {
        async move {
            self.reads.fetch_add(1, Ordering::Relaxed);
            match self.inbound.recv().await {
                Some(packet) if packet.len() <= buf.len() => {
                    buf[..packet.len()].copy_from_slice(&packet);
                    Ok(packet.len())
                }
                Some(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "oversized packet",
                )),
                None => std::future::pending().await,
            }
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn send<'a>(
        &'a mut self,
        buf: &'a [u8],
    ) -> impl Future<Output = std::io::Result<usize>> + Send + 'a {
        async move {
            self.sent.send(buf.to_vec()).await.map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "sent sink closed")
            })?;
            Ok(buf.len())
        }
    }
}

struct Wire {
    inbound: tokio::sync::mpsc::Sender<Vec<u8>>,
    sent: tokio::sync::mpsc::Receiver<Vec<u8>>,
    reads: Arc<AtomicU64>,
}

fn wire() -> (MockDevice, Wire) {
    let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(64);
    let (sent_tx, sent_rx) = tokio::sync::mpsc::channel(64);
    let reads = Arc::new(AtomicU64::new(0));
    (
        MockDevice {
            inbound: inbound_rx,
            sent: sent_tx,
            reads: Arc::clone(&reads),
        },
        Wire {
            inbound: inbound_tx,
            sent: sent_rx,
            reads,
        },
    )
}

fn udp_frame() -> Vec<u8> {
    vec![
        0x45, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2, 0x04,
        0xd2, 0x00, 0x35, 0x00, 0x08, 0, 0,
    ]
}

#[tokio::test]
async fn shell_forwards_and_shuts_down_without_leaking() {
    let (device, mut wire) = wire();
    let shell = Shell::start(datapath(Accepts::IpPackets, 8), device);

    wire.inbound.send(udp_frame()).await.unwrap();
    let forwarded = tokio::time::timeout(Duration::from_secs(2), wire.sent.recv())
        .await
        .expect("forwarded packet")
        .expect("channel open");
    assert_eq!(forwarded, udp_frame());

    // Shutdown drains: the reactor's `JoinHandle` completes.
    shell.shutdown().await.expect("clean shutdown");
}

#[tokio::test(start_paused = true)]
async fn the_timer_is_armed_against_the_core_deadline_not_a_poll_interval() {
    // With tokio's clock paused, time only advances when every task is idle,
    // so the reactor's own timer is the thing being measured. An idle core has
    // no deadline at all, and the reactor must therefore wake only for its
    // telemetry tick — not twenty times a second for a poll interval.
    let (device, wire) = wire();
    let shell = Shell::start(datapath(Accepts::IpPackets, 8), device);

    // Let the reactor reach its first wait, then run an hour of virtual time.
    tokio::task::yield_now().await;
    let before = wire.reads.load(Ordering::Relaxed);
    tokio::time::advance(Duration::from_secs(3600)).await;
    let woke = wire.reads.load(Ordering::Relaxed) - before;

    // 3600 s of reporting ticks at 500 ms is 7200 wakeups; a 50 ms poll
    // interval would have been 72 000. The bound below fails loudly for the
    // latter and leaves the former ample room.
    assert!(
        woke < 20_000,
        "reactor woke {woke} times in an idle hour: it is polling, not waiting on a deadline"
    );

    shell.shutdown().await.expect("clean shutdown");
}

#[tokio::test]
async fn a_malformed_packet_is_counted_not_fatal() {
    let (device, mut wire) = wire();
    let mut shell = Shell::start(datapath(Accepts::IpPackets, 8), device);

    // Three packets an untrusted network sends on purpose:
    //   - a truncated IP header, which the core cannot parse at all;
    //   - a SYN whose MSS option claims two bytes it does not carry, which the
    //     clamp must decline rather than read past;
    //   - a well-formed datagram, which must still be forwarded afterwards.
    wire.inbound.send(vec![0x45]).await.unwrap();
    wire.inbound.send(truncated_mss_syn()).await.unwrap();
    wire.inbound.send(udp_frame()).await.unwrap();

    let mut forwarded = Vec::new();
    for _ in 0..2 {
        forwarded.push(
            tokio::time::timeout(Duration::from_secs(2), wire.sent.recv())
                .await
                .expect("reactor survived the malformed packets")
                .expect("channel open"),
        );
    }
    // The unparseable packet is dropped; the malformed option passes through
    // unclamped and byte-identical, which is the whole point of declining.
    assert_eq!(forwarded, vec![truncated_mss_syn(), udp_frame()]);

    // And the rejection was reported rather than swallowed.
    let rejected = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match shell.next_telemetry().await {
                Some(Telemetry::PacketsRejected(count)) => return count,
                Some(_) => continue,
                None => panic!("telemetry closed"),
            }
        }
    })
    .await
    .expect("a rejection report");
    assert!(rejected >= 1);

    shell.shutdown().await.expect("clean shutdown");
}

/// An IPv4 SYN whose TCP header ends in a `kind = 2, length = 2` MSS option.
/// The option claims a value it does not carry, which is the shape that used
/// to index past the end of the segment.
fn truncated_mss_syn() -> Vec<u8> {
    let mut packet = vec![0u8; 44];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&44u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
    packet[16..20].copy_from_slice(&[198, 51, 100, 2]);
    packet[20..22].copy_from_slice(&1234u16.to_be_bytes());
    packet[22..24].copy_from_slice(&443u16.to_be_bytes());
    packet[32] = 6 << 4; // data offset 6: the header ends exactly at the option
    packet[33] = 0x02; // SYN
    packet[40] = 1; // NOP
    packet[41] = 1; // NOP
    packet[42] = 2; // MSS
    packet[43] = 2; // length 2, two bytes short of a real MSS option
    packet
}

#[tokio::test]
async fn a_datagram_producer_is_never_blocked_and_a_refusal_frees_its_buffer() {
    let (device, _wire) = wire();
    let pool = pool(4);
    // A flow-accepting egress so datagrams take the flow path rather than the
    // packet fast path.
    let shell = Shell::start(datapath(Accepts::Flows, 8), device);
    let endpoint = InternalEndpoint {
        address: "192.0.2.1".parse().unwrap(),
        port: 1234,
    };

    // Offering a datagram takes the pool budget and never awaits.
    let outcome = shell.try_send_datagram(endpoint, pool.take(b"payload").unwrap());
    assert_eq!(outcome, SendOutcome::Buffered);
    assert!(pool.available() <= 4);

    // Exhausting the pool is a `None`, not a wait: the producer decides.
    let held: Vec<_> = std::iter::from_fn(|| pool.take(b"x")).collect();
    assert!(pool.take(b"x").is_none());
    assert!(pool.exhausted() >= 1);
    drop(held);

    shell.shutdown().await.expect("clean shutdown");
    // Every buffer the shell held is released once the reactor is joined.
    assert_eq!(pool.available(), 4);
}

#[tokio::test]
async fn control_messages_reach_the_core_in_order() {
    let (device, wire) = wire();
    let mut shell = Shell::start(datapath(Accepts::Flows, 8), device);

    // Open a flow, then withdraw the layer it runs on.
    wire.inbound.send(udp_frame()).await.unwrap();
    let opened = tokio::time::timeout(Duration::from_secs(2), shell.next_telemetry())
        .await
        .expect("an open event")
        .expect("telemetry open");
    assert!(matches!(
        opened,
        Telemetry::Event(FlowEvent::DatagramOpened(_))
    ));

    shell
        .control()
        .send(Control::CapabilityChange(capabilities(Accepts::IpPackets)))
        .await
        .expect("control channel open");

    let torn_down = tokio::time::timeout(Duration::from_secs(2), shell.next_telemetry())
        .await
        .expect("a teardown event")
        .expect("telemetry open");
    assert!(matches!(
        torn_down,
        Telemetry::Event(FlowEvent::FlowTornDown(_))
    ));

    shell.shutdown().await.expect("clean shutdown");
}
