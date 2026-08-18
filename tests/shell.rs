//! The P8 gate, extended by P10's fusion. Each test names one property:
//!
//! 1. the reactor carries a packet from the device out through the egress and
//!    shuts down leaving no task behind;
//! 2. its timer is armed against deadlines it can name — the core's, the
//!    telemetry report, the egress tick — never a poll interval;
//! 3. a malformed packet is an observation, not the end of the reactor;
//! 4. a datagram producer is never blocked, and a refusal releases its buffer;
//! 5. control messages reach the core in order.

use std::{
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use boreas_core::{
    Accepts, AsyncDevice, AsyncNetwork, BufferPool, Control, DatagramFidelity, Datapath, DnsPolicy,
    DnsUpstream, EgressEmit, EgressError, FilterPolicy, FlowEvent, HostPolicy, Inbound,
    InternalEndpoint, Mtu, NatBehavior, PacketEgress, PathProperties, Relay, Session, Shell,
    Telemetry, Upstream,
};

fn properties() -> PathProperties {
    PathProperties {
        datagram_fidelity: DatagramFidelity::Native,
        overhead_bytes: 60,
        max_datagram_size: Some(1500),
        preserves_ecn: true,
        nat_behavior: NatBehavior::EndpointIndependent,
    }
}

/// `flow_idle_timeout` is the RFC 4787 floor, which is also the deadline the
/// timer test reads back out of the core.
fn datapath_on(accepts: Accepts, queue_depth: usize, pool: Arc<BufferPool>) -> Datapath {
    Datapath::new(
        FilterPolicy::PassThrough,
        DnsPolicy::Forward,
        accepts,
        properties(),
        Mtu::new(1500).unwrap(),
        boreas_core::Limits {
            reassembly_timeout: Duration::from_secs(30),
            max_pending_reassemblies: NonZeroUsize::new(8).unwrap(),
            flow_idle_timeout: Duration::from_secs(120),
            datagram_buffer_capacity: NonZeroUsize::new(queue_depth).unwrap(),
            // Long enough to outlast a browser's cached Alt-Svc entry for
            // an origin, which is what the DNS rewrite alone cannot reach.
            inspection_window: Duration::from_secs(60),
            max_inspected_addresses: NonZeroUsize::new(256).unwrap(),
            inspected_ports: boreas_core::DEFAULT_INSPECTED_PORTS,
            origination_ports: None,
        },
        pool,
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
    fn mtu(&self) -> Mtu {
        Mtu::new(1500).unwrap()
    }

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
    ) -> impl Future<Output = std::io::Result<()>> + Send + 'a {
        async move {
            self.sent.send(buf.to_vec()).await.map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "sent sink closed")
            })
        }
    }
}

struct Wire {
    inbound: tokio::sync::mpsc::Sender<Vec<u8>>,
    sent: tokio::sync::mpsc::Receiver<Vec<u8>>,
    reads: Arc<AtomicU64>,
}

/// The network seam over the same channel shape. `recv` awaits a tokio
/// channel, which is cancel-safe, so it satisfies the obligation
/// `AsyncNetwork::recv` states.
struct MockNetwork {
    inbound: tokio::sync::mpsc::Receiver<Vec<u8>>,
    sent: tokio::sync::mpsc::Sender<Vec<u8>>,
}

impl AsyncNetwork for MockNetwork {
    #[allow(clippy::manual_async_fn)]
    fn recv<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = std::io::Result<usize>> + Send + 'a {
        async move {
            match self.inbound.recv().await {
                Some(datagram) if datagram.len() <= buf.len() => {
                    buf[..datagram.len()].copy_from_slice(&datagram);
                    Ok(datagram.len())
                }
                Some(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "oversized datagram",
                )),
                None => std::future::pending().await,
            }
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn send<'a>(
        &'a mut self,
        buf: &'a [u8],
    ) -> impl Future<Output = std::io::Result<()>> + Send + 'a {
        async move {
            self.sent.send(buf.to_vec()).await.map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "network sink closed")
            })
        }
    }
}

struct Peer {
    inbound: tokio::sync::mpsc::Sender<Vec<u8>>,
    sent: tokio::sync::mpsc::Receiver<Vec<u8>>,
}

fn network() -> (MockNetwork, Peer) {
    let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(64);
    let (sent_tx, sent_rx) = tokio::sync::mpsc::channel(64);
    (
        MockNetwork {
            inbound: inbound_rx,
            sent: sent_tx,
        },
        Peer {
            inbound: inbound_tx,
            sent: sent_rx,
        },
    )
}

/// A packet egress with no protocol: bytes cross unchanged in both
/// directions. It isolates the reactor's routing — device to egress to
/// network, network to egress to core to device — from any tunnel's
/// cryptography, which `tests/egress.rs` covers separately.
struct PassThroughEgress {
    pool: Arc<BufferPool>,
}

impl PacketEgress for PassThroughEgress {
    fn properties(&self) -> PathProperties {
        properties()
    }

    fn handle_tun_packet(
        &mut self,
        packet: &[u8],
        out: &mut Vec<EgressEmit>,
    ) -> Result<(), EgressError> {
        out.push(EgressEmit::ToNetwork(
            self.pool.take(packet).ok_or(EgressError::PoolExhausted)?,
        ));
        Ok(())
    }

    fn handle_network_packet(
        &mut self,
        datagram: &[u8],
        out: &mut Vec<EgressEmit>,
    ) -> Result<(), EgressError> {
        out.push(EgressEmit::ToTunnel(
            self.pool.take(datagram).ok_or(EgressError::PoolExhausted)?,
        ));
        Ok(())
    }

    fn tick(&mut self, _out: &mut Vec<EgressEmit>) -> Result<(), EgressError> {
        Ok(())
    }

    fn tick_interval(&self) -> Duration {
        Duration::from_millis(250)
    }
}

/// A DNS upstream that is never consulted: these sessions are configured with
/// `DnsPolicy::Forward`, so the core emits no queries at all. It exists to
/// name that fact rather than to answer anything.
struct NoUpstream;

impl DnsUpstream for NoUpstream {
    fn kind(&self) -> Upstream {
        Upstream::Do53
    }

    #[allow(clippy::manual_async_fn)]
    fn query(&self, _message: &[u8]) -> impl Future<Output = std::io::Result<Vec<u8>>> + Send {
        async {
            Err(std::io::Error::other(
                "this session forwards DNS rather than intercepting it",
            ))
        }
    }
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
async fn a_fast_path_packet_leaves_by_the_egress_and_returns_by_the_device() {
    // The fused shape, end to end inside the reactor. A packet from the
    // client's TUN must leave through the egress and appear on the network,
    // and a datagram from the network must be decapsulated and delivered to
    // the device. A shell that owned only a device could do neither, and the
    // packet would come straight back at the client.
    let (device, mut wire) = wire();
    let (net, mut peer) = network();
    let pool = pool(64);
    let shell = Shell::start(
        datapath_on(Accepts::IpPackets, 8, Arc::clone(&pool)),
        Session {
            device,
            network: net,
            egress: PassThroughEgress { pool },
            upstream: NoUpstream,
            policy: tokio::sync::watch::channel(Arc::new(HostPolicy::new())).1,
            termination: None,
            relay: None,
        },
    );

    wire.inbound.send(udp_frame()).await.unwrap();
    let outbound = tokio::time::timeout(Duration::from_secs(2), peer.sent.recv())
        .await
        .expect("the packet reached the network")
        .expect("channel open");
    assert_eq!(outbound, udp_frame());
    assert!(
        wire.sent.try_recv().is_err(),
        "a tun-side packet must not be looped back down the tun"
    );

    peer.inbound.send(udp_frame()).await.unwrap();
    let inbound = tokio::time::timeout(Duration::from_secs(2), wire.sent.recv())
        .await
        .expect("the datagram reached the device")
        .expect("channel open");
    assert_eq!(inbound, udp_frame());

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
    let (net, _peer) = network();
    let pool = pool(64);
    let shell = Shell::start(
        datapath_on(Accepts::IpPackets, 8, Arc::clone(&pool)),
        Session {
            device,
            network: net,
            egress: PassThroughEgress { pool },
            upstream: NoUpstream,
            policy: tokio::sync::watch::channel(Arc::new(HostPolicy::new())).1,
            termination: None,
            relay: None,
        },
    );

    // Let the reactor reach its first wait, then run an hour of virtual time.
    tokio::task::yield_now().await;
    let before = wire.reads.load(Ordering::Relaxed);
    tokio::time::advance(Duration::from_secs(3600)).await;
    let woke = wire.reads.load(Ordering::Relaxed) - before;

    // Every wakeup in an idle hour is a named deadline: 7 200 telemetry
    // reports at 500 ms and 14 400 egress ticks at 250 ms, so about 21 600.
    // A 50 ms poll interval would be 72 000. The bound fails loudly for the
    // latter and leaves the accounted-for wakeups ample room.
    assert!(
        woke < 30_000,
        "reactor woke {woke} times in an idle hour: it is polling, not waiting on a deadline"
    );

    shell.shutdown().await.expect("clean shutdown");
}

#[tokio::test]
async fn a_malformed_packet_is_counted_not_fatal() {
    let (device, wire) = wire();
    let (net, mut peer) = network();
    let pool = pool(64);
    let mut shell = Shell::start(
        datapath_on(Accepts::IpPackets, 8, Arc::clone(&pool)),
        Session {
            device,
            network: net,
            egress: PassThroughEgress { pool },
            upstream: NoUpstream,
            policy: tokio::sync::watch::channel(Arc::new(HostPolicy::new())).1,
            termination: None,
            relay: None,
        },
    );
    let wire = wire.inbound;

    // Three packets an untrusted network sends on purpose:
    //   - a truncated IP header, which the core cannot parse at all;
    //   - a SYN whose MSS option claims two bytes it does not carry, which the
    //     clamp must decline rather than read past;
    //   - a well-formed datagram, which must still be forwarded afterwards.
    wire.send(vec![0x45]).await.unwrap();
    wire.send(truncated_mss_syn()).await.unwrap();
    wire.send(udp_frame()).await.unwrap();

    let mut forwarded = Vec::new();
    for _ in 0..2 {
        forwarded.push(
            tokio::time::timeout(Duration::from_secs(2), peer.sent.recv())
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

/// **The L4 datagram path through the reactor.** On a flow-accepting egress a
/// client datagram is not a packet to forward: it must reach the relay carrying
/// the target the client addressed, and the reply must come back down the
/// device as a whole IP packet from that peer. Neither half existed — the
/// payload was queued and never drained, and there was nothing to drain it
/// into.
#[tokio::test]
async fn a_client_datagram_reaches_the_relay_and_its_reply_reaches_the_device() {
    let (device, mut wire) = wire();
    let (net, _peer) = network();
    let pool = pool(64);
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel(8);
    let (in_tx, in_rx) = tokio::sync::mpsc::channel(8);

    let shell = Shell::start(
        datapath_on(Accepts::Flows, 8, Arc::clone(&pool)),
        Session {
            device,
            network: net,
            egress: PassThroughEgress {
                pool: Arc::clone(&pool),
            },
            upstream: NoUpstream,
            policy: tokio::sync::watch::channel(Arc::new(HostPolicy::new())).1,
            termination: None,
            relay: Some(Relay {
                outbound: out_tx,
                inbound: in_rx,
            }),
        },
    );

    wire.inbound.send(udp_frame()).await.unwrap();
    let outbound = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
        .await
        .expect("the datagram reached the relay")
        .expect("channel open");
    assert_eq!(
        outbound.target,
        std::net::SocketAddr::from(([198, 51, 100, 2], 53)),
        "the target the client addressed travels with the datagram"
    );
    assert_eq!(outbound.client.port, 1234);
    assert_eq!(&*outbound.payload, &udp_frame()[28..]);
    assert!(
        wire.sent.try_recv().is_err(),
        "a terminated datagram is consumed, not forwarded"
    );

    // The reply, synthesized back into an IP packet addressed to the client.
    in_tx
        .send(Inbound {
            client: outbound.client,
            peer: InternalEndpoint {
                address: "198.51.100.2".parse().unwrap(),
                port: 53,
            },
            payload: pool.take(b"answer").unwrap(),
        })
        .await
        .unwrap();
    let returned = tokio::time::timeout(Duration::from_secs(2), wire.sent.recv())
        .await
        .expect("the reply reached the device")
        .expect("channel open");
    assert_eq!(&returned[12..16], &[198, 51, 100, 2], "source is the peer");
    assert_eq!(
        &returned[16..20],
        &[192, 0, 2, 1],
        "destination is the client"
    );
    assert_eq!(&returned[returned.len() - 6..], b"answer");

    drop(outbound);
    shell.shutdown().await.expect("clean shutdown");
    assert_eq!(pool.available(), 64, "every buffer returned to the budget");
}

#[tokio::test]
async fn control_messages_reach_the_core_in_order() {
    let (device, wire) = wire();
    let (net, _peer) = network();
    let pool = pool(64);
    let mut shell = Shell::start(
        datapath_on(Accepts::Flows, 8, Arc::clone(&pool)),
        Session {
            device,
            network: net,
            egress: PassThroughEgress { pool },
            upstream: NoUpstream,
            policy: tokio::sync::watch::channel(Arc::new(HostPolicy::new())).1,
            termination: None,
            relay: None,
        },
    );

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
        .send(Control::PathChange(Accepts::IpPackets, properties()))
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
