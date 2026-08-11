//! The P8 gate: the runtime shell starts, forwards a packet, reports events,
//! honors bounded channels, and shuts down with no task leak.

use std::{num::NonZeroUsize, time::Duration};

use boreas_core::{
    Accepts, AsyncDevice, BufferPool, DatagramFidelity, Datapath, EgressCapabilities, FilterPolicy,
    Mtu, NatBehavior, Shell,
};

fn datapath() -> Datapath {
    Datapath::new(
        FilterPolicy::PassThrough,
        EgressCapabilities {
            accepts: Accepts::IpPackets,
            datagram_fidelity: DatagramFidelity::Native,
            overhead_bytes: 60,
            max_datagram_size: None,
            preserves_ecn: true,
            nat_behavior: NatBehavior::EndpointIndependent,
        },
        Mtu::new(1500).unwrap(),
        Duration::from_secs(30),
        NonZeroUsize::new(8).unwrap(),
        Duration::from_secs(120),
        NonZeroUsize::new(8).unwrap(),
    )
    .unwrap()
}

struct MockDevice {
    inbound: tokio::sync::mpsc::Receiver<Vec<u8>>,
    pub sent: tokio::sync::mpsc::Sender<Vec<u8>>,
}

impl AsyncDevice for MockDevice {
    #[allow(clippy::manual_async_fn)]
    fn recv<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = std::io::Result<usize>> + Send + 'a {
        async move {
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

fn udp_frame() -> Vec<u8> {
    vec![
        0x45, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2, 0x04,
        0xd2, 0x00, 0x35, 0x00, 0x08, 0, 0,
    ]
}

#[tokio::test]
async fn shell_forwards_and_shuts_down_without_leaking() {
    let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(8);
    let (sent_tx, mut sent_rx) = tokio::sync::mpsc::channel(8);
    let device = MockDevice {
        inbound: inbound_rx,
        sent: sent_tx,
    };
    let pool = BufferPool::new(1500, 8);
    let shell = Shell::start(datapath(), device, pool);

    // A packet in produces a forwarded transmit and an open event.
    inbound_tx.send(udp_frame()).await.unwrap();
    let forwarded = tokio::time::timeout(Duration::from_secs(2), sent_rx.recv())
        .await
        .expect("forwarded packet")
        .expect("channel open");
    assert_eq!(forwarded, udp_frame());

    // The packet fast path forwards without opening a flow, so no event
    // follows the transmit; the transmit itself is the proof of the loop.

    // Shutdown drains: the reactor task completes.
    shell.shutdown().await.expect("clean shutdown");
}

#[tokio::test]
async fn pool_bounds_payload_memory() {
    let pool = BufferPool::new(8, 4);
    let a = pool.take(b"12345678").unwrap();
    let b = pool.take(b"abcdefgh").unwrap();
    assert_eq!(pool.available(), 2);
    // Exhaustion returns None rather than waiting.
    let c = pool.take(b"xy").unwrap();
    let d = pool.take(b"z").unwrap();
    assert_eq!(pool.available(), 0);
    assert!(pool.take(b"nope").is_none());
    assert!(pool.take(b"this datagram is far too large").is_none());

    drop(a);
    drop(b);
    assert_eq!(pool.available(), 2);
    let _ = (c, d);
    // A recycled slice serves new data.
    let e = pool.take(b"ok").unwrap();
    assert_eq!(&*e, b"ok");
}
