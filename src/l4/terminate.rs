//! Reactor bridge for [`LocalStack`] and terminated TCP streams.
//!
//! **The bridge runs as a separate task.** `hyper` awaits while serving a
//! terminated connection, so running it in the reactor would delay packet
//! handling. The reactor supplies packets and drains replies; this task owns
//! the work between those points.
//!
//! **Backpressure is TCP flow control, not loss.** The pump reads from a socket
//! only after reserving channel capacity. Without capacity, bytes remain in
//! `smoltcp`'s receive buffer and the advertised window closes. The channels
//! and stream come from [`crate::bridge`], shared with the QUIC driver.
//!
//! **The pump is a bounded sweep.** One pass probes each live connection, and
//! [`TerminationLimits::max_sockets`](crate::TerminationLimits) bounds that
//! work. A ready list is a measurement-driven optimization, not a second
//! ownership model.

use std::{collections::HashMap, sync::Arc, time::Instant};

use bytes::Bytes;
use tokio::{
    sync::{Notify, mpsc},
    time::{Instant as TokioInstant, sleep_until},
};
use tokio_util::sync::CancellationToken;

use crate::{
    LocalStack, Pooled, StreamError, StreamId, Terminated,
    bridge::{CHUNK, Plumbing, pair},
};

/// One accepted connection and its serving stream.
///
/// The server address identifies the certificate host and the client address
/// identifies the flow.
#[derive(Debug)]
pub struct Accepted {
    pub terminated: Terminated,
    pub stream: TerminatedStream,
}

/// A terminated TCP connection exposed as an async byte stream.
///
/// Closing the write half sends FIN; an exhausted read half observes peer FIN.
///
/// This aliases [`crate::BridgedStream`], also used by the QUIC driver.
pub type TerminatedStream = crate::BridgedStream;

/// Drives the local TCP terminator until cancellation.
///
/// `packets` carries client packets routed to termination, `replies` carries
/// generated segments to the device-owning reactor, and `accepted` publishes
/// new connections.
///
/// Awaiting `replies` cannot deadlock with the reactor: it only `try_send`s into
/// `packets`, and TCP segments must not be dropped like datagrams.
pub async fn run_terminator(
    mut stack: LocalStack,
    mut packets: mpsc::Receiver<Pooled>,
    replies: mpsc::Sender<Pooled>,
    accepted: mpsc::Sender<Accepted>,
    shutdown: CancellationToken,
) {
    let wake = Arc::new(Notify::new());
    let mut conns: HashMap<StreamId, Plumbing> = HashMap::new();
    let mut buf = vec![0u8; CHUNK];

    loop {
        // Arm one timer for the stack's next retransmit, delayed ACK, or
        // TIME-WAIT deadline. With the pool exhausted the stack cannot
        // transmit and its deadline is now; wait a moment for a slice instead
        // of spinning.
        let deadline = stack
            .poll_at(Instant::now())
            .map(TokioInstant::from_std)
            .unwrap_or_else(|| TokioInstant::now() + std::time::Duration::from_millis(250));
        let deadline = if stack.pool().available() == 0 {
            deadline.max(TokioInstant::now() + std::time::Duration::from_millis(5))
        } else {
            deadline
        };

        tokio::select! {
            _ = shutdown.cancelled() => break,
            packet = packets.recv() => match packet {
                // Move the shared-budget buffer into the stack until consumed.
                Some(packet) => {
                    stack.push(packet);
                    take_pending(&mut stack, &mut packets);
                }
                None => break,
            },
            () = wake.notified() => {}
            () = sleep_until(deadline) => {}
        }

        service(&mut stack, &mut conns, &wake, &mut buf, &replies, &accepted).await;
    }

    // Flush decisions already made so cancellation cannot strand a FIN or final
    // segment.
    service(&mut stack, &mut conns, &wake, &mut buf, &replies, &accepted).await;
}

/// Moves every packet already queued into the stack, so a burst costs one
/// `service` pass rather than one per packet. `service` walks every socket,
/// so with s connections and a burst of k segments this is O(s) rather than
/// O(k · s). Bounded by the channel's depth.
fn take_pending(stack: &mut LocalStack, packets: &mut mpsc::Receiver<Pooled>) -> usize {
    let mut taken = 0;
    while let Ok(packet) = packets.try_recv() {
        stack.push(packet);
        taken += 1;
    }
    taken
}

/// Advances the stack, publishes connections, pumps streams, and drains output.
async fn service(
    stack: &mut LocalStack,
    conns: &mut HashMap<StreamId, Plumbing>,
    wake: &Arc<Notify>,
    buf: &mut [u8],
    replies: &mpsc::Sender<Pooled>,
    accepted: &mpsc::Sender<Accepted>,
) {
    stack.poll(Instant::now());

    while let Some(terminated) = stack.poll_accept() {
        let (stream, plumbing) = pair(Arc::clone(wake));
        // Offered, never awaited: a consumer slow to take connections must
        // not stall every established one's ACKs and retransmits. A full
        // queue, or no consumer, is a refused connection.
        if accepted.try_send(Accepted { terminated, stream }).is_err() {
            stack.abort(terminated.id);
            continue;
        }
        conns.insert(terminated.id, plumbing);
    }

    for (&id, plumbing) in conns.iter_mut() {
        pump(stack, id, plumbing, buf);
    }

    // Poll again so pumped bytes become segments in this pass.
    stack.poll(Instant::now());

    while let Some(packet) = stack.poll_transmit() {
        if replies.send(packet).await.is_err() {
            return; // the reactor is gone.
        }
    }

    while let Some(ended) = stack.poll_closed() {
        if let Some(mut plumbing) = conns.remove(&ended.id)
            && ended.reset
        {
            plumbing.reset();
        }
    }
}

/// Moves bytes in both directions without loss. Each direction stops when its
/// destination is full and resumes on the next sweep.
fn pump(stack: &mut LocalStack, id: StreamId, plumbing: &mut Plumbing, buf: &mut [u8]) {
    // Reserve capacity before reading so the TCP receive window closes when
    // the task cannot accept more bytes.
    let mut peer_finished = false;
    let mut peer_reset = false;
    while let Some(sender) = plumbing.to_task.as_ref() {
        let Ok(permit) = sender.try_reserve() else {
            break;
        };
        match stack.recv(id, buf) {
            Ok(0) => break,
            Ok(read) => permit.send(Bytes::copy_from_slice(&buf[..read])),
            Err(StreamError::WouldBlock) => break,
            Err(StreamError::Closed | StreamError::Unknown) => {
                peer_finished = true;
                break;
            }
            Err(StreamError::Reset) => {
                peer_reset = true;
                break;
            }
        }
    }
    // Outside the loop because the reserved permit borrows the field cleared.
    if peer_reset {
        plumbing.reset();
    } else if peer_finished {
        plumbing.to_task = None;
    }

    // Task to client.
    loop {
        let chunk = match plumbing.pending_out.take() {
            Some(chunk) => chunk,
            None => match plumbing.from_task.try_recv() {
                Ok(chunk) => chunk,
                Err(mpsc::error::TryRecvError::Empty) => break,
                // Queued task bytes have drained, so close the connection now.
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    if !plumbing.finished {
                        plumbing.finished = true;
                        stack.close(id);
                    }
                    break;
                }
            },
        };
        match stack.send(id, &chunk) {
            Ok(written) if written < chunk.len() => {
                // Preserve the unsent tail for the next sweep.
                plumbing.pending_out = Some(chunk.slice(written..));
                break;
            }
            Ok(_) => {}
            // The send buffer is full: the chunk waits for the next sweep.
            Err(StreamError::WouldBlock) => {
                plumbing.pending_out = Some(chunk);
                break;
            }
            Err(StreamError::Closed | StreamError::Unknown | StreamError::Reset) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::Ipv4Addr, num::NonZeroUsize, time::Duration};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::{BufferPool, Mtu, TerminationLimits};

    /// Drives the terminator against the deterministic `smoltcp` client using
    /// real channels and a Tokio runtime; only the wire is in memory.
    struct Rig {
        packets: mpsc::Sender<Pooled>,
        replies: mpsc::Receiver<Pooled>,
        accepted: mpsc::Receiver<Accepted>,
        shutdown: CancellationToken,
        handle: tokio::task::JoinHandle<()>,
        pool: Arc<BufferPool>,
    }

    impl Rig {
        fn start(ports: &[u16]) -> Self {
            // Share one payload budget, as production does.
            let pool = BufferPool::new(
                NonZeroUsize::new(2048).unwrap(),
                NonZeroUsize::new(256).unwrap(),
            );
            let stack = LocalStack::new(
                Mtu::new(1500).unwrap(),
                ports,
                TerminationLimits {
                    max_sockets: NonZeroUsize::new(16).unwrap(),
                    backlog: NonZeroUsize::new(2).unwrap(),
                    socket_buffer: NonZeroUsize::new(8192).unwrap(),
                },
                Arc::clone(&pool),
                Instant::now(),
            )
            .expect("the fixture's ceiling holds a backlog per port");
            let (packets_tx, packets_rx) = mpsc::channel(64);
            let (replies_tx, replies_rx) = mpsc::channel(64);
            let (accepted_tx, accepted_rx) = mpsc::channel(4);
            let shutdown = CancellationToken::new();
            let handle = tokio::spawn(run_terminator(
                stack,
                packets_rx,
                replies_tx,
                accepted_tx,
                shutdown.clone(),
            ));
            Self {
                packets: packets_tx,
                replies: replies_rx,
                accepted: accepted_rx,
                shutdown,
                handle,
                pool,
            }
        }

        async fn feed(&self, packet: &[u8]) {
            let pooled = self.pool.take(packet).expect("pool has room");
            self.packets.send(pooled).await.expect("terminator lives");
        }

        /// Collects segments produced while the task makes progress.
        async fn drain(&mut self) -> Vec<Vec<u8>> {
            let mut out = Vec::new();
            while let Ok(Some(packet)) =
                tokio::time::timeout(Duration::from_millis(50), self.replies.recv()).await
            {
                out.push(packet.to_vec());
            }
            out
        }

        async fn stop(self) {
            self.shutdown.cancel();
            let _ = self.handle.await;
        }
    }

    /// A queued burst enters the stack in one move: `service` is then one pass
    /// over the sockets for the whole burst, not one per segment.
    #[tokio::test]
    async fn a_burst_already_queued_is_taken_before_the_stack_is_serviced() {
        let pool = BufferPool::new(
            NonZeroUsize::new(2048).unwrap(),
            NonZeroUsize::new(64).unwrap(),
        );
        let mut stack = LocalStack::new(
            Mtu::new(1500).unwrap(),
            &[443],
            TerminationLimits {
                max_sockets: NonZeroUsize::new(4).unwrap(),
                backlog: NonZeroUsize::new(1).unwrap(),
                socket_buffer: NonZeroUsize::new(4096).unwrap(),
            },
            Arc::clone(&pool),
            Instant::now(),
        )
        .unwrap();
        let (tx, mut rx) = mpsc::channel(64);
        for n in 0..10u8 {
            tx.send(pool.take(&[0x45, n]).unwrap()).await.unwrap();
        }

        assert_eq!(take_pending(&mut stack, &mut rx), 10);
        assert_eq!(take_pending(&mut stack, &mut rx), 0, "nothing left behind");
        assert_eq!(
            pool.available(),
            64 - 10,
            "the burst now lives in the stack"
        );
    }

    #[tokio::test]
    async fn a_handshake_yields_a_stream_that_echoes_through_the_bridge() {
        let mut rig = Rig::start(&[443]);
        let mut client = crate::l4::stream::tests::Client::connect(
            Ipv4Addr::new(192, 0, 2, 10),
            49152,
            Ipv4Addr::new(198, 51, 100, 5),
            443,
        );

        // Relay packets until the handshake publishes the connection.
        let mut accepted = None;
        for _ in 0..12 {
            for packet in client.take_outbound() {
                rig.feed(&packet).await;
            }
            for packet in rig.drain().await {
                client.deliver(&packet);
            }
            client.tick();
            if let Ok(next) = rig.accepted.try_recv() {
                accepted = Some(next);
                break;
            }
        }
        let accepted = accepted.expect("the connection is published");
        assert_eq!(accepted.terminated.server.port, 443);
        assert_eq!(accepted.terminated.client.port, 49152);

        // Serve the stream as the interception layer would, by echoing bytes.
        let mut stream = accepted.stream;
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let read = stream.read(&mut buf).await.expect("read");
            stream.write_all(&buf[..read]).await.expect("write");
            stream.flush().await.unwrap();
        });

        client.send(b"ping").expect("client sends");
        let mut echoed = Vec::new();
        for _ in 0..16 {
            for packet in client.take_outbound() {
                rig.feed(&packet).await;
            }
            for packet in rig.drain().await {
                client.deliver(&packet);
            }
            client.tick();
            echoed.extend(client.take_received());
            if echoed == b"ping" {
                break;
            }
        }
        assert_eq!(echoed, b"ping", "the bytes crossed the bridge and returned");

        rig.stop().await;
    }

    /// A client slower than the task fills the send buffer; every byte the
    /// task wrote still arrives, in order.
    #[tokio::test]
    async fn a_slow_client_receives_every_byte_the_task_wrote() {
        let mut rig = Rig::start(&[443]);
        let mut client = crate::l4::stream::tests::Client::connect(
            Ipv4Addr::new(192, 0, 2, 10),
            49153,
            Ipv4Addr::new(198, 51, 100, 5),
            443,
        );
        let mut accepted = None;
        for _ in 0..12 {
            for packet in client.take_outbound() {
                rig.feed(&packet).await;
            }
            for packet in rig.drain().await {
                client.deliver(&packet);
            }
            client.tick();
            if let Ok(next) = rig.accepted.try_recv() {
                accepted = Some(next);
                break;
            }
        }
        let mut stream = accepted.expect("the connection is published").stream;

        // Eight times the 8 KiB socket buffer, in one write.
        let body: Vec<u8> = (0..65536u32).map(|n| (n % 251) as u8).collect();
        let written = body.clone();
        tokio::spawn(async move {
            stream.write_all(&written).await.expect("write");
            stream.flush().await.unwrap();
        });

        let mut received = Vec::new();
        for _ in 0..400 {
            for packet in client.take_outbound() {
                rig.feed(&packet).await;
            }
            for packet in rig.drain().await {
                client.deliver(&packet);
            }
            client.tick();
            received.extend(client.take_received());
            if received.len() >= body.len() {
                break;
            }
        }
        assert_eq!(received.len(), body.len(), "every byte arrived");
        assert!(received == body, "in order and uncorrupted");

        rig.stop().await;
    }
}
