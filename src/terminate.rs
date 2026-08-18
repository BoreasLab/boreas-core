//! The reactor bridge: it drives [`LocalStack`] as a task and turns each
//! terminated TCP connection into an ordinary `AsyncRead + AsyncWrite` stream
//! the interception layer can serve.
//!
//! **This is a second task, and the split is load-bearing** — the same argument
//! that separates the resolver from the reactor. A terminated connection is
//! served by `hyper`, which awaits, so running it inside the reactor would put
//! an HTTP round trip in front of every packet. The reactor forwards the
//! packets a flow plan routed to termination and drains the replies; everything
//! between those two points happens here.
//!
//! **Backpressure is TCP's own window, not a drop.** A datagram may be dropped
//! under load — a stub resolver retries — but a byte stream may not: a dropped
//! byte is a corrupted response. So the pump only moves bytes out of a socket
//! when the consuming channel has already reserved capacity. When it has not,
//! bytes stay in `smoltcp`'s receive buffer, the advertised window shrinks, and
//! the peer stops sending. The bound is enforced by refusing to read, which is
//! exactly the mechanism TCP provides for it. The channels and the stream that
//! rides on them are [`crate::bridge`]'s, shared with the QUIC driver, which
//! needs the same hand-off for a different state machine.
//!
//! **The pump is a sweep, and its cost is bounded by the socket ceiling.** One
//! pass costs O(live connections) channel probes, and
//! [`TerminationLimits::max_sockets`](crate::TerminationLimits) is what bounds
//! that count — the same admission rule that bounds the socket set itself. A
//! ready-list would make it O(ready), which is worth doing only once a
//! measurement shows the sweep on the profile; at the tens-to-hundreds of
//! connections the ceiling admits, the probe is cheaper than the bookkeeping.

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

/// One accepted connection: what it is, and the stream that serves it.
///
/// The endpoints travel with the stream because the layer above needs both —
/// the server address names the host whose certificate must be forged, and the
/// client address identifies the flow.
#[derive(Debug)]
pub struct Accepted {
    pub terminated: Terminated,
    pub stream: TerminatedStream,
}

/// A terminated TCP connection, as an ordinary async byte stream.
///
/// Half-close is exposed: closing the write half sends FIN; an exhausted read
/// half observes the peer's FIN.
///
/// The name is the local one for [`crate::BridgedStream`]: the QUIC driver
/// hands back the same type for the same reasons, and only the pump behind it
/// differs.
pub type TerminatedStream = crate::BridgedStream;

/// Drives the terminator until cancelled.
///
/// `packets` carries the client packets the datapath routed to termination;
/// `replies` carries the segments this stack produced back to the reactor,
/// which owns the device. `accepted` publishes each new connection.
///
/// Awaiting on `replies` is safe and deliberate: the reactor only ever
/// `try_send`s into `packets`, so there is no cycle in which both tasks wait on
/// each other, and a reply is a byte-stream segment that must not be dropped
/// the way a datagram may be.
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
        // One timer, armed against the stack's own next deadline — a
        // retransmit, a delayed ACK, a TIME-WAIT expiry — exactly as the
        // reactor arms one against the datapath's.
        let deadline = stack
            .poll_at(Instant::now())
            .map(TokioInstant::from_std)
            .unwrap_or_else(|| TokioInstant::now() + std::time::Duration::from_millis(250));

        tokio::select! {
            _ = shutdown.cancelled() => break,
            packet = packets.recv() => match packet {
                // Moved into the stack's inbound queue rather than copied out
                // of it: the buffer is already on the shared budget, and it is
                // released when `smoltcp` has consumed the packet.
                Some(packet) => stack.push(packet),
                None => break,
            },
            () = wake.notified() => {}
            () = sleep_until(deadline) => {}
        }

        service(&mut stack, &mut conns, &wake, &mut buf, &replies, &accepted).await;
    }

    // Everything already decided still belongs on the wire: one last pass so a
    // FIN or a final segment is not stranded by cancellation.
    service(&mut stack, &mut conns, &wake, &mut buf, &replies, &accepted).await;
}

/// One servicing pass: advance the state machines, publish new connections,
/// pump every live one, then drain what that produced.
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
        // A consumer that cannot take the connection is one that has gone away;
        // aborting is the honest answer, because nothing will ever serve it.
        if accepted
            .send(Accepted { terminated, stream })
            .await
            .is_err()
        {
            stack.abort(terminated.id);
            continue;
        }
        conns.insert(terminated.id, plumbing);
    }

    for (&id, plumbing) in conns.iter_mut() {
        pump(stack, id, plumbing, buf);
    }

    // Pumping fed the send buffers; polling again turns those bytes into
    // segments in this same pass rather than one wakeup later.
    stack.poll(Instant::now());

    while let Some(packet) = stack.poll_transmit() {
        if replies.send(packet).await.is_err() {
            return; // the reactor is gone; nothing left to serve
        }
    }

    while let Some(closed) = stack.poll_closed() {
        conns.remove(&closed);
    }
}

/// Moves bytes in both directions for one connection, without ever dropping a
/// byte: each direction stops at the first sign of a full destination and
/// resumes on the next sweep.
fn pump(stack: &mut LocalStack, id: StreamId, plumbing: &mut Plumbing, buf: &mut [u8]) {
    // Client to task. A permit is taken *before* the socket is read, so bytes
    // leave the receive buffer only when there is somewhere to put them; when
    // there is not, the window closes and the peer stops sending.
    let mut peer_finished = false;
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
        }
    }
    if peer_finished {
        // The peer's FIN: dropping the sender is what gives the task its end of
        // stream. Done outside the loop because the reserved permit borrows the
        // very field being cleared.
        plumbing.to_task = None;
    }

    // Task to client.
    loop {
        let chunk = match plumbing.pending_out.take() {
            Some(chunk) => chunk,
            None => match plumbing.from_task.try_recv() {
                Ok(chunk) => chunk,
                Err(mpsc::error::TryRecvError::Empty) => break,
                // The task finished and everything it wrote is already in the
                // send buffer, so the connection's write half closes now.
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
                // A partial write is the send buffer filling up. Keep the tail
                // exactly, and resume from it next sweep.
                plumbing.pending_out = Some(chunk.slice(written..));
                break;
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::Ipv4Addr, num::NonZeroUsize, time::Duration};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::{BufferPool, Mtu, TerminationLimits};

    /// Drives the terminator against the deterministic smoltcp client the
    /// `stream` module already uses for its loopback tests, over real channels
    /// and a real tokio runtime. The wire is in memory; everything else —
    /// the task split, the pump, the backpressure — is production code.
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
            // One budget for the whole rig, exactly as production shares one
            // between the datapath and the terminator.
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

        /// Collects the segments the terminator produced, waiting briefly for
        /// the task to make progress.
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

    #[tokio::test]
    async fn a_handshake_yields_a_stream_that_echoes_through_the_bridge() {
        let mut rig = Rig::start(&[443]);
        let mut client = crate::stream::tests::Client::connect(
            Ipv4Addr::new(192, 0, 2, 10),
            49152,
            Ipv4Addr::new(198, 51, 100, 5),
            443,
        );

        // Complete the handshake by relaying between the client stack and the
        // terminator task until the connection is published.
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

        // An echo task serves the stream exactly as the interception layer
        // would: it reads bytes and writes them back.
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
}
