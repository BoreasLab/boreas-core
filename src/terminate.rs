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
//! exactly the mechanism TCP provides for it.
//!
//! **The pump is a sweep, and its cost is bounded by the socket ceiling.** One
//! pass costs O(live connections) channel probes, and
//! [`TerminationLimits::max_sockets`](crate::TerminationLimits) is what bounds
//! that count — the same admission rule that bounds the socket set itself. A
//! ready-list would make it O(ready), which is worth doing only once a
//! measurement shows the sweep on the profile; at the tens-to-hundreds of
//! connections the ceiling admits, the probe is cheaper than the bookkeeping.

use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

use bytes::{Buf, Bytes};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Notify, mpsc},
    time::{Instant as TokioInstant, sleep_until},
};
use tokio_util::sync::{CancellationToken, PollSender};

use crate::{LocalStack, Pooled, StreamError, StreamId, Terminated};

/// Bytes moved in one chunk between the pump and a stream task. A cap on the
/// copy the pump performs per probe, so one busy connection cannot monopolize a
/// sweep; the channel depth times this is the per-connection buffer the bridge
/// adds on top of `smoltcp`'s own.
const CHUNK: usize = 16 * 1024;

/// Chunks in flight per direction, per connection. Small on purpose: the
/// socket buffer is the real window, and this only smooths the hand-off.
const STREAM_DEPTH: usize = 8;

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
/// Reads yield the bytes the client sent; writes are delivered to the client as
/// TCP segments. Closing the write half sends FIN, and an exhausted read half
/// is the peer's FIN — so the type's `AsyncRead`/`AsyncWrite` contract carries
/// the connection's half-close semantics rather than hiding them.
#[derive(Debug)]
pub struct TerminatedStream {
    inbound: mpsc::Receiver<Bytes>,
    /// `None` once the write half is shut down: dropping the sender is what
    /// tells the pump to send FIN, so shutdown is expressed by ownership rather
    /// than by a flag the pump would have to poll.
    outbound: Option<PollSender<Bytes>>,
    /// Wakes the pump after a write, so a stream task never waits for the next
    /// packet or timer to have its bytes delivered.
    wake: Arc<Notify>,
    /// The unconsumed tail of a chunk larger than the last read buffer.
    pending: Bytes,
}

impl AsyncRead for TerminatedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pending.is_empty() {
            match this.inbound.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => this.pending = chunk,
                // The pump dropped its sender: the peer sent FIN, and an empty
                // read is how `AsyncRead` spells end of stream.
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
        let moved = buf.remaining().min(this.pending.len());
        buf.put_slice(&this.pending[..moved]);
        this.pending.advance(moved);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TerminatedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let Some(sender) = this.outbound.as_mut() else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the write half is shut down",
            )));
        };
        match sender.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let moved = buf.len().min(CHUNK);
                sender
                    .send_item(Bytes::copy_from_slice(&buf[..moved]))
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "the pump is gone"))?;
                this.wake.notify_one();
                Poll::Ready(Ok(moved))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the pump is gone",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Bytes are already queued for the pump; there is no buffer of our own to
    /// force out, and waiting for the client to acknowledge them is not what
    /// flush means here.
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Dropping the sender is the signal: the pump sees a closed channel,
        // drains what was queued, and only then sends FIN.
        this.outbound = None;
        this.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

/// The pump's half of one connection's plumbing.
struct Plumbing {
    /// Client bytes toward the task. `None` once the peer's FIN has been
    /// observed and the task has been given its end-of-stream.
    to_task: Option<mpsc::Sender<Bytes>>,
    from_task: mpsc::Receiver<Bytes>,
    /// A chunk the socket's send buffer could not take in full. Held here so
    /// the next sweep resumes exactly where this one stopped, which is what
    /// makes a partial write lossless.
    pending_out: Option<Bytes>,
    /// Set once the task's sender is gone and everything it wrote has been
    /// handed to the socket, so FIN is sent exactly once.
    finished: bool,
}

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
    replies: mpsc::Sender<Vec<u8>>,
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
                Some(packet) => {
                    stack.push(&packet);
                    // The pooled buffer is released here, returning its bytes
                    // to the shared budget as soon as the stack has copied them.
                    drop(packet);
                }
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
    replies: &mpsc::Sender<Vec<u8>>,
    accepted: &mpsc::Sender<Accepted>,
) {
    stack.poll(Instant::now());

    while let Some(terminated) = stack.poll_accept() {
        let (to_task, inbound) = mpsc::channel(STREAM_DEPTH);
        let (outbound, from_task) = mpsc::channel(STREAM_DEPTH);
        let stream = TerminatedStream {
            inbound,
            outbound: Some(PollSender::new(outbound)),
            wake: Arc::clone(wake),
            pending: Bytes::new(),
        };
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
        conns.insert(
            terminated.id,
            Plumbing {
                to_task: Some(to_task),
                from_task,
                pending_out: None,
                finished: false,
            },
        );
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
        replies: mpsc::Receiver<Vec<u8>>,
        accepted: mpsc::Receiver<Accepted>,
        shutdown: CancellationToken,
        handle: tokio::task::JoinHandle<()>,
        pool: Arc<BufferPool>,
    }

    impl Rig {
        fn start(ports: &[u16]) -> Self {
            let stack = LocalStack::new(
                Mtu::new(1500).unwrap(),
                ports,
                TerminationLimits {
                    max_sockets: NonZeroUsize::new(16).unwrap(),
                    backlog: NonZeroUsize::new(2).unwrap(),
                    socket_buffer: NonZeroUsize::new(8192).unwrap(),
                },
                Instant::now(),
            );
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
                pool: BufferPool::new(
                    NonZeroUsize::new(2048).unwrap(),
                    NonZeroUsize::new(256).unwrap(),
                ),
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
                out.push(packet);
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
                client.deliver(packet);
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
                client.deliver(packet);
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
