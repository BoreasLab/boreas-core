//! The seam between a sans-io state machine and the reactor: one bounded
//! channel per direction, and an `AsyncRead + AsyncWrite` over the pair.
//!
//! Two drivers in this crate need exactly this. [`run_terminator`](crate::run_terminator)
//! turns each `smoltcp` connection into a stream the interception layer serves;
//! the driver behind [`QuicConnection`](crate::QuicConnection) turns each
//! `quiche` bidirectional stream into one a proxy protocol writes its header
//! onto. Their pumps differ
//! — the two stacks disagree about how a socket reports the peer's FIN and
//! about what a partial write means — but the hand-off is identical, and the
//! `poll_read`/`poll_write` contract is subtle enough that having one of it is
//! worth more than having each driver's version read locally.
//!
//! **Backpressure is the protocol's own window, never a drop.** A datagram may
//! be dropped under load; a byte stream may not, because a dropped byte is a
//! corrupted response. So a driver takes a channel permit *before* it reads
//! from its socket. When no permit is available the bytes stay where they are,
//! the advertised window closes, and the peer stops sending — which is the
//! mechanism both TCP and QUIC already provide for this and neither needs help
//! with.
//!
//! **Shutdown is expressed by ownership.** Dropping the write half's sender is
//! what tells the driver to send FIN, and dropping the driver's inbound sender
//! is what gives the reader end of stream. Neither direction needs a flag the
//! other has to poll, and neither can be observed half-applied.

use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Notify, mpsc},
};
use tokio_util::sync::PollSender;

/// Bytes moved in one chunk between a driver and a stream task. A cap on the
/// copy performed per probe, so one busy connection cannot monopolise a sweep;
/// the channel depth times this is the per-stream buffer the bridge adds on top
/// of the transport's own.
pub(crate) const CHUNK: usize = 16 * 1024;

/// Chunks in flight per direction, per stream. Small on purpose: the
/// transport's receive buffer is the real window, and this only smooths the
/// hand-off.
pub(crate) const DEPTH: usize = 8;

/// A transport stream, bridged to the reactor as an ordinary async byte stream.
///
/// Reads yield what the peer sent; writes are delivered to the peer. Closing
/// the write half sends FIN, and an exhausted read half is the peer's FIN — so
/// the `AsyncRead`/`AsyncWrite` contract carries half-close semantics rather
/// than hiding them.
///
/// **An abrupt failure arrives as end of stream, not as an error.** If the
/// driver dies — a reset connection, a cancelled task — its senders drop, and a
/// reader cannot distinguish that from an orderly FIN. Consumers here are HTTP
/// implementations that already treat a truncated body as a failure of the
/// message rather than of the socket, so the distinction does not change what
/// anything does with it.
#[derive(Debug)]
pub struct BridgedStream {
    inbound: mpsc::Receiver<Bytes>,
    /// `None` once the write half is shut down.
    outbound: Option<PollSender<Bytes>>,
    /// Wakes the driver after a write, so a stream task never waits for the
    /// next packet or timer to have its bytes delivered.
    wake: Arc<Notify>,
    /// The unconsumed tail of a chunk larger than the last read buffer.
    pending: Bytes,
}

/// The driver's half of one stream's plumbing.
pub(crate) struct Plumbing {
    /// Peer bytes toward the task. `None` once the peer's FIN has been observed
    /// and the task has been given its end of stream.
    pub(crate) to_task: Option<mpsc::Sender<Bytes>>,
    pub(crate) from_task: mpsc::Receiver<Bytes>,
    /// A chunk the transport's send buffer could not take in full. Held so the
    /// next sweep resumes exactly where this one stopped, which is what makes a
    /// partial write lossless.
    pub(crate) pending_out: Option<Bytes>,
    /// Set once the task's sender is gone and everything it wrote has been
    /// handed to the transport, so FIN is sent exactly once.
    pub(crate) finished: bool,
}

/// Wires one stream: the half the consumer holds and the half the driver pumps.
pub(crate) fn pair(wake: Arc<Notify>) -> (BridgedStream, Plumbing) {
    let (to_task, inbound) = mpsc::channel(DEPTH);
    let (outbound, from_task) = mpsc::channel(DEPTH);
    (
        BridgedStream {
            inbound,
            outbound: Some(PollSender::new(outbound)),
            wake,
            pending: Bytes::new(),
        },
        Plumbing {
            to_task: Some(to_task),
            from_task,
            pending_out: None,
            finished: false,
        },
    )
}

impl AsyncRead for BridgedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pending.is_empty() {
            match this.inbound.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => this.pending = chunk,
                // The driver dropped its sender: the peer sent FIN, and an
                // empty read is how `AsyncRead` spells end of stream.
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

impl AsyncWrite for BridgedStream {
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
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "the driver is gone"))?;
                this.wake.notify_one();
                Poll::Ready(Ok(moved))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "the driver is gone",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Bytes are already queued for the driver; there is no buffer of our own
    /// to force out, and waiting for the peer to acknowledge them is not what
    /// flush means here.
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Dropping the sender is the signal: the driver sees a closed channel,
        // drains what was queued, and only then sends FIN.
        this.outbound = None;
        this.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The half-close law, from both ends: a shut-down write half refuses
    /// further writes without disturbing the read half, and a dropped inbound
    /// sender reads as end of stream rather than as an error.
    #[tokio::test]
    async fn each_half_closes_without_disturbing_the_other() {
        let (mut stream, mut plumbing) = pair(Arc::new(Notify::new()));

        stream.write_all(b"out").await.unwrap();
        stream.shutdown().await.unwrap();
        assert_eq!(
            plumbing.from_task.recv().await.as_deref(),
            Some(&b"out"[..])
        );
        assert!(plumbing.from_task.recv().await.is_none(), "FIN is a drop");
        assert!(
            stream.write_all(b"more").await.is_err(),
            "the write half stays shut"
        );

        // The read half is untouched by the write half's shutdown.
        let sender = plumbing.to_task.take().unwrap();
        sender.send(Bytes::from_static(b"in")).await.unwrap();
        drop(sender);
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"in");
    }

    /// A chunk larger than the reader's buffer must be delivered in full across
    /// successive reads. The `pending` tail is what makes that true, and losing
    /// it would silently truncate every response larger than one read.
    #[tokio::test]
    async fn a_chunk_larger_than_the_read_buffer_is_delivered_whole() {
        let (mut stream, mut plumbing) = pair(Arc::new(Notify::new()));
        let chunk = Bytes::from(vec![0xab; 100]);
        plumbing.to_task.take().unwrap().send(chunk).await.unwrap();

        let mut received = Vec::new();
        let mut small = [0u8; 7];
        while received.len() < 100 {
            let read = stream.read(&mut small).await.unwrap();
            received.extend_from_slice(&small[..read]);
        }
        assert_eq!(received, vec![0xab; 100]);
    }
}
