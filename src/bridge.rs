//! The bridge between a sans-io state machine and the reactor: one bounded
//! channel per direction exposed as `AsyncRead + AsyncWrite`.
//!
//! [`run_terminator`](crate::run_terminator) uses it for `smoltcp` connections,
//! and [`QuicConnection`](crate::QuicConnection) uses it for `quiche` streams.
//! Their pumps differ, but the async hand-off and its polling contract are the
//! same.
//!
//! **Byte-stream backpressure is flow control, not loss.** A driver reserves a
//! channel permit before reading from its socket. With no permit, bytes remain
//! in the transport and the peer's TCP or QUIC flow-control window closes.
//!
//! **Shutdown is expressed by ownership.** Dropping the write sender tells the
//! driver to send FIN after queued bytes; dropping the inbound sender gives
//! the reader end of stream. No shared shutdown flag is required.

use std::{
    io,
    pin::Pin,
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Notify, mpsc},
};
use tokio_util::sync::PollSender;

/// Maximum bytes copied into one bridge message.
pub(crate) const CHUNK: usize = 16 * 1024;

/// Maximum queued chunks in each direction.
pub(crate) const DEPTH: usize = 8;

/// A transport stream exposed to the reactor as an async byte stream.
///
/// Closing the write half sends FIN; an exhausted read half observes peer FIN.
///
/// A failed or cancelled driver also appears as end of stream because its
/// sender is dropped. HTTP consumers already treat a truncated body as a
/// message failure.
#[derive(Debug)]
pub struct BridgedStream {
    inbound: mpsc::Receiver<Bytes>,
    /// Set by the driver when the peer reset rather than closed.
    reset: Arc<AtomicBool>,
    /// Absent after the write half is shut down.
    outbound: Option<PollSender<Bytes>>,
    /// Wakes the driver after a write so queued bytes are delivered promptly.
    wake: Arc<Notify>,
    /// Unconsumed bytes from a chunk larger than the last read buffer.
    pending: Bytes,
}

/// The driver's half of one stream bridge.
pub(crate) struct Plumbing {
    /// Peer bytes toward the task; absent after peer FIN is delivered.
    pub(crate) to_task: Option<mpsc::Sender<Bytes>>,
    reset: Arc<AtomicBool>,
    pub(crate) from_task: mpsc::Receiver<Bytes>,
    /// A chunk not fully accepted by the transport. Retaining it makes partial
    /// writes lossless.
    pub(crate) pending_out: Option<Bytes>,
    /// Set after the task sender is gone and queued bytes have drained, so FIN
    /// is sent once.
    pub(crate) finished: bool,
}

/// Creates the consumer and driver halves of one stream bridge.
pub(crate) fn pair(wake: Arc<Notify>) -> (BridgedStream, Plumbing) {
    let (to_task, inbound) = mpsc::channel(DEPTH);
    let (outbound, from_task) = mpsc::channel(DEPTH);
    let reset = Arc::new(AtomicBool::new(false));
    (
        BridgedStream {
            inbound,
            reset: Arc::clone(&reset),
            outbound: Some(PollSender::new(outbound)),
            wake,
            pending: Bytes::new(),
        },
        Plumbing {
            to_task: Some(to_task),
            reset,
            from_task,
            pending_out: None,
            finished: false,
        },
    )
}

impl Plumbing {
    /// The peer reset the connection: what the task has not read is lost,
    /// and its next read is an error, not a clean end.
    pub(crate) fn reset(&mut self) {
        self.reset.store(true, Ordering::Release);
        self.to_task = None;
    }
}

/// Creates two directly connected streams for consumer tests.
///
/// There is no pump or socket: each outbound sender is the other inbound
/// receiver, preserving chunking, [`DEPTH`] backpressure, and half-close.
#[cfg(test)]
pub(crate) fn duplex() -> (BridgedStream, BridgedStream) {
    let wake = Arc::new(Notify::new());
    let (left_in, left_out) = mpsc::channel(DEPTH);
    let (right_in, right_out) = mpsc::channel(DEPTH);
    (
        BridgedStream {
            inbound: left_out,
            reset: Arc::new(AtomicBool::new(false)),
            outbound: Some(PollSender::new(right_in)),
            wake: Arc::clone(&wake),
            pending: Bytes::new(),
        },
        BridgedStream {
            inbound: right_out,
            reset: Arc::new(AtomicBool::new(false)),
            outbound: Some(PollSender::new(left_in)),
            wake,
            pending: Bytes::new(),
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
        // An empty chunk carries nothing and must not read as end of stream.
        while this.pending.is_empty() {
            match this.inbound.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => {
                    this.pending = chunk;
                    // Receiving frees a channel permit. Wake the driver so it
                    // can resume reading instead of waiting for its next timer.
                    this.wake.notify_one();
                }
                // Dropping the driver sender is the bridge's end-of-stream
                // signal, unless the driver said the peer reset.
                Poll::Ready(None) => {
                    return Poll::Ready(if this.reset.load(Ordering::Acquire) {
                        Err(io::Error::from(io::ErrorKind::ConnectionReset))
                    } else {
                        Ok(())
                    });
                }
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
        // Nothing to queue; an empty chunk would read as EOF at the far end.
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
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

    /// Bytes are already queued for the driver; there is no local buffer to
    /// flush or peer acknowledgement to await.
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Closing the channel tells the driver to drain queued bytes before FIN.
        this.outbound = None;
        this.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A write half can close independently, and a dropped inbound sender reads
    /// as end of stream rather than as an error.
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

        // Write shutdown does not affect the read half.
        let sender = plumbing.to_task.take().unwrap();
        sender.send(Bytes::from_static(b"in")).await.unwrap();
        drop(sender);
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"in");
    }

    /// A chunk larger than the reader's buffer is delivered across successive
    /// reads; the pending tail prevents truncation.
    /// A reset is not a clean end: a body cut short by RST must not parse as
    /// complete.
    #[tokio::test]
    async fn a_reset_is_an_error_not_a_clean_end() {
        let (mut stream, mut plumbing) = pair(Arc::new(Notify::new()));
        plumbing
            .to_task
            .as_ref()
            .unwrap()
            .send(Bytes::from_static(b"part"))
            .await
            .unwrap();
        plumbing.reset();
        let mut buf = [0u8; 8];
        assert_eq!(stream.read(&mut buf).await.unwrap(), 4);
        assert_eq!(
            stream.read(&mut buf).await.unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
    }

    /// An empty chunk is not the end of the stream, and writing nothing
    /// sends nothing.
    #[tokio::test]
    async fn an_empty_chunk_is_skipped_rather_than_read_as_eof() {
        let (mut stream, mut plumbing) = pair(Arc::new(Notify::new()));
        let to_task = plumbing.to_task.as_ref().unwrap();
        to_task.send(Bytes::new()).await.unwrap();
        to_task.send(Bytes::from_static(b"data")).await.unwrap();
        let mut buf = [0u8; 8];
        let read = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..read], b"data");

        assert_eq!(stream.write(&[]).await.unwrap(), 0);
        assert!(
            plumbing.from_task.try_recv().is_err(),
            "nothing was queued for the driver"
        );
    }

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
