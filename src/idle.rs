//! A bidirectional copy that ends when neither side has moved a byte for a
//! while. `copy_bidirectional` alone runs until both halves close, and a
//! peer that stops talking without closing would hold two sockets forever.

use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::Instant,
};

/// RFC 5382 REQ-5: an established TCP connection is not expired before two
/// hours four minutes of silence. An app that keeps a connection open with
/// nothing to say counts on that.
pub(crate) const TCP_IDLE: Duration = Duration::from_secs(2 * 3600 + 4 * 60);

/// Copies both ways until both close, or until `idle` passes with nothing
/// moved either way, which is `TimedOut`.
pub(crate) async fn copy_until_idle<A, B>(a: &mut A, b: &mut B, idle: Duration) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let base = Instant::now();
    let touched = Arc::new(AtomicU64::new(0));
    let mut a = Touched::new(a, &touched, base);
    let mut b = Touched::new(b, &touched, base);
    let copy = tokio::io::copy_bidirectional(&mut a, &mut b);
    tokio::pin!(copy);
    loop {
        let last = base + Duration::from_millis(touched.load(Ordering::Relaxed));
        tokio::select! {
            outcome = &mut copy => return outcome.map(drop),
            () = tokio::time::sleep_until(last + idle) => {
                // A byte may have moved while the timer was armed.
                if base + Duration::from_millis(touched.load(Ordering::Relaxed)) == last {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "idle"));
                }
            }
        }
    }
}

/// A stream that notes when a byte last crossed it.
struct Touched<'a, S> {
    inner: &'a mut S,
    touched: Arc<AtomicU64>,
    base: Instant,
}

impl<'a, S> Touched<'a, S> {
    fn new(inner: &'a mut S, touched: &Arc<AtomicU64>, base: Instant) -> Self {
        Self {
            inner,
            touched: Arc::clone(touched),
            base,
        }
    }

    fn touch(&self) {
        let millis = self.base.elapsed().as_millis();
        self.touched
            .store(u64::try_from(millis).unwrap_or(u64::MAX), Ordering::Relaxed);
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Touched<'_, S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut *self.inner).poll_read(cx, buf);
        if matches!(polled, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.touch();
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Touched<'_, S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let polled = Pin::new(&mut *self.inner).poll_write(cx, buf);
        if matches!(polled, Poll::Ready(Ok(n)) if n > 0) {
            self.touch();
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Bytes keep the copy alive; silence ends it.
    #[tokio::test(start_paused = true)]
    async fn silence_ends_the_copy_and_traffic_does_not() {
        let (mut left, mut near) = tokio::io::duplex(64);
        let (mut far, mut right) = tokio::io::duplex(64);
        let copy = tokio::spawn(async move {
            copy_until_idle(&mut near, &mut far, Duration::from_secs(10)).await
        });

        for _ in 0..3 {
            tokio::time::sleep(Duration::from_secs(7)).await;
            left.write_all(b"ping").await.unwrap();
            let mut buf = [0u8; 4];
            right.read_exact(&mut buf).await.unwrap();
        }
        assert!(!copy.is_finished(), "traffic every 7 s beats a 10 s idle");

        tokio::time::sleep(Duration::from_secs(11)).await;
        let ended = copy.await.unwrap();
        assert_eq!(ended.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }
}
