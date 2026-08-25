//! Sans-IO vocabulary for protocol state machines and their I/O adapters.
//!
//! Pure protocol code converts bytes to bytes and decisions. It owns no socket,
//! clock, or timer; [`crate::Wait`] bounds the surrounding session instead.
//! Negotiations and codecs write into caller-owned buffers, and [`Decode`]
//! returns an input remainder so adapters never index by codec-supplied counts.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{EgressError, ProxyError};

// Pure protocol state.

/// Streaming decode result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decoded<T> {
    /// More input is needed.
    Incomplete,
    /// A complete message and the number of bytes consumed.
    Complete { value: T, consumed: usize },
}

/// Pure state machine for a one-time protocol negotiation.
///
/// Calls may repeat the same input while more bytes arrive. Implementations
/// emit each phase once and report the exact consumed prefix.
pub trait Negotiation {
    /// Value established by the negotiation.
    type Output;

    /// Processes all received input and appends output for the next phase.
    fn advance(
        &mut self,
        input: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<Decoded<Self::Output>, ProxyError>;
}

/// Codec result carrying the unconsumed input remainder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decode<'a> {
    /// Framing continues; decoded bytes are in the sink.
    Framed { rest: &'a [u8] },
    /// Framing ended; `rest` is transparent payload from now on.
    Transparent { rest: &'a [u8] },
}

impl<'a> Decode<'a> {
    /// Number of input bytes consumed, bounded by the input slice.
    fn consumed(self, input: &[u8]) -> usize {
        let rest = match self {
            Self::Framed { rest } | Self::Transparent { rest } => rest,
        };
        input.len().saturating_sub(rest.len())
    }
}

/// Pure post-negotiation framing codec.
pub trait Codec {
    /// Decodes available input and appends plaintext to `out`.
    fn decode<'a>(&mut self, input: &'a [u8], out: &mut Vec<u8>) -> Result<Decode<'a>, ProxyError>;

    /// Encodes one bounded payload into `out`.
    fn encode(&mut self, _payload: &[u8], _out: &mut Vec<u8>) -> Result<(), ProxyError> {
        Err(ProxyError::Unframed)
    }

    /// Maximum payload accepted by one [`Self::encode`] call.
    fn max_payload(&self) -> usize {
        usize::MAX
    }

    /// Whether writes are framed as well as reads.
    fn writes(&self) -> Writes {
        Writes::Framed
    }
}

/// Static write-framing property.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Writes {
    /// Payloads use [`Codec::encode`].
    Framed,
    /// Payloads reach the inner stream unchanged.
    Verbatim,
}

// I/O adapter.

/// Read size during negotiation.
const NEGOTIATION_CHUNK: usize = 512;

/// Maximum negotiation buffer size.
const MAX_NEGOTIATION: usize = 16 * 1024;

/// Drives one [`Negotiation`] and returns bytes read past its frame.
///
/// The caller must replay the returned surplus through [`crate::Prefixed`].
pub async fn negotiate<S, H>(
    stream: &mut S,
    machine: &mut H,
) -> Result<(H::Output, Vec<u8>), EgressError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    H: Negotiation,
{
    let mut received: Vec<u8> = Vec::new();
    let mut sending: Vec<u8> = Vec::new();
    let mut chunk = [0u8; NEGOTIATION_CHUNK];

    loop {
        sending.clear();
        let progress = machine.advance(&received, &mut sending)?;
        if !sending.is_empty() {
            stream.write_all(&sending).await?;
            stream.flush().await?;
        }
        if let Decoded::Complete { value, consumed } = progress {
            // Keep an invalid parser count from becoming an index panic.
            if consumed > received.len() {
                return Err(ProxyError::Header.into());
            }
            received.drain(..consumed);
            return Ok((value, received));
        }
        if received.len() >= MAX_NEGOTIATION {
            return Err(ProxyError::Header.into());
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(EgressError::Io(std::io::ErrorKind::UnexpectedEof));
        }
        received.extend_from_slice(&chunk[..read]);
    }
}

/// Read size while framing is active.
const FRAMED_CHUNK: usize = 16 * 1024;

/// Async byte stream adapter for a [`Codec`].
///
/// Transparent codecs bypass framing after their header.
pub struct Framed<S, C> {
    inner: S,
    codec: C,
    /// Input awaiting codec consumption.
    coded: Vec<u8>,
    /// Decoded bytes awaiting the caller.
    plain: Vec<u8>,
    plain_at: usize,
    /// Whether reads now pass directly to `inner`.
    transparent: bool,
    /// Encoded bytes awaiting `inner`.
    pending: Vec<u8>,
    pending_at: usize,
    /// Caller-payload length represented by `pending`.
    taken: usize,
    /// Write mode captured at construction.
    writes: Writes,
}

impl<S, C: Codec> Framed<S, C> {
    pub fn new(inner: S, codec: C) -> Self {
        Self {
            writes: codec.writes(),
            inner,
            coded: Vec::new(),
            plain: Vec::new(),
            plain_at: 0,
            transparent: false,
            pending: Vec::new(),
            pending_at: 0,
            taken: 0,
            codec,
        }
    }

    /// Starts with bytes already read during negotiation.
    pub fn with_prefix(inner: S, codec: C, prefix: Vec<u8>) -> Self {
        Self {
            coded: prefix,
            ..Self::new(inner, codec)
        }
    }

    /// Hands buffered plaintext to the caller.
    fn drain(&mut self, buf: &mut ReadBuf<'_>) -> Option<()> {
        let held = self
            .plain
            .get(self.plain_at..)
            .filter(|rest| !rest.is_empty())?;
        let moved = held.len().min(buf.remaining());
        buf.put_slice(&held[..moved]);
        self.plain_at += moved;
        if self.plain_at == self.plain.len() {
            // Reuse the drained buffer.
            self.plain.clear();
            self.plain_at = 0;
        }
        Some(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin, C: Codec + Unpin> AsyncRead for Framed<S, C> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            // Drain decoded bytes before reading more input.
            if this.drain(buf).is_some() {
                return Poll::Ready(Ok(()));
            }
            // Transparent mode avoids another copy.
            if this.transparent && this.coded.is_empty() {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }

            if !this.coded.is_empty() {
                let outcome = this
                    .codec
                    .decode(&this.coded, &mut this.plain)
                    .map_err(fatal)?;
                match outcome {
                    Decode::Transparent { rest } => {
                        // Retain surplus so small caller buffers cannot lose it.
                        this.plain.extend_from_slice(rest);
                        this.coded.clear();
                        this.transparent = true;
                        continue;
                    }
                    Decode::Framed { .. } => {
                        let consumed = outcome.consumed(&this.coded);
                        this.coded.drain(..consumed);
                        // Otherwise the codec needs more input.
                        if consumed > 0 || !this.plain.is_empty() {
                            continue;
                        }
                    }
                }
            }

            let mut chunk = [0u8; FRAMED_CHUNK];
            let mut reading = ReadBuf::new(&mut chunk);
            match Pin::new(&mut this.inner).poll_read(cx, &mut reading) {
                Poll::Ready(Ok(())) => {
                    let filled = reading.filled();
                    if filled.is_empty() {
                        // A partial frame ends with the underlying stream.
                        return Poll::Ready(Ok(()));
                    }
                    this.coded.extend_from_slice(filled);
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin, C: Codec + Unpin> AsyncWrite for Framed<S, C> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        // Verbatim writes bypass the codec.
        if this.writes == Writes::Verbatim {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        // Serialize framed writes to avoid interleaving frames.
        if this.pending_at == this.pending.len() {
            this.pending.clear();
            this.pending_at = 0;
            let take = buf.len().min(this.codec.max_payload());
            if take == 0 {
                return Poll::Ready(Ok(0));
            }
            this.codec
                .encode(&buf[..take], &mut this.pending)
                .map_err(fatal)?;
            this.taken = take;
        }
        while this.pending_at < this.pending.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.pending[this.pending_at..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "the inner stream stopped accepting a frame mid-way",
                    )));
                }
                Poll::Ready(Ok(written)) => this.pending_at += written,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(this.taken))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Converts a codec failure into a terminal stream error.
fn fatal(error: ProxyError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two-round negotiation used to test repeated input, surplus, and
    /// one-time phase output.
    #[derive(Default)]
    struct Greeting {
        greeted: bool,
        requested: bool,
    }

    impl Negotiation for Greeting {
        type Output = u8;

        fn advance(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<Decoded<u8>, ProxyError> {
            if !self.greeted {
                out.extend_from_slice(b"HELLO");
                self.greeted = true;
                return Ok(Decoded::Incomplete);
            }
            let Some(&ack) = input.first() else {
                return Ok(Decoded::Incomplete);
            };
            if ack != b'K' {
                return Err(ProxyError::Version(ack));
            }
            if !self.requested {
                out.extend_from_slice(b"REQ");
                self.requested = true;
            }
            let Some(&reply) = input.get(1) else {
                return Ok(Decoded::Incomplete);
            };
            Ok(Decoded::Complete {
                value: reply,
                consumed: 2,
            })
        }
    }

    /// Split input must produce the same verdict as one complete reply.
    #[test]
    fn a_negotiation_reaches_the_same_verdict_however_the_bytes_are_split() {
        for prefix in 0..=2usize {
            let mut machine = Greeting::default();
            let mut sent = Vec::new();
            let wire = b"KZtrailing";

            // Each prefix represents another driver read.
            let mut verdict = None;
            for taken in 0..=prefix.min(wire.len()) {
                verdict = Some(machine.advance(&wire[..taken], &mut sent).unwrap());
            }
            match (prefix, verdict.unwrap()) {
                (0 | 1, Decoded::Incomplete) => {}
                (2, Decoded::Complete { value, consumed }) => {
                    assert_eq!(value, b'Z');
                    assert_eq!(consumed, 2, "the trailing bytes are not the reply's");
                }
                (prefix, other) => panic!("{prefix} bytes gave {other:?}"),
            }
        }
    }

    /// Re-entering an emitted phase must not duplicate its output.
    #[test]
    fn re_offering_the_same_input_writes_nothing_further() {
        let mut machine = Greeting::default();
        let mut first = Vec::new();
        machine.advance(b"", &mut first).unwrap();
        assert_eq!(first, b"HELLO");

        let mut again = Vec::new();
        machine.advance(b"", &mut again).unwrap();
        assert!(again.is_empty(), "the greeting is written once");

        let mut third = Vec::new();
        machine.advance(b"K", &mut third).unwrap();
        assert_eq!(third, b"REQ");
        let mut fourth = Vec::new();
        machine.advance(b"K", &mut fourth).unwrap();
        assert!(fourth.is_empty(), "and so is the request");
    }

    /// The I/O driver returns bytes read beyond the negotiation.
    #[tokio::test]
    async fn the_driver_returns_what_it_read_past_the_negotiation() {
        let (mut peer, ours) = tokio::io::duplex(256);
        tokio::spawn(async move {
            let mut greeting = [0u8; 5];
            peer.read_exact(&mut greeting).await.unwrap();
            assert_eq!(&greeting, b"HELLO");
            // One read contains both negotiation bytes and the server banner.
            peer.write_all(b"KZ220 ready\r\n").await.unwrap();
            let mut request = [0u8; 3];
            peer.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"REQ");
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });

        let mut stream = ours;
        let (value, surplus) = negotiate(&mut stream, &mut Greeting::default())
            .await
            .expect("the negotiation completes");
        assert_eq!(value, b'Z');
        assert_eq!(
            surplus, b"220 ready\r\n",
            "the peer's banner survives the handshake that over-read it"
        );
    }

    /// Unfinished peer chatter is rejected at the buffer ceiling. Silence is
    /// left to the session deadline in [`crate::Wait`].
    #[tokio::test]
    async fn a_negotiation_the_peer_will_not_end_is_refused_rather_than_buffered() {
        let (mut peer, ours) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            // Chatter that never forms a complete message.
            let filler = vec![b'K'; 1024];
            while peer.write_all(&filler).await.is_ok() {}
        });

        struct Never;
        impl Negotiation for Never {
            type Output = ();
            fn advance(&mut self, _: &[u8], _: &mut Vec<u8>) -> Result<Decoded<()>, ProxyError> {
                Ok(Decoded::Incomplete)
            }
        }

        let mut stream = ours;
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            negotiate(&mut stream, &mut Never),
        )
        .await
        .expect("the buffer ceiling ends this without a deadline");
        assert!(outcome.is_err(), "an endless negotiation is refused");
    }

    /// Codec that strips a two-byte header before becoming transparent.
    #[derive(Default)]
    struct StripTwo {
        stripped: bool,
    }

    impl Codec for StripTwo {
        fn decode<'a>(
            &mut self,
            input: &'a [u8],
            _out: &mut Vec<u8>,
        ) -> Result<Decode<'a>, ProxyError> {
            if self.stripped {
                return Ok(Decode::Transparent { rest: input });
            }
            let Some((_header, rest)) = input.split_at_checked(2) else {
                return Ok(Decode::Framed { rest: input });
            };
            self.stripped = true;
            Ok(Decode::Transparent { rest })
        }

        fn writes(&self) -> Writes {
            Writes::Verbatim
        }
    }

    /// Read-only framing must leave writes transparent.
    ///
    /// `StripTwo` has no encoder, so a successful round trip proves that
    /// [`Writes::Verbatim`] bypasses [`Codec::encode`].
    #[tokio::test]
    async fn a_read_only_framing_writes_without_touching_the_codec() {
        assert!(
            matches!(
                StripTwo::default().encode(b"anything", &mut Vec::new()),
                Err(ProxyError::Unframed)
            ),
            "a verbatim codec has no encoder to reach"
        );

        let (mut peer, ours) = tokio::io::duplex(4096);
        let mut framed = Framed::new(ours, StripTwo::default());
        framed.write_all(b"straight through").await.unwrap();
        framed.flush().await.unwrap();

        let mut back = [0u8; 16];
        peer.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"straight through");
    }

    /// A small caller buffer must receive all payload bytes that arrived with
    /// the header.
    #[tokio::test]
    async fn a_small_reader_takes_every_byte_of_a_surplus_larger_than_its_buffer() {
        let (mut peer, ours) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut wire = vec![0u8, 0u8];
            wire.extend(std::iter::repeat_n(b'x', 300));
            peer.write_all(&wire).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let mut framed = Framed::new(ours, StripTwo::default());
        let mut total = 0usize;
        let mut small = [0u8; 16];
        while total < 300 {
            let read = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                framed.read(&mut small),
            )
            .await
            .expect("the payload is still coming")
            .expect("no error");
            if read == 0 {
                break;
            }
            assert!(small[..read].iter().all(|byte| *byte == b'x'));
            total += read;
        }
        assert_eq!(total, 300, "every byte of the surplus reached the caller");
    }

    /// Codec with a one-byte length prefix.
    #[derive(Default)]
    struct LengthPrefixed;

    impl Codec for LengthPrefixed {
        fn decode<'a>(
            &mut self,
            input: &'a [u8],
            out: &mut Vec<u8>,
        ) -> Result<Decode<'a>, ProxyError> {
            let Some(&length) = input.first() else {
                return Ok(Decode::Framed { rest: input });
            };
            let Some((frame, rest)) = input[1..].split_at_checked(usize::from(length)) else {
                return Ok(Decode::Framed { rest: input });
            };
            out.extend_from_slice(frame);
            Ok(Decode::Framed { rest })
        }

        fn encode(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<(), ProxyError> {
            out.push(payload.len() as u8);
            out.extend_from_slice(payload);
            Ok(())
        }

        fn max_payload(&self) -> usize {
            255
        }
    }

    /// Frames must decode correctly across arbitrary read boundaries.
    #[tokio::test]
    async fn framing_survives_arbitrary_read_boundaries() {
        for chunk in [1usize, 2, 3, 17, 1024] {
            let (mut peer, ours) = tokio::io::duplex(4096);
            let mut wire = Vec::new();
            for frame in [&b"one"[..], b"a longer frame", b"z"] {
                wire.push(frame.len() as u8);
                wire.extend_from_slice(frame);
            }
            tokio::spawn(async move {
                for piece in wire.chunks(chunk) {
                    peer.write_all(piece).await.unwrap();
                    peer.flush().await.unwrap();
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            });

            let mut framed = Framed::new(ours, LengthPrefixed);
            let mut seen = Vec::new();
            while seen.len() < 18 {
                let mut buf = [0u8; 64];
                let read = tokio::time::timeout(
                    std::time::Duration::from_millis(500),
                    framed.read(&mut buf),
                )
                .await
                .unwrap_or_else(|_| panic!("chunked by {chunk}: stalled"))
                .unwrap();
                if read == 0 {
                    break;
                }
                seen.extend_from_slice(&buf[..read]);
            }
            assert_eq!(seen, b"onea longer framez", "chunked by {chunk}");
        }
    }

    /// `poll_write` reports payload bytes, not the larger encoded frame.
    #[tokio::test]
    async fn a_write_is_framed_and_reported_in_the_callers_own_units() {
        let (mut peer, ours) = tokio::io::duplex(4096);
        let mut framed = Framed::new(ours, LengthPrefixed);

        let written = framed.write(b"payload").await.unwrap();
        assert_eq!(written, 7, "the caller wrote seven bytes, not nine");
        framed.flush().await.unwrap();

        let mut back = [0u8; 8];
        peer.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"\x07payload");
    }

    /// Payloads larger than one frame are split at the codec limit.
    #[tokio::test]
    async fn a_write_larger_than_one_frame_is_split() {
        let (mut peer, ours) = tokio::io::duplex(8192);
        let mut framed = Framed::new(ours, LengthPrefixed);

        let big = vec![b'q'; 300];
        let written = framed.write(&big).await.unwrap();
        assert_eq!(written, 255, "one frame's worth, and the caller retries");
        framed.flush().await.unwrap();

        let mut back = vec![0u8; 256];
        peer.read_exact(&mut back).await.unwrap();
        assert_eq!(back[0], 255);
        assert!(back[1..].iter().all(|byte| *byte == b'q'));
    }
}
