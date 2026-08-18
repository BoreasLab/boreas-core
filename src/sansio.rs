//! The vocabulary every wire protocol in this crate is written in.
//!
//! **No function in the pure half of this module touches a socket, a clock, or
//! a random number generator.** A protocol here is a function from bytes to
//! bytes and a decision; the shell below it is the only thing that awaits. That
//! is sans-IO in Cory Benfield's original sense — *"defined entirely in terms of
//! synchronous functions returning synchronous results"* — and the payoff is
//! the one his write-up names: the protocol can be driven byte at a time by a
//! test, with no mock, no socket, and no runtime.
//!
//! # Why this shape and not the canonical one
//!
//! The sans-IO quartet the Rust ecosystem converged on is quinn-proto's:
//! `handle_input`, `poll_transmit`, `poll_timeout`, `handle_timeout`. Half of
//! it is missing here, deliberately.
//!
//! **A proxy handshake owns no timers.** SOCKS5, Shadowsocks, VLESS, and the
//! V2Ray transports are sequential exchanges over a transport that already
//! retransmits; nothing in them schedules a wake-up, so `poll_timeout` would
//! always answer `None` and `handle_timeout` would have nothing to do. The
//! deadline that does bound them is a session property, not a protocol one, and
//! it lives in [`crate::Wait`]. Adding the two vacuous methods would buy the
//! shape of the ecosystem's pattern and none of its substance — and would
//! invite exactly the failure Firezone warns about, where a `poll_timeout` that
//! never advances turns a driver into a busy loop.
//!
//! What remains is the half that does pay, and it is the older shape: `h11`'s
//! `receive_data`/`next_event` and `snow`'s `read_message`/`write_message` —
//! bytes in, bytes out, synchronous.
//!
//! # Buffers
//!
//! Output goes into a caller-owned sink, never a returned `Vec`. That is
//! quinn-proto's choice (`poll_transmit(now, max_datagrams, buf: &mut Vec<u8>)`
//! returning a size rather than the bytes) and it is already this crate's, in
//! [`crate::PacketEgress`]. A driver clears and reuses one buffer for the life
//! of a connection, so framing costs no allocation per chunk.
//!
//! The known cost of a sans-IO boundary is the copy it forces: bytes must land
//! in the protocol's buffer before they can reach the caller's. [`Decode`]
//! exists to refuse that cost where it is avoidable — a codec whose framing has
//! *ended* says so, and [`Framed`] stops copying and reads straight through.
//!
//! [`Decode`] carries the *remainder* of the input rather than a count of what
//! was taken, and that is the second thing it is for. A count is a number the
//! adapter turns into `drain(..n)` and `input[n..]`, so a codec that miscounts
//! panics a connection task; a remainder is carved out of the input, so the
//! arithmetic that could be wrong does not exist.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{EgressError, ProxyError};

// ------------------------------------------------------- The pure half

/// Streaming decode result; `Incomplete` distinguishes short input from a
/// protocol error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decoded<T> {
    /// More bytes are needed. The caller reads and calls again.
    Incomplete,
    /// A whole message, and how many bytes of the buffer it used.
    Complete { value: T, consumed: usize },
}

/// One protocol negotiation, as a pure state machine.
///
/// Named to distinguish this exchange from QUIC's `Handshake` connection type.
///
/// **Total, and re-entrant on its input.** [`Self::advance`] is called with
/// everything received so far — not with the delta — so a machine that answers
/// [`Decoded::Incomplete`] will see those same bytes again with more behind
/// them. Two obligations follow, and both are load-bearing:
///
/// - It must not write the same bytes to `out` twice. A machine emits when it
///   changes phase, so re-entering a phase it has already emitted for must
///   write nothing.
/// - It must report `consumed` exactly. Everything past it is the payload of
///   whatever the negotiation was for, and a machine that over-reports silently
///   eats the peer's first bytes — which, for a server-first protocol behind
///   the proxy, is its whole banner.
pub trait Negotiation {
    /// What the negotiation establishes. `()` when the answer is just "it
    /// worked".
    type Output;

    /// Offers everything received so far, and takes whatever should be sent.
    ///
    /// Called once with an empty slice to start, which is how a client-speaks-
    /// first protocol gets to write its opening bytes without a special case.
    fn advance(
        &mut self,
        input: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<Decoded<Self::Output>, ProxyError>;
}

/// Decode result. `Transparent` ends framing, so VLESS avoids copying
/// subsequent bytes.
///
/// Both variants carry the **remainder** of the input rather than a count of
/// what was taken. See [`Decode::consumed`] for why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decode<'a> {
    /// Took a prefix; whatever it decoded to is in the sink, and `rest` is what
    /// the codec has not consumed.
    ///
    /// An empty `rest` equal in length to the input, with an empty sink, means
    /// "not enough yet" — the codec's spelling of [`Decoded::Incomplete`].
    Framed { rest: &'a [u8] },
    /// Took a prefix, and **everything in `rest` and after is payload, verbatim
    /// and forever**. The adapter will not call this codec again.
    Transparent { rest: &'a [u8] },
}

impl<'a> Decode<'a> {
    /// How much of `input` the codec took.
    ///
    /// **Cannot exceed the input, which is the point of holding a slice.** A
    /// count would let a codec name a prefix longer than what it was given, and
    /// the adapter turns that count into `drain(..consumed)` and
    /// `input[consumed..]` — an index panic in a network task, guarded by
    /// nothing but each codec having got its own arithmetic right. A remainder
    /// is carved out of the input, so the arithmetic that could be wrong no
    /// longer exists.
    fn consumed(self, input: &[u8]) -> usize {
        let rest = match self {
            Self::Framed { rest } | Self::Transparent { rest } => rest,
        };
        input.len().saturating_sub(rest.len())
    }
}

/// Post-negotiation framing, as a pure codec.
///
/// Split from [`Negotiation`] because the two have different lifetimes: a
/// handshake runs once and is discarded, a codec runs for every byte of the
/// connection. A protocol with no framing implements only the former; one whose
/// framing never ends (Shadowsocks) implements only the latter; VLESS
/// implements a codec that ends, which is what [`Decode::Transparent`] is for.
pub trait Codec {
    /// Decodes as much of `input` as it can, appending plaintext to `out`.
    ///
    /// Must make progress or say it cannot: returning `Framed { rest: input }`
    /// without appending is the only way to ask for more input, and the adapter
    /// reads before calling again.
    /// The returned remainder must be a suffix of `input`; carve it with
    /// `&input[taken..]` rather than building one, so the adapter's
    /// "how much was taken" is arithmetic neither side can get wrong.
    fn decode<'a>(&mut self, input: &'a [u8], out: &mut Vec<u8>) -> Result<Decode<'a>, ProxyError>;

    /// Encodes one payload into `out`, whole.
    ///
    /// The payload is never longer than [`Self::max_payload`]; the adapter
    /// splits before calling.
    fn encode(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<(), ProxyError>;

    /// The largest payload a single [`Self::encode`] may be handed.
    ///
    /// Defaults to unbounded, which is right for a codec whose framing carries
    /// no length. One that does — every AEAD chunk format here — names the
    /// bound its length field can express, and the adapter splits rather than
    /// letting the codec discover the problem mid-encode.
    fn max_payload(&self) -> usize {
        usize::MAX
    }

    /// Whether this codec frames what is written as well as what is read.
    ///
    /// Read by the adapter once, at construction. **The two directions are
    /// genuinely independent**: VLESS strips one header off what arrives and
    /// writes raw bytes forever, so routing its writes through [`Self::encode`]
    /// would copy every outbound byte through a sink to hand it back unchanged.
    fn writes(&self) -> Writes {
        Writes::Framed
    }
}

/// How a codec treats what is written through it.
///
/// Static write-framing property; it cannot change mid-connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Writes {
    /// Every payload goes through [`Codec::encode`].
    Framed,
    /// Payloads reach the inner stream untouched, with no copy and no encode
    /// call.
    Verbatim,
}

// ------------------------------------------------------ The thin shell

/// How much is read at a time while a negotiation is in progress.
///
/// Small to bound hostile-peer bytes; excess is replayed rather than dropped.
const NEGOTIATION_CHUNK: usize = 512;

/// The largest negotiation this will buffer before giving up.
///
/// A peer that has not finished by here is not one any protocol in this crate
/// speaks, and the bound is what stops it growing the buffer without end.
const MAX_NEGOTIATION: usize = 16 * 1024;

/// Runs one [`Negotiation`] to completion over `stream`.
///
/// **This is the only place a proxy negotiation performs I/O**, which is the
/// whole point: every protocol's sequencing lives in a pure state machine that
/// a test drives byte at a time, and the awaiting happens once, here.
///
/// Returns what the negotiation established and **whatever was read past it**.
/// That surplus is not an edge case: TCP does not preserve the sender's
/// boundaries, and a server-first protocol behind the proxy sends its banner
/// the instant the far side connects, arriving coalesced into the same segment
/// as the reply for exactly the flows where it matters most. Dropping it
/// truncates the response with no error anywhere. Hand it to
/// [`Prefixed`](crate::Prefixed).
///
/// O(bytes exchanged), with one buffer for the negotiation and one for its
/// output; the deadline is the caller's, from [`crate::Wait`].
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
            // Total, rather than `drain(..consumed)`. A negotiation naming more
            // than it was given is a defect in this crate and not something a
            // peer can cause, but the alternative to saying so is an index
            // panic in a connection task. `Codec` does not need this because
            // [`Decode`] carries the remainder instead of a count; `Decoded` is
            // shared with a dozen in-scope parsers where a count is the natural
            // shape, so the check lives at the one boundary that indexes with it.
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

/// How much ciphertext is read at a time once framing is running. One AEAD
/// chunk of every format here fits comfortably.
const FRAMED_CHUNK: usize = 16 * 1024;

/// A byte stream over a [`Codec`].
///
/// **One adapter for every framed protocol in this crate.** Before it there was
/// one hand-written `poll_read` state machine per protocol, each re-deriving
/// the same four-part dance — accumulate, decode when there is enough, hand out
/// what fits, keep the rest — and one of them got it wrong in a way that
/// silently truncated payload.
///
/// The steady state of a [`Decode::Transparent`] codec costs nothing: no copy,
/// no buffer, the caller's `poll_read` reaches the inner stream directly.
pub struct Framed<S, C> {
    inner: S,
    codec: C,
    /// Read from `inner`, not yet consumed by the codec.
    coded: Vec<u8>,
    /// Decoded and waiting for the caller, and how far it has been taken.
    plain: Vec<u8>,
    plain_at: usize,
    /// Set once the codec has said the rest of the stream is payload verbatim.
    /// From here `coded` stays empty and reads go straight through.
    transparent: bool,
    /// Encoded and waiting for `inner`, and how far it has reached.
    pending: Vec<u8>,
    pending_at: usize,
    /// How much of the caller's payload `pending` encodes, which is what
    /// `poll_write` reports once it has all left. Not `pending.len()`: that is
    /// the framed size, and telling a caller its 100 bytes became 116 would
    /// have it advance past bytes it never wrote.
    taken: usize,
    /// Asked of the codec once, at construction.
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

    /// Starts with `prefix` already received, for a codec whose stream began
    /// before the adapter did — the surplus [`negotiate`] read past a
    /// handshake.
    pub fn with_prefix(inner: S, codec: C, prefix: Vec<u8>) -> Self {
        Self {
            coded: prefix,
            ..Self::new(inner, codec)
        }
    }

    /// Hands the caller as much decoded payload as fits, or `None` when there
    /// is none held.
    fn drain(&mut self, buf: &mut ReadBuf<'_>) -> Option<()> {
        let held = self
            .plain
            .get(self.plain_at..)
            .filter(|rest| !rest.is_empty())?;
        let moved = held.len().min(buf.remaining());
        buf.put_slice(&held[..moved]);
        self.plain_at += moved;
        if self.plain_at == self.plain.len() {
            // Everything held has been taken, so the buffer is free to be
            // filled again rather than grown.
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
            // **What is already decoded goes first, always.** Skipping this
            // when the caller's buffer is smaller than what is held is exactly
            // the truncation this adapter exists to make impossible.
            if this.drain(buf).is_some() {
                return Poll::Ready(Ok(()));
            }
            // The zero-copy steady state: framing is over and nothing is held,
            // so the caller reads the inner stream with nothing in between.
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
                        // Whatever followed the framing is payload the caller
                        // is owed. It moves into `plain` rather than being
                        // handed out here, so a caller with a small buffer
                        // takes it across as many reads as it needs.
                        this.plain.extend_from_slice(rest);
                        this.coded.clear();
                        this.transparent = true;
                        continue;
                    }
                    Decode::Framed { .. } => {
                        let consumed = outcome.consumed(&this.coded);
                        this.coded.drain(..consumed);
                        // Progress means something to hand out or something
                        // consumed; neither means the codec needs more input,
                        // and reading is the only thing that provides it.
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
                        // The peer closed. Anything the codec still holds is a
                        // truncated frame, which is end-of-stream for the
                        // caller rather than an error it could act on.
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
        // The zero-copy write path: this protocol frames nothing outbound, so
        // the caller's bytes reach the inner stream with no sink in between.
        if this.writes == Writes::Verbatim {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        // One payload in flight at a time. Encoding a second before the first
        // has left would interleave two frames on the wire, which no framing
        // here can express.
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

/// A codec failure ends the stream. Framing is not something a peer recovers
/// from mid-connection: a chunk that will not decode means the two sides no
/// longer agree on where the next one begins.
fn fatal(error: ProxyError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A two-round negotiation: greet, read one byte of acknowledgement, send a
    /// request, read a reply. Enough shape to exercise re-entrancy, the surplus,
    /// and the write-once-per-phase obligation.
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

    /// **The property sans-IO is for.** A state machine that only works when a
    /// whole reply arrives in one read is one that works in a test and fails on
    /// a real network, and the only way to know is to drive it a byte at a time.
    #[test]
    fn a_negotiation_reaches_the_same_verdict_however_the_bytes_are_split() {
        for prefix in 0..=2usize {
            let mut machine = Greeting::default();
            let mut sent = Vec::new();
            let wire = b"KZtrailing";

            // Offer a growing prefix, exactly as a driver would after each read.
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

    /// A machine emits when it changes phase, so re-entering a phase must write
    /// nothing. Getting this wrong sends the greeting twice, which every server
    /// reads as a protocol violation.
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

    /// The driver over a real (in-memory) stream, and the surplus it must
    /// return rather than swallow.
    #[tokio::test]
    async fn the_driver_returns_what_it_read_past_the_negotiation() {
        let (mut peer, ours) = tokio::io::duplex(256);
        tokio::spawn(async move {
            let mut greeting = [0u8; 5];
            peer.read_exact(&mut greeting).await.unwrap();
            assert_eq!(&greeting, b"HELLO");
            // The acknowledgement, the reply, and a server-first banner, all in
            // one segment -- which is exactly how this arrives in practice.
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

    /// A peer that says nothing is bounded, and a peer that says too much is
    /// bounded, because a negotiation buffer a stranger can grow is a denial of
    /// service that costs them one connection.
    /// **The bound exists because the peer chooses how much to say.** Without
    /// it, a stranger who connects and talks forever grows this buffer for as
    /// long as they like, which is a denial of service costing them one socket.
    ///
    /// Note what is *not* bounded here: a peer that says nothing at all leaves
    /// the read below pending forever. That is deliberate — the deadline for
    /// silence is a session property and lives in [`crate::Wait`], not in a
    /// protocol that has no opinion about how slow a network may be.
    #[tokio::test]
    async fn a_negotiation_the_peer_will_not_end_is_refused_rather_than_buffered() {
        let (mut peer, ours) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            // Endless chatter that never becomes a complete message.
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

    /// A codec that strips a two-byte header and is a byte stream after it —
    /// VLESS's shape, and the one that must not copy in its steady state.
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

        fn encode(&mut self, _payload: &[u8], _out: &mut Vec<u8>) -> Result<(), ProxyError> {
            unreachable!("this codec writes verbatim, so nothing is encoded")
        }

        fn writes(&self) -> Writes {
            Writes::Verbatim
        }
    }

    /// A codec that frames only what it reads must not pay to write. The
    /// `unreachable!` in `StripTwo::encode` is the assertion: reaching it means
    /// the adapter routed a write through a codec that has no framing for it.
    #[tokio::test]
    async fn a_read_only_framing_writes_without_touching_the_codec() {
        let (mut peer, ours) = tokio::io::duplex(4096);
        let mut framed = Framed::new(ours, StripTwo::default());
        framed.write_all(b"straight through").await.unwrap();
        framed.flush().await.unwrap();

        let mut back = [0u8; 16];
        peer.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"straight through");
    }

    /// **The defect this adapter exists to make unrepresentable.** A header and
    /// 300 bytes of payload arrive together; the caller reads 16 at a time. The
    /// hand-written adapter this replaces handed out one bufferful and dropped
    /// the other 284 with no error anywhere.
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

    /// A codec with real framing: a one-byte length then that many bytes.
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

    /// Framing that only works when a whole frame lands in one read is framing
    /// that works in a test. One byte at a time is the honest network.
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

    /// A caller's write becomes a frame, and `poll_write` reports the caller's
    /// count rather than the framed one — telling it otherwise would have it
    /// advance past bytes it never wrote.
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

    /// A payload past what the framing can express is split rather than
    /// refused, so a caller never has to know the codec's limit.
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
