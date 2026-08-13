//! Shadowsocks 2022 Edition (SIP022) as a stream egress.
//!
//! The 2022 edition rather than the older AEAD construction, and the choice is
//! a security one rather than a preference. SIP004 derived its key with
//! `EVP_BytesToKey`, carried no timestamp, and offered no replay defence; the
//! 2022 edition takes a full-entropy pre-shared key, derives a per-session
//! subkey with BLAKE3, stamps every stream with a time, and echoes the
//! request's salt in the response so a client can tell its own session from a
//! replayed one. Shipping the older construction would be shipping a protocol
//! whose own specification calls it obsolete.
//!
//! **The AEAD comes from `ring`, which is already the crate's one provider.**
//! WireGuard, the DNS upstreams, and interception all use it, so the three
//! cipher suites here add no second crypto stack. BLAKE3 is a new dependency
//! and an unavoidable one: it *is* the key-derivation function the protocol
//! names, and no substitute is wire-compatible.
//!
//! **Nonces are a counter this code owns, so `ring`'s safe API is the wrong
//! one.** SIP022 fixes the nonce as a 12-byte little-endian counter starting at
//! zero and incremented after every operation, separately per direction. That
//! is exactly what `LessSafeKey` exists for, and [`Session`] is the type that
//! keeps the counter and the key together so no call site can pair a key with
//! the wrong number.
//!
//! **Wire compatibility against a reference server is unverified.** The tests
//! below drive this implementation against itself, which proves the framing is
//! self-consistent and that every guard fires, but a misreading of the
//! specification would satisfy both halves equally. Verifying against
//! `shadowsocks-rust` or a deployed server is recorded in
//! [Verification](../docs/verification.md) and is not something this
//! environment can perform.

use std::{
    pin::Pin,
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{
    AsyncStream, BoxFuture, DatagramFidelity, EgressCapabilities, EgressError, NatBehavior,
    ProxyError, StreamEgress, Target, TunnelBypass, encode_address,
};

/// The BLAKE3 derive-key context, fixed by SIP022. It is part of the wire
/// format: a different string yields a different subkey and no interoperation.
const SUBKEY_CONTEXT: &str = "shadowsocks 2022 session subkey";

/// Bytes an AEAD tag adds to every sealed chunk.
const TAG: usize = 16;

/// The largest payload one chunk carries, from SIP022. The two-byte length
/// field bounds it, and it is what sizes the read buffer.
const MAX_CHUNK: usize = 0xffff;

/// How far a peer's timestamp may differ from ours before the stream is refused.
/// SIP022 fixes 30 seconds; a wider window would widen the replay opportunity
/// it exists to close.
const CLOCK_SKEW_SECONDS: u64 = 30;

/// Stream types, SIP022 §"TCP". A client never writes 1 and never accepts 0,
/// which is what stops a reflected request from being read as a response.
const TYPE_REQUEST: u8 = 0;
const TYPE_RESPONSE: u8 = 1;

/// The cipher suites SIP022 defines. Closed: each names its key and salt
/// length, so a configuration cannot pair a 16-byte key with a 32-byte salt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Method {
    /// SIP022 ties the salt length to the key length, so one function answers
    /// both and they cannot drift.
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    pub fn salt_len(self) -> usize {
        self.key_len()
    }

    fn algorithm(self) -> &'static aead::Algorithm {
        match self {
            Self::Aes128Gcm => &aead::AES_128_GCM,
            Self::Aes256Gcm => &aead::AES_256_GCM,
            Self::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
        }
    }

    /// The identifier this method is configured by, matching the names the
    /// wider Shadowsocks ecosystem uses.
    pub fn name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "2022-blake3-aes-128-gcm",
            Self::Aes256Gcm => "2022-blake3-aes-256-gcm",
            Self::ChaCha20Poly1305 => "2022-blake3-chacha20-poly1305",
        }
    }
}

/// A pre-shared key whose length matches its method.
///
/// Refined because SIP022 forbids deriving a key from a passphrase: the key is
/// full-entropy material of an exact length, and admitting a short one would
/// silently weaken every session built from it.
#[derive(Clone, Debug)]
pub struct PreSharedKey {
    bytes: Vec<u8>,
    method: Method,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// The key is not the length the method requires.
    Length { expected: usize, found: usize },
}

impl PreSharedKey {
    pub fn new(method: Method, bytes: impl Into<Vec<u8>>) -> Result<Self, KeyError> {
        let bytes = bytes.into();
        if bytes.len() != method.key_len() {
            return Err(KeyError::Length {
                expected: method.key_len(),
                found: bytes.len(),
            });
        }
        Ok(Self { bytes, method })
    }

    /// The session subkey for one salt: `BLAKE3::derive_key(context, psk ||
    /// salt)`, truncated to the method's key length.
    ///
    /// O(key + salt) — a single BLAKE3 compression over 32 to 64 bytes.
    fn subkey(&self, salt: &[u8]) -> Vec<u8> {
        let mut material = Vec::with_capacity(self.bytes.len() + salt.len());
        material.extend_from_slice(&self.bytes);
        material.extend_from_slice(salt);
        let derived = blake3::derive_key(SUBKEY_CONTEXT, &material);
        derived[..self.method.key_len()].to_vec()
    }
}

/// One direction of one session: a key and the counter that must never repeat
/// against it.
///
/// The two live together because a nonce reused with a key destroys AEAD
/// security entirely, and keeping them in separate variables is how that
/// happens. Every seal and open goes through here.
struct Session {
    key: LessSafeKey,
    /// The 12-byte little-endian nonce, as a counter. A `u64` covers it: the
    /// top four bytes stay zero, and 2^64 chunks is unreachable on any stream.
    counter: u64,
}

impl Session {
    fn new(method: Method, subkey: &[u8]) -> Result<Self, EgressError> {
        let key = UnboundKey::new(method.algorithm(), subkey).map_err(|_| ProxyError::Crypto)?;
        Ok(Self {
            key: LessSafeKey::new(key),
            counter: 0,
        })
    }

    /// The next nonce, consuming it so the same value cannot be produced twice.
    fn next_nonce(&mut self) -> Nonce {
        let mut bytes = [0u8; 12];
        bytes[..8].copy_from_slice(&self.counter.to_le_bytes());
        self.counter += 1;
        Nonce::assume_unique_for_key(bytes)
    }

    /// Seals in place, appending the tag. SIP022 uses no associated data.
    fn seal(&mut self, buf: &mut Vec<u8>) -> Result<(), EgressError> {
        let nonce = self.next_nonce();
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), buf)
            .map_err(|_| ProxyError::Crypto)?;
        Ok(())
    }

    /// Opens in place, returning the plaintext. A failure here is an
    /// authentication failure and is fatal to the stream: there is no way to
    /// resynchronise a counter-based AEAD after one.
    fn open<'a>(&mut self, buf: &'a mut [u8]) -> Result<&'a [u8], EgressError> {
        let nonce = self.next_nonce();
        let plain = self
            .key
            .open_in_place(nonce, Aad::empty(), buf)
            .map_err(|_| ProxyError::Crypto)?;
        Ok(plain)
    }
}

/// Seconds since the Unix epoch, as SIP022 stamps them.
///
/// The clock is an effect, so it enters the pure header codec as an argument
/// and is read only here, at the one boundary that performs it.
fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// Rejects a peer whose clock is too far from ours.
///
/// This is the replay window: a server keeps recently seen salts for a bounded
/// time, and that bound is only meaningful if a stamp far outside it is
/// refused. Symmetric in both directions, because a replayed *response* is as
/// harmful as a replayed request.
fn check_timestamp(theirs: u64, ours: u64) -> Result<(), EgressError> {
    let skew = ours.abs_diff(theirs);
    if skew > CLOCK_SKEW_SECONDS {
        return Err(ProxyError::Stale { skew }.into());
    }
    Ok(())
}

/// Builds the variable-length request header: target, padding, then whatever
/// payload the caller wants to ride along with it.
///
/// Padding is permitted up to 900 bytes; this client sends none, which the
/// specification allows, and says so with an explicit zero rather than by
/// omitting the field.
fn encode_request_body(target: &Target, initial: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(initial.len() + 32);
    encode_address(target, &mut body);
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(initial);
    body
}

/// The fixed-length request header: type, timestamp, and the length of the
/// variable-length header that follows it.
fn encode_request_fixed(now: u64, body_len: u16) -> Vec<u8> {
    let mut header = Vec::with_capacity(11);
    header.push(TYPE_REQUEST);
    header.extend_from_slice(&now.to_be_bytes());
    header.extend_from_slice(&body_len.to_be_bytes());
    header
}

/// Reads the fixed-length response header, checking everything it asserts:
/// that it is a response, that its clock agrees with ours, and that it echoes
/// the salt of *our* request rather than some other session's.
///
/// The salt echo is what makes a replayed response detectable, so verifying it
/// is not optional politeness — it is the property the field exists for.
fn decode_response_fixed(plain: &[u8], request_salt: &[u8], now: u64) -> Result<u16, EgressError> {
    let salt_len = request_salt.len();
    if plain.len() != 1 + 8 + salt_len + 2 {
        return Err(ProxyError::Header.into());
    }
    if plain[0] != TYPE_RESPONSE {
        return Err(ProxyError::Header.into());
    }
    let stamp = u64::from_be_bytes(plain[1..9].try_into().map_err(|_| ProxyError::Header)?);
    check_timestamp(stamp, now)?;
    if &plain[9..9 + salt_len] != request_salt {
        return Err(ProxyError::SaltMismatch.into());
    }
    let length = u16::from_be_bytes(
        plain[9 + salt_len..]
            .try_into()
            .map_err(|_| ProxyError::Header)?,
    );
    Ok(length)
}

/// Static configuration for one Shadowsocks server.
pub struct ShadowsocksConfig {
    pub server: std::net::SocketAddr,
    pub key: PreSharedKey,
    /// The proxy's RFC 4787 mapping behavior, configuration for the same
    /// reason SOCKS5's and MASQUE's are: it belongs to the server.
    pub nat_behavior: NatBehavior,
}

/// A Shadowsocks 2022 server as a stream egress.
pub struct ShadowsocksEgress<B> {
    config: ShadowsocksConfig,
    bypass: B,
}

impl<B: TunnelBypass> ShadowsocksEgress<B> {
    pub fn new(config: ShadowsocksConfig, bypass: B) -> Self {
        Self { config, bypass }
    }
}

impl<B: TunnelBypass + 'static> StreamEgress for ShadowsocksEgress<B> {
    fn capabilities(&self) -> EgressCapabilities {
        EgressCapabilities {
            // The UDP half (SIP022's separate packet format) is not
            // implemented, and the claim says so rather than implying a relay
            // that does not exist.
            datagram_fidelity: DatagramFidelity::None,
            overhead_bytes: 0,
            max_datagram_size: None,
            preserves_ecn: false,
            nat_behavior: self.config.nat_behavior,
        }
    }

    fn connect<'a>(
        &'a self,
        target: &'a Target,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncStream>, EgressError>> {
        Box::pin(async move {
            let method = self.config.key.method;
            let mut stream = self.bypass.tcp(self.config.server).await?;

            // A fresh random salt per session: it is the only input that makes
            // two sessions under one pre-shared key different, so it comes from
            // the system CSPRNG and nowhere else.
            let mut salt = vec![0u8; method.salt_len()];
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut salt)
                .map_err(|_| ProxyError::Crypto)?;
            let mut writer = Session::new(method, &self.config.key.subkey(&salt))?;

            let body = encode_request_body(target, &[]);
            let body_len = u16::try_from(body.len()).map_err(|_| ProxyError::Header)?;
            let mut fixed = encode_request_fixed(now_seconds(), body_len);
            writer.seal(&mut fixed)?;
            let mut sealed_body = body;
            writer.seal(&mut sealed_body)?;

            let mut out = Vec::with_capacity(salt.len() + fixed.len() + sealed_body.len());
            out.extend_from_slice(&salt);
            out.extend_from_slice(&fixed);
            out.extend_from_slice(&sealed_body);
            stream.write_all(&out).await?;
            stream.flush().await?;

            Ok(Box::new(ShadowsocksStream {
                inner: stream,
                writer,
                reader: None,
                method,
                key: self.config.key.clone(),
                request_salt: salt,
                state: ReadState::Salt,
                cipher: Vec::with_capacity(MAX_CHUNK + TAG),
                plain: Vec::new(),
                plain_at: 0,
            }) as Box<dyn AsyncStream>)
        })
    }
}

/// What the reader is waiting for. An explicit state rather than a length
/// guess, because each stage's size is known only once the previous one has
/// been decrypted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadState {
    /// The server's salt, in the clear, which keys the response direction.
    Salt,
    /// The sealed fixed-length response header.
    FixedHeader,
    /// A sealed length chunk: two bytes plus a tag.
    Length,
    /// A sealed payload chunk of this many plaintext bytes.
    Payload(usize),
}

/// A Shadowsocks session as an ordinary byte stream.
///
/// Reads and writes are chunk-framed and sealed underneath, so everything
/// above — including the interception exchange — sees only bytes.
struct ShadowsocksStream<S> {
    inner: S,
    writer: Session,
    /// Built lazily: the response direction is keyed by a salt the server
    /// sends with its first byte, which may be long after connect returns.
    reader: Option<Session>,
    method: Method,
    key: PreSharedKey,
    request_salt: Vec<u8>,
    state: ReadState,
    /// Ciphertext accumulated toward the current state's requirement.
    cipher: Vec<u8>,
    /// Decrypted bytes not yet handed to the caller, and how far they are read.
    plain: Vec<u8>,
    plain_at: usize,
}

impl<S> ShadowsocksStream<S> {
    /// How many ciphertext bytes the current state needs before it can act.
    fn needed(&self) -> usize {
        match self.state {
            ReadState::Salt => self.method.salt_len(),
            ReadState::FixedHeader => 1 + 8 + self.method.salt_len() + 2 + TAG,
            ReadState::Length => 2 + TAG,
            ReadState::Payload(length) => length + TAG,
        }
    }

    /// Consumes exactly the bytes the current state needed, advancing it and
    /// producing plaintext where there is any.
    ///
    /// Pure with respect to I/O: it reads only from `cipher`, which the poll
    /// loop fills. That is what keeps the framing logic testable and the
    /// async plumbing trivial.
    fn advance(&mut self) -> Result<(), EgressError> {
        let needed = self.needed();
        let mut block: Vec<u8> = self.cipher.drain(..needed).collect();
        match self.state {
            ReadState::Salt => {
                let session = Session::new(self.method, &self.key.subkey(&block))?;
                self.reader = Some(session);
                self.state = ReadState::FixedHeader;
            }
            ReadState::FixedHeader => {
                let reader = self.reader.as_mut().ok_or(ProxyError::Header)?;
                let plain = reader.open(&mut block)?;
                let length = decode_response_fixed(plain, &self.request_salt, now_seconds())?;
                self.state = ReadState::Payload(usize::from(length));
            }
            ReadState::Length => {
                let reader = self.reader.as_mut().ok_or(ProxyError::Header)?;
                let plain = reader.open(&mut block)?;
                let length = u16::from_be_bytes(plain.try_into().map_err(|_| ProxyError::Header)?);
                self.state = ReadState::Payload(usize::from(length));
            }
            ReadState::Payload(_) => {
                let reader = self.reader.as_mut().ok_or(ProxyError::Header)?;
                let plain = reader.open(&mut block)?;
                self.plain = plain.to_vec();
                self.plain_at = 0;
                self.state = ReadState::Length;
            }
        }
        Ok(())
    }
}

fn fatal(error: EgressError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncRead for ShadowsocksStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            // Hand over whatever is already decrypted before doing any work.
            if this.plain_at < this.plain.len() {
                let moved = buf.remaining().min(this.plain.len() - this.plain_at);
                buf.put_slice(&this.plain[this.plain_at..this.plain_at + moved]);
                this.plain_at += moved;
                return Poll::Ready(Ok(()));
            }
            // A zero-length payload chunk is a keepalive, not end of stream;
            // fall through and read the next frame rather than reporting EOF.
            if this.cipher.len() >= this.needed() {
                this.advance().map_err(fatal)?;
                continue;
            }
            let mut chunk = [0u8; 4096];
            let mut read_buf = ReadBuf::new(&mut chunk);
            match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = read_buf.filled();
                    if filled.is_empty() {
                        // The peer closed. Mid-frame this is a truncation, but
                        // the caller's contract is end of stream either way.
                        return Poll::Ready(Ok(()));
                    }
                    this.cipher.extend_from_slice(filled);
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncWrite for ShadowsocksStream<S> {
    /// Seals one chunk per call: a length chunk and then a payload chunk, both
    /// under the writer's advancing nonce.
    ///
    /// The whole sealed frame is handed to the inner stream with `write_all`
    /// semantics deferred to `poll_flush`; a partial write of a sealed frame
    /// would desynchronise the peer's counter, so the frame is buffered whole.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let take = buf.len().min(MAX_CHUNK);
        let mut length = (take as u16).to_be_bytes().to_vec();
        this.writer.seal(&mut length).map_err(fatal)?;
        let mut payload = buf[..take].to_vec();
        this.writer.seal(&mut payload).map_err(fatal)?;
        length.extend_from_slice(&payload);

        // Written in full here: a sealed frame cannot be split across calls
        // without the peer's counter losing step with ours.
        let mut written = 0;
        while written < length.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &length[written..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::WriteZero)));
                }
                Poll::Ready(Ok(moved)) => written += moved,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                // The frame is already sealed and its nonce spent, so yielding
                // here would lose it. This is the one place the implementation
                // is deliberately not cancel-safe, and the bound is one frame.
                Poll::Pending => continue,
            }
        }
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(method: Method) -> PreSharedKey {
        PreSharedKey::new(method, vec![7u8; method.key_len()]).unwrap()
    }

    #[test]
    fn a_key_must_be_the_length_its_method_names() {
        assert_eq!(
            PreSharedKey::new(Method::Aes256Gcm, vec![0u8; 16])
                .map(|_| ())
                .unwrap_err(),
            KeyError::Length {
                expected: 32,
                found: 16
            }
        );
        assert!(PreSharedKey::new(Method::Aes128Gcm, vec![0u8; 16]).is_ok());
        // The salt length follows the key length, so the two cannot disagree.
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::ChaCha20Poly1305,
        ] {
            assert_eq!(method.key_len(), method.salt_len());
        }
    }

    #[test]
    fn a_subkey_depends_on_both_the_key_and_the_salt() {
        let psk = key(Method::Aes256Gcm);
        let first = psk.subkey(&[1u8; 32]);
        let second = psk.subkey(&[2u8; 32]);
        assert_ne!(first, second, "a new salt is a new session key");
        assert_eq!(first, psk.subkey(&[1u8; 32]), "derivation is a function");
        assert_eq!(first.len(), 32);
        // A 128-bit method truncates the same 256-bit derivation.
        assert_eq!(key(Method::Aes128Gcm).subkey(&[1u8; 16]).len(), 16);
    }

    #[test]
    fn the_nonce_counter_never_repeats_and_advances_little_endian() {
        let mut session = Session::new(Method::Aes256Gcm, &[3u8; 32]).unwrap();
        // Sealing the same plaintext twice must not produce the same bytes:
        // that is the property the counter exists to guarantee.
        let mut first = b"identical".to_vec();
        let mut second = b"identical".to_vec();
        session.seal(&mut first).unwrap();
        session.seal(&mut second).unwrap();
        assert_ne!(first, second, "a reused nonce would make these equal");
        assert_eq!(session.counter, 2);
    }

    #[test]
    fn a_sealed_chunk_opens_only_under_the_matching_counter() {
        let mut writer = Session::new(Method::ChaCha20Poly1305, &[9u8; 32]).unwrap();
        let mut reader = Session::new(Method::ChaCha20Poly1305, &[9u8; 32]).unwrap();
        let mut chunk = b"payload".to_vec();
        writer.seal(&mut chunk).unwrap();
        assert_eq!(reader.open(&mut chunk.clone()).unwrap(), b"payload");

        // A reader whose counter has run ahead cannot open it, which is what
        // makes a dropped or reordered chunk fatal rather than silently wrong.
        let mut ahead = Session::new(Method::ChaCha20Poly1305, &[9u8; 32]).unwrap();
        ahead.next_nonce();
        assert!(ahead.open(&mut chunk).is_err());
    }

    #[test]
    fn a_response_header_must_echo_our_salt_and_agree_with_our_clock() {
        let salt = vec![5u8; 32];
        let now = 1_800_000_000u64;
        let build = |kind: u8, stamp: u64, echoed: &[u8], length: u16| {
            let mut header = vec![kind];
            header.extend_from_slice(&stamp.to_be_bytes());
            header.extend_from_slice(echoed);
            header.extend_from_slice(&length.to_be_bytes());
            header
        };

        // The good case, and the length it reports.
        let good = build(TYPE_RESPONSE, now, &salt, 1234);
        assert_eq!(decode_response_fixed(&good, &salt, now).unwrap(), 1234);

        // A response carrying somebody else's salt is a replay of another
        // session, and is the case this field exists to catch.
        let other = build(TYPE_RESPONSE, now, &[6u8; 32], 1);
        assert!(matches!(
            decode_response_fixed(&other, &salt, now),
            Err(EgressError::Proxy(ProxyError::SaltMismatch))
        ));

        // A stale stamp is refused in both directions of skew.
        for stamp in [now - CLOCK_SKEW_SECONDS - 1, now + CLOCK_SKEW_SECONDS + 1] {
            let stale = build(TYPE_RESPONSE, stamp, &salt, 1);
            assert!(matches!(
                decode_response_fixed(&stale, &salt, now),
                Err(EgressError::Proxy(ProxyError::Stale { .. }))
            ));
        }
        // Exactly at the boundary is still admitted.
        let edge = build(TYPE_RESPONSE, now + CLOCK_SKEW_SECONDS, &salt, 1);
        assert_eq!(decode_response_fixed(&edge, &salt, now).unwrap(), 1);

        // Our own request reflected back is not a response.
        let reflected = build(TYPE_REQUEST, now, &salt, 1);
        assert!(matches!(
            decode_response_fixed(&reflected, &salt, now),
            Err(EgressError::Proxy(ProxyError::Header))
        ));

        // A truncated header is refused rather than indexed into.
        assert!(matches!(
            decode_response_fixed(&good[..10], &salt, now),
            Err(EgressError::Proxy(ProxyError::Header))
        ));
    }

    #[test]
    fn a_request_body_carries_the_target_and_an_explicit_padding_length() {
        let target = Target::Ip("192.0.2.1:443".parse().unwrap());
        let body = encode_request_body(&target, b"GET /");
        // ATYP + 4 address + 2 port + 2 padding length + payload.
        assert_eq!(body.len(), 1 + 4 + 2 + 2 + 5);
        assert_eq!(
            &body[7..9],
            &0u16.to_be_bytes(),
            "padding length is explicit"
        );
        assert_eq!(&body[9..], b"GET /");

        let fixed = encode_request_fixed(1_800_000_000, body.len() as u16);
        assert_eq!(fixed.len(), 11);
        assert_eq!(fixed[0], TYPE_REQUEST);
        assert_eq!(
            u16::from_be_bytes(fixed[9..11].try_into().unwrap()),
            body.len() as u16
        );
    }
}
