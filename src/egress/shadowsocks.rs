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
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::SecureRandom,
};
use tokio::io::AsyncWriteExt;

use crate::{
    Association, AsyncStream, BoxFuture, Codec, DatagramFidelity, DatagramSink, DatagramSource,
    Decode, Decoded, EgressError, Framed, NatBehavior, PathProperties, ProxyError, StreamEgress,
    Target, TunnelBypass, decode_address, encode_address,
    wire::{Reader, Writer},
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
    /// The key material itself. Crate-private: the one legitimate reader is
    /// the packet cipher, whose AES methods key their separate-header block on
    /// the pre-shared key directly rather than on anything derived.
    fn raw(&self) -> &[u8] {
        &self.bytes
    }

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
    fn new(method: Method, subkey: &[u8]) -> Result<Self, ProxyError> {
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
    fn seal(&mut self, buf: &mut Vec<u8>) -> Result<(), ProxyError> {
        let nonce = self.next_nonce();
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), buf)
            .map_err(|_| ProxyError::Crypto)?;
        Ok(())
    }

    /// Opens in place, returning the plaintext. A failure here is an
    /// authentication failure and is fatal to the stream: there is no way to
    /// resynchronise a counter-based AEAD after one.
    fn open<'a>(&mut self, buf: &'a mut [u8]) -> Result<&'a [u8], ProxyError> {
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
fn check_timestamp(theirs: u64, ours: u64) -> Result<(), ProxyError> {
    let skew = ours.abs_diff(theirs);
    if skew > CLOCK_SKEW_SECONDS {
        return Err(ProxyError::Stale { skew });
    }
    Ok(())
}

/// The largest padding SIP022 permits in a request header.
const MAX_PADDING: usize = 900;

/// Builds the variable-length request header: target, padding, then whatever
/// payload rides along with it.
///
/// **A request must carry padding or an initial payload, and may not be empty
/// of both.** SIP022 requires it and a reference server rejects the violation
/// outright with "missing payload or padding": with neither, the header's
/// encrypted length would leak the address length exactly, which is what the
/// padding is there to blur. The caller supplies the padding bytes rather than
/// this function generating them, so the encoder stays pure and the randomness
/// stays at the one boundary that performs effects.
fn encode_request_body(target: &Target, padding: &[u8], initial: &[u8]) -> Vec<u8> {
    debug_assert!(
        !padding.is_empty() || !initial.is_empty(),
        "SIP022 forbids a request with neither padding nor payload"
    );
    debug_assert!(padding.len() <= MAX_PADDING);
    let mut body = Vec::with_capacity(initial.len() + padding.len() + 32);
    encode_address(target, &mut body);
    Writer::new(&mut body).vector_u16(padding).bytes(initial);
    body
}

/// The fixed-length request header: type, timestamp, and the length of the
/// variable-length header that follows it.
fn encode_request_fixed(now: u64, body_len: u16) -> Vec<u8> {
    let mut header = Vec::with_capacity(11);
    Writer::new(&mut header)
        .u8(TYPE_REQUEST)
        .u64(now)
        .u16(body_len);
    header
}

/// Reads the fixed-length response header, checking everything it asserts:
/// that it is a response, that its clock agrees with ours, and that it echoes
/// the salt of *our* request rather than some other session's.
///
/// The salt echo is what makes a replayed response detectable, so verifying it
/// is not optional politeness — it is the property the field exists for.
fn decode_response_fixed(plain: &[u8], request_salt: &[u8], now: u64) -> Result<u16, ProxyError> {
    // An exact length, not a minimum: this header is opened from a block whose
    // size the state machine already chose, so a different size is a framing
    // error rather than a short read.
    if plain.len() != 1 + 8 + request_salt.len() + 2 {
        return Err(ProxyError::Header);
    }
    let mut reader = Reader::new(plain);
    let (Some(TYPE_RESPONSE), Some(stamp)) = (reader.u8(), reader.u64()) else {
        return Err(ProxyError::Header);
    };
    check_timestamp(stamp, now)?;
    if reader.take(request_salt.len()) != Some(request_salt) {
        return Err(ProxyError::SaltMismatch);
    }
    reader.u16().ok_or(ProxyError::Header)
}

/// Static configuration for one Shadowsocks server.
pub struct ShadowsocksConfig {
    pub server: std::net::SocketAddr,
    pub key: PreSharedKey,
    /// The proxy's RFC 4787 mapping behavior, configuration for the same
    /// reason SOCKS5's and MASQUE's are: it belongs to the server.
    pub nat_behavior: NatBehavior,
}

// -------------------------------------------------------- SIP022 UDP

/// **SIP022's packet format is a second construction, not a variation of the
/// stream one.** A stream is salt-then-chunks under one derived key with a
/// counter nonce; a packet stands alone, so it carries its own key material and
/// its own nonce, and the two AES methods and the ChaCha method do that
/// *differently*. Modelling them as one format with flags is how a client ends
/// up deriving a subkey for a method that has none.
///
/// The AES methods put an 8-byte session ID and an 8-byte packet ID in a
/// 16-byte *separate header*, encrypt it as a single AES-ECB block under the
/// pre-shared key itself, and derive the body's subkey from the session ID. The
/// ChaCha method has no separate header at all: a random 24-byte XChaCha20
/// nonce goes in front, the body is keyed by the pre-shared key directly, and
/// the session and packet IDs move *inside* the encrypted body.
///
/// Both come from BoringSSL, which is already linked for every hello this crate
/// sends: `ring` exposes neither a raw AES block nor XChaCha20-Poly1305, and
/// neither is a thing to hand-roll.
enum PacketCipher {
    /// The AES methods. `header` is keyed by the pre-shared key and used one
    /// block at a time with padding off, which is the only correct way to use
    /// ECB and is why it appears nowhere else.
    Separate {
        key: PreSharedKey,
        header: boring::symm::Cipher,
    },
    /// `2022-blake3-chacha20-poly1305`. One context for the association's life,
    /// because the key never changes: it is the pre-shared key.
    Merged { key: boring::aead::AeadCtx },
}

/// Bytes of the AES methods' separate header.
const SEPARATE_HEADER: usize = 16;

/// The AEAD nonce is a window over the plaintext separate header rather than a
/// field of its own: the last four bytes of the session ID followed by the
/// whole packet ID. Uniqueness therefore comes from the packet counter, which
/// is what makes the counter's discipline load-bearing.
const NONCE_WINDOW: std::ops::Range<usize> = 4..SEPARATE_HEADER;

/// XChaCha20-Poly1305's nonce, written in the clear ahead of the body.
const MERGED_NONCE: usize = 24;

/// Packet types, the packet-format counterparts of [`TYPE_REQUEST`] and
/// [`TYPE_RESPONSE`]. Separate constants because they are a separate namespace
/// in the specification, even though they happen to agree.
const PACKET_TO_SERVER: u8 = 0;
const PACKET_TO_CLIENT: u8 = 1;

/// The largest UDP payload a datagram can carry, which sizes the receive buffer
/// exactly: nothing larger can arrive, so a payload this cannot hold does not
/// exist.
const MAX_UDP_PAYLOAD: usize = u16::MAX as usize;

/// The largest client datagram this egress will carry, and therefore what the
/// planner budgets QUIC against.
///
/// It is the IPv6 minimum path less the worst case this format adds: the
/// separate header or nonce, the tag, the fixed message header, and the largest
/// address SIP022 can express. Deliberately the *worst* case rather than the
/// one a given target happens to cost, because the number is a promise made
/// once per session and a flow must not discover mid-transfer that its
/// destination's name was long.
const MAX_PROXIED_DATAGRAM: u16 = {
    // nonce or separate header, tag, type, timestamp, padding length
    let framing = MERGED_NONCE + TAG + 1 + 8 + 2;
    // domain form: type byte, length octet, 255 bytes of name, port
    let address = 1 + 1 + 255 + 2;
    (crate::MIN_IPV6_MTU as usize - 48 - framing - address) as u16
};

/// One packet's plaintext, after whichever framing its method used has been
/// removed. Both constructions produce exactly this, which is what lets
/// everything above them be written once.
struct Opened {
    session: [u8; 8],
    packet_id: u64,
    /// The message proper, starting at its type byte.
    message: Vec<u8>,
}

impl PacketCipher {
    fn new(key: &PreSharedKey) -> Result<Self, EgressError> {
        Ok(match key.method {
            Method::Aes128Gcm => Self::Separate {
                key: key.clone(),
                header: boring::symm::Cipher::aes_128_ecb(),
            },
            Method::Aes256Gcm => Self::Separate {
                key: key.clone(),
                header: boring::symm::Cipher::aes_256_ecb(),
            },
            Method::ChaCha20Poly1305 => Self::Merged {
                key: boring::aead::AeadCtx::new_default_tag(
                    &boring::aead::Algorithm::xchacha20_poly1305(),
                    key.raw(),
                )
                .map_err(|_| ProxyError::Crypto)?,
            },
        })
    }

    /// Seals one packet for the server.
    ///
    /// O(message length), with one allocation for the datagram the caller is
    /// about to hand to the socket.
    fn seal(
        &self,
        session: [u8; 8],
        packet_id: u64,
        message: &[u8],
    ) -> Result<Vec<u8>, EgressError> {
        let mut identity = [0u8; SEPARATE_HEADER];
        identity[..8].copy_from_slice(&session);
        identity[8..].copy_from_slice(&packet_id.to_be_bytes());

        match self {
            Self::Separate { .. } => {
                let sealed = self.aead(&session)?;
                let mut out = self.block(boring::symm::Mode::Encrypt, &identity)?;
                out.extend_from_slice(message);
                let tag =
                    Self::finish(&sealed, &identity[NONCE_WINDOW], &mut out, SEPARATE_HEADER)?;
                out.extend_from_slice(&tag);
                Ok(out)
            }
            Self::Merged { key } => {
                let mut out = vec![0u8; MERGED_NONCE];
                random(&mut out)?;
                let nonce: [u8; MERGED_NONCE] = out[..].try_into().expect("just sized");
                // The identity is inside the body here, not ahead of it.
                out.extend_from_slice(&identity);
                out.extend_from_slice(message);
                let tag = Self::finish(key, &nonce, &mut out, MERGED_NONCE)?;
                out.extend_from_slice(&tag);
                Ok(out)
            }
        }
    }

    /// Opens one packet from the server.
    ///
    /// Nothing here trusts anything: the identity is read, the body is
    /// authenticated under a key derived from it, and only then does a caller
    /// see a byte of it. A forged identity yields a key that opens nothing.
    fn open(&self, datagram: &[u8]) -> Result<Opened, EgressError> {
        let (identity, key, nonce, body) = match self {
            Self::Separate { .. } => {
                let (header, body) = datagram
                    .split_at_checked(SEPARATE_HEADER)
                    .ok_or(ProxyError::Header)?;
                let identity = self.block(boring::symm::Mode::Decrypt, header)?;
                let nonce = identity[NONCE_WINDOW].to_vec();
                let key = self.aead(&identity[..8])?;
                (identity, key, nonce, body.to_vec())
            }
            Self::Merged { key } => {
                let (nonce, body) = datagram
                    .split_at_checked(MERGED_NONCE)
                    .ok_or(ProxyError::Header)?;
                let mut plain = Self::reveal(key, nonce, body.to_vec())?;
                if plain.len() < SEPARATE_HEADER {
                    return Err(ProxyError::Header.into());
                }
                let identity = plain[..SEPARATE_HEADER].to_vec();
                plain.drain(..SEPARATE_HEADER);
                return Ok(Self::identify(&identity, plain));
            }
        };
        let message = Self::reveal(&key, &nonce, body)?;
        Ok(Self::identify(&identity, message))
    }

    /// Splits a `SEPARATE_HEADER`-sized identity into its session and packet
    /// id. Every caller has already sized `identity`, so a short one is a
    /// defect here rather than something a peer can send.
    fn identify(identity: &[u8], message: Vec<u8>) -> Opened {
        let mut reader = Reader::new(identity);
        let (Some(session), Some(packet_id)) = (reader.array::<8>(), reader.u64()) else {
            unreachable!("identify is only reached with a {SEPARATE_HEADER}-byte identity");
        };
        Opened {
            session: *session,
            packet_id,
            message,
        }
    }

    /// Seals `out[at..]` in place and returns the tag to append. Split out
    /// because both constructions seal the same way once they have agreed on a
    /// key and a nonce, and only the framing around it differs.
    fn finish(
        key: &boring::aead::AeadCtx,
        nonce: &[u8],
        out: &mut [u8],
        at: usize,
    ) -> Result<Vec<u8>, EgressError> {
        let mut tag = vec![0u8; TAG];
        key.seal_in_place(nonce, &mut out[at..], &mut tag, &[])
            .map_err(|_| ProxyError::Crypto)?;
        Ok(tag)
    }

    fn reveal(
        key: &boring::aead::AeadCtx,
        nonce: &[u8],
        mut body: Vec<u8>,
    ) -> Result<Vec<u8>, EgressError> {
        let at = body.len().checked_sub(TAG).ok_or(ProxyError::Header)?;
        let tag = body.split_off(at);
        key.open_in_place(nonce, &mut body, &tag, &[])
            .map_err(|_| ProxyError::Crypto)?;
        Ok(body)
    }

    /// The AEAD context for one AES-method session. The subkey is derived from
    /// the session ID exactly as the stream side derives its own from the salt,
    /// which is why one `subkey` serves both.
    fn aead(&self, session: &[u8]) -> Result<boring::aead::AeadCtx, EgressError> {
        let Self::Separate { key, .. } = self else {
            return Err(ProxyError::Crypto.into());
        };
        let algorithm = match key.method {
            Method::Aes128Gcm => boring::aead::Algorithm::aes_128_gcm(),
            _ => boring::aead::Algorithm::aes_256_gcm(),
        };
        boring::aead::AeadCtx::new_default_tag(&algorithm, &key.subkey(session))
            .map_err(|_| ProxyError::Crypto.into())
    }

    /// One ECB block, padding off. `Crypter` rather than `symm::encrypt`
    /// because the latter pads to a second block, and a 32-byte separate header
    /// is not a separate header.
    fn block(&self, mode: boring::symm::Mode, input: &[u8]) -> Result<Vec<u8>, EgressError> {
        let Self::Separate { key, header } = self else {
            return Err(ProxyError::Crypto.into());
        };
        let mut crypter = boring::symm::Crypter::new(*header, mode, key.raw(), None)
            .map_err(|_| ProxyError::Crypto)?;
        crypter.pad(false);
        let mut out = vec![0u8; input.len() + header.block_size()];
        let written = crypter
            .update(input, &mut out)
            .map_err(|_| ProxyError::Crypto)?;
        let extra = crypter
            .finalize(&mut out[written..])
            .map_err(|_| ProxyError::Crypto)?;
        out.truncate(written + extra);
        Ok(out)
    }
}

/// Fills `bytes` from the system CSPRNG and nowhere else.
fn random(bytes: &mut [u8]) -> Result<(), EgressError> {
    ring::rand::SystemRandom::new()
        .fill(bytes)
        .map_err(|_| ProxyError::Crypto)?;
    Ok(())
}

/// Builds one client-to-server message: type, timestamp, padding, target
/// address, payload.
///
/// **Padding is a policy, and this one is the reference implementations'.**
/// Both `shadowsocks-go` and `sing-shadowsocks` pad only queries to port 53,
/// where a datagram's length otherwise leaks which name was asked for; padding
/// everything would cost bandwidth on a phone for no distinguishability that
/// TLS has not already provided. The length is `1 + rand % 900`, matching their
/// `MaxPaddingLength`.
///
/// O(payload length), one allocation.
fn encode_packet_request(
    target: &Target,
    now: u64,
    payload: &[u8],
) -> Result<Vec<u8>, EgressError> {
    let pad = padding_for(target)?;
    let mut out = Vec::with_capacity(11 + pad.len() + 22 + payload.len());
    Writer::new(&mut out)
        .u8(PACKET_TO_SERVER)
        .u64(now)
        .vector_u16(&pad);
    encode_address(target, &mut out);
    Writer::new(&mut out).bytes(payload);
    Ok(out)
}

fn padding_for(target: &Target) -> Result<Vec<u8>, EgressError> {
    if target.port() != crate::DNS_PORT {
        return Ok(Vec::new());
    }
    let mut pick = [0u8; 2];
    random(&mut pick)?;
    let mut pad = vec![0u8; 1 + usize::from(u16::from_be_bytes(pick)) % MAX_PADDING];
    random(&mut pad)?;
    Ok(pad)
}

/// Reads one server-to-client message, returning where the reply came from and
/// where its payload starts.
///
/// Three checks, all of them MUST-level in SIP022 and each closing a different
/// hole: the type byte stops a reflected request from being read as a response,
/// the clock bounds the replay window to 30 seconds, and the echoed client
/// session ID stops another client's reply being delivered to this one.
///
/// O(address length). Total on untrusted input.
fn decode_packet_response(
    message: &[u8],
    client_session: &[u8; 8],
    now: u64,
) -> Result<(Target, usize), EgressError> {
    // type(1) + timestamp(8) + client session(8) + padding
    let mut reader = Reader::new(message);
    let (Some(PACKET_TO_CLIENT), Some(stamp), Some(session)) =
        (reader.u8(), reader.u64(), reader.array::<8>())
    else {
        return Err(ProxyError::Header.into());
    };
    check_timestamp(stamp, now)?;
    if session != client_session {
        return Err(ProxyError::SaltMismatch.into());
    }
    if reader.vector_u16().is_none() {
        return Err(ProxyError::Header.into());
    }
    let at = reader.position();
    match decode_address(reader.rest())? {
        Decoded::Complete { value, consumed } => Ok((value, at + consumed)),
        Decoded::Incomplete => Err(ProxyError::Header.into()),
    }
}

/// A sliding window over one server session's packet IDs, in WireGuard's shape:
/// the highest identifier seen and a bitmap of the 64 below it.
///
/// SIP022 requires one — a relay whose replies can be replayed is a relay whose
/// client can be made to re-process an old answer — and points at WireGuard's
/// as a usable implementation. Sixty-four is ample for a UDP association: a
/// reply reordered by more than that many packets is one the transport above
/// has already given up on.
///
/// O(1) per packet, and no allocation ever.
#[derive(Default)]
struct Window {
    /// `None` until the first packet, because **SIP022 starts a packet counter
    /// at zero**: a bare `u64` high-water mark would make the very first
    /// legitimate packet indistinguishable from a replay of itself.
    highest: Option<u64>,
    below: u64,
}

impl Window {
    /// Whether `id` is fresh, recording it when it is.
    ///
    /// **Called only after the packet has authenticated**, which is SIP022's
    /// own rule: advancing on an unauthenticated identifier would let anyone
    /// who can guess a session ID push the window past every real packet.
    fn admit(&mut self, id: u64) -> bool {
        let Some(highest) = self.highest else {
            self.highest = Some(id);
            return true;
        };
        let Some(behind) = highest.checked_sub(id) else {
            // Ahead of everything seen: shift the bitmap by the gap, then mark
            // the old high-water mark as seen. A gap of 64 or more leaves
            // nothing of the old window inside the new one, so it starts empty.
            let gap = id - highest;
            self.below = if gap < 64 {
                (self.below << gap) | (1 << (gap - 1))
            } else {
                0
            };
            self.highest = Some(id);
            return true;
        };
        if behind == 0 || behind > 64 {
            return false;
        }
        let bit = 1u64 << (behind - 1);
        if self.below & bit != 0 {
            return false;
        }
        self.below |= bit;
        true
    }
}

/// One SIP022 datagram association: a socket to the server, the session this
/// client speaks under, and the counter that must never repeat against it.
///
/// The counter and the key live together for the reason the stream side's do:
/// the AEAD nonce is a window over the packet identifier, so a repeated
/// identifier is a repeated nonce, which is total loss of confidentiality.
struct PacketRelay {
    socket: tokio::net::UdpSocket,
    cipher: PacketCipher,
    session: [u8; 8],
    /// SIP022 starts at zero and adds one per packet sent. Atomic because the
    /// sink is shared by every flow in the mapping and `send_to` takes `&self`.
    next: std::sync::atomic::AtomicU64,
}

impl DatagramSink for PacketRelay {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        target: &'a Target,
    ) -> BoxFuture<'a, Result<(), EgressError>> {
        Box::pin(async move {
            let message = encode_packet_request(target, now_seconds(), payload)?;
            let packet_id = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let datagram = self.cipher.seal(self.session, packet_id, &message)?;
            self.socket.send(&datagram).await?;
            Ok(())
        })
    }
}

/// The receiving half, and the state that makes a reply believable.
struct PacketSource {
    relay: Arc<PacketRelay>,
    /// **Two server sessions, not one.** SIP022 requires a client to survive a
    /// server restart, which changes the server's session ID mid-association;
    /// it permits keeping exactly the current one and one predecessor, which is
    /// what this is. A third would be a cache with an eviction policy for a set
    /// that never exceeds two.
    sessions: [Option<([u8; 8], Window)>; 2],
    /// One receive buffer for the association's life, sized so that nothing a
    /// UDP datagram can carry is ever truncated.
    framed: Vec<u8>,
}

impl PacketSource {
    /// The window for `session`, admitting it as the current one if it is new
    /// and retiring whatever was oldest.
    fn window(&mut self, session: [u8; 8]) -> &mut Window {
        if let Some(at) = self
            .sessions
            .iter()
            .position(|held| held.as_ref().is_some_and(|(id, _)| *id == session))
        {
            return &mut self.sessions[at].as_mut().expect("just found").1;
        }
        self.sessions.swap(0, 1);
        self.sessions[0] = Some((session, Window::default()));
        &mut self.sessions[0].as_mut().expect("just written").1
    }
}

impl DatagramSource for PacketSource {
    fn recv_from<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<(usize, Target), EgressError>> {
        Box::pin(async move {
            loop {
                let read = self.relay.socket.recv(&mut self.framed).await?;
                // **A bad packet is skipped, never fatal.** Anything can send to
                // a UDP socket, so a datagram that will not open is noise on a
                // public port rather than a failure of this association.
                let Ok(opened) = self.relay.cipher.open(&self.framed[..read]) else {
                    continue;
                };
                let Ok((from, at)) =
                    decode_packet_response(&opened.message, &self.relay.session, now_seconds())
                else {
                    continue;
                };
                // Only now, with the packet authenticated and its header
                // validated, may the window move.
                if !self.window(opened.session).admit(opened.packet_id) {
                    continue;
                }
                let payload = &opened.message[at..];
                let Some(into) = buf.get_mut(..payload.len()) else {
                    return Err(EgressError::DatagramTooLarge {
                        required: payload.len(),
                    });
                };
                into.copy_from_slice(payload);
                return Ok((payload.len(), from));
            }
        })
    }
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
    fn properties(&self) -> PathProperties {
        PathProperties {
            // **Native, and the packet format is why.** SIP022 carries one
            // client datagram as one server datagram with its own address
            // inside, so a boundary crosses intact and one association serves
            // every peer -- which is what makes QUIC survive this egress rather
            // than be steered off it.
            datagram_fidelity: DatagramFidelity::Native,
            // A datagram is re-originated by the server, so the client's own
            // packet size stops existing at the proxy and there is no
            // per-packet header for the *client's* path to charge for. What the
            // framing costs is charged in `max_datagram_size` instead, which is
            // the budget that actually binds.
            overhead_bytes: 0,
            max_datagram_size: Some(MAX_PROXIED_DATAGRAM),
            preserves_ecn: false,
            nat_behavior: self.config.nat_behavior,
        }
    }

    /// Opens the datagram half: one socket to the server, one client session,
    /// and the counter that must never repeat against it.
    ///
    /// **No handshake, which is the point of the format.** Unlike SOCKS5's UDP
    /// ASSOCIATE there is no control connection whose lifetime bounds this one
    /// and no relay address to be told; the first packet establishes the
    /// session by carrying its identifier, so an association costs one socket
    /// and one round of randomness.
    fn associate(&self) -> BoxFuture<'_, Result<Association, EgressError>> {
        Box::pin(async move {
            let socket = self.bypass.udp(self.config.server).await?;
            let mut session = [0u8; 8];
            // SIP022: "the server session ID MUST be randomly generated", and
            // the client's likewise -- it is the salt every packet key on this
            // association is derived from.
            random(&mut session)?;
            let relay = Arc::new(PacketRelay {
                socket,
                cipher: PacketCipher::new(&self.config.key)?,
                session,
                next: std::sync::atomic::AtomicU64::new(0),
            });
            Ok(Association {
                source: Box::new(PacketSource {
                    relay: Arc::clone(&relay),
                    sessions: [None, None],
                    framed: vec![0u8; MAX_UDP_PAYLOAD],
                }),
                sink: relay,
            })
        })
    }

    fn connect<'a>(
        &'a self,
        target: &'a Target,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncStream>, EgressError>> {
        Box::pin(async move {
            let method = self.config.key.method;
            let mut stream =
                crate::within(crate::Wait::TcpConnect, self.bypass.tcp(self.config.server)).await?;

            // A fresh random salt per session: it is the only input that makes
            // two sessions under one pre-shared key different, so it comes from
            // the system CSPRNG and nowhere else.
            let random = ring::rand::SystemRandom::new();
            let mut salt = vec![0u8; method.salt_len()];
            random.fill(&mut salt).map_err(|_| ProxyError::Crypto)?;
            let mut writer = Session::new(method, &self.config.key.subkey(&salt))?;

            // No initial payload here — `connect` returns before the caller
            // has written anything — so padding is mandatory rather than
            // optional, and its length is randomised so the header's size
            // carries no information about the address inside it.
            let mut length_pick = [0u8; 2];
            random
                .fill(&mut length_pick)
                .map_err(|_| ProxyError::Crypto)?;
            let padding_len = 1 + usize::from(u16::from_be_bytes(length_pick)) % MAX_PADDING;
            let mut padding = vec![0u8; padding_len];
            random.fill(&mut padding).map_err(|_| ProxyError::Crypto)?;
            let body = encode_request_body(target, &padding, &[]);
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

            Ok(Box::new(Framed::new(
                stream,
                StreamCodec {
                    writer,
                    reader: None,
                    method,
                    key: self.config.key.clone(),
                    request_salt: salt,
                    state: ReadState::Salt,
                },
            )) as Box<dyn AsyncStream>)
        })
    }
}

/// What the reader is waiting for. See [`StreamCodec::needed`] for why this is
/// a state and not a length.
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

/// A Shadowsocks session's framing, as a pure codec.
///
/// **Everything below reads from a slice and writes to a sink.** The framing
/// logic was already almost pure — it read only from a buffer the poll loop
/// filled — and lifting the last of it out removed two defects with the loop it
/// replaced. One was a busy spin: the old writer looped on `Poll::Pending`
/// rather than yielding, because a sealed frame whose nonce is already spent
/// cannot be dropped and re-made, so it had nowhere to put one. [`Framed`] has
/// somewhere, and parks instead of burning a core until the socket drains.
struct StreamCodec {
    writer: Session,
    /// Built lazily: the response direction is keyed by a salt the server sends
    /// with its first byte, which may be long after connect returned.
    reader: Option<Session>,
    method: Method,
    key: PreSharedKey,
    request_salt: Vec<u8>,
    state: ReadState,
}

impl StreamCodec {
    /// How many ciphertext bytes the current state needs before it can act.
    ///
    /// **A state rather than a length guess**, because each stage's size is
    /// known only once the previous one has been decrypted.
    fn needed(&self) -> usize {
        match self.state {
            ReadState::Salt => self.method.salt_len(),
            ReadState::FixedHeader => 1 + 8 + self.method.salt_len() + 2 + TAG,
            ReadState::Length => 2 + TAG,
            ReadState::Payload(length) => length + TAG,
        }
    }
}

impl Codec for StreamCodec {
    /// O(chunk), with one copy of the sealed block because opening is in place
    /// and the input is borrowed.
    fn decode<'a>(&mut self, input: &'a [u8], out: &mut Vec<u8>) -> Result<Decode<'a>, ProxyError> {
        let needed = self.needed();
        let Some((block, rest)) = input.split_at_checked(needed) else {
            return Ok(Decode::Framed { rest: input });
        };
        let mut block = block.to_vec();
        match self.state {
            ReadState::Salt => {
                self.reader = Some(Session::new(self.method, &self.key.subkey(&block))?);
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
                let length = Reader::new(plain).u16().ok_or(ProxyError::Header)?;
                self.state = ReadState::Payload(usize::from(length));
            }
            ReadState::Payload(_) => {
                let reader = self.reader.as_mut().ok_or(ProxyError::Header)?;
                out.extend_from_slice(reader.open(&mut block)?);
                self.state = ReadState::Length;
            }
        }
        Ok(Decode::Framed { rest })
    }

    /// Seals one chunk: a length under the writer's nonce, then the payload
    /// under the next.
    ///
    /// O(payload). The two seals must reach the peer in this order and without
    /// anything between them, which is why the whole frame goes into one sink
    /// and [`Framed`] writes it whole.
    fn encode(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<(), ProxyError> {
        let mut length = Vec::with_capacity(2);
        Writer::new(&mut length).u16(payload.len() as u16);
        self.writer.seal(&mut length)?;
        let mut sealed = payload.to_vec();
        self.writer.seal(&mut sealed)?;
        Writer::new(out).bytes(&length).bytes(&sealed);
        Ok(())
    }

    /// The two-byte length field's ceiling. A caller writing more is split by
    /// the adapter rather than discovering the limit here.
    fn max_payload(&self) -> usize {
        MAX_CHUNK
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
            Err(ProxyError::SaltMismatch)
        ));

        // A stale stamp is refused in both directions of skew.
        for stamp in [now - CLOCK_SKEW_SECONDS - 1, now + CLOCK_SKEW_SECONDS + 1] {
            let stale = build(TYPE_RESPONSE, stamp, &salt, 1);
            assert!(matches!(
                decode_response_fixed(&stale, &salt, now),
                Err(ProxyError::Stale { .. })
            ));
        }
        // Exactly at the boundary is still admitted.
        let edge = build(TYPE_RESPONSE, now + CLOCK_SKEW_SECONDS, &salt, 1);
        assert_eq!(decode_response_fixed(&edge, &salt, now).unwrap(), 1);

        // Our own request reflected back is not a response.
        let reflected = build(TYPE_REQUEST, now, &salt, 1);
        assert!(matches!(
            decode_response_fixed(&reflected, &salt, now),
            Err(ProxyError::Header)
        ));

        // A truncated header is refused rather than indexed into.
        assert!(matches!(
            decode_response_fixed(&good[..10], &salt, now),
            Err(ProxyError::Header)
        ));
    }

    #[test]
    fn a_request_body_carries_the_target_and_an_explicit_padding_length() {
        let target = Target::Ip("192.0.2.1:443".parse().unwrap());
        // With an initial payload, no padding is required.
        let body = encode_request_body(&target, &[], b"GET /");
        // ATYP + 4 address + 2 port + 2 padding length + payload.
        assert_eq!(body.len(), 1 + 4 + 2 + 2 + 5);
        assert_eq!(
            &body[7..9],
            &0u16.to_be_bytes(),
            "padding length is explicit"
        );
        assert_eq!(&body[9..], b"GET /");

        // With no payload, padding carries SIP022's requirement instead, and
        // its length is declared where the reader expects it. A request with
        // neither is what the reference server rejects outright.
        let padded = encode_request_body(&target, &[0xab; 16], &[]);
        assert_eq!(&padded[7..9], &16u16.to_be_bytes());
        assert_eq!(padded.len(), 1 + 4 + 2 + 2 + 16);

        let fixed = encode_request_fixed(1_800_000_000, body.len() as u16);
        assert_eq!(fixed.len(), 11);
        assert_eq!(fixed[0], TYPE_REQUEST);
        assert_eq!(
            u16::from_be_bytes(fixed[9..11].try_into().unwrap()),
            body.len() as u16
        );
    }

    /// **A server written from the specification, not from the encoder above.**
    /// Round-tripping a codec against itself proves only that it is
    /// self-consistent; the thing that matters is agreeing with a peer, so this
    /// reads the bytes the way SIP022's field tables say to and answers the
    /// same way.
    fn spec_server_reply(
        key: &PreSharedKey,
        datagram: &[u8],
        from: &Target,
        payload: &[u8],
        server_session: [u8; 8],
        packet_id: u64,
    ) -> (Vec<u8>, Target, Vec<u8>) {
        use boring::{
            aead::{AeadCtx, Algorithm},
            symm::{Cipher, Crypter, Mode},
        };

        let aes = matches!(key.method, Method::Aes128Gcm | Method::Aes256Gcm);
        let algorithm = match key.method {
            Method::Aes128Gcm => Algorithm::aes_128_gcm(),
            Method::Aes256Gcm => Algorithm::aes_256_gcm(),
            Method::ChaCha20Poly1305 => Algorithm::xchacha20_poly1305(),
        };

        // --- read what the client sent
        let (identity, body, nonce) = if aes {
            let block = match key.method {
                Method::Aes128Gcm => Cipher::aes_128_ecb(),
                _ => Cipher::aes_256_ecb(),
            };
            let mut crypter = Crypter::new(block, Mode::Decrypt, key.raw(), None).unwrap();
            crypter.pad(false);
            let mut plain = vec![0u8; 32];
            let n = crypter.update(&datagram[..16], &mut plain).unwrap();
            plain.truncate(n);
            let nonce = plain[4..16].to_vec();
            (plain, datagram[16..].to_vec(), nonce)
        } else {
            (Vec::new(), datagram[24..].to_vec(), datagram[..24].to_vec())
        };
        let ctx = if aes {
            AeadCtx::new_default_tag(&algorithm, &key.subkey(&identity[..8])).unwrap()
        } else {
            AeadCtx::new_default_tag(&algorithm, key.raw()).unwrap()
        };
        let mut opened = body.clone();
        let tag = opened.split_off(opened.len() - 16);
        ctx.open_in_place(&nonce, &mut opened, &tag, &[]).unwrap();
        // For the merged form the identity is the first 16 bytes of the body.
        let (client_session, message) = if aes {
            (identity[..8].to_vec(), opened.as_slice())
        } else {
            (opened[..8].to_vec(), &opened[16..])
        };

        assert_eq!(message[0], 0, "type: client to server");
        let pad = u16::from_be_bytes(message[9..11].try_into().unwrap()) as usize;
        let Decoded::Complete {
            value: target,
            consumed,
        } = decode_address(&message[11 + pad..]).unwrap()
        else {
            panic!("the client wrote a whole address");
        };
        let sent = message[11 + pad + consumed..].to_vec();

        // --- answer the way the field table says to
        let mut reply = Vec::new();
        reply.push(1u8); // type: server to client
        reply.extend_from_slice(&now_seconds().to_be_bytes());
        reply.extend_from_slice(&client_session);
        reply.extend_from_slice(&0u16.to_be_bytes()); // no padding
        encode_address(from, &mut reply);
        reply.extend_from_slice(payload);

        let mut identity = [0u8; 16];
        identity[..8].copy_from_slice(&server_session);
        identity[8..].copy_from_slice(&packet_id.to_be_bytes());
        let out = if aes {
            let block = match key.method {
                Method::Aes128Gcm => Cipher::aes_128_ecb(),
                _ => Cipher::aes_256_ecb(),
            };
            let mut crypter = Crypter::new(block, Mode::Encrypt, key.raw(), None).unwrap();
            crypter.pad(false);
            let mut header = vec![0u8; 32];
            let n = crypter.update(&identity, &mut header).unwrap();
            header.truncate(n);
            let ctx = AeadCtx::new_default_tag(&algorithm, &key.subkey(&server_session)).unwrap();
            let mut tag = vec![0u8; 16];
            ctx.seal_in_place(&identity[4..16], &mut reply, &mut tag, &[])
                .unwrap();
            [header, reply, tag].concat()
        } else {
            let ctx = AeadCtx::new_default_tag(&algorithm, key.raw()).unwrap();
            let nonce = [7u8; 24];
            let mut body = [identity.to_vec(), reply].concat();
            let mut tag = vec![0u8; 16];
            ctx.seal_in_place(&nonce, &mut body, &mut tag, &[]).unwrap();
            [nonce.to_vec(), body, tag].concat()
        };
        (out, target, sent)
    }

    /// Every method's packet format, against a server that reads the
    /// specification rather than this file. **The two AES methods and the
    /// ChaCha one are different constructions**, so a test that only covered
    /// one would leave the other's framing entirely unexercised.
    #[test]
    fn a_packet_round_trips_against_a_server_built_from_the_field_tables() {
        for method in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::ChaCha20Poly1305,
        ] {
            let psk = key(method);
            let cipher = PacketCipher::new(&psk).unwrap();
            let session = [9u8; 8];
            let target = Target::Domain {
                host: crate::DomainName::new("example.com").unwrap(),
                port: 443,
            };

            let message = encode_packet_request(&target, now_seconds(), b"hello").unwrap();
            let datagram = cipher.seal(session, 0, &message).unwrap();

            let (reply, seen, sent) = spec_server_reply(
                &psk,
                &datagram,
                &Target::Ip("198.51.100.7:443".parse().unwrap()),
                b"world",
                [4u8; 8],
                0,
            );
            assert_eq!(seen, target, "{}: the target crossed", method.name());
            assert_eq!(sent, b"hello", "{}: the payload crossed", method.name());

            let opened = cipher.open(&reply).unwrap();
            assert_eq!(opened.session, [4u8; 8], "{}", method.name());
            let (from, at) =
                decode_packet_response(&opened.message, &session, now_seconds()).unwrap();
            assert_eq!(from, Target::Ip("198.51.100.7:443".parse().unwrap()));
            assert_eq!(&opened.message[at..], b"world", "{}", method.name());
        }
    }

    /// The three MUST-level checks, each closing a different hole. A reflected
    /// request read as a response would deliver a client its own bytes; a stale
    /// timestamp is the replay window SIP022 bounds at 30 seconds; and a reply
    /// echoing another client's session is another client's traffic.
    #[test]
    fn a_reply_must_be_a_reply_recent_and_addressed_to_this_client() {
        let session = [9u8; 8];
        let ours = |kind: u8, when: u64, echo: [u8; 8]| {
            let mut message = vec![kind];
            message.extend_from_slice(&when.to_be_bytes());
            message.extend_from_slice(&echo);
            message.extend_from_slice(&0u16.to_be_bytes());
            encode_address(
                &Target::Ip("198.51.100.7:443".parse().unwrap()),
                &mut message,
            );
            message.extend_from_slice(b"payload");
            message
        };
        let now = now_seconds();

        assert!(
            decode_packet_response(&ours(PACKET_TO_CLIENT, now, session), &session, now).is_ok()
        );
        assert!(
            decode_packet_response(&ours(PACKET_TO_SERVER, now, session), &session, now).is_err(),
            "a reflected request is not a response"
        );
        assert!(
            decode_packet_response(
                &ours(PACKET_TO_CLIENT, now - CLOCK_SKEW_SECONDS - 1, session),
                &session,
                now
            )
            .is_err(),
            "and neither is a replay from a minute ago"
        );
        assert!(
            decode_packet_response(&ours(PACKET_TO_CLIENT, now, [1u8; 8]), &session, now).is_err(),
            "nor another client's reply"
        );
    }

    /// SIP022 requires a sliding window because a relay whose replies can be
    /// replayed is a relay whose client can be made to re-process an old
    /// answer. Reordering inside the window is ordinary on any path and must
    /// still be accepted.
    #[test]
    fn the_replay_window_admits_reordering_and_refuses_repetition() {
        let mut window = Window::default();
        assert!(window.admit(0));
        assert!(!window.admit(0), "the same packet twice is a replay");
        assert!(window.admit(5));
        assert!(window.admit(3), "reordering inside the window is not");
        assert!(!window.admit(3));
        assert!(window.admit(4));
        assert!(!window.admit(5));

        // Far ahead resets the bitmap; everything under the new floor is gone
        // rather than admitted, which is the conservative half of the trade.
        assert!(window.admit(1_000));
        assert!(
            !window.admit(4),
            "below the window is refused, not admitted"
        );
        assert!(window.admit(999), "and just inside it is still accepted");
    }

    /// The nonce is a window over the packet identifier, so a repeated
    /// identifier is a repeated nonce — which against one key is total loss of
    /// confidentiality, not a degraded mode.
    #[test]
    fn the_packet_counter_never_repeats_a_nonce() {
        let psk = key(Method::Aes256Gcm);
        let cipher = PacketCipher::new(&psk).unwrap();
        let session = [3u8; 8];
        let message = encode_packet_request(
            &Target::Ip("198.51.100.7:443".parse().unwrap()),
            now_seconds(),
            b"x",
        )
        .unwrap();

        let mut headers = std::collections::HashSet::new();
        for packet_id in 0..64 {
            let datagram = cipher.seal(session, packet_id, &message).unwrap();
            assert!(
                headers.insert(datagram[..SEPARATE_HEADER].to_vec()),
                "two packets sealed under one nonce"
            );
        }
    }

    /// A datagram that will not open is noise, not a failure: anything on the
    /// internet can send to a UDP socket, so an association that died on the
    /// first stray packet would not survive a public port for a minute.
    #[test]
    fn a_packet_that_will_not_open_is_refused_rather_than_believed() {
        let psk = key(Method::Aes128Gcm);
        let cipher = PacketCipher::new(&psk).unwrap();
        let message = encode_packet_request(
            &Target::Ip("198.51.100.7:443".parse().unwrap()),
            now_seconds(),
            b"x",
        )
        .unwrap();
        let mut datagram = cipher.seal([1u8; 8], 0, &message).unwrap();

        assert!(cipher.open(&datagram).is_ok());
        let last = datagram.len() - 1;
        datagram[last] ^= 0x01;
        assert!(cipher.open(&datagram).is_err(), "a flipped tag bit");
        datagram[last] ^= 0x01;
        datagram[0] ^= 0x01;
        assert!(cipher.open(&datagram).is_err(), "a forged session identity");
        assert!(cipher.open(&[]).is_err(), "and nothing at all");
    }

    /// Padding exists to stop a datagram's length naming which host was looked
    /// up, so it applies where that leak is — plain DNS — and nowhere else.
    #[test]
    fn only_a_query_to_the_resolver_is_padded() {
        let dns = Target::Ip("198.51.100.7:53".parse().unwrap());
        let web = Target::Ip("198.51.100.7:443".parse().unwrap());
        let now = now_seconds();

        let padded = encode_packet_request(&dns, now, b"query").unwrap();
        let bare = encode_packet_request(&web, now, b"query").unwrap();
        assert_eq!(
            u16::from_be_bytes(bare[9..11].try_into().unwrap()),
            0,
            "everything else pays nothing"
        );
        let length = u16::from_be_bytes(padded[9..11].try_into().unwrap());
        assert!(
            (1..=MAX_PADDING as u16).contains(&length),
            "1 + rand % 900, as both reference implementations do: {length}"
        );
    }

    /// The response fixed header a server writes, built here from SIP022's
    /// field table rather than from this file's decoder — so the tests below
    /// check agreement with the specification and not with themselves.
    fn server_fixed_header(now: u64, request_salt: &[u8], length: u16) -> Vec<u8> {
        let mut header = Vec::with_capacity(11 + request_salt.len());
        header.push(TYPE_RESPONSE);
        header.extend_from_slice(&now.to_be_bytes());
        header.extend_from_slice(request_salt);
        header.extend_from_slice(&length.to_be_bytes());
        header
    }

    /// A codec pair keyed the way a real session is, so the two directions can
    /// be run against each other without a server.
    fn paired(method: Method) -> (StreamCodec, Session, Vec<u8>, PreSharedKey) {
        let psk = key(method);
        let request_salt = vec![7u8; method.salt_len()];
        let response_salt = vec![9u8; method.salt_len()];
        // What the client holds.
        let client = StreamCodec {
            writer: Session::new(method, &psk.subkey(&request_salt)).unwrap(),
            reader: None,
            method,
            key: psk.clone(),
            request_salt: request_salt.clone(),
            state: ReadState::Salt,
        };
        // What a server would seal responses with.
        let server = Session::new(method, &psk.subkey(&response_salt)).unwrap();
        (client, server, response_salt, psk)
    }

    /// **Every read boundary, without a socket.** The framing is four states
    /// whose sizes are each known only after the previous one decrypts, so a
    /// decoder that assumed a whole stage arrives at once would pass a loopback
    /// test and stall on a real path.
    #[test]
    fn the_stream_framing_decodes_one_byte_at_a_time() {
        let (mut codec, mut server, response_salt, _psk) = paired(Method::Aes256Gcm);

        // A server's first bytes: its salt, the sealed fixed header naming the
        // first chunk's length, then that chunk.
        let payload = b"hello from the far side";
        let mut wire = response_salt.clone();
        let mut fixed =
            server_fixed_header(now_seconds(), &codec.request_salt, payload.len() as u16);
        server.seal(&mut fixed).unwrap();
        wire.extend_from_slice(&fixed);
        let mut sealed = payload.to_vec();
        server.seal(&mut sealed).unwrap();
        wire.extend_from_slice(&sealed);

        // Offer a growing prefix, one byte at a time, exactly as `Framed` does.
        let mut out = Vec::new();
        let mut at = 0usize;
        for taken in 0..=wire.len() {
            loop {
                let offered = &wire[at..taken];
                let Decode::Framed { rest } = codec.decode(offered, &mut out).unwrap() else {
                    panic!("this framing never ends");
                };
                let consumed = offered.len() - rest.len();
                if consumed == 0 {
                    break;
                }
                at += consumed;
            }
        }
        assert_eq!(out, payload, "every stage crossed a byte at a time");
    }

    /// A sealed chunk whose tag does not verify ends the stream. Framing is not
    /// something a peer recovers from mid-connection: a chunk that will not
    /// open means the two sides no longer agree where the next one begins.
    #[test]
    fn a_chunk_that_will_not_open_is_refused() {
        let (mut codec, mut server, response_salt, _psk) = paired(Method::Aes128Gcm);
        let mut wire = response_salt.clone();
        let mut fixed = server_fixed_header(now_seconds(), &codec.request_salt, 4);
        server.seal(&mut fixed).unwrap();
        wire.extend_from_slice(&fixed);

        let mut out = Vec::new();
        let mut at = 0usize;
        // The salt, then the header.
        for _ in 0..2 {
            let offered = &wire[at..];
            let Decode::Framed { rest } = codec.decode(offered, &mut out).unwrap() else {
                unreachable!()
            };
            at += offered.len() - rest.len();
        }
        // A payload chunk of the right length whose contents are noise.
        let noise = vec![0u8; 4 + TAG];
        assert!(matches!(
            codec.decode(&noise, &mut out),
            Err(ProxyError::Crypto)
        ));
    }

    /// The two-byte length field is the ceiling, and the adapter splits rather
    /// than letting a caller discover it mid-encode.
    #[test]
    fn a_payload_past_the_length_field_is_the_adapters_problem_not_the_codecs() {
        let (codec, _server, _salt, _psk) = paired(Method::Aes256Gcm);
        assert_eq!(codec.max_payload(), MAX_CHUNK);
        assert_eq!(MAX_CHUNK, 0xffff, "what two bytes can express");
    }

    /// **The spin this port removed.** The old writer looped on `Poll::Pending`
    /// because a sealed frame's nonce is already spent and it had nowhere to
    /// park one; against a peer that stops reading it burned a core. `Framed`
    /// holds the frame and yields, so a full pipe costs nothing.
    #[tokio::test]
    async fn a_peer_that_stops_reading_parks_the_writer_rather_than_spinning() {
        let (peer, ours) = tokio::io::duplex(64);
        let (mut codec, _server, _salt, _psk) = paired(Method::Aes256Gcm);
        codec.state = ReadState::Salt;
        let mut framed = Framed::new(ours, codec);

        // Far more than the pipe holds, and nobody is draining it.
        let payload = vec![b'x'; 8192];
        let stalled = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            framed.write_all(&payload),
        )
        .await;
        assert!(stalled.is_err(), "the write is parked, which is the point");
        drop(peer);
    }
}
