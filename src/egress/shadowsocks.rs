//! Shadowsocks 2022 Edition (SIP022) stream and datagram egress.
//!
//! SIP022 uses full-entropy keys, BLAKE3 session derivation, timestamp checks,
//! and replay protection. AEAD operations use the crate's existing providers;
//! counters remain paired with their keys so nonces cannot repeat.
//!
//! Stream and packet formats are separate SIP022 constructions. Local tests
//! cover field-level framing; interoperability remains tracked in
//! [Verification](../docs/verification.md).

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

/// SIP022's fixed BLAKE3 derive-key context.
const SUBKEY_CONTEXT: &str = "shadowsocks 2022 session subkey";

const TAG: usize = 16;

const MAX_CHUNK: usize = 0xffff;

const CLOCK_SKEW_SECONDS: u64 = 30;

const TYPE_REQUEST: u8 = 0;
const TYPE_RESPONSE: u8 = 1;

/// SIP022 cipher suites and their key lengths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Method {
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

    pub fn name(self) -> &'static str {
        match self {
            Self::Aes128Gcm => "2022-blake3-aes-128-gcm",
            Self::Aes256Gcm => "2022-blake3-aes-256-gcm",
            Self::ChaCha20Poly1305 => "2022-blake3-chacha20-poly1305",
        }
    }
}

/// A SIP022 pre-shared key with method-specific length.
#[derive(Clone, Debug)]
pub struct PreSharedKey {
    bytes: Vec<u8>,
    method: Method,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// The key length does not match the method.
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

/// One session direction with its AEAD key and nonce counter.
struct Session {
    key: LessSafeKey,
    /// Little-endian nonce counter stored in the low eight bytes.
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

    fn next_nonce(&mut self) -> Nonce {
        let mut bytes = [0u8; 12];
        bytes[..8].copy_from_slice(&self.counter.to_le_bytes());
        self.counter += 1;
        Nonce::assume_unique_for_key(bytes)
    }

    fn seal(&mut self, buf: &mut Vec<u8>) -> Result<(), ProxyError> {
        let nonce = self.next_nonce();
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), buf)
            .map_err(|_| ProxyError::Crypto)?;
        Ok(())
    }

    fn open<'a>(&mut self, buf: &'a mut [u8]) -> Result<&'a [u8], ProxyError> {
        let nonce = self.next_nonce();
        let plain = self
            .key
            .open_in_place(nonce, Aad::empty(), buf)
            .map_err(|_| ProxyError::Crypto)?;
        Ok(plain)
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn check_timestamp(theirs: u64, ours: u64) -> Result<(), ProxyError> {
    let skew = ours.abs_diff(theirs);
    if skew > CLOCK_SKEW_SECONDS {
        return Err(ProxyError::Stale { skew });
    }
    Ok(())
}

const MAX_PADDING: usize = 900;

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

fn encode_request_fixed(now: u64, body_len: u16) -> Vec<u8> {
    let mut header = Vec::with_capacity(11);
    Writer::new(&mut header)
        .u8(TYPE_REQUEST)
        .u64(now)
        .u16(body_len);
    header
}

fn decode_response_fixed(plain: &[u8], request_salt: &[u8], now: u64) -> Result<u16, ProxyError> {
    // The state machine selected the exact ciphertext size.
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
    /// Proxy mapping behavior from RFC 4787.
    pub nat_behavior: NatBehavior,
}

// SIP022 UDP packet egress.

enum PacketCipher {
    /// AES packet format with an encrypted separate header.
    Separate {
        key: PreSharedKey,
        header: boring::symm::Cipher,
    },
    /// XChaCha packet format keyed by the association PSK.
    Merged { key: boring::aead::AeadCtx },
}

const SEPARATE_HEADER: usize = 16;

const NONCE_WINDOW: std::ops::Range<usize> = 4..SEPARATE_HEADER;

const MERGED_NONCE: usize = 24;

const PACKET_TO_SERVER: u8 = 0;
const PACKET_TO_CLIENT: u8 = 1;

const MAX_UDP_PAYLOAD: usize = u16::MAX as usize;

/// Maximum client datagram after worst-case SIP022 framing.
const MAX_PROXIED_DATAGRAM: u16 = {
    // Worst-case outer framing: nonce or header, tag, type, timestamp, padding.
    let framing = MERGED_NONCE + TAG + 1 + 8 + 2;
    // Longest encoded domain address.
    let address = 1 + 1 + 255 + 2;
    (crate::MIN_IPV6_MTU as usize - 48 - framing - address) as u16
};

struct Opened {
    session: [u8; 8],
    packet_id: u64,
    /// Message beginning at its type byte.
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
                // Merged format keeps identity inside the encrypted body.
                out.extend_from_slice(&identity);
                out.extend_from_slice(message);
                let tag = Self::finish(key, &nonce, &mut out, MERGED_NONCE)?;
                out.extend_from_slice(&tag);
                Ok(out)
            }
        }
    }

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

fn random(bytes: &mut [u8]) -> Result<(), EgressError> {
    ring::rand::SystemRandom::new()
        .fill(bytes)
        .map_err(|_| ProxyError::Crypto)?;
    Ok(())
}

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

fn decode_packet_response(
    message: &[u8],
    client_session: &[u8; 8],
    now: u64,
) -> Result<(Target, usize), EgressError> {
    // Type, timestamp, echoed client session, and padding length.
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

#[derive(Default)]
struct Window {
    /// No high-water mark exists until the first packet.
    highest: Option<u64>,
    below: u64,
}

impl Window {
    fn admit(&mut self, id: u64) -> bool {
        let Some(highest) = self.highest else {
            self.highest = Some(id);
            return true;
        };
        let Some(behind) = highest.checked_sub(id) else {
            // Shift the bitmap and retain the old high-water mark when in range.
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

struct PacketRelay {
    socket: tokio::net::UdpSocket,
    cipher: PacketCipher,
    session: [u8; 8],
    /// Atomic packet counter shared by all mapped flows.
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

struct PacketSource {
    relay: Arc<PacketRelay>,
    /// Current and immediately previous server sessions.
    sessions: [Option<([u8; 8], Window)>; 2],
    /// Receive buffer large enough for any UDP datagram.
    framed: Vec<u8>,
}

impl PacketSource {
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
                // Unauthenticated UDP input is noise, not association failure.
                let Ok(opened) = self.relay.cipher.open(&self.framed[..read]) else {
                    continue;
                };
                let Ok((from, at)) =
                    decode_packet_response(&opened.message, &self.relay.session, now_seconds())
                else {
                    continue;
                };
                // Advance replay state only after authentication and validation.
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
            // SIP022 preserves one client datagram per server datagram.
            datagram_fidelity: DatagramFidelity::Native,
            // Framing is included in the maximum datagram budget.
            overhead_bytes: 0,
            max_datagram_size: Some(MAX_PROXIED_DATAGRAM),
            preserves_ecn: false,
            nat_behavior: self.config.nat_behavior,
        }
    }

    fn associate(&self) -> BoxFuture<'_, Result<Association, EgressError>> {
        Box::pin(async move {
            let socket = self.bypass.udp(self.config.server).await?;
            let mut session = [0u8; 8];
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

            // A fresh CSPRNG salt separates sessions under one PSK.
            let random = ring::rand::SystemRandom::new();
            let mut salt = vec![0u8; method.salt_len()];
            random.fill(&mut salt).map_err(|_| ProxyError::Crypto)?;
            let mut writer = Session::new(method, &self.config.key.subkey(&salt))?;

            // No initial payload means request padding is mandatory.
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

/// Stream reader state; each next length depends on the prior decrypted stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadState {
    /// Server salt that keys the response direction.
    Salt,
    /// Sealed response header.
    FixedHeader,
    /// Sealed payload-length chunk.
    Length,
    /// Sealed payload chunk of this plaintext length.
    Payload(usize),
}

/// Pure Shadowsocks stream framing codec.
struct StreamCodec {
    writer: Session,
    /// Built from the server salt on the first response.
    reader: Option<Session>,
    method: Method,
    key: PreSharedKey,
    request_salt: Vec<u8>,
    state: ReadState,
}

impl StreamCodec {
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

    fn encode(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<(), ProxyError> {
        let mut length = Vec::with_capacity(2);
        Writer::new(&mut length).u16(payload.len() as u16);
        self.writer.seal(&mut length)?;
        let mut sealed = payload.to_vec();
        self.writer.seal(&mut sealed)?;
        Writer::new(out).bytes(&length).bytes(&sealed);
        Ok(())
    }

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
        // BLAKE3 always derives 256 bits before method-specific truncation.
        assert_eq!(key(Method::Aes128Gcm).subkey(&[1u8; 16]).len(), 16);
    }

    #[test]
    fn the_nonce_counter_never_repeats_and_advances_little_endian() {
        let mut session = Session::new(Method::Aes256Gcm, &[3u8; 32]).unwrap();
        // Identical plaintexts require distinct ciphertexts under fresh nonces.
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

        // Counter drift makes the next chunk fail authentication.
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

        let good = build(TYPE_RESPONSE, now, &salt, 1234);
        assert_eq!(decode_response_fixed(&good, &salt, now).unwrap(), 1234);

        // The echoed salt binds the response to this request.
        let other = build(TYPE_RESPONSE, now, &[6u8; 32], 1);
        assert!(matches!(
            decode_response_fixed(&other, &salt, now),
            Err(ProxyError::SaltMismatch)
        ));

        // The replay window is symmetric around the local clock.
        for stamp in [now - CLOCK_SKEW_SECONDS - 1, now + CLOCK_SKEW_SECONDS + 1] {
            let stale = build(TYPE_RESPONSE, stamp, &salt, 1);
            assert!(matches!(
                decode_response_fixed(&stale, &salt, now),
                Err(ProxyError::Stale { .. })
            ));
        }
        // The configured boundary is inclusive.
        let edge = build(TYPE_RESPONSE, now + CLOCK_SKEW_SECONDS, &salt, 1);
        assert_eq!(decode_response_fixed(&edge, &salt, now).unwrap(), 1);

        let reflected = build(TYPE_REQUEST, now, &salt, 1);
        assert!(matches!(
            decode_response_fixed(&reflected, &salt, now),
            Err(ProxyError::Header)
        ));

        assert!(matches!(
            decode_response_fixed(&good[..10], &salt, now),
            Err(ProxyError::Header)
        ));
    }

    #[test]
    fn a_request_body_carries_the_target_and_an_explicit_padding_length() {
        let target = Target::Ip("192.0.2.1:443".parse().unwrap());
        // Initial data satisfies SIP022's non-empty request requirement.
        let body = encode_request_body(&target, &[], b"GET /");
        assert_eq!(body.len(), 1 + 4 + 2 + 2 + 5);
        assert_eq!(
            &body[7..9],
            &0u16.to_be_bytes(),
            "padding length is explicit"
        );
        assert_eq!(&body[9..], b"GET /");

        // Without initial data, the declared padding carries that requirement.
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

    /// Decodes a request and builds a field-table-compatible server reply.
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

        // Decode the client packet independently of the production decoder.
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
        // Merged packets place the identity at the start of the plaintext body.
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

        // Encode the server response from the SIP022 field order.
        let mut reply = Vec::new();
        reply.push(1u8); // Server-to-client message type.
        reply.extend_from_slice(&now_seconds().to_be_bytes());
        reply.extend_from_slice(&client_session);
        reply.extend_from_slice(&0u16.to_be_bytes()); // No response padding.
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

        // A large jump retires IDs below the new window.
        assert!(window.admit(1_000));
        assert!(
            !window.admit(4),
            "below the window is refused, not admitted"
        );
        assert!(window.admit(999), "and just inside it is still accepted");
    }

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

    fn server_fixed_header(now: u64, request_salt: &[u8], length: u16) -> Vec<u8> {
        let mut header = Vec::with_capacity(11 + request_salt.len());
        header.push(TYPE_RESPONSE);
        header.extend_from_slice(&now.to_be_bytes());
        header.extend_from_slice(request_salt);
        header.extend_from_slice(&length.to_be_bytes());
        header
    }

    fn paired(method: Method) -> (StreamCodec, Session, Vec<u8>, PreSharedKey) {
        let psk = key(method);
        let request_salt = vec![7u8; method.salt_len()];
        let response_salt = vec![9u8; method.salt_len()];
        let client = StreamCodec {
            writer: Session::new(method, &psk.subkey(&request_salt)).unwrap(),
            reader: None,
            method,
            key: psk.clone(),
            request_salt: request_salt.clone(),
            state: ReadState::Salt,
        };
        let server = Session::new(method, &psk.subkey(&response_salt)).unwrap();
        (client, server, response_salt, psk)
    }

    #[test]
    fn the_stream_framing_decodes_one_byte_at_a_time() {
        let (mut codec, mut server, response_salt, _psk) = paired(Method::Aes256Gcm);

        let payload = b"hello from the far side";
        let mut wire = response_salt.clone();
        let mut fixed =
            server_fixed_header(now_seconds(), &codec.request_salt, payload.len() as u16);
        server.seal(&mut fixed).unwrap();
        wire.extend_from_slice(&fixed);
        let mut sealed = payload.to_vec();
        server.seal(&mut sealed).unwrap();
        wire.extend_from_slice(&sealed);

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

    #[test]
    fn a_chunk_that_will_not_open_is_refused() {
        let (mut codec, mut server, response_salt, _psk) = paired(Method::Aes128Gcm);
        let mut wire = response_salt.clone();
        let mut fixed = server_fixed_header(now_seconds(), &codec.request_salt, 4);
        server.seal(&mut fixed).unwrap();
        wire.extend_from_slice(&fixed);

        let mut out = Vec::new();
        let mut at = 0usize;
        for _ in 0..2 {
            let offered = &wire[at..];
            let Decode::Framed { rest } = codec.decode(offered, &mut out).unwrap() else {
                unreachable!()
            };
            at += offered.len() - rest.len();
        }
        let noise = vec![0u8; 4 + TAG];
        assert!(matches!(
            codec.decode(&noise, &mut out),
            Err(ProxyError::Crypto)
        ));
    }

    /// The adapter owns splitting at the two-byte length ceiling.
    #[test]
    fn a_payload_past_the_length_field_is_the_adapters_problem_not_the_codecs() {
        let (codec, _server, _salt, _psk) = paired(Method::Aes256Gcm);
        assert_eq!(codec.max_payload(), MAX_CHUNK);
        assert_eq!(MAX_CHUNK, 0xffff, "what two bytes can express");
    }

    #[tokio::test]
    async fn a_peer_that_stops_reading_parks_the_writer_rather_than_spinning() {
        let (peer, ours) = tokio::io::duplex(64);
        let (mut codec, _server, _salt, _psk) = paired(Method::Aes256Gcm);
        codec.state = ReadState::Salt;
        let mut framed = Framed::new(ours, codec);

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
