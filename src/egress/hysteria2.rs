//! Hysteria2 stream egress over one authenticated QUIC connection.
//!
//! No RFC defines its wire format, so layouts and limits follow
//! [sing-quic](https://github.com/SagerNet/sing-quic)'s `hysteria2` package and
//! are checked by `tests/interop.rs`.
//!
//! Authentication is one HTTP/3 request with status `233`; subsequent streams
//! use Hysteria2 frames after the HTTP/3 layer is dropped. Both request types
//! use the reference padding ranges to avoid a distinctive wire shape.

use std::{net::SocketAddr, ops::Range, sync::Arc, time::Duration};

use ring::rand::SecureRandom;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{
    Association, AsyncStream, BoxFuture, DatagramFidelity, DatagramSink, DatagramSource, Decoded,
    EgressError, NatBehavior, PathProperties, Prefixed, ProxyError, StreamEgress, Target,
    TunnelBypass,
    egress::quic::{DATAGRAM_DEPTH, Handshake, QuicConnection, client_config},
    live::Live,
    wire::{Reader, Writer, varint_len},
};

const AUTH_AUTHORITY: &str = "hysteria";
const AUTH_PATH: &str = "/auth";

const HEADER_AUTH: &[u8] = b"hysteria-auth";
const HEADER_CC_RX: &[u8] = b"hysteria-cc-rx";
const HEADER_PADDING: &[u8] = b"hysteria-padding";
const HEADER_UDP: &str = "hysteria-udp";

const STATUS_AUTH_OK: u16 = 233;

const FRAME_TCP_REQUEST: u64 = 0x401;

/// Reference limits for lengths received from the server.
const MAX_ADDRESS_LEN: u64 = 2048;
const MAX_MESSAGE_LEN: u64 = 2048;
const MAX_PADDING_LEN: u64 = 4096;

/// Reference padding ranges, expressed as half-open intervals.
const AUTH_PADDING: Range<usize> = 256..2048;
const REQUEST_PADDING: Range<usize> = 64..512;

/// Reference padding alphabet.
const PADDING_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// Reference idle timeout; QUIC driving owns the timer.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Generates reference-shaped random padding. O(range.end).
fn padding(range: Range<usize>) -> Result<Vec<u8>, ProxyError> {
    let random = ring::rand::SystemRandom::new();
    let mut choice = [0u8; 2];
    random.fill(&mut choice).map_err(|_| ProxyError::Crypto)?;
    let span = range.end - range.start;
    let length = range.start + usize::from(u16::from_be_bytes(choice)) % span;

    let mut bytes = vec![0u8; length];
    random.fill(&mut bytes).map_err(|_| ProxyError::Crypto)?;
    for byte in &mut bytes {
        // Padding is opaque; only its length is protocol-visible.
        *byte = PADDING_ALPHABET[usize::from(*byte) % PADDING_ALPHABET.len()];
    }
    Ok(bytes)
}

/// Writes `varint(type) || varint(address) || address || varint(padding) || padding`.
/// The address is the target's textual `host:port` form.
pub fn encode_tcp_request(target: &Target, padding: &[u8], out: &mut Vec<u8>) {
    let address = target.to_string();
    Writer::new(out)
        .varint(FRAME_TCP_REQUEST)
        .vector_varint(address.as_bytes())
        .vector_varint(padding);
}

/// Server result for a stream-open request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TcpResponse {
    /// Status zero; the stream carries payload.
    Accepted,
    /// Nonzero status and the server's bounded explanation.
    Refused(String),
}

/// Reads `status || vstring(message) || vbytes(padding)` and preserves surplus.
pub fn decode_tcp_response(bytes: &[u8]) -> Result<Decoded<TcpResponse>, ProxyError> {
    let mut reader = Reader::new(bytes);
    let Some(status) = reader.u8() else {
        return Ok(Decoded::Incomplete);
    };
    let Some(message_len) = reader.varint() else {
        return Ok(Decoded::Incomplete);
    };
    if message_len > MAX_MESSAGE_LEN {
        return Err(ProxyError::Header);
    }
    let Some(message) = reader.take(message_len as usize) else {
        return Ok(Decoded::Incomplete);
    };
    let Some(padding_len) = reader.varint() else {
        return Ok(Decoded::Incomplete);
    };
    if padding_len > MAX_PADDING_LEN {
        return Err(ProxyError::Header);
    }
    if reader.skip(padding_len as usize).is_none() {
        return Ok(Decoded::Incomplete);
    }
    // Refuse malformed diagnostic text rather than logging replacement bytes.
    let message = std::str::from_utf8(message)
        .map_err(|_| ProxyError::Header)?
        .to_owned();
    Ok(Decoded::Complete {
        // Any nonzero status is a refusal.
        value: match status {
            0 => TcpResponse::Accepted,
            _ => TcpResponse::Refused(message),
        },
        consumed: reader.position(),
    })
}

pub struct Hysteria2Config {
    /// Server UDP endpoint.
    pub server: SocketAddr,
    /// SNI name and certificate verification name.
    pub server_name: String,
    /// Password sent in the authentication header.
    pub password: String,
    /// RFC 4787 mapping behavior provided by the server.
    pub nat_behavior: NatBehavior,
}

pub type QuicConfigFactory = Box<dyn Fn() -> Result<quiche::Config, EgressError> + Send + Sync>;

struct OpenStream {
    request: Option<Vec<u8>>,
}

impl OpenStream {
    fn new(target: &Target, padding: Vec<u8>) -> Self {
        let mut request = Vec::with_capacity(128);
        encode_tcp_request(target, &padding, &mut request);
        Self {
            request: Some(request),
        }
    }
}

impl crate::Negotiation for OpenStream {
    type Output = ();

    fn advance(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<Decoded<()>, ProxyError> {
        if let Some(request) = self.request.take() {
            out.extend_from_slice(&request);
        }
        let Decoded::Complete { value, consumed } = decode_tcp_response(input)? else {
            return Ok(Decoded::Incomplete);
        };
        if let TcpResponse::Refused(message) = value {
            return Err(ProxyError::Denied(message));
        }
        Ok(Decoded::Complete {
            value: (),
            consumed,
        })
    }
}

// UDP over QUIC.

/// One Hysteria2 UDP message carried by one QUIC DATAGRAM.
///
/// ```text
/// [uint32] Session ID
/// [uint16] Packet ID
/// [uint8]  Fragment ID
/// [uint8]  Fragment count
/// [varint] Address length
/// [bytes]  Address string, "host:port"
/// [bytes]  Payload
/// ```
///
/// The address remains textual and is resolved by the server. QUIC supplies
/// framing and authentication, so this message has no additional type field.
struct UdpMessage<'a> {
    session: u32,
    packet: u16,
    fragment: u8,
    fragments: u8,
    address: &'a str,
    payload: &'a [u8],
}

const UDP_FIXED: usize = 4 + 2 + 1 + 1;

/// Reference `MaxDatagramFrameSize`.
const MAX_DATAGRAM_FRAME: usize = 1200;

impl UdpMessage<'_> {
    /// Per-fragment overhead, including the repeated address.
    fn header_len(address: &str) -> usize {
        UDP_FIXED + varint_len(address.len() as u64) + address.len()
    }

    fn write(&self, out: &mut Vec<u8>) {
        Writer::new(out)
            .u32(self.session)
            .u16(self.packet)
            .u8(self.fragment)
            .u8(self.fragments)
            .vector_varint(self.address.as_bytes())
            .bytes(self.payload);
    }

    /// Parses a complete, bounded message from untrusted input.
    fn read(bytes: &[u8]) -> Option<UdpMessage<'_>> {
        let mut reader = Reader::new(bytes);
        let session = reader.u32()?;
        let packet = reader.u16()?;
        let fragment = reader.u8()?;
        let fragments = reader.u8()?;
        let length = reader.varint()?;
        if length == 0 || length > MAX_MESSAGE_LEN {
            return None;
        }
        let address = reader.take(length as usize)?;
        let payload = reader.rest();
        // Empty payloads are not valid Hysteria2 messages.
        if payload.is_empty() {
            return None;
        }
        Some(UdpMessage {
            session,
            packet,
            fragment,
            fragments,
            address: std::str::from_utf8(address).ok()?,
            payload,
        })
    }
}

/// Splits a datagram into messages of at most `frame` bytes, the full header
/// on each one.
fn fragment(
    session: u32,
    packet: u16,
    address: &str,
    payload: &[u8],
    frame: usize,
) -> Option<Vec<Vec<u8>>> {
    let budget = frame.checked_sub(UdpMessage::header_len(address))?;
    if budget == 0 {
        return None;
    }
    let count = payload.len().div_ceil(budget).max(1);
    let fragments = u8::try_from(count).ok()?;
    Some(
        payload
            .chunks(budget)
            .chain(payload.is_empty().then_some(&[][..]))
            .enumerate()
            .map(|(index, chunk)| {
                let mut out = Vec::with_capacity(MAX_DATAGRAM_FRAME);
                UdpMessage {
                    session,
                    packet,
                    fragment: index as u8,
                    fragments,
                    address,
                    payload: chunk,
                }
                .write(&mut out);
                out
            })
            .collect(),
    )
}

/// Reassembles one packet at a time; a new packet replaces partial state.
#[derive(Default)]
struct Defragmenter {
    packet: u16,
    fragments: u8,
    /// Fragments in index order.
    held: Vec<Option<Vec<u8>>>,
}

impl Defragmenter {
    /// Returns a payload only after every fragment has arrived.
    fn push(&mut self, message: &UdpMessage<'_>) -> Option<Vec<u8>> {
        // Both reference implementations treat zero like an unfragmented packet.
        if message.fragments <= 1 {
            return Some(message.payload.to_vec());
        }
        if message.fragment >= message.fragments {
            return None;
        }
        if self.packet != message.packet || self.fragments != message.fragments {
            self.packet = message.packet;
            self.fragments = message.fragments;
            self.held = vec![None; usize::from(message.fragments)];
        }
        self.held[usize::from(message.fragment)] = Some(message.payload.to_vec());
        if self.held.iter().any(Option::is_none) {
            return None;
        }
        let whole = self.held.iter().flatten().flatten().copied().collect();
        self.held.clear();
        // Completed packets leave no stale fragment state.
        self.fragments = 0;
        Some(whole)
    }
}

pub struct Hysteria2Egress<B> {
    config: Arc<Hysteria2Config>,
    bypass: Arc<B>,
    quic: Arc<QuicConfigFactory>,
    /// Shared authenticated connection, dialled on its own task.
    connection: Live<QuicConnection>,
    /// Datagram routes for the current connection, if supported.
    datagrams: Arc<std::sync::Mutex<Option<Arc<Sessions>>>>,
    /// Cancels the connection driver on drop.
    shutdown: CancellationToken,
}

impl<B> Drop for Hysteria2Egress<B> {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// An egress failure carried through `Live`, which speaks `io::Error`.
fn failed(error: EgressError) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

impl<B: TunnelBypass + 'static> Hysteria2Egress<B> {
    pub fn new(config: Hysteria2Config, bypass: B, quic: QuicConfigFactory) -> Self {
        Self {
            config: Arc::new(config),
            bypass: Arc::new(bypass),
            quic: Arc::new(quic),
            connection: Live::new(),
            datagrams: Arc::new(std::sync::Mutex::new(None)),
            shutdown: CancellationToken::new(),
        }
    }

    pub fn quic_config() -> Result<quiche::Config, EgressError> {
        let mut config = client_config(quiche::h3::APPLICATION_PROTOCOL, IDLE_TIMEOUT)?;
        // The UDP relay rides DATAGRAM frames, sent only to a client that
        // advertised them (RFC 9221 section 3).
        config.enable_dgram(true, DATAGRAM_DEPTH, DATAGRAM_DEPTH);
        Ok(config)
    }

    async fn connection(&self) -> Result<QuicConnection, EgressError> {
        let (config, bypass, quic) = (
            Arc::clone(&self.config),
            Arc::clone(&self.bypass),
            Arc::clone(&self.quic),
        );
        let (datagrams, shutdown) = (Arc::clone(&self.datagrams), self.shutdown.clone());
        self.connection
            .get(QuicConnection::is_alive, async move {
                let socket = bypass.udp(config.server).await?;
                let mut handshake = Handshake::establish(
                    socket,
                    config.server,
                    &config.server_name,
                    quic().map_err(failed)?,
                )
                .await
                .map_err(failed)?;

                let pad = padding(AUTH_PADDING).map_err(|error| failed(error.into()))?;
                let response = handshake
                    .http3(&[
                        quiche::h3::Header::new(b":method", b"POST"),
                        quiche::h3::Header::new(b":scheme", b"https"),
                        quiche::h3::Header::new(b":authority", AUTH_AUTHORITY.as_bytes()),
                        quiche::h3::Header::new(b":path", AUTH_PATH.as_bytes()),
                        quiche::h3::Header::new(HEADER_AUTH, config.password.as_bytes()),
                        // Zero selects congestion control instead of a claimed
                        // receive rate.
                        quiche::h3::Header::new(HEADER_CC_RX, b"0"),
                        quiche::h3::Header::new(HEADER_PADDING, &pad),
                    ])
                    .await
                    .map_err(failed)?;

                if response.status != STATUS_AUTH_OK {
                    return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
                }
                // Datagram support is a server-declared capability.
                let carries_datagrams = response.header(HEADER_UDP).is_some_and(|value| {
                    matches!(value, "true" | "1" | "t" | "T" | "TRUE" | "True")
                });

                let connection = handshake.drive(shutdown.clone());
                // Start routing before allowing sessions to register.
                let hub = if carries_datagrams {
                    let hub = Sessions::new();
                    hub.serve(&connection, shutdown).await;
                    Some(hub)
                } else {
                    None
                };
                *crate::locked(&datagrams) = hub;
                Ok(connection)
            })
            .await
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::PermissionDenied => ProxyError::AuthFailed.into(),
                _ => EgressError::from(error),
            })
    }

    /// Response header reporting datagram support.
    pub fn udp_header() -> &'static str {
        HEADER_UDP
    }
}

type Route = mpsc::Sender<(Vec<u8>, Target)>;

struct Sessions {
    /// Routes keyed by session identifier.
    routes: std::sync::Mutex<std::collections::HashMap<u32, Route>>,
    /// Next session identifier; reference implementations start at one.
    next: std::sync::atomic::AtomicU32,
}

impl Sessions {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            routes: std::sync::Mutex::new(std::collections::HashMap::new()),
            next: std::sync::atomic::AtomicU32::new(1),
        })
    }

    async fn serve(self: &Arc<Self>, connection: &QuicConnection, shutdown: CancellationToken) {
        let Some(mut inbound) = connection.receive_datagrams().await else {
            return;
        };
        let hub = Arc::clone(self);
        tokio::spawn(async move {
            // Each session's reassembly state belongs to this reader task.
            let mut partial: std::collections::HashMap<u32, Defragmenter> =
                std::collections::HashMap::new();
            loop {
                let datagram = tokio::select! {
                    () = shutdown.cancelled() => break,
                    next = inbound.recv() => match next {
                        Some(next) => next,
                        None => break,
                    },
                };
                // Ignore malformed messages without killing other sessions.
                let Some(message) = UdpMessage::read(&datagram) else {
                    continue;
                };
                let Some(route) = crate::locked(&hub.routes).get(&message.session).cloned() else {
                    // Drop state for a session that has closed.
                    partial.remove(&message.session);
                    continue;
                };
                let Ok(from) = message.address.parse::<SocketAddr>().map(Target::Ip) else {
                    // Replies must identify a concrete source address.
                    continue;
                };
                let Some(whole) = partial.entry(message.session).or_default().push(&message) else {
                    continue;
                };
                if route.try_send((whole, from)).is_err() {
                    // A full or closed route drops the datagram.
                    continue;
                }
            }
        });
    }

    fn open(&self) -> (u32, mpsc::Receiver<(Vec<u8>, Target)>) {
        let id = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (sender, receiver) = mpsc::channel(SESSION_DEPTH);
        crate::locked(&self.routes).insert(id, sender);
        (id, receiver)
    }

    fn close(&self, id: u32) {
        crate::locked(&self.routes).remove(&id);
    }
}

/// Capacity of each bounded, lossy session route.
const SESSION_DEPTH: usize = 64;

struct UdpSession {
    connection: QuicConnection,
    hub: Arc<Sessions>,
    id: u32,
    /// Packet identifier for the next datagram.
    next_packet: std::sync::atomic::AtomicU32,
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        self.hub.close(self.id);
    }
}

impl DatagramSink for UdpSession {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        target: &'a Target,
    ) -> BoxFuture<'a, Result<(), EgressError>> {
        Box::pin(async move {
            let address = target.to_string();
            let packet = self
                .next_packet
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u16;
            // What the peer takes now, never above the reference size.
            let frame = self
                .connection
                .datagram_budget()
                .map_or(MAX_DATAGRAM_FRAME, |budget| {
                    budget.get().min(MAX_DATAGRAM_FRAME)
                });
            let Some(fragments) = fragment(self.id, packet, &address, payload, frame) else {
                return Err(EgressError::DatagramTooLarge {
                    required: payload.len(),
                });
            };
            for datagram in fragments {
                self.connection.send_datagram(datagram).await?;
            }
            Ok(())
        })
    }
}

struct UdpReplies {
    inbound: mpsc::Receiver<(Vec<u8>, Target)>,
    /// Keeps the route registered while this receiver exists.
    _session: Arc<UdpSession>,
}

impl DatagramSource for UdpReplies {
    fn recv_from<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<(usize, Target), EgressError>> {
        Box::pin(async move {
            let (payload, from) = self.inbound.recv().await.ok_or(EgressError::Quic)?;
            let Some(into) = buf.get_mut(..payload.len()) else {
                return Err(EgressError::DatagramTooLarge {
                    required: payload.len(),
                });
            };
            into.copy_from_slice(&payload);
            Ok((payload.len(), from))
        })
    }
}

impl<B: TunnelBypass + 'static> StreamEgress for Hysteria2Egress<B> {
    fn properties(&self) -> PathProperties {
        PathProperties {
            // Each datagram uses QUIC DATAGRAM; fragments are reassembled before delivery.
            datagram_fidelity: DatagramFidelity::Native,
            overhead_bytes: 0,
            max_datagram_size: None,
            preserves_ecn: false,
            nat_behavior: self.config.nat_behavior,
        }
    }

    fn associate(&self) -> BoxFuture<'_, Result<Association, EgressError>> {
        Box::pin(async move {
            let connection = self.connection().await?;
            let Some(hub) = crate::locked(&self.datagrams).clone() else {
                // Do not emulate unsupported datagrams with silent loss.
                return Err(EgressError::DatagramsUnsupported);
            };
            let (id, inbound) = hub.open();
            let session = Arc::new(UdpSession {
                connection,
                hub,
                id,
                next_packet: std::sync::atomic::AtomicU32::new(1),
            });
            Ok(Association {
                source: Box::new(UdpReplies {
                    inbound,
                    _session: Arc::clone(&session),
                }),
                sink: session,
            })
        })
    }

    fn connect<'a>(
        &'a self,
        target: &'a Target,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncStream>, EgressError>> {
        Box::pin(async move {
            if target.to_string().len() as u64 > MAX_ADDRESS_LEN {
                return Err(ProxyError::Address.into());
            }
            let connection = self.connection().await?;
            let mut stream = connection.open_bidi().await?;

            let mut open = OpenStream::new(target, padding(REQUEST_PADDING)?);
            let ((), surplus) = crate::negotiate(&mut stream, &mut open).await?;
            Ok(Box::new(Prefixed::new(surplus, stream)) as Box<dyn AsyncStream>)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DomainName;

    #[test]
    fn a_tcp_request_is_the_frame_type_then_two_length_prefixed_fields() {
        let target = Target::Domain {
            host: DomainName::new("example.com").unwrap(),
            port: 443,
        };
        let mut out = Vec::new();
        encode_tcp_request(&target, b"pad", &mut out);
        assert_eq!(
            out,
            [
                &[0x44, 0x01][..],
                &[15][..],
                b"example.com:443",
                &[3][..],
                b"pad",
            ]
            .concat()
        );
    }

    #[test]
    fn an_ipv6_target_is_bracketed_in_the_address_string() {
        let target = Target::Ip("[::1]:8080".parse().unwrap());
        let mut out = Vec::new();
        encode_tcp_request(&target, b"", &mut out);
        assert!(
            out.windows(10).any(|window| window == b"[::1]:8080"),
            "encoded as {out:?}"
        );
    }

    #[test]
    fn every_proper_prefix_of_a_response_is_incomplete() {
        let mut frame = vec![0u8, 0x02];
        frame.extend_from_slice(b"ok");
        frame.push(0x04);
        frame.extend_from_slice(b"pppp");

        for cut in 0..frame.len() {
            assert_eq!(
                decode_tcp_response(&frame[..cut]),
                Ok(Decoded::Incomplete),
                "a {cut}-byte prefix decoded"
            );
        }
        assert_eq!(
            decode_tcp_response(&frame),
            Ok(Decoded::Complete {
                value: TcpResponse::Accepted,
                consumed: frame.len(),
            })
        );

        let mut with_payload = frame.clone();
        with_payload.extend_from_slice(b"SSH-2.0-OpenSSH");
        assert_eq!(
            decode_tcp_response(&with_payload),
            Ok(Decoded::Complete {
                value: TcpResponse::Accepted,
                consumed: frame.len(),
            })
        );
    }

    #[test]
    fn a_non_zero_status_is_a_refusal_carrying_its_message() {
        let mut frame = vec![1u8, 0x07];
        frame.extend_from_slice(b"refused");
        frame.push(0x00);
        let Ok(Decoded::Complete { value, .. }) = decode_tcp_response(&frame) else {
            panic!("the frame is complete");
        };
        assert_eq!(value, TcpResponse::Refused("refused".to_owned()));
    }

    #[test]
    fn a_length_beyond_the_protocol_ceiling_is_refused_not_allocated() {
        let mut frame = vec![0u8];
        Writer::new(&mut frame).varint(MAX_MESSAGE_LEN + 1);
        assert_eq!(decode_tcp_response(&frame), Err(ProxyError::Header));

        let mut frame = vec![0u8, 0x00];
        Writer::new(&mut frame).varint(MAX_PADDING_LEN + 1);
        assert_eq!(decode_tcp_response(&frame), Err(ProxyError::Header));
    }

    #[test]
    fn padding_stays_inside_the_reference_range_and_alphabet() {
        for _ in 0..64 {
            let bytes = padding(REQUEST_PADDING).unwrap();
            assert!(
                REQUEST_PADDING.contains(&bytes.len()),
                "length {} outside {REQUEST_PADDING:?}",
                bytes.len()
            );
            assert!(bytes.iter().all(|byte| PADDING_ALPHABET.contains(byte)));
        }
    }

    #[test]
    fn a_udp_message_lays_its_fields_out_where_the_specification_says() {
        let mut out = Vec::new();
        UdpMessage {
            session: 0x0102_0304,
            packet: 0x0506,
            fragment: 2,
            fragments: 5,
            address: "example.com:443",
            payload: b"body",
        }
        .write(&mut out);

        assert_eq!(&out[..4], &[1, 2, 3, 4], "session, uint32 big endian");
        assert_eq!(&out[4..6], &[5, 6], "packet, uint16 big endian");
        assert_eq!(out[6], 2, "fragment index");
        assert_eq!(out[7], 5, "fragment count");
        assert_eq!(out[8], 15, "address length, QUIC varint");
        assert_eq!(&out[9..24], b"example.com:443");
        assert_eq!(&out[24..], b"body");

        let read = UdpMessage::read(&out).expect("what was written reads back");
        assert_eq!(read.session, 0x0102_0304);
        assert_eq!(read.packet, 0x0506);
        assert_eq!(read.fragment, 2);
        assert_eq!(read.fragments, 5);
        assert_eq!(read.address, "example.com:443");
        assert_eq!(read.payload, b"body");
    }

    #[test]
    fn a_malformed_message_is_refused_rather_than_partially_believed() {
        let mut whole = Vec::new();
        UdpMessage {
            session: 1,
            packet: 0,
            fragment: 0,
            fragments: 1,
            address: "198.51.100.7:53",
            payload: b"x",
        }
        .write(&mut whole);
        assert!(UdpMessage::read(&whole).is_some());

        for length in 0..whole.len() {
            assert!(
                UdpMessage::read(&whole[..length]).is_none(),
                "a message cut at {length} bytes is not a message"
            );
        }

        let mut empty_address = whole.clone();
        empty_address[8] = 0;
        assert!(
            UdpMessage::read(&empty_address).is_none(),
            "an address of length zero names nothing"
        );

        let mut not_utf8 = whole.clone();
        not_utf8[9] = 0xff;
        assert!(UdpMessage::read(&not_utf8).is_none(), "the address is text");
    }

    #[test]
    fn every_fragment_fits_the_frame_and_carries_the_address_again() {
        let address = "a-rather-long-name.example.com:443";
        let payload = vec![0xabu8; 4000];
        let fragments =
            fragment(7, 9, address, &payload, MAX_DATAGRAM_FRAME).expect("4000 bytes fragments");

        assert!(fragments.len() > 1, "a 4000-byte payload does not fit one");
        assert!(
            fragments.iter().all(|one| one.len() <= MAX_DATAGRAM_FRAME),
            "and none of the pieces exceeds the frame"
        );

        let mut rebuilt = Vec::new();
        for (index, bytes) in fragments.iter().enumerate() {
            let message = UdpMessage::read(bytes).expect("each fragment is a message");
            assert_eq!(message.session, 7);
            assert_eq!(message.packet, 9, "one identifier across the whole packet");
            assert_eq!(message.fragment, index as u8);
            assert_eq!(message.fragments, fragments.len() as u8);
            assert_eq!(message.address, address, "repeated in every fragment");
            rebuilt.extend_from_slice(message.payload);
        }
        assert_eq!(rebuilt, payload);
    }

    #[test]
    fn a_datagram_that_fits_is_not_fragmented() {
        let fragments =
            fragment(1, 0, "198.51.100.7:53", b"query", MAX_DATAGRAM_FRAME).expect("it fits");
        assert_eq!(fragments.len(), 1);
        assert_eq!(UdpMessage::read(&fragments[0]).unwrap().fragments, 1);
    }

    #[test]
    fn reassembly_needs_every_fragment_and_tolerates_their_order() {
        let address = "198.51.100.7:53";
        let payload: Vec<u8> = (0..3000).map(|byte| byte as u8).collect();
        let fragments = fragment(1, 4, address, &payload, MAX_DATAGRAM_FRAME).unwrap();
        let read = |bytes: &Vec<u8>| -> Vec<u8> { bytes.clone() };

        let mut forward = Defragmenter::default();
        let mut whole = None;
        for bytes in &fragments {
            whole = forward.push(&UdpMessage::read(bytes).unwrap());
        }
        assert_eq!(whole.as_deref(), Some(payload.as_slice()));

        let mut backward = Defragmenter::default();
        let mut whole = None;
        for bytes in fragments.iter().rev().map(read).collect::<Vec<_>>() {
            whole = backward.push(&UdpMessage::read(&bytes).unwrap());
        }
        assert_eq!(whole.as_deref(), Some(payload.as_slice()));

        let mut lossy = Defragmenter::default();
        for bytes in fragments.iter().skip(1) {
            assert!(
                lossy.push(&UdpMessage::read(bytes).unwrap()).is_none(),
                "a packet missing a fragment is a packet that did not arrive"
            );
        }
    }

    #[test]
    fn a_new_packet_discards_the_partial_one_before_it() {
        let address = "198.51.100.7:53";
        let first = fragment(1, 10, address, &vec![1u8; 3000], MAX_DATAGRAM_FRAME).unwrap();
        let second = fragment(1, 11, address, &vec![2u8; 3000], MAX_DATAGRAM_FRAME).unwrap();

        let mut defrag = Defragmenter::default();
        assert!(defrag.push(&UdpMessage::read(&first[0]).unwrap()).is_none());
        let mut whole = None;
        for bytes in &second {
            whole = defrag.push(&UdpMessage::read(bytes).unwrap());
        }
        assert_eq!(
            whole.map(|payload| payload.len()),
            Some(3000),
            "the second packet completes without the first's fragment"
        );
    }

    fn encode_tcp_response(ok: bool, message: &str, padding: &[u8], out: &mut Vec<u8>) {
        Writer::new(out)
            .u8(if ok { 0 } else { 1 })
            .vector_varint(message.as_bytes())
            .vector_varint(padding);
    }

    #[test]
    fn opening_a_stream_writes_the_request_then_reads_its_response() {
        use crate::Negotiation;
        let target = Target::Domain {
            host: crate::DomainName::new("example.com").unwrap(),
            port: 443,
        };
        let mut open = OpenStream::new(&target, b"pad".to_vec());

        let mut request = Vec::new();
        assert!(matches!(
            open.advance(&[], &mut request).unwrap(),
            Decoded::Incomplete
        ));
        let mut expected = Vec::new();
        encode_tcp_request(&target, b"pad", &mut expected);
        assert_eq!(request, expected);

        let mut again = Vec::new();
        open.advance(&[], &mut again).unwrap();
        assert!(again.is_empty());
    }

    #[test]
    fn the_response_is_read_however_the_bytes_are_split() {
        use crate::Negotiation;
        let target = Target::Ip("198.51.100.7:443".parse().unwrap());
        let mut wire = Vec::new();
        encode_tcp_response(true, "ok", b"pad", &mut wire);
        let frame = wire.len();
        wire.extend_from_slice(b"220 banner");

        let mut open = OpenStream::new(&target, Vec::new());
        let mut verdict = None;
        for taken in 0..=wire.len() {
            let mut out = Vec::new();
            verdict = Some(open.advance(&wire[..taken], &mut out).unwrap());
        }
        assert!(
            matches!(verdict, Some(Decoded::Complete { consumed, .. }) if consumed == frame),
            "the frame, and not one byte of the banner behind it"
        );
    }

    #[test]
    fn a_refused_stream_fails_the_dial_and_says_why() {
        use crate::Negotiation;
        let target = Target::Ip("198.51.100.7:443".parse().unwrap());
        let mut wire = Vec::new();
        encode_tcp_response(false, "no such host", b"", &mut wire);

        let mut open = OpenStream::new(&target, Vec::new());
        let error = open.advance(&wire, &mut Vec::new()).unwrap_err();
        assert!(
            matches!(&error, ProxyError::Denied(reason) if reason == "no such host"),
            "{error:?}"
        );
    }
}
