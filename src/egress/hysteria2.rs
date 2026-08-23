//! Hysteria2 as a stream egress.
//!
//! One QUIC connection to the server, authenticated once, carrying every flow
//! as a bidirectional stream. That shape is what makes it worth having: on a
//! lossy long-RTT path a proxy that multiplexes over QUIC does not head-of-line
//! block one flow behind another's retransmit, which every TCP-carried protocol
//! in this crate does.
//!
//! **There is no specification, so the reference implementation is the
//! specification.** Hysteria2 is defined by its implementation rather than by
//! an RFC, so every constant and every field order here was read out of
//! [sing-quic](https://github.com/SagerNet/sing-quic)'s `hysteria2` package
//! before it was written, and then checked against a running server by
//! `tests/interop.rs`. A protocol with no written-down wire format is one where
//! self-testing proves the least.
//!
//! **Authentication is an ordinary HTTP/3 request, and then HTTP/3 is done.**
//! The client `POST`s to `https://hysteria/auth` with the password in a header
//! and expects status **233**, which is not an HTTP status code — it is a
//! sentinel chosen so that anything scanning the endpoint, including a browser,
//! gets a response indistinguishable from a plain web server's. After that the
//! connection carries raw streams; see [`crate::egress::quic`] for why the HTTP/3 layer
//! must be dropped before the first one is opened.
//!
//! **Padding is mandatory on both messages**, which is a lesson this crate has
//! already paid for once: Shadowsocks 2022 rejected our sessions because a
//! header with neither payload nor padding leaks its length exactly. Hysteria2
//! pads for the same reason, and the sizes here are the reference's own ranges
//! rather than invented ones, because a *different* padding distribution is
//! itself a fingerprint.

use std::{net::SocketAddr, ops::Range, sync::Arc, time::Duration};

use ring::rand::SecureRandom;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

use crate::{
    Association, AsyncStream, BoxFuture, DatagramFidelity, DatagramSink, DatagramSource, Decoded,
    EgressError, NatBehavior, PathProperties, Prefixed, ProxyError, StreamEgress, Target,
    TunnelBypass,
    egress::quic::{Handshake, QuicConnection, client_config},
    wire::{Reader, Writer, varint_len},
};

/// The `:authority` and `:path` the authentication request carries. Fixed
/// strings, not a real host: the request never leaves the QUIC connection it is
/// sent on, so the authority names the protocol rather than a name to resolve.
const AUTH_AUTHORITY: &str = "hysteria";
const AUTH_PATH: &str = "/auth";

/// Header names, lowercase because HTTP/3 requires it.
const HEADER_AUTH: &[u8] = b"hysteria-auth";
const HEADER_CC_RX: &[u8] = b"hysteria-cc-rx";
const HEADER_PADDING: &[u8] = b"hysteria-padding";
/// Whether the server will carry datagrams. Read and reported rather than
/// acted on, because this egress does not implement Hysteria2's UDP yet.
const HEADER_UDP: &str = "hysteria-udp";

/// Authentication succeeded. Deliberately not a real HTTP status: a probe that
/// is not a Hysteria2 client sees an ordinary rejection instead.
const STATUS_AUTH_OK: u16 = 233;

/// The frame type that opens a TCP proxy stream.
const FRAME_TCP_REQUEST: u64 = 0x401;

/// Ceilings from the reference, which exist so a hostile server cannot make a
/// client allocate without bound. They are checked here for the same reason:
/// a length is a promise from an untrusted peer.
const MAX_ADDRESS_LEN: u64 = 2048;
const MAX_MESSAGE_LEN: u64 = 2048;
const MAX_PADDING_LEN: u64 = 4096;

/// Padding sizes, half-open exactly as the reference writes them. Matching the
/// distribution matters as much as padding at all: a client whose padding is
/// uniformly the wrong width is more identifiable than one that does not pad.
const AUTH_PADDING: Range<usize> = 256..2048;
const REQUEST_PADDING: Range<usize> = 64..512;

/// The alphabet the reference pads with. ASCII alphanumerics, so the padding
/// looks like the header values around it rather than like a block of entropy.
const PADDING_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// How long a connection may sit idle before QUIC closes it. The reference uses
/// 30 seconds with a 10-second keepalive; this is the same ceiling, and the
/// driver's timer handles the rest.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Random padding of a length drawn from `range`.
///
/// Both the length and the contents are random, and both come from the same
/// CSPRNG the rest of the crate uses. O(range.end).
fn padding(range: Range<usize>) -> Result<Vec<u8>, ProxyError> {
    let random = ring::rand::SystemRandom::new();
    let mut choice = [0u8; 2];
    random.fill(&mut choice).map_err(|_| ProxyError::Crypto)?;
    let span = range.end - range.start;
    let length = range.start + usize::from(u16::from_be_bytes(choice)) % span;

    let mut bytes = vec![0u8; length];
    random.fill(&mut bytes).map_err(|_| ProxyError::Crypto)?;
    for byte in &mut bytes {
        // Modulo bias over a 62-symbol alphabet is irrelevant here: the padding
        // conveys nothing, and only its length is observable on the wire.
        *byte = PADDING_ALPHABET[usize::from(*byte) % PADDING_ALPHABET.len()];
    }
    Ok(bytes)
}

/// Writes the frame that opens a proxy stream.
///
/// `varint(0x401) || varint(len) || address || varint(len) || padding`, where
/// the address is the target's text form — `host:port`, with an IPv6 literal
/// bracketed. Hysteria2 sends a *string* rather than a typed address, which is
/// why this shares nothing with SOCKS5's or VLESS's encoders.
///
/// Padding is a parameter rather than generated here so the encoder stays pure
/// and its output is a function of its inputs, which is what lets a test assert
/// the layout byte for byte.
///
/// O(address length + padding length).
pub fn encode_tcp_request(target: &Target, padding: &[u8], out: &mut Vec<u8>) {
    let address = target.to_string();
    Writer::new(out)
        .varint(FRAME_TCP_REQUEST)
        .vector_varint(address.as_bytes())
        .vector_varint(padding);
}

/// What the server answered when asked to open a stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TcpResponse {
    /// Status zero. The stream carries payload from here.
    Accepted,
    /// Any non-zero status, carrying the server's explanation — capped at the
    /// protocol's 2048-byte ceiling by the decoder.
    ///
    /// A sum rather than `{ ok: bool, message: String }`, because that pair
    /// admitted an acceptance carrying a refusal reason and a refusal
    /// explaining nothing. Only one of the two fields was ever meaningful at a
    /// time, and which one is exactly what `status` decides.
    Refused(String),
}

/// Reads the response frame: `status || vstring(message) || vbytes(padding)`.
///
/// [`Decoded::Incomplete`] for every proper prefix, so a caller can read and
/// retry; the `consumed` count is what lets it keep the payload that followed.
///
/// O(message length + padding length), and it allocates only for the message.
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
    // A message that is not UTF-8 is a malformed frame rather than a lossy
    // one: it is the server's own diagnostic text, and mangling it would put
    // replacement characters into an operator's logs.
    let message = std::str::from_utf8(message)
        .map_err(|_| ProxyError::Header)?
        .to_owned();
    Ok(Decoded::Complete {
        // The reference treats every non-zero status as a refusal.
        value: match status {
            0 => TcpResponse::Accepted,
            _ => TcpResponse::Refused(message),
        },
        consumed: reader.position(),
    })
}

/// Static configuration for one Hysteria2 server.
pub struct Hysteria2Config {
    /// The server's UDP endpoint.
    pub server: SocketAddr,
    /// The name presented in SNI and verified against the server's certificate.
    pub server_name: String,
    /// The shared password, sent verbatim in the authentication header.
    pub password: String,
    /// What RFC 4787 mapping behavior the server's own egress provides.
    ///
    /// Configuration for the same reason MASQUE's and SOCKS5's are: the mapping
    /// belongs to the server and is unobservable from here, so the planner is
    /// entitled to a measured claim rather than an optimistic constant.
    pub nat_behavior: NatBehavior,
}

/// Builds the `quiche::Config` for one connection.
///
/// A factory rather than a value because `quiche::Config` is neither `Clone`
/// nor reusable across connections, and this egress redials when its connection
/// dies. Certificate verification is set here, by the caller, for the same
/// reason it is for MASQUE: a test server and a production one differ there and
/// nowhere else.
pub type QuicConfigFactory = Box<dyn Fn() -> Result<quiche::Config, EgressError> + Send + Sync>;

/// Opening one proxied TCP stream: the request frame out, the response frame
/// back.
///
/// A single exchange, so the machine has one conditional and no offset —
/// contrast [`crate::Negotiation`]'s multi-phase users, which have to remember
/// where earlier phases reached.
struct OpenStream {
    /// Taken on the first advance, which is how "write once" is enforced by the
    /// type rather than by a flag.
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

    /// O(response length), which the frame's own varints bound.
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

// ------------------------------------------------------- UDP over QUIC

/// A `UDPMessage`, which is what one QUIC DATAGRAM carries.
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
/// **The address is a string, not a structure.** Hysteria2 writes `host:port`
/// as text and lets the server resolve it, which is why a name survives the
/// crossing intact rather than being resolved on this side — the same property
/// [`Target`] exists to protect everywhere else in this crate.
///
/// There is no frame-type varint and no authentication of its own: this rides
/// inside QUIC, which provides both.
struct UdpMessage<'a> {
    session: u32,
    packet: u16,
    fragment: u8,
    fragments: u8,
    address: &'a str,
    payload: &'a [u8],
}

/// Header bytes before the address: session, packet, fragment, count.
const UDP_FIXED: usize = 4 + 2 + 1 + 1;

/// The reference's `MaxDatagramFrameSize`. A message larger than this must be
/// fragmented or dropped, never truncated.
const MAX_DATAGRAM_FRAME: usize = 1200;

impl UdpMessage<'_> {
    /// Bytes this message's header costs, which is what fragmentation has to
    /// subtract from the frame budget. The address is repeated in *every*
    /// fragment, so this is per fragment rather than per message.
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

    /// Total on untrusted input: every short buffer, over-long length, and
    /// non-UTF-8 address is `None` rather than a panic or a partial read.
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
        // The reference requires at least one payload byte, so a zero-length
        // one is not representable and is refused rather than delivered empty.
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

/// Splits one datagram into as many messages as the frame budget needs.
///
/// **Every fragment repeats the whole header, address included**, which is what
/// makes the budget per fragment rather than amortised, and is what the
/// reference does. `FragCount` is 1 for the ordinary case, where the spec says
/// the packet and fragment identifiers are irrelevant.
///
/// O(payload length). Returns `None` for a payload that cannot be fragmented
/// into at most 255 pieces, which is a datagram no path would carry anyway.
fn fragment(session: u32, packet: u16, address: &str, payload: &[u8]) -> Option<Vec<Vec<u8>>> {
    let budget = MAX_DATAGRAM_FRAME.checked_sub(UdpMessage::header_len(address))?;
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

/// Reassembles one session's fragmented messages.
///
/// **One packet at a time, deliberately.** The reference discards everything it
/// holds the moment a different packet identifier arrives, and so does this: a
/// datagram transport that buffered several partial packets would be a memory
/// pool an attacker fills by sending first fragments, and the spec's own rule —
/// lose one fragment, discard the packet — means nothing held is worth much.
#[derive(Default)]
struct Defragmenter {
    packet: u16,
    fragments: u8,
    /// Fragments in index order, `None` where one has not arrived.
    held: Vec<Option<Vec<u8>>>,
}

impl Defragmenter {
    /// Returns the whole payload once every fragment of one packet is in hand.
    ///
    /// O(1) amortised per fragment, plus one copy of the payload when it
    /// completes.
    fn push(&mut self, message: &UdpMessage<'_>) -> Option<Vec<u8>> {
        // **`<= 1`, not `== 1`, and that is a decision rather than an
        // accident.** The specification says "For packets that are not
        // fragmented, the Fragment Count MUST be set to 1" and is silent on
        // zero, so a zero is a value no conforming sender emits. Both
        // references fill the silence the same way — apernet/hysteria's
        // `Defragger::Feed` and sing-quic's `udpDefragger::feed` each open with
        // `FragCount <= 1`, returning the message whole — and this rides an
        // authenticated connection, where refusing a datagram two reference
        // implementations deliver buys nothing.
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
        // A completed packet leaves nothing behind, so the next first fragment
        // starts from empty rather than from a stale count.
        self.fragments = 0;
        Some(whole)
    }
}

/// A Hysteria2 server as a stream egress.
pub struct Hysteria2Egress<B> {
    config: Hysteria2Config,
    bypass: B,
    quic: QuicConfigFactory,
    /// The shared connection every flow rides on. An async mutex because
    /// establishing one awaits, and because two flows arriving together must
    /// produce *one* connection rather than two — the second waits and finds
    /// the first's.
    connection: Mutex<Option<QuicConnection>>,
    /// The datagram hub for the live connection, or `None` when the server
    /// answered `Hysteria-UDP: false`. Replaced whenever a connection is, since
    /// a session identifier means nothing on a different connection.
    datagrams: Mutex<Option<Arc<Sessions>>>,
    /// Cancels the driver task. Held here so the connection's lifetime is the
    /// egress's: dropping the egress ends the task rather than leaving it
    /// holding a socket nobody can reach.
    shutdown: CancellationToken,
}

impl<B> Drop for Hysteria2Egress<B> {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

impl<B: TunnelBypass> Hysteria2Egress<B> {
    pub fn new(config: Hysteria2Config, bypass: B, quic: QuicConfigFactory) -> Self {
        Self {
            config,
            bypass,
            quic,
            connection: Mutex::new(None),
            datagrams: Mutex::new(None),
            shutdown: CancellationToken::new(),
        }
    }

    /// A `quiche::Config` with Hysteria2's ALPN and the idle timeout the
    /// reference uses, ready for a caller to set verification on.
    pub fn quic_config() -> Result<quiche::Config, EgressError> {
        client_config(quiche::h3::APPLICATION_PROTOCOL, IDLE_TIMEOUT)
    }

    /// The live connection, dialling and authenticating one if there is none.
    ///
    /// Holding the lock across the handshake is deliberate: it is what makes
    /// concurrent first flows share a connection instead of racing to build
    /// two, and a second connection would mean a second authentication and a
    /// second socket for no gain.
    async fn connection(&self) -> Result<QuicConnection, EgressError> {
        let mut held = self.connection.lock().await;
        if let Some(connection) = held.as_ref()
            && connection.is_alive()
        {
            return Ok(connection.clone());
        }

        let socket = self.bypass.udp(self.config.server).await?;
        let mut handshake = Handshake::establish(
            socket,
            self.config.server,
            &self.config.server_name,
            (self.quic)()?,
        )
        .await?;

        let pad = padding(AUTH_PADDING)?;
        let response = handshake
            .http3(&[
                quiche::h3::Header::new(b":method", b"POST"),
                quiche::h3::Header::new(b":scheme", b"https"),
                quiche::h3::Header::new(b":authority", AUTH_AUTHORITY.as_bytes()),
                quiche::h3::Header::new(b":path", AUTH_PATH.as_bytes()),
                quiche::h3::Header::new(HEADER_AUTH, self.config.password.as_bytes()),
                // Zero means "I do not know my own receive bandwidth, use
                // congestion control". Honest: this client runs `quiche`'s
                // CUBIC rather than Hysteria's Brutal, which is a sender-side
                // rate the server would otherwise trust us to have measured.
                quiche::h3::Header::new(HEADER_CC_RX, b"0"),
                quiche::h3::Header::new(HEADER_PADDING, &pad),
            ])
            .await?;

        if response.status != STATUS_AUTH_OK {
            return Err(ProxyError::AuthFailed.into());
        }
        // **The server declares UDP support unilaterally and the client must
        // obey it.** The request says nothing about datagrams; the response
        // says whether any will be carried, and a server that said no "SHOULD
        // silently discard" what a client sends anyway -- so sending would look
        // exactly like a working relay that drops everything.
        let carries_datagrams = response
            .header(HEADER_UDP)
            .is_some_and(|value| matches!(value, "true" | "1" | "t" | "T" | "TRUE" | "True"));

        let connection = handshake.drive(self.shutdown.clone());
        // One hub per connection, started before any session can register, so
        // a session opened immediately after this cannot miss its own replies.
        let hub = if carries_datagrams {
            let hub = Sessions::new();
            hub.serve(&connection, self.shutdown.clone()).await;
            Some(hub)
        } else {
            None
        };
        *self.datagrams.lock().await = hub;
        *held = Some(connection.clone());
        Ok(connection)
    }

    /// The response header a server declares datagram support in.
    pub fn udp_header() -> &'static str {
        HEADER_UDP
    }
}

/// One session's inbound queue: a reassembled datagram and where it came from.
type Route = mpsc::Sender<(Vec<u8>, Target)>;

/// The datagram side of one authenticated connection.
///
/// **One QUIC connection carries every session, so someone has to
/// demultiplex.** Hysteria2 gives each association a 32-bit session identifier
/// and the server echoes it on every reply, so the routing key is in the
/// message — but only one reader may take the connection's datagram stream, so
/// that reader is here and it fans out.
struct Sessions {
    /// Where a session's reassembled datagrams go, by session identifier.
    routes: std::sync::Mutex<std::collections::HashMap<u32, Route>>,
    /// **The client picks these, and the reference starts at 1.** Zero is
    /// avoided for the same reason the reference avoids it as a packet
    /// identifier: it reads as "unset" in a capture.
    next: std::sync::atomic::AtomicU32,
}

impl Sessions {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            routes: std::sync::Mutex::new(std::collections::HashMap::new()),
            next: std::sync::atomic::AtomicU32::new(1),
        })
    }

    /// Starts the one task that reads the connection's datagrams and routes
    /// them. Returns `false` when something already claimed the stream, which
    /// means a hub is already running for this connection.
    async fn serve(self: &Arc<Self>, connection: &QuicConnection, shutdown: CancellationToken) {
        let Some(mut inbound) = connection.receive_datagrams().await else {
            return;
        };
        let hub = Arc::clone(self);
        tokio::spawn(async move {
            // Reassembly is per session, and the map is owned by this task
            // alone -- so a session's partial packet cannot be observed or
            // filled in by any other.
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
                // A malformed datagram is noise, not a failure: it rides an
                // authenticated connection, but a server that speaks a dialect
                // this client does not is not a reason to drop every session.
                let Some(message) = UdpMessage::read(&datagram) else {
                    continue;
                };
                let Some(route) = crate::locked(&hub.routes).get(&message.session).cloned() else {
                    // A session that has gone away. Its reassembly state goes
                    // with it, or a server that kept sending would keep a
                    // buffer alive for a mapping nobody holds.
                    partial.remove(&message.session);
                    continue;
                };
                let Ok(from) = message.address.parse::<SocketAddr>().map(Target::Ip) else {
                    // The reply names where it came from; a name here gives no
                    // address to write into the synthesized packet's source,
                    // and a client discards a reply from an address it did not
                    // dial.
                    continue;
                };
                let Some(whole) = partial.entry(message.session).or_default().push(&message) else {
                    continue;
                };
                if route.try_send((whole, from)).is_err() {
                    // The mapping is gone or is not keeping up. Either way this
                    // is a dropped datagram, which is what a dropped datagram
                    // is.
                    continue;
                }
            }
        });
    }

    /// Registers a session and returns its identifier and inbound queue.
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

/// Datagrams held for one session that is not being drained. Bounded and lossy
/// for the reason every datagram queue here is.
const SESSION_DEPTH: usize = 64;

/// The sending half of one Hysteria2 association.
struct UdpSession {
    connection: QuicConnection,
    hub: Arc<Sessions>,
    id: u32,
    /// Identifies the fragments of one datagram. The reference draws a fresh
    /// one per fragmented packet and leaves it at zero otherwise, which is
    /// exactly what the spec means by "irrelevant" when the count is 1.
    next_packet: std::sync::atomic::AtomicU32,
}

impl Drop for UdpSession {
    /// **The protocol has no way to close a session, so this is the only
    /// signal.** The server releases its port on its own idle timer; what this
    /// releases is the routing entry, without which the hub would keep a
    /// channel alive for a mapping nobody holds.
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
            let Some(fragments) = fragment(self.id, packet, &address, payload) else {
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

/// The receiving half: one session's queue, filled by the hub.
struct UdpReplies {
    inbound: mpsc::Receiver<(Vec<u8>, Target)>,
    /// Held so the routing entry outlives this half too. Without it a caller
    /// that dropped the sink and kept the source would stop receiving.
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
            // **Native: a client datagram is one QUIC DATAGRAM, unreliable and
            // unordered exactly as it was.** Fragmentation is the one caveat
            // and it does not change the claim -- a packet that needs it is
            // reassembled whole or discarded whole, never delivered in pieces.
            //
            // A server that answered `Hysteria-UDP: false` is a separate
            // matter: `associate` refuses, and the flow fails rather than
            // silently disappearing into a relay that discards it.
            datagram_fidelity: DatagramFidelity::Native,
            // A terminated path re-originates the byte stream, so the client's
            // packet size stops existing and there is no per-packet header to
            // charge for.
            overhead_bytes: 0,
            max_datagram_size: None,
            preserves_ecn: false,
            nat_behavior: self.config.nat_behavior,
        }
    }

    /// Opens a datagram association: one session identifier on the connection
    /// every other flow already shares.
    ///
    /// **No handshake and no control stream.** Hysteria2 has neither for UDP --
    /// the first datagram establishes the session by carrying its identifier,
    /// and there is no way to close one, so the server releases its port on its
    /// own idle timer. What this allocates is a routing entry, and dropping the
    /// association is what frees it.
    fn associate(&self) -> BoxFuture<'_, Result<Association, EgressError>> {
        Box::pin(async move {
            let connection = self.connection().await?;
            let Some(hub) = self.datagrams.lock().await.clone() else {
                // The server said it carries none. Refusing is the honest
                // answer: sending anyway would look exactly like a relay that
                // works and drops everything.
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

            // **The response is awaited here rather than lazily**, which costs
            // one round trip before `connect` returns and buys an honest error:
            // a refusal becomes a failed dial, as it does for SOCKS5, instead
            // of surfacing later as an unexplained read error on a stream the
            // caller has already committed to.
            let mut open = OpenStream::new(target, padding(REQUEST_PADDING)?);
            // Anything past the response frame is the target's first payload,
            // which coalesces into the same stream write for every server-first
            // protocol. Replaying it is what keeps a banner from vanishing.
            let ((), surplus) = crate::negotiate(&mut stream, &mut open).await?;
            Ok(Box::new(Prefixed::new(surplus, stream)) as Box<dyn AsyncStream>)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DomainName;

    /// The request layout, byte for byte, against a hand-written expectation.
    /// Padding is passed in rather than generated so this is a total function
    /// of its inputs and the assertion can be exact.
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
                // 0x401 needs the two-byte varint form: 0x40 | 0x04, 0x01.
                &[0x44, 0x01][..],
                &[15][..],
                b"example.com:443",
                &[3][..],
                b"pad",
            ]
            .concat()
        );
    }

    /// An IPv6 target must be bracketed, because the address form is a *string*
    /// and `::1:443` would otherwise be ambiguous with the address itself. This
    /// is `SocketAddr`'s own `Display`, and the test pins that it stays so.
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

    /// The law every streaming decoder in this crate obeys: no proper prefix
    /// decodes, the whole message does, and `consumed` is exact so the caller
    /// can keep what followed.
    #[test]
    fn every_proper_prefix_of_a_response_is_incomplete() {
        // Written as the specification lays the frame out, one literal byte
        // per varint, so this checks the decoder rather than our encoder.
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

        // The payload that follows must be reported as surplus rather than
        // swallowed, which is the whole point of `consumed`.
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

    /// A refusal carries the server's reason, and a non-zero status is what
    /// makes it a refusal.
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

    /// Lengths are a promise from an untrusted peer, so a server claiming a
    /// message larger than the protocol's ceiling is rejected rather than
    /// allocated for.
    #[test]
    fn a_length_beyond_the_protocol_ceiling_is_refused_not_allocated() {
        let mut frame = vec![0u8];
        Writer::new(&mut frame).varint(MAX_MESSAGE_LEN + 1);
        assert_eq!(decode_tcp_response(&frame), Err(ProxyError::Header));

        let mut frame = vec![0u8, 0x00];
        Writer::new(&mut frame).varint(MAX_PADDING_LEN + 1);
        assert_eq!(decode_tcp_response(&frame), Err(ProxyError::Header));
    }

    /// Padding must land inside the reference's range and use its alphabet: a
    /// client that pads differently is distinguishable from one that does not
    /// pad, which defeats the point.
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

    /// The field table from the protocol specification, read back by hand
    /// rather than through this file's own decoder. Round-tripping a codec
    /// against itself proves only self-consistency; the offsets are the thing
    /// a peer agrees with.
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
        // "example.com:443" is 15 bytes, which a one-byte QUIC varint holds.
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

    /// A message is bytes from a server, so every truncation and every
    /// impossible length is `None` rather than a panic or a partial read.
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

    /// **Every fragment repeats the whole header, address included**, so the
    /// budget is per fragment. Getting that wrong by one varint byte makes the
    /// last fragment exceed the frame and the server drop the packet.
    #[test]
    fn every_fragment_fits_the_frame_and_carries_the_address_again() {
        let address = "a-rather-long-name.example.com:443";
        let payload = vec![0xabu8; 4000];
        let fragments = fragment(7, 9, address, &payload).expect("4000 bytes fragments");

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

    /// The ordinary case is one message with a count of 1, where the
    /// specification says the packet and fragment identifiers are irrelevant.
    #[test]
    fn a_datagram_that_fits_is_not_fragmented() {
        let fragments = fragment(1, 0, "198.51.100.7:53", b"query").expect("it fits");
        assert_eq!(fragments.len(), 1);
        assert_eq!(UdpMessage::read(&fragments[0]).unwrap().fragments, 1);
    }

    /// Reassembly in order, out of order, and not at all. **Losing one fragment
    /// discards the packet** — the specification requires it, and a transport
    /// that delivered a hole would be worse than one that delivered nothing.
    #[test]
    fn reassembly_needs_every_fragment_and_tolerates_their_order() {
        let address = "198.51.100.7:53";
        let payload: Vec<u8> = (0..3000).map(|byte| byte as u8).collect();
        let fragments = fragment(1, 4, address, &payload).unwrap();
        let read = |bytes: &Vec<u8>| -> Vec<u8> { bytes.clone() };

        // In order.
        let mut forward = Defragmenter::default();
        let mut whole = None;
        for bytes in &fragments {
            whole = forward.push(&UdpMessage::read(bytes).unwrap());
        }
        assert_eq!(whole.as_deref(), Some(payload.as_slice()));

        // Reversed, which a lossy path produces routinely.
        let mut backward = Defragmenter::default();
        let mut whole = None;
        for bytes in fragments.iter().rev().map(read).collect::<Vec<_>>() {
            whole = backward.push(&UdpMessage::read(&bytes).unwrap());
        }
        assert_eq!(whole.as_deref(), Some(payload.as_slice()));

        // One missing: nothing is ever produced.
        let mut lossy = Defragmenter::default();
        for bytes in fragments.iter().skip(1) {
            assert!(
                lossy.push(&UdpMessage::read(bytes).unwrap()).is_none(),
                "a packet missing a fragment is a packet that did not arrive"
            );
        }
    }

    /// A new packet identifier discards whatever was held. Buffering several
    /// partial packets would be a pool an attacker fills with first fragments,
    /// and the specification's own rule means nothing held is worth much.
    #[test]
    fn a_new_packet_discards_the_partial_one_before_it() {
        let address = "198.51.100.7:53";
        let first = fragment(1, 10, address, &vec![1u8; 3000]).unwrap();
        let second = fragment(1, 11, address, &vec![2u8; 3000]).unwrap();

        let mut defrag = Defragmenter::default();
        assert!(defrag.push(&UdpMessage::read(&first[0]).unwrap()).is_none());
        // Everything from the second packet, which must complete on its own.
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

    /// A response frame as the protocol specification lays it out:
    /// `status || vstring(message) || vbytes(padding)`. Built here rather than
    /// with a shipped encoder, because this crate is a client and never writes
    /// one — so the tests below check the decoder against the specification
    /// instead of against its own inverse.
    fn encode_tcp_response(ok: bool, message: &str, padding: &[u8], out: &mut Vec<u8>) {
        Writer::new(out)
            .u8(if ok { 0 } else { 1 })
            .vector_varint(message.as_bytes())
            .vector_varint(padding);
    }

    /// The exchange, driven without a QUIC connection anywhere. Before the port
    /// this needed a live server: the request and the response read were
    /// sequenced inside `connect`, so there was nothing to hand bytes to.
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

        // A second offer must not write the request again; a server reading two
        // would take the first bytes of the second as payload.
        let mut again = Vec::new();
        open.advance(&[], &mut again).unwrap();
        assert!(again.is_empty());
    }

    /// **Every read boundary.** A response frame is a status byte and two
    /// length-prefixed strings, so a machine that assumed it arrives whole
    /// would work against loopback and stall behind a middlebox.
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

    /// A refusal is a failed dial rather than a stream that fails later, which
    /// is the whole reason the response is awaited at connect.
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
