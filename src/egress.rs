//! Egress implementations and the sum that binds path properties to layer.
//!
//! An [`PathProperties`] value is a claim; an [`Egress`] is the thing the
//! claim is about. Before this module existed, `accepts` was a runtime field
//! that could disagree with the implementation it described. Now the layer is
//! the enum variant and the path properties come from the implementation behind
//! it, so the two cannot drift apart.
//!
//! [`PacketEgress`] is the whole sans-io interface, not just a path-properties
//! report: bytes in, [`EgressEmit`] values out, timers on an explicit `tick`.
//! That is what lets the reactor drive any packet egress without naming
//! WireGuard, and what makes `Box<dyn PacketEgress>` a thing you can run
//! rather than only interrogate.
//!
//! [`WireGuardEgress`] is the first implementation: a sans-io wrapper over
//! GotaTun's `Tunn`. It performs no socket I/O of its own, but it reads the
//! real clock for handshake and rekey timers, so it belongs to the shell side
//! of the pure-core boundary, not to [`crate::Datapath`].
//!
//! Every emitted buffer is [`Pooled`]. The engineering plan's per-packet
//! budget forbids a heap allocation per packet, and an egress sits on the
//! hottest path there is, so its outputs draw on the same single budget the
//! datapath's do; exhaustion is a counted drop, never a wait.

use std::{sync::Arc, time::Duration};

use gotatun::{
    noise::{
        Tunn, TunnResult, errors::WireGuardError, index_table::IndexTable,
        rate_limiter::RateLimiter,
    },
    packet::{Packet, WgKind},
    tun::MtuWatcher,
    x25519::{PublicKey, StaticSecret},
};

use crate::{
    Accepts, BufferPool, ChainError, DatagramFidelity, Mtu, NatBehavior, PathProperties, Pooled,
    ProxyError, TunnelBypass,
};

/// An egress that accepts whole IP packets, such as WireGuard or MASQUE
/// CONNECT-IP.
///
/// Emissions go into a caller-owned sink rather than a returned `Vec`, so the
/// reactor reuses one buffer for the life of the process and a packet costs no
/// allocation for the container it travels in. The sink is appended to, never
/// cleared: one call may legitimately produce a handshake response for the
/// network *and* a packet for the tunnel, and a caller batching several calls
/// keeps their order.
pub trait PacketEgress: Send {
    /// The path properties the planner sees. The accepted layer is not part
    /// of it: the [`Egress`] variant already says so.
    fn properties(&self) -> PathProperties;

    /// Accepts one whole IP packet from the tunnel side, bound outward.
    fn handle_tun_packet(
        &mut self,
        packet: &[u8],
        out: &mut Vec<EgressEmit>,
    ) -> Result<(), EgressError>;

    /// Accepts one datagram from the network, bound inward.
    fn handle_network_packet(
        &mut self,
        datagram: &[u8],
        out: &mut Vec<EgressEmit>,
    ) -> Result<(), EgressError>;

    /// The largest datagram this egress's peer can send it, which is what sizes
    /// the reactor's network receive buffer.
    ///
    /// The default is the ceiling a UDP payload length field can express, which
    /// is safe for every protocol and precise for none: over-sizing a receive
    /// buffer costs one allocation for the life of the process, under-sizing it
    /// truncates a valid datagram into a malformed one. An implementation that
    /// knows its own framing overrides this with the real bound.
    fn max_network_datagram(&self) -> usize {
        usize::from(u16::MAX)
    }

    /// Drives the implementation's own timers: handshake retries, rekeys,
    /// expiry, keepalives.
    fn tick(&mut self, out: &mut Vec<EgressEmit>) -> Result<(), EgressError>;

    /// How often [`tick`](Self::tick) must be called. The implementation owns
    /// its own cadence, so the shell arms a timer rather than knowing any
    /// protocol's timer granularity.
    fn tick_interval(&self) -> Duration;

    /// The next instant this egress must be ticked, when it can name one more
    /// precisely than its cadence.
    ///
    /// WireGuard rounds its timers to the second, so a fixed interval is the
    /// whole truth for it and the default `None` is correct. QUIC's timer is a
    /// deadline that moves with loss recovery, so a MASQUE egress that could
    /// only be ticked on a cadence would either burn wakeups or miss a
    /// retransmission. The reactor folds this into the one timer it already
    /// arms, which is what keeps the wakeup budget a property of the session
    /// rather than of each protocol.
    fn next_deadline(&self) -> Option<std::time::Instant> {
        None
    }
}

/// A boxed packet egress is itself one.
///
/// The shape of an egress is a deployment's choice and therefore not known
/// until runtime, so the reactor is handed a `Box<dyn PacketEgress>` — and the
/// reactor is generic over `E: PacketEgress`, not over a box. This impl is what
/// joins the two, exactly as [`crate::ProxyTransport`]'s does for a transport
/// chain.
impl PacketEgress for Box<dyn PacketEgress> {
    fn properties(&self) -> PathProperties {
        (**self).properties()
    }

    fn handle_tun_packet(
        &mut self,
        packet: &[u8],
        out: &mut Vec<EgressEmit>,
    ) -> Result<(), EgressError> {
        (**self).handle_tun_packet(packet, out)
    }

    fn handle_network_packet(
        &mut self,
        datagram: &[u8],
        out: &mut Vec<EgressEmit>,
    ) -> Result<(), EgressError> {
        (**self).handle_network_packet(datagram, out)
    }

    fn max_network_datagram(&self) -> usize {
        (**self).max_network_datagram()
    }

    fn tick(&mut self, out: &mut Vec<EgressEmit>) -> Result<(), EgressError> {
        (**self).tick(out)
    }

    fn tick_interval(&self) -> Duration {
        (**self).tick_interval()
    }

    fn next_deadline(&self) -> Option<std::time::Instant> {
        (**self).next_deadline()
    }
}

/// A domain name as a proxy protocol carries it: at most 255 bytes, because
/// that is what a single length octet can describe on the SOCKS5, Shadowsocks,
/// VLESS, and TUIC wires alike.
///
/// Refined rather than a bare `String`: the wire limit is an invariant every
/// encoder would otherwise have to re-check, and an over-long name would be
/// discovered as a truncated address on the far side rather than as a rejected
/// configuration here.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DomainName(String);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainNameError {
    Empty,
    TooLong(usize),
    /// A NUL byte, which no name has and every C-shaped parser downstream
    /// would misread.
    Interior,
}

impl DomainName {
    /// The one boundary untrusted text crosses to become a name.
    ///
    /// **The name is normalized to lower case here, and that is the point of
    /// having a boundary.** DNS labels and TLS server names are
    /// case-insensitive, so `Example.com` and `example.com` are one host — and
    /// every consumer that compared them as strings was lower-casing its input
    /// again, once per connection, once per request, once per response. Doing
    /// it once at construction makes "a `DomainName` is lower case" an
    /// invariant those consumers can read instead of re-establish.
    ///
    /// O(bytes), with the allocation the caller was going to make anyway and
    /// an in-place fold rather than a second one.
    pub fn new(name: impl Into<String>) -> Result<Self, DomainNameError> {
        let mut name = name.into();
        match name.len() {
            0 => Err(DomainNameError::Empty),
            length if length > 255 => Err(DomainNameError::TooLong(length)),
            _ if name.as_bytes().contains(&0) => Err(DomainNameError::Interior),
            _ => {
                name.make_ascii_lowercase();
                Ok(Self(name))
            }
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Always 255 or fewer, which is what makes the single length octet on
    /// every proxy wire safe to write without a second check.
    pub fn wire_len(&self) -> u8 {
        self.0.len() as u8
    }
}

impl std::fmt::Display for DomainName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where a flow is bound.
///
/// A name is kept as a name when the client supplied one, rather than being
/// resolved here and sent as an address. Two reasons, and both are properties
/// of the product: the exit resolves in its own DNS view, so a CDN answers
/// with a nearby edge instead of one near the client; and a name resolved
/// locally would leak the destination to the local resolver the tunnel exists
/// to bypass.
/// `Hash`, because a proxy whose datagram framing binds a stream to one
/// destination has to key its streams by it — VLESS is that proxy, and the
/// alternative is a linear scan per datagram.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Target {
    Ip(std::net::SocketAddr),
    Domain { host: DomainName, port: u16 },
}

impl Target {
    pub fn port(&self) -> u16 {
        match self {
            Self::Ip(address) => address.port(),
            Self::Domain { port, .. } => *port,
        }
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(address) => write!(f, "{address}"),
            Self::Domain { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

/// The byte stream a stream egress hands back: exactly what `hyper` and the
/// interception exchange already consume, so a proxied flow and a direct one
/// are the same type to everything above.
pub trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> AsyncStream for T {}

/// A stream that yields a prefix before anything the underlying stream has.
///
/// **This exists because a handshake reader over-reads, and the surplus is
/// payload.** Every proxy in this crate reads a variable-length reply from a
/// byte stream, so it must read *at least* the reply and may read past it —
/// TCP does not preserve the sender's boundaries, and a server-first protocol
/// (SSH, SMTP, IMAP) sends its banner the instant the proxy connects, which
/// arrives coalesced into the same segment as the reply for exactly the flows
/// where it matters most. Discarding the surplus truncates the response with no
/// error anywhere, so the decoder reports how many bytes it consumed and the
/// rest is replayed here.
///
/// O(1) per read, and the prefix is freed as soon as it is drained.
pub struct Prefixed<S> {
    prefix: bytes::Bytes,
    inner: S,
}

impl<S> Prefixed<S> {
    /// Wraps `inner` only when there is something to replay, so the common case
    /// of an exact read costs neither an allocation nor an extra layer of
    /// polling.
    pub fn new(prefix: Vec<u8>, inner: S) -> Either<Prefixed<S>, S> {
        if prefix.is_empty() {
            Either::Right(inner)
        } else {
            Either::Left(Self {
                prefix: prefix.into(),
                inner,
            })
        }
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Prefixed<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !this.prefix.is_empty() {
            use bytes::Buf;
            let moved = buf.remaining().min(this.prefix.len());
            buf.put_slice(&this.prefix[..moved]);
            this.prefix.advance(moved);
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Prefixed<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// One of two stream types, so a wrapper can be skipped when it would be
/// nothing but a passthrough. A sum rather than boxing: the choice is made once
/// per flow and the variant is known statically at every use.
pub enum Either<L, R> {
    Left(L),
    Right(R),
}

impl<L, R> tokio::io::AsyncRead for Either<L, R>
where
    L: tokio::io::AsyncRead + Unpin,
    R: tokio::io::AsyncRead + Unpin,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Left(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            Self::Right(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl<L, R> tokio::io::AsyncWrite for Either<L, R>
where
    L: tokio::io::AsyncWrite + Unpin,
    R: tokio::io::AsyncWrite + Unpin,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Left(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            Self::Right(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Left(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            Self::Right(stream) => std::pin::Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Left(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            Self::Right(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// A future returned through a trait object. Boxing is a per-flow cost, paid
/// once at connect and amortised over every byte the flow then carries, which
/// is why it is acceptable here and would not be on the packet path.
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The sending half of a datagram association through a proxy, as SOCKS5's UDP
/// ASSOCIATE, Shadowsocks, and VLESS all provide it.
///
/// Send names the *target*, because a proxied datagram carries its destination
/// in the payload rather than in the socket: one association serves every peer
/// the flow talks to, which is what makes an endpoint-independent mapping
/// expressible at all.
///
/// `Sync`, and shared: every live flow sends through the one association.
pub trait DatagramSink: Send + Sync {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        target: &'a Target,
    ) -> BoxFuture<'a, Result<(), EgressError>>;
}

/// The receiving half.
///
/// **Owned by exactly one reader, and `&mut` says so.** Two readers of one
/// datagram association would race for each arriving datagram, which is not a
/// thing any caller wants; making the receive half affine states that in the
/// type instead of in a comment, and it is also what lets an implementation
/// hold its own framing buffer rather than allocating one per datagram.
pub trait DatagramSource: Send {
    /// Returns the payload length written into `buf` and where it came from.
    ///
    /// A payload larger than `buf` is [`EgressError::DatagramTooLarge`], never
    /// a short success: a datagram is an indivisible message, so half of one is
    /// not a smaller one.
    fn recv_from<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<(usize, Target), EgressError>>;
}

/// One datagram association, split into the half that is shared and the half
/// that is owned. The split is the ownership model, not a convenience: it is
/// what makes concurrent sending safe without making concurrent receiving
/// expressible.
pub struct Association {
    pub sink: Arc<dyn DatagramSink>,
    pub source: Box<dyn DatagramSource>,
}

/// An egress that accepts L4 flows, such as SOCKS5 or Shadowsocks.
///
/// This is also the seam local termination dials through: interception
/// terminates the client's connection and then needs one to the real server,
/// and "open a byte stream to this target" is the same question a proxy
/// answers. A direct TCP dialer is the identity instance of it.
pub trait StreamEgress: Send + Sync {
    /// The path properties the planner sees. The accepted layer is not part
    /// of it: the [`Egress`] variant already says so.
    fn properties(&self) -> PathProperties;

    /// Opens a byte stream to `target`.
    fn connect<'a>(
        &'a self,
        target: &'a Target,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncStream>, EgressError>>;

    /// Opens a datagram association.
    ///
    /// The default refuses, which is the honest answer for an egress whose
    /// [`PathProperties::datagram_fidelity`] is
    /// [`DatagramFidelity::None`](crate::DatagramFidelity::None): those two
    /// statements must agree, and an egress that does not implement this has
    /// already said so in its claim.
    fn associate(&self) -> BoxFuture<'_, Result<Association, EgressError>> {
        Box::pin(async { Err(EgressError::DatagramsUnsupported) })
    }
}

/// The identity [`StreamEgress`]: it opens the connection the client asked for,
/// to the address the client asked for, and adds nothing.
///
/// **The most common configuration in the product this serves.** A content
/// blocker filters what crosses without moving where it goes, so its egress is
/// the one that does nothing — and without this type that configuration was the
/// one thing the crate could not express, since every other egress is a proxy.
///
/// It dials through [`TunnelBypass`](crate::TunnelBypass) rather than through
/// `TcpStream::connect`, which is the whole reason it is not trivial: a
/// re-originated connection that went out over the default route would re-enter
/// Boreas's own TUN and be terminated again, forever. The bypass is what the
/// platform uses to exclude it, and naming the obligation here is what stops it
/// being forgotten.
pub struct DirectEgress<B> {
    bypass: B,
    /// Mapping behaviour reported to the planner. Configuration rather than a
    /// constant because it is the *host's* NAT that governs here, not a
    /// proxy's: a phone behind a carrier-grade NAT and a desktop with a public
    /// address are the same code and different answers.
    nat_behavior: NatBehavior,
}

impl<B: TunnelBypass> DirectEgress<B> {
    pub fn new(bypass: B, nat_behavior: NatBehavior) -> Self {
        Self {
            bypass,
            nat_behavior,
        }
    }
}

impl<B: TunnelBypass + 'static> StreamEgress for DirectEgress<B> {
    fn properties(&self) -> PathProperties {
        PathProperties {
            // **Native, because there is nothing in the way.** A datagram sent
            // here is the datagram the host stack sends, so QUIC survives, and
            // the association below is one ordinary connected socket.
            datagram_fidelity: DatagramFidelity::Native,
            // Nothing is encapsulated, so nothing is charged. The client's own
            // path MTU governs and this adds no header to it.
            overhead_bytes: 0,
            max_datagram_size: None,
            preserves_ecn: false,
            nat_behavior: self.nat_behavior,
        }
    }

    fn connect<'a>(
        &'a self,
        target: &'a Target,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncStream>, EgressError>> {
        Box::pin(async move {
            let address = crate::origin::resolve(target).await?;
            let stream = crate::within(crate::Wait::TcpConnect, self.bypass.tcp(address)).await?;
            // Nagle would hold a short request waiting for bytes that are not
            // coming, which on a re-originated exchange is pure added latency.
            stream.set_nodelay(true)?;
            Ok(Box::new(stream) as Box<dyn AsyncStream>)
        })
    }

    /// **One socket per client mapping, not per target**, which is what makes
    /// the endpoint-independent claim above true: the same socket carries
    /// datagrams to every peer the mapping talks to, so a peer sees one source
    /// port for the life of the association exactly as it would without Boreas.
    fn associate(&self) -> BoxFuture<'_, Result<Association, EgressError>> {
        Box::pin(async move {
            // Unconnected: `send_to` names a different peer per datagram, which
            // a connected socket forbids. Bound through the bypass so the
            // socket leaves by a route that is not the tunnel.
            let relay = Arc::new(DirectRelay(self.bypass.unbound().await?));
            Ok(Association {
                source: Box::new(DirectSource {
                    relay: Arc::clone(&relay),
                }),
                sink: relay,
            })
        })
    }
}

/// One unbound socket, shared by the association's two halves. A newtype rather
/// than an impl on tokio's socket, so this crate's trait stays this crate's.
struct DirectRelay(tokio::net::UdpSocket);

impl DatagramSink for DirectRelay {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        target: &'a Target,
    ) -> BoxFuture<'a, Result<(), EgressError>> {
        Box::pin(async move {
            let address = crate::origin::resolve(target).await?;
            self.0.send_to(payload, address).await?;
            Ok(())
        })
    }
}

struct DirectSource {
    relay: Arc<DirectRelay>,
}

impl DatagramSource for DirectSource {
    fn recv_from<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<(usize, Target), EgressError>> {
        Box::pin(async move {
            let (len, from) = self.relay.0.recv_from(buf).await?;
            Ok((len, Target::Ip(from)))
        })
    }
}

/// A configured egress implementation. The variant determines the accepted
/// layer, which is what makes a mismatched `accepts` field unconstructable.
pub enum Egress {
    Packet(Box<dyn PacketEgress>),
    Stream(Box<dyn StreamEgress>),
}

impl Egress {
    /// The layer this egress accepts, derived from the variant.
    pub fn accepts(&self) -> Accepts {
        match self {
            Self::Packet(_) => Accepts::IpPackets,
            Self::Stream(_) => Accepts::Flows,
        }
    }

    /// The path properties of the implementation behind the variant.
    pub fn properties(&self) -> PathProperties {
        match self {
            Self::Packet(egress) => egress.properties(),
            Self::Stream(egress) => egress.properties(),
        }
    }

    /// Chains two egresses' path properties. Layer agreement is now a genuine
    /// configuration conflict — a packet egress cannot carry a stream
    /// egress's flows — so `MixedLayers` is reported here, where the
    /// implementations are known, rather than between two bare claims.
    pub fn chain(first: &Egress, next: &Egress) -> Result<PathProperties, ChainError> {
        if first.accepts() != next.accepts() {
            return Err(ChainError::MixedLayers);
        }
        first.properties().chain(next.properties())
    }
}

/// Total WireGuard encapsulation overhead over an IPv6 underlay: 40 bytes of
/// outer IPv6, 8 of UDP, and 32 of WireGuard header and authentication tag.
/// IPv4 underlays cost 60; path properties report the worst case so the inner
/// MTU never exceeds reality on either underlay.
pub const WIREGUARD_OVERHEAD_BYTES: u16 = 80;

/// Match GotaTun's own device: handshake initiations per second per peer.
const HANDSHAKE_RATE_LIMIT: u64 = 100;

/// GotaTun's own device ticks every 250 ms. WireGuard rounds its timers to the
/// second, so any cadence in that range is correct; this one matches the
/// reference implementation rather than inventing a number.
const WIREGUARD_TICK: Duration = Duration::from_millis(250);

/// The bytes a WireGuard data message adds to the packet it carries: a 16-byte
/// message header (type, receiver index, counter) plus the 16-byte Poly1305
/// tag. Handshake messages are all smaller than a full data message, so this
/// bounds every datagram a peer can send.
const WIREGUARD_FRAMING_BYTES: usize = 32;

/// WireGuard pads a data payload up to a 16-byte multiple, so the largest
/// message a peer can send is the padded MTU plus the framing above.
const WIREGUARD_PADDING_ALIGNMENT: usize = 16;

/// Buffers pre-allocated for the tunnel's own staging.
///
/// One packet is in the tunnel at a time on this reactor, so the steady state
/// needs a handful; the pool grows on demand and recycles on drop, so this is a
/// warm-up rather than a ceiling. Each buffer is GotaTun's default 4096 bytes,
/// which is 64 KiB pre-allocated in total.
const TUNNEL_BUFFERS: usize = 16;

/// Static configuration for one WireGuard peer. Keys are fixed-size arrays,
/// so validity is structural and there is nothing to validate at runtime.
pub struct WireGuardConfig {
    pub private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    /// Keepalive interval in seconds; `None` disables it.
    pub persistent_keepalive: Option<u16>,
    /// The tunnel MTU, used to pad data packets to a 16-byte multiple without
    /// exceeding it, per the WireGuard protocol's padding rule.
    pub inner_mtu: Mtu,
}

/// What the sans-io egress produced, for the shell to deliver. Keeping the
/// two destinations in one sum means a handler's caller cannot lose half of a
/// handshake exchange: a decapsulation can legitimately produce both a
/// handshake response for the network and a packet for the tunnel.
#[derive(Debug, PartialEq, Eq)]
pub enum EgressEmit {
    /// A UDP payload for the WireGuard peer's endpoint.
    ToNetwork(Pooled),
    /// A decrypted IP packet for the datapath's egress side.
    ToTunnel(Pooled),
}

#[derive(Debug)]
pub enum EgressError {
    /// Bytes from the UDP socket that are not a WireGuard packet. Routine on a
    /// public port; the caller counts and continues.
    MalformedNetworkPacket,
    /// The shared buffer pool had no room for an emission. A drop, never a
    /// wait, on the same budget every other payload draws from.
    PoolExhausted,
    /// The tunnel itself failed, e.g. `ConnectionExpired` once the handshake
    /// has been retried past its limit.
    WireGuard(WireGuardError),
    /// A MASQUE tunnel could not be configured or driven. Construction-time or
    /// protocol-level, never a per-packet condition.
    Masque,
    /// A QUIC connection could not be established, authenticated, or driven —
    /// the transport under a QUIC-based egress rather than that egress's own
    /// protocol, which is why it is distinct from [`Self::Proxy`].
    Quic,
    /// This egress carries no datagrams, which its path properties already
    /// says: `datagram_fidelity` is `None` and `associate` refuses.
    DatagramsUnsupported,
    /// A datagram arrived that will not fit the buffer offered for it. Explicit
    /// rather than a truncated success: the boundary of a datagram is the thing
    /// a relay claiming native fidelity promises to preserve, and half a QUIC
    /// packet is not a smaller QUIC packet.
    DatagramTooLarge { required: usize },
    /// The proxy refused, or spoke something this client could not parse.
    Proxy(ProxyError),
    /// The transport under the proxy failed: no route, refused, reset.
    Io(std::io::ErrorKind),
}

impl std::fmt::Display for EgressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedNetworkPacket => f.write_str("not a WireGuard packet"),
            Self::PoolExhausted => f.write_str("no pooled buffer for the emission"),
            // GotaTun's error type is a plain enum without `Display`; Debug
            // names the variant, which is what an operator needs.
            Self::WireGuard(error) => write!(f, "WireGuard failure: {error:?}"),
            Self::Masque => f.write_str("MASQUE tunnel failure"),
            Self::Quic => f.write_str("QUIC connection failure"),
            Self::DatagramsUnsupported => f.write_str("this egress carries no datagrams"),
            Self::DatagramTooLarge { required } => {
                write!(f, "the datagram needs {required} bytes of buffer")
            }
            Self::Proxy(error) => write!(f, "proxy failure: {error}"),
            Self::Io(kind) => write!(f, "transport failure: {kind}"),
        }
    }
}

impl std::error::Error for EgressError {}

impl From<std::io::Error> for EgressError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.kind())
    }
}

impl From<ProxyError> for EgressError {
    fn from(error: ProxyError) -> Self {
        Self::Proxy(error)
    }
}

impl From<WireGuardError> for EgressError {
    fn from(error: WireGuardError) -> Self {
        Self::WireGuard(error)
    }
}

/// A WireGuard peer as a packet egress. Packets in, datagrams out, timers on
/// an explicit tick; the UDP socket and its endpoint live in the shell.
pub struct WireGuardEgress {
    tunn: Tunn,
    mtu: MtuWatcher,
    /// The same number [`Self::mtu`] watches, kept as the refined type so the
    /// receive-buffer bound can be read without the `&mut` the watcher's own
    /// accessor requires.
    inner_mtu: Mtu,
    pool: Arc<BufferPool>,
    /// Scratch for [`Self::flush_queue`], kept so a call that finds nothing to
    /// flush — which is nearly every call — costs no allocation.
    queued: Vec<WgKind>,
    /// GotaTun's own recycled buffers, for the packets handed *into* the
    /// tunnel.
    ///
    /// **The second budget, and it is not a duplicate of the first.**
    /// [`BufferPool`] holds what this crate owns — packets on their way to a
    /// device or a socket. This one holds what `Tunn` owns while it encrypts or
    /// decrypts, which is a different lifetime and a different allocator's
    /// buffer type. Without it, every packet in either direction cost a
    /// `BytesMut` allocation, which is exactly the per-packet heap cost the
    /// engineering plan's budget forbids.
    packets: gotatun::packet::PacketBufPool,
    /// IP packets encapsulated so far. This is the fast-path counter: every
    /// one of these is a packet that bypassed local termination entirely.
    fast_path_packets: u64,
}

impl WireGuardEgress {
    /// `pool` is the same budget the datapath draws on; its slice size must
    /// admit an encapsulated packet, which is `inner_mtu + 32` bytes.
    pub fn new(config: WireGuardConfig, pool: Arc<BufferPool>) -> Self {
        let private_key = StaticSecret::from(config.private_key);
        let our_public = PublicKey::from(&private_key);
        Self {
            tunn: Tunn::new(
                private_key,
                PublicKey::from(config.peer_public_key),
                config.preshared_key,
                config.persistent_keepalive,
                IndexTable::from_os_rng(),
                Arc::new(RateLimiter::new(&our_public, HANDSHAKE_RATE_LIMIT)),
            ),
            mtu: MtuWatcher::new(config.inner_mtu.get()),
            inner_mtu: config.inner_mtu,
            pool,
            queued: Vec::new(),
            packets: gotatun::packet::PacketBufPool::new(TUNNEL_BUFFERS),
            fast_path_packets: 0,
        }
    }

    /// The fast-path counter behind the M1 gate: every packet counted here
    /// was encapsulated directly and never entered local termination.
    pub fn fast_path_packets(&self) -> u64 {
        self.fast_path_packets
    }

    /// Packets queued while no session existed, encapsulated once one does.
    ///
    /// Staged through a scratch buffer because `get_queued_packets` borrows the
    /// tunnel mutably and `network_emit` borrows the pool; the queue is bounded
    /// by the tunnel's own depth and is empty on every packet but the one that
    /// completes a handshake. The buffer is *taken out of* `self` and put back,
    /// so it keeps its capacity across calls — this runs on every inbound
    /// datagram and every tick, which is exactly where a fresh `Vec` per call
    /// would be a steady-state cost with no steady-state work.
    fn flush_queue(&mut self, out: &mut Vec<EgressEmit>) -> Result<(), EgressError> {
        let mut queued = std::mem::take(&mut self.queued);
        queued.clear();
        queued.extend(self.tunn.get_queued_packets(&mut self.mtu));
        let result = queued
            .drain(..)
            .try_for_each(|kind| self.network_emit(kind).map(|emit| out.push(emit)));
        self.queued = queued;
        result
    }

    /// Stages `bytes` in a recycled tunnel buffer.
    ///
    /// Falls back to an owned copy for a packet larger than a pooled buffer,
    /// which a jumbo-MTU tunnel can produce: correctness first, and the pool's
    /// fixed slice is a performance property rather than a limit on what can be
    /// carried.
    fn stage(&self, bytes: &[u8]) -> Packet<[u8]> {
        let mut packet = self.packets.get();
        if packet.buf_mut().len() < bytes.len() {
            return Packet::copy_from(bytes);
        }
        packet.buf_mut()[..bytes.len()].copy_from_slice(bytes);
        packet.truncate(bytes.len());
        packet
    }

    fn network_emit(&self, kind: WgKind) -> Result<EgressEmit, EgressError> {
        let packet: Packet = kind.into();
        self.pool
            .take(packet.as_ref())
            .map(EgressEmit::ToNetwork)
            .ok_or(EgressError::PoolExhausted)
    }
}

impl PacketEgress for WireGuardEgress {
    fn properties(&self) -> PathProperties {
        PathProperties {
            datagram_fidelity: DatagramFidelity::Native,
            overhead_bytes: WIREGUARD_OVERHEAD_BYTES,
            max_datagram_size: None,
            // The inner header's ECN survives encryption untouched, but no
            // outer-header marking propagates mid-tunnel, and no capture has
            // verified either direction yet. Claim nothing.
            preserves_ecn: false,
            // One peer behind one endpoint: there is no mapping to vary.
            nat_behavior: NatBehavior::EndpointIndependent,
        }
    }

    /// Encapsulates one IP packet from the tunnel. Before a session exists
    /// this emits the handshake initiation and queues the packet inside the
    /// tunnel; the queue flushes on the tick or inbound packet that completes
    /// the handshake. At most one emission, always network-bound.
    fn handle_tun_packet(
        &mut self,
        packet: &[u8],
        out: &mut Vec<EgressEmit>,
    ) -> Result<(), EgressError> {
        self.fast_path_packets += 1;
        let Some(kind) = self
            .tunn
            .handle_outgoing_packet(self.stage(packet), Some(&mut self.mtu))
        else {
            return Ok(());
        };
        out.push(self.network_emit(kind)?);
        Ok(())
    }

    /// Handles one UDP payload from the peer. A malformed datagram is an
    /// observation, not a tunnel failure; a completed handshake flushes
    /// whatever was queued while it ran.
    fn handle_network_packet(
        &mut self,
        datagram: &[u8],
        out: &mut Vec<EgressEmit>,
    ) -> Result<(), EgressError> {
        let kind = self
            .stage(datagram)
            .try_into_wg()
            .map_err(|_| EgressError::MalformedNetworkPacket)?;

        match self.tunn.handle_incoming_packet(kind) {
            TunnResult::Done => {}
            TunnResult::Err(error) => return Err(error.into()),
            TunnResult::WriteToNetwork(kind) => out.push(self.network_emit(kind)?),
            TunnResult::WriteToTunnel(packet) => {
                let bytes: &[u8] = packet.as_ref();
                // A keepalive answers liveness inside the protocol; it is not
                // an IP packet and must not reach the datapath. Data payloads
                // are padded to a 16-byte multiple, and the IP header's own
                // length field governs, so the tunnel is owed exactly the
                // packet and not the padding.
                if !bytes.is_empty() {
                    let stripped = strip_padding(bytes);
                    let pooled = self.pool.take(stripped).ok_or(EgressError::PoolExhausted)?;
                    out.push(EgressEmit::ToTunnel(pooled));
                }
            }
        }
        self.flush_queue(out)
    }

    /// Drives handshake retries, rekeys, session expiry, and keepalives.
    fn tick(&mut self, out: &mut Vec<EgressEmit>) -> Result<(), EgressError> {
        if let Some(kind) = self.tunn.update_timers()? {
            out.push(self.network_emit(kind)?);
        }
        self.flush_queue(out)
    }

    fn tick_interval(&self) -> Duration {
        WIREGUARD_TICK
    }

    /// A padded inner packet plus WireGuard's own framing. Exact rather than
    /// the trait's 64 KiB default, because this is the egress the mobile target
    /// runs and one buffer is one buffer.
    fn max_network_datagram(&self) -> usize {
        usize::from(self.inner_mtu.get()).next_multiple_of(WIREGUARD_PADDING_ALIGNMENT)
            + WIREGUARD_FRAMING_BYTES
    }
}

/// The exact IP packet, without WireGuard's 16-byte-alignment padding.
///
/// O(1) and allocation-free: both families state their own length at a fixed
/// offset in the fixed header, so this reads two bytes rather than running a
/// full network-and-transport parse for a number the header already carries.
/// A packet whose own header does not describe a sane length passes through
/// untouched: the datapath is the authority on rejecting it, and guessing a
/// length here would only hide its count.
fn strip_padding(packet: &[u8]) -> &[u8] {
    let declared = match packet.first().map(|version| version >> 4) {
        Some(4) if packet.len() >= 20 => {
            let header = usize::from(packet[0] & 0x0f) * 4;
            let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            (header >= 20 && total >= header).then_some(total)
        }
        Some(6) if packet.len() >= 40 => {
            Some(40 + usize::from(u16::from_be_bytes([packet[4], packet[5]])))
        }
        _ => None,
    };
    declared
        .and_then(|length| packet.get(..length))
        .unwrap_or(packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroUsize;

    /// Large enough that nothing here meets the budget, so a `PoolExhausted`
    /// in these tests would be a defect rather than the congestion path.
    fn pool() -> Arc<BufferPool> {
        BufferPool::new(
            NonZeroUsize::new(2048).unwrap(),
            NonZeroUsize::new(64).unwrap(),
        )
    }

    fn config(private_key: [u8; 32], peer_public_key: [u8; 32]) -> WireGuardConfig {
        WireGuardConfig {
            private_key,
            peer_public_key,
            preshared_key: None,
            persistent_keepalive: None,
            inner_mtu: Mtu::new(1420).unwrap(),
        }
    }

    /// Deterministic stand-ins for real keys; x25519 accepts any 32 bytes.
    fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let private = StaticSecret::from([seed; 32]);
        (private.to_bytes(), PublicKey::from(&private).to_bytes())
    }

    fn pair(pool: &Arc<BufferPool>) -> (WireGuardEgress, WireGuardEgress) {
        let (client_private, client_public) = keypair(1);
        let (server_private, server_public) = keypair(2);
        (
            WireGuardEgress::new(config(client_private, server_public), Arc::clone(pool)),
            WireGuardEgress::new(config(server_private, client_public), Arc::clone(pool)),
        )
    }

    /// Delivers one end's emits to the other, ping-ponging until neither has
    /// anything left to say — the deterministic stand-in for two shells joined
    /// by a loopback socket. Tunnel-bound packets are collected.
    fn exchange(
        client: &mut WireGuardEgress,
        server: &mut WireGuardEgress,
        initial: Vec<EgressEmit>,
    ) -> Vec<Vec<u8>> {
        fn deliver(
            target: &mut WireGuardEgress,
            incoming: &mut Vec<EgressEmit>,
            outgoing: &mut Vec<EgressEmit>,
            tunnelled: &mut Vec<Vec<u8>>,
        ) {
            for emit in incoming.drain(..) {
                match emit {
                    EgressEmit::ToNetwork(datagram) => target
                        .handle_network_packet(&datagram, outgoing)
                        .expect("in-band WireGuard exchange"),
                    EgressEmit::ToTunnel(packet) => tunnelled.push(packet.to_vec()),
                }
            }
        }

        let mut tunnelled = Vec::new();
        let (mut to_server, mut to_client) = (initial, Vec::new());
        while !to_server.is_empty() || !to_client.is_empty() {
            deliver(server, &mut to_server, &mut to_client, &mut tunnelled);
            deliver(client, &mut to_client, &mut to_server, &mut tunnelled);
        }
        tunnelled
    }

    #[test]
    fn handshake_then_ip_packet_round_trips_byte_exact() {
        let pool = pool();
        let (mut client, mut server) = pair(&pool);
        let ip_packet = [
            0x45, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2, 0x04,
            0xd2, 0x00, 0x35, 0x00, 0x08, 0, 0,
        ];

        // The first packet triggers the handshake and is queued behind it.
        let mut first = Vec::new();
        client.handle_tun_packet(&ip_packet, &mut first).unwrap();
        assert!(
            first
                .iter()
                .all(|emit| matches!(emit, EgressEmit::ToNetwork(_))),
            "nothing reaches the tunnel before the handshake"
        );
        let tunnelled = exchange(&mut client, &mut server, first);
        assert_eq!(tunnelled, vec![ip_packet], "queued packet flushes intact");
        assert_eq!(client.fast_path_packets(), 1);

        // With a session established, a second packet crosses directly.
        let mut second = Vec::new();
        client.handle_tun_packet(&ip_packet, &mut second).unwrap();
        let tunnelled = exchange(&mut client, &mut server, second);
        assert_eq!(tunnelled, vec![ip_packet]);
        assert_eq!(client.fast_path_packets(), 2);

        // Every pooled buffer the exchange used has been returned: an egress
        // that leaked the budget would starve the datapath sharing it.
        assert_eq!(pool.available(), 64);
    }

    #[test]
    fn non_wireguard_datagrams_are_rejected_not_fatal() {
        let pool = pool();
        let (mut client, _server) = pair(&pool);
        let mut out = Vec::new();
        assert!(matches!(
            client.handle_network_packet(&[0xde, 0xad, 0xbe, 0xef], &mut out),
            Err(EgressError::MalformedNetworkPacket)
        ));
        assert!(out.is_empty());
        // The tunnel still works afterwards.
        client.handle_tun_packet(&[0x45; 28], &mut out).unwrap();
        assert!(!out.is_empty());
    }

    #[test]
    fn an_exhausted_pool_refuses_an_emission_instead_of_allocating() {
        let pool = BufferPool::new(
            NonZeroUsize::new(2048).unwrap(),
            NonZeroUsize::new(1).unwrap(),
        );
        let (mut client, _server) = pair(&pool);
        let held = pool.take(b"the only buffer").expect("within budget");

        let mut out = Vec::new();
        assert!(matches!(
            client.handle_tun_packet(&[0x45; 28], &mut out),
            Err(EgressError::PoolExhausted)
        ));
        assert!(out.is_empty(), "a refusal emits nothing");
        assert_eq!(pool.exhausted(), 1);
        drop(held);

        // The refusal is the pool's state, not a broken egress: with the
        // budget back, an egress emits normally. It is deliberately a fresh
        // one — the dropped bytes were a handshake initiation, and WireGuard
        // recovers those from its own retry timer on `tick`, not from the
        // next packet, so re-offering to the same tunnel proves nothing.
        let (mut fresh, _server) = pair(&pool);
        fresh.handle_tun_packet(&[0x45; 28], &mut out).unwrap();
        assert_eq!(out.len(), 1);
    }

    /// **The invariant every downstream comparison now reads instead of
    /// re-establishing.** A name arrives from an SNI, a proxy configuration, or
    /// a request header in whatever case its author chose; DNS and TLS treat
    /// those as one host, so the boundary makes them one value. Every consumer
    /// that used to lower-case its input per connection, per request, and per
    /// response now compares borrowed.
    #[test]
    fn a_name_is_normalized_where_it_is_admitted() {
        assert_eq!(
            DomainName::new("Example.COM").unwrap().as_str(),
            "example.com"
        );
        assert_eq!(
            DomainName::new("Example.COM"),
            DomainName::new("example.com"),
            "one host is one value"
        );
        // The refinement still holds, and is checked on the original bytes.
        assert_eq!(DomainName::new(""), Err(DomainNameError::Empty));
        assert_eq!(
            DomainName::new("A".repeat(256)),
            Err(DomainNameError::TooLong(256))
        );
        assert_eq!(DomainName::new("A\0B"), Err(DomainNameError::Interior));
        // Non-ASCII is left exactly as it was: an IDN is punycode on the wire,
        // and case-folding beyond ASCII is not a thing DNS asks for.
        assert_eq!(
            DomainName::new("xn--Bcher-kva.example").unwrap().as_str(),
            "xn--bcher-kva.example"
        );
    }

    #[test]
    fn padding_is_stripped_by_the_header_the_packet_declares() {
        // IPv4: 28 declared bytes inside a 32-byte padded payload.
        let mut padded = vec![0u8; 32];
        padded[0] = 0x45;
        padded[2..4].copy_from_slice(&28u16.to_be_bytes());
        assert_eq!(strip_padding(&padded).len(), 28);

        // IPv6: 40 fixed bytes plus a declared 8-byte payload.
        let mut padded = vec![0u8; 64];
        padded[0] = 0x60;
        padded[4..6].copy_from_slice(&8u16.to_be_bytes());
        assert_eq!(strip_padding(&padded).len(), 48);

        // Nonsense passes through whole rather than being guessed at: a
        // declared length below the header, past the buffer, or on a version
        // that is neither family.
        let mut broken = vec![0u8; 32];
        broken[0] = 0x45;
        broken[2..4].copy_from_slice(&8u16.to_be_bytes());
        assert_eq!(strip_padding(&broken).len(), 32);
        broken[2..4].copy_from_slice(&9999u16.to_be_bytes());
        assert_eq!(strip_padding(&broken).len(), 32);
        assert_eq!(strip_padding(&[0x00; 32]).len(), 32);
        assert_eq!(strip_padding(&[]).len(), 0);
    }

    #[test]
    fn the_reported_properties_match_the_implementation() {
        let pool = pool();
        let (client, _server) = pair(&pool);
        let egress = Egress::Packet(Box::new(client));
        assert_eq!(egress.accepts(), Accepts::IpPackets);
        let properties = egress.properties();
        assert_eq!(properties.datagram_fidelity, DatagramFidelity::Native);
        assert_eq!(properties.overhead_bytes, WIREGUARD_OVERHEAD_BYTES);

        // A stream egress chained behind a packet egress is a configuration
        // conflict reported where the implementations are known.
        struct NoStreams;
        impl StreamEgress for NoStreams {
            fn connect<'a>(
                &'a self,
                _target: &'a crate::Target,
            ) -> crate::BoxFuture<'a, Result<Box<dyn crate::AsyncStream>, EgressError>>
            {
                // This fixture exists to be chained against, never dialled.
                Box::pin(async { Err(EgressError::DatagramsUnsupported) })
            }

            fn properties(&self) -> PathProperties {
                PathProperties {
                    datagram_fidelity: DatagramFidelity::Native,
                    overhead_bytes: 0,
                    max_datagram_size: None,
                    preserves_ecn: false,
                    nat_behavior: NatBehavior::EndpointIndependent,
                }
            }
        }
        let stream = Egress::Stream(Box::new(NoStreams));
        assert_eq!(
            Egress::chain(&egress, &stream),
            Err(ChainError::MixedLayers)
        );
    }
}
