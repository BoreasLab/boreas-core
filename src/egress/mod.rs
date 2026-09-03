//! Egress implementations and shared packet and flow vocabulary.
//!
//! `Egress` derives its accepted layer from its variant. `PacketEgress` is
//! sans-IO: packets enter, pooled emissions leave, and an explicit tick drives
//! protocol timers.
//!
//! `WireGuardEgress` wraps GotaTun's sans-IO `Tunn`. Socket I/O stays in the
//! shell, and pool exhaustion is a counted drop.

pub(crate) mod hysteria2;
pub(crate) mod masque;
pub(crate) mod origin;
pub(crate) mod quic;
pub(crate) mod shadowsocks;
pub(crate) mod socks5;
pub(crate) mod transport;
pub(crate) mod vless;

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

/// Sans-IO egress for whole IP packets.
///
/// Emissions append to the caller's vector and may contain multiple ordered
/// destinations, such as a handshake response followed by a tunnel packet.
pub trait PacketEgress: Send {
    fn properties(&self) -> PathProperties;

    fn handle_tun_packet(
        &mut self,
        packet: &[u8],
        out: &mut Vec<EgressEmit>,
    ) -> Result<(), EgressError>;

    fn handle_network_packet(
        &mut self,
        datagram: &[u8],
        out: &mut Vec<EgressEmit>,
    ) -> Result<(), EgressError>;

    /// Maximum peer datagram size for the reactor's receive buffer.
    ///
    /// The default covers every UDP length-field value. Implementations with a
    /// tighter framing bound should override it; truncation would corrupt a
    /// valid datagram.
    fn max_network_datagram(&self) -> usize {
        usize::from(u16::MAX)
    }

    fn tick(&mut self, out: &mut Vec<EgressEmit>) -> Result<(), EgressError>;

    fn tick_interval(&self) -> Duration;

    fn next_deadline(&self) -> Option<std::time::Instant> {
        None
    }
}

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

/// A lowercase, NUL-free domain name no longer than one wire length octet.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DomainName(String);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainNameError {
    Empty,
    TooLong(usize),
    /// An interior NUL cannot be represented by downstream parsers.
    Interior,
}

impl DomainName {
    /// Validates and normalizes a domain name at the wire boundary.
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

    /// Length in the one-octet proxy representation.
    pub fn wire_len(&self) -> u8 {
        self.0.len() as u8
    }
}

impl std::fmt::Display for DomainName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A flow's IP or unresolved domain destination.
///
/// Domain targets remain unresolved so the exit chooses its DNS view; the
/// client's local resolver never sees them. Hashing supports proxy stream maps.
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

/// Byte stream shared by direct, proxied, and intercepted flows.
pub trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> AsyncStream for T {}

/// Replays handshake bytes read beyond the protocol boundary.
///
/// TCP can coalesce proxy response bytes with the next application payload;
/// discarding that surplus truncates the flow.
pub struct Prefixed<S> {
    prefix: bytes::Bytes,
    inner: S,
}

impl<S> Prefixed<S> {
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

/// Either a wrapped stream or the original stream without boxing.
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

pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Shared sender for a proxy datagram association.
///
/// The target travels in the proxy payload, so one association can serve many
/// peers. `Sync` permits concurrent flow senders.
pub trait DatagramSink: Send + Sync {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        target: &'a Target,
    ) -> BoxFuture<'a, Result<(), EgressError>>;
}

pub trait DatagramSource: Send {
    /// Writes one complete payload and returns its source target. An undersized
    /// buffer returns [`EgressError::DatagramTooLarge`] rather than truncating.
    fn recv_from<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, Result<(usize, Target), EgressError>>;
}

pub struct Association {
    pub sink: Arc<dyn DatagramSink>,
    pub source: Box<dyn DatagramSource>,
}

pub trait StreamEgress: Send + Sync {
    fn properties(&self) -> PathProperties;

    fn connect<'a>(
        &'a self,
        target: &'a Target,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncStream>, EgressError>>;

    /// The default agrees with [`DatagramFidelity::None`](crate::DatagramFidelity::None).
    fn associate(&self) -> BoxFuture<'_, Result<Association, EgressError>> {
        Box::pin(async { Err(EgressError::DatagramsUnsupported) })
    }
}

/// Direct L4 egress through the platform's tunnel bypass.
///
/// Re-originated traffic must use the bypass or it can re-enter Boreas's TUN
/// and be intercepted again.
pub struct DirectEgress<B> {
    bypass: B,
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
            datagram_fidelity: DatagramFidelity::Native,
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
            let address = origin::resolve(target).await?;
            let stream = crate::within(crate::Wait::TcpConnect, self.bypass.tcp(address)).await?;
            // Re-originated request streams should not wait for Nagle coalescing.
            stream.set_nodelay(true)?;
            Ok(Box::new(stream) as Box<dyn AsyncStream>)
        })
    }

    fn associate(&self) -> BoxFuture<'_, Result<Association, EgressError>> {
        Box::pin(async move {
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

struct DirectRelay(tokio::net::UdpSocket);

impl DatagramSink for DirectRelay {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        target: &'a Target,
    ) -> BoxFuture<'a, Result<(), EgressError>> {
        Box::pin(async move {
            let address = origin::resolve(target).await?;
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

pub enum Egress {
    Packet(Box<dyn PacketEgress>),
    Stream(Box<dyn StreamEgress>),
}

impl Egress {
    pub fn accepts(&self) -> Accepts {
        match self {
            Self::Packet(_) => Accepts::IpPackets,
            Self::Stream(_) => Accepts::Flows,
        }
    }

    pub fn properties(&self) -> PathProperties {
        match self {
            Self::Packet(egress) => egress.properties(),
            Self::Stream(egress) => egress.properties(),
        }
    }

    /// Combines two egresses after checking their accepted layers agree.
    pub fn chain(first: &Egress, next: &Egress) -> Result<PathProperties, ChainError> {
        if first.accepts() != next.accepts() {
            return Err(ChainError::MixedLayers);
        }
        first.properties().chain(next.properties())
    }
}

/// Worst-case WireGuard overhead over an IPv6 underlay.
pub const WIREGUARD_OVERHEAD_BYTES: u16 = 80;

const HANDSHAKE_RATE_LIMIT: u64 = 100;

const WIREGUARD_TICK: Duration = Duration::from_millis(250);

/// Source the limiter accounts handshakes to: the connected socket's one peer.
const PEER: std::net::SocketAddr =
    std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

const TUNNEL_BUFFERS: usize = 16;

/// Static configuration for one WireGuard peer.
pub struct WireGuardConfig {
    pub private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    /// Keepalive interval in seconds, or `None` to disable it.
    pub persistent_keepalive: Option<u16>,
    /// Inner MTU used for WireGuard's 16-byte data padding.
    pub inner_mtu: Mtu,
}

#[derive(Debug, PartialEq, Eq)]
pub enum EgressEmit {
    /// WireGuard UDP payload for the peer.
    ToNetwork(Pooled),
    /// Decrypted IP packet for the datapath.
    ToTunnel(Pooled),
}

#[derive(Debug)]
pub enum EgressError {
    /// UDP bytes that are not a WireGuard packet.
    MalformedNetworkPacket,
    /// No buffer was available for an emission.
    PoolExhausted,
    /// GotaTun rejected or expired the tunnel.
    WireGuard(WireGuardError),
    /// MASQUE setup or protocol failure.
    Masque,
    /// QUIC transport failure beneath a proxy protocol.
    Quic,
    /// This egress does not support datagrams.
    DatagramsUnsupported,
    /// A datagram exceeded the caller's buffer; truncation is not allowed.
    DatagramTooLarge { required: usize },
    /// Proxy refusal or malformed proxy response.
    Proxy(ProxyError),
    /// Underlying transport failure.
    Io(std::io::ErrorKind),
}

impl std::fmt::Display for EgressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedNetworkPacket => f.write_str("not a WireGuard packet"),
            Self::PoolExhausted => f.write_str("no pooled buffer for the emission"),
            // GotaTun exposes no Display implementation.
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

/// Sans-IO WireGuard packet egress.
pub struct WireGuardEgress {
    tunn: Tunn,
    /// Checks handshake MACs and hands out cookies under load, before any
    /// asymmetric work (whitepaper section 5.4).
    limiter: Arc<RateLimiter>,
    mtu: MtuWatcher,
    pool: Arc<BufferPool>,
    /// Reused scratch space for queued GotaTun outputs.
    queued: Vec<WgKind>,
    /// GotaTun-owned recycled buffers for tunnel input.
    ///
    /// Its lifetime and buffer type differ from `BufferPool`, which owns
    /// emissions leaving this crate.
    packets: gotatun::packet::PacketBufPool,
    /// Count of packets sent through the packet fast path.
    fast_path_packets: u64,
}

impl WireGuardEgress {
    /// Creates an egress using the datapath's emission pool.
    pub fn new(config: WireGuardConfig, pool: Arc<BufferPool>) -> Self {
        let private_key = StaticSecret::from(config.private_key);
        let our_public = PublicKey::from(&private_key);
        let limiter = Arc::new(RateLimiter::new(&our_public, HANDSHAKE_RATE_LIMIT));
        Self {
            tunn: Tunn::new(
                private_key,
                PublicKey::from(config.peer_public_key),
                config.preshared_key,
                config.persistent_keepalive,
                IndexTable::from_os_rng(),
                Arc::clone(&limiter),
            ),
            limiter,
            mtu: MtuWatcher::new(config.inner_mtu.get()),
            pool,
            queued: Vec::new(),
            packets: gotatun::packet::PacketBufPool::new(TUNNEL_BUFFERS),
            fast_path_packets: 0,
        }
    }

    pub fn fast_path_packets(&self) -> u64 {
        self.fast_path_packets
    }

    /// Emits packets GotaTun queued during handshake establishment.
    ///
    /// The scratch vector separates GotaTun and pool borrows while retaining
    /// capacity across calls.
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
            // No verified outer-header ECN mapping exists.
            preserves_ecn: false,
            nat_behavior: NatBehavior::EndpointIndependent,
        }
    }

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

    fn handle_network_packet(
        &mut self,
        datagram: &[u8],
        out: &mut Vec<EgressEmit>,
    ) -> Result<(), EgressError> {
        // The socket is connected to the one peer, so the limiter's
        // per-source accounting needs no real address; a cookie is bound to
        // whatever we say and echoed back as is.
        let kind = match self.limiter.verify_packet(PEER, self.stage(datagram)) {
            Ok(kind) => kind,
            // Under load: a cookie the peer must echo before we do the DH.
            Err(TunnResult::WriteToNetwork(cookie)) => {
                out.push(self.network_emit(cookie)?);
                return Ok(());
            }
            Err(TunnResult::Err(WireGuardError::InvalidPacket)) => {
                return Err(EgressError::MalformedNetworkPacket);
            }
            Err(TunnResult::Err(error)) => return Err(error.into()),
            Err(TunnResult::Done | TunnResult::WriteToTunnel(_)) => return Ok(()),
        };

        match self.tunn.handle_incoming_packet(kind) {
            TunnResult::Done => {}
            TunnResult::Err(error) => return Err(error.into()),
            TunnResult::WriteToNetwork(kind) => out.push(self.network_emit(kind)?),
            TunnResult::WriteToTunnel(packet) => {
                let bytes: &[u8] = packet.as_ref();
                // Keepalives have no IP payload; data packets declare their
                // unpadded length in the IP header.
                if !bytes.is_empty() {
                    let stripped = strip_padding(bytes);
                    let pooled = self.pool.take(stripped).ok_or(EgressError::PoolExhausted)?;
                    out.push(EgressEmit::ToTunnel(pooled));
                }
            }
        }
        self.flush_queue(out)
    }

    fn tick(&mut self, out: &mut Vec<EgressEmit>) -> Result<(), EgressError> {
        if let Some(kind) = self.tunn.update_timers()? {
            out.push(self.network_emit(kind)?);
        }
        self.flush_queue(out)
    }

    fn tick_interval(&self) -> Duration {
        WIREGUARD_TICK
    }

    // WireGuard negotiates no MTU: the peer sends up to its own interface's
    // MTU plus framing, which our inner MTU says nothing about. The trait's
    // default, every UDP length, is the only bound that never truncates.
}

/// Removes WireGuard padding using the IP header's declared length.
///
/// Invalid or unsupported headers pass through unchanged; packet validation
/// belongs to the datapath.
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

        let mut second = Vec::new();
        client.handle_tun_packet(&ip_packet, &mut second).unwrap();
        let tunnelled = exchange(&mut client, &mut server, second);
        assert_eq!(tunnelled, vec![ip_packet]);
        assert_eq!(client.fast_path_packets(), 2);

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

        let (mut fresh, _server) = pair(&pool);
        fresh.handle_tun_packet(&[0x45; 28], &mut out).unwrap();
        assert_eq!(out.len(), 1);
    }

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
        assert_eq!(DomainName::new(""), Err(DomainNameError::Empty));
        assert_eq!(
            DomainName::new("A".repeat(256)),
            Err(DomainNameError::TooLong(256))
        );
        assert_eq!(DomainName::new("A\0B"), Err(DomainNameError::Interior));
        assert_eq!(
            DomainName::new("xn--Bcher-kva.example").unwrap().as_str(),
            "xn--bcher-kva.example"
        );
    }

    #[test]
    fn padding_is_stripped_by_the_header_the_packet_declares() {
        let mut padded = vec![0u8; 32];
        padded[0] = 0x45;
        padded[2..4].copy_from_slice(&28u16.to_be_bytes());
        assert_eq!(strip_padding(&padded).len(), 28);

        let mut padded = vec![0u8; 64];
        padded[0] = 0x60;
        padded[4..6].copy_from_slice(&8u16.to_be_bytes());
        assert_eq!(strip_padding(&padded).len(), 48);

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

        struct NoStreams;
        impl StreamEgress for NoStreams {
            fn connect<'a>(
                &'a self,
                _target: &'a crate::Target,
            ) -> crate::BoxFuture<'a, Result<Box<dyn crate::AsyncStream>, EgressError>>
            {
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
