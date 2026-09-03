//! DNS upstream transports and their wire handling.
//!
//! Policy remains in [`crate::policy::dns`]; this module supplies transport
//! provenance and performs only the selected protocol exchange. Mozilla's
//! trust bundle is independent of the user-installed interception root.
//!
//! Every transport keeps its connection. Do53 and DoT pipeline queries on one
//! by transaction id ([`crate::policy::demux`]); DoH answers in order, so it
//! keeps a few idle connections and uses one per query in flight; DoQ gives
//! each query its own stream over one connection, with a zero message id as
//! RFC 9250 requires. [`TunnelBypass`] keeps resolver sockets outside the tunnel.

use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    ClientProfile, Message, Originator, Upstream,
    live::Live,
    policy::demux::{Demux, Transport, bounded},
};

/// Maximum DNS message accepted from an upstream.
pub(crate) const MAX_DNS_MESSAGE: usize = 4096;

/// One DNS upstream transport.
pub trait DnsUpstream: Send + Sync {
    /// Transport provenance recorded in a resolution.
    fn kind(&self) -> Upstream;

    /// Sends one DNS message and returns its reply.
    fn query(&self, message: &[u8]) -> impl Future<Output = io::Result<Vec<u8>>> + Send;
}

/// Creates resolver sockets outside the tunnel.
pub trait TunnelBypass: Send + Sync {
    fn udp(
        &self,
        peer: SocketAddr,
    ) -> impl Future<Output = io::Result<tokio::net::UdpSocket>> + Send;

    fn tcp(
        &self,
        peer: SocketAddr,
    ) -> impl Future<Output = io::Result<tokio::net::TcpStream>> + Send;

    /// Creates an unconnected UDP socket for per-datagram destinations.
    fn unbound(&self) -> impl Future<Output = io::Result<tokio::net::UdpSocket>> + Send;
}

/// Default-route sockets for environments without tunnel interception.
#[derive(Clone, Copy, Debug, Default)]
pub struct DirectSockets;

impl TunnelBypass for DirectSockets {
    // The explicit return type states the trait's `Send` guarantee.
    #[allow(clippy::manual_async_fn)]
    fn udp(
        &self,
        peer: SocketAddr,
    ) -> impl Future<Output = io::Result<tokio::net::UdpSocket>> + Send {
        async move {
            let bind: SocketAddr = if peer.is_ipv4() {
                ([0, 0, 0, 0], 0).into()
            } else {
                ([0u16; 8], 0).into()
            };
            let socket = tokio::net::UdpSocket::bind(bind).await?;
            socket.connect(peer).await?;
            Ok(socket)
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn tcp(
        &self,
        peer: SocketAddr,
    ) -> impl Future<Output = io::Result<tokio::net::TcpStream>> + Send {
        async move { tokio::net::TcpStream::connect(peer).await }
    }

    #[allow(clippy::manual_async_fn)]
    fn unbound(&self) -> impl Future<Output = io::Result<tokio::net::UdpSocket>> + Send {
        // One IPv6 socket serves both address families where supported.
        async move { tokio::net::UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, 0)).await }
    }
}

/// Plain DNS to one resolver: UDP (RFC 1035 section 4.2.1), and TCP for a
/// reply UDP truncated (RFC 7766 section 5).
pub struct Do53Upstream<B> {
    resolver: SocketAddr,
    bypass: Arc<B>,
    timeout: Duration,
    /// Sockets on distinct source ports, taken in turn, so a forger must
    /// guess the port as well as the id (RFC 5452 section 9.2).
    sockets: [Live<Demux>; SOURCE_PORTS],
    next: AtomicUsize,
    stream: Live<Demux>,
}

/// Default query timeout: two UDP attempts and a TCP retry fit inside it.
pub const DEFAULT_UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);

/// UDP sockets a Do53 upstream rotates through. Each costs a descriptor, and
/// on Android one `protect` call, once.
const SOURCE_PORTS: usize = 8;

/// A datagram unanswered for this long is sent again, from the next port.
const UDP_RETRANSMIT: Duration = Duration::from_secs(1);

/// A connection with nothing in flight is closed after this. Resolvers close
/// idle DoT sessions themselves at about this age.
const UPSTREAM_IDLE: Duration = Duration::from_secs(30);

impl<B: TunnelBypass + 'static> Do53Upstream<B> {
    pub fn new(resolver: SocketAddr, bypass: B) -> Self {
        Self {
            resolver,
            bypass: Arc::new(bypass),
            timeout: DEFAULT_UPSTREAM_TIMEOUT,
            sockets: std::array::from_fn(|_| Live::new()),
            next: AtomicUsize::new(0),
            stream: Live::new(),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Over the next socket in turn; unanswered, once more from the one after.
    async fn over_udp(&self, message: &[u8]) -> io::Result<Vec<u8>> {
        match tokio::time::timeout(UDP_RETRANSMIT, self.over_socket(message)).await {
            Ok(outcome) => outcome,
            Err(_) => self.over_socket(message).await,
        }
    }

    async fn over_socket(&self, message: &[u8]) -> io::Result<Vec<u8>> {
        let slot = self.next.fetch_add(1, Ordering::Relaxed) % SOURCE_PORTS;
        let resolver = self.resolver;
        let connect = || {
            let bypass = Arc::clone(&self.bypass);
            async move { bypass.udp(resolver).await.map(Datagrams) }
        };
        on_connection(&self.sockets[slot], connect, message).await
    }

    async fn over_tcp(&self, message: &[u8]) -> io::Result<Vec<u8>> {
        let resolver = self.resolver;
        let connect = || {
            let bypass = Arc::clone(&self.bypass);
            async move {
                let io = bypass.tcp(resolver).await?;
                io.set_nodelay(true)?;
                Ok(Frames {
                    io,
                    buffer: Vec::new(),
                })
            }
        };
        on_connection(&self.stream, connect, message).await
    }
}

impl<B: TunnelBypass + 'static> DnsUpstream for Do53Upstream<B> {
    fn kind(&self) -> Upstream {
        Upstream::Do53
    }

    #[allow(clippy::manual_async_fn)]
    fn query(&self, message: &[u8]) -> impl Future<Output = io::Result<Vec<u8>>> + Send {
        async move {
            tokio::time::timeout(self.timeout, async {
                let reply = self.over_udp(message).await?;
                if Message::parse(&reply).is_ok_and(|parsed| parsed.is_truncated())
                    && let Ok(whole) = self.over_tcp(message).await
                {
                    return Ok(whole);
                }
                // Truncated and TCP failed: the client sees TC and decides.
                Ok(reply)
            })
            .await
            .map_err(timed_out)?
        }
    }
}

/// Queries over the live connection, opening one when there is none. A
/// connection that ends under a query is replaced and the query sent once
/// more; a second failure is the caller's.
async fn on_connection<T, F>(
    live: &Live<Demux>,
    connect: impl Fn() -> F,
    message: &[u8],
) -> io::Result<Vec<u8>>
where
    T: Transport,
    F: Future<Output = io::Result<T>> + Send + 'static,
{
    let mut retried = false;
    loop {
        let open = connect();
        let demux = live
            .get(Demux::is_alive, async move {
                open.await
                    .map(|transport| Demux::spawn(transport, UPSTREAM_IDLE))
            })
            .await?;
        match demux.query(message).await {
            Err(error) if error.kind() == io::ErrorKind::ConnectionAborted && !retried => {
                retried = true;
            }
            outcome => return outcome,
        }
    }
}

/// One connected UDP socket: a datagram each way.
struct Datagrams(tokio::net::UdpSocket);

impl Transport for Datagrams {
    async fn send(&mut self, message: &[u8]) -> io::Result<()> {
        self.0.send(message).await.map(drop)
    }

    async fn recv(&mut self) -> io::Result<Vec<u8>> {
        let mut reply = vec![0u8; MAX_DNS_MESSAGE];
        let len = self.0.recv(&mut reply).await?;
        reply.truncate(len);
        Ok(reply)
    }
}

/// Length-prefixed messages on a byte stream, RFC 7766 framing.
///
/// `recv` is cancel-safe: bytes land in `buffer` in the poll that read them,
/// so a dropped call loses nothing. The drain moves at most a reply or two.
struct Frames<S> {
    io: S,
    buffer: Vec<u8>,
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> Transport
    for Frames<S>
{
    async fn send(&mut self, message: &[u8]) -> io::Result<()> {
        let length = u16::try_from(message.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "query exceeds 65535"))?;
        // One write: one TLS record and one segment per query, not two.
        let mut framed = Vec::with_capacity(2 + message.len());
        framed.extend_from_slice(&length.to_be_bytes());
        framed.extend_from_slice(message);
        self.io.write_all(&framed).await?;
        self.io.flush().await
    }

    async fn recv(&mut self) -> io::Result<Vec<u8>> {
        loop {
            if let Some(&[high, low]) = self.buffer.first_chunk::<2>() {
                let length = bounded(usize::from(u16::from_be_bytes([high, low])))?;
                if self.buffer.len() >= 2 + length {
                    let message = self.buffer[2..2 + length].to_vec();
                    self.buffer.drain(..2 + length);
                    return Ok(message);
                }
            }
            let mut chunk = [0u8; 2048];
            let read = self.io.read(&mut chunk).await?;
            if read == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }
}

/// TLS dialer shared by DoT and DoH.
/// The stream a TLS upstream hands back. Named because two dialers and four
/// transports return it and the type is a mouthful.
type UpstreamTls = tokio_boring::SslStream<crate::Opaque<tokio::net::TcpStream>>;

struct TlsDialer<B> {
    resolver: SocketAddr,
    server_name: String,
    originator: Arc<Originator>,
    /// ALPN list in wire format.
    alpn: Vec<u8>,
    bypass: B,
}

/// TLS-upstream configuration failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpstreamError {
    /// Server name is not verifiable by rustls.
    InvalidServerName,
    /// URL is not an absolute `https://` URL with a host.
    InvalidUrl,
    /// The crypto provider rejected the requested protocol versions.
    UnsupportedTlsVersions,
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidServerName => "not a verifiable TLS server name",
            Self::InvalidUrl => "not an absolute https URL with a host",
            Self::UnsupportedTlsVersions => "the crypto provider rejected the TLS versions",
        })
    }
}

impl std::error::Error for UpstreamError {}

impl<B: TunnelBypass> TlsDialer<B> {
    /// Creates a dialer with the given ALPN list.
    fn new(
        resolver: SocketAddr,
        server_name: &str,
        alpn: &[&[u8]],
        bypass: B,
    ) -> Result<Self, UpstreamError> {
        // Reject names that no handshake can verify.
        ServerName::try_from(server_name).map_err(|_| UpstreamError::InvalidServerName)?;

        Ok(Self {
            resolver,
            server_name: server_name.to_owned(),
            originator: Arc::new(Originator::new()),
            alpn: crate::alpn_list(alpn),
            bypass,
        })
    }

    async fn connect(&self) -> io::Result<UpstreamTls> {
        let stream = crate::within(crate::Wait::TcpConnect, self.bypass.tcp(self.resolver)).await?;
        // DNS requests are request/response traffic; do not delay small writes.
        stream.set_nodelay(true)?;
        self.originator
            .connect(
                &self.server_name,
                &ClientProfile::chrome(),
                &self.alpn,
                stream,
            )
            .await
    }
}

/// DNS over TLS, RFC 7858: one session, queries pipelined on it by id.
pub struct DotUpstream<B> {
    dialer: Arc<TlsDialer<B>>,
    timeout: Duration,
    live: Live<Demux>,
}

/// The IANA-assigned port for DNS over TLS.
pub const DOT_PORT: u16 = 853;

impl<B: TunnelBypass + 'static> DotUpstream<B> {
    /// Configures the resolver address and certificate name separately.
    pub fn new(resolver: SocketAddr, server_name: &str, bypass: B) -> Result<Self, UpstreamError> {
        Ok(Self {
            dialer: Arc::new(TlsDialer::new(resolver, server_name, &[b"dot"], bypass)?),
            timeout: DEFAULT_UPSTREAM_TIMEOUT,
            live: Live::new(),
        })
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl<B: TunnelBypass + 'static> DnsUpstream for DotUpstream<B> {
    fn kind(&self) -> Upstream {
        Upstream::DoT
    }

    #[allow(clippy::manual_async_fn)]
    fn query(&self, message: &[u8]) -> impl Future<Output = io::Result<Vec<u8>>> + Send {
        async move {
            let connect = || {
                let dialer = Arc::clone(&self.dialer);
                async move {
                    dialer.connect().await.map(|io| Frames {
                        io,
                        buffer: Vec::new(),
                    })
                }
            };
            tokio::time::timeout(self.timeout, on_connection(&self.live, connect, message))
                .await
                .map_err(timed_out)?
        }
    }
}

/// Reads one bounded two-octet-length-prefixed DNS message.
async fn read_length_prefixed<S>(stream: &mut S) -> io::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes(header));
    if length > MAX_DNS_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "reply exceeds the accepted message size",
        ));
    }
    let mut reply = vec![0u8; length];
    stream.read_exact(&mut reply).await?;
    Ok(reply)
}

/// DNS over HTTPS, RFC 8484, over HTTP/1.1 with connections kept alive.
///
/// HTTP/1.1 answers in order, so one connection serves one query at a time;
/// a burst uses several, and up to [`DOH_IDLE_CONNECTIONS`] wait for the next.
pub struct DohUpstream<B> {
    dialer: TlsDialer<B>,
    timeout: Duration,
    /// Request authority and path.
    authority: String,
    path: String,
    idle: std::sync::Mutex<Vec<UpstreamTls>>,
}

/// Connections kept after a reusable response. More than a burst of this size
/// pays a handshake, which is what it paid on every query before.
const DOH_IDLE_CONNECTIONS: usize = 4;

impl<B: TunnelBypass> DohUpstream<B> {
    /// Configures an absolute `https://` endpoint and its already-known address.
    pub fn new(url: &str, resolver: SocketAddr, bypass: B) -> Result<Self, UpstreamError> {
        // URI parsing preserves bracketed IPv6 authorities.
        let uri: http::Uri = url.parse().map_err(|_| UpstreamError::InvalidUrl)?;
        if uri.scheme_str() != Some("https") {
            return Err(UpstreamError::InvalidUrl);
        }
        let authority = uri.authority().ok_or(UpstreamError::InvalidUrl)?;
        // TLS verifies the host; HTTP preserves the authority including port.
        let host = authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']');
        if host.is_empty() {
            return Err(UpstreamError::InvalidUrl);
        }
        let path = uri
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str);

        Ok(Self {
            dialer: TlsDialer::new(resolver, host, &[b"http/1.1"], bypass)?,
            timeout: DEFAULT_UPSTREAM_TIMEOUT,
            authority: authority.as_str().to_owned(),
            path: path.to_owned(),
            idle: std::sync::Mutex::new(Vec::new()),
        })
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Keeps a connection for the next query, up to the idle ceiling.
    fn park(&self, stream: UpstreamTls) {
        let mut idle = crate::locked(&self.idle);
        if idle.len() < DOH_IDLE_CONNECTIONS {
            idle.push(stream);
        }
    }

    /// One request on one connection. Reusable when the response framed its
    /// body by length and did not ask to close.
    async fn exchange(
        &self,
        stream: &mut UpstreamTls,
        head: &str,
        message: &[u8],
    ) -> io::Result<(Vec<u8>, bool)> {
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(message).await?;
        stream.flush().await?;
        read_http_response(stream).await
    }
}

impl<B: TunnelBypass> DnsUpstream for DohUpstream<B> {
    fn kind(&self) -> Upstream {
        Upstream::DoH
    }

    #[allow(clippy::manual_async_fn)]
    fn query(&self, message: &[u8]) -> impl Future<Output = io::Result<Vec<u8>>> + Send {
        async move {
            let head = format!(
                "POST {} HTTP/1.1\r\n\
                 host: {}\r\n\
                 accept: application/dns-message\r\n\
                 content-type: application/dns-message\r\n\
                 content-length: {}\r\n\r\n",
                self.path,
                self.authority,
                message.len(),
            );
            tokio::time::timeout(self.timeout, async {
                let parked = crate::locked(&self.idle).pop();
                let (mut stream, reused) = match parked {
                    Some(stream) => (stream, true),
                    None => (self.dialer.connect().await?, false),
                };
                let outcome = self.exchange(&mut stream, &head, message).await;
                let (body, reusable) = match outcome {
                    Ok(answered) => answered,
                    // A kept connection the resolver closed meanwhile: once
                    // more on a fresh one, which is what every query cost before.
                    Err(_) if reused => {
                        stream = self.dialer.connect().await?;
                        self.exchange(&mut stream, &head, message).await?
                    }
                    Err(error) => return Err(error),
                };
                if reusable {
                    self.park(stream);
                }
                Ok(body)
            })
            .await
            .map_err(timed_out)?
        }
    }
}

/// DNS over QUIC, RFC 9250. Each query uses its own stream and a zero message ID.
pub struct DoqUpstream<B> {
    resolver: SocketAddr,
    server_name: Arc<str>,
    bypass: Arc<B>,
    quic: Arc<crate::QuicConfigFactory>,
    connection: Live<crate::QuicConnection>,
    /// Cancels the connection driver on drop.
    shutdown: tokio_util::sync::CancellationToken,
    timeout: Duration,
}

/// RFC 9250 section 4.1.1 ALPN.
const DOQ_ALPN: &[u8] = b"doq";

/// DoQ connection idle timeout.
const DOQ_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Width of the DNS message ID.
const DNS_ID_BYTES: usize = 2;

impl<B> Drop for DoqUpstream<B> {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

impl<B: TunnelBypass + 'static> DoqUpstream<B> {
    /// Configures the resolver address, certificate name, and QUIC factory.
    pub fn new(
        resolver: SocketAddr,
        server_name: &str,
        bypass: B,
        quic: crate::QuicConfigFactory,
    ) -> Self {
        Self {
            resolver,
            server_name: server_name.into(),
            bypass: Arc::new(bypass),
            quic: Arc::new(quic),
            connection: Live::new(),
            shutdown: tokio_util::sync::CancellationToken::new(),
            timeout: DEFAULT_UPSTREAM_TIMEOUT,
        }
    }

    /// Builds a DoQ config with its ALPN and idle timeout.
    pub fn quic_config() -> Result<quiche::Config, crate::EgressError> {
        crate::client_config(&[DOQ_ALPN], DOQ_IDLE_TIMEOUT)
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Returns the live connection, establishing one if needed.
    async fn connection(&self) -> io::Result<crate::QuicConnection> {
        let (bypass, quic) = (Arc::clone(&self.bypass), Arc::clone(&self.quic));
        let (resolver, server_name) = (self.resolver, Arc::clone(&self.server_name));
        let shutdown = self.shutdown.clone();
        self.connection
            .get(crate::QuicConnection::is_alive, async move {
                let socket = bypass.udp(resolver).await?;
                let config = quic().map_err(quic_failed)?;
                let handshake = crate::Handshake::establish(socket, resolver, &server_name, config)
                    .await
                    .map_err(quic_failed)?;
                Ok(handshake.drive(shutdown))
            })
            .await
    }
}

fn quic_failed(_: crate::EgressError) -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionRefused,
        "the DoQ connection failed",
    )
}

impl<B: TunnelBypass + 'static> DnsUpstream for DoqUpstream<B> {
    fn kind(&self) -> Upstream {
        Upstream::DoQ
    }

    #[allow(clippy::manual_async_fn)]
    fn query(&self, message: &[u8]) -> impl Future<Output = io::Result<Vec<u8>>> + Send {
        async move {
            let Some(id) = message.get(..DNS_ID_BYTES) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "not a DNS message",
                ));
            };
            let id = [id[0], id[1]];
            let length = u16::try_from(message.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "query exceeds 65535"))?;

            tokio::time::timeout(self.timeout, async {
                let connection = self.connection().await?;
                let mut stream = connection.open_bidi().await.map_err(quic_failed)?;
                stream.write_all(&length.to_be_bytes()).await?;
                stream.write_all(&[0, 0]).await?;
                stream.write_all(&message[DNS_ID_BYTES..]).await?;
                stream.flush().await?;
                stream.shutdown().await?;

                let mut reply = read_length_prefixed(&mut stream).await?;
                if let Some(slot) = reply.get_mut(..DNS_ID_BYTES) {
                    slot.copy_from_slice(&id);
                }
                Ok(reply)
            })
            .await
            .map_err(timed_out)?
        }
    }
}

/// Maximum HTTP response-head size.
const MAX_HTTP_HEAD: usize = 8 * 1024;

/// Reads a `200` HTTP/1.1 response body, and whether the connection can carry
/// another request: a `content-length` frames the body and nothing asked to
/// close; otherwise the body runs to the close and the connection is spent.
async fn read_http_response<S>(stream: &mut S) -> io::Result<(Vec<u8>, bool)>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buffer = Vec::with_capacity(1024);
    let mut head_end = None;
    while head_end.is_none() {
        if buffer.len() > MAX_HTTP_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "response head exceeds the accepted size",
            ));
        }
        let mut chunk = [0u8; 512];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed inside the response head",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        head_end = find_head_end(&buffer);
    }
    let body_at = head_end.expect("the loop exits only once the head is complete");

    if !status_is_ok(&buffer[..body_at]) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "resolver did not answer with 200",
        ));
    }

    let head = &buffer[..body_at];
    let length = header(head, b"content-length").and_then(|value| {
        std::str::from_utf8(value)
            .ok()?
            .trim()
            .parse::<usize>()
            .ok()
    });
    let closing = header(head, b"connection").is_some_and(|value| {
        value
            .split(|byte| *byte == b',')
            .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"close"))
    });

    let mut body = buffer.split_off(body_at);
    match length {
        Some(length) => {
            bounded(length)?;
            if body.len() > length {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "more body than the content-length",
                ));
            }
            let have = body.len();
            body.resize(length, 0);
            stream.read_exact(&mut body[have..]).await.map_err(|_| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed inside the body",
                )
            })?;
            Ok((body, !closing))
        }
        None => {
            loop {
                if body.len() > MAX_DNS_MESSAGE {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "reply exceeds the accepted message size",
                    ));
                }
                let mut chunk = [0u8; 512];
                match stream.read(&mut chunk).await? {
                    0 => break,
                    read => body.extend_from_slice(&chunk[..read]),
                }
            }
            Ok((body, false))
        }
    }
}

/// The value of the first header named `name`, case-insensitively.
fn header<'a>(head: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    head.split(|byte| *byte == b'\n').skip(1).find_map(|line| {
        let colon = line.iter().position(|byte| *byte == b':')?;
        line[..colon]
            .eq_ignore_ascii_case(name)
            .then(|| line[colon + 1..].trim_ascii())
    })
}

/// Finds the offset just past an HTTP head.
fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| at + 4)
}

/// Whether an HTTP/1.0 or HTTP/1.1 status line reports 200.
fn status_is_ok(head: &[u8]) -> bool {
    let line = head.split(|byte| *byte == b'\r').next().unwrap_or_default();
    let mut fields = line.split(|byte| *byte == b' ');
    let version = fields.next().unwrap_or_default();
    let status = fields.next().unwrap_or_default();
    (version == b"HTTP/1.1" || version == b"HTTP/1.0") && status == b"200"
}

fn timed_out(_: tokio::time::error::Elapsed) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "upstream did not answer")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn address(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), port)
    }

    #[test]
    fn every_transport_names_itself() {
        assert_eq!(
            Do53Upstream::new(address(53), DirectSockets).kind(),
            Upstream::Do53
        );
        assert_eq!(
            DotUpstream::new(address(DOT_PORT), "one.one.one.one", DirectSockets)
                .unwrap()
                .kind(),
            Upstream::DoT
        );
        assert_eq!(
            DohUpstream::new(
                "https://one.one.one.one/dns-query",
                address(443),
                DirectSockets
            )
            .unwrap()
            .kind(),
            Upstream::DoH
        );
    }

    /// DoQ writes a zero ID upstream and restores the caller's ID downstream.
    #[test]
    fn doq_writes_a_zero_id_upstream_and_restores_the_caller_s_on_the_way_back() {
        let query = [0xab, 0xcd, 0x01, 0x00, 0x00, 0x01];
        let id = [query[0], query[1]];
        let mut on_the_wire = vec![0u8, 0u8];
        on_the_wire.extend_from_slice(&query[DNS_ID_BYTES..]);
        assert_eq!(
            on_the_wire,
            vec![0, 0, 0x01, 0x00, 0x00, 0x01],
            "the wire must carry a zero id"
        );

        let mut reply = vec![0u8, 0u8, 0x81, 0x80];
        reply[..DNS_ID_BYTES].copy_from_slice(&id);
        assert_eq!(
            reply,
            vec![0xab, 0xcd, 0x81, 0x80],
            "the client's id must come back"
        );

        assert!([0u8; 1].get(..DNS_ID_BYTES).is_none());
    }

    #[test]
    fn a_tls_upstream_refuses_a_name_it_could_not_verify() {
        assert_eq!(
            DotUpstream::new(address(DOT_PORT), "not a name", DirectSockets).err(),
            Some(UpstreamError::InvalidServerName)
        );
        for url in [
            "http://plain.example/dns-query",
            "one.one.one.one",
            "https://",
        ] {
            assert_eq!(
                DohUpstream::new(url, address(443), DirectSockets).err(),
                Some(UpstreamError::InvalidUrl),
                "{url}"
            );
        }
        assert!(DotUpstream::new(address(DOT_PORT), "1.1.1.1", DirectSockets).is_ok());
    }

    #[test]
    fn a_doh_url_splits_into_the_authority_and_path_a_request_needs() {
        let upstream = DohUpstream::new(
            "https://dns.example:8443/resolve",
            address(8443),
            DirectSockets,
        )
        .unwrap();
        assert_eq!(upstream.authority, "dns.example:8443");
        assert_eq!(upstream.path, "/resolve");
        assert_eq!(upstream.dialer.server_name, "dns.example");

        let bare = DohUpstream::new("https://dns.example", address(443), DirectSockets).unwrap();
        assert_eq!(bare.path, "/");
    }

    /// URI parsing keeps an IPv6 host separate from its port.
    #[test]
    fn an_ipv6_literal_resolver_keeps_its_address_as_the_server_name() {
        for (url, server_name, authority) in [
            (
                "https://[2001:db8::1]/dns-query",
                "2001:db8::1",
                "[2001:db8::1]",
            ),
            (
                "https://[2001:db8::1]:8443/dns-query",
                "2001:db8::1",
                "[2001:db8::1]:8443",
            ),
        ] {
            let upstream = DohUpstream::new(url, address(8443), DirectSockets).unwrap();
            assert_eq!(upstream.dialer.server_name, server_name, "{url}");
            assert_eq!(upstream.authority, authority, "{url}");
            assert_eq!(upstream.path, "/dns-query", "{url}");
        }
    }

    /// A resolver on loopback: UDP answers as told, TCP answers whole.
    struct FakeResolver {
        address: SocketAddr,
        /// Source ports the UDP queries came from, in order.
        sources: Arc<std::sync::Mutex<Vec<u16>>>,
    }

    impl FakeResolver {
        /// `udp` maps a query to its datagram reply, or `None` to drop it.
        async fn start(udp: impl Fn(&[u8], usize) -> Option<Vec<u8>> + Send + 'static) -> Self {
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = socket.local_addr().unwrap();
            let listener = tokio::net::TcpListener::bind(address).await.unwrap();
            let sources = Arc::new(std::sync::Mutex::new(Vec::new()));
            let seen = Arc::clone(&sources);
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                let mut count = 0;
                loop {
                    let Ok((len, from)) = socket.recv_from(&mut buf).await else {
                        break;
                    };
                    seen.lock().unwrap().push(from.port());
                    if let Some(reply) = udp(&buf[..len], count) {
                        socket.send_to(&reply, from).await.unwrap();
                    }
                    count += 1;
                }
            });
            tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    let mut head = [0u8; 2];
                    stream.read_exact(&mut head).await.unwrap();
                    let mut query = vec![0u8; usize::from(u16::from_be_bytes(head))];
                    stream.read_exact(&mut query).await.unwrap();
                    let mut reply = query;
                    reply[2] |= 0x80;
                    reply.push(b'W');
                    let mut framed = (reply.len() as u16).to_be_bytes().to_vec();
                    framed.extend_from_slice(&reply);
                    stream.write_all(&framed).await.unwrap();
                }
            });
            Self { address, sources }
        }
    }

    /// RFC 7766 section 5: a truncated UDP reply is asked again over TCP,
    /// and the client gets the whole answer.
    #[tokio::test]
    async fn a_truncated_udp_reply_is_asked_again_over_tcp() {
        let resolver = FakeResolver::start(|query, _| {
            let mut reply = query.to_vec();
            reply[2] |= 0x82; // response, truncated
            Some(reply)
        })
        .await;
        let upstream = Do53Upstream::new(resolver.address, DirectSockets);
        let reply = upstream
            .query(&crate::testing::dns::query("big.example", 5))
            .await
            .unwrap();
        assert_eq!(*reply.last().unwrap(), b'W', "the TCP answer");
        assert!(!Message::parse(&reply).unwrap().is_truncated());
        assert_eq!(u16::from_be_bytes([reply[0], reply[1]]), 5);
    }

    /// RFC 1035 section 4.2.1: a lost datagram is sent again; RFC 5452
    /// section 9.2: from a different source port.
    #[tokio::test]
    async fn a_lost_datagram_is_sent_again_from_another_port() {
        let resolver = FakeResolver::start(|query, count| {
            (count > 0).then(|| {
                let mut reply = query.to_vec();
                reply[2] |= 0x80;
                reply
            })
        })
        .await;
        let upstream = Do53Upstream::new(resolver.address, DirectSockets);
        let started = std::time::Instant::now();
        upstream
            .query(&crate::testing::dns::query("slow.example", 6))
            .await
            .expect("the second attempt was answered");
        assert!(started.elapsed() >= UDP_RETRANSMIT);
        let sources = resolver.sources.lock().unwrap().clone();
        assert_eq!(sources.len(), 2);
        assert_ne!(sources[0], sources[1], "another port for the retry");
    }

    #[tokio::test]
    async fn the_length_prefixed_reader_bounds_what_a_resolver_can_make_it_hold() {
        let mut framed: Vec<u8> = 4u16.to_be_bytes().to_vec();
        framed.extend_from_slice(b"abcd");
        let mut cursor = std::io::Cursor::new(framed);
        assert_eq!(read_length_prefixed(&mut cursor).await.unwrap(), b"abcd");

        let oversized = (MAX_DNS_MESSAGE as u16 + 1).to_be_bytes().to_vec();
        let mut cursor = std::io::Cursor::new(oversized);
        assert_eq!(
            read_length_prefixed(&mut cursor).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut short: Vec<u8> = 8u16.to_be_bytes().to_vec();
        short.extend_from_slice(b"abc");
        let mut cursor = std::io::Cursor::new(short);
        assert_eq!(
            read_length_prefixed(&mut cursor).await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    /// Two replies in one read and one reply over several reads both come out
    /// whole, and a length past the bound is refused before it is read.
    #[tokio::test]
    async fn frames_come_out_whole_however_the_bytes_arrive() {
        let (mut peer, ours) = tokio::io::duplex(4096);
        let mut frames = Frames {
            io: ours,
            buffer: Vec::new(),
        };
        peer.write_all(&[0, 2, 1, 1, 0, 3, 2, 2, 2]).await.unwrap();
        assert_eq!(frames.recv().await.unwrap(), [1, 1]);
        assert_eq!(frames.recv().await.unwrap(), [2, 2, 2]);

        tokio::spawn(async move {
            for byte in [0u8, 4, 9, 9, 9, 9] {
                peer.write_all(&[byte]).await.unwrap();
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            peer.write_all(&0xFFFFu16.to_be_bytes()).await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        });
        assert_eq!(frames.recv().await.unwrap(), [9, 9, 9, 9]);
        assert_eq!(
            frames.recv().await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[tokio::test]
    async fn only_a_200_yields_a_body() {
        let response = |head: &str, body: &[u8]| {
            let mut bytes = head.as_bytes().to_vec();
            bytes.extend_from_slice(body);
            std::io::Cursor::new(bytes)
        };

        let mut ok = response(
            "HTTP/1.1 200 OK\r\ncontent-type: application/dns-message\r\n\r\n",
            b"\x00\x01dns",
        );
        assert_eq!(
            read_http_response(&mut ok).await.unwrap(),
            (b"\x00\x01dns".to_vec(), false),
            "no length: the body ran to the close, and the connection is spent"
        );

        let mut old = response("HTTP/1.0 200 OK\r\n\r\n", b"dns");
        assert_eq!(read_http_response(&mut old).await.unwrap().0, b"dns");

        // A length frames the body, and the connection stays usable unless
        // the resolver said otherwise. Bytes past the length are not a next
        // response, since nothing was asked yet: they are a malformed one.
        let mut framed = response("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n", b"dns");
        assert_eq!(
            read_http_response(&mut framed).await.unwrap(),
            (b"dns".to_vec(), true)
        );
        let mut surplus = response("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n", b"dnsNEXT");
        assert_eq!(
            read_http_response(&mut surplus).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let mut closing = response(
            "HTTP/1.1 200 OK\r\ncontent-length: 3\r\nConnection: keep-alive, Close\r\n\r\n",
            b"dns",
        );
        assert_eq!(
            read_http_response(&mut closing).await.unwrap(),
            (b"dns".to_vec(), false)
        );
        let mut short = response("HTTP/1.1 200 OK\r\ncontent-length: 8\r\n\r\n", b"dns");
        assert_eq!(
            read_http_response(&mut short).await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );

        for head in [
            "HTTP/1.1 404 Not Found\r\n\r\n",
            "HTTP/1.1 500 Internal Server Error\r\n\r\n",
            "HTTP/1.1 301 Moved\r\nlocation: /elsewhere\r\n\r\n",
            "not http at all\r\n\r\n",
        ] {
            let mut bad = response(head, b"body");
            assert_eq!(
                read_http_response(&mut bad).await.unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{head:?}"
            );
        }

        let endless = vec![b'x'; MAX_HTTP_HEAD + 1024];
        let mut cursor = std::io::Cursor::new(endless);
        assert_eq!(
            read_http_response(&mut cursor).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut huge = response("HTTP/1.1 200 OK\r\n\r\n", &vec![b'x'; MAX_DNS_MESSAGE + 1]);
        assert_eq!(
            read_http_response(&mut huge).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
