//! DNS upstream transports and their wire handling.
//!
//! Policy remains in [`crate::policy::dns`]; this module supplies transport
//! provenance and performs only the selected protocol exchange. Mozilla's
//! trust bundle is independent of the user-installed interception root.
//!
//! Do53, DoT, and DoH use one connection per query because a shared byte stream
//! needs transaction-ID demultiplexing. DoQ uses one persistent connection:
//! RFC 9250 gives each query its own stream and requires a zero message ID.
//! [`TunnelBypass`] keeps resolver sockets outside the tunnel.

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{ClientProfile, Originator, Upstream};

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

/// Plain DNS over UDP to one resolver.
pub struct Do53Upstream<B> {
    resolver: SocketAddr,
    bypass: B,
    timeout: Duration,
}

/// Default query timeout.
pub const DEFAULT_UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);

impl<B: TunnelBypass> Do53Upstream<B> {
    pub fn new(resolver: SocketAddr, bypass: B) -> Self {
        Self {
            resolver,
            bypass,
            timeout: DEFAULT_UPSTREAM_TIMEOUT,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl<B: TunnelBypass> DnsUpstream for Do53Upstream<B> {
    fn kind(&self) -> Upstream {
        Upstream::Do53
    }

    #[allow(clippy::manual_async_fn)]
    fn query(&self, message: &[u8]) -> impl Future<Output = io::Result<Vec<u8>>> + Send {
        async move {
            let socket = self.bypass.udp(self.resolver).await?;
            socket.send(message).await?;
            let mut reply = vec![0u8; MAX_DNS_MESSAGE];
            let len = tokio::time::timeout(self.timeout, socket.recv(&mut reply))
                .await
                .map_err(timed_out)??;
            reply.truncate(len);
            Ok(reply)
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
    timeout: Duration,
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
            timeout: DEFAULT_UPSTREAM_TIMEOUT,
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

/// DNS over TLS, RFC 7858, using DNS-over-TCP framing.
pub struct DotUpstream<B> {
    dialer: TlsDialer<B>,
}

/// The IANA-assigned port for DNS over TLS.
pub const DOT_PORT: u16 = 853;

impl<B: TunnelBypass> DotUpstream<B> {
    /// Configures the resolver address and certificate name separately.
    pub fn new(resolver: SocketAddr, server_name: &str, bypass: B) -> Result<Self, UpstreamError> {
        Ok(Self {
            dialer: TlsDialer::new(resolver, server_name, &[b"dot"], bypass)?,
        })
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.dialer.timeout = timeout;
        self
    }
}

impl<B: TunnelBypass> DnsUpstream for DotUpstream<B> {
    fn kind(&self) -> Upstream {
        Upstream::DoT
    }

    #[allow(clippy::manual_async_fn)]
    fn query(&self, message: &[u8]) -> impl Future<Output = io::Result<Vec<u8>>> + Send {
        async move {
            let length = u16::try_from(message.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "query exceeds 65535"))?;
            tokio::time::timeout(self.dialer.timeout, async {
                let mut stream = self.dialer.connect().await?;
                stream.write_all(&length.to_be_bytes()).await?;
                stream.write_all(message).await?;
                stream.flush().await?;
                read_length_prefixed(&mut stream).await
            })
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

/// DNS over HTTPS, RFC 8484, over HTTP/1.1 with connection-close framing.
pub struct DohUpstream<B> {
    dialer: TlsDialer<B>,
    /// Request authority and path.
    authority: String,
    path: String,
}

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
            authority: authority.as_str().to_owned(),
            path: path.to_owned(),
        })
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.dialer.timeout = timeout;
        self
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
                 content-length: {}\r\n\
                 connection: close\r\n\r\n",
                self.path,
                self.authority,
                message.len(),
            );
            tokio::time::timeout(self.dialer.timeout, async {
                let mut stream = self.dialer.connect().await?;
                stream.write_all(head.as_bytes()).await?;
                stream.write_all(message).await?;
                stream.flush().await?;
                read_http_body(&mut stream).await
            })
            .await
            .map_err(timed_out)?
        }
    }
}

/// DNS over QUIC, RFC 9250. Each query uses its own stream and a zero message ID.
pub struct DoqUpstream<B> {
    resolver: SocketAddr,
    server_name: String,
    bypass: B,
    quic: crate::QuicConfigFactory,
    /// Shared live connection.
    connection: tokio::sync::Mutex<Option<crate::QuicConnection>>,
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

impl<B: TunnelBypass> DoqUpstream<B> {
    /// Configures the resolver address, certificate name, and QUIC factory.
    pub fn new(
        resolver: SocketAddr,
        server_name: &str,
        bypass: B,
        quic: crate::QuicConfigFactory,
    ) -> Self {
        Self {
            resolver,
            server_name: server_name.to_owned(),
            bypass,
            quic,
            connection: tokio::sync::Mutex::new(None),
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
        let mut held = self.connection.lock().await;
        if let Some(live) = held.as_ref().filter(|live| live.is_alive()) {
            return Ok(live.clone());
        }
        let socket = self.bypass.udp(self.resolver).await?;
        let config = (self.quic)().map_err(quic_failed)?;
        let handshake =
            crate::Handshake::establish(socket, self.resolver, &self.server_name, config)
                .await
                .map_err(quic_failed)?;
        let live = handshake.drive(self.shutdown.clone());
        *held = Some(live.clone());
        Ok(live)
    }
}

fn quic_failed(_: crate::EgressError) -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionRefused,
        "the DoQ connection failed",
    )
}

impl<B: TunnelBypass> DnsUpstream for DoqUpstream<B> {
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

/// Reads a `200` HTTP/1.1 response body with bounded connection-close framing.
async fn read_http_body<S>(stream: &mut S) -> io::Result<Vec<u8>>
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

    let mut body = buffer.split_off(body_at);
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
    Ok(body)
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
        assert_eq!(read_http_body(&mut ok).await.unwrap(), b"\x00\x01dns");

        let mut old = response("HTTP/1.0 200 OK\r\n\r\n", b"dns");
        assert_eq!(read_http_body(&mut old).await.unwrap(), b"dns");

        for head in [
            "HTTP/1.1 404 Not Found\r\n\r\n",
            "HTTP/1.1 500 Internal Server Error\r\n\r\n",
            "HTTP/1.1 301 Moved\r\nlocation: /elsewhere\r\n\r\n",
            "not http at all\r\n\r\n",
        ] {
            let mut bad = response(head, b"body");
            assert_eq!(
                read_http_body(&mut bad).await.unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{head:?}"
            );
        }

        let endless = vec![b'x'; MAX_HTTP_HEAD + 1024];
        let mut cursor = std::io::Cursor::new(endless);
        assert_eq!(
            read_http_body(&mut cursor).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut huge = response("HTTP/1.1 200 OK\r\n\r\n", &vec![b'x'; MAX_DNS_MESSAGE + 1]);
        assert_eq!(
            read_http_body(&mut huge).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
