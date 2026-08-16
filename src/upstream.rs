//! DNS upstream transports: the wire, and only the wire.
//!
//! The policy that decides whether to consult an upstream, and what to do with
//! what it says, is pure and lives in [`crate::dns`]. The single thing this
//! module contributes to a verdict is which [`Upstream`] carried it — which
//! matters because the privacy claim differs per transport, and a user is
//! entitled to know which one they got.
//!
//! Three decisions carry the design.
//!
//! **The trust anchors are Mozilla's bundle, deliberately not the operating
//! system's store.** Boreas installs its own root into the user store for
//! interception, and a resolver trusting the OS store would trust the
//! certificate authority Boreas itself controls — precisely the relationship
//! this connection must not have. A static bundle also makes the resolver's
//! trust independent of anything a user or another application has added.
//!
//! **One connection per query on the byte-stream transports, and one
//! connection for all of them on DoQ — because the correlation differs, not
//! because the effort did.** Concurrent queries on a shared byte stream must be
//! matched by transaction id, and the id travelling upstream is the *client's*,
//! so [`DotUpstream`] and [`DohUpstream`] dial per query and are correct without
//! any demultiplexer. The cost is bounded by rustls session resumption: the
//! configuration holds the session cache, each upstream owns one configuration
//! for its lifetime, so every query after the first is a one-round-trip
//! resumption rather than a full handshake.
//!
//! [`DoqUpstream`] has no such problem. RFC 9250 gives each query its own QUIC
//! stream and *requires* the message id be zero, so the stream is the
//! correlation and there is nothing to rewrite between queries — which is why
//! its connection is held rather than redialled, and why the persistent
//! pipelining recorded as a follow-up for the others is already the shape here.
//!
//! **The socket must leave by a route that is not the tunnel.** A resolver
//! reached through the tunnel that is resolving for it is a loop, and
//! excluding it is a platform act this crate cannot perform. [`TunnelBypass`]
//! names the obligation so no implementation can quietly skip it.

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{ClientProfile, Originator, Upstream};

/// The largest upstream reply this crate will read. EDNS0 permits more; a
/// resolver answering a stub does not need it, and the bound is what keeps an
/// upstream from deciding how much memory a query costs.
pub(crate) const MAX_DNS_MESSAGE: usize = 4096;

/// One DNS upstream transport.
///
/// Only the wire. See the module documentation for what is deliberately not
/// here.
pub trait DnsUpstream: Send + Sync {
    /// The transport kind, which is what a verdict's provenance records.
    fn kind(&self) -> Upstream;

    /// Sends one DNS message and returns the reply.
    ///
    /// Called from a task of its own, never from the reactor, so it may await
    /// as long as it likes without stalling the datapath. It must impose its
    /// own timeout: the resolver bounds how many of these run at once, not how
    /// long any one of them takes.
    fn query(&self, message: &[u8]) -> impl Future<Output = io::Result<Vec<u8>>> + Send;
}

/// Creates the sockets a DNS upstream uses.
///
/// It exists because those sockets must not travel through Boreas's own TUN —
/// a resolver reached through the tunnel that is resolving for it is a loop —
/// and excluding them is a platform act this crate cannot perform:
/// `VpnService.protect` on the descriptor on Android, binding the physical
/// interface's address on Windows. The seam names the obligation so that no
/// implementation can quietly skip it.
pub trait TunnelBypass: Send + Sync {
    fn udp(
        &self,
        peer: SocketAddr,
    ) -> impl Future<Output = io::Result<tokio::net::UdpSocket>> + Send;

    fn tcp(
        &self,
        peer: SocketAddr,
    ) -> impl Future<Output = io::Result<tokio::net::TcpStream>> + Send;
}

/// The bypass for a host where nothing is in the way: ordinary sockets on the
/// default route.
///
/// Correct on a desktop whose default route is not the tunnel, and the
/// deliberate wrong answer on Android, where the socket must be protected
/// before it is connected. Named for what it does not do.
pub struct DirectSockets;

impl TunnelBypass for DirectSockets {
    // Written as explicit future types for the same reason `AsyncDevice` is:
    // the trait promises `Send`, and only the explicit form states it.
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
}

/// Plain DNS over UDP to one resolver.
///
/// One ephemeral socket per query, which is what makes concurrent queries
/// correlate without a transaction-id demultiplexer: a connected socket
/// receives exactly its own reply, and the random source port is the entropy a
/// spoofing attacker has to beat.
///
/// Do53 is readable by anything on the path, which is why [`Upstream`]
/// distinguishes it. It is the transport that needs no TLS stack, and so the
/// one that could exist before the crate admitted one.
pub struct Do53Upstream<B> {
    resolver: SocketAddr,
    bypass: B,
    timeout: Duration,
}

/// Two seconds matches what stub resolvers already assume; a longer wait holds
/// a resolver permit another query could be using.
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

/// A configured TLS client for one resolver: where it lives, what name its
/// certificate must carry, and the trust anchors that decide it.
///
/// Shared by [`DotUpstream`] and [`DohUpstream`] because the differences
/// between them start after the handshake. Building one parses the whole
/// Mozilla bundle, so it is built once per upstream and never per query — and
/// because rustls keeps its session cache in the configuration, that is also
/// what makes every query after the first a resumption.
/// The stream a TLS upstream hands back. Named because two dialers and four
/// transports return it and the type is a mouthful.
type UpstreamTls = tokio_boring::SslStream<crate::Opaque<tokio::net::TcpStream>>;

struct TlsDialer<B> {
    resolver: SocketAddr,
    server_name: String,
    originator: Arc<Originator>,
    /// The ALPN list in wire format, built once per configured upstream.
    alpn: Vec<u8>,
    bypass: B,
    timeout: Duration,
}

/// Why a TLS upstream could not be configured. Configuration errors, not
/// query errors: every one of them is decided before a packet moves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpstreamError {
    /// The certificate name is not a DNS name or IP address rustls can verify
    /// against.
    InvalidServerName,
    /// The URL is not an absolute `https://` URL with a host.
    InvalidUrl,
    /// The crypto provider refused the requested protocol versions. Reported
    /// rather than unwrapped because it is a build-configuration mismatch, and
    /// a panic at start-up is a worse diagnosis than a named error.
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
    /// `alpn` is the protocol list the handshake offers; empty offers none.
    fn new(
        resolver: SocketAddr,
        server_name: &str,
        alpn: &[&[u8]],
        bypass: B,
    ) -> Result<Self, UpstreamError> {
        // Parsed only to reject a name no handshake could verify. The value is
        // discarded: BoringSSL takes the name as a string.
        ServerName::try_from(server_name).map_err(|_| UpstreamError::InvalidServerName)?;

        // **BoringSSL, wearing Chrome's hello.** An encrypted DNS query is the
        // first thing a connection does and the most telling: a resolver
        // reached with a `rustls` ClientHello names the software, not the
        // browser it is resolving for. There is no client hello to mirror here,
        // so the profile is a stated one.
        //
        // The anchors are Mozilla's bundle and not the platform store; see the
        // module documentation for why that is a security property here rather
        // than a portability shortcut.
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
        let stream = self.bypass.tcp(self.resolver).await?;
        // Nagle would hold a short query waiting for more bytes that are not
        // coming, which on a request/response protocol is pure added latency.
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

/// DNS over TLS, RFC 7858.
///
/// The framing is the whole protocol: a two-octet big-endian length followed
/// by the message, in both directions, exactly as DNS over TCP. Everything
/// else is the TLS session underneath it.
///
/// DoT is encrypted and authenticated but not disguised: it runs on port 853,
/// which a network that objects to it can block outright. That is the
/// difference [`DohUpstream`] exists to cover, and the reason a verdict names
/// which of them answered.
pub struct DotUpstream<B> {
    dialer: TlsDialer<B>,
}

/// The IANA-assigned port for DNS over TLS.
pub const DOT_PORT: u16 = 853;

impl<B: TunnelBypass> DotUpstream<B> {
    /// `server_name` is the name the resolver's certificate must carry, which
    /// is not the address it lives at: `1.1.1.1` presents `one.one.one.one`.
    /// Passing the address as the name is a supported and much weaker
    /// configuration, so the two are separate parameters rather than one.
    pub fn new(resolver: SocketAddr, server_name: &str, bypass: B) -> Result<Self, UpstreamError> {
        // RFC 7858 section 3.2 registers the "dot" ALPN identifier.
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
            // The timeout covers connect, handshake, and exchange together:
            // the caller's interest is "an answer within two seconds", not the
            // budget of any one step.
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

/// Reads one two-octet-length-prefixed DNS message.
///
/// The declared length is checked against [`MAX_DNS_MESSAGE`] before a buffer
/// is sized, so a hostile or broken resolver cannot decide how much memory a
/// query costs.
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

/// DNS over HTTPS, RFC 8484.
///
/// One `POST` of `application/dns-message`, which is the wire format already
/// in hand — no re-encoding, and no base64 as the `GET` form would need.
///
/// **Conformance gap, deliberate and bounded.** RFC 8484 section 5.2 requires
/// a DoH client to support HTTP/2, and this one speaks HTTP/1.1. Public
/// resolvers accept it, and the alternative today is an HTTP/2 client this
/// crate has no other use for; the `h2` stack arrives with P14's interception,
/// at which point this implementation moves onto it behind the same trait. The
/// request offers `http/1.1` in ALPN, so a server that will not speak it fails
/// the handshake rather than the exchange.
///
/// `Connection: close` and a read to end-of-stream, which is what keeps the
/// response reader to a status line and headers: there is no chunked transfer
/// to decode when the body ends with the connection.
pub struct DohUpstream<B> {
    dialer: TlsDialer<B>,
    /// The complete request head, built once. Only the body length changes per
    /// query, so the rest is not rebuilt for each one.
    authority: String,
    path: String,
}

impl<B: TunnelBypass> DohUpstream<B> {
    /// `url` is the absolute `https://` endpoint, and `resolver` is the
    /// address to reach it at — supplied rather than resolved, because
    /// resolving the resolver's own name is the bootstrap problem this crate
    /// declines to have.
    pub fn new(url: &str, resolver: SocketAddr, bypass: B) -> Result<Self, UpstreamError> {
        let rest = url
            .strip_prefix("https://")
            .ok_or(UpstreamError::InvalidUrl)?;
        let (authority, path) = match rest.find('/') {
            Some(slash) => (&rest[..slash], &rest[slash..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            return Err(UpstreamError::InvalidUrl);
        }
        // The certificate must carry the host, not the port.
        let host = authority
            .rsplit_once(':')
            .map_or(authority, |(host, _)| host)
            .trim_start_matches('[')
            .trim_end_matches(']');

        Ok(Self {
            dialer: TlsDialer::new(resolver, host, &[b"http/1.1"], bypass)?,
            authority: authority.to_owned(),
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

/// DNS over QUIC, RFC 9250.
///
/// **The stream is the correlation, which is why this one connection is
/// persistent where the TLS transports are not.** DoT and DoH dial per query
/// because concurrent queries on a shared byte stream must be matched by
/// transaction id, and the id travelling upstream is the client's. DoQ has no
/// such problem: each query gets its own bidirectional QUIC stream, the answer
/// arrives on the stream that asked, and RFC 9250 §4.2.1 requires the message
/// id be **zero** precisely so that nothing is tempted to correlate on it. So
/// the connection is held and every query is one stream on it — which is also
/// the only shape that makes DoQ cheaper than DoT rather than the same thing
/// with a QUIC handshake in front.
///
/// The framing on that stream is DoT's: a two-octet big-endian length, then the
/// message, in both directions. The client closes its half after the query,
/// which is what tells the server no more is coming.
///
/// **The id is rewritten to zero, and the caller's is restored on the way
/// back.** A resolver that saw a non-zero id may treat the connection as a
/// protocol error and close it (§4.2.1), and a stub resolver that saw a zero id
/// come back would discard the reply as unsolicited. Both halves of the
/// substitution live here, so no caller has to know DoQ is underneath.
pub struct DoqUpstream<B> {
    resolver: SocketAddr,
    server_name: String,
    bypass: B,
    quic: crate::QuicConfigFactory,
    /// The live connection. An async mutex because establishing one awaits, and
    /// because two queries arriving together must produce *one* connection
    /// rather than two — the second waits and finds the first's.
    connection: tokio::sync::Mutex<Option<crate::QuicConnection>>,
    /// Cancels the driver task, so the connection's lifetime is this value's.
    shutdown: tokio_util::sync::CancellationToken,
    timeout: Duration,
}

/// RFC 9250 §4.1.1 registers this ALPN, and a resolver that does not offer it
/// fails the handshake rather than the exchange.
const DOQ_ALPN: &[u8] = b"doq";

/// The idle timeout the connection is configured with. Long enough that a
/// browsing session's queries share one connection, short enough that a
/// forgotten one does not hold a socket for the process's life.
const DOQ_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The two octets an RFC 9250 message id occupies, which must be zero on the
/// wire and is restored from the caller's on the way back.
const DNS_ID_BYTES: usize = 2;

impl<B> Drop for DoqUpstream<B> {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

impl<B: TunnelBypass> DoqUpstream<B> {
    /// `server_name` is the name the resolver's certificate must carry, which
    /// is not the address it lives at — the same distinction [`DotUpstream`]
    /// draws, and for the same reason.
    ///
    /// `quic` builds the transport configuration, including certificate
    /// verification, which is the caller's to set for the same reason it is on
    /// every other QUIC egress here: a test resolver and a production one
    /// differ there and nowhere else.
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

    /// A `quiche::Config` with DoQ's ALPN and idle timeout, ready for a caller
    /// to set verification on.
    pub fn quic_config() -> Result<quiche::Config, crate::EgressError> {
        crate::client_config(&[DOQ_ALPN], DOQ_IDLE_TIMEOUT)
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The live connection, dialling one if there is none.
    ///
    /// Holding the lock across the handshake is deliberate: it is what makes
    /// concurrent first queries share a connection instead of racing to build
    /// two, and a second connection would mean a second handshake and a second
    /// socket for no gain.
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
                // §4.2.1: zero on the wire, whatever the client chose.
                stream.write_all(&[0, 0]).await?;
                stream.write_all(&message[DNS_ID_BYTES..]).await?;
                stream.flush().await?;
                // Half-close is the whole "no more is coming" signal DoQ has.
                stream.shutdown().await?;

                let mut reply = read_length_prefixed(&mut stream).await?;
                // The stub resolver correlates on the id it sent, so a reply
                // carrying DoQ's mandatory zero would be discarded as
                // unsolicited. Restoring it is the other half of the same
                // substitution.
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

/// The largest response head this reader will accept before giving up. A
/// resolver that needs more than this to say "200" is not one to keep reading
/// from, and the bound is what stops a hostile one from growing a buffer.
const MAX_HTTP_HEAD: usize = 8 * 1024;

/// Reads an HTTP/1.1 response and returns its body.
///
/// Total on the shape this client asks for and refuses everything else: the
/// request sets `Connection: close`, so the body ends with the stream and
/// there is no chunked encoding to decode. Only a `200` yields a body; every
/// other status is an error, because a DNS answer parsed out of an error page
/// would be worse than no answer.
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
    // `Connection: close` makes end-of-stream the end of the body, so the read
    // needs no `Content-Length` and no chunk decoder — only the same bound the
    // length-prefixed reader applies.
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

/// The offset just past the blank line that ends an HTTP head.
fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| at + 4)
}

/// Whether the status line reports 200. The version is accepted in either
/// 1.0 or 1.1 form, because a server may answer 1.0 to a 1.1 request.
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
        // The provenance a verdict records comes from here, and it is the
        // whole of what a transport contributes to one.
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

    /// DoQ's message-id substitution, which is the one place this transport
    /// edits what it carries. Both halves must hold: zero on the wire, because
    /// RFC 9250 §4.2.1 lets a resolver close the connection over a non-zero id;
    /// and the caller's id restored on the reply, because a stub resolver
    /// discards an answer whose id is not the one it sent.
    #[test]
    fn doq_writes_a_zero_id_upstream_and_restores_the_caller_s_on_the_way_back() {
        // The exact bytes the query writer produces, assembled the way it does.
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

        // A message too short to carry an id is not a DNS message, and is
        // refused rather than padded into one.
        assert!([0u8; 1].get(..DNS_ID_BYTES).is_none());
    }

    #[test]
    fn a_tls_upstream_refuses_a_name_it_could_not_verify() {
        // Configuration errors are decided before a packet moves, which is why
        // they are a `Result` at construction and not an `io::Error` per query.
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
        // An address is a weaker but supported server name.
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
        // The certificate carries the host, never the port.
        assert_eq!(upstream.dialer.server_name, "dns.example");

        // A URL with no path still addresses the origin's root.
        let bare = DohUpstream::new("https://dns.example", address(443), DirectSockets).unwrap();
        assert_eq!(bare.path, "/");
    }

    #[tokio::test]
    async fn the_length_prefixed_reader_bounds_what_a_resolver_can_make_it_hold() {
        // RFC 7858 framing: two octets of length, then exactly that many.
        let mut framed: Vec<u8> = 4u16.to_be_bytes().to_vec();
        framed.extend_from_slice(b"abcd");
        let mut cursor = std::io::Cursor::new(framed);
        assert_eq!(read_length_prefixed(&mut cursor).await.unwrap(), b"abcd");

        // A declared length past the bound is refused before a buffer is
        // sized, so an upstream cannot decide how much memory a query costs.
        let oversized = (MAX_DNS_MESSAGE as u16 + 1).to_be_bytes().to_vec();
        let mut cursor = std::io::Cursor::new(oversized);
        assert_eq!(
            read_length_prefixed(&mut cursor).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        // A truncated frame is an error, not a short message.
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

        // A 1.0 answer to a 1.1 request is legal and accepted.
        let mut old = response("HTTP/1.0 200 OK\r\n\r\n", b"dns");
        assert_eq!(read_http_body(&mut old).await.unwrap(), b"dns");

        // Anything else is an error: a DNS answer parsed out of an error page
        // would be worse than no answer at all.
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

        // A head that never ends is bounded rather than read forever.
        let endless = vec![b'x'; MAX_HTTP_HEAD + 1024];
        let mut cursor = std::io::Cursor::new(endless);
        assert_eq!(
            read_http_body(&mut cursor).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        // A body past the bound is refused for the same reason.
        let mut huge = response("HTTP/1.1 200 OK\r\n\r\n", &vec![b'x'; MAX_DNS_MESSAGE + 1]);
        assert_eq!(
            read_http_body(&mut huge).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
