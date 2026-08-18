//! The transports a proxy protocol can speak over, as one composable family.
//!
//! VLESS carries no encryption and no framing of its own; it is a header
//! followed by bytes. Everything that makes a deployment survive a hostile
//! network — TLS, looking like a WebSocket to a CDN, riding HTTP/2 so a
//! middlebox sees an ordinary request — lives *under* the protocol rather than
//! inside it. sing-box calls these V2Ray transports and offers five (`http`,
//! `ws`, `quic`, `grpc`, `httpupgrade`) beneath an optional TLS layer; this
//! module is that set.
//!
//! **The family is closed under composition, and the types say so.** A
//! transport is one method — *obtain a byte stream* — so a transport that wraps
//! another is a transport, and TLS is not a flag on five configurations but a
//! sixth transport the others are built over:
//!
//! ```text
//! WebSocketTransport::new(ws, TlsTransport::new(tls, DirectSockets))
//! GrpcTransport::new(grpc, TlsTransport::new(tls, DirectSockets))
//! ```
//!
//! sing-box reaches the same arrangement by threading a `tlsConfig` through
//! every constructor and branching on it five times. Making the layer a value
//! rather than a nullable parameter removes those branches and, with them, the
//! possibility of a transport that forgets to apply the TLS it was handed.
//!
//! **Every wire detail here was read from sing-box's `transport/v2ray*`
//! packages before it was written**, and checked against a running server
//! afterwards, because these formats are defined by implementation rather than
//! by specification. Two of them are traps worth naming in advance:
//!
//! - **gRPC's length prefix is a protobuf varint, not a QUIC varint.** They are
//!   different encodings that agree on small values, so [`crate::varint`] would
//!   appear to work and would corrupt any message of 64 bytes or more. It has
//!   its own encoder here, and a test asserts the two disagree.
//! - **Both HTTPUpgrade and WebSocket over-read.** Reading a header from a byte
//!   stream consumes whatever followed it in the same segment, and what follows
//!   is payload. Both hand the surplus to [`Prefixed`], which is the same fix
//!   the SOCKS5 reply reader needed.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use futures_core::Stream;
use futures_sink::Sink;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Mutex,
};
use tokio_util::sync::CancellationToken;

use crate::{
    AsyncStream, BoxFuture, ClientProfile, EgressError, Originator, Prefixed, ProxyError,
    TunnelBypass,
    quic::{Handshake, QuicConnection, client_config},
};

/// How a proxy protocol obtains the byte stream it speaks over.
///
/// The one seam that separates *what is said* from *what carries it*. It is
/// deliberately a single method with no configuration in its signature: a
/// transport that needed to be told about the protocol above it would not be a
/// transport, it would be half of one.
pub trait ProxyTransport: Send + Sync {
    fn dial(&self) -> BoxFuture<'_, Result<Box<dyn AsyncStream>, EgressError>>;

    /// The name the layer below is addressed by, for an HTTP-shaped transport
    /// above it to put in `Host` when the deployment has not overridden it.
    ///
    /// **sing-box's rule, and it matters on the wire**: configured host, then
    /// the TLS server name, then the server's address. A transport that made
    /// something up instead — `localhost`, say — announces itself to any server
    /// that logs the field and to any CDN that routes on it.
    ///
    /// `None` only for a transport that genuinely cannot know. Every chain
    /// bottoms out at [`PlainTransport`] or [`TlsTransport`], both of which can.
    fn authority(&self) -> Option<&str> {
        None
    }
}

/// A boxed chain is itself a transport.
///
/// Composition is what this family is built on, but the *shape* of a chain is a
/// deployment's choice and therefore not known until runtime — the type of
/// `WebSocketTransport<TlsTransport<DirectSockets>>` cannot be written down by
/// code that reads a configuration file. This impl is what lets such code
/// assemble one and hand it over.
impl ProxyTransport for Box<dyn ProxyTransport> {
    fn dial(&self) -> BoxFuture<'_, Result<Box<dyn AsyncStream>, EgressError>> {
        (**self).dial()
    }

    fn authority(&self) -> Option<&str> {
        (**self).authority()
    }
}

/// A plain TCP transport through the tunnel bypass.
///
/// Correct for VLESS behind a transport that already provides confidentiality,
/// and for tests. On its own it is cleartext, which is why the type says
/// `Plain` rather than something that could be mistaken for secure.
pub struct PlainTransport<B> {
    server: SocketAddr,
    /// Rendered once, because `authority` hands out a borrow and a
    /// `SocketAddr` has no `&str` view of its own.
    authority: String,
    bypass: B,
}

impl<B: TunnelBypass> PlainTransport<B> {
    pub fn new(server: SocketAddr, bypass: B) -> Self {
        Self {
            authority: server.to_string(),
            server,
            bypass,
        }
    }
}

impl<B: TunnelBypass + 'static> ProxyTransport for PlainTransport<B> {
    fn dial(&self) -> BoxFuture<'_, Result<Box<dyn AsyncStream>, EgressError>> {
        Box::pin(async move {
            let stream =
                crate::within(crate::Wait::TcpConnect, self.bypass.tcp(self.server)).await?;
            Ok(Box::new(stream) as Box<dyn AsyncStream>)
        })
    }

    fn authority(&self) -> Option<&str> {
        Some(&self.authority)
    }
}

// ---------------------------------------------------------------- TLS

/// TLS over TCP: the layer the other transports are built on.
pub struct TlsConfig {
    pub server: SocketAddr,
    /// Presented in SNI and verified against the server's certificate.
    pub server_name: String,
    /// ALPN to offer. The transport above chooses it — `http/1.1` for
    /// WebSocket and HTTPUpgrade, `h2` for gRPC and HTTP — because offering the
    /// wrong one is how a server closes the connection at the handshake with no
    /// explanation.
    pub alpn: Vec<Vec<u8>>,
    /// Trust anchors to accept *in addition to* the bundled Mozilla set,
    /// DER-encoded.
    ///
    /// Empty in the ordinary case. It exists because a self-hosted server very
    /// often presents a certificate from a private CA, and the honest answer to
    /// that is to name the CA — not to offer a "skip verification" switch,
    /// which is the same feature with no way to tell a configured exception
    /// from an attack.
    pub extra_roots: Vec<Vec<u8>>,
}

pub struct TlsTransport<B> {
    server: SocketAddr,
    server_name: String,
    originator: Arc<Originator>,
    /// The ALPN list in wire format, built once because it never varies for a
    /// configured transport.
    alpn: Vec<u8>,
    bypass: B,
}

impl<B: TunnelBypass> TlsTransport<B> {
    /// **BoringSSL, wearing Chrome's hello.** A VLESS-family transport exists to
    /// look like a browser reaching a website, so a `rustls` ClientHello on the
    /// wire is the one thing it must not send. There is no client hello to
    /// mirror on this leg — nothing local originated it — so the profile is
    /// [`ClientProfile::chrome`] rather than the empty one, which would leave
    /// BoringSSL's own defaults and no `X25519MLKEM768`.
    ///
    /// Trust anchors are Mozilla's bundle rather than the platform store, for
    /// the reason the DNS upstreams give: the set this crate verifies against
    /// should not be one a device owner or an MDM profile can widen.
    pub fn new(config: TlsConfig, bypass: B) -> Result<Self, EgressError> {
        // Parsed only to reject a name no handshake could verify. The value is
        // discarded: BoringSSL takes the name as a string.
        rustls::pki_types::ServerName::try_from(config.server_name.as_str())
            .map_err(|_| ProxyError::Address)?;
        let alpn: Vec<&[u8]> = config.alpn.iter().map(Vec::as_slice).collect();
        Ok(Self {
            server: config.server,
            server_name: config.server_name,
            originator: Arc::new(Originator::new().with_extra_roots(&config.extra_roots)),
            alpn: crate::alpn_list(&alpn),
            bypass,
        })
    }
}

impl<B: TunnelBypass + 'static> ProxyTransport for TlsTransport<B> {
    fn dial(&self) -> BoxFuture<'_, Result<Box<dyn AsyncStream>, EgressError>> {
        Box::pin(async move {
            let tcp = crate::within(crate::Wait::TcpConnect, self.bypass.tcp(self.server)).await?;
            let stream = self
                .originator
                .connect(&self.server_name, &ClientProfile::chrome(), &self.alpn, tcp)
                .await?;
            Ok(Box::new(stream) as Box<dyn AsyncStream>)
        })
    }

    /// The name in SNI, which is what a server expects to see echoed in `Host`
    /// and what a fronted deployment's CDN routes on.
    fn authority(&self) -> Option<&str> {
        Some(&self.server_name)
    }
}

// ------------------------------------------------------- HTTP framing

/// The `Host` and extra headers an HTTP-shaped transport sends.
///
/// Shared by WebSocket, HTTPUpgrade, gRPC, and HTTP because all four send an
/// HTTP request whose headers are how a deployment makes itself look like
/// whatever the operator wants it to look like.
#[derive(Clone, Default)]
pub struct HttpHeaders {
    /// Overrides the `Host` header. A CDN deployment sets this to the fronted
    /// name while connecting to a different address entirely.
    pub host: Option<String>,
    pub extra: Vec<(String, String)>,
}

impl HttpHeaders {
    fn host_or(&self, fallback: &str) -> String {
        self.host.clone().unwrap_or_else(|| fallback.to_owned())
    }
}

/// Normalises a configured path the way sing-box does: a path that does not
/// begin with `/` gets one, because a server matching on `/x` never matches a
/// request for `x` and the failure looks like a rejected connection.
fn normalise_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    }
}

// ---------------------------------------------------------- WebSocket

pub struct WebSocketConfig {
    pub path: String,
    pub headers: HttpHeaders,
}

/// VLESS over WebSocket: the most deployed transport in the family, because a
/// WebSocket traverses a CDN and an ordinary TCP connection does not.
///
/// **The protocol comes from `tokio-tungstenite`; only the trait adaptation is
/// written here.** Framing, masking, and the ping/pong and close state machine
/// are exactly the things a hand-rolled implementation gets subtly wrong, and
/// that crate is the ecosystem's standard for them. What it does not provide is
/// an `AsyncRead + AsyncWrite` view, because a WebSocket is a message stream
/// and not a byte stream; the ~80 lines below are that projection, and writing
/// them is cheaper than the `futures-io`-to-`tokio-io` compatibility shim the
/// available adapter crates would need.
pub struct WebSocketTransport<T> {
    path: String,
    headers: HttpHeaders,
    inner: T,
}

impl<T: ProxyTransport> WebSocketTransport<T> {
    pub fn new(config: WebSocketConfig, inner: T) -> Self {
        Self {
            path: normalise_path(&config.path),
            headers: config.headers,
            inner,
        }
    }
}

impl<T: ProxyTransport + 'static> ProxyTransport for WebSocketTransport<T> {
    fn dial(&self) -> BoxFuture<'_, Result<Box<dyn AsyncStream>, EgressError>> {
        Box::pin(async move {
            let stream = self.inner.dial().await?;
            // The authority is only ever a name here: the socket is already
            // connected, so this URI is read for its `Host` header and its path
            // and never resolved.
            let host = self.headers.host_or(self.inner.authority().unwrap_or(""));
            let uri = format!("ws://{host}{}", self.path);
            let mut request = http::Request::builder()
                .uri(&uri)
                .header("Host", &host)
                // tungstenite requires these to be present and correct; it
                // generates the key and verifies the accept token itself.
                .header("Connection", "Upgrade")
                .header("Upgrade", "websocket")
                .header("Sec-WebSocket-Version", "13")
                .header(
                    "Sec-WebSocket-Key",
                    tokio_tungstenite::tungstenite::handshake::client::generate_key(),
                );
            for (name, value) in &self.headers.extra {
                request = request.header(name.as_str(), value.as_str());
            }
            let request = request
                .body(())
                .map_err(|_| EgressError::Proxy(ProxyError::Header))?;

            let (socket, _response) = tokio_tungstenite::client_async(request, stream)
                .await
                .map_err(|_| EgressError::Proxy(ProxyError::Header))?;
            Ok(Box::new(WebSocketStream::new(socket)) as Box<dyn AsyncStream>)
        })
    }

    /// Delegated: what a chain is addressed by belongs to whatever is
    /// underneath it, not to the framing on top.
    fn authority(&self) -> Option<&str> {
        self.inner.authority()
    }
}

/// A WebSocket message stream, projected to a byte stream.
///
/// Writes become one binary message each and reads concatenate binary payloads,
/// which is what sing-box's own conn does. Non-binary data frames are skipped
/// rather than treated as an error, again matching it: a server or an
/// intermediary that sends a text frame has not corrupted the tunnel.
struct WebSocketStream<S> {
    socket: tokio_tungstenite::WebSocketStream<S>,
    /// The unconsumed tail of a message larger than the last read buffer. The
    /// same idiom [`crate::bridge`] uses, and for the same reason: losing it
    /// silently truncates every message that does not fit one read.
    pending: bytes::Bytes,
}

impl<S> WebSocketStream<S> {
    fn new(socket: tokio_tungstenite::WebSocketStream<S>) -> Self {
        Self {
            socket,
            pending: bytes::Bytes::new(),
        }
    }
}

impl<S> AsyncRead for WebSocketStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use bytes::Buf;
        use std::task::Poll;
        use tokio_tungstenite::tungstenite::Message;

        let this = self.get_mut();
        loop {
            if !this.pending.is_empty() {
                let moved = buf.remaining().min(this.pending.len());
                buf.put_slice(&this.pending[..moved]);
                this.pending.advance(moved);
                return Poll::Ready(Ok(()));
            }
            match std::pin::Pin::new(&mut this.socket).poll_next(cx) {
                Poll::Ready(Some(Ok(Message::Binary(payload)))) => {
                    // An empty binary message carries nothing; returning here
                    // would be a spurious end of stream, so loop instead.
                    if payload.is_empty() {
                        continue;
                    }
                    this.pending = payload;
                }
                // A close frame, or the stream ending, is end of stream.
                Poll::Ready(Some(Ok(Message::Close(_))) | None) => return Poll::Ready(Ok(())),
                // Text, ping, pong, and frame-level messages carry no tunnel
                // payload. `tungstenite` answers pings itself; these are simply
                // not ours.
                Poll::Ready(Some(Ok(_))) => continue,
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Err(std::io::Error::other(error)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncWrite for WebSocketStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;
        use tokio_tungstenite::tungstenite::Message;

        let this = self.get_mut();
        match std::pin::Pin::new(&mut this.socket).poll_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(std::io::Error::other(error))),
            Poll::Pending => return Poll::Pending,
        }
        std::pin::Pin::new(&mut this.socket)
            .start_send(Message::Binary(bytes::Bytes::copy_from_slice(buf)))
            .map_err(std::io::Error::other)?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().socket)
            .poll_flush(cx)
            .map_err(std::io::Error::other)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // `poll_close` sends the close frame, which is the WebSocket spelling
        // of FIN and what the peer needs to see to finish cleanly.
        std::pin::Pin::new(&mut self.get_mut().socket)
            .poll_close(cx)
            .map_err(std::io::Error::other)
    }
}

// -------------------------------------------------------- HTTPUpgrade

pub struct HttpUpgradeConfig {
    pub path: String,
    pub headers: HttpHeaders,
}

/// VLESS over an HTTP/1.1 Upgrade, with no framing at all after the handshake.
///
/// It exists because WebSocket's per-message header and masking cost real
/// throughput while the thing that actually gets a connection through a CDN is
/// the *handshake* looking like a WebSocket's. So this sends exactly that
/// handshake, takes the `101`, and then speaks raw bytes.
///
/// **The reference is sing-box's `v2rayhttpupgrade`, and this matches it byte
/// for byte** — including the two details a from-scratch implementation gets
/// wrong. sing-box builds a Go `http.Request` and calls `Write`, so the wire
/// order is Go's: request line, `Host`, `User-Agent`, then every remaining
/// header **sorted by canonical name**. And it sends Go's default
/// `User-Agent`, because it never sets one. Neither is negotiable: a request
/// whose header order differs from every other client of this protocol is a
/// request that stands out in exactly the logs this transport exists to blend
/// into.
pub struct HttpUpgradeTransport<T> {
    path: String,
    headers: HttpHeaders,
    inner: T,
}

impl<T: ProxyTransport> HttpUpgradeTransport<T> {
    pub fn new(config: HttpUpgradeConfig, inner: T) -> Self {
        Self {
            path: normalise_path(&config.path),
            headers: config.headers,
            inner,
        }
    }
}

impl<T: ProxyTransport + 'static> ProxyTransport for HttpUpgradeTransport<T> {
    fn dial(&self) -> BoxFuture<'_, Result<Box<dyn AsyncStream>, EgressError>> {
        Box::pin(async move {
            let mut stream = self.inner.dial().await?;
            let host = self.headers.host_or(self.inner.authority().unwrap_or(""));
            let mut upgrade = Upgrade::new(&self.path, &host, &self.headers);
            // Whatever followed the `101` is already tunnel payload; the
            // negotiation reports it and `Prefixed` replays it. Omitting that
            // truncates the first read of every connection where the server
            // answers and sends in one segment, which is what sing-box's
            // `bufio.NewCachedConn` exists to prevent on its side.
            //
            // **The mirror image of this is a race in the reference servers,
            // and it is not ours to fix.** Go's `http.Server` buffers whatever
            // it read when a handler hijacks the connection and hands it back
            // in a `bufrw`; both sing-box and Xray-core discard that value, so
            // payload arriving in the window between their `101` and their
            // `Hijack` is lost and the flow is reset. Waiting before writing
            // would narrow that window without closing it, at the cost of a
            // delay on every connection, so this client does what the reference
            // clients do and writes immediately. `tests/interop.rs` retries a
            // flow for this reason and says so.
            let ((), surplus) = crate::negotiate(&mut stream, &mut upgrade).await?;
            Ok(Box::new(Prefixed::new(surplus, stream)) as Box<dyn AsyncStream>)
        })
    }

    fn authority(&self) -> Option<&str> {
        self.inner.authority()
    }
}

/// Go's default, which is what sing-box sends because it never sets one. A
/// deployment that wants a browser's puts it in `headers`.
const GO_USER_AGENT: &str = "Go-http-client/1.1";

/// The HTTP/1.1 Upgrade exchange, as a pure state machine.
///
/// No socket, no clock: the request is built once at construction and handed
/// over on the first advance, and every subsequent one re-reads the same
/// growing response buffer. That is what lets the whole exchange — including a
/// server that dribbles its status line one byte at a time — be tested without
/// a network.
struct Upgrade {
    /// Taken on the first advance, which is how "write once per phase" is
    /// enforced by the type rather than by a flag.
    request: Option<Vec<u8>>,
}

impl Upgrade {
    fn new(path: &str, host: &str, headers: &HttpHeaders) -> Self {
        Self {
            request: Some(encode_upgrade_request(path, host, headers)),
        }
    }
}

impl crate::Negotiation for Upgrade {
    type Output = ();

    /// O(response head), re-parsed from the start on each offer. The head is
    /// bounded by the driver, and re-parsing a few hundred bytes a handful of
    /// times is cheaper than the incremental parser it would take to avoid it.
    fn advance(
        &mut self,
        input: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<crate::Decoded<()>, ProxyError> {
        if let Some(request) = self.request.take() {
            out.extend_from_slice(&request);
        }
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut response = httparse::Response::new(&mut headers);
        let head = match response.parse(input).map_err(|_| ProxyError::Header)? {
            httparse::Status::Complete(head) => head,
            httparse::Status::Partial => return Ok(crate::Decoded::Incomplete),
        };

        // The numeric code, as sing-box checks it. Xray-core compares the whole
        // status line to `"101 Switching Protocols"`, which breaks against a
        // server that writes a different reason phrase; matching the stricter
        // reader would refuse connections the other reference client accepts.
        if response.code != Some(101) {
            return Err(ProxyError::Denied(format!(
                "expected 101, got {}",
                response.code.unwrap_or(0)
            )));
        }
        // A `101` without the upgrade headers is a proxy that answered without
        // switching protocols, and writing tunnel bytes into it would be
        // writing into an HTTP response body. Both reference clients check
        // both, case-insensitively on the value.
        let named = |name: &str, want: &str| {
            response.headers.iter().any(|header| {
                header.name.eq_ignore_ascii_case(name)
                    && std::str::from_utf8(header.value)
                        .is_ok_and(|value| value.trim().eq_ignore_ascii_case(want))
            })
        };
        if !named("Connection", "upgrade") || !named("Upgrade", "websocket") {
            return Err(ProxyError::Denied(
                "101 without the upgrade headers".to_owned(),
            ));
        }
        Ok(crate::Decoded::Complete {
            value: (),
            consumed: head,
        })
    }
}

/// Builds the request exactly as Go's `(*http.Request).Write` would.
///
/// The ordering is the whole point and it is not this crate's choice: request
/// line, `Host`, `User-Agent`, then everything else **sorted by canonical
/// header name**, because that is what `Header.writeSubset` does and therefore
/// what every server that has ever seen this protocol expects. `Connection` and
/// `Upgrade` are in that sorted run rather than ahead of it, so a configured
/// header beginning with `S` lands between them.
///
/// O(headers log headers) for the sort, once per dial.
fn encode_upgrade_request(path: &str, host: &str, headers: &HttpHeaders) -> Vec<u8> {
    let mut sorted: Vec<(String, &str)> = headers
        .extra
        .iter()
        .map(|(name, value)| (canonical(name), value.as_str()))
        .filter(|(name, _)| name != "Host" && name != "User-Agent")
        .collect();
    sorted.push(("Connection".to_owned(), "Upgrade"));
    sorted.push(("Upgrade".to_owned(), "websocket"));
    sorted.sort_by(|left, right| left.0.cmp(&right.0));

    let agent = headers
        .extra
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("User-Agent"))
        .map_or(GO_USER_AGENT, |(_, value)| value.as_str());

    let mut request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {agent}\r\n");
    for (name, value) in sorted {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.into_bytes()
}

/// A header name in MIME canonical form: `content-type` becomes `Content-Type`.
///
/// Go canonicalises before sorting, so sorting the raw configured spelling
/// would order `x-foo` after `Upgrade` where Go orders `X-Foo` before it.
///
/// O(name length), one allocation.
fn canonical(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut starting = true;
    for byte in name.chars() {
        if starting {
            out.extend(
                byte.to_ascii_uppercase()
                    .to_lowercase()
                    .flat_map(char::to_uppercase),
            );
        } else {
            out.push(byte.to_ascii_lowercase());
        }
        starting = byte == '-';
    }
    out
}

// --------------------------------------------------- HTTP/2 and gRPC

/// What an HTTP/2-carried transport puts in its request, and how it frames the
/// bytes inside the body.
///
/// gRPC and `http` differ *only* in these two respects — one path and header
/// set versus another, length-prefixed messages versus raw bytes — so they are
/// one implementation parameterised by this rather than two that drift.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Framing {
    /// gRPC: each write becomes one length-delimited message.
    Grpc,
    /// `http`: the body is the byte stream, unframed.
    Raw,
}

pub struct GrpcConfig {
    /// The service name in the request path, which becomes
    /// `/{service_name}/Tun`.
    pub service_name: String,
    pub headers: HttpHeaders,
}

pub struct HttpConfig {
    pub path: String,
    /// sing-box defaults to `PUT`; a deployment behind a cache that rejects it
    /// uses `GET` or `POST` instead.
    pub method: String,
    pub headers: HttpHeaders,
}

/// VLESS over gRPC: an HTTP/2 `POST` whose body is a stream of gRPC messages.
///
/// It is a *lite* gRPC — the framing and the content type, with no protobuf
/// schema, no compression, and no trailers logic — which is exactly what
/// sing-box's `v2raygrpclite` is and what servers in the wild expect.
pub struct GrpcTransport<T> {
    config: GrpcConfig,
    inner: T,
    connection: Mutex<Option<h2::client::SendRequest<bytes::Bytes>>>,
}

/// VLESS over HTTP/2: a streaming request whose body is the tunnel.
pub struct HttpTransport<T> {
    config: HttpConfig,
    inner: T,
    connection: Mutex<Option<h2::client::SendRequest<bytes::Bytes>>>,
}

impl<T: ProxyTransport> GrpcTransport<T> {
    pub fn new(config: GrpcConfig, inner: T) -> Self {
        Self {
            config,
            inner,
            connection: Mutex::new(None),
        }
    }
}

impl<T: ProxyTransport> HttpTransport<T> {
    pub fn new(config: HttpConfig, inner: T) -> Self {
        Self {
            config: HttpConfig {
                path: normalise_path(&config.path),
                ..config
            },
            inner,
            connection: Mutex::new(None),
        }
    }
}

/// Obtains an HTTP/2 request sender, reusing the live one when there is one.
///
/// **One connection, many streams** — which is the entire reason to carry a
/// proxy over HTTP/2. Holding the lock across the handshake is deliberate, as
/// it is for Hysteria2: it makes concurrent first flows share a connection
/// rather than race to build two.
async fn h2_sender<T: ProxyTransport>(
    held: &Mutex<Option<h2::client::SendRequest<bytes::Bytes>>>,
    inner: &T,
) -> Result<h2::client::SendRequest<bytes::Bytes>, EgressError> {
    let mut held = held.lock().await;
    if let Some(sender) = held.as_ref()
        && let Ok(ready) = sender.clone().ready().await
    {
        *held = Some(ready.clone());
        return Ok(ready);
    }

    let stream = inner.dial().await?;
    let (sender, connection) = h2::client::handshake(stream)
        .await
        .map_err(|_| EgressError::Proxy(ProxyError::Header))?;
    // The connection future *is* the HTTP/2 driver: nothing moves on any stream
    // unless it is polled. It ends when the connection does, which is what
    // makes a detached task the right shape rather than a leak.
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let ready = sender
        .ready()
        .await
        .map_err(|_| EgressError::Proxy(ProxyError::Header))?;
    *held = Some(ready.clone());
    Ok(ready)
}

/// Opens one HTTP/2 stream and returns it as a byte stream **without waiting
/// for the response**.
///
/// **Waiting here deadlocks, and the reference is built the same way.** The
/// server does not answer until it has read the proxy header out of the request
/// body, and the protocol above does not write that header until this returns —
/// so a `dial` that awaited the response would wait for a message that waits
/// for it. sing-box resolves this by running its `RoundTrip` on a goroutine and
/// handing back a connection whose *reads* block until the response arrives;
/// [`Recv::Pending`] is that same structure as a state rather than a task, and
/// it also spares the flow a round trip it never needed.
///
/// The cost is that a refusal — a bad path, a wrong content type — surfaces on
/// the first read rather than from `dial`. That is inherent: the server has not
/// decided yet at the moment `dial` returns.
fn h2_dial(
    mut sender: h2::client::SendRequest<bytes::Bytes>,
    request: http::Request<()>,
    framing: Framing,
) -> Result<Box<dyn AsyncStream>, EgressError> {
    // `end_of_stream: false` is load-bearing: the request body is the tunnel's
    // uplink and stays open for the life of the flow.
    let (response, send) = sender
        .send_request(request, false)
        .map_err(|_| EgressError::Proxy(ProxyError::Header))?;
    Ok(Box::new(H2Stream {
        send,
        recv: Recv::Pending(response),
        framing,
        pending: bytes::Bytes::new(),
        remaining: 0,
        head: Vec::new(),
    }))
}

/// The downlink half of an HTTP/2 stream, which does not exist until the server
/// has answered.
enum Recv {
    Pending(h2::client::ResponseFuture),
    Ready(h2::RecvStream),
    /// The response arrived and was a refusal, or the stream failed. Kept as a
    /// state so a second read reports end of stream rather than polling a
    /// future that has already completed.
    Done,
}

impl<T: ProxyTransport + 'static> ProxyTransport for GrpcTransport<T> {
    fn dial(&self) -> BoxFuture<'_, Result<Box<dyn AsyncStream>, EgressError>> {
        Box::pin(async move {
            let sender = h2_sender(&self.connection, &self.inner).await?;
            let host = self
                .config
                .headers
                .host_or(self.inner.authority().unwrap_or(""));
            let mut request = http::Request::builder()
                .method(http::Method::POST)
                .uri(format!(
                    "https://{host}/{}/Tun",
                    self.config.service_name.trim_matches('/')
                ))
                .header("content-type", "application/grpc")
                // The reference sends gRPC-Go's own user agent, and matching it
                // is the point: a distinctive one would identify the client to
                // anyone watching, which is what the transport exists to avoid.
                .header("user-agent", "grpc-go/1.48.0")
                .header("te", "trailers");
            for (name, value) in &self.config.headers.extra {
                request = request.header(name.as_str(), value.as_str());
            }
            let request = request
                .body(())
                .map_err(|_| EgressError::Proxy(ProxyError::Header))?;
            h2_dial(sender, request, Framing::Grpc)
        })
    }

    /// Delegated: what a chain is addressed by belongs to whatever is
    /// underneath it, not to the framing on top.
    fn authority(&self) -> Option<&str> {
        self.inner.authority()
    }
}

impl<T: ProxyTransport + 'static> ProxyTransport for HttpTransport<T> {
    fn dial(&self) -> BoxFuture<'_, Result<Box<dyn AsyncStream>, EgressError>> {
        Box::pin(async move {
            let sender = h2_sender(&self.connection, &self.inner).await?;
            let host = self
                .config
                .headers
                .host_or(self.inner.authority().unwrap_or(""));
            let method = http::Method::from_bytes(self.config.method.as_bytes())
                .map_err(|_| EgressError::Proxy(ProxyError::Header))?;
            let mut request = http::Request::builder()
                .method(method)
                .uri(format!("https://{host}{}", self.config.path));
            for (name, value) in &self.config.headers.extra {
                request = request.header(name.as_str(), value.as_str());
            }
            let request = request
                .body(())
                .map_err(|_| EgressError::Proxy(ProxyError::Header))?;
            h2_dial(sender, request, Framing::Raw)
        })
    }

    /// Delegated: what a chain is addressed by belongs to whatever is
    /// underneath it, not to the framing on top.
    fn authority(&self) -> Option<&str> {
        self.inner.authority()
    }
}

/// One HTTP/2 stream as a byte stream, with or without gRPC framing.
struct H2Stream {
    send: h2::SendStream<bytes::Bytes>,
    recv: Recv,
    framing: Framing,
    /// Undelivered payload from the last DATA frame.
    pending: bytes::Bytes,
    /// Bytes still owed to the gRPC message being read. Zero means the next
    /// bytes are a header.
    remaining: usize,
    /// A gRPC header split across DATA frames. HTTP/2 does not align its frames
    /// to the framing above it, so a header arriving in two pieces is ordinary
    /// rather than exceptional, and this is what makes the reader total.
    head: Vec<u8>,
}

/// The gRPC message header this transport writes and reads:
/// `00 | u32be(total) | 0x0A | protobuf-varint(len) | payload`.
///
/// The first byte is gRPC's "not compressed" flag and the `u32` is gRPC's own
/// message length. What follows is a protobuf message with one `bytes` field:
/// `0x0A` is the tag for field 1, wire type 2.
const GRPC_HEADER_MIN: usize = 6;

/// Protobuf's varint — LEB128, little-endian groups of seven bits.
///
/// **Not [`crate::varint`].** QUIC's encoding puts its length in the *high*
/// bits of the first byte and is big-endian; protobuf's puts a continuation
/// flag in the high bit and is little-endian. They agree on 0..=63 and diverge
/// immediately after, so using the wrong one produces a transport that works in
/// testing and corrupts every message of 64 bytes or more.
fn put_protobuf_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// The decoding half. `None` for a proper prefix, so a caller reads more.
fn get_protobuf_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (index, &byte) in bytes.iter().enumerate() {
        // Ten groups of seven bits is the most a `u64` can hold; refusing past
        // that stops a hostile peer from spinning this forever.
        if index >= 10 {
            return None;
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
    }
    None
}

/// Wraps one payload as a gRPC message. O(payload length).
fn encode_grpc_message(payload: &[u8], out: &mut Vec<u8>) {
    let mut length = Vec::with_capacity(10);
    put_protobuf_varint(payload.len() as u64, &mut length);
    out.push(0); // not compressed
    out.extend_from_slice(&((1 + length.len() + payload.len()) as u32).to_be_bytes());
    out.push(0x0A); // protobuf field 1, wire type 2
    out.extend_from_slice(&length);
    out.extend_from_slice(payload);
}

/// Reads a gRPC message header, returning the payload length and the header's
/// own size.
///
/// `None` for a proper prefix, which is the whole reason this is separate:
/// **an HTTP/2 DATA frame boundary falls wherever the peer's window put it**,
/// so a header routinely arrives in two pieces and a reader that assumed
/// otherwise would work against every server that happens to send it whole.
///
/// This is as far as sans-IO reaches into [`H2Stream`], and the line is not
/// arbitrary. The framing is a decision about bytes and lifts cleanly; the
/// capacity a write must reserve is the connection's flow-control window,
/// which *is* backpressure and cannot be expressed without the connection that
/// owns it.
///
/// O(header length), which the varint's ten-group ceiling bounds.
fn decode_grpc_header(head: &[u8]) -> Option<(usize, usize)> {
    let (length, used) = get_protobuf_varint(head.get(GRPC_HEADER_MIN..)?)?;
    Some((length as usize, GRPC_HEADER_MIN + used))
}

impl AsyncRead for H2Stream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use bytes::Buf;
        use std::{future::Future, task::Poll};

        let this = self.get_mut();
        loop {
            // Deliver whatever is already decoded before asking for more.
            let deliverable = match this.framing {
                Framing::Raw => this.pending.len(),
                Framing::Grpc => this.remaining.min(this.pending.len()),
            };
            if deliverable > 0 {
                let moved = buf.remaining().min(deliverable);
                if moved > 0 {
                    buf.put_slice(&this.pending[..moved]);
                    this.pending.advance(moved);
                    this.remaining = this.remaining.saturating_sub(moved);
                    return Poll::Ready(Ok(()));
                }
                // A zero-capacity read buffer: nothing to do, and reporting
                // ready with no bytes is a legal no-op rather than EOF.
                return Poll::Ready(Ok(()));
            }

            // A gRPC header may be next, and may be split across frames.
            if this.framing == Framing::Grpc && this.remaining == 0 && !this.pending.is_empty() {
                this.head.extend_from_slice(&this.pending);
                this.pending = bytes::Bytes::new();
            }
            if this.framing == Framing::Grpc
                && this.remaining == 0
                && let Some((length, header)) = decode_grpc_header(&this.head)
            {
                this.remaining = length;
                this.pending = bytes::Bytes::from(this.head.split_off(header));
                this.head.clear();
                continue;
            }

            // The response may not have arrived yet: `dial` deliberately does
            // not wait for it, so the first read is where it lands.
            let body = match &mut this.recv {
                Recv::Ready(body) => body,
                Recv::Done => return Poll::Ready(Ok(())),
                Recv::Pending(response) => match std::pin::Pin::new(response).poll(cx) {
                    Poll::Ready(Ok(response)) => {
                        let status = response.status();
                        if status != http::StatusCode::OK {
                            this.recv = Recv::Done;
                            return Poll::Ready(Err(std::io::Error::other(format!(
                                "the server refused the stream with HTTP/2 status {status}"
                            ))));
                        }
                        this.recv = Recv::Ready(response.into_body());
                        continue;
                    }
                    Poll::Ready(Err(error)) => {
                        this.recv = Recv::Done;
                        return Poll::Ready(Err(std::io::Error::other(error)));
                    }
                    Poll::Pending => return Poll::Pending,
                },
            };

            match std::pin::Pin::new(&mut *body).poll_data(cx) {
                Poll::Ready(Some(Ok(data))) => {
                    // Releasing capacity is what keeps the peer sending; an
                    // HTTP/2 receiver that never does stalls after one window.
                    let _ = body.flow_control().release_capacity(data.len());
                    if this.framing == Framing::Grpc && this.remaining == 0 {
                        this.head.extend_from_slice(&data);
                    } else {
                        this.pending = data;
                    }
                }
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Err(std::io::Error::other(error)));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;

        let this = self.get_mut();
        // Ask for the whole write, then take what the window grants. Reserving
        // before framing matters for gRPC: a message may not be split, so it
        // has to be written whole or not at all.
        this.send.reserve_capacity(buf.len());
        let granted = match this.send.poll_capacity(cx) {
            Poll::Ready(Some(Ok(granted))) => granted,
            Poll::Ready(Some(Err(error))) => {
                return Poll::Ready(Err(std::io::Error::other(error)));
            }
            Poll::Ready(None) => {
                return Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)));
            }
            Poll::Pending => return Poll::Pending,
        };
        let moved = granted.min(buf.len());
        let payload = match this.framing {
            Framing::Raw => bytes::Bytes::copy_from_slice(&buf[..moved]),
            Framing::Grpc => {
                let mut framed = Vec::with_capacity(moved + 16);
                encode_grpc_message(&buf[..moved], &mut framed);
                bytes::Bytes::from(framed)
            }
        };
        this.send
            .send_data(payload, false)
            .map_err(std::io::Error::other)?;
        Poll::Ready(Ok(moved))
    }

    /// `h2` writes when its connection task runs; there is no buffer here to
    /// force out, and waiting for the peer to acknowledge is not what flush
    /// means.
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // An empty DATA frame with END_STREAM is HTTP/2's FIN.
        this.send
            .send_data(bytes::Bytes::new(), true)
            .map_err(std::io::Error::other)?;
        std::task::Poll::Ready(Ok(()))
    }
}

// --------------------------------------------------------------- QUIC

pub struct QuicTransportConfig {
    pub server: SocketAddr,
    pub server_name: String,
    pub idle_timeout: Duration,
}

/// VLESS over QUIC, which costs almost nothing now that Hysteria2 exists.
///
/// sing-box's `quic` transport is a QUIC connection with the `h3` ALPN whose
/// bidirectional streams carry the payload raw — no HTTP/3, despite the ALPN.
/// That is precisely the QUIC stream driver minus the authentication request,
/// so this is that driver with its `http3` step skipped, and every property it
/// establishes (backpressure from QUIC's own window, one connection per
/// egress, the driver's lifetime bound to this value) holds unchanged.
pub struct QuicTransport<B> {
    config: QuicTransportConfig,
    bypass: B,
    connection: Mutex<Option<QuicConnection>>,
    shutdown: CancellationToken,
}

impl<B> Drop for QuicTransport<B> {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

impl<B: TunnelBypass> QuicTransport<B> {
    pub fn new(config: QuicTransportConfig, bypass: B) -> Self {
        Self {
            config,
            bypass,
            connection: Mutex::new(None),
            shutdown: CancellationToken::new(),
        }
    }

    /// The `quiche::Config` this transport needs, for a caller to set
    /// certificate verification on — the same division [`crate::MasqueEgress`]
    /// and Hysteria2 use.
    pub fn quic_config(idle_timeout: Duration) -> Result<quiche::Config, EgressError> {
        client_config(quiche::h3::APPLICATION_PROTOCOL, idle_timeout)
    }
}

impl<B: TunnelBypass + 'static> QuicTransport<B> {
    async fn connection(&self) -> Result<QuicConnection, EgressError> {
        let mut held = self.connection.lock().await;
        if let Some(connection) = held.as_ref()
            && connection.is_alive()
        {
            return Ok(connection.clone());
        }
        let socket = self.bypass.udp(self.config.server).await?;
        let handshake = Handshake::establish(
            socket,
            self.config.server,
            &self.config.server_name,
            Self::quic_config(self.config.idle_timeout)?,
        )
        .await?;
        let connection = handshake.drive(self.shutdown.clone());
        *held = Some(connection.clone());
        Ok(connection)
    }
}

impl<B: TunnelBypass + 'static> ProxyTransport for QuicTransport<B> {
    fn dial(&self) -> BoxFuture<'_, Result<Box<dyn AsyncStream>, EgressError>> {
        Box::pin(async move {
            let connection = self.connection().await?;
            let stream = connection.open_bidi().await?;
            Ok(Box::new(stream) as Box<dyn AsyncStream>)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// **The trap this module exists to avoid.** Protobuf and QUIC varints
    /// agree on every value below 64 and disagree immediately above it, so a
    /// transport built on the wrong one passes a small-message test and
    /// corrupts real traffic. This pins that they differ.
    #[test]
    fn the_protobuf_varint_is_not_the_quic_varint() {
        for value in [0u64, 1, 63] {
            let (mut protobuf, mut quic) = (Vec::new(), Vec::new());
            put_protobuf_varint(value, &mut protobuf);
            crate::varint::put(value, &mut quic);
            assert_eq!(protobuf, quic, "the two agree below 64");
        }
        for value in [64u64, 128, 300, 16_384] {
            let (mut protobuf, mut quic) = (Vec::new(), Vec::new());
            put_protobuf_varint(value, &mut protobuf);
            crate::varint::put(value, &mut quic);
            assert_ne!(
                protobuf, quic,
                "{value} must not encode identically, or the wrong codec would pass tests"
            );
        }
        // The exact protobuf encodings, so a rewrite cannot drift.
        let mut out = Vec::new();
        put_protobuf_varint(300, &mut out);
        assert_eq!(out, [0xac, 0x02]);
    }

    /// Round trip and totality: every proper prefix is incomplete, which is
    /// what lets the reader survive a header split across HTTP/2 frames.
    #[test]
    fn protobuf_varints_round_trip_and_every_prefix_is_incomplete() {
        for value in [0u64, 1, 127, 128, 16_383, 16_384, u32::MAX as u64] {
            let mut encoded = Vec::new();
            put_protobuf_varint(value, &mut encoded);
            assert_eq!(get_protobuf_varint(&encoded), Some((value, encoded.len())));
            for cut in 0..encoded.len() {
                assert_eq!(get_protobuf_varint(&encoded[..cut]), None, "{value}");
            }
        }
    }

    /// The gRPC frame, byte for byte, against the reference's own layout:
    /// `00 | u32be(1 + varint + payload) | 0A | varint(payload) | payload`.
    #[test]
    fn a_grpc_message_matches_the_reference_layout() {
        let mut out = Vec::new();
        encode_grpc_message(b"hello", &mut out);
        assert_eq!(
            out,
            [
                0x00, // not compressed
                0x00, 0x00, 0x00, 0x07, // 1 + 1 + 5
                0x0A, // field 1, wire type 2
                0x05, // payload length
                b'h', b'e', b'l', b'l', b'o',
            ]
        );

        // A payload past the one-byte varint boundary, where the length prefix
        // grows and the u32 must grow with it.
        let mut out = Vec::new();
        encode_grpc_message(&vec![0u8; 300], &mut out);
        assert_eq!(out[0], 0);
        assert_eq!(
            u32::from_be_bytes([out[1], out[2], out[3], out[4]]),
            1 + 2 + 300
        );
        assert_eq!(&out[5..8], &[0x0A, 0xac, 0x02]);
        assert_eq!(out.len(), 6 + 2 + 300);
    }

    /// A path without a leading slash is a configuration a server never
    /// matches, so it is normalised rather than passed through.
    #[test]
    fn a_path_is_given_its_leading_slash() {
        assert_eq!(normalise_path("ws"), "/ws");
        assert_eq!(normalise_path("/ws"), "/ws");
        assert_eq!(normalise_path(""), "/");
    }

    /// The `Host` override is what a CDN-fronted deployment depends on, so an
    /// absent override must fall back rather than send an empty header.
    #[test]
    fn the_host_header_prefers_the_override() {
        let headers = HttpHeaders {
            host: Some("fronted.example".to_owned()),
            extra: Vec::new(),
        };
        assert_eq!(headers.host_or("origin.example"), "fronted.example");
        assert_eq!(
            HttpHeaders::default().host_or("origin.example"),
            "origin.example"
        );
    }

    /// **The wire order is Go's, not ours, and that is the point.** sing-box
    /// builds an `http.Request` and calls `Write`, which emits the request
    /// line, `Host`, `User-Agent`, then every remaining header sorted by
    /// canonical name. A request in any other order is a request that stands
    /// out in the one log this transport exists to look ordinary in.
    #[test]
    fn an_upgrade_request_is_byte_identical_to_the_reference_clients() {
        let request = encode_upgrade_request("/tunnel", "cdn.example", &HttpHeaders::default());
        assert_eq!(
            String::from_utf8(request).unwrap(),
            "GET /tunnel HTTP/1.1\r\n\
             Host: cdn.example\r\n\
             User-Agent: Go-http-client/1.1\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             \r\n"
        );
    }

    /// Configured headers join the sorted run rather than sitting after it, so
    /// one beginning with `S` lands *between* `Connection` and `Upgrade` —
    /// which is exactly where Go puts it and nowhere a hand-rolled builder
    /// would.
    #[test]
    fn configured_headers_are_sorted_in_among_the_upgrade_pair() {
        let headers = HttpHeaders {
            host: None,
            extra: vec![
                ("x-late".to_owned(), "z".to_owned()),
                ("sec-early".to_owned(), "a".to_owned()),
                ("accept".to_owned(), "*/*".to_owned()),
            ],
        };
        let request = String::from_utf8(encode_upgrade_request("/", "h", &headers)).unwrap();
        let names: Vec<&str> = request
            .lines()
            .filter_map(|line| line.split_once(':').map(|(name, _)| name))
            .collect();
        assert_eq!(
            names,
            [
                "Host",
                "User-Agent",
                "Accept",
                "Connection",
                "Sec-Early",
                "Upgrade",
                "X-Late",
            ],
            "canonicalised, then sorted, exactly as Go's writeSubset does"
        );
    }

    /// A deployment that wants a browser's user agent gets it, and does not get
    /// two.
    #[test]
    fn a_configured_user_agent_replaces_gos_default_rather_than_joining_it() {
        let headers = HttpHeaders {
            host: None,
            extra: vec![("User-Agent".to_owned(), "Mozilla/5.0".to_owned())],
        };
        let request = String::from_utf8(encode_upgrade_request("/", "h", &headers)).unwrap();
        assert_eq!(request.matches("User-Agent:").count(), 1);
        assert!(request.contains("User-Agent: Mozilla/5.0\r\n"));
        assert!(!request.contains(GO_USER_AGENT));
    }

    /// The `Host` a server sees is the fronted name when one is configured, and
    /// otherwise whatever the layer below is addressed by. **Never a made-up
    /// constant**: a request announcing `localhost` to a CDN is a request that
    /// does not route and a log line that does not blend in.
    #[test]
    fn the_host_falls_back_to_what_the_layer_below_is_addressed_by() {
        let fronted = HttpHeaders {
            host: Some("fronted.example".to_owned()),
            extra: Vec::new(),
        };
        assert_eq!(fronted.host_or("origin.example"), "fronted.example");
        assert_eq!(
            HttpHeaders::default().host_or("origin.example"),
            "origin.example"
        );
    }

    /// The exchange, driven a byte at a time. A client that only works when the
    /// whole response head lands in one read is one that works against a
    /// loopback test and fails behind a middlebox that splits the segment.
    #[tokio::test]
    async fn the_upgrade_completes_however_the_response_is_split() {
        for chunk in [1usize, 7, 4096] {
            let (mut peer, ours) = tokio::io::duplex(4096);
            tokio::spawn(async move {
                let mut seen = Vec::new();
                let mut buf = [0u8; 256];
                while !seen.windows(4).any(|end| end == b"\r\n\r\n") {
                    let read = peer.read(&mut buf).await.unwrap();
                    if read == 0 {
                        return;
                    }
                    seen.extend_from_slice(&buf[..read]);
                }
                let response = b"HTTP/1.1 101 Switching Protocols\r\n\
                                 Connection: upgrade\r\n\
                                 Upgrade: websocket\r\n\r\npayload";
                for piece in response.chunks(chunk) {
                    peer.write_all(piece).await.unwrap();
                    peer.flush().await.unwrap();
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            });

            let mut stream = ours;
            let mut upgrade = Upgrade::new("/", "h", &HttpHeaders::default());
            let ((), surplus) = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                crate::negotiate(&mut stream, &mut upgrade),
            )
            .await
            .unwrap_or_else(|_| panic!("chunked by {chunk}: stalled"))
            .unwrap_or_else(|error| panic!("chunked by {chunk}: {error}"));
            assert_eq!(surplus, b"payload", "chunked by {chunk}");
        }
    }

    /// A `101` is not enough on its own. Both reference clients check the
    /// upgrade headers too, because a proxy that answered without switching
    /// protocols would take tunnel bytes as an HTTP response body.
    #[test]
    fn a_response_that_did_not_switch_protocols_is_refused() {
        use crate::Negotiation;
        let refusals: [&[u8]; 4] = [
            b"HTTP/1.1 200 OK\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: close\r\nUpgrade: websocket\r\n\r\n",
        ];
        for response in refusals {
            let mut upgrade = Upgrade::new("/", "h", &HttpHeaders::default());
            let mut out = Vec::new();
            assert!(
                upgrade.advance(response, &mut out).is_err(),
                "{}",
                String::from_utf8_lossy(response)
            );
        }
    }

    /// Header values arrive with the space after the colon still attached in
    /// some servers' spelling; comparing without trimming rejects a perfectly
    /// ordinary `101`.
    #[test]
    fn header_values_are_compared_case_insensitively_and_untrimmed() {
        use crate::Negotiation;
        let mut upgrade = Upgrade::new("/", "h", &HttpHeaders::default());
        let mut out = Vec::new();
        let response = b"HTTP/1.1 101 Switching Protocols\r\n\
                         Connection: Upgrade\r\n\
                         Upgrade: WebSocket\r\n\r\n";
        assert!(matches!(
            upgrade.advance(response, &mut out).unwrap(),
            crate::Decoded::Complete { .. }
        ));
    }

    /// **A DATA frame boundary falls wherever the peer's window put it**, so a
    /// gRPC header routinely arrives in two pieces. Every proper prefix must
    /// say "not yet" rather than guess, and the whole must report both the
    /// payload length and its own size — reporting the header's size wrong by
    /// one desynchronises every message after it.
    #[test]
    fn a_grpc_header_split_anywhere_is_read_once_it_is_whole() {
        for payload in [0usize, 1, 63, 64, 300, 100_000] {
            let mut framed = Vec::new();
            encode_grpc_message(&vec![b'x'; payload], &mut framed);

            // Every proper prefix of the header is incomplete.
            let (length, header) = decode_grpc_header(&framed).unwrap_or_else(|| {
                panic!("a whole message of {payload} bytes carries a whole header")
            });
            assert_eq!(length, payload);
            for taken in 0..header {
                assert!(
                    decode_grpc_header(&framed[..taken]).is_none(),
                    "{payload}-byte message: {taken} header bytes is not a header"
                );
            }
            assert_eq!(
                &framed[header..],
                vec![b'x'; payload].as_slice(),
                "the header size names exactly where the payload starts"
            );
        }
    }

    /// A length field a hostile peer never terminates would otherwise be read
    /// forever. Ten groups is all a `u64` holds, and past that the frame is
    /// refused rather than awaited.
    #[test]
    fn a_length_field_that_never_ends_is_refused_rather_than_awaited() {
        let mut endless = vec![0u8; GRPC_HEADER_MIN];
        endless.extend(std::iter::repeat_n(0xff, 32));
        assert!(decode_grpc_header(&endless).is_none());
    }
}
