//! Composable proxy transports for VLESS.
//!
//! Each layer obtains a byte stream from the layer below. TLS, WebSocket,
//! HTTP Upgrade, HTTP/2, gRPC, and QUIC therefore compose as values rather
//! than optional settings on every protocol.
//!
//! Wire details follow sing-box's V2Ray transport implementations. gRPC uses a
//! protobuf varint, not the QUIC varint, and HTTP handshakes preserve surplus
//! bytes so payload read with the response is not lost.

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
    egress::quic::{Handshake, QuicConnection, client_config},
    wire::Writer,
};

/// Obtains the byte stream used by a proxy protocol.
pub trait ProxyTransport: Send + Sync {
    fn dial(&self) -> BoxFuture<'_, Result<Box<dyn AsyncStream>, EgressError>>;

    /// Returns the layer's authority for HTTP `Host` fallback.
    fn authority(&self) -> Option<&str> {
        None
    }
}

/// A boxed transport preserves dynamic chain composition.
impl ProxyTransport for Box<dyn ProxyTransport> {
    fn dial(&self) -> BoxFuture<'_, Result<Box<dyn AsyncStream>, EgressError>> {
        (**self).dial()
    }

    fn authority(&self) -> Option<&str> {
        (**self).authority()
    }
}

/// Plain TCP through the tunnel bypass.
pub struct PlainTransport<B> {
    server: SocketAddr,
    /// Stored because `SocketAddr` has no borrowed string view.
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

/// TLS over TCP.
pub struct TlsConfig {
    pub server: SocketAddr,
    /// SNI name and certificate verification name.
    pub server_name: String,
    /// ALPN identifiers selected by the transport above.
    pub alpn: Vec<Vec<u8>>,
    /// Additional DER-encoded trust anchors.
    pub extra_roots: Vec<Vec<u8>>,
}

pub struct TlsTransport<B> {
    server: SocketAddr,
    server_name: String,
    originator: Arc<Originator>,
    /// Wire-format ALPN list.
    alpn: Vec<u8>,
    bypass: B,
}

impl<B: TunnelBypass> TlsTransport<B> {
    /// Builds a Chrome-shaped TLS client using the bundled trust roots.
    pub fn new(config: TlsConfig, bypass: B) -> Result<Self, EgressError> {
        // Validate the name before handing its string form to BoringSSL.
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

    /// Returns the SNI name for HTTP `Host` fallback.
    fn authority(&self) -> Option<&str> {
        Some(&self.server_name)
    }
}

// ------------------------------------------------------- HTTP framing

/// `Host` override and additional headers for HTTP-shaped transports.
#[derive(Clone, Default)]
pub struct HttpHeaders {
    /// Optional fronted `Host` name.
    pub host: Option<String>,
    pub extra: Vec<(String, String)>,
}

impl HttpHeaders {
    fn host_or(&self, fallback: &str) -> String {
        self.host.clone().unwrap_or_else(|| fallback.to_owned())
    }
}

/// Adds the leading slash required by HTTP request paths.
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

/// VLESS over WebSocket, projected to a byte stream with tungstenite.
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
            // The socket is already connected; the URI supplies HTTP fields only.
            let host = self.headers.host_or(self.inner.authority().unwrap_or(""));
            let uri = format!("ws://{host}{}", self.path);
            let mut request = http::Request::builder()
                .uri(&uri)
                .header("Host", &host)
                // tungstenite generates the key and verifies the accept token.
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

    /// Delegates authority to the wrapped transport.
    fn authority(&self) -> Option<&str> {
        self.inner.authority()
    }
}

/// Projects WebSocket binary messages onto a byte stream.
struct WebSocketStream<S> {
    socket: tokio_tungstenite::WebSocketStream<S>,
    /// Unconsumed tail of the last binary message.
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
                    // Empty messages do not signal EOF.
                    if payload.is_empty() {
                        continue;
                    }
                    this.pending = payload;
                }
                // Close and stream end both terminate the byte stream.
                Poll::Ready(Some(Ok(Message::Close(_))) | None) => return Poll::Ready(Ok(())),
                // Non-binary frames carry no tunnel payload.
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
        // A close frame is WebSocket's orderly stream shutdown.
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

/// VLESS over HTTP/1.1 Upgrade with raw bytes after the handshake.
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
            // The handshake may read tunnel payload with the `101` response.
            let ((), surplus) = crate::negotiate(&mut stream, &mut upgrade).await?;
            Ok(Box::new(Prefixed::new(surplus, stream)) as Box<dyn AsyncStream>)
        })
    }

    fn authority(&self) -> Option<&str> {
        self.inner.authority()
    }
}

/// Go's default user agent used by sing-box when none is configured.
const GO_USER_AGENT: &str = "Go-http-client/1.1";

/// Pure HTTP/1.1 Upgrade negotiation state.
struct Upgrade {
    /// Request emitted on the first advance.
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

    /// Parses the bounded response head on each offer.
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

        // Match the status code, independent of the reason phrase.
        if response.code != Some(101) {
            return Err(ProxyError::Denied(format!(
                "expected 101, got {}",
                response.code.unwrap_or(0)
            )));
        }
        // Require both headers before treating the response as a tunnel.
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

/// Builds the Go-compatible HTTP Upgrade request and header order.
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

/// Converts a header name to MIME canonical form before sorting.
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

/// Body framing used by HTTP/2 transports.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Framing {
    /// Each write becomes one length-delimited message.
    Grpc,
    /// The body is an unframed byte stream.
    Raw,
}

pub struct GrpcConfig {
    /// Service name in the `/{service_name}/Tun` request path.
    pub service_name: String,
    pub headers: HttpHeaders,
}

pub struct HttpConfig {
    pub path: String,
    /// HTTP method, defaulting to sing-box's `PUT` at configuration time.
    pub method: String,
    pub headers: HttpHeaders,
}

/// VLESS over gRPC with a streaming HTTP/2 body.
pub struct GrpcTransport<T> {
    config: GrpcConfig,
    inner: T,
    connection: Mutex<Option<h2::client::SendRequest<bytes::Bytes>>>,
}

/// VLESS over HTTP/2 with a streaming request body.
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

/// Obtains or reuses an HTTP/2 request sender. The lock covers the handshake so
/// concurrent first flows share one connection.
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
    // HTTP/2 streams progress only while their connection future is polled.
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

/// Opens an HTTP/2 stream without waiting for its response. The server needs
/// request-body data before replying, so refusal is reported on the first read.
fn h2_dial(
    mut sender: h2::client::SendRequest<bytes::Bytes>,
    request: http::Request<()>,
    framing: Framing,
) -> Result<Box<dyn AsyncStream>, EgressError> {
    // The request body remains open for the tunnel uplink.
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

/// Downlink state for an HTTP/2 stream response.
enum Recv {
    Pending(h2::client::ResponseFuture),
    Ready(h2::RecvStream),
    /// Refused or failed; subsequent reads return end of stream.
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
                // Match gRPC-Go's reference user agent.
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

    /// Delegates authority to the wrapped transport.
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

    /// Delegates authority to the wrapped transport.
    fn authority(&self) -> Option<&str> {
        self.inner.authority()
    }
}

/// HTTP/2 stream projected to a byte stream, optionally with gRPC framing.
struct H2Stream {
    send: h2::SendStream<bytes::Bytes>,
    recv: Recv,
    framing: Framing,
    /// Undelivered payload from the last DATA frame.
    pending: bytes::Bytes,
    /// Bytes remaining in the current gRPC message; zero means a header follows.
    remaining: usize,
    /// gRPC header bytes split across HTTP/2 DATA frames.
    head: Vec<u8>,
}

/// gRPC header and payload layout:
/// `00 | u32be(total) | 0x0A | protobuf-varint(len) | payload`.
const GRPC_HEADER_MIN: usize = 6;

/// Encodes protobuf's little-endian groups-of-seven varint.
///
/// This differs from [`crate::varint`], whose QUIC encoding uses high-bit length
/// markers and diverges at 64.
fn put_protobuf_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// Decodes a protobuf varint; `None` means the prefix is incomplete or invalid.
fn get_protobuf_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (index, &byte) in bytes.iter().enumerate() {
        // Ten groups hold a `u64`; reject longer prefixes.
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

/// Wraps one payload as a gRPC message.
fn encode_grpc_message(payload: &[u8], out: &mut Vec<u8>) {
    let mut length = Vec::with_capacity(10);
    put_protobuf_varint(payload.len() as u64, &mut length);
    Writer::new(out)
        .u8(0) // not compressed
        .u32((1 + length.len() + payload.len()) as u32)
        .u8(0x0A) // field 1, wire type 2
        .bytes(&length)
        .bytes(payload);
}

/// Reads a gRPC header, returning payload length and header size.
///
/// `None` means the HTTP/2 DATA frame ended inside the header. This is the
/// sans-IO boundary: framing is byte-local, while capacity belongs to h2.
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
            // Deliver decoded bytes before polling the connection.
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
                // A zero-capacity read is a successful no-op, not EOF.
                return Poll::Ready(Ok(()));
            }

            // A gRPC header may span DATA frames.
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

            // `dial` does not await the response; the first read does.
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
                    // Release capacity so the peer can send past one window.
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
        // Reserve before framing so one gRPC message is written whole.
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

    /// h2 flushes when its connection task runs; this stream has no flush buffer.
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
        // An empty DATA frame with END_STREAM is HTTP/2 FIN.
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

/// VLESS over QUIC streams using the `h3` ALPN without HTTP/3 framing.
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

    /// Builds a QUIC config for the caller to configure certificate verification.
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

    /// Protobuf and QUIC varints agree below 64 but diverge at 64.
    #[test]
    fn the_protobuf_varint_is_not_the_quic_varint() {
        for value in [0u64, 1, 63] {
            let (mut protobuf, mut quic) = (Vec::new(), Vec::new());
            put_protobuf_varint(value, &mut protobuf);
            Writer::new(&mut quic).varint(value);
            assert_eq!(protobuf, quic, "the two agree below 64");
        }
        for value in [64u64, 128, 300, 16_384] {
            let (mut protobuf, mut quic) = (Vec::new(), Vec::new());
            put_protobuf_varint(value, &mut protobuf);
            Writer::new(&mut quic).varint(value);
            assert_ne!(
                protobuf, quic,
                "{value} must not encode identically, or the wrong codec would pass tests"
            );
        }
        // Pin a multi-byte protobuf encoding.
        let mut out = Vec::new();
        put_protobuf_varint(300, &mut out);
        assert_eq!(out, [0xac, 0x02]);
    }

    /// Round trips values and rejects every incomplete prefix.
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

    /// Matches the reference gRPC frame layout.
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

        // Check the multi-byte varint boundary.
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

    /// Normalizes paths without a leading slash.
    #[test]
    fn a_path_is_given_its_leading_slash() {
        assert_eq!(normalise_path("ws"), "/ws");
        assert_eq!(normalise_path("/ws"), "/ws");
        assert_eq!(normalise_path(""), "/");
    }

    /// Prefers the configured `Host` and otherwise uses the fallback.
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

    /// Matches Go's request-line and canonical header order.
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

    /// Sorts configured headers into Go's canonical header run.
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

    /// Replaces, rather than duplicates, the default user agent.
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

    /// Falls back to the wrapped transport's authority.
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

    /// Completes when the response arrives in arbitrarily sized chunks.
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

    /// Requires upgrade headers in addition to status `101`.
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

    /// Compares upgrade values case-insensitively after trimming whitespace.
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

    /// Handles gRPC headers split across HTTP/2 DATA frames.
    #[test]
    fn a_grpc_header_split_anywhere_is_read_once_it_is_whole() {
        for payload in [0usize, 1, 63, 64, 300, 100_000] {
            let mut framed = Vec::new();
            encode_grpc_message(&vec![b'x'; payload], &mut framed);

            // Every proper prefix needs more input.
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

    /// Refuses a varint longer than the ten groups allowed by `u64`.
    #[test]
    fn a_length_field_that_never_ends_is_refused_rather_than_awaited() {
        let mut endless = vec![0u8; GRPC_HEADER_MIN];
        endless.extend(std::iter::repeat_n(0xff, 32));
        assert!(decode_grpc_header(&endless).is_none());
    }
}
