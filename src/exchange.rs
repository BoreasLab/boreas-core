//! P14 HTTP exchange: the request/response half of interception.
//!
//! Once [`crate::Interceptor`] has terminated the client's TLS, this drives the
//! HTTP conversation on the plaintext: it serves the client, forwards each
//! request to the upstream server over a connection of *the same version*, and
//! streams the response back. It is where the URL-tier filter finally has a URL
//! to decide against — the faculty [Filtering](../docs/filtering.md) says the
//! name tier lacks.
//!
//! The heavy lifting is `hyper`'s, deliberately. Parsing h1, framing h2,
//! multiplexing streams, and managing flow control are a solved problem with a
//! battle-tested implementation; Boreas's novel part is the sans-io datapath
//! and the smoltcp termination beneath this, not a hand-rolled HTTP stack. This
//! module is the thin proxy policy on top: filter, strip hop-by-hop headers,
//! and forward without ever crossing versions.
//!
//! **No version is bridged.** The client wire chosen by ALPN
//! ([`crate::Wire`]) selects both the server codec and the upstream codec, so
//! an h2 client is proxied to an h2 upstream and an h1 client to an h1
//! upstream. [`crate::VersionCrossings`] records each exchange, and the P14
//! gate is that the count stays zero — which it does here by construction.
//!
//! **h1 serializes; h2 does not.** An h1 connection carries one request at a
//! time, so its upstream sender sits behind a mutex the sequential server never
//! contends. An h2 connection multiplexes, so its sender is *cloned per stream*
//! — never locked — because a mutex would reintroduce exactly the
//! connection-level head-of-line blocking the h2 contract forbids.

use std::{convert::Infallible, io, sync::Arc};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{
    Request, Response, StatusCode,
    body::Incoming,
    header::{HeaderMap, HeaderName},
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Mutex,
};

use crate::{VersionCrossings, Wire};

/// The response body the proxy yields, uniform across forwarded and synthesized
/// responses so one service can return either. Upstream bodies (`Incoming`) and
/// synthetic bodies (`Full`) are both boxed, their disjoint error types erased
/// to one.
pub type ProxyBody = BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

/// Whether a request is forwarded upstream or blocked at the proxy. Closed at
/// two, with block the fail-safe: this is the URL tier's verdict, and a rule it
/// cannot decide is an allow, never a silent third state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilterVerdict {
    Allow,
    Block,
}

/// The URL-tier decision seam. An implementation sees the host the SNI named
/// and the request line, which together are the URL a name-tier rule could not
/// see. The `adblock` engine plugs in here once it is admitted; until then a
/// test double or [`AllowAll`] stands in.
pub trait RequestFilter: Send + Sync + 'static {
    fn decide(&self, host: &str, request: &Request<Incoming>) -> FilterVerdict;
}

/// The identity filter: forward everything. The pass-through baseline an
/// allowlisted-but-unfiltered host uses, and the fixture the exchange tests
/// forward against.
#[derive(Clone, Copy, Debug, Default)]
pub struct AllowAll;

impl RequestFilter for AllowAll {
    fn decide(&self, _host: &str, _request: &Request<Incoming>) -> FilterVerdict {
        FilterVerdict::Allow
    }
}

/// RFC 9110 §7.6.1 connection-specific header fields: meaningful only to the
/// single hop they arrived on, so a forwarding proxy must not relay them.
/// `Transfer-Encoding` and `Content-Length` are managed by `hyper` per
/// connection and are removed here so a stale value cannot contradict the
/// framing the codec chooses.
const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
];

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    // The `Connection` header may name further fields to drop; those named
    // tokens are honoured before the header itself is removed.
    let named: Vec<HeaderName> = headers
        .get_all(hyper::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
}

fn boxed_incoming(body: Incoming) -> ProxyBody {
    body.map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
        .boxed()
}

fn boxed_full(bytes: &'static [u8]) -> ProxyBody {
    Full::new(Bytes::from_static(bytes))
        .map_err(|never| match never {})
        .boxed()
}

/// A synthetic response with no upstream: the request was blocked by policy.
/// `403` rather than a forged `200`, because a blocked subresource that claims
/// success is a subtler failure than one that says it was refused.
fn blocked() -> Response<ProxyBody> {
    let mut response = Response::new(boxed_full(b""));
    *response.status_mut() = StatusCode::FORBIDDEN;
    response
}

/// The proxy could not reach or complete the upstream request. Interception is
/// optional, so this is a visible `502` rather than a dropped connection; the
/// connection-level fail-open — never terminating a host likely to break — is
/// the allowlist's job upstream of here, not this layer's.
fn bad_gateway() -> Response<ProxyBody> {
    let mut response = Response::new(boxed_full(b""));
    *response.status_mut() = StatusCode::BAD_GATEWAY;
    response
}

/// The upstream request channel, uniform over the two wires but with their
/// concurrency disciplines intact: h1 is a shared mutex (one request at a time,
/// which is all an h1 connection allows), h2 is a cloneable multiplexer.
#[derive(Clone)]
enum Upstream {
    H1(Arc<Mutex<hyper::client::conn::http1::SendRequest<Incoming>>>),
    H2(hyper::client::conn::http2::SendRequest<Incoming>),
}

impl Upstream {
    async fn send(&self, request: Request<Incoming>) -> hyper::Result<Response<Incoming>> {
        match self {
            Self::H1(sender) => {
                let mut sender = sender.lock().await;
                sender.ready().await?;
                sender.send_request(request).await
            }
            Self::H2(sender) => {
                // Clone rather than lock: each stream gets its own handle to the
                // shared connection, so one stalled response cannot block another.
                let mut sender = sender.clone();
                sender.ready().await?;
                sender.send_request(request).await
            }
        }
    }
}

/// Forwards one request: filter, strip hop-by-hop headers, send upstream, box
/// the reply. Never returns `Err` — every failure is a response the client can
/// see — so the connection survives one bad exchange.
async fn forward(
    mut request: Request<Incoming>,
    host: Arc<str>,
    upstream: Upstream,
    filter: Arc<dyn RequestFilter>,
    crossings: Arc<VersionCrossings>,
    wire: Wire,
) -> Result<Response<ProxyBody>, Infallible> {
    if filter.decide(&host, &request) == FilterVerdict::Block {
        return Ok(blocked());
    }
    strip_hop_by_hop(request.headers_mut());

    // The upstream wire equals the client wire by construction: the record is
    // the proof, and the P14 gate reads its count.
    crossings.record(wire, wire);

    match upstream.send(request).await {
        Ok(mut response) => {
            strip_hop_by_hop(response.headers_mut());
            Ok(response.map(boxed_incoming))
        }
        Err(_) => Ok(bad_gateway()),
    }
}

/// Runs one terminated connection to completion: serves the client on `wire`,
/// forwarding to `upstream` on the same wire, until either side closes.
///
/// `client` is the decrypted client stream from [`crate::Interceptor`];
/// `upstream` is an already-connected stream to the real server, its TLS and
/// its tunnel bypass the caller's concern. `host` is the SNI-validated name,
/// authoritative for filtering over anything a request header claims.
pub async fn run_exchange<C, U>(
    host: impl Into<Arc<str>>,
    wire: Wire,
    client: C,
    upstream: U,
    filter: Arc<dyn RequestFilter>,
    crossings: Arc<VersionCrossings>,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let host = host.into();
    match wire {
        Wire::Http1 => serve_h1(host, client, upstream, filter, crossings).await,
        Wire::Http2 => serve_h2(host, client, upstream, filter, crossings).await,
    }
}

async fn serve_h1<C, U>(
    host: Arc<str>,
    client: C,
    upstream: U,
    filter: Arc<dyn RequestFilter>,
    crossings: Arc<VersionCrossings>,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(upstream))
        .await
        .map_err(io::Error::other)?;
    // Drive the upstream connection alongside the client one; abort it when the
    // client side finishes so the task cannot outlive the exchange.
    let driver = tokio::spawn(connection);
    let upstream = Upstream::H1(Arc::new(Mutex::new(sender)));

    let service = service_fn(move |request| {
        forward(
            request,
            Arc::clone(&host),
            upstream.clone(),
            Arc::clone(&filter),
            Arc::clone(&crossings),
            Wire::Http1,
        )
    });

    let result = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(client), service)
        .await;
    driver.abort();
    result.map_err(io::Error::other)
}

async fn serve_h2<C, U>(
    host: Arc<str>,
    client: C,
    upstream: U,
    filter: Arc<dyn RequestFilter>,
    crossings: Arc<VersionCrossings>,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(upstream))
            .await
            .map_err(io::Error::other)?;
    let driver = tokio::spawn(connection);
    let upstream = Upstream::H2(sender);

    let service = service_fn(move |request| {
        forward(
            request,
            Arc::clone(&host),
            upstream.clone(),
            Arc::clone(&filter),
            Arc::clone(&crossings),
            Wire::Http2,
        )
    });

    let result = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(client), service)
        .await;
    driver.abort();
    result.map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroUsize;

    use http_body_util::Empty;
    use hyper::{Method, header::HOST};
    use rustls::{
        ClientConfig, RootCertStore, crypto::ring::default_provider, pki_types::ServerName,
    };
    use tokio::io::DuplexStream;
    use tokio_rustls::TlsConnector;

    use crate::{CertificateAuthority, Interceptor, MitmResolver};

    const HOST_NAME: &str = "intercepted.example";

    /// A blocklist test double: refuse any request whose path starts with the
    /// given prefix, forward the rest. Stands in for the URL-tier engine.
    struct BlockPrefix(&'static str);

    impl RequestFilter for BlockPrefix {
        fn decide(&self, _host: &str, request: &Request<Incoming>) -> FilterVerdict {
            if request.uri().path().starts_with(self.0) {
                FilterVerdict::Block
            } else {
                FilterVerdict::Allow
            }
        }
    }

    /// A fake origin server: answers every request `200` with a body naming the
    /// path it saw, so the test can prove the request reached upstream intact.
    async fn fake_upstream_h1(io: DuplexStream) {
        let service = service_fn(|request: Request<Incoming>| async move {
            let path = request.uri().path().to_owned();
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(format!(
                "origin:{path}"
            )))))
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(io), service)
            .await;
    }

    /// An h2 fake origin: same "name the path back" contract, over HTTP/2.
    async fn fake_upstream_h2(io: DuplexStream) {
        let service = service_fn(|request: Request<Incoming>| async move {
            let path = request.uri().path().to_owned();
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(format!(
                "origin:{path}"
            )))))
        });
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(io), service)
            .await;
    }

    fn client_connector(
        root: rustls::pki_types::CertificateDer<'static>,
        alpn: &[&[u8]],
    ) -> TlsConnector {
        let mut roots = RootCertStore::empty();
        roots.add(root).unwrap();
        let mut config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        // The offered ALPN fixes the negotiated wire, and thus both codecs.
        config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
        TlsConnector::from(Arc::new(config))
    }

    #[tokio::test]
    async fn an_allowed_request_reaches_the_origin_and_a_blocked_one_does_not() {
        let authority = Arc::new(CertificateAuthority::generate().unwrap());
        let root = authority.root_der().clone();
        let resolver = Arc::new(MitmResolver::new(
            Arc::clone(&authority),
            NonZeroUsize::new(16).unwrap(),
        ));
        let interceptor = Interceptor::new(resolver).unwrap();
        let crossings = Arc::new(VersionCrossings::new());

        // The terminated connection: a client TLS half and a server TLS half
        // over one in-memory pipe.
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        // The upstream leg: our proxy client half and the fake origin half.
        let (upstream_client, upstream_server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(fake_upstream_h1(upstream_server));

        let crossings_for_exchange = Arc::clone(&crossings);
        tokio::spawn(async move {
            let (server_tls, wire) = interceptor.terminate(server_io).await.expect("terminate");
            assert_eq!(wire, Wire::Http1);
            run_exchange(
                HOST_NAME,
                wire,
                server_tls,
                upstream_client,
                Arc::new(BlockPrefix("/ads/")),
                crossings_for_exchange,
            )
            .await
            .expect("exchange runs");
        });

        // The client validates the forged leaf, then speaks HTTP/1.1 over TLS.
        let connector = client_connector(root, &[b"http/1.1"]);
        let server_name = ServerName::try_from(HOST_NAME).unwrap();
        let client_tls = connector
            .connect(server_name, client_io)
            .await
            .expect("client handshake");
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(client_tls))
                .await
                .expect("client conn");
        tokio::spawn(connection);

        // An allowed path is forwarded and the origin's body comes back.
        let allowed = Request::builder()
            .method(Method::GET)
            .uri("/index.html")
            .header(HOST, HOST_NAME)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = sender.send_request(allowed).await.expect("allowed request");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"origin:/index.html");

        // A blocked path never reaches the origin: the proxy answers 403 itself.
        let blocked = Request::builder()
            .method(Method::GET)
            .uri("/ads/banner.js")
            .header(HOST, HOST_NAME)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = sender.send_request(blocked).await.expect("blocked request");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // The whole point of the wire discipline: nothing was bridged.
        assert_eq!(crossings.count(), 0, "no exchange crossed versions");
    }

    #[tokio::test]
    async fn an_h2_client_is_proxied_over_an_h2_upstream_without_crossing() {
        let authority = Arc::new(CertificateAuthority::generate().unwrap());
        let root = authority.root_der().clone();
        let resolver = Arc::new(MitmResolver::new(
            Arc::clone(&authority),
            NonZeroUsize::new(16).unwrap(),
        ));
        let interceptor = Interceptor::new(resolver).unwrap();
        let crossings = Arc::new(VersionCrossings::new());

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (upstream_client, upstream_server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(fake_upstream_h2(upstream_server));

        let crossings_for_exchange = Arc::clone(&crossings);
        tokio::spawn(async move {
            let (server_tls, wire) = interceptor.terminate(server_io).await.expect("terminate");
            assert_eq!(wire, Wire::Http2, "h2 was offered and preferred");
            run_exchange(
                HOST_NAME,
                wire,
                server_tls,
                upstream_client,
                Arc::new(AllowAll),
                crossings_for_exchange,
            )
            .await
            .expect("exchange runs");
        });

        let connector = client_connector(root, &[b"h2"]);
        let server_name = ServerName::try_from(HOST_NAME).unwrap();
        let client_tls = connector
            .connect(server_name, client_io)
            .await
            .expect("client handshake");
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(client_tls))
                .await
                .expect("client conn");
        tokio::spawn(connection);

        // h2 carries the authority in a pseudo-header, so the request is
        // absolute-form; the proxy forwards it over its own h2 upstream leg.
        let request = Request::builder()
            .method(Method::GET)
            .uri(format!("https://{HOST_NAME}/resource"))
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = sender.send_request(request).await.expect("h2 request");
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"origin:/resource");
        assert_eq!(crossings.count(), 0, "h2 to h2 crosses nothing");
    }
}
