//! HTTP exchange after TLS interception.
//!
//! The ALPN-selected [`crate::Wire`] drives both HTTP codecs; this module adds
//! URL filtering, hop-by-hop handling, response steering, and body rewriting.
//! HTTP parsing, framing, multiplexing, and flow control remain in `hyper`.
//!
//! h1 serializes upstream requests behind a mutex. h2 clones its sender per
//! stream so one response cannot block another. h1 upgrades preserve their
//! `Connection` and `Upgrade` fields and splice the resulting byte streams.

use std::{
    convert::Infallible,
    io,
    sync::{Arc, Mutex as StdMutex},
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{
    Request, Response, StatusCode,
    body::Incoming,
    header::{CONNECTION, HeaderMap, HeaderName, HeaderValue, UPGRADE},
    service::service_fn,
    upgrade::OnUpgrade,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Mutex,
};

use crate::{H2Profile, Rewriting, VersionCrossings, Wire};

pub type ProxyBody = BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilterVerdict {
    Allow,
    Block,
}

pub trait RequestFilter: Send + Sync + 'static {
    fn decide(&self, host: &str, request: &Request<Incoming>) -> FilterVerdict;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AllowAll;

impl RequestFilter for AllowAll {
    fn decide(&self, _host: &str, _request: &Request<Incoming>) -> FilterVerdict {
        FilterVerdict::Allow
    }
}

/// RFC 9110 section 7.6.1 fields that must not cross an ordinary hop.
/// `Connection` and `Upgrade` are handled separately because h1 upgrades need
/// them.
const HOP_BY_HOP: [&str; 7] = [
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "content-length",
];

// Alt-Svc steering.

/// RFC 7838 field name and withdrawal value.
const ALT_SVC: &str = "alt-svc";
const ALT_SVC_CLEAR: &str = "clear";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AltSvc {
    /// No recognized HTTP/3 alternative was removed.
    Untouched,
    /// HTTP/3 alternatives removed; other values preserved in order.
    Narrowed(String),
    /// All alternatives removed; withdraw the cached advertisement.
    Cleared,
}

/// Removes HTTP/3 alternatives from one or more `Alt-Svc` values.
#[must_use]
pub fn steer_alt_svc<'a>(values: impl IntoIterator<Item = &'a str>) -> AltSvc {
    let mut kept: Vec<&str> = Vec::new();
    let mut removed = false;
    let mut saw_any = false;

    for value in values {
        // `clear` already withdraws the advertisement.
        if value.trim().eq_ignore_ascii_case(ALT_SVC_CLEAR) {
            saw_any = true;
            continue;
        }
        for alternative in alt_values(value) {
            saw_any = true;
            if advertises_h3(alternative) {
                removed = true;
            } else {
                kept.push(alternative);
            }
        }
    }

    match (removed, kept.is_empty(), saw_any) {
        (false, ..) => AltSvc::Untouched,
        (true, true, _) => AltSvc::Cleared,
        (true, false, _) => AltSvc::Narrowed(kept.join(", ")),
    }
}

/// Splits an `Alt-Svc` value at commas outside quoted strings.
fn alt_values(value: &str) -> impl Iterator<Item = &str> {
    let mut quoted = false;
    let mut escaped = false;
    value
        .split(move |character| {
            if escaped {
                escaped = false;
                return false;
            }
            match character {
                '\\' if quoted => {
                    escaped = true;
                    false
                }
                '"' => {
                    quoted = !quoted;
                    false
                }
                ',' => !quoted,
                _ => false,
            }
        })
        .map(str::trim)
        .filter(|alternative| !alternative.is_empty())
}

/// Whether an alt-value names `h3` or an h3 draft token.
fn advertises_h3(alternative: &str) -> bool {
    let id = alternative
        .split('=')
        .next()
        .unwrap_or_default()
        .trim()
        .trim_matches('"');
    let decoded = percent_decode(id);
    decoded.eq_ignore_ascii_case("h3") || decoded.to_ascii_lowercase().starts_with("h3-")
}

/// Decodes `%XX` escapes while preserving malformed escapes literally.
fn percent_decode(id: &str) -> String {
    let bytes = id.as_bytes();
    let mut out = String::with_capacity(id.len());
    let mut index = 0;
    while index < bytes.len() {
        let decoded = (bytes[index] == b'%')
            .then(|| id.get(index + 1..index + 3))
            .flatten()
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match decoded {
            Some(byte) => {
                out.push(char::from(byte));
                index += 3;
            }
            None => {
                out.push(char::from(bytes[index]));
                index += 1;
            }
        }
    }
    out
}

/// Applies [`steer_alt_svc`] to response headers.
fn steer_response(headers: &mut HeaderMap) {
    let steering = steer_alt_svc(
        headers
            .get_all(ALT_SVC)
            .iter()
            .filter_map(|value| value.to_str().ok()),
    );
    let replacement = match steering {
        AltSvc::Untouched => return,
        AltSvc::Cleared => HeaderValue::from_static(ALT_SVC_CLEAR),
        AltSvc::Narrowed(kept) => match HeaderValue::from_str(&kept) {
            Ok(value) => value,
            // If survivors cannot be encoded, withdraw the advertisement.
            Err(_) => HeaderValue::from_static(ALT_SVC_CLEAR),
        },
    };
    headers.remove(ALT_SVC);
    headers.insert(ALT_SVC, replacement);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Handling {
    Ordinary,
    /// Preserve the h1 upgrade offer.
    Upgrade,
}

/// Recognizes a complete h1 upgrade offer.
fn handling<B>(request: &Request<B>) -> Handling {
    let offers_upgrade = request
        .headers()
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
    if offers_upgrade && request.headers().contains_key(UPGRADE) {
        Handling::Upgrade
    } else {
        Handling::Ordinary
    }
}

/// Removes ordinary hop-by-hop fields while preserving surviving order.
fn strip_hop_by_hop(headers: &mut HeaderMap, handling: Handling) {
    // Connection may nominate additional hop-by-hop fields.
    let named: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        // Keep the upgrade token on an upgrade path.
        .filter(|token| handling == Handling::Ordinary || !token.eq_ignore_ascii_case("upgrade"))
        .filter_map(|token| HeaderName::from_bytes(token.as_bytes()).ok())
        .collect();

    let discard = |name: &HeaderName| {
        HOP_BY_HOP.contains(&name.as_str())
            || (handling == Handling::Ordinary && (*name == CONNECTION || *name == UPGRADE))
            || named.contains(name)
    };

    if !headers.keys().any(discard) {
        return;
    }

    // HeaderMap::drain yields a name only for the first value of a repeated field.
    let mut kept = HeaderMap::with_capacity(headers.len());
    let mut keeping: Option<HeaderName> = None;
    for (name, value) in headers.drain() {
        if let Some(name) = name {
            keeping = (!discard(&name)).then_some(name);
        }
        if let Some(name) = &keeping {
            kept.append(name, value);
        }
    }
    *headers = kept;
}

fn boxed_full(bytes: &'static [u8]) -> ProxyBody {
    Full::new(Bytes::from_static(bytes))
        .map_err(|never| match never {})
        .boxed()
}

fn blocked() -> Response<ProxyBody> {
    let mut response = Response::new(boxed_full(b""));
    *response.status_mut() = StatusCode::FORBIDDEN;
    response
}

fn bad_gateway() -> Response<ProxyBody> {
    let mut response = Response::new(boxed_full(b""));
    *response.status_mut() = StatusCode::BAD_GATEWAY;
    response
}

/// Upstream sender with h1 serialization and h2 multiplexing.
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
                // Cloning preserves h2 stream concurrency.
                let mut sender = sender.clone();
                sender.ready().await?;
                sender.send_request(request).await
            }
        }
    }
}

struct Pending {
    client: OnUpgrade,
    upstream: OnUpgrade,
}

struct Proxy {
    host: Arc<str>,
    upstream: Upstream,
    filter: Arc<dyn RequestFilter>,
    crossings: Arc<VersionCrossings>,
    wire: Wire,
    rewriting: Rewriting,
    upgrade: StdMutex<Option<Pending>>,
}

impl Proxy {
    /// Filters, forwards, and shapes one request without failing the connection.
    async fn forward(
        &self,
        mut request: Request<Incoming>,
    ) -> Result<Response<ProxyBody>, Infallible> {
        if self.filter.decide(&self.host, &request) == FilterVerdict::Block {
            return Ok(blocked());
        }
        let handling = handling(&request);
        let client = (handling == Handling::Upgrade).then(|| hyper::upgrade::on(&mut request));

        strip_hop_by_hop(request.headers_mut(), handling);

        self.crossings.record(self.wire, self.wire);

        let Ok(mut response) = self.upstream.send(request).await else {
            return Ok(bad_gateway());
        };
        if let Some(client) = client
            && response.status() == StatusCode::SWITCHING_PROTOCOLS
        {
            let upstream = hyper::upgrade::on(&mut response);
            *crate::locked(&self.upgrade) = Some(Pending { client, upstream });
            return Ok(response.map(|body| body.map_err(Into::into).boxed()));
        }

        strip_hop_by_hop(response.headers_mut(), Handling::Ordinary);
        steer_response(response.headers_mut());
        Ok(self.rewriting.apply(&self.host, response))
    }

    fn take_upgrade(&self) -> Option<Pending> {
        crate::locked(&self.upgrade).take()
    }
}

async fn splice_upgrade(pending: Pending) -> io::Result<()> {
    let (client, upstream) =
        tokio::try_join!(pending.client, pending.upstream).map_err(io::Error::other)?;
    let mut client = TokioIo::new(client);
    let mut upstream = TokioIo::new(upstream);
    tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .map(drop)
}

pub async fn run_exchange<C, U>(
    host: impl Into<Arc<str>>,
    wire: Wire,
    client: C,
    upstream: U,
    filter: Arc<dyn RequestFilter>,
    crossings: Arc<VersionCrossings>,
    rewriting: Rewriting,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let host = host.into();
    match wire {
        Wire::Http1 => serve_h1(host, client, upstream, filter, crossings, rewriting).await,
        Wire::Http2 => serve_h2(host, client, upstream, filter, crossings, rewriting).await,
    }
}

async fn serve_h1<C, U>(
    host: Arc<str>,
    client: C,
    upstream: U,
    filter: Arc<dyn RequestFilter>,
    crossings: Arc<VersionCrossings>,
    rewriting: Rewriting,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(upstream))
        .await
        .map_err(io::Error::other)?;
    // Both legs must retain upgrade ownership after a 101 response.
    let driver = tokio::spawn(connection.with_upgrades());
    let proxy = Arc::new(Proxy {
        host,
        upstream: Upstream::H1(Arc::new(Mutex::new(sender))),
        filter,
        crossings,
        wire: Wire::Http1,
        rewriting,
        upgrade: StdMutex::new(None),
    });

    let service = {
        let proxy = Arc::clone(&proxy);
        service_fn(move |request| {
            let proxy = Arc::clone(&proxy);
            async move { proxy.forward(request).await }
        })
    };

    let result = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(client), service)
        .with_upgrades()
        .await;

    match proxy.take_upgrade() {
        None => {
            driver.abort();
            result.map_err(io::Error::other)
        }
        Some(pending) => {
            result.map_err(io::Error::other)?;
            splice_upgrade(pending).await
        }
    }
}

async fn serve_h2<C, U>(
    host: Arc<str>,
    client: C,
    upstream: U,
    filter: Arc<dyn RequestFilter>,
    crossings: Arc<VersionCrossings>,
    rewriting: Rewriting,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Apply the browser-shaped upstream HTTP/2 profile.
    let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
    let (sender, connection) = H2Profile::CHROME
        .apply(&mut builder)
        .handshake(TokioIo::new(upstream))
        .await
        .map_err(io::Error::other)?;
    let driver = tokio::spawn(connection);
    let proxy = Arc::new(Proxy {
        host,
        upstream: Upstream::H2(sender),
        filter,
        crossings,
        wire: Wire::Http2,
        rewriting,
        // h2 cannot populate this h1-only upgrade slot.
        upgrade: StdMutex::new(None),
    });

    let service = {
        let proxy = Arc::clone(&proxy);
        service_fn(move |request| {
            let proxy = Arc::clone(&proxy);
            async move { proxy.forward(request).await }
        })
    };

    // Match Chrome's larger request-header limit for cookie-heavy requests.
    let result = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .max_header_list_size(H2Profile::CHROME.max_header_list_size)
        .serve_connection(TokioIo::new(client), service)
        .await;
    driver.abort();
    result.map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Reader;
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

    async fn fake_upstream_reflecting_head(io: DuplexStream) {
        let service = service_fn(|request: Request<Incoming>| async move {
            let names: Vec<&str> = request.headers().keys().map(HeaderName::as_str).collect();
            let encoding = request
                .headers()
                .get("accept-encoding")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("<absent>")
                .to_owned();
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(format!(
                "{}|{encoding}",
                names.join(",")
            )))))
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(io), service)
            .await;
    }

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

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (upstream_client, upstream_server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(fake_upstream_h1(upstream_server));

        let crossings_for_exchange = Arc::clone(&crossings);
        tokio::spawn(async move {
            let wire = Wire::Http1;
            let server_tls = interceptor
                .terminate(server_io, wire)
                .await
                .expect("terminate");
            run_exchange(
                HOST_NAME,
                wire,
                server_tls,
                upstream_client,
                Arc::new(BlockPrefix("/ads/")),
                crossings_for_exchange,
                Rewriting::Off,
            )
            .await
            .expect("exchange runs");
        });

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

        let blocked = Request::builder()
            .method(Method::GET)
            .uri("/ads/banner.js")
            .header(HOST, HOST_NAME)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = sender.send_request(blocked).await.expect("blocked request");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        assert_eq!(crossings.count(), 0, "no exchange crossed versions");
    }

    async fn upgrading_origin(io: DuplexStream) {
        let service = service_fn(|mut request: Request<Incoming>| async move {
            let protocol = request
                .headers()
                .get(UPGRADE)
                .cloned()
                .expect("the offer reached the origin");
            let upgraded = hyper::upgrade::on(&mut request);
            tokio::spawn(async move {
                let Ok(upgraded) = upgraded.await else { return };
                let mut io = TokioIo::new(upgraded);
                let mut buf = [0u8; 64];
                while let Ok(read) = tokio::io::AsyncReadExt::read(&mut io, &mut buf).await {
                    if read == 0
                        || tokio::io::AsyncWriteExt::write_all(&mut io, &buf[..read])
                            .await
                            .is_err()
                    {
                        break;
                    }
                }
            });
            let mut response = Response::new(Full::new(Bytes::new()));
            *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
            response.headers_mut().insert(UPGRADE, protocol);
            response.headers_mut().insert(
                CONNECTION,
                hyper::header::HeaderValue::from_static("upgrade"),
            );
            Ok::<_, Infallible>(response)
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(io), service)
            .with_upgrades()
            .await;
    }

    #[tokio::test]
    async fn a_protocol_upgrade_survives_the_proxy_and_carries_bytes() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (upstream_client, upstream_server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(upgrading_origin(upstream_server));
        let crossings = Arc::new(VersionCrossings::new());

        let exchange = tokio::spawn(run_exchange(
            HOST_NAME,
            Wire::Http1,
            server_io,
            upstream_client,
            Arc::new(AllowAll),
            Arc::clone(&crossings),
            Rewriting::Off,
        ));

        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(client_io))
                .await
                .expect("client conn");
        tokio::spawn(connection.with_upgrades());

        let request = Request::builder()
            .method(Method::GET)
            .uri("/socket")
            .header(HOST, HOST_NAME)
            .header(CONNECTION, "Upgrade")
            .header(UPGRADE, "websocket")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let mut response = sender
            .send_request(request)
            .await
            .expect("the offer is sent");
        assert_eq!(
            response.status(),
            StatusCode::SWITCHING_PROTOCOLS,
            "the origin's agreement must reach the client"
        );
        assert_eq!(
            response.headers().get(UPGRADE).unwrap(),
            "websocket",
            "the field naming the new protocol must survive the sweep"
        );

        let upgraded = hyper::upgrade::on(&mut response)
            .await
            .expect("the client's connection is handed over");
        let mut io = TokioIo::new(upgraded);
        tokio::io::AsyncWriteExt::write_all(&mut io, b"frame")
            .await
            .unwrap();
        let mut echoed = [0u8; 5];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::io::AsyncReadExt::read_exact(&mut io, &mut echoed),
        )
        .await
        .expect("the upgraded stream is spliced")
        .unwrap();
        assert_eq!(&echoed, b"frame", "bytes crossed the upgraded connection");

        drop(io);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), exchange).await;
        assert_eq!(crossings.count(), 0, "an upgrade crosses no versions");
    }

    #[test]
    fn every_http3_alternative_is_withdrawn_and_nothing_else_is_touched() {
        for untouched in [
            "h2=\":443\"; ma=3600",
            "clear",
            "",
            "not a valid alt-svc value at all",
        ] {
            assert_eq!(steer_alt_svc([untouched]), AltSvc::Untouched, "{untouched}");
        }

        assert_eq!(
            steer_alt_svc(["h3=\":443\"; ma=2592000, h3-29=\":443\", h2=\":443\"; ma=3600"]),
            AltSvc::Narrowed("h2=\":443\"; ma=3600".to_owned())
        );
        assert_eq!(
            steer_alt_svc(["h%33=\":443\", h2=\":443\""]),
            AltSvc::Narrowed("h2=\":443\"".to_owned())
        );

        assert_eq!(steer_alt_svc(["h3=\":443\"; ma=2592000"]), AltSvc::Cleared);
        assert_eq!(
            steer_alt_svc(["h3=\":443\"", "h3-29=\":443\""]),
            AltSvc::Cleared
        );
        assert_eq!(
            steer_alt_svc(["h3=\":443\"", "h2=\":443\""]),
            AltSvc::Narrowed("h2=\":443\"".to_owned())
        );

        assert_eq!(
            steer_alt_svc(["h2=\":443\"; note=\"a,b\", h3=\":443\""]),
            AltSvc::Narrowed("h2=\":443\"; note=\"a,b\"".to_owned())
        );
    }

    #[tokio::test]
    async fn a_forwarded_response_loses_its_http3_advertisement() {
        let authority = Arc::new(CertificateAuthority::generate().unwrap());
        let root = authority.root_der().clone();
        let resolver = Arc::new(MitmResolver::new(
            Arc::clone(&authority),
            NonZeroUsize::new(16).unwrap(),
        ));
        let interceptor = Interceptor::new(resolver).unwrap();

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (upstream_client, upstream_server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let service = service_fn(|_: Request<Incoming>| async {
                let mut response = Response::new(Full::new(Bytes::from_static(b"body")));
                response.headers_mut().insert(
                    "alt-svc",
                    hyper::header::HeaderValue::from_static("h3=\":443\"; ma=2592000, h2=\":443\""),
                );
                Ok::<_, Infallible>(response)
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(upstream_server), service)
                .await;
        });

        tokio::spawn(async move {
            let wire = Wire::Http1;
            let server_tls = interceptor
                .terminate(server_io, wire)
                .await
                .expect("terminate");
            let _ = run_exchange(
                HOST_NAME,
                wire,
                server_tls,
                upstream_client,
                Arc::new(AllowAll),
                Arc::new(VersionCrossings::new()),
                Rewriting::Off,
            )
            .await;
        });

        let connector = client_connector(root, &[b"http/1.1"]);
        let client_tls = connector
            .connect(ServerName::try_from(HOST_NAME).unwrap(), client_io)
            .await
            .expect("client handshake");
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(client_tls))
                .await
                .expect("client conn");
        tokio::spawn(connection);

        let response = sender
            .send_request(
                Request::builder()
                    .uri("/")
                    .header(HOST, HOST_NAME)
                    .body(Empty::<Bytes>::new())
                    .unwrap(),
            )
            .await
            .expect("the exchange completes");
        assert_eq!(
            response.headers().get("alt-svc").unwrap(),
            "h2=\":443\"",
            "the h3 advertisement must not reach the client"
        );
    }

    #[test]
    fn only_a_complete_offer_is_read_as_an_upgrade() {
        let offer = Request::builder()
            .header(CONNECTION, "keep-alive, Upgrade")
            .header(UPGRADE, "websocket")
            .body(())
            .unwrap();
        assert_eq!(handling(&offer), Handling::Upgrade);

        for incomplete in [
            Request::builder().header(UPGRADE, "websocket").body(()),
            Request::builder().header(CONNECTION, "Upgrade").body(()),
            Request::builder().header(CONNECTION, "keep-alive").body(()),
            Request::builder().body(()),
        ] {
            assert_eq!(handling(&incomplete.unwrap()), Handling::Ordinary);
        }

        let mut ordinary = HeaderMap::new();
        ordinary.insert(CONNECTION, "close, x-custom".parse().unwrap());
        ordinary.insert("x-custom", "1".parse().unwrap());
        ordinary.insert(UPGRADE, "h2c".parse().unwrap());
        strip_hop_by_hop(&mut ordinary, Handling::Ordinary);
        assert!(ordinary.is_empty(), "{ordinary:?}");

        let mut offered = HeaderMap::new();
        offered.insert(CONNECTION, "Upgrade".parse().unwrap());
        offered.insert(UPGRADE, "websocket".parse().unwrap());
        offered.insert("te", "trailers".parse().unwrap());
        strip_hop_by_hop(&mut offered, Handling::Upgrade);
        assert_eq!(offered.len(), 2);
        assert!(offered.contains_key(CONNECTION) && offered.contains_key(UPGRADE));
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
            let wire = Wire::Http2;
            let server_tls = interceptor
                .terminate(server_io, wire)
                .await
                .expect("terminate");
            run_exchange(
                HOST_NAME,
                wire,
                server_tls,
                upstream_client,
                Arc::new(AllowAll),
                crossings_for_exchange,
                Rewriting::Off,
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

    #[tokio::test]
    async fn a_relayed_request_keeps_its_field_order_and_encodings() {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let (upstream_client, upstream_server) = tokio::io::duplex(4096);
        tokio::spawn(fake_upstream_reflecting_head(upstream_server));
        tokio::spawn(run_exchange(
            HOST_NAME,
            Wire::Http1,
            server_io,
            upstream_client,
            Arc::new(AllowAll),
            Arc::new(VersionCrossings::new()),
            Rewriting::Off,
        ));

        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(client_io))
                .await
                .unwrap();
        tokio::spawn(connection);
        let request = Request::builder()
            .method(Method::POST)
            .uri("/submit")
            .header(HOST, HOST_NAME)
            .header("user-agent", "boreas-test")
            .header("accept", "text/html")
            .header("accept-encoding", "gzip, deflate, br, zstd")
            .header("accept-language", "en-GB,en;q=0.9")
            .header("cookie", "a=1")
            .body(Full::new(Bytes::from_static(b"body")))
            .unwrap();
        let response = sender.send_request(request).await.expect("forwarded");
        let body = response.into_body().collect().await.unwrap().to_bytes();

        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            "host,user-agent,accept,accept-encoding,accept-language,cookie,content-length\
|gzip, deflate, br, zstd"
        );
    }

    #[test]
    fn dropping_a_field_leaves_the_order_of_the_rest() {
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("host", "example.test"),
            ("user-agent", "boreas-test"),
            ("content-length", "4"),
            ("accept", "text/html"),
            ("cookie", "a=1"),
        ] {
            headers.insert(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
        }
        strip_hop_by_hop(&mut headers, Handling::Ordinary);
        let names: Vec<&str> = headers.keys().map(HeaderName::as_str).collect();
        assert_eq!(names, ["host", "user-agent", "accept", "cookie"]);

        let mut untouched = headers.clone();
        strip_hop_by_hop(&mut untouched, Handling::Ordinary);
        assert_eq!(untouched, headers);
    }

    // HTTP/2 fingerprint.

    const FRAME_HEADERS: u8 = 0x1;
    const FRAME_PRIORITY: u8 = 0x2;
    const FRAME_SETTINGS: u8 = 0x4;
    const FRAME_WINDOW_UPDATE: u8 = 0x8;

    struct RawFrame {
        kind: u8,
        flags: u8,
        stream: u32,
        payload: Vec<u8>,
    }

    async fn read_frame<R: tokio::io::AsyncRead + Unpin>(io: &mut R) -> RawFrame {
        use tokio::io::AsyncReadExt;
        let mut head = [0u8; 9];
        io.read_exact(&mut head).await.expect("frame header");
        let length = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
        let mut payload = vec![0u8; length];
        io.read_exact(&mut payload).await.expect("frame payload");
        RawFrame {
            kind: head[3],
            flags: head[4],
            stream: u32::from_be_bytes([head[5] & 0x7f, head[6], head[7], head[8]]),
            payload,
        }
    }

    /// Reads an HPACK prefixed integer (RFC 7541 section 5.1).
    fn varint(first: u8, mut rest: &[u8], bits: u32) -> (usize, &[u8]) {
        let mask = (1usize << bits) - 1;
        let mut value = usize::from(first) & mask;
        if value == mask {
            let mut shift = 0;
            loop {
                let (&byte, tail) = rest.split_first().expect("truncated integer");
                rest = tail;
                value += usize::from(byte & 0x7f) << shift;
                shift += 7;
                if byte & 0x80 == 0 {
                    break;
                }
            }
        }
        (value, rest)
    }

    /// Skips one HPACK string literal.
    fn skip_string(rest: &[u8]) -> &[u8] {
        let (&first, after) = rest.split_first().expect("truncated string");
        let (length, after) = varint(first, after, 7);
        &after[length..]
    }

    /// Maps relevant static-table indices to fingerprint letters.
    fn pseudo_letter(index: usize) -> Option<char> {
        match index {
            1 => Some('a'),
            2 | 3 => Some('m'),
            4 | 5 => Some('p'),
            6 | 7 => Some('s'),
            _ => None,
        }
    }

    /// Reads pseudo-header order from the first HPACK block.
    fn pseudo_order(block: &[u8]) -> String {
        let mut letters: Vec<char> = Vec::new();
        let mut rest = block;
        while let Some((&first, after)) = rest.split_first() {
            if first & 0x80 != 0 {
                let (index, tail) = varint(first, after, 7);
                letters.extend(pseudo_letter(index));
                rest = tail;
                continue;
            }
            if first & 0xe0 == 0x20 {
                (_, rest) = varint(first, after, 5);
                continue;
            }
            let prefix = if first & 0xc0 == 0x40 { 6 } else { 4 };
            let (index, tail) = varint(first, after, prefix);
            letters.extend(pseudo_letter(index));
            rest = skip_string(if index == 0 { skip_string(tail) } else { tail });
        }
        letters
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Verifies the Chrome-shaped preface and first request on the wire.
    #[tokio::test]
    async fn the_upstream_preface_is_chromes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (client_near, client_far) = tokio::io::duplex(64 * 1024);
        let (upstream_near, mut origin) = tokio::io::duplex(64 * 1024);

        tokio::spawn(run_exchange(
            HOST_NAME,
            Wire::Http2,
            client_far,
            upstream_near,
            Arc::new(AllowAll),
            Arc::new(VersionCrossings::new()),
            Rewriting::Off,
        ));
        origin
            .write_all(&[0, 0, 0, FRAME_SETTINGS, 0, 0, 0, 0, 0])
            .await
            .unwrap();

        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(client_near))
                .await
                .expect("client conn");
        tokio::spawn(connection);
        let request = Request::builder()
            .method(Method::GET)
            .uri(format!("https://{HOST_NAME}/"))
            .body(Empty::<Bytes>::new())
            .unwrap();
        tokio::spawn(async move { sender.send_request(request).await });

        let mut preface = [0u8; 24];
        origin.read_exact(&mut preface).await.expect("preface");
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

        let mut settings = Vec::new();
        let mut increment = 0;
        let headers = loop {
            let frame = read_frame(&mut origin).await;
            match frame.kind {
                FRAME_SETTINGS if frame.flags & 0x1 != 0 => {}
                FRAME_SETTINGS => {
                    let mut reader = Reader::new(&frame.payload);
                    settings =
                        std::iter::from_fn(|| Some(format!("{}:{}", reader.u16()?, reader.u32()?)))
                            .collect();
                }
                FRAME_WINDOW_UPDATE => {
                    assert_eq!(frame.stream, 0, "the connection window, not a stream's");
                    increment = Reader::new(&frame.payload).u32().expect("a full increment");
                }
                FRAME_PRIORITY => panic!("Chrome sends no PRIORITY frame"),
                FRAME_HEADERS => break frame,
                _ => {}
            }
        };
        assert_eq!(headers.flags & 0x28, 0);

        assert_eq!(
            format!(
                "{}|{increment}|0|{}",
                settings.join(";"),
                pseudo_order(&headers.payload)
            ),
            H2Profile::CHROME.akamai(),
        );
    }
}
