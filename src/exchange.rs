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
//!
//! **An upgrade is a message, not noise.** `Connection` and `Upgrade` are
//! hop-by-hop fields, and a proxy that strips them unconditionally destroys the
//! one mechanism h1 has for handing a connection to another protocol — which is
//! how WebSockets work, and which [Filtering](../docs/filtering.md) requires be
//! preserved. [`Handling`] is the sum that says which of the two an exchange is,
//! and the upgrade branch relays both fields, completes both handshakes, and
//! then splices the two byte streams. On h2 the sum is inhabited only by
//! [`Handling::Ordinary`] by construction: `SETTINGS_ENABLE_CONNECT_PROTOCOL`
//! is never advertised, so RFC 8441 extended CONNECT is not offered and a
//! client that wants a WebSocket opens an h1 connection for it, which this
//! module then handles as an upgrade.

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

use crate::{Rewriting, VersionCrossings, Wire};

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
///
/// `connection` and `upgrade` are deliberately absent: they are hop-by-hop too,
/// but they are also the entire h1 upgrade mechanism, so they are governed by
/// [`Handling`] rather than swept unconditionally.
const HOP_BY_HOP: [&str; 7] = [
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "content-length",
];

// ---------------------------------------------------------------------------
// Alt-Svc steering
// ---------------------------------------------------------------------------

/// The `Alt-Svc` field name, and the RFC 7838 §3 keyword that withdraws every
/// alternative the origin previously advertised.
const ALT_SVC: &str = "alt-svc";
const ALT_SVC_CLEAR: &str = "clear";

/// What steering does to a response's `Alt-Svc` advertisement.
///
/// **This is the header half of a decision the resolver already makes.**
/// [`alpn_policy`](crate::alpn_policy) strips `h3` from an inspected host's
/// HTTPS and SVCB records, and [Filtering](../docs/filtering.md)'s steering
/// table asks for the same on the response header — because a client also
/// discovers HTTP/3 through `Alt-Svc`, and an inspected host reached over h3 is
/// a host whose interception silently never fires. Every response crossing this
/// proxy is on a connection Boreas terminated, so every one of them is a
/// response from a host that is being inspected: the policy needs no argument
/// beyond the header itself.
///
/// A closed sum rather than an `Option<String>`, because withdrawing every
/// alternative is not the same edit as removing some of them: RFC 7838 spells
/// the first `clear`, and an *empty* field would say nothing at all and leave
/// the client's cached advertisement in place — which is the case the whole
/// transient UDP/443 backstop exists to cover.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AltSvc {
    /// Nothing advertised HTTP/3, so the field is left byte-for-byte as it
    /// arrived. The overwhelming majority, and the fail-open default.
    Untouched,
    /// Some alternatives advertised h3 and some did not. The h3 ones are gone
    /// and the rest survive verbatim, in order.
    Narrowed(String),
    /// Every alternative advertised h3, so there is nothing left to offer and
    /// the origin's previous advertisement is withdrawn outright.
    Cleared,
}

/// Removes every HTTP/3 alternative from one or more `Alt-Svc` field values.
///
/// Total on untrusted input: a field this cannot parse yields no alternatives,
/// which is [`AltSvc::Untouched`] — the reading that changes nothing.
///
/// O(bytes of the field), one pass, and allocation-free unless something is
/// actually removed.
#[must_use]
pub fn steer_alt_svc<'a>(values: impl IntoIterator<Item = &'a str>) -> AltSvc {
    let mut kept: Vec<&str> = Vec::new();
    let mut removed = false;
    let mut saw_any = false;

    for value in values {
        // `clear` is already the answer steering wants; it is not an
        // alternative to keep, and re-emitting it would be the same header.
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

/// Splits an `Alt-Svc` field into its alt-values at top-level commas.
///
/// Quoted strings are respected, because a parameter value may be one and may
/// contain a comma; splitting naively there would cut an alternative in half
/// and the half that survived would be nonsense the client then acted on.
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

/// Whether one alt-value's protocol identifier names an HTTP/3 version.
///
/// The identifier is an ALPN token with `%`-encoding (RFC 7838 §3), so it is
/// decoded before it is compared: a server that wrote `h%33` would otherwise
/// keep an advertisement this is meant to withdraw. Every deployed HTTP/3 ALPN
/// token is `h3` or `h3-<draft>`, and matching the prefix rather than a fixed
/// list is what keeps a future draft from slipping past.
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

/// Decodes `%XX` escapes. Total: an incomplete or non-hex escape is kept as the
/// literal bytes it is, which is what a comparison against a known token wants.
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

/// Applies [`steer_alt_svc`] to a response's headers in place.
fn steer_response(headers: &mut HeaderMap) {
    let steering = steer_alt_svc(
        headers
            .get_all(ALT_SVC)
            .iter()
            .filter_map(|value| value.to_str().ok()),
    );
    let replacement = match steering {
        // Byte-exact: a response advertising no h3 is not touched at all.
        AltSvc::Untouched => return,
        AltSvc::Cleared => HeaderValue::from_static(ALT_SVC_CLEAR),
        AltSvc::Narrowed(kept) => match HeaderValue::from_str(&kept) {
            Ok(value) => value,
            // A survivor that will not fit a header field is one this cannot
            // re-emit, and withdrawing everything is the safe direction: the
            // client loses an alternative rather than reaching h3.
            Err(_) => HeaderValue::from_static(ALT_SVC_CLEAR),
        },
    };
    headers.remove(ALT_SVC);
    headers.insert(ALT_SVC, replacement);
}

/// What this exchange is, and therefore what the hop-by-hop sweep may remove.
///
/// A closed sum rather than a boolean, because the two carry different
/// obligations and a caller that reads `true` has to remember which way round
/// it went. There is no third state: a message either is an upgrade by RFC 9110
/// §7.8's exact definition or is an ordinary message, and everything malformed
/// lands in the second.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Handling {
    Ordinary,
    /// The client asked to leave HTTP behind on this connection. Both fields
    /// that say so are relayed rather than stripped, because upstream is the
    /// peer that has to agree.
    Upgrade,
}

/// Reads a request as an upgrade offer, or as an ordinary message.
///
/// The definition is exact: a `Connection` header naming the `upgrade` token
/// *and* an `Upgrade` header naming a protocol. Either alone is not an offer,
/// and treating it as one would relay a connection-specific field for nothing.
///
/// O(bytes of the two fields), no allocation.
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

fn strip_hop_by_hop(headers: &mut HeaderMap, handling: Handling) {
    // The `Connection` header may name further fields to drop; those named
    // tokens are honoured before the header itself is removed. The collection
    // is built only when the field is present at all, which on h2 is never —
    // `Connection` is forbidden there — so the common wire pays nothing.
    if headers.contains_key(CONNECTION) {
        let named: Vec<HeaderName> = headers
            .get_all(CONNECTION)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .map(str::trim)
            // On the upgrade path `Connection: upgrade` names the very field
            // that carries the offer, so honouring it would delete the message.
            .filter(|token| {
                handling == Handling::Ordinary || !token.eq_ignore_ascii_case("upgrade")
            })
            .filter_map(|token| HeaderName::from_bytes(token.as_bytes()).ok())
            .collect();
        for name in named {
            headers.remove(name);
        }
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
    if handling == Handling::Ordinary {
        headers.remove(CONNECTION);
        headers.remove(UPGRADE);
    }
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

/// The two halves of an h1 upgrade, waiting for their connections to be handed
/// over. Neither is useful without the other, so they are one value.
struct Pending {
    client: OnUpgrade,
    upstream: OnUpgrade,
}

/// Everything one terminated connection's requests share.
///
/// **One `Arc` per request rather than five.** These were passed as five
/// separately cloned handles into the service closure; grouping them means the
/// per-request cost is a single refcount bump, and the two that are only *read*
/// — the filter and the rewriting policy — are borrowed out of it rather than
/// cloned at all.
struct Proxy {
    host: Arc<str>,
    upstream: Upstream,
    filter: Arc<dyn RequestFilter>,
    crossings: Arc<VersionCrossings>,
    wire: Wire,
    rewriting: Rewriting,
    /// Where an upgrade parks its two halves for the connection loop to splice.
    ///
    /// A `std::sync::Mutex` and never held across an `await`: it is touched
    /// once when a 101 is produced and once when the connection ends. `None`
    /// for the whole life of every ordinary connection, which is nearly all of
    /// them.
    upgrade: StdMutex<Option<Pending>>,
}

impl Proxy {
    /// Forwards one request: filter, sweep hop-by-hop headers, send upstream,
    /// box the reply. Never returns `Err` — every failure is a response the
    /// client can see — so the connection survives one bad exchange.
    async fn forward(
        &self,
        mut request: Request<Incoming>,
    ) -> Result<Response<ProxyBody>, Infallible> {
        if self.filter.decide(&self.host, &request) == FilterVerdict::Block {
            return Ok(blocked());
        }
        let handling = handling(&request);
        // The client's half is claimed before the request is consumed, and it
        // resolves only if a 101 actually comes back — so claiming it costs
        // nothing on an offer the origin declines.
        let client = (handling == Handling::Upgrade).then(|| hyper::upgrade::on(&mut request));

        strip_hop_by_hop(request.headers_mut(), handling);
        // Asked *after* the hop-by-hop sweep, because the field it sets is one
        // the sweep would otherwise be free to remove.
        self.rewriting.prepare(&self.host, request.headers_mut());

        // The upstream wire equals the client wire by construction: the record
        // is the proof, and the P14 gate reads its count.
        self.crossings.record(self.wire, self.wire);

        let Ok(mut response) = self.upstream.send(request).await else {
            return Ok(bad_gateway());
        };
        // **A 101 is the origin agreeing, and it is the only thing that turns
        // the offer into a splice.** Anything else — including an origin that
        // ignored the offer and answered 200 — is an ordinary response, and its
        // connection-specific fields are swept as usual.
        if let Some(client) = client
            && response.status() == StatusCode::SWITCHING_PROTOCOLS
        {
            let upstream = hyper::upgrade::on(&mut response);
            *self
                .upgrade
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()) = Some(Pending { client, upstream });
            // Relayed verbatim: the 101's `Connection` and `Upgrade` are what
            // tell the client the switch happened, and no body follows to
            // rewrite.
            return Ok(response.map(|body| body.map_err(Into::into).boxed()));
        }

        strip_hop_by_hop(response.headers_mut(), Handling::Ordinary);
        // The header half of protocol steering. Unconditional, because every
        // response here is on a connection this process terminated, and an
        // inspected host reached over h3 is one whose interception never fires.
        steer_response(response.headers_mut());
        // The HTML tier, which decides for itself whether this response is one
        // it can read and forwards it untouched when it is not.
        Ok(self.rewriting.apply(&self.host, response))
    }

    fn take_upgrade(&self) -> Option<Pending> {
        self.upgrade
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .take()
    }
}

/// Joins the two upgraded connections and copies between them until either
/// closes.
///
/// Awaited by the connection loop rather than spawned, so the upgraded stream
/// lives inside the exchange's own lifetime and is torn down with it — the same
/// structured-cancellation rule the rest of the crate follows.
async fn splice_upgrade(pending: Pending) -> io::Result<()> {
    let (client, upstream) =
        tokio::try_join!(pending.client, pending.upstream).map_err(io::Error::other)?;
    let mut client = TokioIo::new(client);
    let mut upstream = TokioIo::new(upstream);
    tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .map(drop)
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
    // `with_upgrades` on both legs is what lets a 101 hand each connection over
    // instead of ending it. Without it the upgrade futures below never resolve
    // and a WebSocket handshake completes into a connection nobody owns.
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
        // No upgrade: the upstream connection has nothing left to do, and
        // aborting it is what keeps the task from outliving the exchange.
        None => {
            driver.abort();
            result.map_err(io::Error::other)
        }
        // An upgrade: the upstream driver must *not* be aborted, because it is
        // the thing that still has to hand its connection over. It resolves on
        // its own the moment it does.
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
    let (sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(upstream))
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
        // Unreachable on h2: `Connection` and `Upgrade` are forbidden fields
        // there, so `handling` can only answer `Ordinary`, and RFC 8441's
        // extended CONNECT is never advertised. The slot exists because the
        // record is shared, not because this wire can fill it.
        upgrade: StdMutex::new(None),
    });

    let service = {
        let proxy = Arc::clone(&proxy);
        service_fn(move |request| {
            let proxy = Arc::clone(&proxy);
            async move { proxy.forward(request).await }
        })
    };

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
                Rewriting::Off,
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

    /// An origin that agrees to every upgrade and then echoes the raw stream —
    /// a WebSocket server reduced to the only part this proxy has to preserve.
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

    /// **The WebSocket gate.** `Connection` and `Upgrade` are hop-by-hop, and a
    /// proxy that swept them unconditionally would answer every WebSocket
    /// handshake with an ordinary response — a broken chat, feed, or dev server
    /// on every intercepted host, which is exactly the breakage the filtering
    /// contract forbids. The assertion is on bytes crossing the upgraded
    /// stream, because a 101 that reached the client but left the connection
    /// unspliced would still look like success.
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

    /// **The header half of protocol steering.** A browser discovers HTTP/3
    /// through `Alt-Svc` as well as through DNS, and an inspected host reached
    /// over h3 is one whose interception silently never fires — so an
    /// advertisement that survived this proxy would defeat the whole tier.
    #[test]
    fn every_http3_alternative_is_withdrawn_and_nothing_else_is_touched() {
        // Nothing to steer: byte-exact, which is the fail-open default.
        for untouched in [
            "h2=\":443\"; ma=3600",
            "clear",
            "",
            "not a valid alt-svc value at all",
        ] {
            assert_eq!(steer_alt_svc([untouched]), AltSvc::Untouched, "{untouched}");
        }

        // Mixed: the h3 alternatives go and the rest survive verbatim, in
        // order. Draft versions count, and so does a percent-encoded token a
        // server could use to slip one past a fixed-string comparison.
        assert_eq!(
            steer_alt_svc(["h3=\":443\"; ma=2592000, h3-29=\":443\", h2=\":443\"; ma=3600"]),
            AltSvc::Narrowed("h2=\":443\"; ma=3600".to_owned())
        );
        assert_eq!(
            steer_alt_svc(["h%33=\":443\", h2=\":443\""]),
            AltSvc::Narrowed("h2=\":443\"".to_owned())
        );

        // Nothing left to offer: withdrawn outright rather than emptied, because
        // an empty field says nothing and leaves the client's cache in place.
        assert_eq!(steer_alt_svc(["h3=\":443\"; ma=2592000"]), AltSvc::Cleared);
        // Several fields intersect into one decision.
        assert_eq!(
            steer_alt_svc(["h3=\":443\"", "h3-29=\":443\""]),
            AltSvc::Cleared
        );
        assert_eq!(
            steer_alt_svc(["h3=\":443\"", "h2=\":443\""]),
            AltSvc::Narrowed("h2=\":443\"".to_owned())
        );

        // A comma inside a quoted parameter is not a separator; splitting there
        // would cut an alternative in half and leave the client acting on the
        // remains.
        assert_eq!(
            steer_alt_svc(["h2=\":443\"; note=\"a,b\", h3=\":443\""]),
            AltSvc::Narrowed("h2=\":443\"; note=\"a,b\"".to_owned())
        );
    }

    /// The steering must reach a real response's headers, not just the pure
    /// function: this is the seam where forgetting to call it would be silent.
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
            let (server_tls, wire) = interceptor.terminate(server_io).await.expect("terminate");
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

    /// The dual: an `Upgrade` field with no `Connection: upgrade` token is not
    /// an offer, so it is swept like any other connection-specific field and
    /// the exchange stays ordinary.
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

        // And the sweep honours the distinction: an ordinary message loses both
        // fields, an offer keeps exactly those two and loses the rest.
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
            let (server_tls, wire) = interceptor.terminate(server_io).await.expect("terminate");
            assert_eq!(wire, Wire::Http2, "h2 was offered and preferred");
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
