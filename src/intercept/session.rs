//! Assembles policy, protocol recognition, interception, and splicing for one
//! terminated connection.
//!
//! The client name is learned from the first bytes: TLS SNI or cleartext HTTP
//! `Host`. Recognition is fail-open; only a named, allowlisted host can reach
//! interception, and every other outcome is spliced with a reason.
//!
//! The origin selects the ALPN before the local client is terminated. Both legs
//! therefore use one negotiated wire version, while version crossings remain
//! counted as an acceptance check.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncReadExt, copy_bidirectional},
    sync::mpsc,
};
use tokio_util::task::TaskTracker;

use crate::{
    Accepted, CosmeticSource, Demotion, Demotions, DomainName, EgressError, Either, Hello,
    InterceptDecision, InterceptPolicy, InterceptedTier, Interceptor, Leg, NoCosmetics, Originator,
    Prefixed, RequestFilter, RewriteFailures, Rewriting, StreamBudget, StreamEgress, Target,
    VersionCrossings, Wire, classify, run_exchange, wire::Reader,
};

/// TLS handshake record content type.
const RECORD_HANDSHAKE: u8 = 0x16;
/// TLS record-layer major version.
const RECORD_MAJOR: u8 = 0x03;

/// Maximum bytes examined for one TLS record.
const MAX_RECORD: usize = (1 << 14) + 5;

/// Maximum cleartext request headers examined before splicing.
const MAX_REQUEST_HEADERS: usize = 64;

/// Result of recognizing the client's first bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Introduction {
    /// More bytes are required.
    Incomplete,
    /// TLS metadata extracted from one complete handshake record.
    Tls(Hello),
    /// Complete cleartext HTTP/1.x request head and optional host.
    Http { host: Option<DomainName> },
    /// Input is neither recognized TLS nor HTTP.
    Plain,
}

/// Origin connection mode after a host is known.
enum Approach {
    Tls {
        profile: crate::ClientProfile,
        alpn: crate::Offer,
    },
    Cleartext,
}

/// Recognizes TLS or cleartext HTTP without consuming the input.
pub fn introduce(bytes: &[u8]) -> Introduction {
    // TLS record header: content type, legacy version, and payload length.
    let mut reader = Reader::new(bytes);
    let Some(&[content, major, _minor]) = reader.array::<3>() else {
        return Introduction::Incomplete;
    };
    if content != RECORD_HANDSHAKE || major != RECORD_MAJOR {
        return request_head(bytes);
    }
    let Some(record) = reader.vector_u16() else {
        return Introduction::Incomplete;
    };
    Introduction::Tls(crate::read_hello(record))
}

/// Parses a complete cleartext HTTP/1.x request head for its host.
fn request_head(bytes: &[u8]) -> Introduction {
    let mut fields = [httparse::EMPTY_HEADER; MAX_REQUEST_HEADERS];
    let mut request = httparse::Request::new(&mut fields);
    match request.parse(bytes) {
        Ok(httparse::Status::Complete(_)) => Introduction::Http {
            host: host_field(request.headers),
        },
        Ok(httparse::Status::Partial) => Introduction::Incomplete,
        Err(_) => Introduction::Plain,
    }
}

/// Extracts and validates the host portion of a `Host` authority.
fn host_field(fields: &[httparse::Header<'_>]) -> Option<DomainName> {
    let value = fields
        .iter()
        .find(|field| field.name.eq_ignore_ascii_case("host"))?
        .value;
    let authority: http::uri::Authority = std::str::from_utf8(value).ok()?.parse().ok()?;
    DomainName::new(authority.host()).ok()
}

/// Reason a connection was spliced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpliceReason {
    /// The host is not allowlisted.
    NotAllowlisted,
    /// No usable host name was present.
    Unnamed,
    /// Input was not TLS.
    NotTls,
    /// Recognition did not complete before the deadline or bound.
    Undecided,
    /// Interception was previously demoted for this host.
    Demoted(Demotion),
    /// The current origin handshake failed before local termination.
    OriginHandshake,
}

/// Result of serving one connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Handling {
    /// Intercepted at the selected tier.
    Intercepted {
        host: DomainName,
        wire: Wire,
        tier: InterceptedTier,
    },
    Spliced {
        reason: SpliceReason,
    },
    /// Interception failed and the host was demoted.
    Demoted {
        host: DomainName,
        cause: Demotion,
    },
}

#[derive(Debug)]
pub enum SessionError {
    /// Upstream connection or protocol failure.
    Upstream(EgressError),
    /// The client rejected the forged TLS leaf.
    ClientHandshake(std::io::Error),
    /// Bidirectional transfer failure.
    Transfer(std::io::Error),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Upstream(error) => write!(f, "upstream unreachable: {error}"),
            Self::ClientHandshake(error) => write!(f, "client handshake failed: {error}"),
            Self::Transfer(error) => write!(f, "transfer failed: {error}"),
        }
    }
}

impl std::error::Error for SessionError {}

/// Limits for protocol recognition before policy applies.
#[derive(Clone, Copy, Debug)]
pub struct SessionLimits {
    /// Maximum time to wait for a conclusive introduction.
    pub peek_timeout: Duration,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            // Bound silent connections without penalizing slow first packets.
            peek_timeout: Duration::from_secs(5),
        }
    }
}

/// Immutable and shared state for all sessions.
pub struct Sessions {
    pub interceptor: Arc<Interceptor>,
    pub policy: Arc<InterceptPolicy>,
    /// Egress for both spliced and intercepted flows.
    pub egress: Arc<dyn StreamEgress>,
    pub filter: Arc<dyn RequestFilter>,
    pub crossings: Arc<VersionCrossings>,
    /// Per-host record of interception failures.
    pub demotions: Arc<Demotions>,
    pub limits: SessionLimits,
    /// Source for optional HTML element-hiding rules.
    cosmetic: Arc<dyn CosmeticSource>,
    budget: StreamBudget,
    /// BoringSSL origin connector, shared to cache profiles and trust anchors.
    originator: Arc<Originator>,
}

impl Sessions {
    pub fn new(
        interceptor: Arc<Interceptor>,
        policy: Arc<InterceptPolicy>,
        egress: Arc<dyn StreamEgress>,
        filter: Arc<dyn RequestFilter>,
        limits: SessionLimits,
    ) -> Result<Self, EgressError> {
        Ok(Self {
            interceptor,
            policy,
            egress,
            filter,
            crossings: Arc::new(VersionCrossings::new()),
            demotions: Arc::new(Demotions::new()),
            limits,
            cosmetic: Arc::new(NoCosmetics),
            budget: StreamBudget::default(),
            originator: Arc::new(Originator::new()),
        })
    }

    /// Adds trust roots for private or test upstream origins.
    pub fn with_upstream_roots(mut self, extra_roots: &[Vec<u8>]) -> Result<Self, EgressError> {
        self.originator = Arc::new(Originator::new().with_extra_roots(extra_roots));
        Ok(self)
    }

    /// Configures cosmetic rules and the stream rewrite budget.
    #[must_use]
    pub fn with_cosmetic_rules(
        mut self,
        cosmetic: Arc<dyn CosmeticSource>,
        budget: StreamBudget,
    ) -> Self {
        self.cosmetic = cosmetic;
        self.budget = budget;
        self
    }

    /// Selects response rewriting for an intercepted tier.
    fn rewriting(&self, tier: InterceptedTier, failures: &Arc<RewriteFailures>) -> Rewriting {
        match tier {
            InterceptedTier::Rewrite => Rewriting::On {
                source: Arc::clone(&self.cosmetic),
                budget: self.budget,
                failures: Arc::clone(failures),
            },
            InterceptedTier::Inspect => Rewriting::Off,
        }
    }
}

/// Serves one terminated connection and returns its handling result.
pub async fn serve_session(
    stream: crate::TerminatedStream,
    server: std::net::SocketAddr,
    sessions: Arc<Sessions>,
) -> Result<Handling, SessionError> {
    let port = server.port();
    let (introduction, peeked, stream) = peek(stream, sessions.limits.peek_timeout).await;

    let (host, approach) = match introduction {
        Introduction::Tls(Hello {
            host: Some(host),
            profile,
            alpn,
        }) => (host, Approach::Tls { profile, alpn }),
        Introduction::Http { host: Some(host) } => (host, Approach::Cleartext),
        Introduction::Tls(Hello { host: None, .. }) | Introduction::Http { host: None } => {
            return splice(sessions, server, peeked, stream, SpliceReason::Unnamed).await;
        }
        Introduction::Plain => {
            return splice(sessions, server, peeked, stream, SpliceReason::NotTls).await;
        }
        Introduction::Incomplete => {
            return splice(sessions, server, peeked, stream, SpliceReason::Undecided).await;
        }
    };
    if sessions.policy.decide(host.as_str()) == InterceptDecision::Splice {
        return splice(
            sessions,
            server,
            peeked,
            stream,
            SpliceReason::NotAllowlisted,
        )
        .await;
    }
    // Policy selects candidates; standing records whether interception works.
    let tier = match sessions
        .demotions
        .standing(host.as_str(), Instant::now())
        .permits()
    {
        Ok(tier) => tier,
        // A recorded demotion is the only standing that forbids interception.
        Err(cause) => {
            return splice(
                sessions,
                server,
                peeked,
                stream,
                SpliceReason::Demoted(cause),
            )
            .await;
        }
    };

    let target = Target::Domain {
        host: host.clone(),
        port,
    };
    // Bound the complete proxy dial, including an egress that accepts but stalls.
    let transport = crate::within(crate::Wait::ProxyDial, sessions.egress.connect(&target))
        .await
        .map_err(SessionError::Upstream)?;

    // Both modes produce two streams and one wire version.
    let (client, upstream, wire) = match approach {
        // The origin selects ALPN before the forged leaf is sent. This keeps
        // both legs on one version and leaves origin failure spliceable.
        Approach::Tls { profile, alpn } => {
            // Mirror the client's profile on the origin-facing handshake.
            let upstream = match sessions
                .originator
                .connect(host.as_str(), &profile, &alpn.encode(), transport)
                .await
            {
                Ok(upstream) => upstream,
                Err(error) => {
                    if let Some(cause) = classify(Leg::Upstream, &error) {
                        sessions
                            .demotions
                            .record(host.as_str(), cause, Instant::now());
                    }
                    return splice(
                        sessions,
                        server,
                        peeked,
                        stream,
                        SpliceReason::OriginHandshake,
                    )
                    .await;
                }
            };
            let wire = Wire::from_alpn(upstream.ssl().selected_alpn_protocol());

            let replayed = Prefixed::new(peeked, stream);
            let client = match sessions.interceptor.terminate(replayed, wire).await {
                Ok(client) => client,
                Err(error) => {
                    // The leaf is already sent, so client rejection cannot splice.
                    return learn(&sessions, &host, Leg::Client, error, |error| {
                        SessionError::ClientHandshake(error)
                    });
                }
            };
            (Either::Left(client), Either::Left(upstream), wire)
        }
        // Cleartext has no handshake and only the HTTP/1.x wire.
        Approach::Cleartext => (
            Either::Right(Prefixed::new(peeked, stream)),
            Either::Right(transport),
            Wire::Http1,
        ),
    };

    // Exchange termination is normal session completion.
    let failures = Arc::new(RewriteFailures::new());
    let _ = run_exchange(
        host.as_str(),
        wire,
        client,
        upstream,
        Arc::clone(&sessions.filter),
        Arc::clone(&sessions.crossings),
        sessions.rewriting(tier, &failures),
    )
    .await;
    // Record rewrite exhaustion only after the exchange ends.
    if failures.count() > 0 {
        sessions
            .demotions
            .record(host.as_str(), Demotion::RewriteExhausted, Instant::now());
    }
    Ok(Handling::Intercepted { host, wire, tier })
}

/// Records what a failed handshake proved, if it proved anything.
///
/// A conclusive failure is not an error of the session. The connection is lost
/// either way; what distinguishes the two outcomes is whether the next
/// connection to this host will repeat it, and a recorded demotion is exactly
/// the promise that it will not. Everything else — a reset, a timeout, a peer
/// that vanished — proves nothing and stays an error.
fn learn(
    sessions: &Sessions,
    host: &DomainName,
    leg: Leg,
    error: std::io::Error,
    otherwise: impl FnOnce(std::io::Error) -> SessionError,
) -> Result<Handling, SessionError> {
    match classify(leg, &error) {
        Some(cause) => {
            sessions
                .demotions
                .record(host.as_str(), cause, Instant::now());
            Ok(Handling::Demoted {
                host: host.clone(),
                cause,
            })
        }
        None => Err(otherwise(error)),
    }
}

/// Reads until introduction, timeout, EOF, or the record bound is conclusive.
///
/// Returns the peeked bytes so splicing and TLS termination can replay them.
async fn peek(
    mut stream: crate::TerminatedStream,
    timeout: Duration,
) -> (Introduction, Vec<u8>, crate::TerminatedStream) {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        match introduce(&buf) {
            Introduction::Incomplete if buf.len() < MAX_RECORD => {}
            // The bound prevents unbounded waiting on incomplete input.
            Introduction::Incomplete => return (Introduction::Incomplete, buf, stream),
            conclusive => return (conclusive, buf, stream),
        }
        let read = match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => return (introduce(&buf), buf, stream),
            Ok(Ok(read)) => read,
            // The caller handles the dead connection during splice.
            Ok(Err(_)) => return (introduce(&buf), buf, stream),
        };
        buf.extend_from_slice(&chunk[..read]);
    }
}

/// Passes a connection through to the original socket address.
///
/// Splicing must preserve the client's DNS choice, so the original address is
/// used instead of resolving the parsed host again.
async fn splice(
    sessions: Arc<Sessions>,
    server: std::net::SocketAddr,
    peeked: Vec<u8>,
    stream: crate::TerminatedStream,
    reason: SpliceReason,
) -> Result<Handling, SessionError> {
    let mut upstream = sessions
        .egress
        .connect(&Target::Ip(server))
        .await
        .map_err(SessionError::Upstream)?;
    let mut client = Prefixed::new(peeked, stream);
    copy_bidirectional(&mut client, &mut upstream)
        .await
        .map_err(SessionError::Transfer)?;
    Ok(Handling::Spliced { reason })
}

/// Serves accepted connections until cancellation and joins every child.
///
/// Admission is already bounded by the terminator's socket limit. Tracking and
/// cancelling children also closes their TLS and egress resources on shutdown.
pub async fn run_sessions(
    mut accepted: mpsc::Receiver<Accepted>,
    sessions: Arc<Sessions>,
    supervision: crate::Supervision,
) {
    let crate::Supervision { shutdown, panics } = supervision;
    let tracker = TaskTracker::new();
    loop {
        let next = tokio::select! {
            () = shutdown.cancelled() => break,
            next = accepted.recv() => next,
        };
        let Some(Accepted { terminated, stream }) = next else {
            break;
        };
        let server = std::net::SocketAddr::new(terminated.server.address, terminated.server.port);
        let sessions = Arc::clone(&sessions);
        let shutdown = shutdown.clone();
        // Contain one connection's panic and record it through supervision.
        tracker.spawn(panics.watch(async move {
            tokio::select! {
                () = shutdown.cancelled() => {}
                _ = serve_session(stream, server, sessions) => {}
            }
        }));
    }

    // Close admission before cancellation and wait for all children.
    tracker.close();
    shutdown.cancel();
    tracker.wait().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TLS ClientHello fields used by introduction tests.
    const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
    const EXTENSION_SERVER_NAME: u16 = 0x0000;
    const NAME_TYPE_HOST: u8 = 0x00;

    pub(super) fn client_hello(server_name: Option<&str>) -> Vec<u8> {
        let mut extensions = Vec::new();
        if let Some(name) = server_name {
            let mut entry = vec![NAME_TYPE_HOST];
            entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
            entry.extend_from_slice(name.as_bytes());

            let mut list = (entry.len() as u16).to_be_bytes().to_vec();
            list.extend_from_slice(&entry);

            extensions.extend_from_slice(&EXTENSION_SERVER_NAME.to_be_bytes());
            extensions.extend_from_slice(&(list.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&list);
        }
        // Keep a non-SNI extension ahead of the lookup path.
        extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // Legacy version.
        body.extend_from_slice(&[0x11; 32]); // Random.
        body.push(0); // Empty legacy session ID.
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // One cipher suite.
        body.extend_from_slice(&[0x01, 0x00]); // One compression method.
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);

        let mut record = vec![RECORD_HANDSHAKE, RECORD_MAJOR, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn a_client_hello_yields_its_server_name() {
        let hello = client_hello(Some("example.com"));
        assert_eq!(
            introduce(&hello),
            Introduction::Tls(Hello {
                host: Some(DomainName::new("example.com").unwrap()),
                profile: crate::ClientProfile::default(),
                alpn: crate::Offer::default(),
            })
        );
    }

    /// A partial ClientHello remains undecided.
    #[test]
    fn every_proper_prefix_of_a_client_hello_is_incomplete() {
        let hello = client_hello(Some("example.com"));
        for cut in 0..hello.len() {
            assert_eq!(
                introduce(&hello[..cut]),
                Introduction::Incomplete,
                "a {cut}-byte prefix decided"
            );
        }
    }

    /// TLS without SNI remains distinct from non-TLS input.
    #[test]
    fn tls_without_a_server_name_is_tls_with_no_host() {
        assert_eq!(
            introduce(&client_hello(None)),
            Introduction::Tls(Hello::default())
        );
    }

    /// Cleartext HTTP uses `Host` as its introduction name.
    #[test]
    fn cleartext_http_is_read_for_its_host() {
        assert_eq!(
            introduce(b"GET / HTTP/1.1\r\nHost: example.com:80\r\n\r\n"),
            Introduction::Http {
                host: Some(DomainName::new("example.com").unwrap())
            }
        );
        assert_eq!(
            introduce(b"GET / HTTP/1.1\r\n\r\n"),
            Introduction::Http { host: None }
        );
        // Authority parsing preserves bracketed IPv6 host syntax.
        for (head, expected) in [
            ("Host: 203.0.113.4", "203.0.113.4"),
            ("Host: [::1]:80", "[::1]"),
        ] {
            assert_eq!(
                introduce(format!("GET / HTTP/1.1\r\n{head}\r\n\r\n").as_bytes()),
                Introduction::Http {
                    host: Some(DomainName::new(expected).unwrap())
                }
            );
        }
        // An incomplete head cannot yet decide that no host exists.
        assert_eq!(
            introduce(b"GET / HTTP/1.1\r\nHost: exa"),
            Introduction::Incomplete
        );
    }

    #[test]
    fn what_is_neither_tls_nor_http_is_plain() {
        assert_eq!(introduce(b"\x00\x01\x02\x03\x04\x05"), Introduction::Plain);
        assert_eq!(
            introduce(b"SSH-2.0-OpenSSH_9.6 Ubuntu\r\n"),
            Introduction::Plain
        );
        // A TLS-like byte with a non-TLS record version is plain input.
        assert_eq!(
            introduce(&[0x16, 0x00, 0x01, 0x00, 0x05]),
            Introduction::Plain
        );
    }

    /// Corrupted input remains total and bounded.
    #[test]
    fn no_mutation_of_a_client_hello_escapes_the_sum() {
        let hello = client_hello(Some("example.com"));
        for index in 0..hello.len() {
            for patch in [0x00u8, 0x01, 0x7f, 0xff] {
                let mut corrupted = hello.clone();
                corrupted[index] = patch;
                // Every byte mutation must remain in the result sum.
                let _ = introduce(&corrupted);
            }
        }
        // A declared record larger than the buffer remains incomplete.
        assert_eq!(
            introduce(&[RECORD_HANDSHAKE, RECORD_MAJOR, 0x01, 0xff, 0xff, 0x01]),
            Introduction::Incomplete
        );
    }

    /// Invalid SNI names do not cross the `DomainName` boundary.
    #[test]
    fn a_hostile_server_name_is_refused_rather_than_admitted() {
        let long = "a".repeat(300);
        assert_eq!(
            introduce(&client_hello(Some(&long))),
            Introduction::Tls(Hello::default())
        );
        assert_eq!(
            introduce(&client_hello(Some("bad\0host"))),
            Introduction::Tls(Hello::default())
        );
    }
}

#[cfg(test)]
mod end_to_end {
    use super::*;
    use std::{
        net::{Ipv4Addr, SocketAddr},
        num::NonZeroUsize,
        sync::Arc,
    };

    use http_body_util::{BodyExt, Empty};
    use hyper_util::rt::TokioIo;
    use tokio::{
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream},
    };

    use crate::{
        AllowAll, AsyncStream, BoxFuture, CertificateAuthority, DatagramFidelity, Interceptor,
        MitmResolver, NatBehavior, PathProperties, Standing, bridge,
    };

    const ALLOWED: &str = "allowed.example";
    const OTHER: &str = "other.example";

    /// A CA and a leaf for `host`, as DER. The origin presents the leaf; the
    /// session's upstream leg is told to trust the CA, exactly as a deployment
    /// behind a private CA would be.
    fn origin_certificate(
        host: &str,
    ) -> (
        Vec<u8>,
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ) {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        // A distinct subject, because rcgen gives every certificate the same
        // default one — which would make the leaf's issuer equal to its own
        // subject and so indistinguishable from a self-signed certificate. The
        // old rustls upstream matched anchors by signature and did not care;
        // BoringSSL reports it as `DEPTH_ZERO_SELF_SIGNED_CERT`, and is right
        // to, so the fixture is what changes.
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "boreas test origin ca");
        let ca = ca_params.clone().self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);

        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec![host.to_owned()])
            .unwrap()
            .signed_by(&leaf_key, &issuer)
            .unwrap();

        (
            ca.der().to_vec(),
            vec![leaf.der().clone()],
            rustls::pki_types::PrivateKeyDer::try_from(leaf_key.serialize_der()).unwrap(),
        )
    }

    /// A real TLS origin answering `200 origin` to anything, on a real socket.
    async fn start_tls_origin(host: &str) -> (SocketAddr, Vec<u8>) {
        let (authority, chain, key) = origin_certificate(host);
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let service = hyper::service::service_fn(|_| async {
                        Ok::<_, std::convert::Infallible>(hyper::Response::new(
                            http_body_util::Full::new(bytes::Bytes::from_static(b"origin")),
                        ))
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                });
            }
        });
        (address, authority)
    }

    /// An origin that records the first bytes it is sent and echoes them, for
    /// proving a splice is byte-exact.
    /// An origin with no TLS at all, which is what a site that never got a
    /// certificate looks like. Answers every request with its own path.
    async fn start_cleartext_origin() -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(
                        |request: hyper::Request<hyper::body::Incoming>| async move {
                            let path = request.uri().path().to_owned();
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(
                                http_body_util::Full::new(bytes::Bytes::from(format!(
                                    "cleartext:{path}"
                                ))),
                            ))
                        },
                    );
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tcp), service)
                        .await;
                });
            }
        });
        address
    }

    async fn start_recording_origin() -> (SocketAddr, Arc<tokio::sync::Mutex<Vec<u8>>>) {
        let seen = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let recorded = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((mut tcp, _)) = listener.accept().await {
                let recorded = Arc::clone(&recorded);
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    while let Ok(read) = tcp.read(&mut buf).await {
                        if read == 0 {
                            break;
                        }
                        recorded.lock().await.extend_from_slice(&buf[..read]);
                        if tcp.write_all(&buf[..read]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        (address, seen)
    }

    /// An egress that dials one fixed address whatever it is asked for.
    ///
    /// It stands in for a configured proxy without needing one: what these
    /// tests exercise is the *assembly*, and a real egress is already verified
    /// against a reference server elsewhere.
    struct ToOrigin(SocketAddr);

    impl StreamEgress for ToOrigin {
        fn properties(&self) -> PathProperties {
            PathProperties {
                datagram_fidelity: DatagramFidelity::None,
                overhead_bytes: 0,
                max_datagram_size: None,
                preserves_ecn: false,
                nat_behavior: NatBehavior::EndpointIndependent,
            }
        }

        fn connect<'a>(
            &'a self,
            _target: &'a Target,
        ) -> BoxFuture<'a, Result<Box<dyn AsyncStream>, EgressError>> {
            Box::pin(async move {
                let stream = TcpStream::connect(self.0).await?;
                Ok(Box::new(stream) as Box<dyn AsyncStream>)
            })
        }
    }

    fn sessions_for(
        authority: Arc<CertificateAuthority>,
        allow: &[&str],
        origin: SocketAddr,
        upstream_roots: &[Vec<u8>],
    ) -> Arc<Sessions> {
        let resolver = Arc::new(MitmResolver::new(authority, NonZeroUsize::new(8).unwrap()));
        Arc::new(
            Sessions::new(
                Arc::new(Interceptor::new(resolver).unwrap()),
                Arc::new(InterceptPolicy::new(
                    allow.iter().map(|host| (*host).to_owned()),
                )),
                Arc::new(ToOrigin(origin)),
                Arc::new(AllowAll),
                SessionLimits::default(),
            )
            .unwrap()
            .with_upstream_roots(upstream_roots)
            .unwrap(),
        )
    }

    /// **The P14 through-line, in one test.** A real `rustls` client that trusts
    /// only the Boreas root speaks TLS to a connection this module classified
    /// from its SNI alone; the forged leaf validates, the request crosses an
    /// upstream TLS connection to a real origin, and the origin's body comes
    /// back. Nothing here is a stub except the egress's choice of address.
    #[tokio::test]
    async fn an_allowlisted_host_is_intercepted_end_to_end() {
        let (origin, origin_ca) = start_tls_origin(ALLOWED).await;
        let authority = Arc::new(CertificateAuthority::generate().unwrap());
        let root = authority.root_der().clone();
        let sessions = sessions_for(authority, &[ALLOWED], origin, &[origin_ca]);

        let (client_side, terminated) = bridge::duplex();
        let served = tokio::spawn(serve_session(terminated, origin, Arc::clone(&sessions)));

        // A client that trusts the Boreas root and nothing else, so a leaf this
        // process did not forge would fail here.
        let mut roots = rustls::RootCertStore::empty();
        roots.add(root).unwrap();
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        // **Chrome's own list, against an origin that speaks only http/1.1.**
        // The origin picks, so this is served over http/1.1 on both legs. Were
        // the client's preference what settled it, the upstream leg would offer
        // `h2` alone and the origin would refuse it outright.
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(
                rustls::pki_types::ServerName::try_from(ALLOWED).unwrap(),
                client_side,
            )
            .await
            .expect("the forged leaf validates against the Boreas root");
        assert_eq!(
            tls.get_ref().1.alpn_protocol(),
            Some(b"http/1.1".as_slice()),
            "the origin's choice is what the client is offered"
        );

        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(connection);
        let response = sender
            .send_request(
                hyper::Request::builder()
                    .uri("/")
                    .header(hyper::header::HOST, ALLOWED)
                    .body(Empty::<bytes::Bytes>::new())
                    .unwrap(),
            )
            .await
            .expect("the exchange reaches the origin");
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"origin", "the real origin answered");

        drop(sender);
        let handling = tokio::time::timeout(Duration::from_secs(5), served)
            .await
            .expect("the session finishes")
            .unwrap()
            .expect("the session succeeds");
        assert_eq!(
            handling,
            Handling::Intercepted {
                host: DomainName::new(ALLOWED).unwrap(),
                wire: Wire::Http1,
                tier: InterceptedTier::Rewrite,
            }
        );
        assert_eq!(
            sessions.crossings.count(),
            0,
            "no exchange may cross HTTP versions"
        );
    }

    /// A host that is not on the allowlist must reach the origin *unaltered*,
    /// ClientHello included. This is the fail-open default, and the assertion is
    /// on the bytes rather than on the decision, because a splice that rewrote
    /// anything would still report itself as a splice.
    #[tokio::test]
    async fn an_unlisted_host_is_spliced_byte_for_byte() {
        let (origin, seen) = start_recording_origin().await;
        let authority = Arc::new(CertificateAuthority::generate().unwrap());
        let sessions = sessions_for(authority, &[ALLOWED], origin, &[]);

        let (mut client_side, terminated) = bridge::duplex();
        let served = tokio::spawn(serve_session(terminated, origin, Arc::clone(&sessions)));

        let hello = super::tests::client_hello(Some(OTHER));
        client_side.write_all(&hello).await.unwrap();
        client_side.flush().await.unwrap();

        let mut echoed = vec![0u8; hello.len()];
        tokio::time::timeout(
            Duration::from_secs(5),
            tokio::io::AsyncReadExt::read_exact(&mut client_side, &mut echoed),
        )
        .await
        .expect("the origin answers")
        .unwrap();
        assert_eq!(echoed, hello, "the splice altered the client's bytes");
        assert_eq!(
            *seen.lock().await,
            hello,
            "the origin received exactly what the client sent"
        );

        drop(client_side);
        let handling = tokio::time::timeout(Duration::from_secs(5), served)
            .await
            .expect("the session finishes")
            .unwrap()
            .expect("the session succeeds");
        assert_eq!(
            handling,
            Handling::Spliced {
                reason: SpliceReason::NotAllowlisted
            }
        );
    }

    /// **A site with no HTTPS is still filtered.** Port 80 is inspected for the
    /// redirects that lead to 443, but a host that never got a certificate
    /// serves its content there, and it used to pass through untouched for want
    /// of an SNI to read. `Host` is what names it, and neither leg handshakes.
    #[tokio::test]
    async fn a_cleartext_host_is_intercepted_through_its_host_header() {
        let origin = start_cleartext_origin().await;
        let authority = Arc::new(CertificateAuthority::generate().unwrap());
        let sessions = sessions_for(authority, &[ALLOWED], origin, &[]);

        let (client_side, terminated) = bridge::duplex();
        let served = tokio::spawn(serve_session(terminated, origin, Arc::clone(&sessions)));

        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(client_side))
                .await
                .unwrap();
        tokio::spawn(connection);
        let response = sender
            .send_request(
                hyper::Request::builder()
                    .uri("/page")
                    .header(hyper::header::HOST, ALLOWED)
                    .body(Empty::<bytes::Bytes>::new())
                    .unwrap(),
            )
            .await
            .expect("the exchange reaches the origin");
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"cleartext:/page", "the real origin answered");

        drop(sender);
        let handling = tokio::time::timeout(Duration::from_secs(5), served)
            .await
            .expect("the session finishes")
            .unwrap()
            .expect("the session succeeds");
        assert_eq!(
            handling,
            Handling::Intercepted {
                host: DomainName::new(ALLOWED).unwrap(),
                wire: Wire::Http1,
                tier: InterceptedTier::TOP,
            }
        );
    }

    /// **The P15 through-line.** A client that does not trust the Boreas root —
    /// a pinned app, or any client the user did not install the root into —
    /// rejects the forged leaf. That connection is lost and cannot be
    /// otherwise: the leaf has been sent by the time the alert arrives, which
    /// is the one failure the upstream-first order does not recover. What P15
    /// buys is the next connection, which
    /// [`a_demoted_host_splices_the_next_connection_byte_for_byte`] covers.
    ///
    /// The origin here is a real TLS server because the upstream handshake now
    /// runs first: reaching the client's leg at all means the origin's leg
    /// already succeeded.
    #[tokio::test]
    async fn a_client_that_refuses_the_forged_leaf_demotes_the_host() {
        let (origin, origin_ca) = start_tls_origin(ALLOWED).await;
        let authority = Arc::new(CertificateAuthority::generate().unwrap());
        let sessions = sessions_for(authority, &[ALLOWED], origin, &[origin_ca]);

        // A client trusting only an unrelated root, which is what a pinned
        // client looks like from here.
        let (unrelated, ..) = origin_certificate("elsewhere.example");
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(unrelated))
            .unwrap();
        let config = Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
        );

        let (client_side, terminated) = bridge::duplex();
        let served = tokio::spawn(serve_session(terminated, origin, Arc::clone(&sessions)));
        let refused = tokio_rustls::TlsConnector::from(Arc::clone(&config))
            .connect(
                rustls::pki_types::ServerName::try_from(ALLOWED).unwrap(),
                client_side,
            )
            .await;
        assert!(refused.is_err(), "the client must reject an unknown root");

        let handling = tokio::time::timeout(Duration::from_secs(5), served)
            .await
            .expect("the session finishes")
            .unwrap()
            .expect("a refusal is a handling, not a failure of the session");
        assert_eq!(
            handling,
            Handling::Demoted {
                host: DomainName::new(ALLOWED).unwrap(),
                cause: Demotion::LeafRejected,
            }
        );
        assert_eq!(
            sessions
                .demotions
                .standing(ALLOWED, Instant::now())
                .permits(),
            Err(Demotion::LeafRejected),
            "the host must stop being intercepted, and say why"
        );
    }

    /// **What the demotion buys, which is the gate P15 measures.** An
    /// allowlisted host whose standing has fallen to splice passes through
    /// untouched, so the client speaks to the origin itself and the pin it was
    /// protecting is never challenged again. Asserted on the bytes that reach
    /// the origin rather than on the decision.
    #[tokio::test]
    async fn a_demoted_host_splices_the_next_connection_byte_for_byte() {
        let (origin, seen) = start_recording_origin().await;
        let authority = Arc::new(CertificateAuthority::generate().unwrap());
        let sessions = sessions_for(authority, &[ALLOWED], origin, &[]);
        sessions
            .demotions
            .record(ALLOWED, Demotion::LeafRejected, Instant::now());

        let (mut client_side, terminated) = bridge::duplex();
        let served = tokio::spawn(serve_session(terminated, origin, Arc::clone(&sessions)));
        let hello = super::tests::client_hello(Some(ALLOWED));
        client_side.write_all(&hello).await.unwrap();

        let mut echoed = vec![0u8; hello.len()];
        tokio::time::timeout(
            Duration::from_secs(5),
            tokio::io::AsyncReadExt::read_exact(&mut client_side, &mut echoed),
        )
        .await
        .expect("the origin answers")
        .unwrap();
        assert_eq!(
            echoed, hello,
            "the demoted splice altered the client's bytes"
        );
        assert_eq!(*seen.lock().await, hello);

        drop(client_side);
        let handling = tokio::time::timeout(Duration::from_secs(5), served)
            .await
            .expect("the session finishes")
            .unwrap()
            .expect("the session succeeds");
        assert_eq!(
            handling,
            Handling::Spliced {
                reason: SpliceReason::Demoted(Demotion::LeafRejected),
            }
        );
    }

    /// Transport trouble must not demote, or a bad minute of network would
    /// disable filtering for half a day. A client that opens a TLS record and
    /// vanishes is exactly that case.
    #[tokio::test]
    async fn a_client_that_vanishes_mid_handshake_proves_nothing() {
        let (origin, _) = start_recording_origin().await;
        let authority = Arc::new(CertificateAuthority::generate().unwrap());
        let sessions = sessions_for(authority, &[ALLOWED], origin, &[]);

        let (mut client_side, terminated) = bridge::duplex();
        let served = tokio::spawn(serve_session(terminated, origin, Arc::clone(&sessions)));
        client_side
            .write_all(&super::tests::client_hello(Some(ALLOWED)))
            .await
            .unwrap();
        drop(client_side);

        let outcome = tokio::time::timeout(Duration::from_secs(5), served)
            .await
            .expect("the session finishes")
            .unwrap();
        assert!(
            outcome.is_err(),
            "a dead connection is an error, not a lesson"
        );
        assert_eq!(
            sessions.demotions.standing(ALLOWED, Instant::now()),
            Standing::Unrestricted,
            "nothing may be recorded against the host"
        );
    }

    /// A cleartext request naming no host is spliced, and says why: `Host` is
    /// what the allowlist reads on this path, and a head without one is the
    /// same non-decision a hello without an SNI is.
    #[tokio::test]
    async fn cleartext_without_a_host_is_spliced_with_its_reason() {
        let (origin, seen) = start_recording_origin().await;
        let authority = Arc::new(CertificateAuthority::generate().unwrap());
        let sessions = sessions_for(authority, &[ALLOWED], origin, &[]);

        let (mut client_side, terminated) = bridge::duplex();
        let served = tokio::spawn(serve_session(terminated, origin, Arc::clone(&sessions)));

        client_side
            .write_all(b"GET / HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut echoed = vec![0u8; 18];
        tokio::time::timeout(
            Duration::from_secs(5),
            tokio::io::AsyncReadExt::read_exact(&mut client_side, &mut echoed),
        )
        .await
        .expect("the origin answers")
        .unwrap();
        assert_eq!(&echoed, b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(*seen.lock().await, b"GET / HTTP/1.1\r\n\r\n".to_vec());

        drop(client_side);
        let handling = tokio::time::timeout(Duration::from_secs(5), served)
            .await
            .expect("the session finishes")
            .unwrap()
            .expect("the session succeeds");
        assert_eq!(
            handling,
            Handling::Spliced {
                reason: SpliceReason::Unnamed
            }
        );
    }
}
