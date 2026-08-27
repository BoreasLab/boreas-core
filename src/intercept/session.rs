//! Session assembly for protocol recognition, interception, and splicing.
//!
//! TLS SNI or cleartext HTTP `Host` names the client. Only a named allowlisted
//! host is intercepted; every other result is spliced with a reason.
//!
//! The origin selects ALPN before local termination, keeping both legs on one
//! wire version. Version crossings remain an acceptance check.

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

const RECORD_HANDSHAKE: u8 = 0x16;
const RECORD_MAJOR: u8 = 0x03;

const MAX_RECORD: usize = (1 << 14) + 5;

const MAX_REQUEST_HEADERS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Introduction {
    Incomplete,
    Tls(Hello),
    Http { host: Option<DomainName> },
    Plain,
}

enum Approach {
    Tls {
        profile: crate::ClientProfile,
        alpn: crate::Offer,
    },
    Cleartext,
}

pub fn introduce(bytes: &[u8]) -> Introduction {
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

fn host_field(fields: &[httparse::Header<'_>]) -> Option<DomainName> {
    let value = fields
        .iter()
        .find(|field| field.name.eq_ignore_ascii_case("host"))?
        .value;
    let authority: http::uri::Authority = std::str::from_utf8(value).ok()?.parse().ok()?;
    DomainName::new(authority.host()).ok()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpliceReason {
    NotAllowlisted,
    Unnamed,
    NotTls,
    Undecided,
    Demoted(Demotion),
    OriginHandshake,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Handling {
    Intercepted {
        host: DomainName,
        wire: Wire,
        tier: InterceptedTier,
    },
    Spliced {
        reason: SpliceReason,
    },
    Demoted {
        host: DomainName,
        cause: Demotion,
    },
}

#[derive(Debug)]
pub enum SessionError {
    Upstream(EgressError),
    ClientHandshake(std::io::Error),
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

#[derive(Clone, Copy, Debug)]
pub struct SessionLimits {
    pub peek_timeout: Duration,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            // Bound silent connections while allowing slow first packets.
            peek_timeout: Duration::from_secs(5),
        }
    }
}

pub struct Sessions {
    pub interceptor: Arc<Interceptor>,
    pub policy: Arc<InterceptPolicy>,
    pub egress: Arc<dyn StreamEgress>,
    pub filter: Arc<dyn RequestFilter>,
    pub crossings: Arc<VersionCrossings>,
    pub demotions: Arc<Demotions>,
    pub limits: SessionLimits,
    cosmetic: Arc<dyn CosmeticSource>,
    budget: StreamBudget,
    /// BoringSSL origin connector, shared for profile and trust-anchor caches.
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

    pub fn with_upstream_roots(mut self, extra_roots: &[Vec<u8>]) -> Result<Self, EgressError> {
        self.originator = Arc::new(Originator::new().with_extra_roots(extra_roots));
        Ok(self)
    }

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
    // Policy selects candidates; standing records whether interception is allowed.
    let tier = match sessions
        .demotions
        .standing(host.as_str(), Instant::now())
        .permits()
    {
        Ok(tier) => tier,
        // A recorded demotion is the only standing that blocks interception.
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
    // Bound the full proxy dial, including an egress that accepts then stalls.
    let transport = crate::within(crate::Wait::ProxyDial, sessions.egress.connect(&target))
        .await
        .map_err(SessionError::Upstream)?;

    // Both modes produce two streams on one wire version.
    let (client, upstream, wire) = match approach {
        // Select ALPN at the origin before sending the forged leaf. Origin
        // failure can then still fall back to a splice.
        Approach::Tls { profile, alpn } => {
            // Mirror the client profile on the origin-facing handshake.
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
        // Cleartext has no handshake and uses HTTP/1.x.
        Approach::Cleartext => (
            Either::Right(Prefixed::new(peeked, stream)),
            Either::Right(transport),
            Wire::Http1,
        ),
    };

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
    // Record rewrite exhaustion after the exchange ends.
    if failures.count() > 0 {
        sessions
            .demotions
            .record(host.as_str(), Demotion::RewriteExhausted, Instant::now());
    }
    Ok(Handling::Intercepted { host, wire, tier })
}

/// Records a demotion when a failed handshake proves a repeatable cause.
///
/// The current connection is lost in either case. Only a classified failure
/// predicts the next connection; resets, timeouts, and vanished peers do not.
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

/// Returns the bytes needed to replay the stream for splicing or termination.
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
            // The bound prevents indefinite waiting for incomplete input.
            Introduction::Incomplete => return (Introduction::Incomplete, buf, stream),
            conclusive => return (conclusive, buf, stream),
        }
        let read = match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => return (introduce(&buf), buf, stream),
            Ok(Ok(read)) => read,
            Ok(Err(_)) => return (introduce(&buf), buf, stream),
        };
        buf.extend_from_slice(&chunk[..read]);
    }
}

/// The original address preserves the client's DNS choice; resolving the host
/// again could select a different destination.
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

/// The terminator bounds admission; tracking children closes their TLS and
/// egress resources during shutdown.
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
        // Contain and record a panic from one connection.
        tracker.spawn(panics.watch(async move {
            tokio::select! {
                () = shutdown.cancelled() => {}
                _ = serve_session(stream, server, sessions) => {}
            }
        }));
    }

    // Stop admission, cancel children, and wait for them all.
    tracker.close();
    shutdown.cancel();
    tracker.wait().await;
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // Put a non-SNI extension before the server-name extension.
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

    #[test]
    fn tls_without_a_server_name_is_tls_with_no_host() {
        assert_eq!(
            introduce(&client_hello(None)),
            Introduction::Tls(Hello::default())
        );
    }

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
        // Authority parsing retains bracketed IPv6 host syntax.
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
        // An incomplete head cannot yet establish that no host exists.
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
        // A TLS-like type with a non-TLS version is plain input.
        assert_eq!(
            introduce(&[0x16, 0x00, 0x01, 0x00, 0x05]),
            Introduction::Plain
        );
    }

    #[test]
    fn no_mutation_of_a_client_hello_escapes_the_sum() {
        let hello = client_hello(Some("example.com"));
        for index in 0..hello.len() {
            for patch in [0x00u8, 0x01, 0x7f, 0xff] {
                let mut corrupted = hello.clone();
                corrupted[index] = patch;
                // Every mutation must remain representable by the result sum.
                let _ = introduce(&corrupted);
            }
        }
        // A record larger than the available bytes remains incomplete.
        assert_eq!(
            introduce(&[RECORD_HANDSHAKE, RECORD_MAJOR, 0x01, 0xff, 0xff, 0x01]),
            Introduction::Incomplete
        );
    }

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
        // Give the CA a distinct subject. rcgen otherwise gives both
        // certificates the same default subject, while BoringSSL correctly
        // reports that chain as `DEPTH_ZERO_SELF_SIGNED_CERT`.
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

    /// It exercises session assembly without requiring a configured proxy; real
    /// egress implementations are tested against a reference server elsewhere.
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

    /// Exercises real client, upstream, and origin connections; only the egress
    /// address is fixed by the fixture.
    #[tokio::test]
    async fn an_allowlisted_host_is_intercepted_end_to_end() {
        let (origin, origin_ca) = start_tls_origin(ALLOWED).await;
        let authority = Arc::new(CertificateAuthority::generate().unwrap());
        let root = authority.root_der().clone();
        let sessions = sessions_for(authority, &[ALLOWED], origin, &[origin_ca]);

        let (client_side, terminated) = bridge::duplex();
        let served = tokio::spawn(serve_session(terminated, origin, Arc::clone(&sessions)));

        // Trust only the Boreas root; an unforgeable leaf would fail here.
        let mut roots = rustls::RootCertStore::empty();
        roots.add(root).unwrap();
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        // Offer Chrome's order to an origin that speaks only HTTP/1.1. The
        // origin chooses, so both legs use HTTP/1.1.
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

    /// Assert byte-for-byte forwarding because a rewriting splice could still
    /// report `Spliced`.
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

    /// Neither leg has a TLS handshake, so the connection remains HTTP/1.1.
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

    /// Origin handshake runs first; a leaf rejection demotes the next
    /// connection to a byte-exact splice.
    #[tokio::test]
    async fn a_client_that_refuses_the_forged_leaf_demotes_the_host() {
        let (origin, origin_ca) = start_tls_origin(ALLOWED).await;
        let authority = Arc::new(CertificateAuthority::generate().unwrap());
        let sessions = sessions_for(authority, &[ALLOWED], origin, &[origin_ca]);

        // Trust only an unrelated root, as a pinned client would.
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

    /// The next connection remains byte-exact and does not challenge the pin
    /// again.
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

    /// Transport trouble does not demote a host. A client that starts TLS and
    /// vanishes provides no repeatable certificate evidence.
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
