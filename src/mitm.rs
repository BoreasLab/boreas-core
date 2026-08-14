//! P14 interception: terminate the client's TLS with a forged leaf, and record
//! the two invariants the milestone gate is written against.
//!
//! This is deliberately narrow, exactly as [Delivery](../docs/delivery.md)
//! scopes P14: an **explicit, manually maintained allowlist**, and h1/h2 only.
//! A host not on the allowlist is spliced byte-for-byte — the fail-open default
//! [Filtering](../docs/filtering.md) mandates — and only an allowlisted host is
//! handed to the terminating TLS server built here.
//!
//! Two properties are load-bearing enough to be types rather than comments:
//!
//! - **The application protocol is chosen by ALPN, never bridged.** Boreas
//!   terminates h1 as h1 and h2 as h2; it never translates a live exchange from
//!   one version to another. [`VersionCrossings`] counts any exchange whose
//!   client and upstream protocols differ, and the P14 gate is that the count
//!   stays zero. Modelling the protocol as a closed [`Wire`] sum keeps "which
//!   versions exist" in one place the counter and the ALPN offer both read.
//! - **h3 is never terminated.** A locally added root cannot validate over
//!   QUIC, so h3 is pass-through and the ALPN offer omits it. There is no h3
//!   variant to bridge to, which is why [`Wire`] has two members and not three.

use std::{
    collections::HashSet,
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use rustls::{ServerConfig, crypto::ring::default_provider};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

use crate::MitmResolver;

/// The application protocol negotiated on a terminated connection. Closed at
/// two: h1 and h2 are the only versions Boreas terminates, because h3 rides
/// QUIC where a user-added root cannot validate and is therefore passed through
/// rather than intercepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wire {
    Http1,
    Http2,
}

impl Wire {
    /// The wire the ALPN identifier names, or `Http1` as the RFC 7301 default
    /// when a peer offers no ALPN at all — which is what a bare HTTP/1.1 client
    /// does.
    fn from_alpn(selected: Option<&[u8]>) -> Self {
        match selected {
            Some(b"h2") => Self::Http2,
            _ => Self::Http1,
        }
    }
}

/// Whether a host is intercepted or spliced. A closed sum so the caller cannot
/// forget the fail-open branch: there is no third "maybe" state, and splice is
/// the answer for everything not explicitly admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterceptDecision {
    Intercept,
    Splice,
}

/// The explicit interception allowlist. P14 keeps it exact-match and
/// hand-maintained on purpose: automatic broadening waits for P15's demotion
/// machinery, so until then every intercepted host is one a human named.
///
/// Membership is an $O(1)$ hash probe on a `HashSet`, whose SipHash resists the
/// collision flooding an attacker-chosen SNI could otherwise attempt.
#[derive(Clone, Debug, Default)]
pub struct InterceptPolicy {
    allow: HashSet<String>,
}

impl InterceptPolicy {
    /// Builds a policy from an explicit host list. Hosts are lower-cased so the
    /// decision matches a `ClientHello` SNI, which is case-insensitive.
    pub fn new(hosts: impl IntoIterator<Item = String>) -> Self {
        Self {
            allow: hosts
                .into_iter()
                .map(|host| host.to_ascii_lowercase())
                .collect(),
        }
    }

    /// Intercept only an exactly allowlisted host; splice everything else.
    ///
    /// **No allocation on the deciding path.** Every host reaching here came
    /// through [`DomainName`](crate::DomainName), which lower-cases at
    /// construction, so the borrowed name is already the key — and a
    /// `HashSet<String>` probes on `&str` directly. The owned copy is the
    /// fallback for a caller that has not normalized, which is a test and not
    /// a connection.
    pub fn decide(&self, host: &str) -> InterceptDecision {
        let found = if host.bytes().any(|byte| byte.is_ascii_uppercase()) {
            self.allow.contains(&host.to_ascii_lowercase())
        } else {
            self.allow.contains(host)
        };
        if found {
            InterceptDecision::Intercept
        } else {
            InterceptDecision::Splice
        }
    }

    pub fn len(&self) -> usize {
        self.allow.len()
    }

    pub fn is_empty(&self) -> bool {
        self.allow.is_empty()
    }
}

/// Counts exchanges whose client-facing and upstream protocols differ.
///
/// The P14 gate is that this stays zero: Boreas serves the version it received
/// and never bridges one to another, so a non-zero count is a bug in the
/// exchange, not a workload property. A monotone counter under relaxed ordering
/// is enough — it is read for a gate, not to synchronize anything.
#[derive(Debug, Default)]
pub struct VersionCrossings(AtomicU64);

impl VersionCrossings {
    pub fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    /// Records one completed exchange, returning whether it crossed versions.
    /// A crossing increments the counter; a same-version exchange does not.
    pub fn record(&self, client: Wire, upstream: Wire) -> bool {
        let crossed = client != upstream;
        if crossed {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        crossed
    }

    /// Total crossings observed. The gate asserts this is zero.
    pub fn count(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// The terminating TLS server: a rustls `ServerConfig` that presents a forged
/// leaf for whatever SNI a client offers, negotiating h2 by preference and
/// falling back to http/1.1 — the two wires [`Wire`] admits, and no h3.
#[derive(Clone)]
pub struct Interceptor {
    acceptor: TlsAcceptor,
}

impl Interceptor {
    /// Builds the server from a certificate resolver. The `ring` provider is
    /// named explicitly rather than taken from a process-global default, so
    /// this composes without a `CryptoProvider::install_default` side effect —
    /// and it is the one provider already in the graph for WireGuard and the
    /// DNS upstreams, so no second crypto stack ships.
    pub fn new(resolver: Arc<MitmResolver>) -> Result<Self, rustls::Error> {
        let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        // Preference order: h2 first, http/1.1 second. h3 is absent by
        // construction — the reason [`Wire`] has no third member.
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
        })
    }

    /// Terminates one client connection: completes the TLS handshake over
    /// `stream` and reports the wire ALPN settled on, which the exchange must
    /// mirror upstream so no version is crossed.
    pub async fn terminate<S>(&self, stream: S) -> io::Result<(TlsStream<S>, Wire)>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let tls = self.acceptor.accept(stream).await?;
        let wire = Wire::from_alpn(tls.get_ref().1.alpn_protocol());
        Ok((tls, wire))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroUsize;

    use rustls::{
        ClientConfig, RootCertStore, crypto::ring::default_provider, pki_types::ServerName,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::TlsConnector;

    use crate::CertificateAuthority;

    #[test]
    fn the_allowlist_intercepts_only_named_hosts_and_is_case_insensitive() {
        let policy = InterceptPolicy::new(["Example.com".to_owned()]);
        assert_eq!(policy.decide("example.com"), InterceptDecision::Intercept);
        assert_eq!(policy.decide("EXAMPLE.COM"), InterceptDecision::Intercept);
        // Fail open: anything not named is spliced, never intercepted.
        assert_eq!(policy.decide("evil.example"), InterceptDecision::Splice);
        assert_eq!(policy.decide("example.com.evil"), InterceptDecision::Splice);
    }

    #[test]
    fn the_crossing_counter_ignores_same_version_and_counts_a_bridge() {
        let crossings = VersionCrossings::new();
        assert!(!crossings.record(Wire::Http2, Wire::Http2));
        assert!(!crossings.record(Wire::Http1, Wire::Http1));
        assert_eq!(crossings.count(), 0, "the gate: same-version stays zero");
        // A bridged exchange — which the design never produces — would show up.
        assert!(crossings.record(Wire::Http1, Wire::Http2));
        assert_eq!(crossings.count(), 1);
    }

    /// The in-process P14 gate: a client that trusts the Boreas root completes a
    /// TLS handshake to an arbitrary host through the interceptor, validates the
    /// forged leaf for that exact name, negotiates h2, and exchanges plaintext
    /// the server decrypts. This is the whole CA-to-resolver-to-server chain,
    /// proven without a device.
    #[tokio::test]
    async fn a_trusting_client_validates_the_forged_leaf_and_exchanges_bytes() {
        let authority = Arc::new(CertificateAuthority::generate().unwrap());
        let root_der = authority.root_der().clone();
        let resolver = Arc::new(MitmResolver::new(
            Arc::clone(&authority),
            NonZeroUsize::new(64).unwrap(),
        ));
        let interceptor = Interceptor::new(resolver).unwrap();

        // A client that trusts the root and asks for a host it has never seen a
        // real certificate for.
        let mut roots = RootCertStore::empty();
        roots.add(root_der).unwrap();
        let mut client_config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(client_config));
        let server_name = ServerName::try_from("intercepted.example").unwrap();

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);

        let server = tokio::spawn(async move {
            let (mut tls, wire) = interceptor
                .terminate(server_io)
                .await
                .expect("server handshake");
            assert_eq!(wire, Wire::Http2, "h2 is the preferred wire");
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf)
                .await
                .expect("server reads plaintext");
            assert_eq!(&buf, b"hello");
            tls.write_all(b"world").await.expect("server writes");
            tls.flush().await.unwrap();
        });

        let mut tls = connector
            .connect(server_name, client_io)
            .await
            .expect("client handshake validates the forged leaf against the root");
        // The forged leaf validated for the requested SNI, or `connect` above
        // would have failed. Now application bytes cross end to end.
        tls.write_all(b"hello").await.unwrap();
        tls.flush().await.unwrap();
        let mut buf = [0u8; 5];
        tls.read_exact(&mut buf).await.expect("client reads reply");
        assert_eq!(&buf, b"world");

        server.await.unwrap();
    }
}
