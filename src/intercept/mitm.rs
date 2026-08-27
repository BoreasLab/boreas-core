//! P14 TLS interception with a forged leaf.
//!
//! P14 permits only an explicit allowlist and h1/h2. Other hosts are spliced
//! byte-for-byte, as [Filtering](../docs/filtering.md) requires. h3 remains
//! pass-through because a user-installed root cannot validate QUIC traffic.
//!
//! ALPN chooses the wire, and the interceptor advertises only the origin's
//! choice. [`VersionCrossings`] counts any client/upstream mismatch; the P14
//! gate requires zero crossings. The closed [`Wire`] sum excludes h3.

use std::{
    collections::HashSet,
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use rustls::{ServerConfig, crypto::ring::default_provider, server::ResolvesServerCert};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

use crate::MitmResolver;

/// The application protocol negotiated on a terminated connection.
///
/// Only h1 and h2 are terminated. h3 rides QUIC and remains pass-through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wire {
    Http1,
    Http2,
}

impl Wire {
    /// Both wires, in server preference order.
    pub const ALL: [Self; 2] = [Self::Http2, Self::Http1];

    /// The ALPN identifier for this wire.
    #[must_use]
    pub const fn identifier(self) -> &'static [u8] {
        match self {
            Self::Http1 => b"http/1.1",
            Self::Http2 => b"h2",
        }
    }

    /// Returns the wire named by an ALPN identifier, or `None` for unsupported
    /// protocols such as `h3`.
    #[must_use]
    pub fn from_identifier(name: &[u8]) -> Option<Self> {
        Self::ALL.into_iter().find(|wire| wire.identifier() == name)
    }

    /// Returns the negotiated wire, defaulting to `Http1` when ALPN is absent.
    #[must_use]
    pub fn from_alpn(selected: Option<&[u8]>) -> Self {
        selected
            .and_then(Self::from_identifier)
            .unwrap_or(Self::Http1)
    }
}

/// Whether a host is intercepted or spliced.
///
/// Splicing is the fail-open result for every host outside the allowlist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterceptDecision {
    Intercept,
    Splice,
}

/// The explicit, exact-match interception allowlist.
///
/// P14 keeps it human-maintained; automatic broadening belongs to P15's
/// demotion machinery.
///
/// Membership is an $O(1)$ hash probe. `HashSet`'s SipHash resists collision
/// flooding from attacker-controlled SNI values.
#[derive(Clone, Debug, Default)]
pub struct InterceptPolicy {
    allow: HashSet<String>,
}

impl InterceptPolicy {
    /// Builds an exact-match policy, lower-casing hosts for case-insensitive SNI.
    pub fn new(hosts: impl IntoIterator<Item = String>) -> Self {
        Self {
            allow: hosts
                .into_iter()
                .map(|host| host.to_ascii_lowercase())
                .collect(),
        }
    }

    /// Intercepts exactly allowlisted hosts and splices everything else.
    ///
    /// Normalized [`DomainName`](crate::DomainName) values probe the set without
    /// allocation. Uppercase inputs use a temporary lowercase copy.
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

/// Counts exchanges whose client and upstream protocols differ.
///
/// The P14 gate requires zero crossings. Relaxed ordering is sufficient because
/// this counter reports a gate result and does not synchronize other state.
#[derive(Debug, Default)]
pub struct VersionCrossings(AtomicU64);

impl VersionCrossings {
    pub fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    /// Records an exchange and returns whether its wires differ.
    pub fn record(&self, client: Wire, upstream: Wire) -> bool {
        let crossed = client != upstream;
        if crossed {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
        crossed
    }

    /// Returns the total crossings observed.
    pub fn count(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// A terminating TLS server that presents a forged leaf for the client's SNI.
///
/// The origin settles the session wire, so the caller selects one acceptor and
/// the server advertises only that protocol. Both acceptors are built once.
///
/// A client that offers no ALPN still negotiates none; RFC 7301 forbids the
/// server from selecting a protocol the client did not offer.
#[derive(Clone)]
pub struct Interceptor {
    acceptors: [TlsAcceptor; Wire::ALL.len()],
}

impl Interceptor {
    /// Builds both wire-specific acceptors from a certificate resolver.
    ///
    /// The `ring` provider is explicit, avoiding process-global installation
    /// and reusing the provider already used by WireGuard and DNS upstreams.
    pub fn new(resolver: Arc<MitmResolver>) -> Result<Self, rustls::Error> {
        let resolver: Arc<dyn ResolvesServerCert> = resolver;
        let build = |wire: Wire| -> Result<TlsAcceptor, rustls::Error> {
            let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_cert_resolver(Arc::clone(&resolver));
            config.alpn_protocols = vec![wire.identifier().to_vec()];
            Ok(TlsAcceptor::from(Arc::new(config)))
        };
        Ok(Self {
            acceptors: [build(Wire::ALL[0])?, build(Wire::ALL[1])?],
        })
    }

    /// Terminates one client connection, advertising only `wire`.
    pub async fn terminate<S>(&self, stream: S, wire: Wire) -> io::Result<TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let index = Wire::ALL
            .iter()
            .position(|candidate| *candidate == wire)
            .expect("Wire::ALL is every wire");
        // Bound the handshake after the initial client-byte peek.
        crate::within(
            crate::Wait::ClientHandshake,
            self.acceptors[index].accept(stream),
        )
        .await
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
        // Anything not named is spliced, never intercepted.
        assert_eq!(policy.decide("evil.example"), InterceptDecision::Splice);
        assert_eq!(policy.decide("example.com.evil"), InterceptDecision::Splice);
    }

    #[test]
    fn the_crossing_counter_ignores_same_version_and_counts_a_bridge() {
        let crossings = VersionCrossings::new();
        assert!(!crossings.record(Wire::Http2, Wire::Http2));
        assert!(!crossings.record(Wire::Http1, Wire::Http1));
        assert_eq!(crossings.count(), 0, "the gate: same-version stays zero");
        // A bridged exchange would increment the gate counter.
        assert!(crossings.record(Wire::Http1, Wire::Http2));
        assert_eq!(crossings.count(), 1);
    }

    /// Verifies root trust, forged-leaf validation for SNI, h2 negotiation, and
    /// plaintext exchange through the interceptor.
    #[tokio::test]
    async fn a_trusting_client_validates_the_forged_leaf_and_exchanges_bytes() {
        let authority = Arc::new(CertificateAuthority::generate().unwrap());
        let root_der = authority.root_der().clone();
        let resolver = Arc::new(MitmResolver::new(
            Arc::clone(&authority),
            NonZeroUsize::new(64).unwrap(),
        ));
        let interceptor = Interceptor::new(resolver).unwrap();

        // The client trusts the Boreas root for an otherwise unknown host.
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
            let mut tls = interceptor
                .terminate(server_io, Wire::Http2)
                .await
                .expect("server handshake");
            assert_eq!(
                tls.get_ref().1.alpn_protocol(),
                Some(b"h2".as_slice()),
                "the advertised wire is the negotiated one"
            );
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
        // Successful connect proves the forged leaf matches the requested SNI.
        tls.write_all(b"hello").await.unwrap();
        tls.flush().await.unwrap();
        let mut buf = [0u8; 5];
        tls.read_exact(&mut buf).await.expect("client reads reply");
        assert_eq!(&buf, b"world");

        server.await.unwrap();
    }
}
