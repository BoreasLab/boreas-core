//! P14 certificate authority: the root Boreas installs in the user store, and
//! the per-host leaves it mints on demand to terminate TLS.
//!
//! The design follows the one interception proxies have converged on. A single
//! long-lived **leaf key** is generated once; every host gets its own
//! *certificate* over that same key, signed by the root. Minting a host is then
//! one signature, not a key generation — the expensive half of a certificate —
//! so a browser opening a page of thirty origins pays thirty signatures against
//! a warm cache rather than thirty P-256 keygens.
//!
//! **The root never leaves this process except as `root_der`.** That DER is
//! what the platform layer installs into the Android or Windows user store, and
//! it is deliberately the *only* way the private half is reachable: the signing
//! key lives behind [`CertificateAuthority`] and mints leaves, nothing more.
//!
//! **A missing certificate is a fail-open signal, not an error to surface.**
//! [`MitmResolver::resolve`] returns `None` when it cannot forge a leaf — no
//! SNI to name a host, or a signing failure — and rustls answers `None` by
//! failing the handshake, which the exchange layer reads as "demote this host
//! to splice." Interception is optional; connectivity is not.

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, date_time_ymd,
};
use rustls::{
    crypto::ring::sign::any_supported_type,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::{CertifiedKey, SigningKey},
};

/// What went wrong provisioning a certificate. All three are construction-time
/// or per-leaf defects rather than routine outcomes: the routine "cannot forge
/// a leaf" case is an `Option::None` at the resolver, not one of these.
#[derive(Debug)]
pub enum CaError {
    /// A key pair could not be generated.
    KeyGeneration(rcgen::Error),
    /// The root or a leaf certificate could not be signed.
    Signing(rcgen::Error),
    /// rustls could not load the leaf key into a signer.
    KeyLoading(rustls::Error),
}

impl fmt::Display for CaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyGeneration(error) => write!(f, "could not generate a key pair: {error}"),
            Self::Signing(error) => write!(f, "could not sign a certificate: {error}"),
            Self::KeyLoading(error) => write!(f, "could not load the leaf key: {error}"),
        }
    }
}

impl std::error::Error for CaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::KeyGeneration(error) | Self::Signing(error) => Some(error),
            Self::KeyLoading(error) => Some(error),
        }
    }
}

/// The validity window stamped on the root and every leaf.
///
/// This layer owns no clock — it is pure with respect to wall time, so a leaf
/// is reproducible from its host alone — so the window is a fixed span wide
/// enough that "now" is always inside it. A user-installed root is not subject
/// to the CA/Browser Forum maximum-validity rules that govern publicly trusted
/// chains, so a wide window is a correctness convenience rather than a policy
/// violation. When the shell gains a clock, narrowing this to `now ± margin` is
/// a local change here and nowhere else.
const NOT_BEFORE: (i32, u8, u8) = (2020, 1, 1);
const NOT_AFTER: (i32, u8, u8) = (2100, 1, 1);

/// The Boreas root and the shared leaf key it signs hosts with.
///
/// Cheap to share behind an `Arc`: minting a leaf borrows `&self` and allocates
/// only the new certificate. Not `Clone`, because two authorities would mean
/// two roots and a client trusts exactly one.
pub struct CertificateAuthority {
    issuer: Issuer<'static, KeyPair>,
    root_der: CertificateDer<'static>,
    /// The subject key shared by every leaf: kept as an rcgen `KeyPair` to sign
    /// certificates over its public half, and as a rustls signer to prove
    /// possession of its private half during a handshake. One key, two views.
    leaf_key_pair: KeyPair,
    leaf_signer: Arc<dyn SigningKey>,
}

impl CertificateAuthority {
    /// Generates a fresh root and leaf key. A defect if key generation or the
    /// self-signature fails; neither is a routine condition.
    pub fn generate() -> Result<Self, CaError> {
        let root_key = KeyPair::generate().map_err(CaError::KeyGeneration)?;
        let mut params = CertificateParams::new(Vec::<String>::new()).map_err(CaError::Signing)?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "Boreas Root CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Boreas");
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.not_before = date_time_ymd(NOT_BEFORE.0, NOT_BEFORE.1, NOT_BEFORE.2);
        params.not_after = date_time_ymd(NOT_AFTER.0, NOT_AFTER.1, NOT_AFTER.2);
        let root = params.self_signed(&root_key).map_err(CaError::Signing)?;
        let root_der = root.der().clone();
        let issuer = Issuer::new(params, root_key);

        let leaf_key_pair = KeyPair::generate().map_err(CaError::KeyGeneration)?;
        let pkcs8 = PrivatePkcs8KeyDer::from(leaf_key_pair.serialize_der());
        let leaf_signer =
            any_supported_type(&PrivateKeyDer::Pkcs8(pkcs8)).map_err(CaError::KeyLoading)?;

        Ok(Self {
            issuer,
            root_der,
            leaf_key_pair,
            leaf_signer,
        })
    }

    /// The root certificate to install in the user store. The only way its
    /// public identity leaves this process; the private half stays here.
    pub fn root_der(&self) -> &CertificateDer<'static> {
        &self.root_der
    }

    /// Mints a leaf for `host`: a certificate whose only subject-alternative
    /// name is `host`, signed by the root, over the shared leaf key. One
    /// signature, no key generation.
    pub fn leaf_for(&self, host: &str) -> Result<Arc<CertifiedKey>, CaError> {
        let mut params = CertificateParams::new(vec![host.to_owned()]).map_err(CaError::Signing)?;
        params.distinguished_name.push(DnType::CommonName, host);
        // A leaf that cannot itself sign certificates: the client checks this,
        // and a MITM leaf claiming CA power is both wrong and a red flag.
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = date_time_ymd(NOT_BEFORE.0, NOT_BEFORE.1, NOT_BEFORE.2);
        params.not_after = date_time_ymd(NOT_AFTER.0, NOT_AFTER.1, NOT_AFTER.2);
        let leaf = params
            .signed_by(&self.leaf_key_pair, &self.issuer)
            .map_err(CaError::Signing)?;
        Ok(Arc::new(CertifiedKey::new(
            vec![leaf.der().clone()],
            Arc::clone(&self.leaf_signer),
        )))
    }
}

impl fmt::Debug for CertificateAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The keys are secrets; naming the type without them is the whole point.
        f.debug_struct("CertificateAuthority")
            .finish_non_exhaustive()
    }
}

/// A bounded, insertion-ordered leaf cache. Eviction is first-in-first-out
/// rather than least-recently-used on purpose: a browsing session touches tens
/// of origins, a miss costs one signature, and recency ordering over a set that
/// small buys nothing a FIFO ring does not. The bound is what matters — state
/// keyed by an attacker-suppliable SNI must not grow without limit.
struct LeafCache {
    by_host: HashMap<String, Arc<CertifiedKey>>,
    order: VecDeque<String>,
    capacity: NonZeroUsize,
}

impl LeafCache {
    fn new(capacity: NonZeroUsize) -> Self {
        Self {
            by_host: HashMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    /// Returns the cached leaf for `host`, or mints one with `make` and inserts
    /// it, evicting the oldest entry when the cache is full. A `make` that
    /// yields `None` (a signing failure) caches nothing.
    fn get_or_insert(
        &mut self,
        host: &str,
        make: impl FnOnce() -> Option<Arc<CertifiedKey>>,
    ) -> Option<Arc<CertifiedKey>> {
        if let Some(existing) = self.by_host.get(host) {
            return Some(Arc::clone(existing));
        }
        let leaf = make()?;
        if self.by_host.len() >= self.capacity.get()
            && let Some(oldest) = self.order.pop_front()
        {
            self.by_host.remove(&oldest);
        }
        self.by_host.insert(host.to_owned(), Arc::clone(&leaf));
        self.order.push_back(host.to_owned());
        Some(leaf)
    }
}

/// The rustls certificate resolver for the terminating server: it turns the
/// SNI in a `ClientHello` into a freshly minted (or cached) leaf.
///
/// Shareable behind an `Arc`, because one authority serves every terminated
/// connection in a session and each handshake resolves independently.
pub struct MitmResolver {
    authority: Arc<CertificateAuthority>,
    cache: Mutex<LeafCache>,
}

impl MitmResolver {
    pub fn new(authority: Arc<CertificateAuthority>, cache_capacity: NonZeroUsize) -> Self {
        Self {
            authority,
            cache: Mutex::new(LeafCache::new(cache_capacity)),
        }
    }

    /// The certificate for `host`, cached across calls. Separated from
    /// [`ResolvesServerCert::resolve`] so the cache is testable without
    /// fabricating a `ClientHello`. `None` on a poisoned lock or a signing
    /// failure — both of which the caller reads as "cannot intercept, splice."
    pub fn leaf(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        let mut cache = self.cache.lock().ok()?;
        cache.get_or_insert(host, || self.authority.leaf_for(host).ok())
    }
}

impl fmt::Debug for MitmResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MitmResolver").finish_non_exhaustive()
    }
}

impl ResolvesServerCert for MitmResolver {
    /// A client that offers no SNI cannot be handed a forged certificate for a
    /// name it did not ask for, so it gets `None` and the handshake fails —
    /// which is the fail-open path, not a leak.
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let host = client_hello.server_name()?;
        self.leaf(host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority() -> Arc<CertificateAuthority> {
        Arc::new(CertificateAuthority::generate().expect("CA generates"))
    }

    #[test]
    fn a_leaf_is_one_certificate_over_the_shared_key() {
        let ca = authority();
        let leaf = ca.leaf_for("example.com").expect("leaf mints");
        // Exactly the leaf: the client already trusts the root, so the chain
        // sends the end-entity certificate and nothing else.
        assert_eq!(leaf.cert.len(), 1);
        assert!(
            !ca.root_der().as_ref().is_empty(),
            "the installable root is real DER"
        );

        // Two hosts share the one signer: the private-key half is identical, so
        // the certified keys point at the same `SigningKey`.
        let other = ca.leaf_for("other.example").expect("leaf mints");
        assert!(
            Arc::ptr_eq(&leaf.key, &other.key),
            "one leaf key, many certs"
        );
    }

    #[test]
    fn the_cache_returns_one_leaf_per_host_and_bounds_its_size() {
        let resolver = MitmResolver::new(authority(), NonZeroUsize::new(2).unwrap());

        // Same host, same certificate: a cache hit is the identical `Arc`.
        let first = resolver.leaf("a.example").expect("mints");
        let again = resolver.leaf("a.example").expect("cached");
        assert!(Arc::ptr_eq(&first, &again), "a hit returns the same leaf");

        // A distinct host is a distinct certificate.
        let second = resolver.leaf("b.example").expect("mints");
        assert!(!Arc::ptr_eq(&first, &second));

        // The cache holds two; a third evicts the oldest, so re-requesting the
        // evicted host mints a fresh certificate rather than returning the old.
        let _third = resolver.leaf("c.example").expect("mints");
        let a_again = resolver.leaf("a.example").expect("re-mints after eviction");
        assert!(
            !Arc::ptr_eq(&first, &a_again),
            "the evicted host was regenerated, not served stale"
        );
    }
}
