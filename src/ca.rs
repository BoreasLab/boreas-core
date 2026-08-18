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

//! # What persists, and what does not
//!
//! **The core owns live state; the host owns durable state.** This crate opens
//! no file and reads no environment: persistence is a platform act, and the
//! platforms disagree about it — Android has app-private storage and a keystore
//! with hardware backing, Windows has DPAPI and a roaming profile. So state
//! crosses the boundary in exactly two places: it is handed in at construction,
//! and it is handed out on request.
//!
//! **Durable state is exactly what cannot be relearned cheaply and correctly**,
//! and by that test there is one thing: the material below. A user approved
//! this root through a system dialog, physically, once; nothing in this process
//! can reconstitute that approval, so losing the key means asking again.
//!
//! Everything else this crate learns is a cache with a lifetime already on it —
//! [`crate::Demotions`], the inspected-address index, the flow tables — and all
//! of it is deliberately lost on restart. The test is the same one: relearning
//! a demotion costs a single connection that is spliced instead of intercepted,
//! which no user perceives, while a *stale* demotion silently withholds
//! filtering from a site that has since become interceptable. A cache whose
//! wrong answers are invisible and whose right answers are cheap does not
//! belong in durable storage, and giving it a persistence path would be the
//! kind of inconsistency that is discovered years later as "why is this site
//! not being filtered".

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
    /// Stored key material that is not this crate's, or not intact. A host that
    /// gets this generates a fresh authority and asks the user to trust it
    /// again, which is the only recovery there is.
    Material,
}

impl fmt::Display for CaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyGeneration(error) => write!(f, "could not generate a key pair: {error}"),
            Self::Signing(error) => write!(f, "could not sign a certificate: {error}"),
            Self::KeyLoading(error) => write!(f, "could not load the leaf key: {error}"),
            Self::Material => f.write_str("stored key material is not intact"),
        }
    }
}

impl std::error::Error for CaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::KeyGeneration(error) | Self::Signing(error) => Some(error),
            Self::KeyLoading(error) => Some(error),
            Self::Material => None,
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

/// The root's issuing parameters, in one place because two callers must agree
/// on them exactly: the one that mints a root and the one that restores it.
///
/// See [`CertificateAuthority::restore`] for why these bytes are effectively a
/// wire format and must not drift.
fn root_params() -> Result<CertificateParams, CaError> {
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
    Ok(params)
}

/// Everything a host must keep so that a restarted tunnel mints under the root
/// the user already trusts.
///
/// **A generated root is worthless the moment the process restarts.** A user
/// installs the root in the device trust store once, deliberately, through a
/// system dialog; an authority that could only be generated would mint a
/// different root every launch and leave a trail of stale entries the user has
/// to remove by hand. So this is not a convenience — it is what makes
/// interception usable at all.
///
/// **The two halves are separate types because they go to different places.**
/// The certificate is public: it is handed to the platform's trust-store
/// installer, and a host that treated it as a secret could not install it at
/// all. [`CaKeys`] is private and belongs in whatever the platform uses for
/// secrets — the Android keystore, DPAPI. Putting them in one blob would force
/// the host to choose one home for both, and the honest choice would be the
/// wrong one for whichever half lost.
#[derive(Clone)]
pub struct CaMaterial {
    /// DER. Public, and the artefact the user is asked to trust.
    pub root_certificate: Vec<u8>,
    /// Private key material. One value, one secure-storage slot.
    pub keys: CaKeys,
}

/// The private key material an authority signs with: the root's key, and the
/// shared key every leaf is minted over.
///
/// **Deliberately opaque.** A host's only jobs are to store these bytes where
/// it stores secrets and to hand them back, and it can do both without knowing
/// there are two keys inside. Naming the fields would invite a host to write
/// one of them somewhere the other did not go, and would make the split part of
/// the interface — so a hardware-backed signer, which is where this should end
/// up, could not be added without a breaking change.
///
/// Not `Debug`, not `Display`, and it does not implement `Deref`: a derived one
/// would print private keys into whatever log the host has on.
#[derive(Clone)]
pub struct CaKeys(Vec<u8>);

impl CaKeys {
    /// The bytes to store. Opaque, self-describing, and versioned by its first
    /// byte so that a host storing today's blob is not stopped from restoring
    /// it under a build that has learned a second format.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Takes bytes back from storage. Nothing is validated here — the keys are
    /// parsed by [`CertificateAuthority::restore`], which is the one place that
    /// can say whether they are usable.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// The format byte. One format so far; the byte exists so a second one is
    /// an addition rather than an ambiguity.
    const VERSION: u8 = 1;

    fn pack(root: &[u8], leaf: &[u8]) -> Self {
        let mut bytes = vec![Self::VERSION];
        for part in [root, leaf] {
            bytes.extend_from_slice(&(part.len() as u32).to_be_bytes());
            bytes.extend_from_slice(part);
        }
        Self(bytes)
    }

    /// Total on untrusted input: a blob a host truncated, corrupted, or wrote
    /// from a future version is [`CaError::Material`], never a panic and never
    /// a key half-read.
    fn unpack(&self) -> Result<(&[u8], &[u8]), CaError> {
        let (&version, mut rest) = self.0.split_first().ok_or(CaError::Material)?;
        if version != Self::VERSION {
            return Err(CaError::Material);
        }
        let mut parts = [&[][..]; 2];
        for slot in &mut parts {
            let (length, tail) = rest.split_at_checked(4).ok_or(CaError::Material)?;
            let length = u32::from_be_bytes(length.try_into().expect("4 bytes")) as usize;
            let (part, tail) = tail.split_at_checked(length).ok_or(CaError::Material)?;
            *slot = part;
            rest = tail;
        }
        if !rest.is_empty() {
            return Err(CaError::Material);
        }
        Ok((parts[0], parts[1]))
    }
}

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
        let params = root_params()?;
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

    /// The private material this authority is, in the form a host stores it.
    ///
    /// **A generated root is worthless the moment the process restarts.** A
    /// user installs the root in the device trust store once, deliberately,
    /// through a system dialog; an authority that could only be generated would
    /// mint a different root on every launch and every previously trusted one
    /// would be a stale entry the user has to remove by hand. Persistence is
    /// therefore not a convenience — it is what makes interception usable at
    /// all, and it is why this and [`Self::restore`] exist as a pair.
    ///
    /// The root's DER travels alongside the keys rather than being re-derived
    /// from them, because a self-signature carries a fresh random serial
    /// number: signing the same parameters twice yields two different
    /// certificates, and the one the user trusted is the one that must come
    /// back.
    pub fn material(&self) -> CaMaterial {
        CaMaterial {
            root_certificate: self.root_der.to_vec(),
            keys: CaKeys::pack(
                &self.issuer.key().serialize_der(),
                &self.leaf_key_pair.serialize_der(),
            ),
        }
    }

    /// Rebuilds the authority a host stored, so the root the user trusted stays
    /// the root this session mints under.
    ///
    /// The issuing parameters come from [`root_params`], the same function
    /// [`Self::generate`] used to mint the stored root. **That makes the
    /// distinguished name a wire format**: a leaf names its issuer by DN and
    /// authority key identifier, so changing either would leave every root a
    /// user has already installed unable to validate the leaves this mints
    /// under it. `a_restored_authority_mints_under_the_root_it_restored` is the
    /// guard, and the alternative — recovering the parameters by parsing the
    /// certificate — costs an X.509 parser in the dependency graph to learn
    /// three fields this crate wrote itself.
    pub fn restore(material: &CaMaterial) -> Result<Self, CaError> {
        let root_der = CertificateDer::from(material.root_certificate.clone()).into_owned();
        let (root, leaf) = material.keys.unpack()?;
        let root_key =
            KeyPair::try_from(&PrivatePkcs8KeyDer::from(root)).map_err(CaError::KeyGeneration)?;
        let issuer = Issuer::new(root_params()?, root_key);

        let leaf_key_pair =
            KeyPair::try_from(&PrivatePkcs8KeyDer::from(leaf)).map_err(CaError::KeyGeneration)?;
        let leaf_signer = any_supported_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            leaf_key_pair.serialize_der(),
        )))
        .map_err(CaError::KeyLoading)?;

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

    /// **The property the whole persistence path exists for.** A user trusted
    /// one root through a system dialog; every leaf minted after a restart must
    /// still chain to *that* root, or interception silently stops working and
    /// the only fix is asking the user to trust something again.
    ///
    /// This is also the guard on [`root_params`]: a leaf names its issuer by
    /// distinguished name, so changing the DN would pass every other test here
    /// and break every root already installed on a device.
    #[test]
    fn a_restored_authority_mints_under_the_root_it_restored() {
        let original = CertificateAuthority::generate().unwrap();
        let material = original.material();
        let restored = CertificateAuthority::restore(&material).unwrap();

        assert_eq!(
            restored.root_der(),
            original.root_der(),
            "the installed root comes back byte for byte, serial included"
        );

        let before = original.leaf_for("example.com").unwrap();
        let after = restored.leaf_for("example.com").unwrap();
        assert_ne!(
            before.cert[0], after.cert[0],
            "a fresh leaf, since each carries its own serial"
        );
        assert_eq!(
            issuer_of(&after.cert[0]),
            issuer_of(&before.cert[0]),
            "but issued by the same name, which is what makes it chain"
        );
        assert_eq!(
            after.key.public_key(),
            before.key.public_key(),
            "and over the same leaf key, so a pin survives the restart too"
        );
    }

    /// The issuer field of a DER certificate, located by structure rather than
    /// parsed: a full X.509 parser in the dependency graph to read one field in
    /// one test would be a poor trade.
    ///
    /// TBSCertificate is `[0] version, serial, signature, issuer, ...`; this
    /// walks those four and returns the issuer's bytes.
    fn issuer_of(der: &rustls::pki_types::CertificateDer<'_>) -> Vec<u8> {
        fn field(bytes: &[u8]) -> (&[u8], &[u8]) {
            let (length, rest) = match bytes[1] {
                short if short < 0x80 => (usize::from(short), &bytes[2..]),
                long => {
                    let count = usize::from(long & 0x7f);
                    let mut length = 0usize;
                    for byte in &bytes[2..2 + count] {
                        length = (length << 8) | usize::from(*byte);
                    }
                    (length, &bytes[2 + count..])
                }
            };
            (&rest[..length], &rest[length..])
        }
        // Certificate -> TBSCertificate -> skip version, serial, signature.
        let (tbs, _) = field(field(der.as_ref()).0);
        let (_version, rest) = field(tbs);
        let (_serial, rest) = field(rest);
        let (_signature, rest) = field(rest);
        field(rest).0.to_vec()
    }

    /// Stored material is bytes a host wrote to disk, so it comes back
    /// truncated, corrupted, or from a build that wrote a format this one has
    /// never seen. Every one of those is an error a host recovers from by
    /// generating afresh — never a panic, and never a key half-read.
    #[test]
    fn material_a_host_could_not_store_intact_is_refused() {
        let good = CertificateAuthority::generate().unwrap().material();
        let bytes = good.keys.as_bytes().to_vec();

        for (label, keys) in [
            ("empty", Vec::new()),
            ("a version this build has never written", {
                let mut other = bytes.clone();
                other[0] = 0xff;
                other
            }),
            ("truncated mid-key", bytes[..bytes.len() / 2].to_vec()),
            ("length longer than what follows", {
                let mut other = bytes.clone();
                other[1..5].copy_from_slice(&u32::MAX.to_be_bytes());
                other
            }),
            ("trailing bytes nothing accounts for", {
                let mut other = bytes.clone();
                other.push(0);
                other
            }),
        ] {
            let material = CaMaterial {
                root_certificate: good.root_certificate.clone(),
                keys: CaKeys::from_bytes(keys),
            };
            assert!(
                matches!(
                    CertificateAuthority::restore(&material),
                    Err(CaError::Material)
                ),
                "{label}"
            );
        }
    }

    /// The secret is one value with one home, and the certificate is not part
    /// of it: a host that had to store them together would either put a public
    /// artefact in the keystore or a private key beside the filter lists, and
    /// the trust-store installer needs the certificate in the clear.
    #[test]
    fn the_public_artefact_is_not_inside_the_secret() {
        let material = CertificateAuthority::generate().unwrap().material();
        assert!(!material.root_certificate.is_empty());
        assert!(
            !material
                .keys
                .as_bytes()
                .windows(material.root_certificate.len())
                .any(|window| window == material.root_certificate),
            "the certificate is handed out separately, not buried in the secret"
        );
    }
}
