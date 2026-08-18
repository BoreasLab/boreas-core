//! P14 certificate authority: the root Boreas installs in the user store, and
//! the per-host leaves it mints on demand to terminate TLS.
//!
//! One long-lived **leaf key** serves every host; each host gets a separately
//! signed certificate. Minting costs one signature, not a P-256 keygen.
//!
//! **The root leaves only as `root_der`.** The platform installs that DER in the
//! user store; the private key remains behind [`CertificateAuthority`].
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
    /// The stored certificate and the stored keys are not two halves of one
    /// authority. Its own recovery, distinct from [`Self::Material`], because
    /// both halves parsed: what failed is that they do not belong together,
    /// which points at a host that wrote its two secure-storage slots at
    /// different times rather than at a corrupted blob.
    Mismatched,
}

impl fmt::Display for CaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyGeneration(error) => write!(f, "could not generate a key pair: {error}"),
            Self::Signing(error) => write!(f, "could not sign a certificate: {error}"),
            Self::KeyLoading(error) => write!(f, "could not load the leaf key: {error}"),
            Self::Material => f.write_str("stored key material is not intact"),
            Self::Mismatched => {
                f.write_str("the stored certificate was not issued to the stored key")
            }
        }
    }
}

impl std::error::Error for CaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::KeyGeneration(error) | Self::Signing(error) => Some(error),
            Self::KeyLoading(error) => Some(error),
            Self::Material | Self::Mismatched => None,
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
    root_certificate: Vec<u8>,
    /// Private key material. One value, one secure-storage slot.
    keys: CaKeys,
}

impl CaMaterial {
    /// The one boundary two secure-storage reads cross to become an authority.
    ///
    /// **Proves the halves are halves of the same thing, which nothing
    /// downstream can.** The two live in different places by design — the
    /// certificate in a trust store, the keys in a keystore — so a host can
    /// write one and not the other: an interrupted rotation, a restored
    /// backup, two slots under different keys. Neither half is corrupt in that
    /// case, so every parse succeeds and the authority builds. What it then
    /// mints are leaves signed by a key the installed root does not carry, and
    /// the user sees every interception fail with nothing to read but a
    /// certificate error. Refusing here turns that into one recoverable error
    /// at startup.
    ///
    /// O(certificate bytes): one DER parse and one public-key comparison, once
    /// per session.
    pub fn from_parts(root_certificate: Vec<u8>, keys: CaKeys) -> Result<Self, CaError> {
        let (root, _leaf) = keys.unpack()?;
        let key =
            boring::pkey::PKey::private_key_from_pkcs8(root).map_err(|_| CaError::Material)?;
        let certificate =
            boring::x509::X509::from_der(&root_certificate).map_err(|_| CaError::Material)?;
        // **The signature, not just the public key.** The root is self-signed,
        // so verifying it under the stored key proves the same thing a
        // public-key comparison would and one thing more: that the certificate
        // is the one this key actually issued, intact, rather than merely one
        // carrying a matching public half.
        if !certificate.verify(&key).unwrap_or(false) {
            return Err(CaError::Mismatched);
        }
        Ok(Self {
            root_certificate,
            keys,
        })
    }

    /// The certificate to hand a platform trust store.
    pub fn root_certificate(&self) -> &[u8] {
        &self.root_certificate
    }

    /// The secret half, to hand a platform keystore.
    pub fn keys(&self) -> &CaKeys {
        &self.keys
    }
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

/// What a host has, and therefore what it is asking for.
///
/// **The intent is a value rather than a choice of constructor**, because the
/// host that expresses it is on the other side of a serialized configuration
/// and cannot call one of two functions. It reads its secure storage, wraps
/// what it found or did not find, and hands over one thing.
///
/// That leaves the host with a single code path, which is the point:
///
/// ```no_run
/// # use boreas_core::{CaKeys, CaMaterial, CertificateAuthority, Trust};
/// # fn trust_store() -> Option<Vec<u8>> { None }
/// # fn keystore() -> Option<Vec<u8>> { None }
/// # fn keep(_: &CaMaterial) {}
/// # fn offer_to_install(_: &[u8]) {}
/// # fn main() -> Result<(), boreas_core::CaError> {
/// // Two slots, so both must be there and both must belong together. A pair
/// // that does not is `CaError::Mismatched`, and generating is the recovery.
/// let stored = match (trust_store(), keystore()) {
///     (Some(certificate), Some(keys)) => {
///         CaMaterial::from_parts(certificate, CaKeys::from_bytes(keys)).ok()
///     }
///     _ => None,
/// };
/// let authority = CertificateAuthority::open(stored.map_or(Trust::Generate, Trust::Restore))?;
/// keep(&authority.material());
/// offer_to_install(authority.root_der());
/// # Ok(()) }
/// ```
///
/// Storing and offering happen unconditionally in both cases: storing what was
/// just restored is a no-op write, and offering a root the user already trusts
/// is a dialog the platform does not show. A host that branched here would have
/// two paths to get wrong instead of none.
pub enum Trust {
    /// Nothing has been trusted yet. Mint a root; the host keeps what comes
    /// back and asks the user to install it.
    Generate,
    /// The user already trusted this root. Use it, so every leaf minted this
    /// session still chains to what is in the device's store.
    Restore(CaMaterial),
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
    /// Opens the authority the host asked for.
    ///
    /// **Restoring never silently falls back to generating.** Stored material
    /// that will not parse means the device's secure storage lost or corrupted
    /// a key, and quietly minting a fresh root would leave a user whose store
    /// still trusts the old one with a session that intercepts nothing and
    /// reports nothing — the failure would surface months later as "filtering
    /// stopped working". The host is told, and re-prompting is its decision to
    /// make because it is the one that can show a dialog.
    pub fn open(trust: Trust) -> Result<Self, CaError> {
        match trust {
            Trust::Generate => Self::generate(),
            Trust::Restore(material) => Self::restore(&material),
        }
    }

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
        // The pair was proven to belong together by `CaMaterial::from_parts`,
        // which is the only way to have one.
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

/// Bounded FIFO leaf cache. FIFO is sufficient for a browsing session's small
/// origin set; the bound prevents attacker-controlled SNI from growing state.
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
    /// No SNI means no name for a forged certificate: fail the handshake and
    /// let the caller splice.
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
        // Client already trusts root; send only end-entity certificate.
        assert_eq!(leaf.cert.len(), 1);
        assert!(
            !ca.root_der().as_ref().is_empty(),
            "the installable root is real DER"
        );

        // Hosts share one signer, so their certified keys share `SigningKey`.
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

    /// Host storage may truncate, corrupt, or contain an unknown format; reject
    /// every such material without panicking or partially reading the key.
    #[test]
    fn material_a_host_could_not_store_intact_is_refused() {
        let good = CertificateAuthority::generate().unwrap().material();
        let bytes = good.keys().as_bytes().to_vec();

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
            assert!(
                matches!(
                    CaMaterial::from_parts(
                        good.root_certificate().to_vec(),
                        CaKeys::from_bytes(keys)
                    ),
                    Err(CaError::Material)
                ),
                "{label}"
            );
        }
    }

    /// **Two secure-storage slots can disagree, and every parse still
    /// succeeds.** A host that wrote its keystore and not its trust store — an
    /// interrupted rotation, a restored backup, two slots keyed differently —
    /// hands over a certificate and keys that are each perfectly intact and are
    /// not two halves of one authority. Without this the session builds, mints
    /// leaves the installed root cannot vouch for, and the user sees a
    /// certificate error on every site with nothing to act on.
    #[test]
    fn a_certificate_and_keys_from_different_authorities_are_refused() {
        let mine = CertificateAuthority::generate().unwrap().material();
        let theirs = CertificateAuthority::generate().unwrap().material();

        assert!(
            matches!(
                CaMaterial::from_parts(theirs.root_certificate().to_vec(), mine.keys().clone()),
                Err(CaError::Mismatched)
            ),
            "a root this key never issued"
        );
        // And the halves that do belong together still assemble, restore, and
        // mint under the very same root.
        let rejoined =
            CaMaterial::from_parts(mine.root_certificate().to_vec(), mine.keys().clone()).unwrap();
        let restored = CertificateAuthority::restore(&rejoined).unwrap();
        assert_eq!(restored.root_der().as_ref(), mine.root_certificate());
    }

    /// Keep public certificate separate from the secret: trust-store installers
    /// need the former in clear, while keystores must protect only the latter.
    #[test]
    fn the_public_artefact_is_not_inside_the_secret() {
        let material = CertificateAuthority::generate().unwrap().material();
        assert!(!material.root_certificate().is_empty());
        assert!(
            !material
                .keys()
                .as_bytes()
                .windows(material.root_certificate().len())
                .any(|window| window == material.root_certificate()),
            "the certificate is handed out separately, not buried in the secret"
        );
    }

    /// Both generate and restore return material to store and a root to offer;
    /// restore therefore needs no host-side special case.
    #[test]
    fn opening_with_or_without_stored_material_leaves_the_host_the_same_two_jobs() {
        let first = CertificateAuthority::open(Trust::Generate).unwrap();
        let kept = first.material();

        let again = CertificateAuthority::open(Trust::Restore(kept.clone())).unwrap();
        assert_eq!(
            again.material().root_certificate,
            kept.root_certificate,
            "what a host stores after restoring is what it already had"
        );
        assert_eq!(
            again.root_der().as_ref(),
            kept.root_certificate.as_slice(),
            "and what it offers is the root the user already trusts"
        );
    }

    /// Do not replace an unreadable key: the device still trusts the old root,
    /// so a fresh one would make interception silently ineffective.
    #[test]
    fn material_that_will_not_parse_is_reported_rather_than_replaced() {
        let good = CertificateAuthority::generate().unwrap().material();
        let broken = CaMaterial {
            root_certificate: good.root_certificate,
            keys: CaKeys::from_bytes(b"not this crate's".to_vec()),
        };
        assert!(matches!(
            CertificateAuthority::open(Trust::Restore(broken)),
            Err(CaError::Material)
        ));
    }
}
