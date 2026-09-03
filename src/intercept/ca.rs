//! Root and per-host leaf certificates for TLS interception.
//!
//! One leaf key is shared across hosts; each host receives its own signed
//! certificate. The root leaves only as `root_der`; its private key stays here.
//!
//! A missing leaf is fail-open: [`MitmResolver::resolve`] returns `None`, and
//! the session demotes the host to a splice.

//! # Persistence boundary
//!
//! The host owns durable state. This crate performs no file or environment I/O;
//! material crosses the boundary through construction and accessors.
//!
//! Only the root material persists. A user-approved root cannot be recreated
//! without another trust-store prompt.
//!
//! Demotions, address indexes, and flow tables are restart-local caches. Their
//! stale values would silently suppress filtering, while relearning is cheap.

use std::{
    fmt,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
};

use crate::fifo::BoundedFifo;

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

use crate::wire::{Reader, Writer};

/// Certificate provisioning failure.
#[derive(Debug)]
pub enum CaError {
    /// Key generation failed.
    KeyGeneration(rcgen::Error),
    /// Certificate signing failed.
    Signing(rcgen::Error),
    /// rustls could not load the leaf signer.
    KeyLoading(rustls::Error),
    /// Stored key material is invalid.
    Material,
    /// The stored certificate and keys belong to different authorities.
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

/// Fixed validity window used by the root and leaves.
const NOT_BEFORE: (i32, u8, u8) = (2020, 1, 1);
const NOT_AFTER: (i32, u8, u8) = (2100, 1, 1);

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

/// Persisted public root certificate and private signing material.
#[derive(Clone)]
pub struct CaMaterial {
    /// Public DER sent to the trust store.
    root_certificate: Vec<u8>,
    /// Private material sent to secure storage.
    keys: CaKeys,
}

impl CaMaterial {
    /// Combines storage halves after verifying the root self-signature.
    pub fn from_parts(root_certificate: Vec<u8>, keys: CaKeys) -> Result<Self, CaError> {
        let (root, _leaf) = keys.unpack()?;
        let key =
            boring::pkey::PKey::private_key_from_pkcs8(root).map_err(|_| CaError::Material)?;
        let certificate =
            boring::x509::X509::from_der(&root_certificate).map_err(|_| CaError::Material)?;
        // The self-signature proves the certificate and stored key are paired.
        if !certificate.verify(&key).unwrap_or(false) {
            return Err(CaError::Mismatched);
        }
        Ok(Self {
            root_certificate,
            keys,
        })
    }

    pub fn root_certificate(&self) -> &[u8] {
        &self.root_certificate
    }

    pub fn keys(&self) -> &CaKeys {
        &self.keys
    }
}

/// Opaque serialized private material for the root and leaf keys.
///
/// It is intentionally not printable or dereferenceable.
#[derive(Clone)]
pub struct CaKeys(Vec<u8>);

impl CaKeys {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    const VERSION: u8 = 1;

    fn pack(root: &[u8], leaf: &[u8]) -> Self {
        let mut bytes = vec![Self::VERSION];
        let mut writer = Writer::new(&mut bytes);
        for part in [root, leaf] {
            writer.vector_u32(part);
        }
        Self(bytes)
    }

    fn unpack(&self) -> Result<(&[u8], &[u8]), CaError> {
        let mut reader = Reader::new(&self.0);
        if reader.u8() != Some(Self::VERSION) {
            return Err(CaError::Material);
        }
        let mut parts = [&[][..]; 2];
        for slot in &mut parts {
            let length = reader.u32().ok_or(CaError::Material)?;
            let length = usize::try_from(length).map_err(|_| CaError::Material)?;
            *slot = reader.take(length).ok_or(CaError::Material)?;
        }
        // Reject bytes outside the defined format.
        if !reader.is_empty() {
            return Err(CaError::Material);
        }
        Ok((parts[0], parts[1]))
    }
}

/// Whether to generate or restore persisted authority material.
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
/// The host can store the returned material and offer the root in either case.
pub enum Trust {
    /// Generate a new root and leaf key.
    Generate,
    /// Restore material for the already trusted root.
    Restore(CaMaterial),
}

/// The Boreas root and shared leaf signer.
pub struct CertificateAuthority {
    issuer: Issuer<'static, KeyPair>,
    root_der: CertificateDer<'static>,
    /// Shared leaf key, held as both rcgen key pair and rustls signer.
    leaf_key_pair: KeyPair,
    leaf_signer: Arc<dyn SigningKey>,
}

impl CertificateAuthority {
    pub fn open(trust: Trust) -> Result<Self, CaError> {
        match trust {
            Trust::Generate => Self::generate(),
            Trust::Restore(material) => Self::restore(&material),
        }
    }

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

    /// Returns the material a host must persist across restarts.
    pub fn material(&self) -> CaMaterial {
        CaMaterial {
            root_certificate: self.root_der.to_vec(),
            keys: CaKeys::pack(
                &self.issuer.key().serialize_der(),
                &self.leaf_key_pair.serialize_der(),
            ),
        }
    }

    /// Restores an authority under the previously trusted root.
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

    pub fn root_der(&self) -> &CertificateDer<'static> {
        &self.root_der
    }

    pub fn leaf_for(&self, host: &str) -> Result<Arc<CertifiedKey>, CaError> {
        let mut params = CertificateParams::new(vec![host.to_owned()]).map_err(CaError::Signing)?;
        params.distinguished_name.push(DnType::CommonName, host);
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
        f.debug_struct("CertificateAuthority")
            .finish_non_exhaustive()
    }
}

/// rustls resolver that maps SNI to a cached forged leaf.
pub struct MitmResolver {
    authority: Arc<CertificateAuthority>,
    /// Bounded: a busy session forges one leaf per host it intercepts.
    cache: Mutex<BoundedFifo<String, Arc<CertifiedKey>>>,
}

impl MitmResolver {
    pub fn new(authority: Arc<CertificateAuthority>, cache_capacity: NonZeroUsize) -> Self {
        Self {
            authority,
            cache: Mutex::new(BoundedFifo::new(cache_capacity)),
        }
    }

    /// A failed mint is not memoized, so a transient failure is retried.
    pub fn leaf(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        let mut cache = crate::locked(&self.cache);
        if let Some(hit) = cache.get(host) {
            return Some(hit);
        }
        let leaf = self.authority.leaf_for(host).ok()?;
        Some(cache.get_or_insert_with(host.to_owned(), || leaf))
    }
}

impl fmt::Debug for MitmResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MitmResolver").finish_non_exhaustive()
    }
}

impl ResolvesServerCert for MitmResolver {
    /// No SNI means no host to forge, so fail open to splicing.
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
        assert_eq!(leaf.cert.len(), 1);
        assert!(
            !ca.root_der().as_ref().is_empty(),
            "the installable root is real DER"
        );

        let other = ca.leaf_for("other.example").expect("leaf mints");
        assert!(
            Arc::ptr_eq(&leaf.key, &other.key),
            "one leaf key, many certs"
        );
    }

    #[test]
    fn the_cache_returns_one_leaf_per_host_and_bounds_its_size() {
        let resolver = MitmResolver::new(authority(), NonZeroUsize::new(2).unwrap());

        let first = resolver.leaf("a.example").expect("mints");
        let again = resolver.leaf("a.example").expect("cached");
        assert!(Arc::ptr_eq(&first, &again), "a hit returns the same leaf");

        let second = resolver.leaf("b.example").expect("mints");
        assert!(!Arc::ptr_eq(&first, &second));

        let _third = resolver.leaf("c.example").expect("mints");
        let a_again = resolver.leaf("a.example").expect("re-mints after eviction");
        assert!(
            !Arc::ptr_eq(&first, &a_again),
            "the evicted host was regenerated, not served stale"
        );
    }

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
        let (tbs, _) = field(field(der.as_ref()).0);
        let (_version, rest) = field(tbs);
        let (_serial, rest) = field(rest);
        let (_signature, rest) = field(rest);
        field(rest).0.to_vec()
    }

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
        let rejoined =
            CaMaterial::from_parts(mine.root_certificate().to_vec(), mine.keys().clone()).unwrap();
        let restored = CertificateAuthority::restore(&rejoined).unwrap();
        assert_eq!(restored.root_der().as_ref(), mine.root_certificate());
    }

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
