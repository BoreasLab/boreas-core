//! The originating side of interception: the ClientHello Boreas sends upstream.
//!
//! **rustls is the server and BoringSSL is the client, and the asymmetry is the
//! design.** Terminating the local browser has no fidelity requirement — the
//! peer is an application on this device and nothing fingerprints it — so
//! [`Interceptor`](crate::Interceptor) keeps rustls and its memory safety.
//! Every leg that *dials out* is fingerprinted by whoever answers, and rustls
//! has no supported way to shape a ClientHello: extension order, GREASE
//! placement, and JA3/JA4-matching hellos are long-standing open requests, and
//! `Acceptor` only lets a caller *read* a peer's. BoringSSL is what Chrome
//! itself speaks, so matching it is configuration rather than reimplementation.
//!
//! **Every dialling leg comes through here**, not only interception: the
//! VLESS-family transports, whose premise is looking like a browser reaching a
//! website, and the encrypted DNS upstreams, whose query is the first thing a
//! connection does. Those two have no client hello to copy, so they wear
//! [`ClientProfile::chrome`] instead of a mirror.
//!
//! **The target is the client on this device, not a canonical Chrome.** Boreas
//! already holds the real ClientHello — it terminated the connection to read the
//! SNI — so the cipher list, groups, signature algorithms, GREASE, and
//! certificate compression are sitting in bytes already parsed. Mirroring them
//! is self-consistent on any device: Chrome gets Chrome, WebView gets WebView,
//! and a Firefox that routes through here gets Firefox. A hardcoded Chrome
//! profile would be exactly right for one client and would manufacture a fresh
//! mismatch for every other, while needing maintenance against Chrome's
//! four-week release train.
//!
//! It also does something a fixed profile cannot advertise its way out of:
//! BoringSSL's *default* supported groups are `X25519`, `P-256`, and `P-384`,
//! so an unmirrored hello cannot carry `X25519MLKEM768` at all — the group
//! current Chrome always offers, and the one a stale TLS stack is most visibly
//! missing.
//!
//! **What is mirrored, and what is not.** Mirrored: supported groups, signature
//! algorithms, certificate-compression algorithms, GREASE, and extension
//! permutation. Not mirrored, because BoringSSL does not expose it: an explicit
//! extension *order* (only randomised permutation, which is what Chrome does
//! anyway), and ALPS. The TLS 1.3 cipher suites are fixed in BoringSSL and
//! already match Chrome's, since Chrome is BoringSSL.
//!
//! **ALPN is mirrored, and the origin is what picks from it.** The upstream
//! handshake offers the client's own list ([`Offer`]) and the client's handshake
//! is then given exactly the one protocol the origin agreed to, so a crossed
//! HTTP version stays unrepresentable while an origin that speaks only
//! HTTP/1.1 is still served. Offering the client's *choice* upstream instead
//! would send `h2` alone to such an origin and be refused outright — a site
//! Chrome loads without complaint, lost to a one-entry ALPN list that is also
//! nothing a browser sends.
//!
//! **The HTTP/2 half is here too, and it is not mirrored — it is Chrome's.**
//! [`H2Profile`] carries the four fields the Akamai fingerprint reads. The
//! asymmetry with the ClientHello above is forced rather than chosen: a
//! ClientHello arrives before anything is decrypted, so Boreas holds the
//! client's own bytes, while an HTTP/2 preface arrives *inside* the connection
//! this process terminates and is consumed by hyper's server before any of it
//! could be copied. Reproducing the client's preface would mean reading frames
//! hyper has already turned into a `Request`. So the upstream preface is a
//! constant, and [`H2Profile::CHROME`] is what it is set to.

use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex},
};

use boring::{
    error::ErrorStack,
    ssl::{
        CertificateCompressionAlgorithm, CertificateCompressor, SslConnector, SslMethod,
        SslSignatureAlgorithm, SslVersion,
    },
    x509::{X509, store::X509StoreBuilder},
};
use hyper::client::conn::http2::Builder as H2Builder;
use tokio::io::{AsyncRead, AsyncWrite};

/// Handshake extensions this module reads out of a ClientHello.
const EXTENSION_SERVER_NAME: u16 = 0x0000;
const EXTENSION_SUPPORTED_GROUPS: u16 = 0x000a;
const EXTENSION_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXTENSION_COMPRESS_CERTIFICATE: u16 = 0x001b;
const EXTENSION_ALPN: u16 = 0x0010;

const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const NAME_TYPE_HOST: u8 = 0x00;

/// RFC 8879's identifier for Brotli certificate compression. Compared against
/// codepoints read off the wire, so it is the number rather than boring's
/// constant, which carries no accessor to compare with.
const BROTLI_ALGORITHM: u16 = 2;

/// How many distinct (profile, wire) pairs keep a built connector.
///
/// A device runs a handful of TLS clients, so this is generous in practice.
/// It is a cap rather than an eviction policy because the profile is derived
/// from bytes a local application chooses: without a bound, an application that
/// varied its hello per connection would grow this map without limit, and an
/// LRU would spend more code on that case than it is worth. Overflow clears,
/// which costs one rebuild per profile and never unbounded memory.
const MAX_CACHED_CONNECTORS: usize = 16;

/// Whether a codepoint is one of the GREASE values reserved by RFC 8701.
///
/// They are the sixteen values whose bytes are equal and whose low nibbles are
/// `0xA` — `0x0A0A`, `0x1A1A`, through `0xFAFA`. A client that sends one is
/// exercising the extension-tolerance mechanism, and a client that sends none
/// is not; reproducing that is a single bit of the profile.
const fn is_grease(value: u16) -> bool {
    value >> 8 == value & 0x00ff && value & 0x000f == 0x000a
}

/// The BoringSSL name for an IANA group codepoint, or `None` for a group this
/// build cannot express.
///
/// A closed table taken from BoringSSL's own `kNamedGroups`, because
/// `set_curves_list` speaks names rather than codepoints. An unknown codepoint
/// is dropped rather than refused: a client offering a group this BoringSSL
/// does not implement still gets a handshake, one group shorter, which is the
/// same fail-open the rest of interception takes.
const fn group_name(codepoint: u16) -> Option<&'static str> {
    Some(match codepoint {
        23 => "P-256",
        24 => "P-384",
        25 => "P-521",
        29 => "X25519",
        0x0202 => "MLKEM1024",
        0x11ec => "X25519MLKEM768",
        0x6399 => "X25519Kyber768Draft00",
        _ => return None,
    })
}

/// What a ClientHello asked for, reduced to what BoringSSL can be told.
///
/// [`Default`] is the honest identity: an empty profile applies nothing and
/// leaves BoringSSL's own defaults in place, which is what a flow whose hello
/// could not be parsed gets. Every field is therefore "what to override",
/// never "what the peer must have sent".
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ClientProfile {
    /// Supported groups, in the client's order, as BoringSSL names.
    groups: Vec<&'static str>,
    /// Signature algorithms, in the client's order. These are IANA codepoints
    /// on both sides, so they map through with no table.
    sigalgs: Vec<u16>,
    /// Certificate-compression algorithms the client advertised.
    compression: Vec<u16>,
    /// Whether the client sent GREASE values.
    grease: bool,
}

impl ClientProfile {
    /// Chrome's own hello, for a leg that has no client to mirror.
    ///
    /// **The fallback is a stated profile, not the empty one.** An empty profile
    /// leaves BoringSSL's defaults — `X25519`, `P-256`, `P-384` — which cannot
    /// carry `X25519MLKEM768` and so name a TLS stack years older than the
    /// browser this build otherwise reproduces. Every leg that dials out
    /// without a ClientHello to copy uses this: the VLESS-family transports,
    /// whose whole premise is looking like a browser reaching a website, and the
    /// encrypted DNS upstreams.
    ///
    /// Mirroring is still preferred wherever a hello exists, for the reason this
    /// module opens with: a fixed profile is right for one client and wrong for
    /// every other, and needs maintaining against a four-week release train.
    #[must_use]
    pub fn chrome() -> Self {
        Self {
            groups: vec!["X25519MLKEM768", "X25519", "P-256", "P-384"],
            // ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256, rsa_pkcs1_sha256,
            // ecdsa_secp384r1_sha384, rsa_pss_rsae_sha384, rsa_pkcs1_sha384,
            // rsa_pss_rsae_sha512, rsa_pkcs1_sha512.
            sigalgs: vec![
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ],
            compression: vec![BROTLI_ALGORITHM],
            grease: true,
        }
    }

    /// Whether this profile overrides anything at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// The groups this profile will ask for, for tests and diagnostics.
    #[must_use]
    pub fn groups(&self) -> &[&'static str] {
        &self.groups
    }

    /// Whether the client advertised Brotli certificate compression, which is
    /// the only algorithm this build can answer.
    #[must_use]
    pub fn compresses_certificates(&self) -> bool {
        self.compression.contains(&BROTLI_ALGORITHM)
    }
}

/// What one ClientHello revealed: the name a policy needs, and the shape an
/// upstream handshake should reproduce.
///
/// One value from one pass, because the two facts come from the same bytes and
/// a second traversal could only disagree with the first.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Hello {
    pub host: Option<crate::DomainName>,
    pub profile: ClientProfile,
    pub alpn: Offer,
}

/// The application protocols a client offered, reduced to the ones Boreas can
/// terminate and kept in the client's own order.
///
/// **This is what lets the origin settle the wire.** The upstream handshake
/// offers this list verbatim, the origin picks one, and the client's handshake
/// is then given that one and no other. An origin that speaks only HTTP/1.1 is
/// therefore served over HTTP/1.1 on both legs, where offering the client's
/// choice would have offered `h2` alone and been refused.
///
/// Empty is a real value meaning *negotiate nothing*: a client that sent no ALPN
/// extension, or offered only protocols this cannot terminate. RFC 7301 makes
/// that HTTP/1.1 on both sides, which is what a bare HTTP/1.1 client already
/// expects.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Offer(Vec<crate::Wire>);

impl Offer {
    /// The protocols named in an `application_layer_protocol_negotiation`
    /// extension body, keeping only what [`Wire`](crate::Wire) admits.
    ///
    /// Total on untrusted input: a body this cannot read is an empty offer.
    /// O(bytes), and the result is bounded by [`Wire::ALL`](crate::Wire::ALL)
    /// however long the client's list is.
    fn read(body: &[u8]) -> Self {
        let Some(list) = Reader::new(body).vector_u16() else {
            return Self::default();
        };
        let mut wires = Vec::new();
        let mut reader = Reader::new(list);
        while let Some(name) = reader.vector_u8() {
            // `h3` and anything else is dropped rather than carried: this leg
            // is TCP, and a protocol the exchange cannot serve is one the
            // origin must not be allowed to pick.
            if let Some(wire) = crate::Wire::from_identifier(name)
                && !wires.contains(&wire)
            {
                wires.push(wire);
            }
        }
        Self(wires)
    }

    /// The wires offered, in the client's order.
    #[must_use]
    pub fn wires(&self) -> &[crate::Wire] {
        &self.0
    }

    /// This offer in ALPN wire format, ready for a handshake.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let names: Vec<&[u8]> = self.0.iter().map(|wire| wire.identifier()).collect();
        alpn_list(&names)
    }
}

/// Reads one handshake record.
///
/// Total on untrusted input: every byte sequence is *some* [`Hello`], and the
/// ones this cannot interpret yield an empty one, which applies no overrides
/// and names no host. There is deliberately no error case — a parser with one
/// would force every caller to choose a fallback, and one of them would
/// eventually choose to intercept.
///
/// One forward pass over the record, $O(n)$ in its bytes, bounded by the
/// 2^14-byte maximum of a TLS record. Allocates only the vectors the profile
/// keeps, each bounded by the extension that fills it.
#[must_use]
pub fn read_hello(record: &[u8]) -> Hello {
    let mut hello = Hello::default();
    let mut reader = Reader::new(record);
    if reader.u8() != Some(HANDSHAKE_CLIENT_HELLO) {
        return hello;
    }
    // A handshake body longer than this record is a ClientHello fragmented
    // across records. Legal, vanishingly rare, and not reassembled here: the
    // result names no host, which splices.
    let Some(body) = reader.u24().and_then(|length| reader.take(length)) else {
        return hello;
    };

    let mut cursor = Reader::new(body);
    let extensions = (|| {
        cursor.take(2)?; // legacy_version
        cursor.take(32)?; // random
        cursor.vector_u8()?; // legacy_session_id
        cursor.vector_u16()?; // cipher_suites
        cursor.vector_u8()?; // legacy_compression_methods
        cursor.vector_u16()
    })();
    let Some(extensions) = extensions else {
        return hello;
    };

    // Extensions are a sequence rather than a map, so this is a scan — but one
    // that reads every header once and skips each body by length, so it is
    // O(bytes) and not O(extensions) times anything.
    let mut reader = Reader::new(extensions);
    while let Some(kind) = reader.u16() {
        let Some(body) = reader.vector_u16() else {
            break;
        };
        hello.profile.grease |= is_grease(kind);
        match kind {
            EXTENSION_SERVER_NAME => hello.host = server_name(body),
            // A client greases its group and signature lists as well as its
            // extension types, so the flag reflects any of them — and the
            // grease values themselves are dropped, because forwarding one as
            // a preference would name an algorithm that does not exist.
            EXTENSION_SUPPORTED_GROUPS => {
                hello.profile.grease |= codepoints(body).any(is_grease);
                hello.profile.groups = codepoints(body).filter_map(group_name).collect();
            }
            EXTENSION_SIGNATURE_ALGORITHMS => {
                hello.profile.grease |= codepoints(body).any(is_grease);
                hello.profile.sigalgs = codepoints(body).filter(|&id| !is_grease(id)).collect();
            }
            EXTENSION_ALPN => hello.alpn = Offer::read(body),
            EXTENSION_COMPRESS_CERTIFICATE => {
                // A one-byte length prefix here, unlike the two-byte vectors
                // above, so it is read on its own terms.
                let mut inner = Reader::new(body);
                if let Some(list) = inner.vector_u8() {
                    hello.profile.compression = list
                        .chunks_exact(2)
                        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                        .collect();
                }
            }
            _ => {}
        }
    }
    hello
}

/// The u16 codepoints of a two-byte-length-prefixed vector, skipping a
/// trailing odd byte rather than failing on it.
fn codepoints(body: &[u8]) -> impl Iterator<Item = u16> + '_ {
    let list = Reader::new(body).vector_u16().unwrap_or_default();
    list.chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
}

/// The SNI host from a `server_name` extension body.
fn server_name(body: &[u8]) -> Option<crate::DomainName> {
    // ServerNameList: a vector of (name_type, opaque name). RFC 6066 allows at
    // most one entry per type and `host_name` is the only type defined, so the
    // first match is the answer.
    let mut names = Reader::new(body.get(2..)?);
    while let Some(name_type) = names.u8() {
        let name = names.vector_u16()?;
        if name_type == NAME_TYPE_HOST {
            // The name crosses into the domain through the same smart
            // constructor every other host does, so an over-long or NUL-bearing
            // SNI is rejected here rather than downstream.
            return std::str::from_utf8(name)
                .ok()
                .and_then(|host| crate::DomainName::new(host).ok());
        }
    }
    None
}

/// A forward cursor over untrusted bytes. Every accessor is total: it returns
/// `None` rather than panicking, so the parser above never indexes.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let taken = self.bytes.get(..length)?;
        self.bytes = &self.bytes[length..];
        Some(taken)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|byte| byte[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u24(&mut self) -> Option<usize> {
        self.take(3).map(|bytes| {
            usize::from(bytes[0]) << 16 | usize::from(bytes[1]) << 8 | usize::from(bytes[2])
        })
    }

    /// A length-prefixed vector with a one-byte length, returning its body.
    fn vector_u8(&mut self) -> Option<&'a [u8]> {
        let length = usize::from(self.u8()?);
        self.take(length)
    }

    /// A length-prefixed vector with a two-byte length, returning its body.
    fn vector_u16(&mut self) -> Option<&'a [u8]> {
        let length = usize::from(self.u16()?);
        self.take(length)
    }
}

/// Brotli certificate decompression, RFC 8879.
///
/// Advertised only when the mirrored client advertised it, and decompression
/// only: `CAN_COMPRESS` is false because this side never sends a certificate
/// chain to the origin. The decoder is the one the HTML tier already carries,
/// so nothing new enters the artefact.
struct Brotli;

impl CertificateCompressor for Brotli {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W>(&self, _input: &[u8], _output: &mut W) -> io::Result<()>
    where
        W: io::Write,
    {
        Err(io::Error::other("this side never compresses a certificate"))
    }

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
    where
        W: io::Write,
    {
        let mut writer = brotli_decompressor::DecompressorWriter::new(output, BROTLI_BUFFER);
        io::Write::write_all(&mut writer, input)?;
        writer
            .into_inner()
            .map(|_| ())
            .map_err(|_| io::Error::other("truncated compressed certificate"))
    }
}

/// Matches the HTML tier's decoder window, and is the size RFC 7932 names as
/// sufficient for any stream a compliant encoder produces.
const BROTLI_BUFFER: usize = 64 * 1024;

/// Why an upstream TLS client could not be built.
///
/// Configuration failures, decided before a packet moves — distinct from a
/// handshake that failed, which is evidence [`classify`](crate::classify) reads.
#[derive(Debug)]
pub enum MirrorError {
    /// A trust anchor did not parse as a DER certificate.
    Anchor,
    /// BoringSSL refused the configuration.
    Configuration(ErrorStack),
}

impl std::fmt::Display for MirrorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Anchor => f.write_str("a trust anchor is not a DER certificate"),
            Self::Configuration(error) => write!(f, "BoringSSL refused the configuration: {error}"),
        }
    }
}

impl std::error::Error for MirrorError {}

impl From<ErrorStack> for MirrorError {
    fn from(error: ErrorStack) -> Self {
        Self::Configuration(error)
    }
}

/// What identifies a built connector: everything that shapes the hello.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Key {
    profile: ClientProfile,
    alpn: Vec<u8>,
}

/// Opens TLS to a remote server, wearing a mirrored ClientHello.
///
/// One of these is shared across connections. Building a connector parses the
/// trust anchors, which is not a per-connection cost, so the built connectors
/// are memoised on the profile and ALPN that shaped them — the two things that
/// vary and the only two.
pub struct Originator {
    /// Trust anchors beyond the bundled Mozilla set, DER-encoded. Empty in the
    /// ordinary case; a self-hosted server behind a private CA is why it exists.
    extra: Vec<Vec<u8>>,
    connectors: Mutex<HashMap<Key, Arc<SslConnector>>>,
}

impl Originator {
    #[must_use]
    pub fn new() -> Self {
        Self {
            extra: Vec::new(),
            connectors: Mutex::new(HashMap::new()),
        }
    }

    /// Trusts `extra` in addition to the bundled anchors, DER-encoded.
    ///
    /// The honest answer to a private CA is to name it. There is deliberately
    /// no "skip verification" switch, which is the same feature with no way to
    /// tell a configured exception from an attack.
    #[must_use]
    pub fn with_extra_roots(mut self, extra: &[Vec<u8>]) -> Self {
        self.extra = extra.to_vec();
        self
    }

    /// The connector for one profile and one ALPN offer, built once.
    fn connector(
        &self,
        profile: &ClientProfile,
        alpn: &[u8],
    ) -> Result<Arc<SslConnector>, MirrorError> {
        let key = Key {
            profile: profile.clone(),
            alpn: alpn.to_vec(),
        };
        // The lock is held across a build on a miss. That is deliberate: the
        // critical section holds no `.await`, a build is microseconds against a
        // handshake's milliseconds, and letting two connections race to build
        // the same connector would spend more.
        let mut connectors = crate::locked(&self.connectors);
        if let Some(existing) = connectors.get(&key) {
            return Ok(Arc::clone(existing));
        }
        let built = Arc::new(self.build(profile, alpn)?);
        if connectors.len() >= MAX_CACHED_CONNECTORS {
            connectors.clear();
        }
        connectors.insert(key, Arc::clone(&built));
        Ok(built)
    }

    fn build(&self, profile: &ClientProfile, alpn: &[u8]) -> Result<SslConnector, MirrorError> {
        let mut builder = SslConnector::builder(SslMethod::tls())?;

        // The anchors are Mozilla's bundle rather than the platform store, for
        // the reason the DNS upstreams give: the set this crate verifies
        // against should not be one a device owner or an MDM profile can widen.
        // `SslConnector::builder` has already called `set_default_verify_paths`,
        // so replacing the store outright is what makes that true.
        let mut store = X509StoreBuilder::new()?;
        for anchor in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
            store.add_cert(X509::from_der(anchor).map_err(|_| MirrorError::Anchor)?)?;
        }
        for anchor in &self.extra {
            store.add_cert(X509::from_der(anchor).map_err(|_| MirrorError::Anchor)?)?;
        }
        builder.set_cert_store_ref(&store.build());

        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_alpn_protos(alpn)?;

        // Everything below is the mirror, and every arm is a no-op when the
        // hello did not say — so an unparsed hello leaves BoringSSL's defaults
        // exactly as they were.
        if !profile.groups.is_empty() {
            builder.set_curves_list(&profile.groups.join(":"))?;
        }
        if !profile.sigalgs.is_empty() {
            let prefs: Vec<SslSignatureAlgorithm> = profile
                .sigalgs
                .iter()
                .copied()
                .map(SslSignatureAlgorithm::from)
                .collect();
            builder.set_verify_algorithm_prefs(&prefs)?;
        }
        if profile.compresses_certificates() {
            builder.add_certificate_compression_algorithm(Brotli)?;
        }
        builder.set_grease_enabled(profile.grease);
        // Chrome permutes its extensions per connection, so a fixed order would
        // be the anomaly. This reproduces the behaviour rather than a hash.
        builder.set_permute_extensions(true);

        Ok(builder.build())
    }

    /// Opens TLS over `stream` to `host`, offering exactly `alpn`.
    ///
    /// `alpn` is the wire-format protocol list — each entry a one-byte length
    /// followed by its name — and it is the caller's decision, never the
    /// profile's. [`alpn_for`] builds it from a [`Wire`](crate::Wire).
    ///
    /// Cancellation-safe in the sense the caller needs: dropping the future
    /// drops the connection, and no state outside it has been mutated.
    pub async fn connect<S>(
        &self,
        host: &str,
        profile: &ClientProfile,
        alpn: &[u8],
        stream: S,
    ) -> Result<tokio_boring::SslStream<Opaque<S>>, io::Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let connector = self
            .connector(profile, alpn)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let configuration = connector
            .configure()
            .map_err(|error| io::Error::other(error.to_string()))?;
        // **Every TLS handshake this crate originates passes here**, so the
        // bound is stated once: the upstream leg of an intercepted session, the
        // TLS under a V2Ray transport, and DoT and DoH alike. A handshake is a
        // wait on a peer that a vanished mobile path never ends.
        crate::within(crate::Wait::TlsHandshake, async {
            tokio_boring::connect(configuration, host, Opaque(stream))
                .await
                .map_err(handshake_error)
        })
        .await
    }
}

impl Default for Originator {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Originator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Originator")
            .field("extra_roots", &self.extra.len())
            .finish_non_exhaustive()
    }
}

/// The SSL library's slot in BoringSSL's packed error codes. The reason
/// numbers below are that library's own numbering and other libraries reuse
/// those integers for unrelated things, so the library is checked before a
/// reason is believed.
const SSL_LIBRARY: boring::error::ErrLib = boring::error::ErrLib(16);

/// BoringSSL's reason code for a chain this side would not verify.
const REASON_CERTIFICATE_VERIFY_FAILED: i32 = 125;
/// ...for finding no application protocol in common.
const REASON_NO_APPLICATION_PROTOCOL: i32 = 307;
/// A received alert is reported as this offset plus the alert's own
/// description byte, which is what makes one subtraction enough to recover it.
const REASON_ALERT_OFFSET: i32 = 1000;

/// What a failed handshake proved, in the terms demotion reads.
///
/// A closed sum, and the three arms are separate because their remedies are:
/// an alert is the peer refusing *us*, [`Self::Untrusted`] is this side
/// refusing *the peer*, and [`Self::NoProtocol`] is neither party being at
/// fault. Flattening them to a message would leave
/// [`classify`](crate::classify) nothing to read and silently disable half of
/// the demotion lattice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The peer sent a fatal alert carrying this description byte.
    Alert(u8),
    /// This side rejected the server's certificate chain.
    Untrusted,
    /// No application protocol in common.
    NoProtocol,
}

/// A TLS handshake failure, keeping BoringSSL's verdict rather than its prose.
#[derive(Debug)]
pub struct HandshakeFailure {
    pub refusal: Option<Refusal>,
    detail: String,
}

impl HandshakeFailure {
    /// Builds one directly, which is how a test synthesizes the evidence a
    /// real handshake would have produced without standing up a hostile server.
    #[must_use]
    pub fn new(refusal: Option<Refusal>, detail: impl Into<String>) -> Self {
        Self {
            refusal,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for HandshakeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for HandshakeFailure {}

/// Turns a failed handshake into an [`io::Error`] that still carries the
/// verdict.
///
/// A transport-level failure keeps its own [`io::ErrorKind`], because a reset
/// or a timeout proves nothing about whether interception works and must not
/// demote a host.
fn handshake_error<S: std::fmt::Debug>(error: tokio_boring::HandshakeError<S>) -> io::Error {
    if let Some(io) = error.as_io_error() {
        return io::Error::new(io.kind(), io.to_string());
    }
    io::Error::other(HandshakeFailure {
        refusal: refusal(&error),
        detail: error.to_string(),
    })
}

/// Reads the first reason in BoringSSL's error stack this module understands.
///
/// The stack is ordered innermost-first, so the first recognised entry is the
/// one that actually stopped the handshake; entries this does not recognise are
/// skipped rather than treated as evidence.
fn refusal<S: std::fmt::Debug>(error: &tokio_boring::HandshakeError<S>) -> Option<Refusal> {
    let source = std::error::Error::source(error)?;
    let stack = source.downcast_ref::<boring::ssl::Error>()?.ssl_error()?;
    stack
        .errors()
        .iter()
        // The reason codes below are the SSL library's own numbering, and other
        // libraries in the stack reuse those integers for unrelated things — so
        // the library is checked before the reason is believed.
        .filter(|entry| entry.library_reason(SSL_LIBRARY).is_some())
        .find_map(|entry| {
            Some(match entry.library_reason(SSL_LIBRARY)? {
                REASON_CERTIFICATE_VERIFY_FAILED => Refusal::Untrusted,
                REASON_NO_APPLICATION_PROTOCOL => Refusal::NoProtocol,
                reason if (REASON_ALERT_OFFSET..REASON_ALERT_OFFSET + 256).contains(&reason) => {
                    Refusal::Alert(u8::try_from(reason - REASON_ALERT_OFFSET).ok()?)
                }
                _ => return None,
            })
        })
}

/// A stream wearing a [`Debug`] it does not have.
///
/// `tokio-boring` exposes the BoringSSL error stack only through
/// [`std::error::Error::source`], which its `HandshakeError` implements just
/// for a `Debug` stream. The streams here are trait objects and are not
/// `Debug`, so rather than push that bound onto every caller — and onto the
/// egress trait — the requirement is satisfied locally by a wrapper that
/// prints nothing about the connection it carries.
pub struct Opaque<S>(S);

impl<S> std::fmt::Debug for Opaque<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("stream")
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Opaque<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Opaque<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// The wire-format encoding of an ALPN protocol list: each name prefixed by its
/// one-byte length. A name longer than 255 bytes cannot be encoded and is
/// dropped, which is not reachable from any caller here.
#[must_use]
pub fn alpn_list(protocols: &[&[u8]]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(protocols.iter().map(|protocol| protocol.len() + 1).sum());
    for protocol in protocols {
        let Ok(length) = u8::try_from(protocol.len()) else {
            continue;
        };
        encoded.push(length);
        encoded.extend_from_slice(protocol);
    }
    encoded
}

// ------------------------------------------------------- HTTP/2 preface

/// HTTP/2's own initial connection window (RFC 9113 §6.9.2). Every endpoint
/// starts here, so the WINDOW_UPDATE a fingerprint reads is the target less
/// this.
const SPEC_WINDOW_SIZE: u32 = 65_535;

/// The pseudo-header order every browser sends, and the Akamai fingerprint's
/// fourth field.
///
/// A constant rather than a setting because nothing in this process decides it:
/// h2 hard-codes the order, and `vendor/patches/h2.patch` is what makes this
/// string true. `exchange::tests` asserts it against the wire.
const PSEUDO_HEADER_ORDER: &str = "m,a,s,p";

/// `SETTINGS_ENABLE_PUSH`. hyper disables push unconditionally and so does
/// Chrome, so there is no knob here and no disagreement to model.
const ENABLE_PUSH: u32 = 0;

/// The HTTP/2 connection preface a client is fingerprinted by.
///
/// **A value, so the fingerprint is a test rather than a habit.** The Akamai
/// fingerprint reads four fields — SETTINGS, the connection WINDOW_UPDATE,
/// PRIORITY, and pseudo-header order. The first two are this struct, the third
/// is `0` for any client that sends no PRIORITY frame, and the fourth is
/// [`PSEUDO_HEADER_ORDER`]. [`Self::akamai`] renders all four, which is what
/// lets a test compare one string against Chrome's published one instead of
/// trusting six loose constants to stay in agreement.
///
/// **An `Option` field models presence, not a default.** Chrome sends no
/// `MAX_CONCURRENT_STREAMS` and no `MAX_FRAME_SIZE`, and *sending* either is as
/// distinguishing as sending a wrong value — so `None` means the setting is
/// absent from the frame. The two non-`Option` fields are the ones hyper always
/// emits and offers no way to suppress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct H2Profile {
    /// `SETTINGS_HEADER_TABLE_SIZE` (1): the HPACK dynamic table this endpoint
    /// will maintain, which bounds what the *peer's* encoder may use. `None`
    /// leaves HPACK's own 4096.
    pub header_table_size: Option<u32>,
    /// `SETTINGS_MAX_CONCURRENT_STREAMS` (3).
    pub max_concurrent_streams: Option<u32>,
    /// `SETTINGS_INITIAL_WINDOW_SIZE` (4): the per-stream receive window.
    pub initial_window_size: u32,
    /// `SETTINGS_MAX_FRAME_SIZE` (5). `None` is what Chrome does, and costs
    /// nothing: the value it would carry is the protocol default anyway.
    pub max_frame_size: Option<u32>,
    /// `SETTINGS_MAX_HEADER_LIST_SIZE` (6): the largest *uncompressed* header
    /// block this endpoint accepts. Not a dictionary, despite living next to
    /// one.
    pub max_header_list_size: u32,
    /// The connection-level receive window, which a client raises with a
    /// WINDOW_UPDATE on stream 0 straight after its SETTINGS. Not a setting;
    /// see [`Self::window_increment`].
    pub connection_window_size: u32,
}

impl H2Profile {
    /// Chrome's preface, unchanged from Chrome 124 through at least 147.
    ///
    /// The windows are Chromium's `kSpdyStreamMaxRecvWindowSize` and
    /// `kSpdySessionMaxRecvWindowSize`; `1` and `6` are `kSpdyMaxHeaderTableSize`
    /// and `kSpdyMaxHeaderListSize`. `3` and `5` are absent because
    /// `AddDefaultHttp2Settings` never sets them.
    pub const CHROME: Self = Self {
        header_table_size: Some(64 * 1024),
        max_concurrent_streams: None,
        initial_window_size: 6 * 1024 * 1024,
        max_frame_size: None,
        max_header_list_size: 256 * 1024,
        connection_window_size: 15 * 1024 * 1024,
    };

    /// The WINDOW_UPDATE increment this profile sends on stream 0.
    #[must_use]
    pub const fn window_increment(&self) -> u32 {
        self.connection_window_size.saturating_sub(SPEC_WINDOW_SIZE)
    }

    /// The SETTINGS this profile puts on the wire, paired with their
    /// identifiers and in ascending order — which is the order h2 encodes them
    /// and therefore the order a fingerprint reads them.
    const fn settings(&self) -> [(u16, Option<u32>); 6] {
        [
            (1, self.header_table_size),
            (2, Some(ENABLE_PUSH)),
            (3, self.max_concurrent_streams),
            (4, Some(self.initial_window_size)),
            (5, self.max_frame_size),
            (6, Some(self.max_header_list_size)),
        ]
    }

    /// This preface in the Akamai fingerprint's notation:
    /// `SETTINGS|WINDOW_UPDATE|PRIORITY|PSEUDO_HEADER_ORDER`.
    #[must_use]
    pub fn akamai(&self) -> String {
        let settings = self
            .settings()
            .into_iter()
            .filter_map(|(id, value)| Some(format!("{id}:{}", value?)))
            .collect::<Vec<_>>()
            .join(";");
        // PRIORITY is `0`: no client here sends a PRIORITY frame, and neither
        // does Chrome since it moved to RFC 9218 priority signalling.
        format!(
            "{settings}|{}|0|{PSEUDO_HEADER_ORDER}",
            self.window_increment()
        )
    }

    /// Configures a hyper HTTP/2 client to open connections with this preface.
    pub fn apply<'a, E: Clone>(&self, builder: &'a mut H2Builder<E>) -> &'a mut H2Builder<E> {
        builder
            .header_table_size(self.header_table_size)
            .max_concurrent_streams(self.max_concurrent_streams)
            .initial_stream_window_size(self.initial_window_size)
            .initial_connection_window_size(self.connection_window_size)
            .max_frame_size(self.max_frame_size)
            .max_header_list_size(self.max_header_list_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Chrome's published fingerprint, verbatim. Six constants can each look
    /// plausible alone; this is the one assertion that fails by naming which
    /// field moved.
    #[test]
    fn the_chrome_profile_renders_chromes_published_fingerprint() {
        assert_eq!(
            H2Profile::CHROME.akamai(),
            "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
        );
    }

    /// A `None` setting is absent from the frame rather than sent with a
    /// default, because sending it at all is what a fingerprint sees.
    #[test]
    fn an_absent_setting_is_omitted_rather_than_defaulted() {
        let profile = H2Profile {
            header_table_size: None,
            max_frame_size: Some(16_384),
            max_concurrent_streams: Some(1000),
            ..H2Profile::CHROME
        };
        assert!(
            profile
                .akamai()
                .starts_with("2:0;3:1000;4:6291456;5:16384;6:262144|")
        );
    }

    /// GREASE is the sixteen values RFC 8701 reserves, and nothing else. A
    /// looser test would let an ordinary extension set the flag.
    #[test]
    fn grease_is_exactly_the_reserved_values() {
        for nibble in 0..16u16 {
            assert!(is_grease(nibble << 12 | 0x0a00 | nibble << 4 | 0x0a));
        }
        for ordinary in [0x0000, 0x000a, 0x0a0b, 0x1a2a, 0x0017, 0x11ec, 0xffff] {
            assert!(!is_grease(ordinary), "{ordinary:#06x}");
        }
    }

    /// The whole point of the mirror: a hello that offers MLKEM produces a
    /// profile that asks for it. BoringSSL's default group list does not
    /// include it, so without this the upstream hello could not carry it.
    #[test]
    fn a_profile_carries_the_groups_the_client_offered() {
        let profile = profile_from(&[extension(
            EXTENSION_SUPPORTED_GROUPS,
            &vector_u16(&[0x11ec, 29, 23]),
        )]);
        assert_eq!(profile.groups(), ["X25519MLKEM768", "X25519", "P-256"]);
    }

    /// A group this BoringSSL cannot name is dropped rather than refused, so
    /// an unfamiliar client still gets a handshake — the same fail-open the
    /// rest of interception takes.
    #[test]
    fn an_unknown_group_is_dropped_not_fatal() {
        let profile = profile_from(&[extension(
            EXTENSION_SUPPORTED_GROUPS,
            &vector_u16(&[0xfefe, 29]),
        )]);
        assert_eq!(profile.groups(), ["X25519"]);
    }

    /// GREASE codepoints are not signature algorithms, and forwarding one as a
    /// verification preference would ask BoringSSL to accept a nonexistent
    /// algorithm.
    #[test]
    fn grease_is_stripped_from_signature_algorithms() {
        let profile = profile_from(&[extension(
            EXTENSION_SIGNATURE_ALGORITHMS,
            &vector_u16(&[0x0a0a, 0x0403, 0x0804]),
        )]);
        assert_eq!(profile.sigalgs, [0x0403, 0x0804]);
        assert!(profile.grease, "the hello still counts as GREASE-bearing");
    }

    /// Bytes that are not a ClientHello yield the identity profile, which
    /// overrides nothing. That is what makes an unparsed hello safe.
    #[test]
    fn an_unreadable_hello_overrides_nothing() {
        for bytes in [b"".as_slice(), b"\x01", b"\x16\x03\x01", b"not tls at all"] {
            assert!(read_hello(bytes).profile.is_empty(), "{bytes:?}");
        }
    }

    /// The stated profile a leg with nothing to mirror wears. Asserted against
    /// the group that actually distinguishes it: an empty profile leaves
    /// BoringSSL's defaults, which cannot express `X25519MLKEM768` at all.
    #[test]
    fn the_chrome_profile_offers_the_group_the_default_one_cannot() {
        let chrome = ClientProfile::chrome();
        assert!(!chrome.is_empty());
        assert_eq!(chrome.groups()[0], "X25519MLKEM768");
        assert!(chrome.compresses_certificates());
        assert!(chrome.grease);
    }

    /// The client's list, in the client's order, so the origin makes the same
    /// choice it would have made for the client itself.
    #[test]
    fn an_offer_carries_the_clients_own_list_in_order() {
        let hello = read_hello(&client_hello(&[extension(
            EXTENSION_ALPN,
            &names(&[b"h2", b"http/1.1"]),
        )]));
        assert_eq!(hello.alpn.wires(), [crate::Wire::Http2, crate::Wire::Http1]);
        assert_eq!(hello.alpn.encode(), b"\x02h2\x08http/1.1");
    }

    /// `h3` rides QUIC, and this leg is TCP. Carrying it would let an origin
    /// select a protocol the exchange cannot serve.
    #[test]
    fn a_protocol_this_cannot_terminate_is_dropped() {
        let hello = read_hello(&client_hello(&[extension(
            EXTENSION_ALPN,
            &names(&[b"h3", b"http/1.1", b"h3"]),
        )]));
        assert_eq!(hello.alpn.wires(), [crate::Wire::Http1]);
    }

    /// No ALPN is an empty offer, which negotiates nothing on either leg —
    /// RFC 7301's reading, and what a bare HTTP/1.1 client expects.
    #[test]
    fn a_hello_without_alpn_offers_nothing() {
        let hello = read_hello(&client_hello(&[]));
        assert!(hello.alpn.wires().is_empty());
        assert!(hello.alpn.encode().is_empty());
    }

    /// A length-prefixed sequence of ALPN names, itself length-prefixed.
    fn names(protocols: &[&[u8]]) -> Vec<u8> {
        let body = alpn_list(protocols);
        let mut out = u16::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        out.extend(body);
        out
    }

    fn profile_from(extensions: &[Vec<u8>]) -> ClientProfile {
        read_hello(&client_hello(extensions)).profile
    }

    /// A two-byte-length-prefixed vector of codepoints.
    fn vector_u16(values: &[u16]) -> Vec<u8> {
        let body: Vec<u8> = values.iter().flat_map(|v| v.to_be_bytes()).collect();
        let mut out = u16::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        out.extend(body);
        out
    }

    fn extension(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut out = kind.to_be_bytes().to_vec();
        out.extend(u16::try_from(body.len()).unwrap().to_be_bytes());
        out.extend(body);
        out
    }

    /// A ClientHello handshake message carrying `extensions`.
    fn client_hello(extensions: &[Vec<u8>]) -> Vec<u8> {
        let joined: Vec<u8> = extensions.concat();
        let mut body = vec![0x03, 0x03];
        body.extend([0u8; 32]); // random
        body.push(0); // legacy_session_id
        body.extend(2u16.to_be_bytes()); // cipher_suites
        body.extend([0x13, 0x01]);
        body.extend([1, 0]); // legacy_compression_methods
        body.extend(u16::try_from(joined.len()).unwrap().to_be_bytes());
        body.extend(joined);

        let mut message = vec![HANDSHAKE_CLIENT_HELLO];
        let length = u32::try_from(body.len()).unwrap().to_be_bytes();
        message.extend(&length[1..]);
        message.extend(body);
        message
    }
}
