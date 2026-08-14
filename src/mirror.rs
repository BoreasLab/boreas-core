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
//! **ALPN is deliberately not mirrored.** The client's offer settles the wire,
//! and the upstream leg is then offered that one protocol and no other, which
//! is what makes a crossed HTTP version unrepresentable rather than merely
//! counted. [`Wire`](crate::Wire) owns that decision; a mirrored ALPN list would
//! quietly take it back.
//!
//! This closes the TLS half of the fingerprint. The HTTP/2 half — the Akamai
//! fingerprint, which is SETTINGS order, the connection WINDOW_UPDATE, and
//! pseudo-header order — is hyper's, and is not addressed here; see
//! [Delivery](../docs/delivery.md).

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
use tokio::io::{AsyncRead, AsyncWrite};

/// Handshake extensions this module reads out of a ClientHello.
const EXTENSION_SERVER_NAME: u16 = 0x0000;
const EXTENSION_SUPPORTED_GROUPS: u16 = 0x000a;
const EXTENSION_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXTENSION_COMPRESS_CERTIFICATE: u16 = 0x001b;

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
        let mut connectors = self.connectors.lock().expect("no panic holds this lock");
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
        tokio_boring::connect(configuration, host, Opaque(stream))
            .await
            .map_err(handshake_error)
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

/// The wire-format ALPN list offering exactly one protocol.
///
/// One, never two: offering the wire the client settled on and nothing else is
/// what makes a crossed HTTP version unrepresentable instead of merely counted.
#[must_use]
pub fn alpn_for(wire: crate::Wire) -> Vec<u8> {
    alpn_list(&[match wire {
        crate::Wire::Http1 => b"http/1.1".as_slice(),
        crate::Wire::Http2 => b"h2".as_slice(),
    }])
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

#[cfg(test)]
mod tests {
    use super::*;

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

    /// One protocol, never two: this is what keeps a crossed HTTP version
    /// unrepresentable rather than merely counted.
    #[test]
    fn alpn_offers_exactly_the_settled_wire() {
        assert_eq!(alpn_for(crate::Wire::Http2), b"\x02h2");
        assert_eq!(alpn_for(crate::Wire::Http1), b"\x08http/1.1");
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
