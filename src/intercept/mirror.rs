//! Originates upstream TLS with a mirrored ClientHello.
//!
//! Local TLS termination uses rustls. Every connection Boreas initiates uses
//! BoringSSL, which can reproduce the client profile or use
//! [`ClientProfile::chrome`] when no ClientHello exists to copy.
//!
//! Supported groups, signature algorithms, certificate compression, GREASE,
//! and ALPN are mirrored where the BoringSSL API permits. HTTP/2 uses the
//! fixed Chrome profile because the local preface is consumed before it can be
//! copied.

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
    x509::{
        X509,
        store::{X509Store, X509StoreBuilder},
    },
};
use hyper::client::conn::http2::Builder as H2Builder;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::wire::Reader;

const EXTENSION_SERVER_NAME: u16 = 0x0000;
const EXTENSION_SUPPORTED_GROUPS: u16 = 0x000a;
const EXTENSION_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXTENSION_COMPRESS_CERTIFICATE: u16 = 0x001b;
const EXTENSION_ALPN: u16 = 0x0010;

const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const NAME_TYPE_HOST: u8 = 0x00;

/// RFC 8879 Brotli certificate-compression identifier.
const BROTLI_ALGORITHM: u16 = 2;

/// Maximum number of cached (profile, ALPN) connectors.
const MAX_CACHED_CONNECTORS: usize = 16;

/// Whether a codepoint is an RFC 8701 GREASE value.
const fn is_grease(value: u16) -> bool {
    value >> 8 == value & 0x00ff && value & 0x000f == 0x000a
}

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

/// ClientHello features that can override BoringSSL defaults.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ClientProfile {
    /// Supported groups in client order.
    groups: Vec<&'static str>,
    /// Signature algorithms in client order.
    sigalgs: Vec<u16>,
    /// Advertised certificate-compression algorithms.
    compression: Vec<u16>,
    /// Whether the client advertised GREASE.
    grease: bool,
}

impl ClientProfile {
    /// Chrome profile for an originating leg with no ClientHello to mirror.
    #[must_use]
    pub fn chrome() -> Self {
        Self {
            groups: vec!["X25519MLKEM768", "X25519", "P-256", "P-384"],
            // Chrome's advertised signature-algorithm order.
            sigalgs: vec![
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ],
            compression: vec![BROTLI_ALGORITHM],
            grease: true,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    #[must_use]
    pub fn groups(&self) -> &[&'static str] {
        &self.groups
    }

    #[must_use]
    pub fn compresses_certificates(&self) -> bool {
        self.compression.contains(&BROTLI_ALGORITHM)
    }
}

/// Host, TLS profile, and ALPN extracted from one ClientHello.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Hello {
    pub host: Option<crate::DomainName>,
    pub profile: ClientProfile,
    pub alpn: Offer,
}

/// Client ALPN offer reduced to protocols Boreas can terminate.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Offer(Vec<crate::Wire>);

impl Offer {
    fn read(body: &[u8]) -> Self {
        let Some(list) = Reader::new(body).vector_u16() else {
            return Self::default();
        };
        let mut wires = Vec::new();
        let mut reader = Reader::new(list);
        while let Some(name) = reader.vector_u8() {
            // This TCP leg cannot carry HTTP/3.
            if let Some(wire) = crate::Wire::from_identifier(name)
                && !wires.contains(&wire)
            {
                wires.push(wire);
            }
        }
        Self(wires)
    }

    #[must_use]
    pub fn wires(&self) -> &[crate::Wire] {
        &self.0
    }

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let names: Vec<&[u8]> = self.0.iter().map(|wire| wire.identifier()).collect();
        alpn_list(&names)
    }
}

/// Reads a ClientHello record; malformed input yields the empty identity.
#[must_use]
pub fn read_hello(record: &[u8]) -> Hello {
    let mut hello = Hello::default();
    let mut reader = Reader::new(record);
    if reader.u8() != Some(HANDSHAKE_CLIENT_HELLO) {
        return hello;
    }
    // Fragmented ClientHello records are not reassembled.
    let Some(body) = reader
        .u24()
        .and_then(|length| reader.take(usize::try_from(length).ok()?))
    else {
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

    // Extensions are length-delimited and may repeat, so scan them in order.
    let mut reader = Reader::new(extensions);
    while let Some(kind) = reader.u16() {
        let Some(body) = reader.vector_u16() else {
            break;
        };
        hello.profile.grease |= is_grease(kind);
        match kind {
            EXTENSION_SERVER_NAME => hello.host = server_name(body),
            // Record GREASE, but do not forward GREASE algorithms.
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
                // Certificate compression uses a one-byte vector length.
                let mut inner = Reader::new(body);
                if let Some(list) = inner.vector_u8() {
                    hello.profile.compression = u16s(list).collect();
                }
            }
            _ => {}
        }
    }
    hello
}

fn u16s(body: &[u8]) -> impl Iterator<Item = u16> + '_ {
    let mut reader = Reader::new(body);
    std::iter::from_fn(move || reader.u16())
}

fn codepoints(body: &[u8]) -> impl Iterator<Item = u16> + '_ {
    u16s(Reader::new(body).vector_u16().unwrap_or_default())
}

fn server_name(body: &[u8]) -> Option<crate::DomainName> {
    // ServerNameList contains typed, length-prefixed names.
    let mut names = Reader::new(body.get(2..)?);
    while let Some(name_type) = names.u8() {
        let name = names.vector_u16()?;
        if name_type == NAME_TYPE_HOST {
            // Reuse the domain constructor for length and character checks.
            return std::str::from_utf8(name)
                .ok()
                .and_then(|host| crate::DomainName::new(host).ok());
        }
    }
    None
}

/// RFC 8879 Brotli certificate decompressor.
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

/// Decoder buffer size shared with the HTML tier.
const BROTLI_BUFFER: usize = 64 * 1024;

/// Reason an upstream TLS client could not be built.
#[derive(Debug)]
pub enum MirrorError {
    /// A trust anchor was not a DER certificate.
    Anchor,
    /// BoringSSL rejected the configuration.
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

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Key {
    profile: ClientProfile,
    alpn: Vec<u8>,
}

/// Opens TLS with a mirrored ClientHello and caches connectors by profile.
pub struct Originator {
    extra: Vec<Vec<u8>>,
    /// The bundled roots plus the extras, parsed once. `None` when an extra
    /// was not a certificate, which every connect then reports.
    store: Option<X509Store>,
    connectors: Mutex<HashMap<Key, Arc<SslConnector>>>,
}

impl Originator {
    #[must_use]
    pub fn new() -> Self {
        Self {
            extra: Vec::new(),
            store: trust(&[]).ok(),
            connectors: Mutex::new(HashMap::new()),
        }
    }

    /// Adds DER-encoded trust anchors to the bundled set.
    #[must_use]
    pub fn with_extra_roots(mut self, extra: &[Vec<u8>]) -> Self {
        self.extra = extra.to_vec();
        self.store = trust(extra).ok();
        self
    }

    fn connector(
        &self,
        profile: &ClientProfile,
        alpn: &[u8],
    ) -> Result<Arc<SslConnector>, MirrorError> {
        let key = Key {
            profile: profile.clone(),
            alpn: alpn.to_vec(),
        };
        if let Some(existing) = crate::locked(&self.connectors).get(&key) {
            return Ok(Arc::clone(existing));
        }
        // Built outside the lock: a miss, which a client can force by varying
        // its hello, holds nobody else up.
        let built = Arc::new(self.build(profile, alpn)?);
        let mut connectors = crate::locked(&self.connectors);
        if connectors.len() >= MAX_CACHED_CONNECTORS {
            connectors.clear();
        }
        Ok(Arc::clone(connectors.entry(key).or_insert(built)))
    }

    fn build(&self, profile: &ClientProfile, alpn: &[u8]) -> Result<SslConnector, MirrorError> {
        let mut builder = SslConnector::builder(SslMethod::tls())?;
        builder.set_cert_store_ref(self.store.as_ref().ok_or(MirrorError::Anchor)?);

        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_alpn_protos(alpn)?;

        // Empty profile fields leave BoringSSL defaults unchanged.
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
        // Chrome permutes extensions per connection.
        builder.set_permute_extensions(true);

        Ok(builder.build())
    }

    /// Opens TLS to `host` over `stream` with the supplied wire-format ALPN.
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
        // Bound every originating TLS handshake.
        crate::within(crate::Wait::TlsHandshake, async {
            tokio_boring::connect(configuration, host, Opaque(stream))
                .await
                .map_err(handshake_error)
        })
        .await
    }
}

/// The bundled roots plus `extra`, not the platform store.
fn trust(extra: &[Vec<u8>]) -> Result<X509Store, MirrorError> {
    let mut store = X509StoreBuilder::new()?;
    for anchor in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        store.add_cert(X509::from_der(anchor).map_err(|_| MirrorError::Anchor)?)?;
    }
    for anchor in extra {
        store.add_cert(X509::from_der(anchor).map_err(|_| MirrorError::Anchor)?)?;
    }
    Ok(store.build())
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

/// BoringSSL's SSL library identifier in packed error codes.
const SSL_LIBRARY: boring::error::ErrLib = boring::error::ErrLib(16);

/// BoringSSL reason for certificate verification failure.
const REASON_CERTIFICATE_VERIFY_FAILED: i32 = 125;
/// BoringSSL reason for no common application protocol.
const REASON_NO_APPLICATION_PROTOCOL: i32 = 307;
/// Offset used to encode a received TLS alert description.
const REASON_ALERT_OFFSET: i32 = 1000;

/// Handshake evidence consumed by demotion policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Peer sent a fatal alert.
    Alert(u8),
    /// Local verification rejected the server certificate.
    Untrusted,
    /// No common application protocol.
    NoProtocol,
}

/// TLS handshake failure with the classified refusal.
#[derive(Debug)]
pub struct HandshakeFailure {
    pub refusal: Option<Refusal>,
    detail: String,
}

impl HandshakeFailure {
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

/// Converts a handshake failure while preserving transport errors and refusal evidence.
fn handshake_error<S: std::fmt::Debug>(error: tokio_boring::HandshakeError<S>) -> io::Error {
    if let Some(io) = error.as_io_error() {
        return io::Error::new(io.kind(), io.to_string());
    }
    io::Error::other(HandshakeFailure {
        refusal: refusal(&error),
        detail: error.to_string(),
    })
}

fn refusal<S: std::fmt::Debug>(error: &tokio_boring::HandshakeError<S>) -> Option<Refusal> {
    let source = std::error::Error::source(error)?;
    let stack = source.downcast_ref::<boring::ssl::Error>()?.ssl_error()?;
    stack
        .errors()
        .iter()
        // Reason values are meaningful only with the matching library id.
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

/// Adds a private `Debug` implementation around a non-debug stream.
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

/// Encodes ALPN names as one-byte-length-prefixed entries.
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

/// HTTP/2 initial connection window from RFC 9113 section 6.9.2.
const SPEC_WINDOW_SIZE: u32 = 65_535;

/// Pseudo-header order used by the Chrome HTTP/2 profile.
const PSEUDO_HEADER_ORDER: &str = "m,a,s,p";

/// `SETTINGS_ENABLE_PUSH`, disabled by hyper and Chrome.
const ENABLE_PUSH: u32 = 0;

/// HTTP/2 settings and connection window for a fingerprinted client.
///
/// `None` means the setting is absent from the frame, not defaulted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct H2Profile {
    /// `SETTINGS_HEADER_TABLE_SIZE` (1).
    pub header_table_size: Option<u32>,
    /// `SETTINGS_MAX_CONCURRENT_STREAMS` (3).
    pub max_concurrent_streams: Option<u32>,
    /// `SETTINGS_INITIAL_WINDOW_SIZE` (4).
    pub initial_window_size: u32,
    /// `SETTINGS_MAX_FRAME_SIZE` (5).
    pub max_frame_size: Option<u32>,
    /// `SETTINGS_MAX_HEADER_LIST_SIZE` (6).
    pub max_header_list_size: u32,
    /// Connection-level receive window advertised by `WINDOW_UPDATE`.
    pub connection_window_size: u32,
}

impl H2Profile {
    /// Chrome's HTTP/2 preface profile.
    pub const CHROME: Self = Self {
        header_table_size: Some(64 * 1024),
        max_concurrent_streams: None,
        initial_window_size: 6 * 1024 * 1024,
        max_frame_size: None,
        max_header_list_size: 256 * 1024,
        connection_window_size: 15 * 1024 * 1024,
    };

    /// WINDOW_UPDATE increment sent on stream 0.
    #[must_use]
    pub const fn window_increment(&self) -> u32 {
        self.connection_window_size.saturating_sub(SPEC_WINDOW_SIZE)
    }

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

    /// Renders the Akamai fingerprint notation.
    #[must_use]
    pub fn akamai(&self) -> String {
        let settings = self
            .settings()
            .into_iter()
            .filter_map(|(id, value)| Some(format!("{id}:{}", value?)))
            .collect::<Vec<_>>()
            .join(";");
        // No PRIORITY frame is sent.
        format!(
            "{settings}|{}|0|{PSEUDO_HEADER_ORDER}",
            self.window_increment()
        )
    }

    /// Applies this profile to a hyper HTTP/2 client.
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

    #[test]
    fn the_chrome_profile_renders_chromes_published_fingerprint() {
        assert_eq!(
            H2Profile::CHROME.akamai(),
            "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
        );
    }

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

    #[test]
    fn grease_is_exactly_the_reserved_values() {
        for nibble in 0..16u16 {
            assert!(is_grease(nibble << 12 | 0x0a00 | nibble << 4 | 0x0a));
        }
        for ordinary in [0x0000, 0x000a, 0x0a0b, 0x1a2a, 0x0017, 0x11ec, 0xffff] {
            assert!(!is_grease(ordinary), "{ordinary:#06x}");
        }
    }

    #[test]
    fn a_profile_carries_the_groups_the_client_offered() {
        let profile = profile_from(&[extension(
            EXTENSION_SUPPORTED_GROUPS,
            &vector_u16(&[0x11ec, 29, 23]),
        )]);
        assert_eq!(profile.groups(), ["X25519MLKEM768", "X25519", "P-256"]);
    }

    #[test]
    fn an_unknown_group_is_dropped_not_fatal() {
        let profile = profile_from(&[extension(
            EXTENSION_SUPPORTED_GROUPS,
            &vector_u16(&[0xfefe, 29]),
        )]);
        assert_eq!(profile.groups(), ["X25519"]);
    }

    #[test]
    fn grease_is_stripped_from_signature_algorithms() {
        let profile = profile_from(&[extension(
            EXTENSION_SIGNATURE_ALGORITHMS,
            &vector_u16(&[0x0a0a, 0x0403, 0x0804]),
        )]);
        assert_eq!(profile.sigalgs, [0x0403, 0x0804]);
        assert!(profile.grease, "the hello still counts as GREASE-bearing");
    }

    #[test]
    fn an_unreadable_hello_overrides_nothing() {
        for bytes in [b"".as_slice(), b"\x01", b"\x16\x03\x01", b"not tls at all"] {
            assert!(read_hello(bytes).profile.is_empty(), "{bytes:?}");
        }
    }

    #[test]
    fn the_chrome_profile_offers_the_group_the_default_one_cannot() {
        let chrome = ClientProfile::chrome();
        assert!(!chrome.is_empty());
        assert_eq!(chrome.groups()[0], "X25519MLKEM768");
        assert!(chrome.compresses_certificates());
        assert!(chrome.grease);
    }

    #[test]
    fn an_offer_carries_the_clients_own_list_in_order() {
        let hello = read_hello(&client_hello(&[extension(
            EXTENSION_ALPN,
            &names(&[b"h2", b"http/1.1"]),
        )]));
        assert_eq!(hello.alpn.wires(), [crate::Wire::Http2, crate::Wire::Http1]);
        assert_eq!(hello.alpn.encode(), b"\x02h2\x08http/1.1");
    }

    #[test]
    fn a_protocol_this_cannot_terminate_is_dropped() {
        let hello = read_hello(&client_hello(&[extension(
            EXTENSION_ALPN,
            &names(&[b"h3", b"http/1.1", b"h3"]),
        )]));
        assert_eq!(hello.alpn.wires(), [crate::Wire::Http1]);
    }

    #[test]
    fn a_hello_without_alpn_offers_nothing() {
        let hello = read_hello(&client_hello(&[]));
        assert!(hello.alpn.wires().is_empty());
        assert!(hello.alpn.encode().is_empty());
    }

    fn names(protocols: &[&[u8]]) -> Vec<u8> {
        let body = alpn_list(protocols);
        let mut out = u16::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        out.extend(body);
        out
    }

    fn profile_from(extensions: &[Vec<u8>]) -> ClientProfile {
        read_hello(&client_hello(extensions)).profile
    }

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
