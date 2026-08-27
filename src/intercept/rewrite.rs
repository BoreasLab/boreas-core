//! P16 HTML rewriting with bounded, fail-open streaming.
//!
//! [`Rewritable`] is decided from headers before decoding. Limits cover held
//! parser state, graceful bail-outs flush it, and ambiguous markup ends
//! visibly. Injected styles use one CSP hash; `integrity=` elements stay put.

use std::{
    collections::BTreeSet,
    fmt,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http::{
    HeaderMap, HeaderValue, Response, StatusCode,
    header::{CONTENT_ENCODING, CONTENT_TYPE},
};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame};
use lol_html::{
    AsciiCompatibleEncoding, MemorySettings, OutputSink, Selector,
    errors::RewritingError,
    send::{Element, HtmlRewriter, Settings},
};

use crate::ProxyBody;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

// Report-only policies do not block; widening them would change their reports.
const CSP: &str = "content-security-policy";

// ---------------------------------------------------------------------------
// Rewritability
// ---------------------------------------------------------------------------

/// Why a response body is forwarded unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotRewritable {
    /// The status has no complete response body.
    NoWholeBody,
    /// The media type is not HTML.
    NotHtml,
    /// The content coding is unsupported or stacked.
    ContentCoded,
    /// The declared charset is unsupported.
    UnsupportedCharset,
}

impl fmt::Display for NotRewritable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoWholeBody => "the response carries no whole body",
            Self::NotHtml => "the response is not text/html",
            Self::ContentCoded => "the body carries an unreadable content coding",
            Self::UnsupportedCharset => "the character encoding is not ASCII-compatible",
        })
    }
}

/// Content codings this build can decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coding {
    /// No coding or `identity`.
    Identity,
    /// RFC 1952 gzip.
    Gzip,
    /// RFC 1950 zlib, named `deflate` on the wire.
    Deflate,
    /// RFC 7932 Brotli.
    Brotli,
    /// RFC 8878 Zstandard.
    Zstd,
}

impl Coding {
    /// Parses one `Content-Encoding` token.
    fn from_token(token: &str) -> Option<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "" | "identity" => Some(Self::Identity),
            "gzip" | "x-gzip" => Some(Self::Gzip),
            "deflate" => Some(Self::Deflate),
            "br" => Some(Self::Brotli),
            "zstd" => Some(Self::Zstd),
            _ => None,
        }
    }
}

/// Validated permission to rewrite and decode a response body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rewritable {
    encoding: AsciiCompatibleEncoding,
    coding: Coding,
}

impl Rewritable {
    /// Returns the content coding.
    #[must_use]
    pub fn coding(self) -> Coding {
        self.coding
    }
}

/// Parses response headers into a rewritable body description.
pub fn rewritable(status: StatusCode, headers: &HeaderMap) -> Result<Rewritable, NotRewritable> {
    if status.is_informational()
        || matches!(
            status,
            StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED | StatusCode::PARTIAL_CONTENT
        )
    {
        return Err(NotRewritable::NoWholeBody);
    }
    // Stacked non-identity codings pass through because only one is decoded.
    let mut coding = Coding::Identity;
    for token in headers
        .get_all(CONTENT_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
    {
        match (coding, Coding::from_token(token)) {
            (_, None) => return Err(NotRewritable::ContentCoded),
            (_, Some(Coding::Identity)) => {}
            (Coding::Identity, Some(named)) => coding = named,
            // This decoder handles only one non-identity coding.
            (_, Some(_)) => return Err(NotRewritable::ContentCoded),
        }
    }

    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .ok_or(NotRewritable::NotHtml)?;
    let (media, charset) = media_type(content_type);
    if !media.eq_ignore_ascii_case("text/html") {
        return Err(NotRewritable::NotHtml);
    }
    let encoding = match charset {
        // Match browser handling of a declared charset.
        None => AsciiCompatibleEncoding::utf_8(),
        Some(label) => encoding_rs::Encoding::for_label_no_replacement(label.as_bytes())
            .and_then(AsciiCompatibleEncoding::new)
            .ok_or(NotRewritable::UnsupportedCharset)?,
    };
    Ok(Rewritable { encoding, coding })
}

/// Splits a media type from its `charset` parameter.
fn media_type(value: &str) -> (&str, Option<&str>) {
    let mut parts = value.split(';');
    let media = parts.next().unwrap_or_default().trim();
    let charset = parts.find_map(|parameter| {
        let (name, value) = parameter.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("charset")
            .then(|| value.trim().trim_matches('"'))
    });
    (media, charset)
}

// ---------------------------------------------------------------------------
// Content-Security-Policy
// ---------------------------------------------------------------------------

/// CSP result for one inline stylesheet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InlineStyle {
    /// The policy already permits it.
    Granted,
    /// The policy gains its hash.
    Widened(String),
    /// The policy forbids inline styles; no stylesheet is injected.
    Refused,
}

// The most specific directive governs a <style> element.
const STYLE_DIRECTIVES: [&str; 2] = ["style-src-elem", "style-src"];
const FALLBACK_DIRECTIVE: &str = "default-src";

/// Adds `source` to the governing style directive when required.
#[must_use]
pub fn permit_inline_style(policy: &str, source: &str) -> InlineStyle {
    let directives: Vec<&str> = policy
        .split(';')
        .map(str::trim)
        .filter(|directive| !directive.is_empty())
        .collect();

    let governing = STYLE_DIRECTIVES
        .iter()
        .find_map(|name| position(&directives, name))
        .map(|index| (index, false));
    let Some((index, inherited)) =
        governing.or_else(|| position(&directives, FALLBACK_DIRECTIVE).map(|index| (index, true)))
    else {
        return InlineStyle::Granted;
    };

    let sources: Vec<&str> = directives[index].split_whitespace().skip(1).collect();
    if sources
        .iter()
        .any(|value| value.eq_ignore_ascii_case("'none'"))
    {
        return InlineStyle::Refused;
    }
    if sources.contains(&source) {
        return InlineStyle::Granted;
    }
    // Under CSP Level 3, a nonce or hash makes 'unsafe-inline' inert.
    let bound = sources.iter().any(|value| is_nonce_or_hash(value));
    if !bound
        && sources
            .iter()
            .any(|value| value.eq_ignore_ascii_case("'unsafe-inline'"))
    {
        return InlineStyle::Granted;
    }

    let mut widened: Vec<String> = directives.iter().map(|value| (*value).to_owned()).collect();
    if inherited {
        // Keep non-style resources governed by the original default-src.
        let mut style = String::from("style-src");
        for value in &sources {
            style.push(' ');
            style.push_str(value);
        }
        style.push(' ');
        style.push_str(source);
        widened.push(style);
    } else {
        widened[index] = format!("{} {source}", directives[index]);
    }
    InlineStyle::Widened(widened.join("; "))
}

/// Finds `name`, comparing only each directive's name token.
fn position(directives: &[&str], name: &str) -> Option<usize> {
    directives.iter().position(|directive| {
        directive
            .split_whitespace()
            .next()
            .is_some_and(|token| token.eq_ignore_ascii_case(name))
    })
}

fn is_nonce_or_hash(source: &str) -> bool {
    let source = source.trim_start_matches('\'');
    ["nonce-", "sha256-", "sha384-", "sha512-"]
        .iter()
        .any(|prefix| {
            source.len() > prefix.len() && source[..prefix.len()].eq_ignore_ascii_case(prefix)
        })
}

// ---------------------------------------------------------------------------
// Cosmetic rules
// ---------------------------------------------------------------------------

/// Compiled element-hiding rules for one host.
#[derive(Debug)]
pub struct HidingRules {
    selector: Selector,
    /// Deterministic `<style>` content named by `source`.
    style: String,
    /// CSP source expression naming [`Self::style`].
    source: String,
    count: usize,
}

impl HidingRules {
    /// Compiles selectors, or returns `None` for an empty or invalid set.
    /// Sorting makes the stylesheet hash independent of input order.
    #[must_use]
    pub fn compile(selectors: impl IntoIterator<Item = String>) -> Option<Self> {
        let ordered: BTreeSet<String> = selectors.into_iter().collect();
        if ordered.is_empty() {
            return None;
        }
        let list = ordered
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(",");
        let selector = list.parse::<Selector>().ok()?;
        let style = format!("{list}{{display:none!important}}");
        let digest = ring::digest::digest(&ring::digest::SHA256, style.as_bytes());
        let source = format!("'sha256-{}'", STANDARD.encode(digest.as_ref()));
        Some(Self {
            selector,
            style,
            source,
            count: ordered.len(),
        })
    }

    /// Returns the stylesheet text named by [`Self::source`].
    #[must_use]
    pub fn style(&self) -> &str {
        &self.style
    }

    /// Returns the CSP source expression admitting [`Self::style`].
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns the number of compiled selectors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.count
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }
}

/// Source of compiled element-hiding rules.
///
/// Adblock Plus parsing belongs to [`RuleEngine`](crate::RuleEngine).
pub trait CosmeticSource: Send + Sync + 'static {
    /// Returns rules for `host`, or `None` when none apply.
    fn rules(&self, host: &str) -> Option<Arc<HidingRules>>;
}

/// Rule source that hides nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoCosmetics;

impl CosmeticSource for NoCosmetics {
    fn rules(&self, _host: &str) -> Option<Arc<HidingRules>> {
        None
    }
}

// ---------------------------------------------------------------------------
// Budgets and reporting
// ---------------------------------------------------------------------------

/// Memory limits for one response rewriter.
#[derive(Clone, Copy, Debug)]
pub struct StreamBudget {
    /// Ceiling for buffered input and selector state.
    max_memory_bytes: usize,
    /// Initial parsing buffer, charged against the ceiling.
    parsing_buffer_bytes: usize,
}

/// Why a rewriting budget is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetError {
    /// The memory ceiling is zero.
    NoCeiling,
    /// The parsing buffer exceeds the memory ceiling.
    BufferExceedsCeiling { parsing: usize, ceiling: usize },
}

impl fmt::Display for BudgetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCeiling => f.write_str("a rewriting ceiling of zero rewrites nothing"),
            Self::BufferExceedsCeiling { parsing, ceiling } => write!(
                f,
                "a {parsing}-byte parsing buffer cannot fit under a {ceiling}-byte ceiling"
            ),
        }
    }
}

impl std::error::Error for BudgetError {}

impl StreamBudget {
    /// Constructs a budget after checking that its buffer fits the ceiling.
    pub fn new(max_memory_bytes: usize, parsing_buffer_bytes: usize) -> Result<Self, BudgetError> {
        match (max_memory_bytes, parsing_buffer_bytes) {
            (0, _) => Err(BudgetError::NoCeiling),
            (ceiling, parsing) if parsing > ceiling => {
                Err(BudgetError::BufferExceedsCeiling { parsing, ceiling })
            }
            _ => Ok(Self {
                max_memory_bytes,
                parsing_buffer_bytes,
            }),
        }
    }

    pub fn max_memory_bytes(self) -> usize {
        self.max_memory_bytes
    }

    pub fn parsing_buffer_bytes(self) -> usize {
        self.parsing_buffer_bytes
    }
}

impl Default for StreamBudget {
    fn default() -> Self {
        Self {
            max_memory_bytes: 2 * 1024 * 1024,
            parsing_buffer_bytes: 16 * 1024,
        }
    }
}

#[cfg(test)]
mod budget_tests {
    use super::*;

    #[test]
    fn a_budget_that_could_never_rewrite_is_refused_where_it_is_written() {
        assert_eq!(StreamBudget::new(0, 0).err(), Some(BudgetError::NoCeiling));
        assert_eq!(
            StreamBudget::new(1024, 4096).err(),
            Some(BudgetError::BufferExceedsCeiling {
                parsing: 4096,
                ceiling: 1024
            })
        );
        assert!(StreamBudget::new(1024, 1024).is_ok());

        let default = StreamBudget::default();
        assert!(
            StreamBudget::new(default.max_memory_bytes(), default.parsing_buffer_bytes()).is_ok(),
            "the default must be a budget its own constructor accepts"
        );
    }
}

/// Count of rewrites abandoned on one connection.
///
/// The session reads this after the exchange, so body polling cannot re-enter
/// session state.
#[derive(Debug, Default)]
pub struct RewriteFailures(AtomicU64);

impl RewriteFailures {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn record(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// Number of rewrites that gave up. Relaxed ordering suffices because this
    /// value only informs a later demotion decision.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// The rewriting body
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Content-coding decode
// ---------------------------------------------------------------------------

/// Maximum Brotli output staging buffer.
const BROTLI_BUFFER_BYTES: usize = 64 * 1024;

/// Largest zstd block with headers, per RFC 8878.
const ZSTD_STAGING_BYTES: usize = 128 * 1024 + 3 + 18;

/// Largest zstd window accepted before decoder allocation.
const ZSTD_WINDOW_BYTES: u64 = 8 * 1024 * 1024;

/// Maximum decoded output for one input chunk.
const MAX_DECODED_CHUNK_BYTES: usize = 8 * 1024 * 1024;

/// Returns whether `ruzstd` reported incomplete input.
fn incomplete(error: &ruzstd::decoding::errors::FrameDecoderError) -> bool {
    let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(error) = cause {
        if let Some(io) = error.downcast_ref::<std::io::Error>() {
            return io.kind() == std::io::ErrorKind::UnexpectedEof;
        }
        cause = error.source();
    }
    false
}

/// Push adapter for `ruzstd`'s pull decoder.
struct Zstd {
    frame: ruzstd::decoding::FrameDecoder,
    /// Compressed bytes waiting for a complete block.
    pending: Vec<u8>,
    plain: Vec<u8>,
    /// Distinguishes an uninitialized decoder from a finished frame.
    started: bool,
}

impl Zstd {
    fn new() -> Self {
        let mut frame = ruzstd::decoding::FrameDecoder::new();
        frame.set_max_window_size(ZSTD_WINDOW_BYTES);
        Self {
            frame,
            pending: Vec::new(),
            plain: Vec::new(),
            started: false,
        }
    }

    fn drain(&mut self, source: &[u8]) -> Result<usize, Undecodable> {
        let mut used = 0;
        while used < source.len() {
            // Bound each decoder call.
            let end = source.len().min(used + ZSTD_STAGING_BYTES);
            let (read, _) = match self.frame.decode_from_to(&source[used..end], &mut []) {
                Ok(progress) => progress,
                // A split frame header may complete in the next chunk.
                Err(error) if incomplete(&error) => break,
                Err(_) => return Err(Undecodable),
            };
            self.started = true;
            self.frame
                .collect_to_writer(&mut self.plain)
                .map_err(|_| Undecodable)?;
            if self.plain.len() > MAX_DECODED_CHUNK_BYTES {
                return Err(Undecodable);
            }
            // The checksum can precede its final four bytes.
            if read == 0 || read > end - used {
                break;
            }
            used += read;
        }
        // Reject a second frame instead of truncating it.
        if self.started && self.frame.is_finished() && used < source.len() {
            return Err(Undecodable);
        }
        Ok(used)
    }

    fn push(&mut self, chunk: &[u8]) -> Result<(), Undecodable> {
        if self.pending.is_empty() {
            // Retain only the incomplete remainder.
            let used = self.drain(chunk)?;
            self.pending.extend_from_slice(&chunk[used..]);
        } else {
            let mut held = std::mem::take(&mut self.pending);
            held.extend_from_slice(chunk);
            let used = self.drain(&held)?;
            self.pending = held;
            self.pending.drain(..used);
        }
        Ok(())
    }
}

/// Push decoder for one response body.
enum Decoder {
    Identity,
    Gzip(Box<flate2::write::GzDecoder<Vec<u8>>>),
    Deflate(Box<flate2::write::ZlibDecoder<Vec<u8>>>),
    Brotli(Box<brotli_decompressor::DecompressorWriter<Vec<u8>>>),
    Zstd(Box<Zstd>),
}

/// The compressed stream was malformed or truncated.
#[derive(Debug)]
pub struct Undecodable;

impl fmt::Display for Undecodable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the compressed body could not be decoded")
    }
}

impl std::error::Error for Undecodable {}

impl Decoder {
    fn new(coding: Coding) -> Self {
        match coding {
            Coding::Identity => Self::Identity,
            Coding::Gzip => Self::Gzip(Box::new(flate2::write::GzDecoder::new(Vec::new()))),
            Coding::Deflate => Self::Deflate(Box::new(flate2::write::ZlibDecoder::new(Vec::new()))),
            Coding::Brotli => Self::Brotli(Box::new(brotli_decompressor::DecompressorWriter::new(
                Vec::new(),
                BROTLI_BUFFER_BYTES,
            ))),
            Coding::Zstd => Self::Zstd(Box::new(Zstd::new())),
        }
    }

    /// Decodes a chunk and borrows plaintext from staging.
    fn decode<'a>(&'a mut self, chunk: &'a [u8]) -> Result<&'a [u8], Undecodable> {
        use std::io::Write;
        let plain: &[u8] = match self {
            Self::Identity => return Ok(chunk),
            Self::Gzip(decoder) => {
                decoder.write_all(chunk).map_err(|_| Undecodable)?;
                decoder.get_ref()
            }
            Self::Deflate(decoder) => {
                decoder.write_all(chunk).map_err(|_| Undecodable)?;
                decoder.get_ref()
            }
            Self::Brotli(decoder) => {
                decoder.write_all(chunk).map_err(|_| Undecodable)?;
                decoder.get_ref()
            }
            Self::Zstd(decoder) => {
                decoder.push(chunk)?;
                &decoder.plain
            }
        };
        (plain.len() <= MAX_DECODED_CHUNK_BYTES)
            .then_some(plain)
            .ok_or(Undecodable)
    }

    /// Finishes the stream and borrows its final bytes.
    fn finish(&mut self) -> Result<&[u8], Undecodable> {
        match self {
            Self::Identity => Ok(&[]),
            Self::Gzip(decoder) => {
                decoder.try_finish().map_err(|_| Undecodable)?;
                Ok(decoder.get_ref())
            }
            Self::Deflate(decoder) => {
                decoder.try_finish().map_err(|_| Undecodable)?;
                Ok(decoder.get_ref())
            }
            Self::Brotli(decoder) => {
                decoder.close().map_err(|_| Undecodable)?;
                Ok(decoder.get_ref())
            }
            Self::Zstd(decoder) => {
                (decoder.started && decoder.frame.is_finished() && decoder.pending.is_empty())
                    .then_some(decoder.plain.as_slice())
                    .ok_or(Undecodable)
            }
        }
    }

    /// Clears staged bytes while retaining the allocation.
    fn clear(&mut self) {
        match self {
            Self::Identity => {}
            Self::Gzip(decoder) => decoder.get_mut().clear(),
            Self::Deflate(decoder) => decoder.get_mut().clear(),
            Self::Brotli(decoder) => decoder.get_mut().clear(),
            Self::Zstd(decoder) => decoder.plain.clear(),
        }
    }

    fn is_identity(&self) -> bool {
        matches!(self, Self::Identity)
    }
}

#[derive(Clone)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl OutputSink for Sink {
    fn handle_chunk(&mut self, chunk: &[u8]) {
        self.0
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .extend_from_slice(chunk);
    }
}

/// The rewriter abandoned a document before completion.
#[derive(Debug)]
pub struct Truncated;

impl fmt::Display for Truncated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the rewriter abandoned the document mid-element")
    }
}

impl std::error::Error for Truncated {}

/// Body stages. A failed rewriter cannot be reused.
enum Stage {
    Rewriting(Box<HtmlRewriter<'static, Sink>>),
    /// Forward remaining bytes after a clean bail-out.
    Raw,
    Ended,
}

/// Response body with HTML rewriting applied.
/// The mutex supplies [`ProxyBody`]'s `Sync` bound; access remains mutable.
pub struct RewritingBody<B> {
    inner: B,
    stage: Mutex<Stage>,
    /// Decoding precedes rewriting because compressed bytes contain no HTML.
    decoder: Decoder,
    sink: Arc<Mutex<Vec<u8>>>,
    failures: Arc<RewriteFailures>,
}

impl<B> RewritingBody<B> {
    fn drain(&mut self) -> Option<Bytes> {
        let sink = self
            .sink
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let mut sink = sink;
        (!sink.is_empty()).then(|| Bytes::from(std::mem::take(&mut *sink)))
    }

    /// Decodes and rewrites one chunk, or forwards after a clean bail-out.
    fn feed(&mut self, data: &[u8]) -> Result<(), Truncated> {
        let Self {
            stage,
            decoder,
            sink,
            failures,
            ..
        } = self;
        let stage = stage.get_mut().unwrap_or_else(|poison| poison.into_inner());
        if matches!(stage, Stage::Ended) {
            return Ok(());
        }

        let decoded = match decoder.decode(data) {
            Ok(decoded) => decoded,
            Err(_) => {
                // Undecodable input ends the body visibly.
                failures.record();
                *stage = Stage::Ended;
                return Err(Truncated);
            }
        };

        let outcome = match stage {
            Stage::Rewriting(rewriter) => match rewriter.write(decoded) {
                Ok(()) => Ok(()),
                Err(error) => {
                    failures.record();
                    // An HtmlRewriter cannot be reused after an error.
                    let graceful = recoverable(&error);
                    *stage = if graceful { Stage::Raw } else { Stage::Ended };
                    graceful.then_some(()).ok_or(Truncated)
                }
            },
            Stage::Raw => {
                sink.lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .extend_from_slice(decoded);
                Ok(())
            }
            Stage::Ended => Ok(()),
        };
        decoder.clear();
        outcome
    }

    /// Finishes decoding and rewriting after the inner body is exhausted.
    fn finish(&mut self) -> Result<(), Truncated> {
        let Self {
            stage,
            decoder,
            sink,
            failures,
            ..
        } = self;
        let stage = stage.get_mut().unwrap_or_else(|poison| poison.into_inner());

        // Feed decoder tail bytes before ending the rewriter.
        let tail = match decoder.finish() {
            Ok(tail) => tail,
            Err(_) => {
                failures.record();
                *stage = Stage::Ended;
                return Err(Truncated);
            }
        };
        if !tail.is_empty() {
            match stage {
                Stage::Rewriting(rewriter) => {
                    if let Err(error) = rewriter.write(tail) {
                        failures.record();
                        let graceful = recoverable(&error);
                        *stage = if graceful { Stage::Raw } else { Stage::Ended };
                        if !graceful {
                            return Err(Truncated);
                        }
                    }
                }
                Stage::Raw => sink
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .extend_from_slice(tail),
                Stage::Ended => {}
            }
        }
        decoder.clear();

        let ending = std::mem::replace(stage, Stage::Ended);
        let Stage::Rewriting(rewriter) = ending else {
            return Ok(());
        };
        match (*rewriter).end() {
            Ok(()) => Ok(()),
            Err(error) => {
                failures.record();
                recoverable(&error).then_some(()).ok_or(Truncated)
            }
        }
    }

    fn ended(&mut self) -> bool {
        matches!(
            self.stage
                .get_mut()
                .unwrap_or_else(|poison| poison.into_inner()),
            Stage::Ended
        )
    }
}

/// Returns whether `lol_html` flushed held bytes before giving up.
fn recoverable(error: &RewritingError) -> bool {
    matches!(
        error,
        RewritingError::MemoryLimitExceeded(_) | RewritingError::ContentHandlerError(_)
    )
}

impl<B> Body for RewritingBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        loop {
            // One input frame may produce several output frames or none.
            if let Some(bytes) = this.drain() {
                return Poll::Ready(Some(Ok(Frame::data(bytes))));
            }
            if this.ended() {
                return Poll::Ready(None);
            }
            match std::task::ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
                None => {
                    if let Err(truncated) = this.finish() {
                        return Poll::Ready(Some(Err(Box::new(truncated))));
                    }
                }
                Some(Err(error)) => return Poll::Ready(Some(Err(error.into()))),
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) => {
                        if let Err(truncated) = this.feed(&data) {
                            return Poll::Ready(Some(Err(Box::new(truncated))));
                        }
                    }
                    // Trailers are outside the document.
                    Err(other) => return Poll::Ready(Some(Ok(other))),
                },
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The seam the exchange uses
// ---------------------------------------------------------------------------

/// HTML rewriting tier with a per-stream budget.
#[derive(Clone)]
pub enum Rewriting {
    /// Forward bodies untouched.
    Off,
    On {
        source: Arc<dyn CosmeticSource>,
        budget: StreamBudget,
        failures: Arc<RewriteFailures>,
    },
}

impl fmt::Debug for Rewriting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Off => f.write_str("Rewriting::Off"),
            Self::On { .. } => f.write_str("Rewriting::On"),
        }
    }
}

impl Rewriting {
    fn rules(&self, host: &str) -> Option<(Arc<HidingRules>, StreamBudget, Arc<RewriteFailures>)> {
        let Self::On {
            source,
            budget,
            failures,
        } = self
        else {
            return None;
        };
        source
            .rules(host)
            .map(|rules| (rules, *budget, Arc::clone(failures)))
    }

    /// Applies the tier to one response and updates its headers.
    pub fn apply<B>(&self, host: &str, response: Response<B>) -> Response<ProxyBody>
    where
        B: Body<Data = Bytes> + Unpin + Send + Sync + 'static,
        B::Error: Into<BoxError>,
    {
        let (mut parts, body) = response.into_parts();
        let Some((rules, budget, failures)) = self.rules(host) else {
            return Response::from_parts(parts, boxed(body));
        };
        // Unsupported bodies pass through unchanged.
        let Ok(rewritable) = rewritable(parts.status, &parts.headers) else {
            return Response::from_parts(parts, boxed(body));
        };

        let inject = relax_policy(&mut parts.headers, &rules.source);
        let decoder = Decoder::new(rewritable.coding);
        if !decoder.is_identity() {
            // Decoding invalidates coding and length headers; recompression is
            // unnecessary on the terminated leg.
            parts.headers.remove(CONTENT_ENCODING);
            parts.headers.remove(http::header::CONTENT_LENGTH);
        }
        let sink = Arc::new(Mutex::new(Vec::new()));
        let rewriter = build(&rules, rewritable, budget, inject, Sink(Arc::clone(&sink)));
        let body = RewritingBody {
            inner: body,
            stage: Mutex::new(Stage::Rewriting(Box::new(rewriter))),
            decoder,
            sink,
            failures,
        };
        Response::from_parts(parts, body.map_err(Into::into).boxed())
    }
}

fn boxed<B>(body: B) -> ProxyBody
where
    B: Body<Data = Bytes> + Send + Sync + 'static,
    B::Error: Into<BoxError>,
{
    body.map_err(Into::into).boxed()
}

/// Rebuilds CSP policies and reports whether injection remains allowed.
/// Policies intersect, so one refusal suppresses injection.
fn relax_policy(headers: &mut HeaderMap, source: &str) -> bool {
    let policies: Vec<String> = headers
        .get_all(CSP)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    if policies.is_empty() {
        return true;
    }

    let mut widened = Vec::with_capacity(policies.len());
    let mut inject = true;
    for policy in &policies {
        match permit_inline_style(policy, source) {
            InlineStyle::Granted => widened.push(policy.clone()),
            InlineStyle::Widened(value) => widened.push(value),
            InlineStyle::Refused => {
                inject = false;
                widened.push(policy.clone());
            }
        }
    }
    // An invalid rebuilt value suppresses injection but permits removal.
    let rebuilt: Option<Vec<HeaderValue>> = widened
        .iter()
        .map(|value| HeaderValue::from_str(value).ok())
        .collect();
    let Some(rebuilt) = rebuilt else {
        return false;
    };
    headers.remove(CSP);
    for value in rebuilt {
        headers.append(CSP, value);
    }
    inject
}

fn build(
    rules: &HidingRules,
    rewritable: Rewritable,
    budget: StreamBudget,
    inject: bool,
    sink: Sink,
) -> HtmlRewriter<'static, Sink> {
    let style = format!("<style>{}</style>", rules.style);
    let mut settings = Settings::new_send()
        .with_encoding(rewritable.encoding)
        // Follow a document-declared <meta charset>.
        .with_adjust_charset_on_meta_tag(true)
        // Stop on ambiguous markup rather than editing an unknown tree.
        .with_strict(true)
        .with_graceful_bail_out_on_content_handler_error(true)
        .with_memory_settings(
            MemorySettings::new()
                .with_max_allowed_memory_usage(budget.max_memory_bytes())
                .with_preallocated_parsing_buffer_size(budget.parsing_buffer_bytes())
                // Flush held bytes before giving up so the response stays whole.
                .with_graceful_bail_out_on_memory_limit_exceeded(true),
        )
        .append_element_content_handler((
            // The body outlives this call, so parsed components must be owned.
            std::borrow::Cow::Owned(rules.selector.clone()),
            lol_html::send::ElementContentHandlers::default().element(hide),
        ));
    if inject {
        settings = settings.append_element_content_handler((
            std::borrow::Cow::Owned("head".parse::<Selector>().expect("`head` is a selector")),
            lol_html::send::ElementContentHandlers::default().element(
                move |element: &mut Element<'_, '_>| {
                    element.prepend(&style, lol_html::html_content::ContentType::Html);
                    Ok(())
                },
            ),
        ));
    }
    HtmlRewriter::new(settings, sink)
}

/// Removes a matched element unless it carries `integrity=`.
fn hide(element: &mut Element<'_, '_>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !element.has_attribute("integrity") {
        element.remove();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    #[test]
    fn only_a_whole_uncompressed_html_body_is_rewritable() {
        assert!(
            rewritable(
                StatusCode::OK,
                &headers(&[("content-type", "text/html; charset=utf-8")])
            )
            .is_ok()
        );
        // Without a header charset, the document may declare one in <meta>.
        assert!(rewritable(StatusCode::OK, &headers(&[("content-type", "text/html")])).is_ok());

        assert_eq!(
            rewritable(
                StatusCode::OK,
                &headers(&[("content-type", "application/json")])
            ),
            Err(NotRewritable::NotHtml)
        );
        assert_eq!(
            rewritable(StatusCode::OK, &HeaderMap::new()),
            Err(NotRewritable::NotHtml),
            "an untyped body is not assumed to be a document"
        );
        for (label, expected) in [
            ("gzip", Coding::Gzip),
            ("x-gzip", Coding::Gzip),
            ("BR", Coding::Brotli),
            ("zstd", Coding::Zstd),
            ("deflate", Coding::Deflate),
            ("identity", Coding::Identity),
        ] {
            assert_eq!(
                rewritable(
                    StatusCode::OK,
                    &headers(&[("content-type", "text/html"), ("content-encoding", label)])
                )
                .map(Rewritable::coding),
                Ok(expected),
                "{label}"
            );
        }
        // Unsupported and stacked codings remain unchanged.
        for value in ["gzip, br", "compress", "br, gzip"] {
            assert_eq!(
                rewritable(
                    StatusCode::OK,
                    &headers(&[("content-type", "text/html"), ("content-encoding", value)])
                ),
                Err(NotRewritable::ContentCoded),
                "{value}"
            );
        }
        assert_eq!(
            rewritable(
                StatusCode::PARTIAL_CONTENT,
                &headers(&[("content-type", "text/html")])
            ),
            Err(NotRewritable::NoWholeBody),
            "a range is not a document"
        );
        assert_eq!(
            rewritable(
                StatusCode::NOT_MODIFIED,
                &headers(&[("content-type", "text/html")])
            ),
            Err(NotRewritable::NoWholeBody)
        );
    }

    /// Unsupported character encodings are refused, never guessed.
    #[test]
    fn unsupported_character_encodings_are_refused() {
        for charset in [
            "utf-16",
            "utf-16le",
            "utf-16be",
            "iso-2022-jp",
            "replacement",
        ] {
            assert_eq!(
                rewritable(
                    StatusCode::OK,
                    &headers(&[("content-type", &format!("text/html; charset={charset}"))])
                ),
                Err(NotRewritable::UnsupportedCharset),
                "{charset}"
            );
        }
        // Unknown labels are not replaced with a default encoding.
        assert_eq!(
            rewritable(
                StatusCode::OK,
                &headers(&[("content-type", "text/html; charset=invented-9")])
            ),
            Err(NotRewritable::UnsupportedCharset)
        );
        // ASCII-compatible labels work with or without quotes.
        for charset in ["utf-8", "\"windows-1252\"", "ISO-8859-1", "shift_jis"] {
            assert!(
                rewritable(
                    StatusCode::OK,
                    &headers(&[("content-type", &format!("text/html; charset={charset}"))])
                )
                .is_ok(),
                "{charset}"
            );
        }
    }

    const HASH: &str = "'sha256-AAAA'";

    #[test]
    fn a_policy_that_does_not_govern_styles_needs_no_change() {
        assert_eq!(
            permit_inline_style("script-src 'self'", HASH),
            InlineStyle::Granted
        );
        assert_eq!(permit_inline_style("", HASH), InlineStyle::Granted);
    }

    #[test]
    fn a_blocking_style_directive_is_widened_by_exactly_one_source() {
        assert_eq!(
            permit_inline_style("style-src 'self' https://cdn.example", HASH),
            InlineStyle::Widened(format!("style-src 'self' https://cdn.example {HASH}"))
        );
        // The specific directive wins; the other stays unchanged.
        assert_eq!(
            permit_inline_style("style-src 'self'; style-src-elem 'self'", HASH),
            InlineStyle::Widened(format!("style-src 'self'; style-src-elem 'self' {HASH}"))
        );
        // Unrelated directives retain their order.
        assert_eq!(
            permit_inline_style("default-src 'self'; style-src 'self'; img-src *", HASH),
            InlineStyle::Widened(format!(
                "default-src 'self'; style-src 'self' {HASH}; img-src *"
            ))
        );
    }

    /// A CSP hash or nonce makes Level 3 `'unsafe-inline'` conditional.
    #[test]
    fn a_policy_already_permitting_inline_styles_is_left_alone() {
        assert_eq!(
            permit_inline_style("style-src 'self' 'unsafe-inline'", HASH),
            InlineStyle::Granted
        );
        // With a nonce present, the added hash changes no other source.
        assert_eq!(
            permit_inline_style("style-src 'unsafe-inline' 'nonce-abc'", HASH),
            InlineStyle::Widened(format!("style-src 'unsafe-inline' 'nonce-abc' {HASH}"))
        );
        // An existing source is not duplicated.
        assert_eq!(
            permit_inline_style(&format!("style-src {HASH}"), HASH),
            InlineStyle::Granted
        );
    }

    /// A `default-src` fallback gets a narrower `style-src` directive.
    #[test]
    fn inheritance_emits_a_narrower_directive_rather_than_widening_the_fallback() {
        let widened = permit_inline_style("default-src 'self' https://cdn.example", HASH);
        assert_eq!(
            widened,
            InlineStyle::Widened(format!(
                "default-src 'self' https://cdn.example; style-src 'self' https://cdn.example {HASH}"
            ))
        );
        let InlineStyle::Widened(policy) = widened else {
            unreachable!()
        };
        assert!(
            policy.starts_with("default-src 'self' https://cdn.example;"),
            "the fallback must be byte-identical: {policy}"
        );
    }

    #[test]
    fn a_policy_forbidding_styles_outright_suppresses_the_injection() {
        assert_eq!(
            permit_inline_style("style-src 'none'", HASH),
            InlineStyle::Refused
        );
        assert_eq!(
            permit_inline_style("default-src 'none'", HASH),
            InlineStyle::Refused
        );
    }

    /// Widening inserts one source and removes none.
    #[test]
    fn widening_never_drops_a_source() {
        for policy in [
            "style-src 'self' https://a.example https://b.example",
            "default-src 'self'; script-src 'unsafe-eval'",
            "style-src-elem https://a.example; frame-ancestors 'self'",
            "style-src",
        ] {
            let InlineStyle::Widened(widened) = permit_inline_style(policy, HASH) else {
                panic!("{policy} should widen");
            };
            for source in policy.split([';', ' ']).filter(|s| !s.is_empty()) {
                assert!(widened.contains(source), "{policy} lost {source}");
            }
            assert!(!widened.contains("unsafe-inline"), "no keyword was added");
            assert_eq!(widened.matches(HASH).count(), 1, "exactly one insertion");
        }
    }

    /// The stylesheet hash is stable under selector reordering.
    #[test]
    fn the_hash_names_the_stylesheet_and_ignores_selector_order() {
        let one = HidingRules::compile(
            [".ad", "div[data-ad]", "#promo"]
                .into_iter()
                .map(str::to_owned),
        )
        .unwrap();
        let other = HidingRules::compile(
            ["#promo", ".ad", "div[data-ad]"]
                .into_iter()
                .map(str::to_owned),
        )
        .unwrap();

        assert_eq!(one.style(), other.style(), "order must not reach the bytes");
        assert_eq!(one.source(), other.source());
        assert_eq!(one.len(), 3);

        let expected = ring::digest::digest(&ring::digest::SHA256, one.style().as_bytes());
        assert_eq!(
            one.source(),
            format!("'sha256-{}'", STANDARD.encode(expected.as_ref()))
        );
    }

    /// Empty and invalid selector sets produce no rules.
    #[test]
    fn an_empty_or_unparseable_selector_set_compiles_to_nothing() {
        assert!(HidingRules::compile(std::iter::empty()).is_none());
        assert!(HidingRules::compile([String::from("[[[not-a-selector")]).is_none());
    }
}

#[cfg(test)]
mod streaming {
    use super::{tests::headers, *};
    use std::collections::VecDeque;

    const HOST: &str = "example.com";
    const HTML: &[(&str, &str)] = &[("content-type", "text/html; charset=utf-8")];

    /// Body fixture yielding one supplied chunk per poll.
    struct Chunks(VecDeque<Bytes>);

    impl Chunks {
        fn of(parts: &[&str]) -> Self {
            Self(
                parts
                    .iter()
                    .map(|part| Bytes::copy_from_slice(part.as_bytes()))
                    .collect(),
            )
        }
    }

    struct Bytes2(VecDeque<Bytes>);

    impl Body for Bytes2 {
        type Data = Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            Poll::Ready(self.0.pop_front().map(|chunk| Ok(Frame::data(chunk))))
        }
    }

    impl Body for Chunks {
        type Data = Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            Poll::Ready(self.0.pop_front().map(|chunk| Ok(Frame::data(chunk))))
        }
    }

    /// Supplies compiled rules without exercising rule parsing.
    struct Fixture(Arc<HidingRules>);

    impl CosmeticSource for Fixture {
        fn rules(&self, host: &str) -> Option<Arc<HidingRules>> {
            (host == HOST).then(|| Arc::clone(&self.0))
        }
    }

    fn tier(
        selectors: &[&str],
        budget: StreamBudget,
    ) -> (Rewriting, Arc<HidingRules>, Arc<RewriteFailures>) {
        let rules =
            Arc::new(HidingRules::compile(selectors.iter().map(|s| (*s).to_owned())).unwrap());
        let failures = Arc::new(RewriteFailures::new());
        (
            Rewriting::On {
                source: Arc::new(Fixture(Arc::clone(&rules))),
                budget,
                failures: Arc::clone(&failures),
            },
            Arc::clone(&rules),
            failures,
        )
    }

    async fn serve(
        rewriting: &Rewriting,
        fields: &[(&str, &str)],
        chunks: &[&str],
    ) -> (HeaderMap, Result<String, BoxError>) {
        let mut response = Response::new(Chunks::of(chunks));
        *response.headers_mut() = headers(fields);
        let (parts, body) = rewriting.apply(HOST, response).into_parts();
        let collected = body
            .collect()
            .await
            .map(|collected| String::from_utf8(collected.to_bytes().to_vec()).unwrap());
        (parts.headers, collected)
    }

    /// Removes a match whose tag spans two input chunks.
    #[tokio::test]
    async fn a_matching_element_is_removed_across_a_chunk_boundary() {
        let (rewriting, ..) = tier(&[".ad"], StreamBudget::default());
        let (_, body) = serve(
            &rewriting,
            HTML,
            &[
                "<html><body><p>keep</p><div class=\"a",
                "d\"><img src=\"banner.png\"></div><p>also keep</p></body></html>",
            ],
        )
        .await;
        let body = body.expect("the document completes");
        assert!(!body.contains("banner.png"), "the element survived: {body}");
        assert!(body.contains("<p>keep</p>"));
        assert!(body.contains("<p>also keep</p>"));
    }

    /// Preserves a matching element protected by SRI.
    #[tokio::test]
    async fn an_integrity_bearing_element_survives_a_matching_rule() {
        let (rewriting, ..) = tier(&["script"], StreamBudget::default());
        let signed = "<script src=\"/a.js\" integrity=\"sha384-abc\"></script>";
        let (_, body) = serve(
            &rewriting,
            HTML,
            &[
                "<html><body>",
                signed,
                "<script src=\"/b.js\"></script></body></html>",
            ],
        )
        .await;
        let body = body.expect("the document completes");
        assert!(
            body.contains(signed),
            "a signed subresource was modified: {body}"
        );
        assert!(!body.contains("/b.js"), "an unsigned one was not removed");
    }

    /// The CSP hash identifies the injected stylesheet.
    #[tokio::test]
    async fn the_injected_stylesheet_is_named_by_the_policy_it_widened() {
        let (rewriting, rules, _) = tier(&[".ad"], StreamBudget::default());
        let source = rules.source().to_owned();
        let (fields, body) = serve(
            &rewriting,
            &[
                ("content-type", "text/html"),
                ("content-security-policy", "style-src 'self'"),
            ],
            &["<html><head><title>t</title></head><body></body></html>"],
        )
        .await;
        let body = body.expect("the document completes");
        assert!(
            body.contains("<style>.ad{display:none!important}</style>"),
            "no stylesheet was injected: {body}"
        );
        let policy_value = fields
            .get("content-security-policy")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(policy_value, format!("style-src 'self' {source}"));
    }

    /// A restrictive style policy suppresses injection but permits removal.
    #[tokio::test]
    async fn a_refusing_policy_suppresses_the_injection_but_not_the_removal() {
        let (rewriting, ..) = tier(&[".ad"], StreamBudget::default());
        let (fields, body) = serve(
            &rewriting,
            &[
                ("content-type", "text/html"),
                ("content-security-policy", "style-src 'none'"),
            ],
            &["<html><head></head><body><div class=\"ad\">gone</div></body></html>"],
        )
        .await;
        let body = body.expect("the document completes");
        assert!(!body.contains("<style>"), "a forbidden style was injected");
        assert!(!body.contains("gone"), "removal still applies");
        assert_eq!(
            fields.get("content-security-policy").unwrap(),
            "style-src 'none'",
            "a refused policy is left exactly as it was"
        );
    }

    /// Bodies outside the tier pass through with headers intact.
    #[tokio::test]
    async fn a_body_the_tier_cannot_read_arrives_byte_for_byte() {
        let (rewriting, ..) = tier(&[".ad"], StreamBudget::default());
        let document = "<html><body><div class=\"ad\">present</div></body></html>";
        for fields in [
            // Unsupported coding.
            &[
                ("content-type", "text/html"),
                ("content-encoding", "compress"),
            ][..],
            // Non-HTML media type.
            &[("content-type", "application/json")][..],
            // Unsupported charset.
            &[("content-type", "text/html; charset=utf-16")][..],
            // Missing media type.
            &[][..],
        ] {
            let (returned, body) = serve(&rewriting, fields, &[document]).await;
            assert_eq!(body.unwrap(), document, "{fields:?} altered the body");
            assert_eq!(returned, headers(fields), "{fields:?} altered the headers");
        }
        // A host without rules bypasses parsing.
        let mut response = Response::new(Chunks::of(&[document]));
        *response.headers_mut() = headers(HTML);
        let (_, body) = rewriting.apply("unlisted.example", response).into_parts();
        let body = body.collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], document.as_bytes());
    }

    /// A memory bail-out flushes held bytes and preserves the response.
    #[tokio::test]
    async fn an_exhausted_budget_costs_no_bytes_and_counts_the_failure() {
        let (rewriting, _, failures) =
            tier(&[".matches-nothing"], StreamBudget::new(1024, 64).unwrap());
        // Keep half a tag pending across one body poll.
        let opening = format!("<div data-x=\"{}", "y".repeat(4096));
        let closing = "\">held</div><p>after</p>";
        let (_, body) = serve(&rewriting, HTML, &[&opening, closing]).await;

        let body = body.expect("a graceful bail-out keeps the response whole");
        assert_eq!(
            body,
            format!("{opening}{closing}"),
            "the bail-out lost or duplicated bytes"
        );
        assert_eq!(failures.count(), 1, "the failure must be counted, once");
    }

    /// Ambiguous markup produces visible truncation instead of unsafe edits.
    #[tokio::test]
    async fn ambiguous_markup_ends_the_body_visibly_rather_than_silently_short() {
        let (rewriting, _, failures) = tier(&[".ad"], StreamBudget::default());
        let (_, body) = serve(
            &rewriting,
            HTML,
            &["<select><xmp><script>\"use strict\";</script></select>"],
        )
        .await;
        assert!(body.is_err(), "the truncation must be reported");
        assert_eq!(failures.count(), 1);
    }

    fn gzipped(plain: &str) -> Vec<u8> {
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(plain.as_bytes()).unwrap();
        encoder.finish().unwrap()
    }

    /// Decodes and rewrites compressed HTML, then removes stale coding headers.
    #[tokio::test]
    async fn a_compressed_document_is_decoded_rewritten_and_emitted_plain() {
        let (rewriting, ..) = tier(&[".ad"], StreamBudget::default());
        let document = "<html><body><p>keep</p><div class=\"ad\">gone</div></body></html>";
        let compressed = gzipped(document);

        // Divide the stream to exercise incremental decoding.
        let split = compressed.len() / 2;
        let mut response = Response::new(Bytes2(VecDeque::from([
            Bytes::copy_from_slice(&compressed[..split]),
            Bytes::copy_from_slice(&compressed[split..]),
        ])));
        *response.headers_mut() = headers(&[
            ("content-type", "text/html; charset=utf-8"),
            ("content-encoding", "gzip"),
            ("content-length", "999"),
        ]);
        let (parts, body) = rewriting.apply(HOST, response).into_parts();
        let out = body.collect().await.expect("the document completes");
        let out = String::from_utf8(out.to_bytes().to_vec()).unwrap();

        assert!(!out.contains("gone"), "the rule did not apply: {out}");
        assert!(out.contains("<p>keep</p>"));
        assert!(
            parts.headers.get("content-encoding").is_none(),
            "a decoded body must not still claim to be compressed"
        );
        assert!(
            parts.headers.get("content-length").is_none(),
            "the compressed length no longer describes this body"
        );
    }

    fn zstandard(plain: &str) -> Vec<u8> {
        ruzstd::encoding::compress_to_vec(
            plain.as_bytes(),
            ruzstd::encoding::CompressionLevel::Fastest,
        )
    }

    /// Decodes zstd input one byte at a time across frame boundaries.
    #[tokio::test]
    async fn a_zstd_document_is_decoded_one_byte_at_a_time() {
        let (rewriting, ..) = tier(&[".ad"], StreamBudget::default());
        let document = "<html><body><p>keep</p><div class=\"ad\">gone</div></body></html>";
        let compressed = zstandard(document);

        let mut response = Response::new(Bytes2(
            compressed
                .iter()
                .map(|byte| Bytes::copy_from_slice(&[*byte]))
                .collect::<VecDeque<_>>(),
        ));
        *response.headers_mut() = headers(&[
            ("content-type", "text/html; charset=utf-8"),
            ("content-encoding", "zstd"),
        ]);
        let (parts, body) = rewriting.apply(HOST, response).into_parts();
        let out = body.collect().await.expect("the document completes");
        let out = String::from_utf8(out.to_bytes().to_vec()).unwrap();

        assert!(!out.contains("gone"), "the rule did not apply: {out}");
        assert!(out.contains("<p>keep</p>"));
        assert!(parts.headers.get("content-encoding").is_none());
    }

    /// Refuses decoded output beyond the per-chunk ceiling.
    #[test]
    fn a_chunk_expanding_past_the_ceiling_is_refused() {
        let bomb = vec![b'a'; 2 * MAX_DECODED_CHUNK_BYTES];
        for (coding, compressed) in [
            (Coding::Gzip, {
                use std::io::Write;
                let mut encoder =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(&bomb).unwrap();
                encoder.finish().unwrap()
            }),
            (Coding::Zstd, {
                ruzstd::encoding::compress_to_vec(
                    bomb.as_slice(),
                    ruzstd::encoding::CompressionLevel::Fastest,
                )
            }),
        ] {
            let mut decoder = Decoder::new(coding);
            assert!(
                decoder.decode(&compressed).is_err(),
                "{coding:?} decoded past the ceiling"
            );
        }
    }

    /// A truncated compressed stream reports an error instead of shortening.
    #[tokio::test]
    async fn a_truncated_compressed_body_ends_visibly() {
        let (rewriting, _, failures) = tier(&[".ad"], StreamBudget::default());
        let compressed = gzipped("<html><body><div class=\"ad\">gone</div></body></html>");
        let mut response = Response::new(Bytes2(VecDeque::from([Bytes::copy_from_slice(
            &compressed[..compressed.len() / 2],
        )])));
        *response.headers_mut() =
            headers(&[("content-type", "text/html"), ("content-encoding", "gzip")]);
        let (_, body) = rewriting.apply(HOST, response).into_parts();
        assert!(
            body.collect().await.is_err(),
            "a truncated stream must be reported, not silently shortened"
        );
        assert_eq!(failures.count(), 1);
    }

    /// A body that contradicts its declared coding reports an error.
    #[tokio::test]
    async fn a_body_that_is_not_the_coding_it_claims_is_reported() {
        let (rewriting, _, failures) = tier(&[".ad"], StreamBudget::default());
        let mut response = Response::new(Bytes2(VecDeque::from([Bytes::from_static(
            b"<html>this is not gzip at all</html>",
        )])));
        *response.headers_mut() =
            headers(&[("content-type", "text/html"), ("content-encoding", "gzip")]);
        let (_, body) = rewriting.apply(HOST, response).into_parts();
        assert!(body.collect().await.is_err());
        assert_eq!(failures.count(), 1);
    }
}
