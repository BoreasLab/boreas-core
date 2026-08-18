//! P16 body rewriting: the HTML tier, and the budgets that keep it optional.
//!
//! This is the last filtering tier and the only one that touches content rather
//! than routing. The name tier answers DNS, the URL tier decides requests, and
//! neither can do anything about an advertisement the server rendered into the
//! document it was asked for. That needs the document — which is why this tier
//! exists, and why it is the one with the most ways to go wrong.
//!
//! **Rewritability is a parse, not a check.** [`rewritable`] turns a response's
//! headers into either a [`Rewritable`] — which carries the character encoding
//! to read the body with, and is the *only* way to obtain a rewriter — or a
//! [`NotRewritable`] naming what disqualified it. A caller cannot forget the
//! conditions because it cannot construct the rewriter without them, and every
//! condition it fails to satisfy is a body forwarded exactly as it arrived.
//!
//! **The budget is memory, not bytes, and that is deliberate.** A large
//! document costs nothing but throughput: it streams through a rewriter that
//! holds only the tag it is in the middle of. What actually threatens the
//! process is *held* state — an unclosed tag megabytes long, a selector
//! matching deeply — and `lol_html`'s memory limiter bounds exactly that. A
//! separate cap on total body bytes would add a failure mode with no clean
//! recovery while guarding nothing the memory limiter does not already guard.
//!
//! **Failing open is the library's own bail-out, wired to a demotion.** When
//! the limit is hit, `lol_html` flushes every byte it was holding, raw, before
//! it gives up — so the response continues from exactly where rewriting stopped
//! and arrives whole, part rewritten and part not, which for a filter whose
//! only edit is *removal* is a partly-filtered page rather than a damaged one.
//! Boreas then stops rewriting that connection, counts the failure, and the
//! session demotes the host to [`Tier::Inspect`](crate::Tier) so the next visit
//! does not pay for the same discovery. Ambiguous markup is the one failure the
//! parser refuses to continue through — that is a security property, not a
//! limitation — and there the body ends visibly rather than silently short.
//!
//! **Relaxing a policy means adding exactly one hash and nothing else.**
//! Hiding elements a script adds later needs an injected stylesheet, which a
//! strict Content-Security-Policy blocks. [`permit_inline_style`] widens the
//! policy by the `'sha256-...'` of the one stylesheet Boreas wrote — never by
//! `'unsafe-inline'`, never by removing a source, and never by touching
//! `default-src`, which governs scripts and frames as well as styles. It also
//! declines to widen a policy that already permits inline styles the old way,
//! because in CSP Level 3 adding a hash *revokes* `'unsafe-inline'` and would
//! break the page it was meant to filter.
//!
//! **An `integrity=` element is never touched.** The page's author committed to
//! that subresource cryptographically, and a cosmetic rule matching one is
//! almost certainly matching the wrong thing.

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

/// The error every body in this module reports, matching [`ProxyBody`].
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The `Content-Security-Policy` field name, and the report-only variant this
/// module deliberately leaves alone: a report-only policy blocks nothing, so
/// widening it would change reports without changing behaviour.
const CSP: &str = "content-security-policy";

// ---------------------------------------------------------------------------
// Rewritability
// ---------------------------------------------------------------------------

/// Why a response body will be forwarded untouched.
///
/// Recorded rather than collapsed to a boolean, because these have very
/// different futures: [`Self::ContentCoded`] names a coding no decoder here
/// covers, and [`Self::NotHtml`] is the overwhelming majority of every real
/// workload and wants to stay cheap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotRewritable {
    /// The status carries no body, or carries only a range of one. Rewriting a
    /// fragment of a document is not rewriting a document.
    NoWholeBody,
    /// Not `text/html`.
    NotHtml,
    /// The body is compressed with a coding this build cannot read — a private
    /// coding, or two codings stacked. Fail-open, exactly as an unsupported
    /// charset is.
    ContentCoded,
    /// A `charset` that a streaming, ASCII-compatible rewriter cannot read —
    /// UTF-16 in either order, ISO-2022-JP, `replacement` — or a label no
    /// encoding is registered for.
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

/// A content coding this build can read.
///
/// **A closed sum, and the point of closing it is that the decoder is chosen by
/// elimination rather than by a lookup that can miss.** A `Coding` value *is*
/// the proof that a decoder exists for the body, so [`Rewritable`] carries one
/// and the rewriter constructor cannot be reached without it. Everything the
/// sum does not name — a private coding, two codings stacked — is not a
/// `Coding` at all and lands in [`NotRewritable::ContentCoded`], which forwards
/// the body byte for byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coding {
    /// No coding, or `identity`. The common case and the free one.
    Identity,
    /// RFC 1952 gzip, which is what `Accept-Encoding: gzip` gets.
    Gzip,
    /// RFC 1950 zlib, spelled `deflate` on the wire. Some servers send raw
    /// RFC 1951 instead; the decoder accepts the header-bearing form, and a
    /// raw stream fails the rewrite and forwards what it was holding, which is
    /// the same graceful bail-out every other decode failure takes.
    Deflate,
    /// RFC 7932 Brotli, which is what CDNs serve HTML as.
    Brotli,
    /// RFC 8878 Zstandard, which Chrome has offered since Chrome 123 and which
    /// CDNs increasingly answer with.
    Zstd,
}

impl Coding {
    /// The coding a `Content-Encoding` token names, or `None` for one no
    /// decoder here covers.
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

/// Proof that a response body may be rewritten, carrying the character encoding
/// to read it with and the content coding to decode it from.
///
/// The only way to build one is [`rewritable`], and the only way to build a
/// rewriter is to hold one — so "construct a rewriter only after `text/html` is
/// confirmed" is a property of the types rather than a rule to remember.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rewritable {
    encoding: AsciiCompatibleEncoding,
    coding: Coding,
}

impl Rewritable {
    /// The content coding the body arrives under.
    #[must_use]
    pub fn coding(self) -> Coding {
        self.coding
    }
}

/// Reads a response's headers as permission to rewrite its body, or as a
/// reason not to.
///
/// O(bytes of the `Content-Type` and `Content-Encoding` fields), one pass, no
/// allocation beyond the coding token's lower-casing.
pub fn rewritable(status: StatusCode, headers: &HeaderMap) -> Result<Rewritable, NotRewritable> {
    if status.is_informational()
        || matches!(
            status,
            StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED | StatusCode::PARTIAL_CONTENT
        )
    {
        return Err(NotRewritable::NoWholeBody);
    }
    // `Content-Encoding` is an ordered list of codings applied in turn. One
    // effective coding is what this decodes; a stack of two is not refused for
    // being hard but for being vanishingly rare and impossible to get subtly
    // wrong by forwarding instead.
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
            // A second non-identity coding on top of the first.
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
        // No declared charset: start from UTF-8 and let the rewriter follow a
        // `<meta charset>` if the document declares one, which is what a
        // browser does with the same input.
        None => AsciiCompatibleEncoding::utf_8(),
        Some(label) => encoding_rs::Encoding::for_label_no_replacement(label.as_bytes())
            .and_then(AsciiCompatibleEncoding::new)
            .ok_or(NotRewritable::UnsupportedCharset)?,
    };
    Ok(Rewritable { encoding, coding })
}

/// Splits a media type from its `charset` parameter. Total: a malformed
/// parameter list yields no charset rather than an error, which lands in the
/// same place as an absent one.
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

/// What a policy permits for one inline stylesheet.
///
/// A closed sum, because the middle case is the one an `Option` would hide:
/// [`Self::Refused`] is a policy that says `'none'`, which no single source can
/// widen without contradicting it, and which must therefore suppress the
/// injection rather than the policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InlineStyle {
    /// The policy already permits it; change nothing.
    Granted,
    /// The policy blocks it and can name the stylesheet's hash instead. The
    /// rewritten header value is carried along.
    Widened(String),
    /// The policy forbids inline styles outright. Elements are still removed —
    /// removal needs no permission — but nothing is injected.
    Refused,
}

/// The directives that govern a `<style>` element, most specific first.
const STYLE_DIRECTIVES: [&str; 2] = ["style-src-elem", "style-src"];
const FALLBACK_DIRECTIVE: &str = "default-src";

/// Widens `policy` by exactly `source`, or explains why it does not need to be.
///
/// The law: the result differs from the input by the insertion of one source
/// expression into one directive. No source is ever removed, no keyword is ever
/// added, and no directive other than the one governing inline styles is
/// touched — including when the governing directive is inherited, where a new
/// `style-src` is emitted rather than `default-src` being widened for
/// everything it governs.
///
/// O(bytes of the policy), with one allocation per directive on the widening
/// path and none otherwise.
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
        // Nothing governs inline styles, so nothing blocks ours.
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
    // **CSP Level 3: a nonce or hash source makes `'unsafe-inline'` inert.** So
    // adding ours to a policy that permits inline styles only through
    // `'unsafe-inline'` would revoke a permission the page is relying on, and
    // break the page this tier exists to improve. Leave it alone; ours is
    // already allowed.
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
        // Widening `default-src` would widen scripts, frames, and images with
        // it. A fresh `style-src` carrying the inherited sources plus ours
        // grants strictly less than that, and grants it only to styles.
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

/// The index of the directive named `name`, comparing only its name token.
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

/// Element-hiding rules for one host, compiled once.
///
/// Everything expensive happens here rather than per response: the selector
/// list is parsed, the stylesheet text is built, and its hash is computed, so
/// serving a document costs one selector clone and no parsing of either kind.
#[derive(Debug)]
pub struct HidingRules {
    selector: Selector,
    /// The `<style>` element's text content. Deterministic given the rule set —
    /// the selectors are ordered before joining — which is what makes the hash
    /// below stable across processes and therefore worth precomputing.
    style: String,
    /// The `'sha256-...'` source expression naming [`Self::style`].
    source: String,
    count: usize,
}

impl HidingRules {
    /// Compiles a selector set, or `None` when there is nothing to hide or the
    /// joined list will not parse.
    ///
    /// The input is ordered here rather than assumed to be ordered, because the
    /// rule engine returns a hash set and the stylesheet's hash has to be a
    /// function of the *rules*, not of an iteration order.
    ///
    /// O(n log n) in selectors to order them, then O(bytes) to parse the joined
    /// list — once per host per rule-set swap, never per response.
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

    /// The stylesheet's text content, which is what the `'sha256-...'` source
    /// in [`Self::source`] names.
    #[must_use]
    pub fn style(&self) -> &str {
        &self.style
    }

    /// The CSP source expression that admits [`Self::style`].
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The number of selectors this hides with.
    #[must_use]
    pub fn len(&self) -> usize {
        self.count
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }
}

/// Where element-hiding rules come from.
///
/// A seam rather than an implementation, and the boundary the design draws:
/// *Adblock Plus syntax is somebody else's parser*, and this module's job
/// begins once a host's selectors are known. [`RuleEngine`](crate::RuleEngine)
/// is the production implementation.
pub trait CosmeticSource: Send + Sync + 'static {
    /// The compiled rules for `host`, or `None` when nothing applies.
    ///
    /// Called once per rewritable response, so an implementation that consults
    /// a large index should cache.
    fn rules(&self, host: &str) -> Option<Arc<HidingRules>>;
}

/// The identity source: nothing is ever hidden.
///
/// What a deployment with no cosmetic lists gets, and what keeps the HTML tier
/// inert rather than absent.
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

/// What one response's rewriter may consume.
#[derive(Clone, Copy, Debug)]
pub struct StreamBudget {
    /// The ceiling on what the rewriter *holds*: buffered unparsed input and
    /// selector-matching state. Exceeding it is a graceful bail-out, not a
    /// failure of the response.
    max_memory_bytes: usize,
    /// The parsing buffer reserved up front, so an ordinary document does not
    /// grow it. Charged against the ceiling above.
    parsing_buffer_bytes: usize,
}

/// A budget that cannot rewrite anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetError {
    /// A ceiling of zero. Every document exceeds it before its first byte, so
    /// rewriting is off — but off by way of a per-response bail-out that looks
    /// like a stream of failures rather than like a setting.
    NoCeiling,
    /// A parsing buffer larger than the ceiling that has to contain it. The
    /// buffer is charged against the ceiling, so this is the same silence
    /// arriving one step later.
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
    /// The one boundary a host's two numbers cross to become a budget.
    ///
    /// **Both failures are silent without it.** The numbers reach `lol_html`
    /// as a memory ceiling and a preallocation charged against it, and a pair
    /// that cannot hold a document produces a bail-out per response — the same
    /// observable as a site that simply does not get rewritten, with a counter
    /// climbing where nobody is looking. A configuration that cannot work now
    /// fails where it is written.
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
            // Comfortably more than any tag or attribute a real document
            // carries, and small enough that the concurrent-stream limit times
            // this stays a number a phone can hold.
            max_memory_bytes: 2 * 1024 * 1024,
            // The bridge's chunk size, so a typical write lands in one buffer.
            parsing_buffer_bytes: 16 * 1024,
        }
    }
}

#[cfg(test)]
mod budget_tests {
    use super::*;

    /// **Both halves of an unusable budget are silent.** They reach `lol_html`
    /// as a ceiling and a preallocation charged against it, so a pair that
    /// cannot hold a document bails out once per response — indistinguishable,
    /// from outside, from a site that simply is not rewritten. This is set
    /// through the stable interface, so the host getting it wrong is a
    /// downstream developer with no way to see it.
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
        // A buffer exactly filling the ceiling is the boundary and is allowed:
        // it leaves nothing spare, but nothing about it is contradictory.
        assert!(StreamBudget::new(1024, 1024).is_ok());

        let default = StreamBudget::default();
        assert!(
            StreamBudget::new(default.max_memory_bytes(), default.parsing_buffer_bytes()).is_ok(),
            "the default must be a budget its own constructor accepts"
        );
    }
}

/// Rewrites abandoned on one connection.
///
/// A counter rather than a callback: the session reads it once the exchange
/// ends, which is the moment it can act, and a counter cannot re-enter the
/// session from inside a body poll.
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

    /// Rewrites that gave up. Read for a demotion decision, not to synchronize
    /// anything, so relaxed ordering is the whole requirement.
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

/// How large a Brotli decoder's ring buffer is. The format's window can reach
/// 16 MiB, but a decoder only needs a buffer to *stage* output in, and 64 KiB
/// is comfortably more than one chunk of a document — so this bounds the
/// decoder's own footprint the way [`StreamBudget`] bounds the rewriter's.
const BROTLI_BUFFER_BYTES: usize = 64 * 1024;

/// The most compressed input a zstd decoder may have to hold before it can make
/// progress: RFC 8878 caps a block at 128 KiB, over a three-byte block header,
/// under a frame header of at most eighteen. It is also the most that is handed
/// over at once, which is what keeps the decoder's own buffer near one block
/// however large a chunk arrives.
const ZSTD_STAGING_BYTES: usize = 128 * 1024 + 3 + 18;

/// The largest window a zstd frame may ask this build to keep. The format
/// permits terabytes and a document needs none of them; the decoder compares
/// this against the frame's declared window and refuses *before* allocating.
const ZSTD_WINDOW_BYTES: u64 = 8 * 1024 * 1024;

/// How much plaintext one chunk may decode to before the body is abandoned.
///
/// **A compression bomb is a body, not a bug.** Every coding here expands, and
/// nothing in a `Content-Length` or a chunk boundary bounds by how much — so
/// this is the ceiling that makes the tier's memory a function of the ceiling
/// rather than of what an origin chose to send. Generous for a document and far
/// under what a bomb reaches, so tripping it is a signal rather than a limit
/// real content meets.
const MAX_DECODED_CHUNK_BYTES: usize = 8 * 1024 * 1024;

/// Whether a decoder error means *not enough bytes yet* rather than *these
/// bytes are wrong*.
///
/// `ruzstd` reads a frame header with `read_exact`, so a header split across
/// chunk boundaries surfaces as an error rather than as no progress made. The
/// `UnexpectedEof` at the end of the chain is what separates the two; anything
/// else is a body this cannot read.
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

/// A push adapter over `ruzstd`, which offers only pull.
///
/// `FrameDecoder` reads whole blocks out of a slice and stages the result
/// internally; this holds the partial block a chunk boundary split, and drains
/// the staged plaintext through `collect_to_writer`, which appends into a `Vec`
/// rather than allocating a fresh one per call.
struct Zstd {
    frame: ruzstd::decoding::FrameDecoder,
    /// Compressed bytes that do not yet form a whole block. Bounded by
    /// [`ZSTD_STAGING_BYTES`], which is what makes this path fixed-memory.
    pending: Vec<u8>,
    plain: Vec<u8>,
    /// Whether a frame header has been read. Tracked here because
    /// `FrameDecoder::is_finished` answers *true* before initialisation as well
    /// as after the last block, and the two mean opposite things.
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

    /// Decodes what `source` holds, appending plaintext and returning how many
    /// of its bytes were consumed.
    fn drain(&mut self, source: &[u8]) -> Result<usize, Undecodable> {
        let mut used = 0;
        while used < source.len() {
            // One staging window at a time: `decode_from_to` decodes *every*
            // whole block its input contains, so an unbounded slice would stage
            // an unbounded amount before anything could drain it.
            let end = source.len().min(used + ZSTD_STAGING_BYTES);
            let (read, _) = match self.frame.decode_from_to(&source[used..end], &mut []) {
                Ok(progress) => progress,
                // The bytes held back are a frame header the chunk boundary
                // split; they decode once the rest of it arrives.
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
            // A frame's trailing four-byte checksum is reported as read whether
            // or not all four arrived, so a claim larger than what was offered
            // means the tail is still in flight rather than consumed.
            if read == 0 || read > end - used {
                break;
            }
            used += read;
        }
        // Bytes after a complete frame would be a second, concatenated one.
        // Legal in the format, sent by no origin, and not decoded here — an
        // error rather than a silent truncation of what follows.
        if self.started && self.frame.is_finished() && used < source.len() {
            return Err(Undecodable);
        }
        Ok(used)
    }

    fn push(&mut self, chunk: &[u8]) -> Result<(), Undecodable> {
        if self.pending.is_empty() {
            // The common case: a chunk holding whole blocks is decoded where it
            // lies, and only its remainder is copied.
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

/// A push-driven decoder for one response body.
///
/// **Push, not pull, because the body already is.** `hyper` hands over chunks
/// as they arrive; a `Read`-shaped decoder would need a thread or a buffer to
/// invert that, and both are the wrong answer on a per-stream path. Each
/// variant is a `Write` adapter over a `Vec` this type owns, so a chunk goes in
/// and whatever plain bytes it produced come straight back out.
///
/// The `Vec` is cleared rather than replaced between chunks, so a body costs
/// one growth to its high-water mark and no allocation after that.
enum Decoder {
    /// No decoding: the input slice *is* the output, so this variant owns
    /// nothing and copies nothing.
    Identity,
    Gzip(Box<flate2::write::GzDecoder<Vec<u8>>>),
    Deflate(Box<flate2::write::ZlibDecoder<Vec<u8>>>),
    Brotli(Box<brotli_decompressor::DecompressorWriter<Vec<u8>>>),
    Zstd(Box<Zstd>),
}

/// The compressed stream was malformed or truncated.
///
/// One variant, because there is one response: stop rewriting and forward what
/// is left. Distinguishing "bad header" from "bad block" would change nothing a
/// caller does.
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

    /// Pushes one chunk through and borrows out whatever plain bytes it
    /// produced. The borrow ends before [`Self::clear`], which is what lets the
    /// staging buffer be reused rather than reallocated.
    ///
    /// O(bytes) in the chunk, amortised no allocation.
    fn decode<'a>(&'a mut self, chunk: &'a [u8]) -> Result<&'a [u8], Undecodable> {
        use std::io::Write;
        let plain: &[u8] = match self {
            // The input slice *is* the output, and it is already bounded by
            // whatever handed it over.
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
        // One ceiling, whatever the coding: see [`MAX_DECODED_CHUNK_BYTES`].
        (plain.len() <= MAX_DECODED_CHUNK_BYTES)
            .then_some(plain)
            .ok_or(Undecodable)
    }

    /// Closes the stream and borrows out the last bytes it was holding. A
    /// decoder that cannot finish is one whose body was truncated on the wire.
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
            // A frame that never finished is a body truncated on the wire, and
            // a block still pending is the same thing one boundary earlier.
            Self::Zstd(decoder) => {
                (decoder.started && decoder.frame.is_finished() && decoder.pending.is_empty())
                    .then_some(decoder.plain.as_slice())
                    .ok_or(Undecodable)
            }
        }
    }

    /// Retires the bytes the last `decode` or `finish` handed out, keeping the
    /// allocation.
    fn clear(&mut self) {
        match self {
            Self::Identity => {}
            Self::Gzip(decoder) => decoder.get_mut().clear(),
            Self::Deflate(decoder) => decoder.get_mut().clear(),
            Self::Brotli(decoder) => decoder.get_mut().clear(),
            Self::Zstd(decoder) => decoder.plain.clear(),
        }
    }

    /// Whether this decoder changes the bytes at all. A body whose coding is
    /// `identity` needs no header edit and no error path.
    fn is_identity(&self) -> bool {
        matches!(self, Self::Identity)
    }
}

/// Where the rewriter's output lands between polls. Shared with the rewriter,
/// which owns its sink and never gives it back.
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

/// The rewriter gave up while holding bytes it could not flush, so the document
/// cannot be completed. Reported as a body error rather than a short read: a
/// client that is told the message did not finish retries, and by then the host
/// is demoted and the retry is clean.
#[derive(Debug)]
pub struct Truncated;

impl fmt::Display for Truncated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the rewriter abandoned the document mid-element")
    }
}

impl std::error::Error for Truncated {}

/// What the body is doing now. Closed at three, and the rewriter exists only in
/// the first — so a poisoned rewriter is not merely unused but unreachable.
enum Stage {
    Rewriting(Box<HtmlRewriter<'static, Sink>>),
    /// Forwarding what remains, after a bail-out that flushed cleanly.
    Raw,
    /// The inner body is exhausted, or the document was abandoned.
    Ended,
}

/// A response body with the HTML tier applied.
///
/// `Mutex` around the stage buys `Sync`, which [`ProxyBody`] requires and a
/// rewriter holding `FnMut` handlers does not have. It is never contended:
/// every access is through `&mut self` from `poll_frame`, so the lock is taken
/// with [`Mutex::get_mut`] and compiles to the field access it looks like.
pub struct RewritingBody<B> {
    inner: B,
    stage: Mutex<Stage>,
    /// The content-coding decoder in front of the rewriter.
    ///
    /// **Decode and rewrite are two stages, not one, and the order is forced:**
    /// a rewriter cannot find a tag in a Brotli stream. The decoder is behind
    /// the same `Mutex` discipline as the stage — reached only through
    /// `&mut self` from `poll_frame` — so it needs no lock of its own.
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

    /// Feeds one chunk: decode it, then rewrite it, moving the stage on if
    /// either gives up.
    ///
    /// `Err` means the document cannot be completed — the rewriter stopped
    /// while holding bytes, or the compressed stream is unreadable and the
    /// plaintext after it is unrecoverable. A graceful rewriter bail-out has
    /// already flushed everything it was given, so it returns `Ok` and merely
    /// stops rewriting.
    fn feed(&mut self, data: &[u8]) -> Result<(), Truncated> {
        let Self {
            stage,
            decoder,
            sink,
            failures,
            ..
        } = self;
        let stage = stage.get_mut().unwrap_or_else(|poison| poison.into_inner());
        // A body already past the rewriter needs no decode: the raw stage
        // forwards the *decoded* remainder, and once the stage has ended there
        // is nothing left to forward at all.
        if matches!(stage, Stage::Ended) {
            return Ok(());
        }

        let decoded = match decoder.decode(data) {
            Ok(decoded) => decoded,
            Err(_) => {
                // A truncated or corrupt compressed stream leaves nothing to
                // forward: the bytes after it cannot be recovered, so the body
                // ends visibly rather than silently short.
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
                    // The rewriter is poisoned after any error, so replacing
                    // the stage is what makes it unreachable rather than merely
                    // unused.
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

    /// Closes the decoder and the rewriter once the inner body is exhausted.
    fn finish(&mut self) -> Result<(), Truncated> {
        let Self {
            stage,
            decoder,
            sink,
            failures,
            ..
        } = self;
        let stage = stage.get_mut().unwrap_or_else(|poison| poison.into_inner());

        // The decoder first: it may still be holding the document's tail.
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

/// Whether the rewriter flushed everything it held before giving up.
///
/// True for the two failures the settings ask it to bail out of gracefully, and
/// false for ambiguous markup — which `lol_html` refuses to bail out of on
/// purpose, because continuing past markup whose parse depends on a tree it
/// cannot see is exactly how a rewriter edits the wrong element.
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
            // Output first, always: the rewriter may have emitted several
            // chunks for one input chunk, or none at all.
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
                    // Trailers pass through: they are not part of the document.
                    Err(other) => return Poll::Ready(Some(Ok(other))),
                },
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The seam the exchange uses
// ---------------------------------------------------------------------------

/// Whether the HTML tier applies to this connection, and under what budget.
///
/// Cloned per request, so everything expensive is behind an `Arc`.
#[derive(Clone)]
pub enum Rewriting {
    /// Forward every body untouched. What a demoted host gets, and what a
    /// deployment with no cosmetic rules gets.
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

    /// Applies the tier to one response, adjusting its headers to match.
    ///
    /// Returns the response with a boxed body either way, because the caller
    /// forwards one type; the difference is whether that body is a rewriter or
    /// the upstream's own.
    pub fn apply<B>(&self, host: &str, response: Response<B>) -> Response<ProxyBody>
    where
        B: Body<Data = Bytes> + Unpin + Send + Sync + 'static,
        B::Error: Into<BoxError>,
    {
        let (mut parts, body) = response.into_parts();
        let Some((rules, budget, failures)) = self.rules(host) else {
            return Response::from_parts(parts, boxed(body));
        };
        // The parse that gates everything below it: no rewriter is constructed
        // for a body this tier cannot read.
        let Ok(rewritable) = rewritable(parts.status, &parts.headers) else {
            return Response::from_parts(parts, boxed(body));
        };

        let inject = relax_policy(&mut parts.headers, &rules.source);
        let decoder = Decoder::new(rewritable.coding);
        if !decoder.is_identity() {
            // **The response is emitted decoded, and the headers must say so.**
            // Leaving `Content-Encoding` in place would tell the client to
            // decompress plaintext; leaving `Content-Length` would state the
            // compressed length of a body that is no longer compressed. Both
            // are removed and the codec picks its own streaming framing, which
            // is what [Filtering](../docs/filtering.md)'s step 6 asks for.
            //
            // Nothing is recompressed on the way out: the leg to the client is
            // this device's own terminated connection, so those bytes never
            // reach a network and shrinking them would spend battery to
            // compress a memory copy.
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

/// Widens every policy on the response so the injected stylesheet is permitted,
/// and reports whether injecting it is allowed at all.
///
/// Several `Content-Security-Policy` fields intersect, so each is widened and
/// any one that refuses inline styles refuses them for the response.
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
    // A value that will not fit in a header field is left as it was; that only
    // suppresses the injection, and removal still applies.
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

/// Builds the rewriter. Private, and reachable only with a [`Rewritable`] in
/// hand.
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
        // Follow a `<meta charset>` the way a browser does, so a document that
        // declares its encoding in the markup rather than the header is read
        // as it was written.
        .with_adjust_charset_on_meta_tag(true)
        // Ambiguous markup stops the rewrite rather than risking an edit to the
        // wrong element. The plan calls this a strictness failure and demotes
        // the host for it; the alternative is editing a document whose parse
        // this rewriter cannot determine.
        .with_strict(true)
        .with_graceful_bail_out_on_content_handler_error(true)
        .with_memory_settings(
            MemorySettings::new()
                .with_max_allowed_memory_usage(budget.max_memory_bytes())
                .with_preallocated_parsing_buffer_size(budget.parsing_buffer_bytes())
                // The fail-open path, and the reason a bail-out keeps the
                // response whole: every byte the rewriter was holding is
                // flushed raw before it gives up.
                .with_graceful_bail_out_on_memory_limit_exceeded(true),
        )
        .append_element_content_handler((
            // Cloned rather than borrowed: the body outlives this call, and
            // cloning a parsed selector list copies components rather than
            // re-parsing them.
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

/// Removes one matched element, unless its author committed to it.
///
/// **`integrity=` is never touched.** The attribute is a cryptographic
/// commitment to a subresource, and a cosmetic rule matching an element that
/// carries one is far more likely to be matching the wrong element than to be
/// naming an advertisement the author signed for.
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
        // No charset is fine: the rewriter starts at UTF-8 and follows a meta.
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
        // A coding this build can read is not a refusal: it carries the
        // decoder that will read it.
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
        // One this build cannot, and two stacked, both forward untouched.
        // Stacked codings, and RFC 2616's LZW that nothing still sends.
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

    /// The gate, in one test: every encoding the design names as unsupported
    /// must forward the body unchanged rather than be read as if it were
    /// ASCII-compatible.
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
        // A label no encoding is registered for is refused too, rather than
        // being read as the default and mangled.
        assert_eq!(
            rewritable(
                StatusCode::OK,
                &headers(&[("content-type", "text/html; charset=invented-9")])
            ),
            Err(NotRewritable::UnsupportedCharset)
        );
        // Ones that are ASCII-compatible are accepted, quoted or not.
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
        // The more specific directive wins when both are present, and the other
        // is left exactly as it was.
        assert_eq!(
            permit_inline_style("style-src 'self'; style-src-elem 'self'", HASH),
            InlineStyle::Widened(format!("style-src 'self'; style-src-elem 'self' {HASH}"))
        );
        // Other directives survive untouched, in order.
        assert_eq!(
            permit_inline_style("default-src 'self'; style-src 'self'; img-src *", HASH),
            InlineStyle::Widened(format!(
                "default-src 'self'; style-src 'self' {HASH}; img-src *"
            ))
        );
    }

    /// **The footgun this function exists to avoid.** In CSP Level 3 a hash or
    /// nonce source makes `'unsafe-inline'` inert, so widening a policy that
    /// permits inline styles the old way would *revoke* the permission the page
    /// depends on — breaking the page this tier is supposed to improve.
    #[test]
    fn a_policy_already_permitting_inline_styles_is_left_alone() {
        assert_eq!(
            permit_inline_style("style-src 'self' 'unsafe-inline'", HASH),
            InlineStyle::Granted
        );
        // Unless it is already bound by a nonce, in which case `'unsafe-inline'`
        // is inert already and adding ours changes nothing else.
        assert_eq!(
            permit_inline_style("style-src 'unsafe-inline' 'nonce-abc'", HASH),
            InlineStyle::Widened(format!("style-src 'unsafe-inline' 'nonce-abc' {HASH}"))
        );
        // And an identical source is not added twice.
        assert_eq!(
            permit_inline_style(&format!("style-src {HASH}"), HASH),
            InlineStyle::Granted
        );
    }

    /// Inheriting from `default-src` must not widen `default-src`, which
    /// governs scripts and frames as well as styles.
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

    /// The stated law: widening only ever inserts, never removes.
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

    /// The hash must name the stylesheet exactly, or the widened policy blocks
    /// the very style it was widened for — and it must be a function of the
    /// *rules* rather than of the order they arrived in, because the engine
    /// hands them over as a hash set.
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

    /// Nothing to hide is not an empty rewriter but no rewriter at all, and a
    /// selector list that will not parse is the same answer rather than a
    /// panic — the engine's syntax is wider than this rewriter's.
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

    /// A body that yields exactly the chunks it was given, one per poll.
    ///
    /// A test can therefore say where a chunk boundary falls, which is the only
    /// place a streaming rewriter differs from a whole-buffer one and so the
    /// only place its bugs live.
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

    /// A body over already-built `Bytes`, for a test whose chunks are binary
    /// rather than text.
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

    /// One host, one selector set. Stands in for the rule engine because what
    /// these tests exercise is the *transformation*: which selectors a list
    /// yields is `adblock`'s question and is answered against `adblock` in
    /// [`crate::RuleEngine`]'s own tests.
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

    /// The tier's actual job, across a chunk boundary that falls inside the tag
    /// being removed — which is where a rewriter that merely searched for
    /// substrings would get it wrong.
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

    /// **The SRI gate.** An element whose author committed to it
    /// cryptographically is never altered, however well a cosmetic rule matches
    /// it — a rule that matches a signed subresource is far likelier to be
    /// matching the wrong thing than to be right.
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

    /// The stylesheet and the policy that admits it must agree exactly, or the
    /// widened policy blocks the very style it was widened for.
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

    /// A policy that forbids inline styles outright must suppress the
    /// injection and nothing else: removal needs no permission.
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

    /// **The fail-open gate, on bytes.** Everything this tier cannot read must
    /// arrive exactly as it was sent, headers included — asserted on the bytes
    /// rather than on the decision, because a body that was parsed and
    /// re-serialized would still call itself unchanged.
    #[tokio::test]
    async fn a_body_the_tier_cannot_read_arrives_byte_for_byte() {
        let (rewriting, ..) = tier(&[".ad"], StreamBudget::default());
        let document = "<html><body><div class=\"ad\">present</div></body></html>";
        for fields in [
            // A coding no decoder here covers.
            &[
                ("content-type", "text/html"),
                ("content-encoding", "compress"),
            ][..],
            // Not a document.
            &[("content-type", "application/json")][..],
            // A character encoding a streaming rewriter cannot read.
            &[("content-type", "text/html; charset=utf-16")][..],
            // No type at all.
            &[][..],
        ] {
            let (returned, body) = serve(&rewriting, fields, &[document]).await;
            assert_eq!(body.unwrap(), document, "{fields:?} altered the body");
            assert_eq!(returned, headers(fields), "{fields:?} altered the headers");
        }
        // And a host with no rules of its own is never parsed at all.
        let mut response = Response::new(Chunks::of(&[document]));
        *response.headers_mut() = headers(HTML);
        let (_, body) = rewriting.apply("unlisted.example", response).into_parts();
        let body = body.collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], document.as_bytes());
    }

    /// **The memory gate.** A budget too small to hold the document must cost
    /// no bytes: `lol_html` flushes everything it was holding before it gives
    /// up, so the response is part rewritten and part raw but arrives whole.
    ///
    /// The rules match nothing and the document has no `<head>`, so rewriting
    /// is the identity here and the assertion can be exact equality — which is
    /// a far stronger statement than "roughly the same length".
    #[tokio::test]
    async fn an_exhausted_budget_costs_no_bytes_and_counts_the_failure() {
        let (rewriting, _, failures) =
            tier(&[".matches-nothing"], StreamBudget::new(1024, 64).unwrap());
        // One tag far longer than the budget, split so the rewriter has to hold
        // the first half across a poll.
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

    /// Ambiguous markup is the one failure `lol_html` refuses to continue
    /// through, because the correct parse depends on a tree it cannot see. The
    /// body then ends *visibly*: a client told the message did not finish
    /// retries, and by then the session has demoted the host and the retry is
    /// clean. A silently short document would be indistinguishable from a
    /// complete one.
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

    /// Compresses `plain` as gzip, so the test states the bytes rather than
    /// trusting a fixture blob.
    fn gzipped(plain: &str) -> Vec<u8> {
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(plain.as_bytes()).unwrap();
        encoder.finish().unwrap()
    }

    /// **The gap this closes.** `Accept-Encoding: identity` is a request, and
    /// a cache, an intermediary, or a non-compliant origin can all ignore it —
    /// at which point a build with no decoder loses the whole HTML tier on that
    /// response, silently. The document must be read, rewritten, and emitted
    /// decoded, with the headers that described the compressed form removed.
    #[tokio::test]
    async fn a_compressed_document_is_decoded_rewritten_and_emitted_plain() {
        let (rewriting, ..) = tier(&[".ad"], StreamBudget::default());
        let document = "<html><body><p>keep</p><div class=\"ad\">gone</div></body></html>";
        let compressed = gzipped(document);

        // Split across a chunk boundary, so the decoder is exercised streaming
        // rather than whole — which is the only place it can differ.
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

    /// Compresses `plain` as zstd, so the test states the bytes rather than
    /// trusting a fixture blob.
    fn zstandard(plain: &str) -> Vec<u8> {
        ruzstd::encoding::compress_to_vec(
            plain.as_bytes(),
            ruzstd::encoding::CompressionLevel::Fastest,
        )
    }

    /// **The coding this tier used to fail open on.** Chrome has offered `zstd`
    /// since Chrome 123 and CDNs answer with it, so a document arriving this way
    /// was forwarded unfiltered. One byte at a time, because that is the shape
    /// that finds a decoder which cannot carry a block across a chunk boundary.
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

    /// **A bomb is a body, not a bug.** Every coding here expands without a
    /// bound the framing states, so the ceiling is what makes this tier's memory
    /// a function of the ceiling rather than of what an origin chose to send.
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

    /// A truncated compressed stream has no recoverable remainder, so the body
    /// ends visibly rather than silently short — the same answer ambiguous
    /// markup gets, and for the same reason.
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

    /// A body whose bytes are not the coding its header claims fails the same
    /// way: there is nothing to forward, so the failure is visible.
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
