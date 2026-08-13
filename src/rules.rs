//! The rule engine: Adblock Plus syntax in, decisions out.
//!
//! [Filtering](../docs/filtering.md) draws the boundary this module implements:
//! *`adblock` decides and `lol_html` transforms.* Brave's engine is the one
//! shipping in a browser against the same subscriptions Boreas targets, and the
//! two faculties [`crate::Deferred`] counts as missing at the name tier are
//! exactly what it supplies — full URL matching with request context, and
//! hostname-scoped cosmetic rules. Neither is a parser worth writing twice, and
//! a second implementation of Adblock syntax would differ from the reference in
//! ways no test here would find.
//!
//! **The engine answers two questions and this module asks both.** A request
//! becomes a [`FilterVerdict`], which is the URL tier P13 deferred to; a host
//! becomes a compiled [`HidingRules`], which is what the HTML tier removes and
//! injects with. One index, loaded once, serving both.
//!
//! **Request context is read from the client, not guessed.** `$third-party`,
//! `$script`, and `$image` decide most of a real list, and a proxy that guesses
//! them wrong either breaks a site or fails to block anything. Boreas
//! terminates TLS, so it sees what a browser actually sends: `Sec-Fetch-Dest`
//! names the resource kind the fetch was made for, and `Referer` names the
//! document it was made from. Where a client sends neither, the request is
//! typed [`Other`](adblock::request::RequestType::Other) and treated as
//! first-party — the reading that blocks least, which is the direction every
//! uncertainty in this crate resolves toward.
//!
//! **Generic cosmetic rules are not served, and that is the engine's design
//! rather than a shortcut here.** `url_cosmetic_resources` deliberately returns
//! only the host-specific set; the generic set is far too large to ship per
//! page and is indexed by class and id token, to be queried with the tokens a
//! document actually contains. A browser collects those from the DOM. A
//! streaming rewriter could collect them as it walks the document and inject a
//! second stylesheet before `</body>` — CSS does not care where the rule was
//! declared — which is a real follow-up rather than an impossibility, and is
//! recorded as one.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use adblock::{
    Engine,
    lists::{FilterSet, ParseOptions},
    request::Request as RuleRequest,
};
use hyper::{Request, Uri, body::Incoming, header};

use crate::{CosmeticSource, FilterVerdict, HidingRules, RequestFilter};

/// The compiled rule index, serving the URL tier and the HTML tier from one
/// copy of the lists.
pub struct RuleEngine {
    engine: Engine,
    /// Compiled hiding rules per host.
    ///
    /// Memoized because `url_cosmetic_resources` walks the hostname's suffixes
    /// and unions several rule sets, and compiling the result parses a selector
    /// list and hashes a stylesheet — all of which is a function of the host
    /// alone and so needs doing once, not once per document. Bounded by the
    /// interception allowlist, since no other host reaches a rewriter.
    cosmetic: RwLock<HashMap<String, Option<Arc<HidingRules>>>>,
}

impl std::fmt::Debug for RuleEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RuleEngine")
    }
}

impl RuleEngine {
    /// Compiles subscriptions into one index.
    ///
    /// Rules the engine cannot parse are ignored rather than fatal, which is
    /// what a browser does with the same lists: a subscription that gains a
    /// syntax this build predates must not take the rest of the list with it.
    ///
    /// O(bytes of the lists). An EasyList-scale build is a sub-second operation
    /// that belongs off the datapath; the result is swapped in whole, never
    /// edited in place.
    #[must_use]
    pub fn from_lists(lists: impl IntoIterator<Item = String>) -> Self {
        let mut set = FilterSet::new(false);
        for list in lists {
            set.add_filter_list(list, ParseOptions::default());
        }
        Self::from_filter_set(set)
    }

    fn from_filter_set(set: FilterSet) -> Self {
        Self {
            engine: Engine::new_with_filter_set(set),
            cosmetic: RwLock::new(HashMap::new()),
        }
    }

    /// An index with no rules: allows every request and hides nothing.
    #[must_use]
    pub fn empty() -> Self {
        Self::from_lists(std::iter::empty())
    }
}

/// The URL a rule is matched against.
///
/// HTTP/1.1 sends an origin-form target and HTTP/2 an absolute one, so the
/// authority comes from the SNI-validated host rather than from anything the
/// request claims — the same rule the exchange already applies to filtering.
/// The scheme is `https` because it is not a guess: Boreas only ever terminates
/// TLS, so an intercepted request is an `https` request by construction.
fn absolute(host: &str, uri: &Uri) -> String {
    if uri.scheme().is_some() {
        return uri.to_string();
    }
    let path = uri.path_and_query().map_or("/", |target| target.as_str());
    format!("https://{host}{path}")
}

/// The resource kind the fetch was made for, in the engine's vocabulary.
///
/// `Sec-Fetch-Dest` is a browser-set request header that names exactly this and
/// cannot be forged by page script, so it is read first. Its values are mapped
/// to the closest content type the engine names; the empty destination is a
/// `fetch()` or `XMLHttpRequest`, which is the one that needs translating.
///
/// Falling back to `Accept` recovers older clients: it is a preference list
/// rather than a declaration, so it is consulted only for its leading type and
/// only when the authoritative header is absent.
fn destination<B>(request: &Request<B>) -> &'static str {
    if let Some(dest) = request
        .headers()
        .get("sec-fetch-dest")
        .and_then(|value| value.to_str().ok())
    {
        return match dest {
            "document" => "document",
            "iframe" | "frame" => "subdocument",
            "script" | "serviceworker" | "sharedworker" | "worker" => "script",
            "style" => "stylesheet",
            "image" => "image",
            "font" => "font",
            "audio" | "video" | "track" | "audioworklet" | "paintworklet" => "media",
            "object" | "embed" => "object",
            "report" => "csp_report",
            "empty" => "xhr",
            _ => "other",
        };
    }
    match request
        .headers()
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .and_then(|accept| accept.split(',').next())
        .map(str::trim)
    {
        Some(accept) if accept.starts_with("text/html") => "document",
        Some(accept) if accept.starts_with("text/css") => "stylesheet",
        Some(accept) if accept.starts_with("image/") => "image",
        Some(accept) if accept.starts_with("font/") => "font",
        Some(accept) if accept.starts_with("audio/") || accept.starts_with("video/") => "media",
        Some("*/*") | Some(_) | None => "other",
    }
}

impl RuleEngine {
    /// The URL tier's verdict.
    ///
    /// **Every uncertainty resolves to allow.** A URL the engine will not parse,
    /// a request with no usable context — each of them forwards, because a
    /// blocked subresource is a broken page and an unblocked one is only an
    /// advertisement. The engine's own `should_block` already folds exceptions
    /// and `$important` in the order the syntax defines, so this adds no
    /// precedence of its own.
    ///
    /// O(1) expected against the compiled index, which is a token-bucketed
    /// match rather than a scan over rules.
    ///
    /// Generic over the body because it reads only the head — saying so in the
    /// type is both honest and what lets this be exercised without standing up
    /// a connection to manufacture a [`hyper::body::Incoming`].
    #[must_use]
    pub fn verdict<B>(&self, host: &str, request: &Request<B>) -> FilterVerdict {
        let url = absolute(host, request.uri());
        // The document the fetch was made from decides `$third-party`. A
        // browser sends at least the origin cross-site by default; with no
        // referrer the request is treated as first-party, which blocks least.
        let source = request
            .headers()
            .get(header::REFERER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or(&url);
        let Ok(matched) = RuleRequest::new(
            &url,
            source,
            destination(request),
            request.method().as_str(),
        ) else {
            return FilterVerdict::Allow;
        };
        if self.engine.check_network_request(&matched).should_block() {
            FilterVerdict::Block
        } else {
            FilterVerdict::Allow
        }
    }
}

impl RequestFilter for RuleEngine {
    fn decide(&self, host: &str, request: &Request<Incoming>) -> FilterVerdict {
        self.verdict(host, request)
    }
}

impl CosmeticSource for RuleEngine {
    fn rules(&self, host: &str) -> Option<Arc<HidingRules>> {
        let host = host.to_ascii_lowercase();
        if let Some(cached) = self
            .cosmetic
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(&host)
        {
            return cached.clone();
        }
        // The engine takes a URL rather than a hostname, and cosmetic rules are
        // scoped by hostname alone, so the document root stands for the page.
        let resources = self
            .engine
            .url_cosmetic_resources(&format!("https://{host}/"));
        let compiled = HidingRules::compile(resources.hide_selectors).map(Arc::new);
        self.cosmetic
            .write()
            .unwrap_or_else(|poison| poison.into_inner())
            .insert(host, compiled.clone());
        compiled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = "\
! a subscription
||ads.example^
||tracker.example^$third-party
||cdn.example/analytics.js$script
@@||cdn.example/analytics.js$script,domain=partner.example
example.com##.ad-banner
example.com##div[data-ad]
example.com#@#.ad-banner
##.generic-ad
";

    fn engine() -> RuleEngine {
        RuleEngine::from_lists([LIST.to_owned()])
    }

    /// A request head. `Incoming` has no public constructor and the filter
    /// never reads a body, which is exactly what [`RuleEngine::verdict`] being
    /// generic over it says.
    fn request(url: &str, headers: &[(&str, &str)]) -> Request<()> {
        let mut builder = Request::builder().uri(url);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).unwrap()
    }

    #[test]
    fn a_blocking_rule_blocks_and_everything_else_forwards() {
        let engine = engine();
        assert_eq!(
            engine.verdict("ads.example", &request("/banner.png", &[])),
            FilterVerdict::Block
        );
        assert_eq!(
            engine.verdict("example.com", &request("/index.html", &[])),
            FilterVerdict::Allow
        );
    }

    /// The faculty the name tier could not have: the same host is blocked or
    /// allowed depending on the document that asked for it.
    #[test]
    fn request_context_decides_a_third_party_rule() {
        let engine = engine();
        // Fetched from another site: third party, and blocked.
        assert_eq!(
            engine.verdict(
                "tracker.example",
                &request("/pixel.gif", &[("referer", "https://example.com/page")])
            ),
            FilterVerdict::Block
        );
        // Fetched from itself: first party, and the rule does not apply.
        assert_eq!(
            engine.verdict(
                "tracker.example",
                &request("/pixel.gif", &[("referer", "https://tracker.example/home")])
            ),
            FilterVerdict::Allow
        );
    }

    /// `Sec-Fetch-Dest` is what makes `$script` mean anything, and it is read
    /// rather than inferred from the path.
    #[test]
    fn the_resource_kind_comes_from_the_client_not_from_the_url() {
        let engine = engine();
        let as_script = request(
            "/analytics.js",
            &[
                ("sec-fetch-dest", "script"),
                ("referer", "https://example.com/"),
            ],
        );
        assert_eq!(
            engine.verdict("cdn.example", &as_script),
            FilterVerdict::Block
        );

        // The identical URL fetched as a document is not what the rule names.
        let as_document = request(
            "/analytics.js",
            &[
                ("sec-fetch-dest", "document"),
                ("referer", "https://example.com/"),
            ],
        );
        assert_eq!(
            engine.verdict("cdn.example", &as_document),
            FilterVerdict::Allow
        );

        // And an exception scoped to one document wins over the block.
        let excepted = request(
            "/analytics.js",
            &[
                ("sec-fetch-dest", "script"),
                ("referer", "https://partner.example/"),
            ],
        );
        assert_eq!(
            engine.verdict("cdn.example", &excepted),
            FilterVerdict::Allow
        );
    }

    #[test]
    fn every_destination_maps_to_a_kind_the_engine_names() {
        for (dest, expected) in [
            ("document", "document"),
            ("iframe", "subdocument"),
            ("script", "script"),
            ("style", "stylesheet"),
            ("image", "image"),
            ("font", "font"),
            ("video", "media"),
            ("embed", "object"),
            ("empty", "xhr"),
            ("manifest", "other"),
        ] {
            assert_eq!(
                destination(&request("/x", &[("sec-fetch-dest", dest)])),
                expected,
                "{dest}"
            );
        }
        // Older clients, read from `Accept` only when the authoritative header
        // is absent.
        assert_eq!(
            destination(&request("/x", &[("accept", "text/html,*/*;q=0.8")])),
            "document"
        );
        assert_eq!(
            destination(&request("/x", &[("accept", "image/webp,*/*")])),
            "image"
        );
        assert_eq!(destination(&request("/x", &[])), "other");
    }

    /// Cosmetic rules arrive host-scoped and exception-resolved, and the
    /// stylesheet the HTML tier injects is built from exactly that set.
    #[test]
    fn cosmetic_rules_reach_the_html_tier_with_exceptions_already_applied() {
        let engine = engine();
        let rules = engine.rules("example.com").expect("example.com has rules");
        assert_eq!(rules.len(), 1, "the exception removed one of the two");
        assert!(rules.style().contains("div[data-ad]"));
        assert!(
            !rules.style().contains(".ad-banner"),
            "an excepted selector must not be hidden"
        );

        // Subdomains inherit, and unrelated hosts get nothing.
        assert!(engine.rules("www.example.com").is_some());
        assert!(engine.rules("other.example").is_none());
    }

    /// The memo must be transparent: asking twice is the same answer and the
    /// same allocation, or the stylesheet's hash could differ between two
    /// responses on one connection and the second would be blocked by the CSP
    /// the first widened.
    #[test]
    fn the_cosmetic_memo_returns_one_compiled_rule_set() {
        let engine = engine();
        let first = engine.rules("example.com").unwrap();
        let second = engine.rules("example.com").unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert!(engine.rules("nothing.example").is_none());
        assert!(
            engine.rules("nothing.example").is_none(),
            "a miss memoizes too"
        );
    }

    #[test]
    fn an_empty_engine_allows_everything_and_hides_nothing() {
        let engine = RuleEngine::empty();
        assert_eq!(
            engine.verdict("ads.example", &request("/banner.png", &[])),
            FilterVerdict::Allow
        );
        assert!(engine.rules("example.com").is_none());
    }
}
