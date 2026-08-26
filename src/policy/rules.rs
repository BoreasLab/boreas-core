//! Rule evaluation for URL requests and host-scoped cosmetic resources.
//!
//! [Filtering](../docs/filtering.md) assigns URL decisions to `adblock` and
//! HTML transformation to `lol_html`. The browser engine supplies the URL and
//! request-context matching plus host-scoped cosmetic lookup that this crate
//! cannot reproduce safely with a second syntax implementation.
//!
//! **The engine answers two questions.** Requests become [`FilterVerdict`]s for
//! the URL tier P13 deferred to; hosts become compiled [`HidingRules`] for the
//! HTML tier. One loaded index serves both.
//!
//! **Request context comes from client headers.** `Sec-Fetch-Dest` identifies
//! the resource kind and `Referer` identifies the initiating document. When
//! neither is usable, the request is typed as [`Other`](adblock::request::RequestType::Other)
//! and treated as first-party, which is the fail-open interpretation.
//!
//! **Generic cosmetic rules are not served.** `url_cosmetic_resources` returns
//! only host-specific rules; generic rules require DOM class and id tokens that
//! a streaming rewriter does not currently collect. The follow-up is recorded
//! rather than hidden behind a partial implementation.

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

/// A compiled index shared by the URL and HTML tiers.
pub struct RuleEngine {
    engine: Engine,
    /// Memoized host-scoped hiding rules. Lookup walks hostname suffixes and
    /// compiles a selector stylesheet, so the result is a function of the host
    /// and is reused for later documents.
    cosmetic: RwLock<HashMap<String, Option<Arc<HidingRules>>>>,
}

impl std::fmt::Debug for RuleEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RuleEngine")
    }
}

impl RuleEngine {
    /// Compiles subscriptions into one index. Syntax the engine does not
    /// understand is ignored, matching browser behavior and keeping one newer
    /// rule from invalidating the rest of a list.
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

    /// Returns an index that allows every request and hides nothing.
    #[must_use]
    pub fn empty() -> Self {
        Self::from_lists(std::iter::empty())
    }
}

/// Builds the absolute URL from the validated host and request target.
fn absolute(host: &str, uri: &Uri) -> String {
    if uri.scheme().is_some() {
        return uri.to_string();
    }
    let path = uri.path_and_query().map_or("/", |target| target.as_str());
    format!("https://{host}{path}")
}

/// Maps client request headers to the engine's resource vocabulary.
/// `Sec-Fetch-Dest` is authoritative; `Accept` is the fallback for older
/// clients.
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
    /// Evaluates one request against the compiled URL rules.
    ///
    /// Unparseable URLs and missing context allow the request. The engine owns
    /// exception and `$important` precedence; this adapter adds none.
    #[must_use]
    pub fn verdict<B>(&self, host: &str, request: &Request<B>) -> FilterVerdict {
        let url = absolute(host, request.uri());
        // The referring document supplies `$third-party` context. No usable
        // referrer is treated as first-party to keep the decision fail-open.
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
        // Normalized hosts hit the memo without allocating. Unnormalized input
        // is lower-cased only for the fallback lookup or insertion.
        if let Some(cached) = self
            .cosmetic
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(host)
        {
            return cached.clone();
        }
        let host = host.to_ascii_lowercase();
        if let Some(cached) = self
            .cosmetic
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(&host)
        {
            return cached.clone();
        }
        // The document root supplies the URL while the engine scopes resources
        // by hostname.
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

    /// Builds a request head; verdict evaluation never reads its body.
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

    /// The same host changes verdict with the requesting document.
    #[test]
    fn request_context_decides_a_third_party_rule() {
        let engine = engine();
        // Fetched from another site: third party, so blocked.
        assert_eq!(
            engine.verdict(
                "tracker.example",
                &request("/pixel.gif", &[("referer", "https://example.com/page")])
            ),
            FilterVerdict::Block
        );
        // Fetched from itself: first party, so the rule does not apply.
        assert_eq!(
            engine.verdict(
                "tracker.example",
                &request("/pixel.gif", &[("referer", "https://tracker.example/home")])
            ),
            FilterVerdict::Allow
        );
    }

    /// `$script` follows `Sec-Fetch-Dest`, not the URL suffix.
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

        // The same URL as a document is not what the rule names.
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

        // An exception scoped to one document wins over the block.
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
        // Older clients use `Accept` only when the authoritative header is
        // absent.
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

    /// Cosmetic lookup returns host-scoped rules with exceptions applied.
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

        // Subdomains inherit; unrelated hosts get nothing.
        assert!(engine.rules("www.example.com").is_some());
        assert!(engine.rules("other.example").is_none());
    }

    /// Repeated lookup returns the same compiled rule set, including misses.
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
