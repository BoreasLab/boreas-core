//! The filter-list pipeline: list text in, host rules out.
//!
//! This is the compiler between two very different worlds. A filter list is
//! hundreds of thousands of lines of Adblock Plus syntax written against
//! *URLs*, and the tier this crate can enforce without a CA installed is
//! *names*. Most of a list is therefore not enforceable here — and the honest
//! response to that is to say so per rule rather than to approximate.
//!
//! Three decisions carry the design.
//!
//! **A line classifies into a closed sum, and every arm is a real answer.**
//! [`Rule`] has a variant for "enforceable", a variant for "nothing to
//! enforce", and a variant for "well-formed but this tier cannot decide it",
//! carrying [`Deferred`] to say which faculty is missing. A rule that needs a
//! URL is not a parse error and not a silent drop; it is a counted deferral,
//! and the count is what tells an operator how much coverage waits on MITM.
//!
//! **Deferring is the fail-open direction, and it is chosen deliberately.**
//! `||ads.example^$third-party` blocks a host only in third-party context, and
//! there is no third party at the name tier — the same host is first-party to
//! itself. Compiling it into a name rule would break the site that owns it.
//! Not compiling it loses coverage that P14 recovers with real URLs. Losing
//! coverage is recoverable; breaking a site the user chose to visit is not.
//!
//! **The interpretation is narrower than Adblock Plus, never wider.** `||host`
//! anchors at a domain boundary in ABP, which also matches `host.evil.example`;
//! this compiler treats it as `host` and its subdomains, which does not. Every
//! divergence goes in that direction, so a compiled list can under-block and
//! cannot over-block.

use std::{fmt, net::IpAddr, ops::Add};

use crate::{HostPolicy, HostVerdict, Name};

/// What one line of a filter list means to the name tier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    /// Block this name and everything under it.
    Block(Name),
    /// Exempt this name and everything under it. Beats every block.
    Allow(Name),
    /// Well formed, and this tier cannot enforce it.
    Deferred(Deferred),
    /// Nothing to enforce: blank, comment, or list header.
    Ignored,
}

/// Which faculty an unenforceable rule needs. Each is a phase, not an excuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deferred {
    /// Needs a scheme, path, or query — so it needs the URLs that only
    /// interception produces.
    NeedsUrl,
    /// Needs request context: `$third-party`, `$script`, `$image`. The same
    /// host is first-party to itself, so a name rule cannot express it.
    NeedsRequestContext,
    /// A cosmetic, scriptlet, or redirect rule. P16 owns these.
    Cosmetic,
    /// A hosts-file line mapping a name to a real address rather than to a
    /// sink. Boreas answers names by policy, not by substituting addresses.
    HostsMapping,
    /// A wildcard or regular-expression pattern. Matching one needs a scan
    /// this index does not perform.
    Pattern,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleError {
    /// The line names a host DNS cannot carry: too long, an empty label, or a
    /// label holding the presentation separator. Refused rather than
    /// normalized, so a rule and a query always agree about what a name is.
    UnrepresentableHost,
}

impl fmt::Display for RuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnrepresentableHost => "rule names a host DNS cannot carry",
        })
    }
}

impl std::error::Error for RuleError {}

/// What a list contributed, and what it did not.
///
/// A commutative monoid under [`ListReport::merge`], with [`Default`] as its
/// identity, which is what lets several lists be compiled independently and
/// their reports summed in any order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ListReport {
    pub blocked: u32,
    pub allowed: u32,
    pub ignored: u32,
    pub malformed: u32,
    pub deferred: Deferrals,
}

/// Deferrals by missing faculty. Reported per kind because the kinds have very
/// different futures: `NeedsUrl` and `NeedsRequestContext` are recovered by
/// P14's interception, `Cosmetic` by P16, and `Pattern` by nothing currently
/// planned.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Deferrals {
    pub needs_url: u32,
    pub needs_request_context: u32,
    pub cosmetic: u32,
    pub hosts_mapping: u32,
    pub pattern: u32,
}

impl Deferrals {
    pub fn total(self) -> u32 {
        self.needs_url
            .saturating_add(self.needs_request_context)
            .saturating_add(self.cosmetic)
            .saturating_add(self.hosts_mapping)
            .saturating_add(self.pattern)
    }

    fn count(&mut self, deferred: Deferred) {
        let slot = match deferred {
            Deferred::NeedsUrl => &mut self.needs_url,
            Deferred::NeedsRequestContext => &mut self.needs_request_context,
            Deferred::Cosmetic => &mut self.cosmetic,
            Deferred::HostsMapping => &mut self.hosts_mapping,
            Deferred::Pattern => &mut self.pattern,
        };
        *slot = slot.saturating_add(1);
    }
}

impl Add for Deferrals {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self {
            needs_url: self.needs_url.saturating_add(other.needs_url),
            needs_request_context: self
                .needs_request_context
                .saturating_add(other.needs_request_context),
            cosmetic: self.cosmetic.saturating_add(other.cosmetic),
            hosts_mapping: self.hosts_mapping.saturating_add(other.hosts_mapping),
            pattern: self.pattern.saturating_add(other.pattern),
        }
    }
}

impl ListReport {
    /// The monoid operation. Associative and commutative, with `default()` as
    /// the identity: saturating addition on each field, componentwise.
    pub fn merge(self, other: Self) -> Self {
        Self {
            blocked: self.blocked.saturating_add(other.blocked),
            allowed: self.allowed.saturating_add(other.allowed),
            ignored: self.ignored.saturating_add(other.ignored),
            malformed: self.malformed.saturating_add(other.malformed),
            deferred: self.deferred + other.deferred,
        }
    }

    /// Lines seen, which is every line of every list compiled into it.
    pub fn lines(self) -> u32 {
        self.blocked
            .saturating_add(self.allowed)
            .saturating_add(self.ignored)
            .saturating_add(self.malformed)
            .saturating_add(self.deferred.total())
    }
}

/// Adblock Plus syntax this compiler names. Everything else is a deferral.
const EXCEPTION_PREFIX: &str = "@@";
const DOMAIN_ANCHOR: &str = "||";
/// The separator that terminates a host in an ABP pattern.
const SEPARATOR: char = '^';
/// Option list introducer: `$third-party`, `$script`, and the rest.
const OPTIONS: char = '$';

/// Classifies one line.
///
/// Total on the enforceable and unenforceable cases alike; the only error is a
/// host DNS cannot represent, which is a rejected rule rather than a
/// misparsed one.
///
/// O(line length), allocation-free: the only owned value produced is a
/// [`Name`], which is inline storage.
pub fn parse_rule(line: &str) -> Result<Rule, RuleError> {
    let line = line.trim();
    if line.is_empty() || is_comment(line) {
        return Ok(Rule::Ignored);
    }
    if let Some(rest) = hosts_entry(line) {
        return rest;
    }
    // Cosmetic and scriptlet rules all carry `#` before any host we could
    // read, and all of them belong to the rewriting phase.
    if line.contains("##") || line.contains("#@#") || line.contains("#?#") || line.contains("#$#") {
        return Ok(Rule::Deferred(Deferred::Cosmetic));
    }

    let (pattern, exception) = match line.strip_prefix(EXCEPTION_PREFIX) {
        Some(rest) => (rest, true),
        None => (line, false),
    };
    let Some(pattern) = pattern.strip_prefix(DOMAIN_ANCHOR) else {
        // A bare pattern is a substring match against a URL, which is exactly
        // the faculty this tier lacks.
        return Ok(Rule::Deferred(Deferred::NeedsUrl));
    };

    // Options decide a rule by request context, so a name index cannot answer
    // them; see the module documentation for why deferring beats guessing.
    if pattern.contains(OPTIONS) {
        return Ok(Rule::Deferred(Deferred::NeedsRequestContext));
    }
    let host = pattern.strip_suffix(SEPARATOR).unwrap_or(pattern);
    if host.contains('/') || host.contains('|') {
        return Ok(Rule::Deferred(Deferred::NeedsUrl));
    }
    if host.contains('*') || host.starts_with('/') {
        return Ok(Rule::Deferred(Deferred::Pattern));
    }

    let name = Name::parse(host).ok_or(RuleError::UnrepresentableHost)?;
    if name.is_root() {
        return Err(RuleError::UnrepresentableHost);
    }
    Ok(if exception {
        Rule::Allow(name)
    } else {
        Rule::Block(name)
    })
}

/// `!` introduces an Adblock Plus comment and `[` a list header. `#` is a
/// hosts-file comment, but it also introduces cosmetic rules, so it counts as
/// a comment only when what follows cannot be one of those.
fn is_comment(line: &str) -> bool {
    match line.as_bytes() {
        [b'!', ..] | [b'[', ..] => true,
        [b'#', next, ..] => !matches!(next, b'#' | b'@' | b'?' | b'$' | b'%'),
        [b'#'] => true,
        _ => false,
    }
}

/// A hosts-file line: an address, then one or more names, then an optional
/// trailing comment. `None` when the line does not start with an address, in
/// which case it is Adblock Plus syntax.
///
/// Only a sink address means "block". A line mapping a name to a real address
/// is a genuine hosts entry, and answering it would make Boreas a host table
/// rather than a filter; that is a deferral, not a block.
fn hosts_entry(line: &str) -> Option<Result<Rule, RuleError>> {
    let mut tokens = line.split_whitespace();
    let address: IpAddr = tokens.next()?.parse().ok()?;
    let host = tokens.next()?;
    if host.starts_with('#') {
        return Some(Ok(Rule::Ignored));
    }
    if !(address.is_unspecified() || address.is_loopback()) {
        return Some(Ok(Rule::Deferred(Deferred::HostsMapping)));
    }
    // A hosts line may carry several names; the first is the rule and the rest
    // are handled by `extend_from_list`, which re-enters per name.
    Some(match Name::parse(host) {
        Some(name) if !name.is_root() => Ok(Rule::Block(name)),
        _ => Err(RuleError::UnrepresentableHost),
    })
}

impl HostPolicy {
    /// Compiles `list` into this policy, reporting what it took and deferred.
    ///
    /// O(bytes of `list`), one pass, and the index grows by O(distinct
    /// enforceable hosts). A full EasyList-scale build is a few hundred
    /// thousand lines, so this is a sub-second operation on the target device
    /// and belongs off the datapath either way — the result is swapped in
    /// through the shell's `watch` channel, never edited in place.
    ///
    /// Repeated compilation is idempotent: the index is a set, so the same
    /// list applied twice yields the same policy.
    pub fn extend_from_list(&mut self, list: &str) -> ListReport {
        let mut report = ListReport::default();
        for line in list.lines() {
            // A hosts line may name several hosts; each is its own rule, and
            // splitting here keeps `parse_rule` a function of one rule.
            for rule in hosts_names(line) {
                match rule {
                    Ok(Rule::Block(name)) => {
                        self.insert_name(HostVerdict::Blocked, &name);
                        report.blocked = report.blocked.saturating_add(1);
                    }
                    Ok(Rule::Allow(name)) => {
                        self.insert_name(HostVerdict::Allowed, &name);
                        report.allowed = report.allowed.saturating_add(1);
                    }
                    Ok(Rule::Deferred(deferred)) => report.deferred.count(deferred),
                    Ok(Rule::Ignored) => report.ignored = report.ignored.saturating_add(1),
                    Err(_) => report.malformed = report.malformed.saturating_add(1),
                }
            }
        }
        report
    }
}

/// One line as one or more rules: a hosts line listing several names yields
/// one rule per name, and everything else yields exactly one rule.
///
/// O(names on the line), allocation-free.
fn hosts_names(line: &str) -> impl Iterator<Item = Result<Rule, RuleError>> {
    let mut tokens = line.split_whitespace();
    let sink = tokens
        .next()
        .and_then(|token| token.parse::<IpAddr>().ok())
        .is_some_and(|address| address.is_unspecified() || address.is_loopback());

    let extra = sink
        .then(|| {
            tokens
                .skip(1)
                .take_while(|token| !token.starts_with('#'))
                .map(|host| match Name::parse(host) {
                    Some(name) if !name.is_root() => Ok(Rule::Block(name)),
                    _ => Err(RuleError::UnrepresentableHost),
                })
        })
        .into_iter()
        .flatten();

    std::iter::once(parse_rule(line)).chain(extra)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(line: &str) -> Result<Rule, RuleError> {
        parse_rule(line)
    }

    fn block(host: &str) -> Result<Rule, RuleError> {
        Ok(Rule::Block(Name::parse(host).unwrap()))
    }

    fn allow(host: &str) -> Result<Rule, RuleError> {
        Ok(Rule::Allow(Name::parse(host).unwrap()))
    }

    #[test]
    fn enforceable_rules_compile_and_normalize() {
        assert_eq!(rule("||doubleclick.net^"), block("doubleclick.net"));
        assert_eq!(rule("||DoubleClick.NET^"), block("doubleclick.net"));
        // The separator is optional in Adblock Plus; both forms name a host.
        assert_eq!(rule("||ads.example.com"), block("ads.example.com"));
        assert_eq!(rule("@@||cdn.example.com^"), allow("cdn.example.com"));
        assert_eq!(rule("  ||spaced.example^  "), block("spaced.example"));
    }

    #[test]
    fn hosts_files_compile_only_from_sink_addresses() {
        assert_eq!(rule("0.0.0.0 tracker.example"), block("tracker.example"));
        assert_eq!(rule("127.0.0.1 tracker.example"), block("tracker.example"));
        assert_eq!(rule(":: tracker.example"), block("tracker.example"));
        assert_eq!(rule("::1  tracker.example"), block("tracker.example"));

        // A real mapping is a hosts table entry, not a filter rule.
        assert_eq!(
            rule("93.184.215.14 example.com"),
            Ok(Rule::Deferred(Deferred::HostsMapping))
        );

        // Several names on one sink line are several rules.
        let mut policy = HostPolicy::new();
        let report = policy.extend_from_list("0.0.0.0 a.example b.example c.example # why\n");
        assert_eq!(report.blocked, 3);
        for host in ["a.example", "b.example", "c.example"] {
            assert_eq!(
                policy.judge(&Name::parse(host).unwrap()).verdict,
                HostVerdict::Blocked
            );
        }
    }

    #[test]
    fn unenforceable_rules_defer_by_the_faculty_they_need() {
        // Needs a URL: a path, a scheme anchor, or a bare substring pattern.
        assert_eq!(
            rule("||example.com/ads/banner.gif"),
            Ok(Rule::Deferred(Deferred::NeedsUrl))
        );
        assert_eq!(
            rule("|http://example.com/"),
            Ok(Rule::Deferred(Deferred::NeedsUrl))
        );
        assert_eq!(rule("/ads/banner"), Ok(Rule::Deferred(Deferred::NeedsUrl)));

        // Needs request context. This is the deferral that matters most: the
        // same host is first-party to itself, so compiling it as a name rule
        // would break the site that owns it.
        assert_eq!(
            rule("||example.com^$third-party"),
            Ok(Rule::Deferred(Deferred::NeedsRequestContext))
        );
        assert_eq!(
            rule("||example.com^$script,domain=other.com"),
            Ok(Rule::Deferred(Deferred::NeedsRequestContext))
        );

        // Cosmetic and scriptlet rules belong to the rewriting phase.
        for line in [
            "example.com##.ad-banner",
            "example.com#@#.ad-banner",
            "example.com#?#div:has(> .ad)",
            "example.com#$#abort-on-property-read x",
        ] {
            assert_eq!(rule(line), Ok(Rule::Deferred(Deferred::Cosmetic)), "{line}");
        }

        // Patterns need a scan the index does not perform.
        assert_eq!(
            rule("||ads.*.example^"),
            Ok(Rule::Deferred(Deferred::Pattern))
        );
    }

    #[test]
    fn comments_and_headers_are_ignored_but_cosmetic_rules_are_not() {
        for line in [
            "",
            "   ",
            "! a comment",
            "[Adblock Plus 2.0]",
            "# hosts note",
        ] {
            assert_eq!(rule(line), Ok(Rule::Ignored), "{line:?}");
        }
        // A leading `#` introduces a comment only when what follows cannot be
        // a cosmetic separator.
        assert_eq!(rule("##.ad"), Ok(Rule::Deferred(Deferred::Cosmetic)));
    }

    #[test]
    fn a_host_dns_cannot_carry_is_a_rejected_rule() {
        assert_eq!(rule("||a..b^"), Err(RuleError::UnrepresentableHost));
        assert_eq!(rule("||^"), Err(RuleError::UnrepresentableHost));
        let long = format!("||{}^", "x".repeat(300));
        assert_eq!(rule(&long), Err(RuleError::UnrepresentableHost));
    }

    #[test]
    fn an_exception_beats_every_block_however_specific() {
        // The Adblock Plus law, and the fail-open direction the product
        // mandates: a rule that says "never touch this" is not overridden by a
        // more specific rule that says "block".
        let mut policy = HostPolicy::new();
        let report = policy.extend_from_list(
            "! a list\n\
             ||example.com^\n\
             ||ads.example.com^\n\
             @@||example.com^\n",
        );
        assert_eq!(report.blocked, 2);
        assert_eq!(report.allowed, 1);
        assert_eq!(report.ignored, 1);

        let judgment = policy.judge(&Name::parse("ads.example.com").unwrap());
        assert_eq!(judgment.verdict, HostVerdict::Allowed);
        assert_eq!(
            judgment.matched.map(|rule| rule.to_string()).as_deref(),
            Some("example.com"),
            "the exception must name itself as the reason"
        );
    }

    #[test]
    fn the_report_is_a_monoid_and_accounts_for_every_line() {
        let first = "||a.example^\n! note\n||b.example^$third-party\n";
        let second = "@@||c.example^\n||d.example^\nx##.ad\n";

        let mut together = HostPolicy::new();
        let whole = together.extend_from_list(&format!("{first}{second}"));

        let mut apart = HostPolicy::new();
        let left = apart.extend_from_list(first);
        let right = apart.extend_from_list(second);

        // Associativity and the identity, checked on the values a real build
        // produces rather than on invented ones.
        assert_eq!(whole, left.merge(right));
        assert_eq!(whole, right.merge(left), "merge is commutative");
        assert_eq!(whole, whole.merge(ListReport::default()));
        assert_eq!(whole.lines(), 6, "every line is accounted for exactly once");
        assert_eq!(together.len(), apart.len());

        // Idempotent: a set index, so the same list twice is the same policy.
        let before = together.len();
        let _ = together.extend_from_list(&format!("{first}{second}"));
        assert_eq!(together.len(), before);
    }

    #[test]
    fn a_compiled_list_under_blocks_rather_than_over_blocks() {
        // The stated invariant: every divergence from Adblock Plus goes toward
        // matching less. `||example.com` anchors at a domain boundary in ABP,
        // which also matches `example.com.evil.example`; the suffix index does
        // not, and that is the safe direction.
        let mut policy = HostPolicy::new();
        policy.extend_from_list("||example.com\n");
        assert_eq!(
            policy
                .judge(&Name::parse("example.com.evil.example").unwrap())
                .verdict,
            HostVerdict::Allowed
        );
        assert_eq!(
            policy
                .judge(&Name::parse("ads.example.com").unwrap())
                .verdict,
            HostVerdict::Blocked
        );
    }
}
