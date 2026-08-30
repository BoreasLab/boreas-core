//! Filter-list compilation from text into host policy rules.
//!
//! Filter lists describe URLs, while this tier can enforce only names without
//! a CA. Rules outside that faculty are reported individually rather than
//! approximated.
//!
//! Three decisions define the compiler.
//!
//! **A line classifies into a closed sum.** [`Rule`] distinguishes enforceable
//! rules, ignored lines, and well-formed rules this tier cannot decide. The
//! [`Deferred`] value records the missing faculty and preserves its count.
//!
//! **Deferral is fail-open.** `||ads.example^$third-party` requires request
//! context that the name tier does not have. Compiling it as a name rule could
//! block the site that owns the name; P14 can recover the deferred coverage.
//!
//! **Interpretation is narrower than Adblock Plus, never wider.** The suffix
//! index may under-block a pattern but cannot turn it into a broader block.

use std::{fmt, net::IpAddr, ops::Add};

use crate::{HostPolicy, HostVerdict, Name};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    Block(Name),
    Allow(Name),
    Deferred(Deferred),
    Ignored,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deferred {
    NeedsUrl,
    NeedsRequestContext,
    Cosmetic,
    HostsMapping,
    Pattern,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleError {
    /// The line names a host DNS cannot represent, so it is rejected rather
    /// than normalized.
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

/// Counts what a list contributed and what it deferred or rejected.
///
/// [`ListReport::merge`] is associative and commutative, with [`Default`] as
/// its identity, so independently compiled reports can be combined in any
/// order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ListReport {
    pub blocked: u32,
    pub allowed: u32,
    pub ignored: u32,
    pub malformed: u32,
    pub deferred: Deferrals,
}

/// Deferrals grouped by the capability each rule requires. `NeedsUrl` and
/// `NeedsRequestContext` are recovered by P14, while `Cosmetic` is owned by P16.
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
    pub fn merge(self, other: Self) -> Self {
        Self {
            blocked: self.blocked.saturating_add(other.blocked),
            allowed: self.allowed.saturating_add(other.allowed),
            ignored: self.ignored.saturating_add(other.ignored),
            malformed: self.malformed.saturating_add(other.malformed),
            deferred: self.deferred + other.deferred,
        }
    }

    pub fn lines(self) -> u32 {
        self.blocked
            .saturating_add(self.allowed)
            .saturating_add(self.ignored)
            .saturating_add(self.malformed)
            .saturating_add(self.deferred.total())
    }
}

const EXCEPTION_PREFIX: &str = "@@";
const DOMAIN_ANCHOR: &str = "||";
/// ABP's host terminator.
const SEPARATOR: char = '^';
/// Introduces ABP options such as `$third-party` and `$script`.
const OPTIONS: char = '$';

/// Classifies one filter-list line.
///
/// The only error is a host that DNS cannot represent. Other unsupported but
/// well-formed syntax becomes an explicit deferral.
///
/// Runs in line length and stores only the inline [`Name`] value it produces.
pub fn parse_rule(line: &str) -> Result<Rule, RuleError> {
    let line = line.trim();
    if line.is_empty() || is_comment(line) {
        return Ok(Rule::Ignored);
    }
    if let Some(rest) = hosts_entry(line) {
        return rest;
    }
    // Cosmetic and scriptlet markers belong to the rewriting phase.
    if line.contains("##") || line.contains("#@#") || line.contains("#?#") || line.contains("#$#") {
        return Ok(Rule::Deferred(Deferred::Cosmetic));
    }

    let (pattern, exception) = match line.strip_prefix(EXCEPTION_PREFIX) {
        Some(rest) => (rest, true),
        None => (line, false),
    };
    let Some(pattern) = pattern.strip_prefix(DOMAIN_ANCHOR) else {
        // A bare pattern needs URL matching.
        return Ok(Rule::Deferred(Deferred::NeedsUrl));
    };

    // Options depend on request context that a name index cannot represent.
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

/// Recognizes list comments and headers while leaving cosmetic markers for the
/// rule classifier.
fn is_comment(line: &str) -> bool {
    match line.as_bytes() {
        [b'!', ..] | [b'[', ..] => true,
        [b'#', next, ..] => !matches!(next, b'#' | b'@' | b'?' | b'$' | b'%'),
        [b'#'] => true,
        _ => false,
    }
}

/// Parses a hosts-file line, returning `None` for Adblock Plus syntax.
///
/// Sink addresses produce blocks. Real address mappings are deferred because
/// this compiler filters names instead of replacing their addresses.
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
    // The first name is the rule; additional names are expanded by the caller.
    Some(match Name::parse(host) {
        Some(name) if !name.is_root() => Ok(Rule::Block(name)),
        _ => Err(RuleError::UnrepresentableHost),
    })
}

impl HostPolicy {
    /// Compiles `list` into this policy and reports every classification.
    ///
    /// Runs in one pass over `list`; the index grows with distinct enforceable
    /// hosts. The result is built off the datapath and swapped through the
    /// shell's `watch` channel.
    ///
    /// Reapplying a list is idempotent because the index is a set.
    pub fn extend_from_list(&mut self, list: &str) -> ListReport {
        let mut report = ListReport::default();
        for line in list.lines() {
            // Expand sink lines here so `parse_rule` remains single-rule.
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

/// The iterator allocates nothing.
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
        // The separator is optional in Adblock Plus.
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

        // A real mapping is a hosts entry, not a filter rule.
        assert_eq!(
            rule("93.184.215.14 example.com"),
            Ok(Rule::Deferred(Deferred::HostsMapping))
        );

        // Each name on a sink line becomes its own rule.
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
        // Paths, scheme anchors, and bare patterns need a URL.
        assert_eq!(
            rule("||example.com/ads/banner.gif"),
            Ok(Rule::Deferred(Deferred::NeedsUrl))
        );
        assert_eq!(
            rule("|http://example.com/"),
            Ok(Rule::Deferred(Deferred::NeedsUrl))
        );
        assert_eq!(rule("/ads/banner"), Ok(Rule::Deferred(Deferred::NeedsUrl)));

        // Request-context options cannot be represented by a name rule.
        assert_eq!(
            rule("||example.com^$third-party"),
            Ok(Rule::Deferred(Deferred::NeedsRequestContext))
        );
        assert_eq!(
            rule("||example.com^$script,domain=other.com"),
            Ok(Rule::Deferred(Deferred::NeedsRequestContext))
        );

        // Cosmetic and scriptlet rules belong to P16's rewriting phase.
        for line in [
            "example.com##.ad-banner",
            "example.com#@#.ad-banner",
            "example.com#?#div:has(> .ad)",
            "example.com#$#abort-on-property-read x",
        ] {
            assert_eq!(rule(line), Ok(Rule::Deferred(Deferred::Cosmetic)), "{line}");
        }

        // Pattern matching needs a scan the index does not perform.
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
        // A leading `#` is a comment only when it is not cosmetic syntax.
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
        // An exception means "never touch this" and is not overridden by a
        // more specific block.
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

        // Check associativity and identity on reports from real list input.
        assert_eq!(whole, left.merge(right));
        assert_eq!(whole, right.merge(left), "merge is commutative");
        assert_eq!(whole, whole.merge(ListReport::default()));
        assert_eq!(whole.lines(), 6, "every line is accounted for exactly once");
        assert_eq!(together.len(), apart.len());

        // The set index makes repeated compilation idempotent.
        let before = together.len();
        let _ = together.extend_from_list(&format!("{first}{second}"));
        assert_eq!(together.len(), before);
    }

    #[test]
    fn a_compiled_list_under_blocks_rather_than_over_blocks() {
        // Any divergence from Adblock Plus must match less, never more.
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
