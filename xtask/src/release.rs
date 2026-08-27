//! The release tag algebra.
//!
//! Published binaries use one of two tag shapes:
//!
//! ```text
//! v0.4.2                                        a release, cut by hand
//! v0.4.3-dev.2026-08-24.11-30-00.g1a2b3c4        a pre-release, cut by main
//! ```
//!
//! Both are valid SemVer. SemVer 2.0.0 §11 sorts a pre-release below the
//! release with the same core version, so the development tag falls between
//! `v0.4.2` and `v0.4.3` when tags are sorted.
//!
//! Three representation choices preserve that ordering:
//!
//! * [`Version`] uses field order for SemVer precedence, so derived `Ord` is
//!   sufficient.
//! * [`Stamp`] is fixed-width and zero-padded, making lexical order match
//!   chronological order.
//! * [`Sha`] has a leading `g`, making every hash identifier alphanumeric under
//!   SemVer's comparison rules.

use std::fmt;

use time::OffsetDateTime;

/// A release triple.
///
/// Field order matches SemVer precedence, so derived `Ord` is sufficient.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    major: u64,
    minor: u64,
    patch: u64,
}

/// The identity for a repository with no releases.
pub const ORIGIN: Version = Version {
    major: 0,
    minor: 0,
    patch: 0,
};

impl Version {
    /// The next patch version.
    #[must_use]
    pub const fn successor(self) -> Self {
        Self {
            patch: self.patch + 1,
            ..self
        }
    }

    /// Parses a strict `vMAJOR.MINOR.PATCH` release tag.
    ///
    /// Pre-release tags return `None` and do not participate in [`resolve`].
    #[must_use]
    pub fn parse_tag(tag: &str) -> Option<Self> {
        Self::parse_triple(tag.strip_prefix('v')?)
    }

    /// Parses three SemVer numeric identifiers.
    ///
    /// Leading zeroes are rejected because SemVer forbids them.
    #[must_use]
    pub fn parse_triple(text: &str) -> Option<Self> {
        let mut fields = text.split('.').map(numeric_identifier);
        let (major, minor, patch) = (fields.next()??, fields.next()??, fields.next()??);
        fields.next().is_none().then_some(Self {
            major,
            minor,
            patch,
        })
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// `u64::from_str` accepts `+` and leading zeroes; SemVer accepts neither.
fn numeric_identifier(text: &str) -> Option<u64> {
    let well_formed = !text.is_empty()
        && text.bytes().all(|b| b.is_ascii_digit())
        && !(text.len() > 1 && text.starts_with('0'));
    well_formed.then(|| text.parse().ok())?
}

/// A UTC instant rendered `yyyy-mm-dd.hh-mm-ss`.
///
/// Fixed width and zero padding make lexical order match chronological order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Stamp(OffsetDateTime);

impl Stamp {
    /// Constructs a test timestamp from Unix seconds.
    #[cfg(test)]
    #[must_use]
    pub fn from_unix(seconds: i64) -> Option<Self> {
        OffsetDateTime::from_unix_timestamp(seconds).ok().map(Self)
    }

    #[must_use]
    pub fn now() -> Self {
        Self(OffsetDateTime::now_utc())
    }
}

impl fmt::Display for Stamp {
    /// Field-by-field formatting keeps the ordering-dependent zero padding
    /// explicit.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (date, time) = (self.0.date(), self.0.time());
        write!(
            f,
            "{:04}-{:02}-{:02}.{:02}-{:02}-{:02}",
            date.year(),
            u8::from(date.month()),
            date.day(),
            time.hour(),
            time.minute(),
            time.second(),
        )
    }
}

/// Seven hex digits of the commit, rendered with a `g` prefix.
///
/// SemVer compares all-digit identifiers numerically and ranks them below
/// alphanumeric identifiers; the prefix avoids that ordering for hashes such
/// as `0012345`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sha([u8; 7]);

impl Sha {
    /// Parses a full or abbreviated hexadecimal object name, keeping seven
    /// digits.
    #[must_use]
    pub fn parse(full: &str) -> Option<Self> {
        let bytes = full.as_bytes();
        (bytes.len() >= 7 && bytes.iter().all(u8::is_ascii_hexdigit))
            .then(|| Self(bytes[..7].try_into().expect("length checked above")))
    }
}

impl fmt::Display for Sha {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "g{}",
            str::from_utf8(&self.0).expect("hex digits are UTF-8")
        )
    }
}

/// What triggered a publish.
///
/// The variants make a release event without a version unrepresentable.
/// `Release` carries a parsed [`Version`], so downstream code cannot receive an
/// unvalidated tag string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Push,
    Release(Version),
}

/// What is being published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Publish {
    Release(Version),
    Pre {
        version: Version,
        stamp: Stamp,
        sha: Sha,
    },
}

impl Publish {
    /// The git tag and published artefact name.
    #[must_use]
    pub fn tag(&self) -> String {
        match self {
            Self::Release(version) => format!("v{version}"),
            Self::Pre {
                version,
                stamp,
                sha,
            } => format!("v{version}-dev.{stamp}.{sha}"),
        }
    }

    /// The core version used in archive names.
    #[must_use]
    pub const fn version(&self) -> Version {
        match self {
            Self::Release(version) | Self::Pre { version, .. } => *version,
        }
    }

    /// Whether GitHub should mark this a pre-release and exclude it from
    /// `Latest`.
    #[must_use]
    pub const fn is_prerelease(&self) -> bool {
        matches!(self, Self::Pre { .. })
    }
}

/// Resolves an event into a publication.
///
/// Releases use the version named by their tag. Pushes use the patch after the
/// newest release, or [`ORIGIN`] when no release exists. No manifest version is
/// consulted, so the tag is the sole release-version source.
///
/// O(n) in the released-tag count.
pub fn resolve(
    event: Event,
    released: impl IntoIterator<Item = Version>,
    now: Stamp,
    sha: Sha,
) -> Publish {
    match event {
        Event::Release(version) => Publish::Release(version),
        Event::Push => Publish::Pre {
            version: released.into_iter().max().unwrap_or(ORIGIN).successor(),
            stamp: now,
            sha,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-08-25 11:30:00 UTC.
    const NOON: i64 = 1_787_657_400;

    fn version(text: &str) -> Version {
        Version::parse_triple(text).expect("a triple")
    }

    fn sha() -> Sha {
        Sha::parse("1a2b3c4d5e6f7890abcdef1234567890abcdef12").expect("hex")
    }

    fn stamp(seconds: i64) -> Stamp {
        Stamp::from_unix(seconds).expect("in range")
    }

    fn pre(released: &[&str], at: i64) -> Publish {
        resolve(
            Event::Push,
            released.iter().filter_map(|t| Version::parse_tag(t)),
            stamp(at),
            sha(),
        )
    }

    /// Published tag shape, including its timestamp and commit.
    #[test]
    fn a_pre_release_names_its_time_and_its_commit() {
        assert_eq!(
            pre(&["v0.4.2"], NOON).tag(),
            "v0.4.3-dev.2026-08-25.11-30-00.g1a2b3c4"
        );
    }

    /// SemVer ordering places a pre-release between its adjacent releases.
    #[test]
    fn a_pre_release_sorts_between_the_releases_it_lies_between() {
        let before = Publish::Release(version("0.4.2"));
        let middle = pre(&["v0.4.2"], NOON);
        let after = Publish::Release(version("0.4.3"));

        assert_eq!(middle.version(), version("0.4.3"));
        assert!(before.version() < middle.version());
        assert_eq!(middle.version(), after.version());
        // The pre-release sorts before the release with the same core version.
        assert!(middle.is_prerelease() && !after.is_prerelease());
    }

    /// Zero padding preserves chronological lexical order.
    #[test]
    fn later_builds_sort_later() {
        let morning = pre(&["v1.0.0"], NOON - 2 * 3600).tag();
        let noon = pre(&["v1.0.0"], NOON).tag();
        assert!(morning < noon, "{morning} should sort below {noon}");
        assert!(morning.contains("09-30-00"), "{morning}");
        assert!(noon.contains("11-30-00"), "{noon}");
    }

    /// The prefix prevents a hash from becoming an all-digit SemVer identifier.
    #[test]
    fn a_commit_is_never_an_all_digit_identifier() {
        let digits = Sha::parse("0012345678901234567890123456789012345678").expect("hex");
        assert_eq!(digits.to_string(), "g0012345");
        assert!(
            !digits.to_string().bytes().all(|b| b.is_ascii_digit()),
            "an all-digit identifier sorts below its alphanumeric siblings"
        );
    }

    /// The base follows release tags only.
    #[test]
    fn the_base_version_is_the_patch_above_the_newest_release() {
        // No release starts from ORIGIN.
        assert_eq!(pre(&[], NOON).version(), version("0.0.1"));
        assert_eq!(pre(&["v0.1.0"], NOON).version(), version("0.1.1"));
        // Tag order does not affect the newest release.
        assert_eq!(pre(&["v0.3.0", "v0.1.0"], NOON).version(), version("0.3.1"));
        // Pre-release tags do not raise the base version.
        assert_eq!(
            pre(&["v0.1.0", "v0.9.9-dev.2026-01-01.00-00-00.gabc1234"], NOON).version(),
            version("0.1.1")
        );
    }

    /// A release uses the version named by its tag; no manifest version is
    /// consulted.
    #[test]
    fn a_release_publishes_the_version_its_tag_names() {
        let released = |tag: &str| {
            resolve(
                Event::Release(Version::parse_tag(tag).expect("a release tag")),
                [],
                stamp(NOON),
                sha(),
            )
        };
        assert_eq!(released("v0.4.2"), Publish::Release(version("0.4.2")));
        assert_eq!(released("v9.9.9"), Publish::Release(version("9.9.9")));
    }

    /// Non-release strings never become `Event::Release`.
    #[test]
    fn only_a_strict_triple_parses_as_a_release() {
        for malformed in [
            "0.4.2",
            "v0.4",
            "v0.4.2.1",
            "v0.04.2",
            "release-0.4.2",
            "",
            // A well-formed pre-release tag is still not a release.
            "v0.4.2-dev.2026-08-25.11-30-00.gabc1234",
        ] {
            assert!(
                Version::parse_tag(malformed).is_none(),
                "{malformed} parsed as a release"
            );
        }
    }

    #[test]
    fn a_tag_round_trips_through_its_parser() {
        for text in ["v0.0.0", "v1.2.3", "v10.20.30"] {
            let parsed = Version::parse_tag(text).expect(text);
            assert_eq!(format!("v{parsed}"), text);
        }
    }

    /// The resolver has no manifest-version input.
    #[test]
    fn the_algebra_takes_no_manifest() {
        let pushed = pre(&["v0.1.0"], NOON);
        assert_eq!(pushed.version(), version("0.1.1"));
    }
}
