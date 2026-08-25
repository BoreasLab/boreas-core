//! The release tag algebra.
//!
//! Every binary this project publishes is named by a git tag, and there are
//! exactly two kinds — which is the first thing worth having in a type rather
//! than in a `if [ "$IS_TAG" = true ]`:
//!
//! ```text
//! v0.4.2                                        a release, cut by hand
//! v0.4.3-dev.2026-08-24.11-30-00.g1a2b3c4        a pre-release, cut by main
//! ```
//!
//! **Both are valid SemVer, and the ordering is the point.** SemVer 2.0.0 §11
//! sorts a pre-release *below* the release sharing its core version, so
//! `v0.4.3-dev...` falls after `v0.4.2` and before `v0.4.3` — which is why a
//! pre-release is numbered for the patch that has not happened yet. Anything
//! that sorts tags gets "newest" right without knowing any of this.
//!
//! Three representation choices carry that ordering, and each is a law with a
//! test rather than a convention:
//!
//! * [`Version`]'s field order *is* SemVer precedence, so `Ord` is derived
//!   rather than written. What could disagree with the spec has nowhere to
//!   live.
//! * [`Stamp`] renders fixed-width and zero-padded, so ASCII order on the
//!   rendering equals chronological order on the instant. Unpadded, `9-30-00`
//!   would sort above `11-30-00`.
//! * [`Sha`] renders with a leading `g`. SemVer ranks an all-digit identifier
//!   below every alphanumeric one, so a commit that abbreviates to seven digits
//!   would sort beneath its siblings; the prefix makes that unrepresentable
//!   rather than merely unlikely.

use std::fmt;

use time::OffsetDateTime;

/// A release triple.
///
/// Field order is the precedence law: the derived `Ord` compares major, then
/// minor, then patch, which is exactly SemVer precedence on versions with no
/// pre-release part.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    major: u64,
    minor: u64,
    patch: u64,
}

/// The identity of `max` over releases: a repository that has never shipped.
pub const ORIGIN: Version = Version {
    major: 0,
    minor: 0,
    patch: 0,
};

impl Version {
    /// The next patch: what a build published between releases works toward.
    #[must_use]
    pub const fn successor(self) -> Self {
        Self {
            patch: self.patch + 1,
            ..self
        }
    }

    /// Strictly `v` and a triple. Everything else — a pre-release tag included
    /// — is not a release and does not participate in [`resolve`]'s fold.
    #[must_use]
    pub fn parse_tag(tag: &str) -> Option<Self> {
        Self::parse_triple(tag.strip_prefix('v')?)
    }

    /// Three numeric identifiers. SemVer forbids a leading zero in one, so
    /// `01` is a refusal rather than a 1.
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

/// `u64::from_str` accepts a leading `+` and a leading zero; a SemVer numeric
/// identifier accepts neither. Parse the stricter grammar.
fn numeric_identifier(text: &str) -> Option<u64> {
    let well_formed = !text.is_empty()
        && text.bytes().all(|b| b.is_ascii_digit())
        && !(text.len() > 1 && text.starts_with('0'));
    well_formed.then(|| text.parse().ok())?
}

/// A UTC instant rendered `yyyy-mm-dd.hh-mm-ss`.
///
/// Fixed width and zero-padded, so lexical order on the rendering equals
/// chronological order on the instant. That is the monotonicity law, and it is
/// tested rather than asserted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Stamp(OffsetDateTime);

impl Stamp {
    /// A fixed instant, which is how the tests below pin every rendering.
    /// Production only ever wants [`Stamp::now`].
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
    /// Written out field by field rather than through a format description, so
    /// the zero padding the ordering depends on is visible in the source.
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
/// The prefix is not decoration. A SemVer identifier of only digits is compared
/// *numerically* and ranks below every alphanumeric one, so a commit
/// abbreviating to `0012345` would sort beneath its siblings. `g` is what
/// `git describe` uses and it makes the identifier alphanumeric always.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sha([u8; 7]);

impl Sha {
    /// A full or abbreviated hex object name, of which the first seven digits
    /// are kept. Anything that is not hex is not a commit.
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
/// A sum rather than a boolean and an optional string: `Release` carries its
/// tag, `Push` has none, and "a release event with no tag" is not a state that
/// can be written down. The shell script this replaces had exactly that pair,
/// and the branch that read them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Push,
    Release { tag: String },
}

/// Why a release was refused. Each variant carries what an operator needs to
/// fix it, because the only reader is a CI log.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("'{tag}' is not a release tag; releases are vMAJOR.MINOR.PATCH")]
    NotARelease { tag: String },
    #[error("tag v{tag} disagrees with Cargo.toml {declared}: bump one to match the other")]
    ManifestDisagrees { tag: Version, declared: Version },
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
    /// The git tag, which is also the name in every published artefact.
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

    /// The core version, which names the archives inside the release.
    #[must_use]
    pub const fn version(&self) -> Version {
        match self {
            Self::Release(version) | Self::Pre { version, .. } => *version,
        }
    }

    /// Whether GitHub should mark this a pre-release, and so keep it out of
    /// "Latest". A projection of the variant, never a field that could disagree
    /// with it.
    #[must_use]
    pub const fn is_prerelease(&self) -> bool {
        matches!(self, Self::Pre { .. })
    }
}

/// The whole algebra.
///
/// Total on `Push`. On `Release`, defined exactly when the tag is a strict
/// triple that agrees with `Cargo.toml` — because the two ship together and a
/// published artefact whose version does not match the crate it was built from
/// is found by a downstream consumer, months later, as a mystery.
///
/// **The base version is one `max` over a total order rather than a branch.**
/// The next pre-release heads for the patch above the newest release, but
/// `Cargo.toml` is also a declaration of where the version is going, and before
/// the first release it is the only one there is. Taking the larger is right in
/// every case without asking which source is authoritative.
///
/// O(n) in the tag count, folding from the identity [`ORIGIN`].
pub fn resolve(
    event: &Event,
    declared: Version,
    released: impl IntoIterator<Item = Version>,
    now: Stamp,
    sha: Sha,
) -> Result<Publish, Refusal> {
    match event {
        Event::Release { tag } => {
            let version =
                Version::parse_tag(tag).ok_or_else(|| Refusal::NotARelease { tag: tag.clone() })?;
            if version == declared {
                Ok(Publish::Release(version))
            } else {
                Err(Refusal::ManifestDisagrees {
                    tag: version,
                    declared,
                })
            }
        }
        Event::Push => Ok(Publish::Pre {
            version: released
                .into_iter()
                .map(Version::successor)
                .chain([declared])
                .max()
                .unwrap_or(ORIGIN),
            stamp: now,
            sha,
        }),
    }
}

/// The version `Cargo.toml` declares for `[package]`.
///
/// A whole TOML parser is not warranted for one field, but the field must come
/// from the right table: a `version` under `[dependencies.foo]` is not this
/// crate's. Scanning stops at the next table header for exactly that reason.
#[must_use]
pub fn manifest_version(manifest: &str) -> Option<Version> {
    manifest
        .lines()
        .map(str::trim)
        .skip_while(|line| *line != "[package]")
        .skip(1)
        .take_while(|line| !line.starts_with('['))
        .find_map(|line| line.strip_prefix("version"))
        .and_then(|rest| rest.trim_start().strip_prefix('='))
        .map(|value| value.trim().trim_matches('"'))
        .and_then(Version::parse_triple)
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

    fn pre(declared: &str, released: &[&str], at: i64) -> Publish {
        resolve(
            &Event::Push,
            version(declared),
            released.iter().filter_map(|t| Version::parse_tag(t)),
            stamp(at),
            sha(),
        )
        .expect("a push is total")
    }

    /// The shape, exactly. A change here is a change every consumer sees.
    #[test]
    fn a_pre_release_names_its_time_and_its_commit() {
        assert_eq!(
            pre("0.4.2", &["v0.4.2"], NOON).tag(),
            "v0.4.3-dev.2026-08-25.11-30-00.g1a2b3c4"
        );
    }

    /// The ordering law, stated as SemVer states it: a pre-release falls
    /// between the release it followed and the release it precedes.
    #[test]
    fn a_pre_release_sorts_between_the_releases_it_lies_between() {
        let before = Publish::Release(version("0.4.2"));
        let middle = pre("0.4.2", &["v0.4.2"], NOON);
        let after = Publish::Release(version("0.4.3"));

        assert_eq!(middle.version(), version("0.4.3"));
        assert!(before.version() < middle.version());
        assert_eq!(middle.version(), after.version());
        // Same core version, and SemVer puts the pre-release first.
        assert!(middle.is_prerelease() && !after.is_prerelease());
    }

    /// What the zero padding buys. An unpadded hour would sort `9-30-00` above
    /// `11-30-00` and reverse two builds an hour apart.
    #[test]
    fn later_builds_sort_later() {
        let morning = pre("1.0.0", &[], NOON - 2 * 3600).tag();
        let noon = pre("1.0.0", &[], NOON).tag();
        assert!(morning < noon, "{morning} should sort below {noon}");
        assert!(morning.contains("09-30-00"), "{morning}");
        assert!(noon.contains("11-30-00"), "{noon}");
    }

    /// A commit that abbreviates to seven digits would be a *numeric* SemVer
    /// identifier, which ranks below every alphanumeric one. The prefix is what
    /// stops that being possible.
    #[test]
    fn a_commit_is_never_an_all_digit_identifier() {
        let digits = Sha::parse("0012345678901234567890123456789012345678").expect("hex");
        assert_eq!(digits.to_string(), "g0012345");
        assert!(
            !digits.to_string().bytes().all(|b| b.is_ascii_digit()),
            "an all-digit identifier sorts below its alphanumeric siblings"
        );
    }

    /// The base is a `max`, so it is right whichever source moved last.
    #[test]
    fn the_base_version_is_the_larger_of_the_tags_and_the_manifest() {
        // Nothing has ever shipped: the manifest is the only claim there is.
        assert_eq!(pre("0.1.0", &[], NOON).version(), version("0.1.0"));
        // After a release, the patch above it.
        assert_eq!(pre("0.1.0", &["v0.1.0"], NOON).version(), version("0.1.1"));
        // A manifest raised ahead of the tags wins.
        assert_eq!(pre("0.2.0", &["v0.1.0"], NOON).version(), version("0.2.0"));
        // And tags ahead of a lagging manifest win, so two builds cannot claim
        // one version.
        assert_eq!(
            pre("0.1.0", &["v0.1.0", "v0.3.0"], NOON).version(),
            version("0.3.1")
        );
        // Pre-release tags are not releases and do not raise the base, or the
        // version would climb with commit volume rather than with intent.
        assert_eq!(
            pre("0.1.0", &["v0.9.9-dev.2026-01-01.00-00-00.gabc1234"], NOON).version(),
            version("0.1.0")
        );
    }

    #[test]
    fn a_release_must_be_a_triple_that_agrees_with_the_manifest() {
        let gate = |tag: &str, declared: &str| {
            resolve(
                &Event::Release {
                    tag: tag.to_owned(),
                },
                version(declared),
                [],
                stamp(NOON),
                sha(),
            )
        };

        assert_eq!(
            gate("v0.4.2", "0.4.2"),
            Ok(Publish::Release(version("0.4.2")))
        );
        assert!(matches!(
            gate("v0.4.3", "0.4.2"),
            Err(Refusal::ManifestDisagrees { .. })
        ));
        for malformed in ["0.4.2", "v0.4", "v0.4.2.1", "v0.04.2", "release-0.4.2", ""] {
            assert!(
                matches!(gate(malformed, "0.4.2"), Err(Refusal::NotARelease { .. })),
                "{malformed} was accepted"
            );
        }
        // A pre-release tag is not a release, even a well-formed one.
        assert!(matches!(
            gate("v0.4.2-dev.2026-08-24.11-30-00.gabc1234", "0.4.2"),
            Err(Refusal::NotARelease { .. })
        ));
    }

    #[test]
    fn a_tag_round_trips_through_its_parser() {
        for text in ["v0.0.0", "v1.2.3", "v10.20.30"] {
            let parsed = Version::parse_tag(text).expect(text);
            assert_eq!(format!("v{parsed}"), text);
        }
    }

    /// The manifest field must come from `[package]` and stop at the next
    /// table, or a dependency's version could be read as this crate's.
    #[test]
    fn the_manifest_version_comes_from_the_package_table() {
        let manifest = "\
[package]\n\
name = \"boreas-core\"\n\
version = \"0.1.0\"\n\
edition = \"2024\"\n\
\n\
[dependencies]\n\
version = \"9.9.9\"\n";
        assert_eq!(manifest_version(manifest), Some(version("0.1.0")));

        let no_version = "[package]\nname = \"x\"\n\n[dependencies]\nversion = \"9.9.9\"\n";
        assert_eq!(manifest_version(no_version), None);
        assert_eq!(manifest_version(""), None);
    }

    /// This repository's own manifest, so a rename or a restructure of it is
    /// caught here rather than at the moment a release is cut.
    #[test]
    fn this_repositorys_manifest_parses() {
        let manifest = std::fs::read_to_string(crate::repo_root().join("Cargo.toml"))
            .expect("the root manifest");
        assert!(manifest_version(&manifest).is_some());
    }
}
