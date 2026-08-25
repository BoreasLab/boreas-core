#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""The release tag algebra: two tag shapes, one order, no ambiguity.

Every binary this project ships is named by a git tag, and there are exactly two
kinds:

    v0.4.2                                       a release, cut by hand
    v0.4.3-dev.2026-08-24.11-30-00.a1b2c3d4e5f6  a pre-release, cut by main

**Both are valid SemVer, and that is the whole point.** SemVer 2.0.0 §11 makes a
pre-release sort *before* the release it shares a core version with, so
`v0.4.3-dev...` precedes `v0.4.3` — which is why a pre-release is numbered for
the patch that has not happened yet rather than the one that has. A consumer
sorting tags gets "newest" for free, and gets it right.

Two properties of the stamp carry that ordering and both are load-bearing:

* **ISO date, zero-padded time.** SemVer compares dot-separated identifiers
  left to right, and any identifier containing a hyphen is compared as ASCII.
  `2026-08-24` and `11-30-00` therefore sort chronologically *because* they are
  zero-padded and big-endian. `2026-8-24` or `9-30-00` would sort wrongly and
  nothing would notice until two builds an hour apart came back in the wrong
  order.
* **The commit last.** It is the tiebreaker for two builds in the same second,
  and it is what makes a tag say which tree it came from without a lookup.

One caveat, recorded rather than fixed: SemVer ranks an all-digit identifier
below any alphanumeric one, so a commit abbreviating to twelve digits would sort
below its siblings. That can only reorder two builds stamped in the same second,
which is not a distinction anything here draws.

    scripts/release.py --next          the next pre-release tag, from git
    scripts/release.py --check v0.4.2  gate a release tag against Cargo.toml
    scripts/release.py --selftest      this module's doctests, which are the laws

**Run it through `uv`.** The PEP 723 block above is the whole environment.
"""

from __future__ import annotations

import argparse
import contextlib
import doctest
import enum
import io
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple

import tomllib

ROOT = Path(__file__).resolve().parent.parent

#: How much of the commit goes in a tag. Twelve is unambiguous for any tree this
#: project will have and still reads in one glance.
COMMIT_CHARS = 12


class Exit(enum.IntEnum):
    """Exit statuses, as a closed sum rather than scattered integers."""

    OK = 0
    ERROR = 1
    MALFORMED = 2


class Version(NamedTuple):
    """A SemVer core version.

    A `NamedTuple` because tuple ordering *is* SemVer's core ordering — compare
    major, then minor, then patch, numerically — so the order comes from the
    representation rather than from a method that could disagree with it.

    >>> Version(0, 4, 2) < Version(0, 4, 10) < Version(0, 5, 0) < Version(1, 0, 0)
    True
    """

    major: int
    minor: int
    patch: int

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    def bump_patch(self) -> Version:
        """The next patch version.

        >>> str(Version(0, 4, 2).bump_patch())
        '0.4.3'
        """
        return Version(self.major, self.minor, self.patch + 1)


class Release(NamedTuple):
    """A version someone decided to ship. Cut by hand, never by CI.

    >>> str(Release(Version(1, 2, 3)))
    'v1.2.3'
    """

    version: Version

    def __str__(self) -> str:
        return f"v{self.version}"


class PreRelease(NamedTuple):
    """A build of `main`, named for the patch it is heading toward.

    `commit` is the abbreviated hash of the tree it was built from; `stamp` is
    when. Both are rendered into the tag, so the tag alone answers "which tree,
    and when" without a lookup.

    >>> at = datetime(2026, 8, 24, 11, 30, 0, tzinfo=timezone.utc)
    >>> str(PreRelease(Version(0, 4, 3), at, "a1b2c3d4e5f6"))
    'v0.4.3-dev.2026-08-24.11-30-00.a1b2c3d4e5f6'
    """

    version: Version
    stamp: datetime
    commit: str

    def __str__(self) -> str:
        day = self.stamp.strftime("%Y-%m-%d")
        # Hyphens, not colons: SemVer's identifier alphabet is `[0-9A-Za-z-]`,
        # and a colon would make the whole tag invalid rather than merely ugly.
        time = self.stamp.strftime("%H-%M-%S")
        return f"v{self.version}-dev.{day}.{time}.{self.commit}"


#: A release tag and nothing else. Anchored at both ends, so `v1.2.3-dev.…`
#: does not match: the two shapes are disjoint by construction rather than by
#: the order the parser tries them in.
RELEASE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")

#: A pre-release tag. The stamp's field widths are fixed, which is what the
#: ordering law depends on — see the module docstring.
PRERELEASE = re.compile(
    r"^v(\d+)\.(\d+)\.(\d+)-dev\.(\d{4}-\d{2}-\d{2})\.(\d{2}-\d{2}-\d{2})\.([0-9a-f]+)$"
)


def parse(tag: str) -> Release | PreRelease | None:
    """The one way a tag string becomes a tag.

    `None` for anything that is not one of the two shapes, so a tag someone
    typed by hand is refused here rather than reaching a build that names an
    artefact after it.

    >>> parse("v1.2.3")
    Release(version=Version(major=1, minor=2, patch=3))
    >>> parse("v0.4.3-dev.2026-08-24.11-30-00.a1b2c3d4e5f6").commit
    'a1b2c3d4e5f6'

    Round-tripping is the law that keeps the parser and the renderer honest.

    >>> at = datetime(2026, 8, 24, 11, 30, 0, tzinfo=timezone.utc)
    >>> both = [Release(Version(1, 2, 3)), PreRelease(Version(0, 4, 3), at, "abc123abc123")]
    >>> all(parse(str(tag)) == tag for tag in both)
    True

    Everything else is refused, including the shapes that look close.

    >>> [parse(bad) for bad in ("1.2.3", "v1.2", "v1.2.3-rc1", "v1.2.3-dev.2026-8-24.1-2-3.ab")]
    [None, None, None, None]
    """
    if (release := RELEASE.match(tag)) is not None:
        return Release(Version(*map(int, release.groups())))
    if (pre := PRERELEASE.match(tag)) is not None:
        major, minor, patch, day, time, commit = pre.groups()
        stamp = datetime.strptime(f"{day} {time}", "%Y-%m-%d %H-%M-%S").replace(
            tzinfo=timezone.utc
        )
        return PreRelease(Version(int(major), int(minor), int(patch)), stamp, commit)
    return None


def precedence(tag: Release | PreRelease) -> tuple:
    """SemVer 2.0.0 §11 precedence, as a sort key.

    The `1` and `0` are the rule that a release outranks any pre-release of the
    same core version. Everything after them only ever compares two
    pre-releases, where the stamp's fixed widths make ASCII order chronological.

    A pre-release sorts below the release it is heading toward:

    >>> at = datetime(2026, 8, 24, 11, 30, 0, tzinfo=timezone.utc)
    >>> precedence(PreRelease(Version(0, 4, 3), at, "aaa")) < precedence(Release(Version(0, 4, 3)))
    True

    And above the release it was cut from, which is what `bump_patch` buys:

    >>> precedence(Release(Version(0, 4, 2))) < precedence(PreRelease(Version(0, 4, 3), at, "aaa"))
    True

    Later builds sort later — the property the zero padding exists for. An
    unpadded `9-30-00` would sort *above* `11-30-00` and break this:

    >>> morning = datetime(2026, 8, 24, 9, 30, 0, tzinfo=timezone.utc)
    >>> noon = datetime(2026, 8, 24, 11, 30, 0, tzinfo=timezone.utc)
    >>> precedence(PreRelease(Version(1, 0, 0), morning, "aaa")) < \
            precedence(PreRelease(Version(1, 0, 0), noon, "aaa"))
    True
    """
    match tag:
        case Release(version):
            return (*version, 1)
        case PreRelease(version, stamp, commit):
            # The two stamp identifiers joined, which orders identically to
            # comparing them one at a time *because* both are fixed width.
            return (*version, 0, stamp.strftime("%Y-%m-%d.%H-%M-%S"), commit)
        case _:  # pragma: no cover - the sum is closed
            raise TypeError(f"not a tag: {tag!r}")


def base(releases: list[Version], crate: Version) -> Version:
    """The core version the next pre-release carries.

    **One `max` over a total order, rather than a branch.** The next pre-release
    heads toward the patch after the newest release — but `Cargo.toml` is also a
    declaration of where the version is going, and before the first release it
    is the only one there is. Taking the larger of the two is correct in every
    case without asking which source is authoritative.

    Before any release, the crate's own version is the answer:

    >>> str(base([], Version(0, 1, 0)))
    '0.1.0'

    After one, the patch above it — so the pre-release sorts above the release
    it followed and below the release it precedes:

    >>> str(base([Version(0, 1, 0)], Version(0, 1, 0)))
    '0.1.1'

    A crate version raised ahead of the tags wins, which is how a minor bump
    reaches pre-releases before its release exists:

    >>> str(base([Version(0, 1, 0)], Version(0, 2, 0)))
    '0.2.0'

    And tags ahead of a lagging `Cargo.toml` also win, so a forgotten bump
    cannot make two builds claim one version:

    >>> str(base([Version(0, 1, 0), Version(0, 3, 0)], Version(0, 1, 0)))
    '0.3.1'
    """
    return max([crate, *(version.bump_patch() for version in releases)])


def crate_version(manifest: Path) -> Version:
    """The version `Cargo.toml` declares.

    One number for the C ABI and the Rust crate both, as `api/stability.md`
    promises: they ship from one repository and one build.
    """
    declared = tomllib.loads(manifest.read_text())["package"]["version"]
    match parse(f"v{declared}"):
        case Release(version):
            return version
        case _:
            raise ValueError(f"Cargo.toml declares no release version: {declared!r}")


def git(*arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.strip()


def released() -> list[Version]:
    """Every release tag in the repository, ignoring everything else.

    Pre-releases are deliberately not counted: they are cut by every push, and
    letting them raise the base would make the version climb with commit volume
    rather than with intent.
    """
    return [
        tag.version
        for line in git("tag", "--list", "v*").splitlines()
        if isinstance(tag := parse(line.strip()), Release)
    ]


def smoke() -> int:
    """Run `main` against this repository, for the same reason `android.py`
    does: doctests prove the algebra and nothing about the argument parser or
    the two files it reads.

    The gate is checked from both sides — the crate's own version is accepted,
    a version that is not it is refused, and a string that is not a release tag
    is refused before either is consulted.
    """
    declared = crate_version(ROOT / "Cargo.toml")
    wrong = declared.bump_patch()
    failures = 0

    def gate(tag: str) -> int:
        """`--check`, with its diagnostics swallowed: three of the five cases
        below are *expected* refusals, and a passing selftest should be quiet."""
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            return main(["--check", tag])

    for complaint, ok in [
        (
            "--next did not produce a pre-release tag",
            isinstance(parse(next_tag()), PreRelease),
        ),
        (f"--check rejected v{declared}", gate(f"v{declared}") == Exit.OK),
        (
            f"--check accepted v{wrong}",
            gate(f"v{wrong}") == Exit.MALFORMED,
        ),
        (
            "--check accepted a pre-release tag",
            gate(next_tag()) == Exit.MALFORMED,
        ),
        (
            "--check accepted a bare version",
            gate(str(declared)) == Exit.MALFORMED,
        ),
    ]:
        if not ok:
            print(f"release: {complaint}", file=sys.stderr)
            failures += 1

    return failures


def next_tag() -> str:
    """The pre-release tag this commit would be published under."""
    return str(
        PreRelease(
            base(released(), crate_version(ROOT / "Cargo.toml")),
            datetime.now(timezone.utc),
            git("rev-parse", f"--short={COMMIT_CHARS}", "HEAD"),
        )
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    what = parser.add_mutually_exclusive_group(required=True)
    what.add_argument("--next", action="store_true", help="the next pre-release tag")
    what.add_argument("--check", metavar="TAG", help="gate a release tag")
    what.add_argument(
        "--selftest", action="store_true", help="run the doctests and exit"
    )
    arguments = parser.parse_args(argv)

    if arguments.selftest:
        results = doctest.testmod(verbose=False)
        failures = smoke()
        print(
            f"release: {results.attempted} doctests, {results.failed} failed; "
            f"the gate smoke-tested, {failures} failed",
            file=sys.stderr,
        )
        return Exit.ERROR if results.failed or failures else Exit.OK

    manifest = ROOT / "Cargo.toml"

    if arguments.next:
        print(next_tag())
        return Exit.OK

    # The gate. A release is the one tag a human types, so it is the one that
    # can disagree with the tree it names — and a released artefact whose
    # version does not match the crate it was built from is discovered by a
    # downstream consumer, months later, as a mystery.
    tag = parse(arguments.check)
    if not isinstance(tag, Release):
        print(
            f"{arguments.check!r} is not a release tag; releases are vMAJOR.MINOR.PATCH",
            file=sys.stderr,
        )
        return Exit.MALFORMED

    declared = crate_version(manifest)
    if tag.version != declared:
        print(
            f"tag {tag} disagrees with Cargo.toml {declared}: bump one to match the other",
            file=sys.stderr,
        )
        return Exit.MALFORMED

    print(tag.version)
    return Exit.OK


if __name__ == "__main__":
    sys.exit(main())
