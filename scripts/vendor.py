#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Materialise the crates this workspace patches, from patches rather than trees.

A vendored crate is a *derived* artefact here. The source of truth is
`vendor/patches/<name>.patch` — a few reviewable lines — and `vendor/<name>/` is
what this script produces by fetching the pristine crates.io package and
applying that patch to it. The tree is committed anyway, because
`[patch.crates-io]` needs the path to exist before `cargo build` runs and a
fresh clone must not need a bootstrap step; `vendor/Vendor.lock` is what ties
the committed tree back to the patch that generated it, so the two cannot drift
apart unnoticed.

The version is not configured anywhere under `vendor/`. It is whatever the root
`Cargo.toml` requires of the crate, resolved against crates.io — one version,
in the file a Rust reader already opens to find it.

Retirement is decidable rather than remembered. A patch whose post-state is
already present upstream *reverse-applies*, and `git apply --reverse --check`
answers that in one call, so an entry that has outlived its reason says so on
the next sync instead of waiting for someone to re-read the manifest.

    uv run scripts/vendor.py              sync every entry to its newest admitted release
    uv run scripts/vendor.py quiche       sync only the named entries
    uv run scripts/vendor.py --check      verify the committed trees against the lock
    uv run scripts/vendor.py --selftest   run this module's doctests

`--check` touches no network and writes nothing: it recomputes the patch and
tree digests and compares them to the lock, which catches both a hand-edited
`vendor/` and a patch nobody re-materialised. It is cheap enough to run in
every CI job. Regenerating from upstream is what the sync workflow does.

stdout is a TSV report — one `outcome<TAB>name<TAB>detail` row per entry — so a
caller can fold it into a summary. Diagnostics go to stderr. The exit status is
a closed sum: 0 every entry is current or was updated, 2 at least one entry
needs a human, 1 something went wrong.

**Run it through `uv`.** The PEP 723 block above is the whole environment:
`requires-python` is 3.12 because `tomllib` and `tarfile`'s `data` extraction
filter are what the design leans on, and `dependencies` is empty because
everything else is standard library. `uv run` reads that block, fetches a
matching interpreter if the host has none, and runs the script in an isolated
environment, so every machine executes the same thing. The shebang says the
same, so `./scripts/vendor.py` is equivalent.
"""

import argparse
import doctest
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from enum import Enum, IntEnum, StrEnum
from pathlib import Path
from typing import Self

# Standard library since 3.11, and this script's PEP 723 block requires 3.12 —
# despite the block it sits in. ruff's import sorter classifies against its own
# default target version rather than against `requires-python`, so it files
# `tomllib` as third-party; the alternative is a config file whose only job is
# to say `target-version`, which is not worth carrying for one import.
import tomllib

INDEX = "https://index.crates.io"
REGISTRY = "https://static.crates.io/crates"
USER_AGENT = "boreas-core-vendor/1 (+https://github.com/BoreasLab/boreas-core)"
NETWORK_TIMEOUT = 60

#: Passed to the throwaway repository `apply_patch` builds, because a runner or
#: a contributor may have no git identity configured and `commit` would refuse.
#: These are git-level options, so they precede the subcommand; after it, `-c`
#: means "reuse the message from this commit" instead.
SCRATCH_IDENTITY = ("-c", "user.email=vendor@boreas.invalid", "-c", "user.name=vendor")


class ManifestError(Exception):
    """The manifests do not describe a vendorable set.

    Carries every problem found rather than the first, because a manifest is
    read by a human who would otherwise fix them one run at a time.
    """

    def __init__(self, problems: Sequence[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = list(problems)


# --------------------------------------------------------------- domain


@dataclass(frozen=True, slots=True, order=True)
class Version:
    """An exact release.

    Pre-release and build metadata are deliberately not representable: a
    vendored crate tracks published stable releases, and admitting `1.0.0-rc.1`
    here would mean ordering it, which is a rule nobody reading this file
    should have to keep in their head.
    """

    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, raw: str) -> Self | None:
        """
        >>> Version.parse("0.29.3")
        Version(major=0, minor=29, patch=3)
        >>> [Version.parse(bad) for bad in ("0.29", "1.0.0-rc.1", "", "a.b.c")]
        [None, None, None, None]
        """
        parts = raw.split(".")
        if len(parts) != 3 or not all(part.isdigit() for part in parts):
            return None
        return cls(*map(int, parts))

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


@dataclass(frozen=True, slots=True)
class Caret:
    """A caret requirement — `^1.2`, or the bare `1.2` Cargo treats as one.

    The only form this tool implements, and every other form is rejected at the
    parse boundary rather than approximated. A `>=`, `*`, or `~` requirement
    has semantics worth getting exactly right, and a vendoring tool that got
    them subtly wrong would resolve to a version Cargo itself would not have
    picked — which is the single failure this subsystem exists to prevent.
    """

    base: Version
    #: How many components the requirement actually wrote, which is what
    #: decides the upper bound when the leading ones are all zero.
    given: int

    @classmethod
    def parse(cls, raw: str) -> Self | None:
        """
        >>> str(Caret.parse("0.29.3")), str(Caret.parse("^1.2"))
        ('^0.29.3', '^1.2')
        >>> [Caret.parse(bad) for bad in (">=1, <2", "~1.2", "*", "1.2.3.4", "")]
        [None, None, None, None, None]
        """
        parts = raw.strip().removeprefix("^").split(".")
        if not 1 <= len(parts) <= 3 or not all(part.isdigit() for part in parts):
            return None
        return cls(Version(*[*map(int, parts), 0, 0][:3]), len(parts))

    def admits(self, version: Version) -> bool:
        """
        >>> req = Caret.parse("0.29.3")
        >>> [req.admits(Version(*v)) for v in ((0,29,3), (0,29,9), (0,29,2), (0,30,0))]
        [True, True, False, False]
        """
        return self.base <= version < self.ceiling()

    def ceiling(self) -> Version:
        """The exclusive upper bound.

        Cargo's rule: the leftmost non-zero component the requirement *wrote*
        is incremented and everything after it drops to zero. When every
        written component is zero the last one written is incremented instead,
        so `^0.0` bounds at `0.1.0` and `^0` at `1.0.0`.

        >>> [str(Caret.parse(r).ceiling()) for r in ("1.2.3", "0.29.3", "0.0.3")]
        ['2.0.0', '0.30.0', '0.0.4']
        >>> [str(Caret.parse(r).ceiling()) for r in ("0.2", "0.0", "0", "1")]
        ['0.3.0', '0.1.0', '1.0.0', '2.0.0']
        """
        components = [self.base.major, self.base.minor, self.base.patch]
        written = components[: self.given]
        index = next((i for i, value in enumerate(written) if value), self.given - 1)
        return Version(*[*components[:index], components[index] + 1, 0, 0][:3])

    def __str__(self) -> str:
        components = [self.base.major, self.base.minor, self.base.patch]
        return "^" + ".".join(map(str, components[: self.given]))


@dataclass(frozen=True, slots=True)
class Entry:
    """One patched crate.

    The name is the only identifier: the directory, the patch file, and the
    registry index path all derive from it, so an entry cannot name a directory
    holding a different crate. The requirement is read from the root
    `Cargo.toml` rather than stored here, so it cannot disagree with what Cargo
    resolves.
    """

    name: str
    requirement: Caret
    reason: str
    retires: str

    def tree(self, root: Path) -> Path:
        return root / "vendor" / self.name

    def patch(self, root: Path) -> Path:
        return root / "vendor" / "patches" / f"{self.name}.patch"

    def index_url(self) -> str:
        """The sparse-index path, whose shape is the registry's own rule: one-
        and two-character names live under `1/` and `2/`, three-character names
        under `3/<first>/`, and everything else under two two-character
        components."""
        name = self.name.lower()
        match len(name):
            case 1 | 2:
                prefix = str(len(name))
            case 3:
                prefix = f"3/{name[0]}"
            case _:
                prefix = f"{name[:2]}/{name[2:4]}"
        return f"{INDEX}/{prefix}/{name}"


@dataclass(frozen=True, slots=True)
class Release:
    version: Version
    #: sha256 of the `.crate` tarball, as the registry index publishes it.
    checksum: str


class Application(StrEnum):
    """How the patch went on — the closed sum `git apply` actually decides.

    `ALREADY_UPSTREAM` and `CONFLICTED` are the two failure shapes, and they
    are separate because their remedies are opposite: the first means delete
    the entry, the second means rebase the patch. A forward-apply failure
    alone cannot tell them apart, which is why the reverse check runs first.
    """

    CLEAN = "clean"
    MERGED = "merged"
    ALREADY_UPSTREAM = "already-upstream"
    CONFLICTED = "conflicted"

    def materialised(self) -> bool:
        """Whether a tree exists as a result. Exactly the two values a lock row
        may record."""
        return self in (Application.CLEAN, Application.MERGED)


@dataclass(frozen=True, slots=True)
class LockRow:
    name: str
    version: Version
    crate_sha256: str
    patch_sha256: str
    tree_sha256: str
    application: Application


class Action(Enum):
    """A moved version and an edited patch demand the identical operation,
    which is why this is two variants and not three."""

    MATERIALIZE = "materialize"
    VERIFY = "verify"


# The outcome of one entry. A closed sum: every arm is produced in exactly one
# place, and `status` and `render` each eliminate all of them.
@dataclass(frozen=True, slots=True)
class Updated:
    name: str
    previous: Version | None
    version: Version
    application: Application


@dataclass(frozen=True, slots=True)
class Current:
    name: str
    version: Version


@dataclass(frozen=True, slots=True)
class Retire:
    """The patch reverse-applies to the pristine package, so upstream has
    adopted it and the entry is now dead weight."""

    name: str
    version: Version


@dataclass(frozen=True, slots=True)
class Conflict:
    """The patch no longer applies, even through a three-way merge. Needs a
    human to rebase it."""

    name: str
    version: Version


@dataclass(frozen=True, slots=True)
class Drifted:
    """`--check` only: the committed tree is not what the patch and the lock
    say it should be."""

    name: str
    detail: str


@dataclass(frozen=True, slots=True)
class Failed:
    name: str
    why: str


Outcome = Updated | Current | Retire | Conflict | Drifted | Failed


class Exit(IntEnum):
    OK = 0
    ERROR = 1
    ATTENTION = 2


def status(outcomes: Iterable[Outcome]) -> Exit:
    """Fold the outcomes into one exit status, worst-wins.

    Ordered by remedy rather than by the numeric value of `Exit`: a broken run
    dominates an entry needing attention, which dominates a clean sync. Taking
    a numeric maximum here would be wrong, because `ATTENTION` is the larger
    integer and the lesser problem.

    >>> v = Version(1, 0, 0)
    >>> status([Current("a", v), Updated("b", None, v, Application.CLEAN)])
    <Exit.OK: 0>
    >>> status([Current("a", v), Retire("b", v)])
    <Exit.ATTENTION: 2>
    >>> status([Retire("a", v), Failed("b", "network")])
    <Exit.ERROR: 1>
    >>> status([])
    <Exit.OK: 0>
    """
    worst = Exit.OK
    for outcome in outcomes:
        match outcome:
            case Failed() | Drifted():
                return Exit.ERROR
            case Retire() | Conflict():
                worst = Exit.ATTENTION
            case Updated() | Current():
                pass
    return worst


def render(outcome: Outcome) -> tuple[str, str, str]:
    """One TSV row per outcome. Total over the sum, so adding a variant makes
    the missing row a visible edit here rather than a silent omission."""
    match outcome:
        case Updated(name, None, version, application):
            return ("updated", name, f"vendored {version} ({application})")
        case Updated(name, previous, version, application):
            return ("updated", name, f"{previous} -> {version} ({application})")
        case Current(name, version):
            return ("current", name, str(version))
        case Retire(name, version):
            return ("retire", name, f"{version} no longer needs the patch")
        case Conflict(name, version):
            return ("conflict", name, f"the patch does not apply to {version}")
        case Drifted(name, detail):
            return ("drifted", name, detail)
        case Failed(name, why):
            return ("failed", name, why)


# ----------------------------------------------------------- pure core


def _entry_problems(
    name: str, body: object, dependencies: dict, redirects: dict
) -> tuple[Entry | None, list[str]]:
    """Parse one manifest entry, or say everything wrong with it.

    All three places that must know about an entry have to agree: `Vendor.toml`
    says why it exists, the root `Cargo.toml` depends on the crate, and
    `[patch.crates-io]` redirects it at the tree this script writes. Any two of
    the three agreeing is the state that rots silently.
    """
    problems: list[str] = []

    def say(what: str) -> None:
        problems.append(f"[patch.{name}]: {what}")

    fields = body if isinstance(body, dict) else {}
    reason = str(fields.get("reason", "")).strip()
    retires = str(fields.get("retires", "")).strip()
    if not reason:
        say("no `reason`; an entry with no stated justification is the one that rots")
    if not retires:
        say("no `retires`; say what would make this patch unnecessary")

    declared = dependencies.get(name)
    raw = declared.get("version") if isinstance(declared, dict) else declared
    requirement = Caret.parse(str(raw)) if raw is not None else None
    if raw is None:
        say(f"the root Cargo.toml has no `{name}` dependency to patch")
    elif requirement is None:
        say(
            f"requirement `{raw}` is not a caret or bare version; no other form is implemented"
        )

    redirect = redirects.get(name)
    expected = f"vendor/{name}"
    if not isinstance(redirect, dict) or redirect.get("path") != expected:
        say(f'[patch.crates-io].{name} must be {{ path = "{expected}" }}')

    if problems or requirement is None:
        return None, problems
    return Entry(name, requirement, reason, retires), problems


def parse_manifests(vendor: dict, cargo: dict) -> list[Entry]:
    """The one boundary untrusted manifest data crosses.

    >>> vendor = {"patch": {"quiche": {"reason": "why", "retires": "when"}}}
    >>> cargo = {"dependencies": {"quiche": "0.29.3"},
    ...          "patch": {"crates-io": {"quiche": {"path": "vendor/quiche"}}}}
    >>> [(e.name, str(e.requirement)) for e in parse_manifests(vendor, cargo)]
    [('quiche', '^0.29.3')]

    Each of the three places that must agree is load-bearing on its own — a
    dependency with no entry, an entry with no dependency, and a redirect
    pointing somewhere else are all rejected rather than half-applied:

    >>> def problems(vendor, cargo):
    ...     try:
    ...         parse_manifests(vendor, cargo)
    ...     except ManifestError as error:
    ...         return error.problems
    >>> problems(vendor, {**cargo, "dependencies": {}})
    ['[patch.quiche]: the root Cargo.toml has no `quiche` dependency to patch']
    >>> problems({"patch": {}}, cargo)
    ['[patch.crates-io].quiche: redirected but absent from vendor/Vendor.toml']
    >>> problems(vendor, {**cargo, "patch": {"crates-io": {"quiche": {"path": "elsewhere"}}}})
    ['[patch.quiche]: [patch.crates-io].quiche must be { path = "vendor/quiche" }']

    A justification is required, and an unimplemented requirement form is
    refused rather than approximated:

    >>> problems({"patch": {"quiche": {"retires": "when"}}}, cargo)
    ['[patch.quiche]: no `reason`; an entry with no stated justification is the one that rots']
    >>> problems(vendor, {**cargo, "dependencies": {"quiche": ">=0.29, <0.30"}})
    ['[patch.quiche]: requirement `>=0.29, <0.30` is not a caret or bare version; no other form is implemented']
    """
    declared = vendor.get("patch", {})
    dependencies = cargo.get("dependencies", {})
    redirects = cargo.get("patch", {}).get("crates-io", {})

    parsed = [
        _entry_problems(name, body, dependencies, redirects)
        for name, body in sorted(declared.items())
    ]
    problems = [problem for _, found in parsed for problem in found]
    problems.extend(
        f"[patch.crates-io].{name}: redirected but absent from vendor/Vendor.toml"
        for name in sorted(set(redirects) - set(declared))
    )
    if problems:
        raise ManifestError(problems)
    return [entry for entry, _ in parsed if entry is not None]


def newest_admitted(requirement: Caret, releases: Iterable[Release]) -> Release | None:
    """The newest release the requirement admits, or `None` when it admits
    none. $O(n)$ over the ~10^2 releases a crate has; an ordered structure
    would be ceremony at that size.

    >>> pool = [Release(Version(0, 29, n), f"sha{n}") for n in (1, 3, 2)]
    >>> pool.append(Release(Version(0, 30, 0), "sha30"))
    >>> newest_admitted(Caret.parse("0.29.1"), pool).version
    Version(major=0, minor=29, patch=3)
    >>> newest_admitted(Caret.parse("9.9.9"), pool) is None
    True
    >>> newest_admitted(Caret.parse("0.29.1"), []) is None
    True
    """
    admitted = filter(lambda release: requirement.admits(release.version), releases)
    return max(admitted, key=lambda release: release.version, default=None)


def plan(row: LockRow | None, target: Release, patch_sha256: str) -> Action:
    """Whether an entry needs materialising.

    >>> target = Release(Version(0, 29, 3), "crate-sha")
    >>> row = LockRow("q", Version(0, 29, 3), "crate-sha", "patch-sha",
    ...               "tree-sha", Application.CLEAN)
    >>> plan(row, target, "patch-sha")
    <Action.VERIFY: 'verify'>
    >>> plan(None, target, "patch-sha")
    <Action.MATERIALIZE: 'materialize'>
    >>> plan(row, target, "edited")
    <Action.MATERIALIZE: 'materialize'>
    >>> plan(row, Release(Version(0, 29, 4), "other"), "patch-sha")
    <Action.MATERIALIZE: 'materialize'>
    """
    if row is None or row.version != target.version or row.patch_sha256 != patch_sha256:
        return Action.MATERIALIZE
    return Action.VERIFY


# ---------------------------------------------------------------- shell


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tree_digest(root: Path) -> str:
    """One comparable value for a directory: every regular file's path,
    executable bit, and content, folded in sorted-path order so the result does
    not depend on how the filesystem enumerates.

    O(bytes) in the tree, which for a vendored crate is a few MB — fast enough
    that `--check` can run in every CI job without a network round trip.
    """
    accumulator = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_dir() and not path.is_symlink():
            continue
        if path.is_symlink() or not path.is_file():
            raise OSError(f"{path}: not a regular file; a crate package holds none")
        mode = "x" if path.stat().st_mode & 0o111 else "-"
        accumulator.update(f"{path.relative_to(root).as_posix()}\0{mode}\0".encode())
        accumulator.update(digest(path.read_bytes()).encode())
    return accumulator.hexdigest()


def get(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=NETWORK_TIMEOUT) as response:
        return response.read()


def releases(entry: Entry) -> list[Release]:
    """Every non-yanked published release, read from the sparse index cargo
    itself uses. The index is the authority on checksums too, which is what
    makes the tarball verifiable."""
    rows = map(json.loads, filter(None, get(entry.index_url()).decode().splitlines()))
    live = filter(lambda row: not row.get("yanked"), rows)
    return [
        Release(version, str(row["cksum"]))
        for row in live
        if (version := Version.parse(str(row["vers"]))) is not None
    ]


def unpack(entry: Entry, release: Release, into: Path) -> Path:
    """Fetch and extract one package, refusing bytes the index does not vouch
    for.

    This is the smart-constructor boundary for third-party code: nothing
    downstream re-checks, so nothing may reach the filesystem unverified. The
    `data` filter is the second half of it — it rejects absolute paths, `..`
    traversal, links, and device nodes, every archive member shape a crate
    package has no business carrying.
    """
    archive = get(f"{REGISTRY}/{entry.name}/{entry.name}-{release.version}.crate")
    if (actual := digest(archive)) != release.checksum:
        raise OSError(
            f"{entry.name} {release.version}: sha256 {actual} does not match "
            f"the registry index's {release.checksum}"
        )
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        tar.extractall(into, filter="data")
    unpacked = into / f"{entry.name}-{release.version}"
    if not unpacked.is_dir():
        raise OSError(
            f"{entry.name} {release.version} did not unpack as {unpacked.name}"
        )
    return unpacked


def git(tree: Path, *arguments: str) -> int:
    return subprocess.run(
        ["git", *arguments], cwd=tree, capture_output=True, check=False
    ).returncode


def apply_patch(tree: Path, patch: Path) -> Application:
    """Put the patch on, and say which of the four things happened.

    The scratch repository exists so `--3way` has blobs to merge against; it is
    removed before the tree is published, so nothing nested ever reaches the
    worktree. The reverse check runs first because "upstream already did this"
    and "this no longer applies" are indistinguishable from a forward failure
    and have opposite remedies.
    """
    git(tree, "init", "-q")
    git(tree, "add", "-A")
    git(tree, *SCRATCH_IDENTITY, "commit", "-q", "-m", "pristine")

    text = str(patch)
    if git(tree, "apply", "--reverse", "--check", text) == 0:
        return Application.ALREADY_UPSTREAM
    if git(tree, "apply", "--check", text) == 0:
        git(tree, "apply", text)
        return Application.CLEAN
    if git(tree, "apply", "--3way", text) == 0:
        return Application.MERGED
    return Application.CONFLICTED


def publish(staged: Path, destination: Path) -> None:
    """Swap whole directories rather than writing into the live one, so a run
    that dies midway leaves the previous tree intact and buildable."""
    shutil.rmtree(staged / ".git", ignore_errors=True)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        shutil.rmtree(destination)
    shutil.move(str(staged), str(destination))


# ----------------------------------------------------------------- lock


def read_lock(path: Path) -> dict[str, LockRow]:
    """Rows the lock actually vouches for. A row recording an application that
    produces no tree is not one of them, so it is dropped and the entry reads
    as never materialised."""
    if not path.is_file():
        return {}
    rows = (
        LockRow(
            str(row["name"]),
            version,
            str(row["crate-sha256"]),
            str(row["patch-sha256"]),
            str(row["tree-sha256"]),
            application,
        )
        for row in tomllib.loads(path.read_text()).get("vendored", [])
        if (version := Version.parse(str(row.get("version", ""))))
        and (application := Application(str(row.get("application", "")))).materialised()
    )
    return {row.name: row for row in rows}


def write_lock(path: Path, rows: dict[str, LockRow]) -> None:
    header = (
        "# Generated by scripts/vendor.py. Do not edit.\n"
        "#\n"
        "# Ties each committed vendor/<name>/ tree to the patch that produced it.\n"
        "# `crate-sha256` is the registry's own checksum for the package the tree\n"
        "# was built from; `tree-sha256` is what `--check` recomputes to prove the\n"
        "# committed tree has not been edited by hand.\n"
    )
    body = "".join(
        "\n[[vendored]]\n"
        f'name = "{row.name}"\n'
        f'version = "{row.version}"\n'
        f'crate-sha256 = "{row.crate_sha256}"\n'
        f'patch-sha256 = "{row.patch_sha256}"\n'
        f'tree-sha256 = "{row.tree_sha256}"\n'
        f'application = "{row.application}"\n'
        for row in sorted(rows.values(), key=lambda row: row.name)
    )
    path.write_text(header + body)


# ------------------------------------------------------------ the sweep


def check_one(entry: Entry, root: Path, row: LockRow | None) -> Outcome:
    """Verify one committed tree against the lock, with no network and no
    writes. Catches both ways a tree and its patch part company: an edited
    patch nobody re-materialised, and an edited tree."""
    patch, tree = entry.patch(root), entry.tree(root)
    if row is None:
        return Drifted(entry.name, "no lock row; run scripts/vendor.py")
    if not patch.is_file():
        return Drifted(entry.name, f"{patch.relative_to(root)} is missing")
    if not tree.is_dir():
        return Drifted(entry.name, f"{tree.relative_to(root)} is missing")
    if not entry.requirement.admits(row.version):
        return Drifted(
            entry.name,
            f"locked at {row.version}, outside Cargo.toml's {entry.requirement}",
        )
    if (actual := digest(patch.read_bytes())) != row.patch_sha256:
        return Drifted(
            entry.name, f"the patch changed ({actual[:12]}); re-run scripts/vendor.py"
        )
    if (actual := tree_digest(tree)) != row.tree_sha256:
        return Drifted(entry.name, f"the tree was edited by hand ({actual[:12]})")
    return Current(entry.name, row.version)


def sync_one(
    entry: Entry, root: Path, rows: dict[str, LockRow], workspace: Path
) -> Outcome:
    """Bring one entry to the newest release its requirement admits."""
    patch = entry.patch(root)
    if not patch.is_file():
        return Failed(entry.name, f"{patch.relative_to(root)} is missing")
    patch_sha256 = digest(patch.read_bytes())

    target = newest_admitted(entry.requirement, releases(entry))
    if target is None:
        return Failed(
            entry.name, f"crates.io has no release matching {entry.requirement}"
        )

    row = rows.get(entry.name)
    if plan(row, target, patch_sha256) is Action.VERIFY and entry.tree(root).is_dir():
        return Current(entry.name, target.version)

    staged = unpack(entry, target, workspace / entry.name)
    match apply_patch(staged, patch):
        case Application.ALREADY_UPSTREAM:
            return Retire(entry.name, target.version)
        case Application.CONFLICTED:
            return Conflict(entry.name, target.version)
        case application:
            publish(staged, entry.tree(root))
            rows[entry.name] = LockRow(
                entry.name,
                target.version,
                target.checksum,
                patch_sha256,
                tree_digest(entry.tree(root)),
                application,
            )
            return Updated(
                entry.name, row.version if row else None, target.version, application
            )


def outcomes(entries: Sequence[Entry], root: Path, check: bool) -> Iterator[Outcome]:
    """One outcome per entry, accumulating rather than failing fast: a broken
    entry must not hide the state of the others."""
    lock_path = root / "vendor" / "Vendor.lock"
    rows = read_lock(lock_path)

    if check:
        yield from (check_one(entry, root, rows.get(entry.name)) for entry in entries)
        return

    with tempfile.TemporaryDirectory(prefix="boreas-vendor-") as scratch:
        for entry in entries:
            try:
                yield sync_one(entry, root, rows, Path(scratch))
            except (
                OSError,
                urllib.error.URLError,
                tarfile.TarError,
                ValueError,
            ) as error:
                yield Failed(entry.name, str(error))
    write_lock(lock_path, rows)


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Materialise patched crates under vendor/."
    )
    parser.add_argument("names", nargs="*", help="entries to act on; default is all")
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the committed trees against the lock; no network, no writes",
    )
    parser.add_argument(
        "--root", type=Path, help="workspace root; default is the git root"
    )
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="run this module's doctests, which cover the pure core, and exit",
    )
    arguments = parser.parse_args(argv)

    # A flag rather than a `python -m doctest` invocation, so the tests run
    # under the interpreter the PEP 723 block pins.
    if arguments.selftest:
        results = doctest.testmod(verbose=False)
        print(
            f"vendor: {results.attempted} doctests, {results.failed} failed",
            file=sys.stderr,
        )
        return Exit.ERROR if results.failed else Exit.OK

    root = arguments.root or Path(
        subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    )

    try:
        entries = parse_manifests(
            tomllib.loads((root / "vendor" / "Vendor.toml").read_text()),
            tomllib.loads((root / "Cargo.toml").read_text()),
        )
    except ManifestError as error:
        for problem in error.problems:
            print(f"vendor: {problem}", file=sys.stderr)
        return Exit.ERROR
    except (OSError, tomllib.TOMLDecodeError) as error:
        print(f"vendor: {error}", file=sys.stderr)
        return Exit.ERROR

    if arguments.names:
        wanted = set(arguments.names)
        if unknown := wanted - {entry.name for entry in entries}:
            print(
                f"vendor: no such entry: {', '.join(sorted(unknown))}", file=sys.stderr
            )
            return Exit.ERROR
        entries = [entry for entry in entries if entry.name in wanted]

    results = list(outcomes(entries, root, arguments.check))
    for kind, name, detail in map(render, results):
        print(f"{kind}\t{name}\t{detail}")
        print(f"vendor: {name}: {kind}: {detail}", file=sys.stderr)
    return status(results)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
