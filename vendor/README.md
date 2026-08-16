# Vendored crates

Crates this workspace needs a change to that upstream has not made.

**The patch is the source; the tree is derived.** `vendor/patches/<name>.patch`
is a few reviewable lines, and `vendor/<name>/` is what
[`scripts/vendor.py`](../scripts/vendor.py) produces by fetching the pristine
crates.io package and applying that patch to it. Inverting those roles — which
is how this directory started — makes the divergence invisible: a pull request
shows tens of thousands of lines, "is this still one line?" needs a download to
answer, and a hand-edit to the tree is indistinguishable from a regeneration.

    vendor/Vendor.toml          why each entry exists, and what retires it
    vendor/patches/<name>.patch the change, in `git apply -p1` form
    vendor/<name>/              generated, committed, never edited by hand
    vendor/Vendor.lock          generated; ties each tree to the patch that made it

## Using it

```sh
uv run scripts/vendor.py             # sync every entry to its newest admitted release
uv run scripts/vendor.py quiche      # only the named entries
uv run scripts/vendor.py --check     # verify the committed trees; no network, no writes
uv run scripts/vendor.py --selftest  # the tool's own doctests
```

Through [`uv`](https://docs.astral.sh/uv/). The script is a
[PEP 723](https://peps.python.org/pep-0723/) single-file program: the
`# /// script` block at its head declares the interpreter floor it needs — 3.12,
for `tomllib` and `tarfile`'s `data` extraction filter — and an empty dependency
set, because everything else it uses is standard library. `uv` reads that block
and fetches a matching interpreter if the host has none, so a contributor's
machine and CI run the same thing. The shebang says the same, so
`./scripts/vendor.py` is equivalent.

`--check` is what CI runs. It recomputes the patch and tree digests and compares
them to the lock, so it catches both halves of the drift this design can suffer:
a patch someone edited without re-materialising, and a tree someone edited
directly. It needs no network, so it is cheap enough for every job.

Editing a patch means re-running `scripts/vendor.py` and committing both.

## Why the trees are committed

`[patch.crates-io]` needs the path to exist before `cargo build` runs, so
generating on demand would put a bootstrap step in front of `cargo test` on a
fresh clone and break the three-command contract in `AGENTS.md`. The trees are
therefore generated *and* committed, with the lock as the thing that proves they
still match their patches. `.gitattributes` marks them `linguist-vendored` and
`-diff` so they stay out of language statistics and out of review diffs.

## Adding an entry

1. Write `vendor/patches/<name>.patch` — a unified diff rooted at the crate, as
   `git diff` produces inside an unpacked package.
2. Add `[patch.<name>]` to `Vendor.toml` with a `reason` and a `retires`.
3. Add `<name> = { path = "vendor/<name>" }` under `[patch.crates-io]` in the
   root `Cargo.toml`.
4. Run `scripts/vendor.py` and commit the tree and the lock.

The tool refuses any entry where those three places disagree — a `Vendor.toml`
entry for a crate the workspace does not depend on, a `[patch.crates-io]`
redirect with no patch behind it, a redirect pointing somewhere other than
`vendor/<name>`. Two of the three agreeing is the state that rots quietly, so it
is rejected rather than half-applied.

**There is no version in this directory.** The version an entry vendors is
whatever the root `Cargo.toml` requires of that crate, resolved against
crates.io — one version, in the file a Rust reader already opens to find it.
Only caret and bare requirements are implemented; anything else is refused at
the parse boundary rather than approximated, because resolving to a version
Cargo itself would not have picked is the one failure this subsystem exists to
prevent.

## Retiring an entry

Not a reminder — a decidable fact. A patch whose post-state is already present
upstream *reverse-applies*, so `scripts/vendor.py` reports `retire` on the first
sync after the change lands, and
[`.github/workflows/sync-vendor.yml`](../.github/workflows/sync-vendor.yml)
raises it as a warning. Retiring is then: delete the patch, the entry, the tree,
and the `[patch.crates-io]` line.

`conflict` is the other half of that fork and means the opposite: the patch no
longer applies at all, even through a three-way merge, and wants rebasing rather
than deleting. A plain forward-apply failure cannot tell the two apart, which is
why the reverse check runs first.

## Current entries

### `h2`

Swaps two blocks in `impl Iterator for Iter` so a request emits `:authority`
before `:scheme`, and nothing else.

The Akamai HTTP/2 fingerprint is four fields — SETTINGS, the connection
WINDOW_UPDATE, PRIORITY, and **pseudo-header order** — and the last one is the
only one no builder can reach. h2 hard-codes `:method :scheme :authority :path`
in `src/frame/headers.rs`; every current browser sends `:method :authority
:scheme :path`. RFC 9113 §8.3 requires only that pseudo-headers precede regular
fields and fixes no order among them, so both are valid HTTP/2 and only one of
them is a browser.

The other three fields are configuration, and `H2Profile::CHROME` in
`src/mirror.rs` supplies them. That module mirrors the client's own ClientHello
onto the upstream handshake; a request that then announces a pseudo-header order
no browser uses gives the whole thing back one layer higher up, which is why
this is worth a patched dependency rather than a documented gap.

Decoding is unaffected: a receiver accepts pseudo-headers in any order, so the
patch is invisible to every peer except a fingerprinter.

### `quiche`

Raises `boring` from `^4.3` to `5.2`, and nothing else.

`boring-sys` declares `links = "boringssl"`, and Cargo admits exactly one such
package per dependency graph:

```
package `boring-sys` links to the native library `boringssl`, but it conflicts
with a previous package which links to `boringssl` as well
help: only one package in the dependency graph may specify the same links value
```

quiche pins `boring = "^4.3"` — on `master` as well as on the released version —
and its crates.io package ships neither a `build.rs` nor a vendored BoringSSL,
so the `boring` crate is the only way it can obtain one. That makes upstream's
pin binding on the whole graph, including Boreas's own originating-TLS seam,
which must be BoringSSL because rustls has no supported way to shape a
ClientHello.

What 4.x binds it to is `BORINGSSL_API_VERSION 21`, from May 2023, whose newest
key agreement is `X25519_KYBER768_DRAFT00` (`0x6399`). Chrome retired that
codepoint and has sent `X25519MLKEM768` (`0x11ec`) since Chrome 131. The group
list is a first-class JA4 field, so mirroring a client's hello onto a stack that
cannot express its `supported_groups` would reproduce that client faithfully in
every field except the one that most plainly dates the handshake. `boring 5.2`
vendors `BORINGSSL_API_VERSION 41`, from May 2026, and has the group.

quiche's use of `boring` is five items wide — `SslContextBuilder`, `SslMethod`,
`SslFiletype`, `SslRef`, and `ex_data::Index`, plus a raw `SSL *` handoff through
`foreign-types-shared` — none of which changed across the 4→5 boundary. That is
why the bump applies cleanly and why this entry is expected to be temporary.

**A consumer of `boreas-core` as a library would not inherit this.** `[patch]`
applies only to the workspace that declares it, so a downstream crate would
resolve `quiche` against `boring 4.x` and hit the `links` conflict above. Boreas
is a binary's core, so this is a noted consequence; if it ever ships as a
library, a hosted fork of quiche becomes the right answer.
