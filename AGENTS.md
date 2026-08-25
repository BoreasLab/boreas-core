# Boreas Agent Guide

## Start Here

Read [docs/README.md](docs/README.md), then load only the documents listed for
the subsystem you are changing. Treat documented decisions and constraints as
the product contract. Do not infer implemented status from visionary scope.

## Non-Negotiable Invariants

- Keep policy and state transitions pure. Platform I/O, sockets, clocks,
  randomness, logging, and task spawning belong at explicit effect boundaries.
- Preserve the L3/L4/L7 contract. L7 receives streams or datagrams, never raw
  packets. Packet fast paths bypass local TCP termination.
- Never block UDP producers. Bound every queue, count drops, and isolate queues
  per flow.
- Never admit IP fragments to L4 before reassembly. Preserve ECN and validate
  ICMP Packet Too Big messages against known flows.
- Permit QUIC only when datagram fidelity is native and inner MTU is at least
  1200 bytes. Inspection-required hosts must be steered to HTTP/2.
- Fail open on optional content rewriting and pinning failures. Do not weaken
  trust-boundary validation, certificate handling, or loss-preventing errors.
- Do not bridge HTTP versions. The negotiated wire protocol is an invariant,
  not an implementation detail.

## Rust Shape

- Model alternatives with enums, constrained values with smart constructors,
  and expected failure with `Result`.
- Prefer borrowed parsing, iterator primitives, and owner-thread state over
  allocation, trait objects, locks, or one task per flow.
- Add dependencies only for an immediate executable need. Verify the current
  release, maintenance state, and transitive graph first. License is not a
  criterion: add any dependency that fits, whatever its terms. Legal owns that
  question and no check in this repository gates it.
- Keep abstractions at ownership boundaries with more than one real
  implementation. No speculative adapters or configuration.
- **A new module goes in the directory whose name says something its filename
  does not** — `src/l3/`, `src/l4/`, `src/policy/`, `src/intercept/`,
  `src/egress/`, `src/host/`, listed in
  [Architecture](docs/architecture.md)'s Source Layout. What no single layer
  owns stays flat at `src/`: the pure core, the wire and sans-io vocabulary,
  the reactor bridge, the API. Export it from `src/lib.rs` regardless — the
  crate's public surface is flat, so a caller never spells a layer and moving a
  module between them breaks nothing.
- **Refine what a client can set; do not refine what the composition root
  derives.** A number a host writes through [api/](api/README.md) reaches a
  place no error can describe, so a pair it can get wrong is parsed where it is
  written — `StreamBudget::new`, `CaMaterial::from_parts`, `LocalStack::new`.
  A number `api.rs` computes from another already has its proof in the
  arithmetic, and wrapping it buys a type around a literal. The test is
  reachability from outside the crate, not representability.
- Read and write a wire format through `wire`, never by hand. `Reader` is
  total and hands back the caller's own bytes at their own lifetime, `Writer`
  appends to a `Vec`, and `Bounded` writes into a buffer that cannot grow. The
  three exist because ten formats each carried their own index arithmetic, and
  the mistake that invites is the same one every time: a length checked in one
  place and assumed in the next. `src/wire.rs`'s header says why no crate was
  added for this and why there is no SIMD path.
  Two things stay as literal indices, deliberately. A fixed-offset read or
  write inside an IP header whose length is already guarded — `datagram[12..16]`
  beside "source address at offset 12" — is the RFC's own diagram, and a cursor
  there would hide it. And **a test builds its wire bytes as literals**: a test
  that assembles its input with the encoder under test proves the two agree,
  not that either is right.
- Write a wire protocol in `sansio`'s vocabulary, not in an `async fn`. A
  negotiation is a `Negotiation` and framing is a `Codec`: bytes in, bytes out,
  no socket and no clock. `negotiate` and `Framed` are the only things that
  await on a protocol's behalf, and adding a third read loop is how the four
  they replaced each came to buffer slightly differently.
- Do not add `poll_timeout`/`handle_timeout` to a protocol that owns no timers.
  These are sequential exchanges over transports that already retransmit; the
  deadline that bounds them is a session property and lives in `Wait`. A
  `poll_timeout` that always answers `None` is a busy loop waiting to happen.
- A pure parser reports what it did **not** consume, not how much it did. A
  count crossing into a driver becomes `drain(..n)` and `input[n..]`, so an
  arithmetic slip in any one codec is an index panic in a connection task;
  a remainder is carved out of the input, so the slip cannot be expressed.
  `Decode` carries `rest` for exactly this reason.
- Take a lock with `locked`, and spawn a long-lived task through
  `Supervision`. Poisoning is one failure class with one answer, and a task
  that ends by unwinding must be counted — `tokio` catches the unwind and
  `TaskTracker::wait` discards the result, so an unwatched task's panic leaves
  no evidence on a device nobody can attach a debugger to.
- Sans-IO stops where backpressure is owned elsewhere. HTTP/2 flow control and
  a QUIC connection's send window are I/O, not decisions about bytes; lift the
  framing and leave them. `decode_grpc_header` is where that line was drawn and
  says why.

## Change Process

1. Read the owning subsystem document and direct callers.
2. State one falsifiable invariant and its cheapest check.
3. Make the smallest root-cause change.
4. Run the focused check immediately, then run:

```sh
uv run scripts/vendor.py --check
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTFLAGS='--cfg fuzzing' cargo check --manifest-path fuzz/Cargo.toml --all-targets
```

`ffi/` is a workspace member, so the commands above need `--workspace` to
reach it. Nothing there may unwind: an `extern "C"` frame that unwinds aborts
the host's whole application, so every entry point goes through
`boundary`, and `ffi/include/boreas.h` is hand-written and checked against the
Rust types by `ffi/tests/header.rs`.

`cargo test` skips `tests/interop.rs` unless a reference binary is named, and
an announced skip is not a check. Before a change to any proxy protocol or
transport lands, run it for real:

```sh
BOREAS_INTEROP=required BOREAS_SINGBOX=$(scripts/reference.sh) \
    cargo test --test interop
```

That suite is the only thing here that checks a wire format against a decoder
this project did not write. `BOREAS_INTEROP=required` turns a missing binary
into a failure, which is what CI sets.

`fuzz/` is its own workspace, so `--all-targets` above does not reach it: a
renamed field compiles here and breaks there, and `[patch.crates-io]` has to be
declared in both. Its check is last because it is the slow one.

`--cfg fuzzing` is not optional. It is what `cargo fuzz` sets, it switches on
`cfg(fuzzing)` code inside dependencies, and a vendored crate is a *path*
dependency — which cargo does not cap lints for, so that crate's own `deny`
attributes apply to us. Without the flag this command compiles a different
graph than the campaign it stands in for.

## Releases

**Every push to `main` publishes a pre-release.** `.github/workflows/release.yml`
builds four Android shared objects and two Windows DLLs, attaches SLSA build
provenance, and creates a GitHub release tagged
`v<major>.<minor>.<patch>-dev.<yyyy-mm-dd>.<hh-mm-ss>.<commit>`. Two downstream
applications consume those artefacts, so a red `main` is a broken build in
somebody else's repository — the workflow runs its own gate for that reason
rather than trusting `ci.yml` to have finished first.

A **release** is the one thing a human does: push a `vMAJOR.MINOR.PATCH` tag.
`scripts/release.py --check` refuses a tag that disagrees with `Cargo.toml`, so
bump the crate version in the same commit you intend to tag.

The two tables the pipeline stands on are `scripts/release.py` (the tag algebra
— a pre-release sorts below the release it heads toward, and later builds sort
later) and `scripts/android.py` (Gradle's ABI name, Rust's target, and the NDK's
compiler triple, which do not all agree). Their doctests *are* those laws and
run in the `check` job. Change either table only with its selftest.

`api/artifacts.md` is what downstream reads. A change to what is published, how
it is laid out, or how it is verified is a change to that page first.

Update the owning document when a decision, constraint, acceptance criterion,
dependency, risk, or verification status changes. Record unresolved claims in
[docs/verification.md](docs/verification.md), never as settled fact.

## The Downstream Contract

[api/](api/README.md) is written for two applications that are not in this
repository: **boreas-android** (Kotlin) and **boreas-windows** (C#). Both
consume the C ABI in `ffi/`, so that folder leads with it and the Rust API is a
third consumer, not the primary one.

- **It aims for sufficiency.** A downstream integration that has to read `src/`
  or `ffi/src/` to make progress has found a defect in `api/`. Fix it there.
- **A change to `ffi/`'s surface is a change to `api/` first.** The header, the
  entry points, and the four pages that describe them move together or not at
  all; `ffi/tests/header.rs` catches the layout half, and nothing catches the
  prose half but this rule.
- **Every external claim in `api/` is fact-checked against a primary source and
  quoted**, because a downstream developer cannot tell a confident sentence from
  a correct one. What could not be confirmed says so in the page and is logged
  in [docs/verification.md](docs/verification.md).
- `scripts/doclinks.py` fails the build on a link into nothing.
