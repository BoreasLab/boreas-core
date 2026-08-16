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

## Change Process

1. Read the owning subsystem document and direct callers.
2. State one falsifiable invariant and its cheapest check.
3. Make the smallest root-cause change.
4. Run the focused check immediately, then run:

```sh
uv run scripts/vendor.py --check
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
RUSTFLAGS='--cfg fuzzing' cargo check --manifest-path fuzz/Cargo.toml --all-targets
```

`fuzz/` is its own workspace, so `--all-targets` above does not reach it: a
renamed field compiles here and breaks there, and `[patch.crates-io]` has to be
declared in both. Its check is last because it is the slow one.

`--cfg fuzzing` is not optional. It is what `cargo fuzz` sets, it switches on
`cfg(fuzzing)` code inside dependencies, and a vendored crate is a *path*
dependency — which cargo does not cap lints for, so that crate's own `deny`
attributes apply to us. Without the flag this command compiles a different
graph than the campaign it stands in for.

Update the owning document when a decision, constraint, acceptance criterion,
dependency, risk, or verification status changes. Record unresolved claims in
[docs/verification.md](docs/verification.md), never as settled fact.
