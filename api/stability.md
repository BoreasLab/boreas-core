# What we promise

Two interfaces, two kinds of promise. The C ABI is the one the shipping
applications use, and it is the stricter of the two.

## The C ABI

Stable: every symbol, type, field, and enum value in [abi.md](abi.md), and the
semantics this folder describes for them.

Within that surface we may:

- **add a function**;
- **add an enum constant**, using the next unused value;
- **add a field to the end of a struct**.

We will not renumber an existing constant, reorder or resize an existing field,
rename a symbol, or change what an existing call does — not without a major
version.

### What a struct field addition means for you

A struct grown at the end is source-compatible and **not** binary-compatible: a
caller compiled against the old header passes a shorter struct than the new
library reads. Rebuild against the new header when you update the library, and
keep the two versioned together. There is deliberately no size or version field
to negotiate with — that machinery costs every caller something on every call to
serve an upgrade path neither shipping application needs, since both compile the
header and ship the library in the same artefact.

### What an enum constant addition means for you

Handle a value you do not recognise rather than asserting exhaustiveness.
`BOREAS_UNRECOGNISED` exists for exactly this on the status enum; for an event
kind, ignore what you cannot interpret. An event we add is an event you were not
missing before.

### The layout is checked, not asserted

Every offset, width, and enum value on [abi.md](abi.md) is verified against the
Rust types by a test that runs in CI. The header and the implementation cannot
drift apart silently — if they did, the build fails rather than your field
reads.

## The Rust API

Stable: the `boreas_core::api` module — `TunnelConfig` and everything reachable
from it, `Platform`, `Tunnel`'s methods, `Event`, `Counters`, and the error
sums — together with `CaMaterial`, `CaKeys`, `Trust`, `Mtu`, `NatBehavior`,
`StreamBudget`, `OriginationPorts`, and the per-egress configuration structs
those name.

Within that surface we may **add a field to a struct** or **add a variant to an
enum**. Both are minor changes.

The enums you *match on* are `#[non_exhaustive]`, so a new variant will not
break your build; add a wildcard arm. The structs you *construct* are
deliberately not, because that attribute forbids the struct expression outright
outside the defining crate — it is an elimination-side guarantee and putting it
on a constructed type makes the type unbuildable rather than future-proof.
Construct with `..Default::default()` where a `Default` exists, and a field
added later reaches you with a value instead of a compile error.

## Not stable

**Every other item the Rust crate exports.** `Datapath`, `Shell`, `Session`, the
egress traits, the DNS message codec, the HTML rewriting tier, the packet
parser, and the rest are public because this crate's own tests, examples, and
fuzz targets drive them directly. They will change, including in patch releases.

If you reach past `api`, you are choosing to track that. Tell us what you needed
and why — a gap in `api` is a bug in `api`.

## Not the interface either

- **The `docs/` folder** is internal design material: architecture decisions,
  phase plans, verification ledgers. It describes how Boreas is built today. It
  is not a contract and is often ahead of or behind the code.
- **The dependency graph.** Boreas uses BoringSSL, quiche, rustls, hyper, and
  smoltcp today. None of those appears in this folder, on purpose — so that
  replacing one is our problem and not yours.
- **Wire behaviour** is a moving target by design. The TLS and HTTP/2
  fingerprints track what current Chrome sends, and they will change when Chrome
  changes. That is the feature, not a break.
- **Thread counts, buffer sizes, and internal timing.** The event stream and the
  counters are the observable surface; how many threads produce them is not.

## Versioning

Semantic versioning over both stable surfaces above. Before `1.0`, a breaking
change to either bumps the minor version and is called out in the changelog with
the migration.

The C ABI and the Rust crate share a version number: they ship from one
repository and one build.

## When this folder is wrong

Tell us. A documentation defect here costs you the same debugging time as a code
defect and is cheaper for us to fix — this folder exists so that integrating
does not require reading the implementation, and every time it does, that is a
bug in the folder.
