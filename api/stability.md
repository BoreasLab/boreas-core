# What we promise

## Stable

The `boreas_core::api` module: `TunnelConfig` and everything reachable from it,
`Platform`, `Tunnel`'s methods, `Event`, `Counters`, and the error sums —
together with `CaMaterial`, `CaKeys`, `Trust`, `Mtu`, `NatBehavior`,
`StreamBudget`, `OriginationPorts`, and the per-egress configuration structs
those name.

Within that surface we may:

- **add a field** to a struct,
- **add a variant** to an enum.

Both are minor changes. The enums you match on are `#[non_exhaustive]`, so a new
variant will not break your build; add a wildcard arm. New struct fields will,
which is why we construct with `..Default::default()` in our own examples and
suggest you do the same where a `Default` exists.

We will not rename or remove anything in that surface without a major version.

## Not stable

**Every other item this crate exports.** `Datapath`, `Shell`, `Session`, the
egress traits, the DNS message codec, the HTML rewriting tier, the packet
parser, and the rest are public because this crate's own tests, examples, and
fuzz targets drive them directly. They will change, including in patch releases.

If you reach past `api`, you are choosing to track that. Tell us what you needed
and why — a gap in `api` is a bug in `api`.

## Not the interface either

- **The `docs/` folder** is internal design material: architecture decisions,
  phase plans, verification ledgers. It describes how Boreas is built today.
  It is not a contract and is often ahead of or behind the code.
- **The dependency graph.** Boreas uses BoringSSL, quiche, rustls, hyper, and
  smoltcp today. None of those appears in `api`, on purpose — so that replacing
  one is our problem and not yours.
- **Wire behaviour** is a moving target by design. The TLS and HTTP/2
  fingerprints track what current Chrome sends, and they will change when Chrome
  changes. That is the feature, not a break.

## Versioning

Semantic versioning over the stable surface above. Before `1.0`, a breaking
change to it bumps the minor version and is called out in the changelog with the
migration.
