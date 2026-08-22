# Boreas Documentation

This index is the map for humans and agents. Start with the smallest document
that owns the work, then follow its links only when a boundary is crossed.

**These documents are internal.** They describe how Boreas is built today and
are not a contract. An application embedding this crate reads [api/](../api/README.md)
instead, which is self-contained and versioned — and a change here that would
alter what that folder promises is a change that needs to be made there first.

`api/` is written for the two applications that exist: **boreas-android**
(Kotlin) and **boreas-windows** (C#). Both consume the C ABI in `ffi/`, so that
is the interface the folder leads with; the Rust API is a third consumer with
the same standing. It aims to be *sufficient* — a downstream integration that
has to read `src/` or `ffi/src/` to make progress has found a defect in
`api/`, and it should be fixed there.

## Product and System

| Document | Read when working on |
|---|---|
| [Product](product.md) | user value, scope, non-goals, market boundary |
| [Architecture](architecture.md) | layer boundaries, flow planning, effect isolation |
| [Networking](networking.md) | IP, MTU, ICMP, TCP, UDP, NAT, reassembly |
| [Filtering](filtering.md) | DNS, TLS trust, HTTP, steering, rewriting |
| [Egress](egress.md) | path properties, chaining, WireGuard, MASQUE, proxies |
| [Platforms](platforms.md) | Android, Windows, iOS, JNI, Wintun |

## Governance and Delivery

| Document | Read when working on |
|---|---|
| [Decisions](decisions.md) | architecture decisions and rejected alternatives |
| [Delivery](delivery.md) | gaps, acceptance gates, roadmap, constraints, risks |
| [Engineering Plan](engineering-plan.md) | phase order, dependency edges, per-phase gates, performance budget |
| [Verification](verification.md) | evidence status, dependencies, open questions |

## Disclosure Rules

- [README.md](../README.md) is the concise human entry point.
- [AGENTS.md](../AGENTS.md) contains only rules needed for almost every change.
- This index routes work. It does not duplicate subsystem specifications.
- Subsystem documents own detailed rationale, invariants, and acceptance gates.
- Unverified external facts live in [Verification](verification.md), even when
  another document explains the design that depends on them.
- When code and visionary documentation differ, report the gap. Do not silently
  narrow the product vision to match current implementation.

## Current Implementation Map

| Path | Responsibility | Design owner |
|---|---|---|
| `src/lib.rs` | refined `Mtu`, error spine, path composition, flow planning, total ingress classification | [Architecture](architecture.md) |
| `src/datapath.rs` | sans-io datapath core: dispatch, flow lifecycle, path-change replanning | [Architecture](architecture.md) |
| `src/device.rs` | device seam, scripted simulator, deterministic harness | [Engineering Plan](engineering-plan.md) |
| `src/shell.rs` | tokio runtime shell, fused device/egress/network reactor, bounded channels, deadline timer | [Architecture](architecture.md) |
| `src/pool.rs` | bounded, recycled, affine payload buffers | [Architecture](architecture.md) |
| `src/dns.rs` | DNS parsing, host policy, verdict provenance, ECH policy | [Filtering](filtering.md) |
| `src/filter.rs` | filter-list parsing, deferral accounting, policy compilation | [Filtering](filtering.md) |
| `src/egress.rs` | egress sum (packet vs stream), sans-io packet-egress interface, WireGuard via GotaTun | [Egress](egress.md) |
| `src/upstream.rs` | DNS upstream transports: Do53, DoT, DoH, and the tunnel-bypass seam | [Filtering](filtering.md) |
| `src/platform.rs` | Android VpnService and Windows Wintun byte shims | [Platforms](platforms.md) |
| `src/packet.rs` | borrowed IP parsing and fragment classification | [Networking](networking.md) |
| `src/reassembly.rs` | dual-family fragment reassembly, discard-on-overlap | [Networking](networking.md) |
| `src/path.rs` | PTB validation against known flows, SYN MSS clamping | [Networking](networking.md) |
| `src/udp.rs` | bounded datagrams and endpoint-independent mapping state | [Networking](networking.md) |
| `src/mitm.rs` | the terminating TLS server, one acceptor per wire, and the interception allowlist | [Filtering](filtering.md) |
| `src/mirror.rs` | the originating side: the ClientHello every dialling leg sends, and Chrome's HTTP/2 preface | [Decisions](decisions.md) |
| `src/session.rs` | what happens to one terminated connection: introduce, decide, originate, terminate, serve | [Filtering](filtering.md) |
| `src/exchange.rs` | the HTTP exchange, URL-tier filtering, hop-by-hop sweep, Alt-Svc steering | [Filtering](filtering.md) |
| `src/rewrite.rs` | the HTML tier: content-coding decode, streaming rewrite under a budget | [Filtering](filtering.md) |
| `src/demote.rs` | what a failed handshake proved, and the tier a host's history permits | [Filtering](filtering.md) |
| `src/transport.rs` | proxy transports: TLS, WebSocket, HTTPUpgrade, gRPC, HTTP/2, QUIC | [Egress](egress.md) |
| `ffi/` | the C boundary and Android's JNI bypass: status codes, handle lifecycle, callback vtables, panic containment | [Platforms](platforms.md) |
| `vendor/` | crates patched in tree, generated from `vendor/patches/` by `scripts/vendor.py` | [vendor/README.md](../vendor/README.md) |
