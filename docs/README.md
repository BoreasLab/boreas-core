# Boreas Documentation

This index is the map for humans and agents. Start with the smallest document
that owns the work, then follow its links only when a boundary is crossed.

## Product and System

| Document | Read when working on |
|---|---|
| [Product](product.md) | user value, scope, non-goals, market boundary |
| [Architecture](architecture.md) | layer boundaries, flow planning, effect isolation |
| [Networking](networking.md) | IP, MTU, ICMP, TCP, UDP, NAT, reassembly |
| [Filtering](filtering.md) | DNS, TLS trust, HTTP, steering, rewriting |
| [Egress](egress.md) | capabilities, chaining, WireGuard, MASQUE, proxies |
| [Platforms](platforms.md) | Android, Windows, iOS, JNI, Wintun |

## Governance and Delivery

| Document | Read when working on |
|---|---|
| [Decisions](decisions.md) | architecture decisions and rejected alternatives |
| [Delivery](delivery.md) | gaps, acceptance gates, roadmap, constraints, risks |
| [Engineering Plan](engineering-plan.md) | phase order, dependency edges, per-phase gates, performance budget |
| [Verification](verification.md) | evidence status, dependencies, licensing, open questions |

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
| `src/lib.rs` | refined `Mtu`, error spine, capability composition, flow planning, ingress actions | [Architecture](architecture.md) |
| `src/packet.rs` | borrowed IP parsing and fragment quarantine; reassembly remains Gap 8 | [Networking](networking.md) |
| `src/udp.rs` | bounded datagrams and endpoint-independent mapping state | [Networking](networking.md) |
