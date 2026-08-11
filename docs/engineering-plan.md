# Engineering Plan

[Delivery](delivery.md) owns product milestones and acceptance criteria. This
document owns the engineering phase order that reaches them: what each phase
delivers, the falsifiable check that closes it, and the dependency edge that
makes the next phase possible. Milestone mapping appears in the last section.

## The Verifiability Problem

Every acceptance gate in [Delivery](delivery.md) is a load or conformance
measurement: 10,000 UDP flows, 32 HTTP/2 streams with one stalled, forged PTB
rejection, fragment fuzzing, steering convergence. Each one needs a packet
source, a clock, and a device.

If the only device is a real one, then every gate depends on the platform
adapters, so the adapters must land first, so the first milestone becomes one
undifferentiated block of TUN plus L3 plus TCP plus UDP plus splice plus
WireGuard. A failure in that block is not attributable to a component, and no
component inside it was ever verified alone.

That is the dependency to break, and it is broken by one decision.

**The datapath core performs no I/O, owns no clock, and spawns no task.** It is
a state machine advanced by function calls, in the shape quiche and rustls use:

```rust
impl Datapath {
    fn on_tun_packet(&mut self, buf: &[u8], now: Instant) -> Result<(), Error>;
    fn on_egress_packet(&mut self, buf: &[u8], now: Instant) -> Result<(), Error>;
    fn poll_transmit(&mut self, buf: &mut [u8]) -> Option<Transmit>;
    fn poll_timeout(&self) -> Option<Instant>;
    fn on_timeout(&mut self, now: Instant);
    fn poll_event(&mut self) -> Option<FlowEvent>;
}
```

The existing code already obeys this discipline. `plan_flow` and `route_ingress`
are pure, `IngressPacket::parse` borrows, and `UdpFlowTable` takes `now` as a
parameter rather than reading a clock. The plan extends that property rather
than introducing it.

Consequences that make the rest of this document work:

- Time is an argument, so timeout behavior is tested without waiting.
- Packets are arguments, so load is generated in-process at any rate.
- Nothing is spawned, so there is no scheduler nondeterminism in the core.
- A platform adapter becomes a byte shim with no policy, verified on its own.

Phase P5 turns this property into a harness. Phases P6 onward consume it.

## Phase Graph

Edges point from prerequisite to dependent. The graph is acyclic; every edge is
justified in the phase entry.

```text
P1 refined types + error spine
 ├──> P2 L3 completion ──┐
 └──> P3 planner completion ──┐
                              v
                        P4 sans-io Datapath
                              │
                              v
                        P5 Device seam + simulator
                          ├──> P6 smoltcp scaling verdict ──> P7 hot-path fixes
                          ├──> P8 tokio shell ──┐
                          └──> P9 platform adapters ──┐
                                                      v
                                                P10 packet egress + splice   [M1]
                                                      │
                                                      v
                                                P11 DNS + ECH policy
                                                      v
                                                P12 adblock + list pipeline  [M2]
                                                      v
                                                P13 protocol steering
                                                      v
                                                P14 MITM, allowlist-only
                                                      v
                                                P15 demotion, then broaden    [M3]
                                                      v
                                                P16 body and header rewriting
                                                      v
                                                P17 egress breadth            [M4]
```

## Tier 0: Pure Core

No runtime, no sockets, no clock. Verified by `cargo test`, proptest, and
`cargo-fuzz`. Every phase here is closed by a deterministic check.

### P1: Refined types and error spine

Introduce smart constructors where a raw primitive currently carries an
unchecked invariant. `plan_flow` takes `path_mtu: u16`, so a caller may pass a
value that no IP path can produce; the function rejects it downstream, but the
precondition is not structural.

**Status: complete.** Delivered:

- `Mtu`: private field, constructor rejects below `MIN_IPV6_MTU` of 1280 bytes
  per ADR-011. `Mtu::admits_quic` names RFC 9000's 1200-byte floor on the type
  that owns the invariant.
- `TransportPath::PacketFastPath` carries the inner MTU; `LocalTermination` does
  not, because a re-originated byte stream has no client packet size. This also
  put `EgressCapabilities::max_datagram_size` to work: it was declared, chained,
  and never consulted, so an egress with a 1000-byte datagram ceiling would
  previously have passed QUIC through below its floor.
- `PlanError::InnerMtu` separates an unusable remainder from overhead that
  exceeds the path entirely. Both variants are reachable and tested.
- `Display` and `std::error::Error` on `PlanError`, `PacketError`,
  `FlowTableError`, `CapabilityError`, and `MtuError`, with `source()` chaining
  where a cause exists. Hand-written: four enums cost about forty lines, which
  does not justify a proc-macro dependency in a core that cross-compiles to
  Android. No `anyhow`; the error type is part of the contract.

Two items from the original scope were dropped as speculative:

- **`Overhead` newtype.** Every `u16` is a valid overhead, including zero, so
  the type would label rather than refine. `chain` already composes with
  `checked_add` and is tested. Add it if a second invariant appears.
- **`Port` refinement.** Port zero is not currently a defect: `InternalEndpoint`
  uses it as a map key, where an odd key is not a bug. RFC 4787 REQ-3 forbids
  port overloading in the *allocator*, which does not exist until P7, so that is
  where the invariant becomes real and where the newtype should land.

Leave `EgressCapabilities::accepts` a runtime field. It becomes redundant with
the implementation variant only once implementations exist, which is P10, and
removing it earlier would be speculative.

**Gate met:** every smart constructor has a rejection test, every new error
variant is constructed by a test, `Display` output is asserted rather than
assumed, and `cargo fmt --check`, `cargo test`, and `cargo clippy --all-targets
--all-features -- -D warnings` are clean at 8 passing tests. That the IPv6 floor
exceeds the QUIC floor is asserted in a `const` block, so a future edit that
inverts them fails to compile rather than silently reopening the black hole.

**Unlocks:** P2 and P3 consume `Mtu` in their signatures.

### P2: L3 completion

`Transport::Fragment` routes to `IngressAction::Reassemble`. This is Gap 8.

**Status: complete.** Delivered:

- `Fragment`/`Reassembler` in `src/reassembly.rs`: dual-family (IPv4 and IPv6)
  bounded pure state machine. Boreas terminates the TUN packets addressed to
  it, so RFC 8200 section 4.5's reassembly requirement applies in full —
  dropping IPv6 fragments would black-hole senders already at the 1280-byte
  minimum. Overlap policy: any overlapping block silently discards the whole
  pending datagram (RFC 5722), applied to IPv4 as defense in depth; identical
  retransmits are discarded too, which is safe because the sender retries from
  a clean key. Capacity-bounded, `now`-parameterized, expiry via the
  `UdpFlowTable` deadline discipline. The original scope said "overlapping and
  duplicate fragments resolved by a stated policy"; discard-on-overlap is that
  policy.
- `validate_ptb` in `src/path.rs`: pure, actionable only when the quoted
  transport is TCP/UDP, the quoted source endpoint matches a known flow, and
  the offered MTU is at or above RFC 9000's 1200-byte floor.
- `clamp_mss` in `src/path.rs`: rewrites an above-budget MSS on IPv4 or IPv6
  SYNs and recomputes the TCP checksum in full; absence of a clampable MSS is
  not an error. Extension headers between the IPv6 fixed header and TCP skip
  the clamp (marked `ponytail:`).

**Gate met:** the `cargo-fuzz` target `reassembler` ran 1.78M executions clean
after fixing one real finding (empty-payload fragment underflowed the block
arithmetic; regression test added). An exhaustive loop over every wire-
expressible IPv4 fragment boundary asserts `Fragment` never routes anywhere
but `Reassemble`. The forged-PTB test corpus proves sub-1200 messages and
unmatched quotes change nothing, while a genuine 1400 PTB against a known flow
yields `PathUpdate`. 17 tests, `cargo fmt --check`, and `cargo clippy
--all-targets --all-features -- -D warnings` clean.

Not in scope, load-bearing later: PTB generation toward the client when an
inbound packet exceeds inner MTU, and ICMP Time Exceeded on reassembly
timeout (RFC 8200 requires it on first-fragment-holding evictions); both need
ICMP construction and land in P4 with the datapath. DPLPMTUD for MASQUE
CONNECT-IP stays in P17.

**Unlocks:** P4. The datapath cannot be correct while L4 can observe a fragment.

### P3: Planner completion

**Status: complete.** Delivered:

- `NatBehavior` on `EgressCapabilities`: ordered
  `EndpointIndependent`/`AddressDependent`/`AddressAndPortDependent`, chained
  by `min` like fidelity. The egress document defers routing consequences to
  the first egress whose behavior affects routing; the field exists now so
  capability reports carry it from day one.
- `replan(current, filter, next, path_mtu) -> Result<Replan, PlanError>`.
  Filter policy and path MTU are session properties and pass through
  unchanged. `Teardown` answers a layer change or a transport-path crossing;
  an inner-MTU move on the packet path is survivable and returns `Unchanged`
  (MTU machinery absorbs it). `Resteer` fires exactly when a `PassThrough`
  flow's new plan steers; recoveries and reason changes on already-steered
  flows are `Unchanged`.

**Gate met:** properties iterate the full domain product rather than naming
examples: chain fidelity and NAT behavior are exactly `min` over all
fidelity/NAT pairs; `plan_flow` never returns `PassThrough` below Native
fidelity or below a 1200-byte budget across the MTU/overhead/ceiling grid;
every Native-to-Emulated transition yields `Resteer`. 21 tests, fmt, clippy
clean.

**Unlocks:** P8 routes live capability changes through `replan`; P13 consumes
`SteeringReason`.

## Tier 1: Datapath and Simulation

### P4: Sans-io Datapath

**Status: complete.** `Datapath` in `src/datapath.rs` composes P1–P3 and
`UdpFlowTable` behind the poll API: `on_tun_packet`, `on_egress_packet`,
`poll_transmit`, `poll_event`, `on_timeout`, and `on_capability_change`. It
owns flow state and queues; it owns no socket, clock, or task. Invalid states
are structural: fragments quarantine and re-enter dispatch only after
reassembly re-parses a whole datagram, so a flow's plan always derives from a
real header; `FlowState` exists only behind a successful `plan_flow`; egress-
side fragments are pathological and drop. MSS clamping fires on the packet
fast path before forwarding. `UdpFlowTable::retain` was added for capability-
driven teardown. `poll_timeout` is omitted for now: neither the reassembler
nor the flow table exposes its earliest deadline yet, and inventing the
accessor is P5's job when the simulator needs a wakeup.

**Gate met:** `tests/golden_replay.rs` drives a scripted trace — open, buffer,
drop-and-report, re-steer, expire — and asserts every event and transmit
byte-exact and in order against a synthetic clock. 27 tests, fmt, clippy
clean.

**Unlocks:** every subsequent phase.

### P5: Device seam and simulator

**Status: complete.** `Device` in `src/device.rs` is the three-method seam
(`recv`/`send`/`mtu`) from the plan; `SimDevice` is the second implementation.
Delivery is scheduled against a virtual tick the harness drives, loss is
one-in-N on each direction, and reordering is a bounded delivery jitter, all
seeded by a SplitMix64 `Rng` — deterministic from the seed, no CSPRNG needed
for a test wire. `set_mtu` scripts mid-run MTU changes; PTB injection is an
ordinary `inject` of an ICMP packet and got no bespoke API. `Harness::step`
drains device to datapath, datapath to device, and fires `on_timeout` at the
virtual instant.

Supporting changes: `next_deadline` on `UdpFlowTable` and `Reassembler`
(reassembly now tracks per-key deadlines, and `expire` no longer evicts a
refreshed key early — a real fix surfaced by the accessor, matching
`UdpFlowTable`'s stale-entry discipline).

**Gate met:** `harness_reproduces_directly_driven_results` drives the same
trace through the harness and through direct datapath calls and asserts
byte-identical transmits. `loss_and_reorder_are_scripted_and_deterministic`
proves same-seed reproduction and actual reordering. 29 tests, fmt, clippy
clean.

**Unlocks:** P6, P7, P8, P9, and every load-based acceptance gate in
[Delivery](delivery.md).

### P6: smoltcp scaling verdict

**Status: complete, provisional pass.** The measurement is
`examples/smoltcp_scaling.rs` (smoltcp 0.13.1 as a dev-dependency, never linked
into the library): N listening TCP sockets on an idle synthetic device, polled
200 rounds each. On the aarch64 dev VM, poll cost is linear at ~5-25 ns per
socket with no superlinear socket-set growth through 2000 sockets; p99 outliers
correlate with timer-wheel fires, not socket count. The declared budget is now
recorded in [Verification](verification.md) item 8: 1,000 sockets, under 100 ns
per socket amortized, p99 under 1 ms excluding timer fires, RSS linear at no
more than 2 KiB per socket. The verdict is provisional: idle listeners on an
didle device, on a VM that is not the mobile target. P7 re-measures under live
traffic; a failure there replaces or specializes smoltcp before any L7 phase
depends on the stream API.

**Unlocks:** P7, and every L7 phase that assumes a stream abstraction. Deferring
this measurement is the single most expensive schedule error available: a
negative result discovered after P14 invalidates work under four phases.

### P7: Hot-path corrections

**Status: complete.** Both measured defects are fixed:

- **Expiry index.** `UdpFlowTable` now holds a 512-bucket, one-second
  `TimerWheel` with an overflow list past the horizon. Refresh mutates only
  the flow's deadline; wheel slots are hints that `expire` re-validates
  against the real deadline and re-buckets. Insert is O(1), expiry is
  O(seconds elapsed + surfaced stale slots), and memory is O(flows + buckets).
  A second defect surfaced in review: open events fired per packet, making the
  event stream O(packets); `open_flow` now reports creation and only new flows
  emit an event.
- **Eager buffers.** `DatagramBuffer::new` no longer pre-allocates; idle flows
  pay nothing. The shared buffer pool is deferred with a `ponytail:` note: the
  datapath's per-flow buffers have no drain path yet, so refcounted pool
  handles have no consumer; the pool lands with P8's runtime shell.

**Gate met:** `tests/scale.rs` drives 10,000 flows through the harness, floods
each with 10 refreshes (110k packets), and asserts one wheel slot per flow,
events equal to flow count, and exact expiry at real deadlines. The
1-flow/10,000-refresh case is a regression test in `udp.rs`. 32 tests, fmt,
clippy clean.

**Unlocks:** the 10,000-flow gate in [Networking](networking.md).

## Tier 2: Async Shell

### P8: Tokio runtime shell

**Status: complete.** `Shell` in `src/shell.rs` interprets the pure core: one
reactor task owns the `Datapath` by value, so no lock guards it and none can be
held across an `await`. Three properties define the phase.

**Backpressure is asymmetric, so the channels are separate.** Control messages
are policy and should block their producer, so `Control` is awaited. Datagrams
are traffic, and blocking a UDP source converts loss into head-of-line delay,
so `Datagram` has its own bounded channel and `Shell::try_send_datagram` offers
without waiting. One channel could not honour both disciplines. A refusal
returns `SendOutcome::Dropped` to the producer, which is the party that knows
which flow it belongs to.

**One timer, armed against `Datapath::poll_timeout`** — the minimum of the
reassembler and flow-table deadlines — never a poll interval. Both underlying
deadline queries are independent of state size: the timer wheel scans at most
512 buckets and the reassembler's index is one `BTreeMap` lookup, recorded as
[Verification](verification.md) item 10.

**A packet is not an error.** Every `DatapathError` describes one packet that
did not make it, so the reactor counts it and keeps interpreting the core;
only the device itself fails fatally, and an interrupted read is retried. The
same classification now applies in `Harness::step`, so a trace replayed under
P5 behaves as it does in production.

Telemetry is aggregated rather than per-event: counters are folded in the
reactor and reported every 500 ms, because a message per occurrence would make
the stream O(packets) under exactly the floods that matter. Observations the
channel refuses are counted and reported as `Telemetry::Lost`, so a gap never
reads as quiet.

The shared buffer pool landed here as `src/pool.rs`, and it is the datapath's
real storage: `FlowState` holds `DatagramBuffer<Pooled>`, so queue memory is
one budget of `capacity x slice_size` instead of the product
`flows x depth x MTU`. Buffers are allocated lazily and recycled, exhaustion is
a drop, and `Drop` is the release — an expiring flow returns its whole queue by
being dropped. `Pooled` is deliberately affine: it is not `Clone`, so two
handles onto the same bytes are unrepresentable rather than merely discouraged.
The pool contains no `unsafe`. Nothing drains these queues yet; the egress that
does is P10, and until then the budget is what keeps an undrained queue bounded.

`AsyncDevice` uses explicit `impl Future + Send` signatures rather than
`async fn` in trait so reactor futures are provably `Send` on a multi-threaded
runtime, and `recv` documents its cancel-safety obligation, because the reactor
selects over it and drops the future routinely. Config reload via
`watch::Receiver<Arc<Engine>>` waits for the filter engine to exist (P12); the
capability-change path through `Control::CapabilityChange` already exercises the
same pointer-swap shape.

**Gate met:** `tests/shell.rs` proves five properties, one per test — forward
and shut down with no task leak; the timer waits on the core's deadline rather
than a poll interval, asserted on tokio's paused clock over an hour of virtual
time; a malformed packet and a crafted TCP option list are counted, not fatal;
a datagram producer is never blocked and a refusal frees its buffer; control
messages reach the core in order. 50 tests, plus `clamp_mss` and `datapath`
fuzz targets on the untrusted paths and a one-minute-per-target fuzz smoke job
in CI. fmt, clippy, and `cargo deny` clean, the last now including
dev-dependencies. tokio is taken with named features rather than `full`; the
full graph is recorded in [Verification](verification.md).

**Unlocks:** P9, P10.

### P9: Platform adapters

Android `VpnService` fd via JNI, and Windows Wintun via `wintun-bindings`, each
as a `Device`. Because P5 defined the seam, these are byte shims with no policy.

**Gate:** loopback ping through the real device produces output identical to the
same trace through `SimDevice`. Verified per platform, alone.

**Unlocks:** P10. Nothing depends on P9 for correctness, which is the point.

### P10: Packet egress and splice

GotaTun as the first `PacketEgress`. Splice via `copy_bidirectional`. The
smoltcp bypass becomes real here.

At this phase `EgressCapabilities::accepts` becomes redundant with the
implementation variant and can lie about it. Replace with a sum whose variant
determines the layer:

```rust
enum Egress { Packet(Box<dyn PacketEgress>), Stream(Box<dyn StreamEgress>) }
```

`CapabilityError::MixedLayers` then reports a genuine configuration conflict
rather than a possible internal inconsistency. Deferring this to P10 rather than
P1 is deliberate: before an implementation exists, the field cannot disagree
with anything.

**Gate:** the M1 product gate — a working single-interface WireGuard client on
both platforms. The fast-path counter proves packet egress never enters smoltcp.
The fusion benchmark runs and reports against the two-process baseline.

**Completes M1.**

## Tier 3: Filtering and Egress Breadth

### P11: DNS and ECH policy

Interception, DoH/DoT/DoQ upstreams via `hickory-resolver`, verdict provenance
retained for explanation. ECH policy stays coupled to resolver control.

**Gate:** answers for A, AAAA, HTTPS, and SVCB carry provenance sufficient to
explain a verdict; ECH is not disabled globally when host policy suffices.

### P12: adblock engine and list pipeline

Network rules and the filter-list build. Reload through the P8 `watch` channel.

**Gate:** the M2 product gate — visible ad blocking across applications with no
CA installed. Confirm the `data/test/fake-uBO-files/` GPL subtree named in
[Verification](verification.md) is absent from the shipped artifact.

**Completes M2.**

### P13: Protocol steering

HTTPS/SVCB and Alt-Svc rewriting, plus the transient UDP/443 backstop.

**This must precede P14, and the order is load-bearing.** Browsers race QUIC
against TCP and take QUIC if it answers within roughly 300 to 500 ms. Ship MITM
first and an allowlisted host reaches h3, where a locally added root can never
validate, so interception silently never fires and the failure looks like a
filtering bug rather than a transport one. [Delivery](delivery.md) places both
in M3; within M3 this order is not interchangeable.

**Gate:** an allowlisted host does not enter the MITM path over QUIC during
cache expiry or the QUIC/TCP race. Convergence within one Alt-Svc cache window
or one backstop window is measured, not assumed.

### P14: MITM, allowlist-only

User-store CA lifecycle, rustls, `rcgen` leaf generation, h1 and h2
interception. Deliberately narrow: an explicit allowlist, manually maintained.

**Scope reduction proposed here.** [Filtering](filtering.md) specifies a neutral
`Exchange` model with three wire adapters, justified by quiche and `tokio-quiche`
not using the `http` crate. In v1 that justification does not apply. Boreas never
terminates h3: Chromium refuses locally added roots over QUIC, so h3 is
pass-through, and `tokio-quiche` appears only as MASQUE packet egress. With no
h3 termination there is no h1/h2-to-h3 bridging surface, so the neutral core has
one wire family and two adapters, both `http`-crate shaped.

Build directly on `http::Request` and `http::Response`. Retain `Wire` as an
observability field and keep the version-crossing counter, since that gate is
independent of the representation. Reinstate the neutral core if h3 termination
enters scope, which requires a non-Chromium target.

This is a proposal against a written design decision and needs sign-off before
[Filtering](filtering.md) is amended.

**Gate:** the version-crossing exchange counter is zero. With 32 streams and one
stalled, other streams' p99 rises less than 10 percent. Also run the device test
for [Verification](verification.md) item 1, whether Chrome bypasses static pins
for a user-installed root, which decides whether Google properties are in scope.

### P15: Demotion, then broaden

Challenge detection, pin-failure detection, automatic demotion to splice.

**This resolves a real near-cycle.** Fail-open is mandatory, so MITM should not
ship without demotion; demotion needs a MITM path to demote from. Splitting P14
and P15 breaks it: P14 ships narrow enough that manual allowlist maintenance is
tractable, P15 makes maintenance automatic, and only then does the allowlist
broaden toward the parity corpus.

**Gate:** the M3 product gate — AdGuard parity on the 200-site corpus, measured
separately for Chrome, WebView, and one Chromium alternative. Automatic
demotion succeeds at least 99 percent of the time. Top-500 crawl shows zero
Boreas-attributable breakage.

**Completes M3.**

### P16: Body and header rewriting

`lol_html` under per-stream budgets, content and character encoding handling,
CSP relaxation, SRI preservation. Rewriters constructed only after `text/html`
is confirmed. Memory settings and strict bail-out wired to fail open.

**Gate:** unsupported encodings splice unchanged; no `integrity=` protected
subresource is modified; memory exhaustion demotes rather than fails.

### P17: Egress breadth

MASQUE CONNECT-IP, SOCKS5 with UDP ASSOCIATE, Shadowsocks, then VLESS/Reality,
Hysteria2, TUIC. Each reports live capability through P3's `replan`.

**Gate:** the M4 product gate. Non-native fidelity tunnels zero QUIC datagrams.
A mid-session MASQUE fallback to HTTP/2 re-steers without dropping flows. Resolve
the `shadowsocks-rust` license item before it ships.

**Completes M4.**

## Broken Cycles

Four dependency loops exist in the naive ordering. Each is broken by a stated
construction rather than by sequencing luck.

| Loop | Why it looks circular | Break |
|---|---|---|
| MTU needs egress overhead; egress needs an MTU | `inner_mtu = path_mtu - overhead` | Overhead is static configuration known before connect. Discovery updates flow through P3 `replan`, so P3 depends on the `EgressCapabilities` type, not on P10's implementation |
| Verification needs a device; the device is a phase | every gate is a load measurement | P5 `SimDevice`. This is the root break; without it P9 must precede everything and M1 becomes one untestable block |
| MITM needs steering; steering targets MITM hosts | both live in M3 | Strict order P13 before P14. Steering acts at discovery, before a connection exists |
| MITM needs demotion; demotion needs MITM | fail-open is mandatory | Split into P14 narrow allowlist and P15 demotion, then broaden |

A fifth is latent rather than circular: smoltcp sits under every stream, so a
scaling failure found late invalidates work above it. P6 converts that from a
schedule risk into a dated measurement.

## Performance Budget

The numbers that decide the architecture, so that later choices are checkable
rather than stylistic.

At 100 Mbps with 1400-byte packets the datapath sees roughly 9,000 packets per
second. Holding the datapath to a tenth of one mobile core gives a budget near
one microsecond of CPU per packet.

| Cost | Order | Fits per-packet? |
|---|---|---|
| borrowed IP parse (`etherparse`) | ~100 ns | yes |
| flow-table hash lookup | tens of ns | yes |
| syscall, each direction | 1–3 µs | no |
| task wakeup | 1–5 µs | no |
| heap allocation | ~100 ns, plus fragmentation | avoid |

Compute is not the constraint; syscalls and wakeups are. Three consequences,
each already reflected above:

1. **Batching is mandatory, not an optimization.** Drain the device fully per
   wakeup. `recvmmsg`/`sendmmsg` and GSO/GRO where the platform supports them.
2. **One reactor, not a task per flow.** A per-flow task costs a wakeup per
   packet, which exceeds the entire budget on its own.
3. **Pool buffers.** Per-packet allocation is affordable in isolation and not in
   aggregate, and owned per-flow queues miss the 10,000-flow memory budget by
   roughly two orders of magnitude.

This is why [Delivery](delivery.md)'s fusion benchmark measures wakeups per
second and context switches: those are the budget, and throughput is downstream
of them. The primary derived metrics are **packets per wakeup** and **packets per
syscall**.

## Milestone Mapping

| Milestone | Phases | Product gate |
|---|---|---|
| M1 | P1–P10 | single-interface WireGuard client on both platforms |
| M2 | P11–P12 | visible ad blocking across applications, no CA |
| M3 | P13–P15 | AdGuard parity on the fixed corpus |
| M4 | P16–P17 | filtering composes with the target egress set |
| M5 | separate track | blocked on the AGPLv3 and App Store decision |

P1 through P7 carry no external dependency beyond `etherparse` and test-only
crates. Every dependency in [Verification](verification.md) is first admitted at
P8 or later, so the license and maintenance review for each one happens against a
working core rather than a plan.

## Open Items This Plan Adds

Record outcomes in [Verification](verification.md).

1. Sign-off on the P14 scope reduction, replacing the neutral `Exchange` model
   with `http`-crate types for v1, and the amendment to
   [Filtering](filtering.md) that follows.
2. The declared P6 budget: socket count, RSS, and p99 latency, fixed before
   smoltcp integration merges rather than after.
3. Whether the timer-wheel granularity of one second and 512 buckets in P7
   survives the 10,000-flow measurement, or needs a second tier.
