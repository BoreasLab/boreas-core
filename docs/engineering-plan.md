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

Two gaps between [Egress](egress.md) and the code: `NatBehavior` is unmodelled,
and capability is documented as a live property with no transition function.
The MASQUE QUIC-to-HTTP/2 fallback gate requires the second.

```rust
enum Replan { Unchanged, Resteer(SteeringReason), Teardown }

fn replan(current: &FlowPlan, next: EgressCapabilities) -> Result<Replan, PlanError>;
```

`Teardown` is reserved for a capability change no live flow can survive.
Re-steering must not drop established flows, which is the acceptance criterion,
so `Resteer` is the expected result of a fidelity downgrade.

**Gate:** properties, not examples. Chain fidelity is monotone non-increasing
under `chain`. `plan_flow` never returns `QuicPolicy::PassThrough` when fidelity
is below `Native` or inner MTU is below 1200 — currently true by construction
and asserted by three examples, which a property test generalizes. Every
Native-to-Emulated transition yields `Resteer`.

**Unlocks:** P8 routes live capability changes through `replan`; P13 consumes
`SteeringReason`.

## Tier 1: Datapath and Simulation

### P4: Sans-io Datapath

Compose P1 through P3 plus the existing `UdpFlowTable` into the poll API above.
The datapath owns flow state; it does not own a socket, a clock, or a task.

**Gate:** pcap replay. A captured trace is fed through the state machine and the
emitted packets and event sequence are asserted byte-exact against a golden
output. Deterministic and reproducible, because the only inputs are bytes and an
`Instant`.

**Unlocks:** every subsequent phase.

### P5: Device seam and simulator

```rust
trait Device {
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn send(&mut self, buf: &[u8]) -> io::Result<usize>;
    fn mtu(&self) -> Mtu;
}
```

Two implementations, satisfying the rule in [AGENTS.md](../AGENTS.md) that an
abstraction needs more than one: `SimDevice` here, the platform adapters in P9.
`SimDevice` scripts loss, reordering, MTU changes, and PTB injection, driven by
a deterministic clock and a seeded RNG.

Also here: the load harness that synthesizes flow counts and packet rates.

**Gate:** the harness is self-verifying. Replaying P4's golden pcap through
`SimDevice` must produce results identical to driving P4 directly. A harness
that cannot reproduce a known-good result cannot certify anything else.

**Unlocks:** P6, P7, P8, P9, and every load-based acceptance gate in
[Delivery](delivery.md).

### P6: smoltcp scaling verdict

[Delivery](delivery.md) rates smoltcp scaling medium-high risk and requires the
socket-count, RSS, and p99 budget to be fixed before integration merges. This
phase is that measurement, and it runs while nothing yet depends on the stream
API.

Run the fixed workload against `SimDevice`. Publish the numbers to
[Verification](verification.md) item 6.

**Gate:** the declared budget is met, or smoltcp is replaced or specialized now.
The phase closes either way; what it must not do is stay open.

**Unlocks:** P7, and every L7 phase that assumes a stream abstraction. Deferring
this measurement is the single most expensive schedule error available: a
negative result discovered after P14 invalidates work under four phases.

### P7: Hot-path corrections

Two defects are already present and confirmed by measurement, not inspection.

**Expiry index grows with packets, not flows.** `UdpFlowTable::get_or_insert_with`
pushes to `self.expirations` unconditionally on every call, including refreshes.
Refreshing one mapping 10,000 times was measured to produce 1 flow and 10,000
expiry keys. `Instant` has nanosecond granularity, so each refresh allocates a
distinct `BTreeMap` key and a `Vec`. At the 10,000-flow acceptance target and a
120-second minimum idle window, the index reaches millions of live entries and
tens of megabytes while the flow count stays flat. The existing `ponytail:`
comment anticipates refresh churn but understates it as one idle window of stale
entries; the true cost is O(packets).

Replace with a hierarchical timer wheel at one-second granularity and lazy
re-insertion: refresh mutates the entry deadline only, and expiry re-buckets an
entry whose real deadline has not passed. Memory becomes O(flows + buckets).
RFC 4787 REQ-5 requires at least 120 seconds and recommends 300, so 512 buckets
cover the range.

**Per-flow queues allocate eagerly.** `DatagramBuffer::new` calls
`VecDeque::with_capacity`, so an idle flow pays its full queue immediately.

Also here: a shared buffer pool. Per-flow queues must hold refcounted slices into
one pool, not owned datagrams. At 10,000 flows and a depth of 8, handles cost
about 1.3 MB and payload is bounded by pool size; owned 1500-byte buffers would
cost about 120 MB and miss the budget on that alone.

**Gate:** at 10,000 flows under the P5 harness, expiry entries scale with flows
and not with packets; RSS is inside the declared budget; no drop is attributable
to allocation. The probe that produced the 1-versus-10,000 result becomes a
regression test.

**Unlocks:** the 10,000-flow gate in [Networking](networking.md).

## Tier 2: Async Shell

### P8: Tokio runtime shell

The core is synchronous. This phase interprets it. The rules follow the
concurrency contract in [Architecture](architecture.md).

- **One reactor task owns the `Datapath` by value.** No `Arc<Mutex<Datapath>>`.
  Exclusive ownership is what makes the state machine's invariants hold without
  a lock, and it is why the core was written pure.
- **One timer.** A single `sleep_until(datapath.poll_timeout())`, re-armed after
  each advance. Never a timer task per flow, per the same document.
- **Bounded channels only.** `mpsc::channel`, never `unbounded_channel`.
- **Backpressure is asymmetric, deliberately.** Stream paths use `send().await`,
  where waiting is correct. Datagram paths use `try_send` and increment a drop
  counter, because waiting converts bounded loss into unbounded latency. The
  existing `SendOutcome` type already names this distinction; the shell must not
  erase it by awaiting a datagram send.
- **Structured cancellation.** A `JoinSet` scoped to each connection, so dropping
  the owner aborts its children. `CancellationToken` for the shutdown tree.
- **Config reload without locks.** `watch::Receiver<Arc<Engine>>` for the filter
  engine, so a reload is a pointer swap and readers clone an `Arc`.
- **Blocking work off the reactor.** `spawn_blocking` for leaf-certificate
  signing and filter-list compilation.

Per-flow tasks are correct for L7 work, which is genuinely independent and
CPU-bound, bounded by a `Semaphore`. Per-flow tasks are wrong for packet
forwarding, for the reason in the budget below.

Start on one multi-threaded runtime with the reactor as an ordinary task. If the
fusion benchmark shows migration cost, move the reactor to a pinned
`current_thread` runtime. Exclusive ownership makes that a move, not a rewrite,
so it is not worth pre-empting.

**Gate:** `clippy::await_holding_lock` and `await_holding_refcell_ref` denied in
CI. Under the P5 load profile, packets per wakeup and packets per syscall are
reported; both must exceed the ratio the budget below requires. Shutdown from
any phase leaks no task, verified by `JoinSet` drain.

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
