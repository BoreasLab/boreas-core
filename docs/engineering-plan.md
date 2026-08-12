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
driven teardown. `poll_timeout` was omitted at the time — neither the
reassembler nor the flow table exposed its earliest deadline — and landed in
P5 with the accessors the simulator needed.

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

**Status: code complete; device gate unexercised.** `src/platform.rs` holds
both byte shims behind the seam, with no policy in either:

- `AndroidTun` (unix): wraps the VpnService fd in tokio's `AsyncFd`, so
  readiness is registered and `recv` is cancel-safe — a dropped future has
  consumed nothing. Takes the fd by ownership; VpnService owns lifecycle.
- `WintunDevice` (windows): `Arc<Session>`; sync `recv` is `try_receive`,
  async `recv` moves `receive_blocking` to the blocking pool because Wintun's
  read wait is a Win32 event tokio cannot poll.

**Corrected during the P10 polish pass: the Windows adapter was not
cancel-safe.** `spawn_blocking` cannot be cancelled, so dropping its
`JoinHandle` lets the read run to completion and *discards the packet it
returned*. The reactor drops that future every time another `select!` arm
wins, which is routine, so the adapter lost one packet per lost race — the
exact obligation `AsyncDevice::recv` states, violated by the adapter that
documented itself as satisfying it. The fix retains the handle in the device:
the task now returns owned bytes and the slot is cleared only after the join
future has resolved, so a dropped future consumes nothing. The extra copy is
Windows-only and unavoidable, because nothing can hand bytes back through a
cancelled future. Compile-checked in CI, not locally; ring's C build still
ends the local cross-check.

Both adapters type-check on their own target (`cargo check` and clippy against
x86_64-pc-windows-msvc and the host). `wintun-bindings` 0.7 is a
Windows-target-only dependency; the dll remains the WireGuard-authorized
signed binary per the verification ledger.

**Gate:** loopback ping through the real device must produce output identical
to the same trace through `SimDevice`, per platform. That needs the Android
and Windows devices, which this environment does not have; the gate is
**unexercised** and recorded as such rather than claimed. Both targets compile
and lint clean, and the simulator equivalence harness exists from P5.

**Unlocks:** P10. Nothing depends on P9 for correctness, which is the point.

### P10: Packet egress and splice

**Status: code complete; M1 device gate unexercised.** Delivered:

- `src/egress.rs` replaces `EgressCapabilities::accepts` with the
  `Egress { Packet, Stream }` sum. The layer is the variant and the
  capabilities come from the implementation behind it, so a claim can no
  longer disagree with its implementation. `CapabilityError::MixedLayers` now
  reports from `Egress::chain`, where two implementations actually meet. The
  pure planner functions take the layer as an explicit parameter, and
  `Control::CapabilityChange` carries it alongside the claim.
- `WireGuardEgress`, a sans-io wrapper over GotaTun 0.8.1's `Tunn`: IP packets
  in, `EgressEmit::{ToNetwork, ToTunnel}` out, handshake retries and
  keepalives on an explicit `tick()` for the shell. Keepalives are suppressed
  at the boundary and WireGuard's 16-byte padding is stripped against the IP
  length field, so the tunnel side sees exactly the packet. The capability
  claim is Native fidelity, 80-byte worst-case (IPv6 underlay) overhead,
  endpoint-independent, and `preserves_ecn: false` until captures prove
  otherwise.
- The fast-path counter, `WireGuardEgress::fast_path_packets`. smoltcp remains
  dev-only, so the bypass is currently structural — nothing links smoltcp —
  and the counter is the tripwire for the phase that adds local termination.
- The fusion benchmark, `examples/fusion.rs`: 10,000 packets driven
  tun → datapath → WireGuard → peer → back, fully in-process. On the aarch64
  dev VM, release build: 2.1 µs per packet end to end, of which 585 ns is the
  core (within the ~1 µs budget) and the residual ~1.5 µs is ring AEAD in both
  directions. The two-process baseline needs real devices and is recorded as
  outstanding in [Verification](verification.md).

**Corrections to what this phase was assumed to contain.** The per-flow
`DatagramBuffer` queues get their drain from the first *stream* egress
(SOCKS5, P17): a packet egress consumes whole packets, so P8's note that "the
egress that drains them is P10" was wrong about the phase, not about the
design. Likewise `copy_bidirectional` splice presupposes locally terminated
streams, and smoltcp integration is explicitly gated on re-measurement under
live traffic ([Verification](verification.md) item 8), which is device-bound.
Both therefore move past P10 rather than into it.

### P10 polish pass

A review of the delivered phase found one latent defect, one unstated
architectural gap, and three costs the performance budget forbids. All five
are closed.

**The defect: a `Transmit` did not say where it was going.** It carried bytes
and nothing else, so the shell had exactly one place to put them — the device
— and a packet from the client's TUN was therefore sent back down the client's
TUN instead of being encapsulated. Nothing caught it because no shell had an
egress to send it to; every test wired the egress by hand. The fix is
`Side { Tunnel, Egress }`, threaded from the ingress call so the destination
is `from.across()`: forwarding is the crossing, `across` is an involution, and
a transmit bound for the side it arrived on is now unconstructable. Fragments
carry their side through reassembly, so a reassembled datagram cannot reverse
direction either.

**The gap: the reactor had no egress.** `Shell::start` took a datapath and a
device, which is not a product — it is a loopback. `PacketEgress` is now the
whole sans-io interface (`handle_tun_packet`, `handle_network_packet`, `tick`,
`tick_interval`) rather than a capability report, so `Box<dyn PacketEgress>`
is a thing the reactor can run; `AsyncNetwork` is the datagram seam beside
`AsyncDevice`, with a `tokio::net::UdpSocket` implementation and no new
dependency. The reactor now closes the loop in one task: device → core →
egress → network, and network → egress → core → device. The drain is an
alternating fixpoint over the two producers, which settles in at most two
passes because a tunnel-bound transmit and a network-bound emission are both
terminal. `tests/shell.rs` asserts both directions and that a tun-side packet
never reappears on the tun.

**The costs.** The plan's own budget says a heap allocation per packet is
forbidden and that pooled buffers are the answer; the delivered phase
allocated three times per packet. Now: `Transmit` and `EgressEmit` both carry
`Pooled`, so the datapath and the egress draw on one budget and exhaustion is
a counted drop (`FlowEvent::TransmitDropped`, `EgressError::PoolExhausted`)
rather than an allocation or a wait; `Pooled` gained `DerefMut`, which is
sound precisely because it is affine, so `clamp_mss` rewrites in place.
Emissions go into a reactor-owned sink instead of a returned `Vec`.
`plan_flow` was being re-derived per packet from inputs that only move when
the configuration does, so `Datapath` memoizes the decision as
`Result<FlowPlan, PlanError>` — keeping the failing configuration's behavior
exactly (every packet counted and refused) while making the succeeding case a
field read — and `route_ingress` became total: possessing a `FlowPlan` *is*
the proof that the configuration plans. `strip_padding` ran a full
network-and-transport `etherparse` parse to read a length the IP header states
at a fixed offset; it is now an O(1) header read, and `etherparse` left the
inbound egress path entirely.

Measured after: core 573 ns/packet against the ~1 µs allowance (585 ns
before), end to end 2 187 ns, and the pool returns every slice at rest, which
is the property that actually changed — steady-state memory is now a declared
budget rather than allocator behavior.

**Deliberately not done, and why.** The budget also calls batching mandatory,
and the reactor still reads one packet per wakeup. Batching needs a
non-blocking read on `AsyncDevice`, which both platform adapters can supply
(`AsyncFd::try_io`, `try_receive`) but neither can be measured here; the
metric it serves — packets per wakeup — is device-bound, so it is recorded as
an open item rather than built blind. The egress tick is likewise an
unconditional 4 Hz wakeup, at parity with GotaTun's own device, and is the
largest fixed wakeup cost in the shell; replacing it with an egress-declared
next deadline needs GotaTun to expose one.

**Gate:** the in-process part is met — `tests/egress.rs` drives the scripted
harness into a real client-server WireGuard pair and asserts byte-exact
return, zero flow state on the packet path, forwarding toward the egress
rather than back down the device, and the reported capability set planning the
fast path. The M1 product gate (single-interface client on Android and Windows
hardware) needs the devices this environment does not have and is
**unexercised**, same as P9's. A Windows CI job now compiles the Wintun
adapter and GotaTun together, because ring's C build ended the local
cross-check. 59 tests, fmt, clippy, and `cargo deny` clean.

## Tier 3: Filtering and Egress Breadth

### P11: DNS and ECH policy

**Status: complete for the phase gate; the encrypted upstreams are deferred
with a reason, below.** Delivered:

- `src/dns.rs`, the pure core. Borrowed message parsing with no allocation:
  the header and question decode eagerly because every caller needs both, and
  the answer section is walked lazily as a fallible iterator. `Name` is fixed
  inline storage — RFC 1035 caps a name at 255 wire bytes, so parsing a query
  allocates nothing at all — ASCII-lowercased per RFC 4343, with bytes outside
  ASCII passing through and comparing bytewise so DNS-SD and internationalized
  names need no opinion about text encoding. **Compression pointers must point
  strictly backwards**, which makes the cursor strictly decrease and the chain
  finite; decompression terminates on adversarial input without a visited set.
- `HostPolicy`, a suffix index. The lookup walks the query's suffixes from most
  to least specific and stops at the first match, so the most specific rule
  wins and, at equal specificity, blocking beats inspection — a refused host is
  never also intercepted. O(labels) hash probes, at most two per label, and the
  253-character name limit bounds labels at 127. The keys use `HashSet`'s
  SipHash with its per-process random seed, which matters because qnames are
  attacker-chosen: any application on the device can ask for any name.
- `ech_policy`, the whole of ECH policy and the phase's second gate: `Strip` if
  and only if the host is inspected. There is no global ECH switch anywhere in
  the crate, because disabling ECH for the session would hand every site's SNI
  back to the network for the sake of the few hosts actually inspected.
  Stripping is a byte range removed from one answer's RDATA, expressed as
  `Rdata { head, tail }`, so it rewrites nothing and allocates nothing.
- `write_response`, which rebuilds the client's answer. Three decisions carry
  it. The transaction id, the question section, and the recursion-desired bit
  come from the *client's query*, never from the upstream — a resolver that
  echoes an upstream's id answers a question the client did not ask; the
  question is copied as raw bytes so a client using 0x20 case randomization
  still recognizes its own query, which is exactly why a compressed question
  name is refused (nothing precedes the question but the header, so a pointer
  there is nonsense, and refusing it is what makes the verbatim copy provably
  safe). And names are written **uncompressed**: the only edit is deleting a
  byte range from one RDATA, and deleting bytes from the middle of a message
  invalidates every compression pointer targeting anything after the deletion.
  Uncompressed output costs tens of bytes on a response crossing a 1420-byte
  tunnel and cannot be wrong.
- Interception in the core. `admit` now settles everything no egress capability
  can change — reassembly, unsupported protocols, and DNS — so all three keep
  working under a configuration that cannot plan a flow, and `route_planned`
  handles the rest. Interception keys on the port rather than on a resolver
  address: the client's configured resolver lives inside the tunnel, so every
  query on port 53 is one Boreas owns. A query becomes a `DnsQuery` carrying a
  pooled payload — which is also its bound, since pending queries cannot
  outgrow the shared budget — and `answer_dns` writes the reply back. That
  needed `packet::write_udp`, the dual of `IngressPacket::parse` and the only
  place this crate originates a packet rather than forwarding one; both
  checksums are computed in full because a synthesized datagram has no
  predecessor to adjust from.
- The shell. `DnsUpstream` is the transport and nothing else; `TunnelBypass`
  names a platform obligation the crate cannot discharge — the upstream socket
  must not travel through Boreas's own TUN, which means `VpnService.protect` on
  Android and binding the physical interface on Windows — and `Do53Upstream`
  uses one ephemeral socket per query, which is what lets concurrent queries
  correlate without a transaction-id demultiplexer. **The resolver is a second
  task, and the split is load-bearing:** a resolution is a network round trip,
  and awaiting one inside the reactor would stall every packet behind a slow
  upstream. They meet over two bounded channels with a 64-permit semaphore, so
  a saturated resolver becomes a dropped query the stub retries, never a
  stalled datapath.
- `Telemetry::Resolved` carries a whole `Resolution`: the name, the rule that
  matched, the transport that answered, the rcode, and what happened to ECH.
  One per query, and a query is a flow-scale event rather than a packet-scale
  one, so it travels whole rather than folded into a counter. A blocked name
  costs no query and leaks no name to any upstream.

**The encrypted transports were deferred at first, then delivered once the TLS
stack was admitted; see the P11 addendum below.** `hickory-resolver` was never
admitted: the parsing, policy, provenance, and rewriting above are ours
regardless of who carries the bytes, so the only thing it would have supplied
is the transports — and those turned out to be a few hundred lines each on top
of `rustls`, against a dependency graph an order of magnitude smaller.

Also deferred: TCP/53 and `TC=1` truncation handling, which need the local
termination that arrives with P14. Until then a response too large for the
1232-byte DNS Flag Day budget becomes a visible `SERVFAIL` the stub retries
rather than a fragmented datagram that a `DF`-set path would drop, and the
counter says how often that happens.

**Gate met:** `tests/dns.rs` drives three queries through the whole shell in
one session — a blocked name, an inspected host, and an allowed host — and
asserts that the blocked name is refused locally with the upstream consulted
three times rather than four, that the inspected host's HTTPS answer loses
exactly its `ech` parameter and keeps its `alpn`, and that **the allowed host,
in the same session and the same run, keeps its ECH configuration**. That last
assertion is the gate: a global switch would have moved both. Every answer's
`Telemetry::Resolved` names its rule, its transport, and its ECH outcome, and
A, AAAA, HTTPS, and SVCB are all covered. The `dns` fuzz target ran 7.16M
executions clean over query and answer bytes that need not agree with each
other, asserting that a written response re-parses and that a stripped answer
never still publishes an ECH configuration; the `datapath` target now also
drives interception and answer synthesis. 75 tests, fmt, clippy, and
`cargo deny` clean.

**Unlocks:** P12 consumes the same `watch`-swappable `Arc<HostPolicy>`; P13
reads `SVCPARAM_ALPN` from the same SvcParam walk this phase added.

### P11 addendum: encrypted transports

Delivered after P13, once P14's dependency question was decided.

- `src/upstream.rs` holds every transport behind `DnsUpstream`, which is only
  the wire: the policy that decides whether to consult one, and what to do with
  what it says, stays pure in `src/dns.rs`. The single thing a transport
  contributes to a verdict is which `Upstream` carried it.
- **DoT (RFC 7858)**, complete and conformant. The framing is the whole
  protocol — two octets of big-endian length then the message, in both
  directions — and the reader checks the declared length against the accepted
  message size *before* sizing a buffer, so a hostile resolver cannot decide
  how much memory a query costs. The `dot` ALPN identifier from section 3.2 is
  offered, so a server that will not speak it fails the handshake rather than
  the exchange.
- **DoH (RFC 8484)**, with one bounded conformance gap. A `POST` of
  `application/dns-message`, which is the wire format already in hand — no
  re-encoding, and no base64 as the `GET` form would need. Section 5.2 requires
  a client to support HTTP/2 and this one speaks HTTP/1.1; public resolvers
  accept it, and the alternative today is an HTTP/2 client the crate has no
  other use for. The `h2` stack arrives with P14's interception, at which point
  this moves onto it behind the same trait. `Connection: close` and a read to
  end-of-stream is what keeps the response reader to a status line and headers:
  there is no chunked transfer to decode when the body ends with the
  connection, and only a `200` yields a body, because a DNS answer parsed out
  of an error page would be worse than no answer.
- **The trust anchors are Mozilla's bundle, deliberately not the platform
  store.** Boreas installs its own root into the user store for interception,
  and a resolver trusting the OS store would trust the certificate authority
  Boreas itself controls — precisely the relationship this connection must not
  have. This is a security property of the choice, not a portability shortcut.
- **One connection per query.** Concurrent queries on a shared connection must
  be matched by transaction id, and the id travelling upstream is the client's,
  so a shared connection needs id rewriting before it can be correct at all.
  A connection per query is correct without either, and the cost is bounded by
  session resumption: each upstream owns one `ClientConfig` for its lifetime
  and rustls keeps the session cache there, so every query after the first is a
  one-round-trip resumption. Persistent pipelined connections remain the
  follow-up, gated on the id rewriting in [Verification](verification.md).
- `TunnelBypass` gained `tcp` alongside `udp`, because TLS needs a stream and
  the platform obligation is identical: the socket must not travel through
  Boreas's own TUN.

**DoQ is not delivered and the reason is not TLS.** DNS over QUIC needs a QUIC
stack, which the plan admits at P17 with `tokio-quiche` for MASQUE. Adding one
here for DNS alone would be the largest dependency in the graph serving the
smallest capability in it.

**Gate met, and measured rather than asserted:** `examples/resolve.rs` resolves
one name through all three transports against a live resolver. On the aarch64
dev VM: Do53 1.9 ms, DoT 10.7 ms then 4.9 ms primed, DoH 10.3 ms then 9.7 ms
primed. The DoT figure is the resumption working; the DoH pair is close because
`Connection: close` forgoes keep-alive, which is the cost the h2 move recovers.
The framing, the bounds, and every refusal are unit-tested against in-memory
streams, because a test that needs somebody else's uptime is not a gate.

### P12: filter-list pipeline

**Status: the name tier is complete; the URL tier is deferred with a reason.**
Delivered:

- `src/filter.rs`, the compiler between two different worlds. A filter list is
  hundreds of thousands of lines written against *URLs*; the tier enforceable
  without a CA is *names*. A line classifies into a closed sum with three real
  answers — enforceable, nothing to enforce, and *well-formed but this tier
  cannot decide it* — and the third carries `Deferred` to name the missing
  faculty. A rule needing a URL is not a parse error and not a silent drop; it
  is a counted deferral, and the count is what tells an operator how much
  coverage waits on P14.
- Adblock Plus network syntax (`||host^`, `@@||host^`), hosts-file syntax
  including multi-name sink lines, comments, and list headers. Exceptions beat
  every block that matches the same query, at any specificity: that is ABP
  semantics and the fail-open direction [Filtering](filtering.md) mandates.
- `ListReport`, a commutative monoid under `merge` with `default()` as its
  identity, so several lists compile independently and sum in any order. Every
  line is accounted for exactly once, which the tests assert against a real
  build rather than an invented one.
- Hot reload through the P8 `watch` channel — the thing that channel was built
  for and had no payload for until now. A build publishes a whole new index;
  each query is decided against exactly one version, the one current when it
  was admitted, so a reload cannot split a decision in half. The resolver reads
  the receiver to decide and the reactor observes it to report
  `Telemetry::PolicyReloaded`.

**Deferring is the design, not a shortcut.** `||ads.example^$third-party`
blocks a host only in third-party context, and there is no third party at the
name tier — the same host is first-party to itself. Compiling it into a name
rule would break the site that owns it. The stated invariant is that every
divergence from Adblock Plus goes toward matching *less*: `||example.com`
anchors at a domain boundary in ABP, which also matches
`example.com.evil.example`, and the suffix index does not. A compiled list can
under-block and cannot over-block.

**The `adblock` crate is not admitted here.** Its engine matches URLs, and
there are no URLs until interception exists, so admitting it now would be a
dependency with no executable path — the rule [AGENTS.md](../AGENTS.md) states.
It belongs at P14, where `http::Request` first supplies what it needs, and the
`data/test/fake-uBO-files/` packaging check in
[Verification](verification.md) moves there with it.

**Gate:** `tests/dns.rs` compiles a mixed ABP-and-hosts list into a live
session, publishes it under a running reactor, and asserts that a name which
resolved a moment earlier is now refused locally with no upstream query, that
an exception in the same list still beats the more specific block above it, and
that the swap is reported with the rules it holds. The M2 *product* gate —
visible ad blocking across applications on a device — needs the device this
environment does not have and is **unexercised**, like P9's and P10's.

**Completes the M2 mechanism; the M2 product gate stays open.**

### P13: Protocol steering

**This must precede P14, and the order is load-bearing.** Browsers race QUIC
against TCP and take QUIC if it answers within roughly 300 to 500 ms. Ship MITM
first and an allowlisted host reaches h3, where a locally added root can never
validate, so interception silently never fires and the failure looks like a
filtering bug rather than a transport one. [Delivery](delivery.md) places both
in M3; within M3 this order is not interchangeable.

**Status: both discovery-time mechanisms complete; Alt-Svc rewriting is
blocked on P14.** Delivered:

- **HTTPS/SVCB rewriting**, on exactly the machinery P11 built. `h3_alpn_param`
  finds the `alpn` parameter when it advertises h3 — registered `h3` and the
  drafts browsers still accept — and extends the range over `no-default-alpn`
  when it follows, which RFC 9460 section 7.1.1 requires because that parameter
  may only appear alongside `alpn`. Keys are strictly increasing and no integer
  lies between 1 and 2, so the pair is always one contiguous range and the
  removal stays a slice operation. Steering removes the advertisement rather
  than editing the list: the record's default ALPN is then `http/1.1`, TLS ALPN
  still negotiates h2 on the connection that follows, and the browser cannot
  reach h3 from DNS.
- `alpn_policy`, with the same law as `ech_policy` — strip if and only if the
  host is inspected — and `answer_policy` deriving both from one verdict.
  Grouping them is not tidiness: a caller holding one without the other could
  steer without stripping ECH, which is precisely the half-applied policy that
  makes an interception fail silently.
- `Rdata` now carries three parts rather than two, because an inspected host
  whose answer advertises h3 loses two disjoint ranges from one RDATA. Two is
  the number of removals any policy in this crate performs, so three slices
  cover the domain and a doubly-rewritten answer still costs no allocation.
- **The transient UDP/443 backstop.** DNS steering stops a browser with no
  cached Alt-Svc entry; the backstop covers the window while a stale one
  expires. `answer_addresses` feeds a steered-address index from the upstream's
  own A and AAAA answers — before the rewrite, so no second parse — and
  `admit` refuses UDP to port 443 for those addresses while the window is open.
  TCP to the same address and port is untouched, because that is the
  destination steering is trying to reach, and the check applies only outward,
  because an inbound packet to port 443 is a response rather than an attempt.
- The index is a `HashMap` and deliberately not a timer wheel. It is bounded by
  the inspected allowlist times its addresses — tens of entries — so an O(1)
  probe per UDP/443 packet is what the hot path needs and a wheel over tens of
  entries would be a segment tree where a prefix sum suffices. The earliest
  deadline is maintained rather than searched, because the reactor reads it
  once per wakeup and wakeups are what the performance budget is written
  against. `Limits` gained the window and a capacity, so state fed by network
  input is bounded like every other queue in this crate.

**Alt-Svc rewriting is deferred, and the reason is structural.** An `Alt-Svc`
header arrives in an HTTP response, so rewriting one requires reading HTTP
responses, which requires the interception P14 has not shipped. The DNS half
and the L4 backstop are exactly the two mechanisms that work *without* it, and
they are what the phase's ordering argument is about: both act at discovery,
before a connection exists. When P14 lands, Alt-Svc rewriting becomes a header
edit on a path that already exists, and the backstop window can shrink to what
the header rewrite leaves uncovered.

**Gate:** `tests/dns.rs` drives an inspected host, an allowed host, and a QUIC
attempt through one session: HTTPS and SVCB answers for the inspected host lose
their h3 advertisement and their ECH configuration, the allowed host in the
same run keeps both, and a QUIC datagram to the inspected host's resolved
address is dropped and counted while TCP to the same address is not. The
convergence *measurement* — that a real browser re-races to TCP within one
window — needs the browser and the device this environment does not have and is
**unexercised**.

### P14: MITM, allowlist-only

User-store CA lifecycle, rustls, `rcgen` leaf generation, h1 and h2
interception. Deliberately narrow: an explicit allowlist, manually maintained.

**Status: blocked on local TCP termination, which is a missing phase rather
than a missing decision.** Interception needs a byte stream to terminate, and
this crate has none: `smoltcp` is still a dev-dependency, exercised only by
`examples/smoltcp_scaling.rs`, and P10 recorded that its integration is gated
on re-measurement under live traffic ([Verification](verification.md) item 6),
which is device-bound. Every other input to P14 — an allowlist, a CA, a leaf
generator, an `http`-shaped exchange — is downstream of having a stream, so
building them first would be building against a substrate whose shape is not
yet fixed. **The plan needs a phase between P10 and P14 that integrates
smoltcp and delivers `TransportPath::LocalTermination` for real.** It is
recorded as an open item below rather than silently absorbed into P14.

**The dependency half is done.** `rustls` 0.23 is admitted, on the `ring`
provider already in the graph for WireGuard, so no second crypto provider is
shipped to a target that counts bytes. `tokio-rustls` and `webpki-roots` come
with it. That was the decision open item 6 asked for, and it is what let P11's
encrypted transports land; `rcgen` and `h2` wait for the stream.

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
4. Device-side batching: the budget calls it mandatory and the reactor still
   reads one packet per wakeup. It needs a non-blocking read on `AsyncDevice`,
   which both adapters can supply, and its metric (packets per wakeup) is
   device-bound. Decide it against the M1 on-device run, not before.
5. The egress tick is an unconditional 4 Hz wakeup, at parity with GotaTun's
   own device and the largest fixed wakeup cost in the shell. Replacing it
   with an egress-declared next deadline requires GotaTun to expose one; carry
   this into the battery measurement.
6. ~~P11's encrypted upstreams need a TLS stack the plan first admits at
   P14.~~ **Decided 2026-08-11:** `rustls` is admitted early, on the `ring`
   provider already in the graph, and P11's DoT and DoH landed on it.
   `hickory-resolver` was not needed once the transports turned out to be a few
   hundred lines each.
8. **The plan is missing a phase between P10 and P14: smoltcp integration and
   real local termination.** P14 cannot start without a byte stream, and P6's
   scaling verdict is explicitly provisional pending re-measurement under live
   traffic. Insert it, sequence its device-bound measurement, and only then
   schedule P14.
7. Whether Boreas should rewrite the transaction id it sends upstream. Today
   the client's own id travels out, and the ephemeral source port carries the
   anti-spoofing entropy. Rewriting is transparent — `write_response` takes the
   id from the client's query and ignores the upstream's — so this is a cheap
   change waiting on a decision, not a design question.
