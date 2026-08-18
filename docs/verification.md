# Verification and Dependency Ledger

This document separates evidence from design. A statement may motivate a
settled architecture while its operational limits still require measurement.
Update the date, source, and status whenever a claim is rechecked.

## Dependency Policy

Runtime dependencies must be maintained and used by an immediate executable
path.

### Current dependencies

Reviewed 2026-08-11 against the resolved `Cargo.lock`.

| Crate | Version | Role |
|---|---:|---|
| `etherparse` | 0.21.0 | borrowed IPv4, IPv6, and transport parsing |
| `arrayvec` | 0.7.8, transitive | bounded parser storage |
| `tokio` | 1.53.1 | runtime shell: reactor task, bounded channels, timer |
| `tokio-util` | 0.7.19 | `CancellationToken` for structured shutdown |
| `tokio-macros` | 2.7.2, transitive | `select!`, `pin!`, `#[tokio::test]` |
| `futures-util` | 0.3.34, transitive | pulled by `tokio-util` |
| `futures-core` | 0.3.34, transitive | pulled by `tokio-util` |
| `futures-sink` | 0.3.34, transitive | pulled by `tokio-util` |
| `futures-task` | 0.3.34, transitive | pulled by `tokio-util` |
| `futures-macro` | 0.3.34, transitive | pulled by `tokio-util` |
| `pin-project-lite` | 0.2.17, transitive | pulled by `tokio` |
| `bytes` | 1.12.1, transitive | pulled by `tokio-util` |
| `slab` | 0.4.12, transitive | pulled by `tokio` |
| `proc-macro2` | 1.0.107, transitive | build-time only |
| `quote` | 1.0.47, transitive | build-time only |
| `syn` | 3.0.3, transitive | build-time only |
| `unicode-ident` | 1.0.24, transitive | build-time only |
| `smoltcp` | 0.13.1, dev-only | the P6 scaling measurement; never linked |
| `gotatun` | 0.8.1 | sans-io WireGuard peer behind `WireGuardEgress` |
| `ring` | 0.17.14, transitive | gotatun's AEAD and X25519 backends |

`gotatun` pulls a wider transitive graph (x25519-dalek, curve25519-dalek,
chacha20poly1305, blake2, and friends).

The DNS transports use that bundle rather than the platform trust store, and
that is a security property rather than a portability shortcut: Boreas installs
its own root into the user store for interception, and a resolver trusting the
OS store would trust the certificate authority Boreas itself controls.

`ring` compiles C at build time, which ended the local
x86_64-pc-windows-msvc cross-check that P9 used: this Linux environment has no
MSVC. A windows-latest CI job now owns that check.

`tokio` is taken with named features (`macros`, `rt`, `rt-multi-thread`,
`sync`, `time`) rather than `full`. Boreas cross-compiles to Android, so the
process, signal, and file drivers `full` would enable are shipped weight for
path properties the shell does not use.

### Planned and evaluated dependencies

Versions are deliberately omitted until first integration. Resolve the latest
compatible release at that time.

| Project | Role | Status | Evidence and caveat |
|---|---|---|---|
| `lol_html` | streaming HTML rewrite | candidate | Cloudflare Workers lineage; designed for bounded memory |
| `adblock` | network, cosmetic, and scriptlet rules | candidate | Brave production lineage; Firefox ships adblock-rust; supports uBO-style syntax and Apple content-blocking export |
| ~~`rustls`~~ | the terminating TLS server | integrated 2026-08-11 at 0.23.43; originating role handed to `boring` 2026-08-14 | Taken with `default-features = false` and the `ring` provider **already in the graph for WireGuard**, so no second crypto backend ships to a target that counts bytes; `tls12` is kept for resolver interoperability. `tokio-rustls` 0.26.4 came with it. `webpki-roots` went with the originating role: the terminating server verifies nothing and needs no anchors |
| `rcgen` | leaf certificate generation | candidate | rustls organization; mature dependency surface |
| `hickory-resolver` | DNSSEC, DoT, DoH, DoQ | not admitted | ISRG Prossimo-backed; **not admitted, and no longer needed.** DoT and DoH landed directly on the crate's own TLS at a few hundred lines each, against a far smaller graph. Reconsider only for DNSSEC validation. Earlier note: Message parsing, host policy, provenance, and ECH rewriting are Boreas's own regardless of who carries the bytes, so the only thing it supplies today is the encrypted transports — and those need the TLS stack the plan first admits at P14. Revisit with that decision |
| `tokio-quiche` and quiche | MASQUE and later H3 | candidate | used by iCloud Private Relay Proxy B, Oxy, and WARP's MASQUE client |
| ~~GotaTun~~ | WireGuard | integrated 2026-08-11 at 0.8.1 | Mullvad project; Windows readiness unexercised, no device in this environment |
| `smoltcp` | locally terminated TCP | dev-only today | vendored in AOSP; host-scale feature limits require testing |
| ~~`boring`~~ / `tokio-boring` | every TLS handshake Boreas initiates | integrated 2026-08-14 at 5.2 | Not a new C dependency: `quiche` already linked BoringSSL through this crate, so the artefact gained an edge rather than a library. 5.x vendors `BORINGSSL_API_VERSION 41`, which has `X25519MLKEM768`; 4.x predates it. Forced `quiche` into `vendor/` — `links = "boringssl"` admits one package per graph |
| ~~`h2`~~ | HTTP/2 framing, and the pseudo-header order | patched in `vendor/` | Already in the graph beneath `hyper`. Vendored for one swap in `impl Iterator for Iter`: h2 emits `:method :scheme :authority :path`, every browser emits `:method :authority :scheme :path`, and neither h2 nor hyper exposes it. RFC 9113 §8.3 fixes no order among pseudo-headers |
| ~~`ruzstd`~~ | zstd decode for the HTML tier | integrated 2026-08-14 at 0.9 | Decoder-only and pure Rust, matching `brotli-decompressor` and `flate2`'s `rust_backend`. Chrome has offered `zstd` since Chrome 123 and CDNs serve it, so without it the tier failed open on a growing share of documents |
| `shadowsocks-rust` | Shadowsocks egress | candidate | mature and active |
| `wintun-bindings` | Windows Wintun loading | verify binding release | exposes Adapter and Session APIs |
| `wintun.dll` | signed Windows TUN driver | candidate | use WireGuard's authorized redistributable signed binary |
| Privaxy | vendorable prior art | reference only | reference for MITM exclusion, WebSocket upgrades, and uBO scriptlet and redirect behavior |

## Rejected Dependency Directions

| Project | Reason |
|---|---|
| `mitmproxy_rs` | PyO3 OS-integration support, not a standalone TLS interception core |
| `boringtun` | upstream restructuring warning and no active dedicated maintainer |
| `tun2socks` | approximately 73K SLoC C core and a duplicate datapath |
| `hyperium/h3` | still experimental for this product boundary |
| `quinn` | maintenance concentrated in two volunteers at evaluation time |
| `hudsucker` | thin, single-maintainer reference implementation; borrow patterns, not dependency risk |

## Verified Design Inputs

The design investigation reported the following as verified by 2026-08-08:

- Chrome on Android and WebView use user-installed roots in the target path.
- Non-rooted user-store trust is primarily a browser boundary; modern native
  apps generally reject user roots by default.
- Chrome's Certificate Transparency requirement applies to the Android
  system-store path, while a user-store validation path avoids that treatment.
- Android network security configuration changed user-root defaults after API
  23.
- `adblock` is MPL-2.0, Firefox ships adblock-rust, and Apple content-blocking
  export exists.
- Wintun provides a userspace raw-IP adapter and WireGuard distributes signed,
  redistributable binaries, avoiding a custom-driver signing program.
- The adblock-rust GPL test-data subtree exists.
- iOS packet-tunnel memory limits and Conscrypt APEX constraints were examined,
  but no longer constrain v1.
- Certificate pinning, JA3/JA4, HTTP/2 fingerprinting, and ECH affect passive or
  intercepted policy as described in the subsystem documents. Chrome's HTTP/2
  preface — `1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p` — was taken from
  Chromium's `AddDefaultHttp2Settings` and cross-checked against curl-impersonate
  and captures through Chrome 147; `src/mirror.rs` holds it as a value and
  `src/exchange.rs` asserts it against the bytes an origin receives.
- QUIC has a 1200-byte path floor and restricted sub-1200 behavior.

Rechecked against primary sources on 2026-08-09:

- RFC 9000 section 14.1: "An endpoint MUST ensure that it can send datagrams of
  at least 1200 bytes", and an endpoint "MUST immediately cease sending QUIC
  packets on the affected path if the path does not support 1200 byte
  datagrams, with the exception of packets used for path validation
  (PATH_CHALLENGE, PATH_RESPONSE), PMTU probes, and CONNECTION_CLOSE frames."
  Earlier internal wording omitted the path-validation exception and asserted a
  "MAY terminate the connection" clause that this check did not confirm; the
  subsystem text now follows the quoted rule only.
- RFC 8200 section 5: "IPv6 requires that every link in the Internet have an MTU
  of 1280 octets or greater", and configurable links "must be configured to have
  an MTU of at least 1280 octets; it is recommended that they be configured with
  an MTU of 1500 octets or greater, to accommodate possible encapsulations
  (i.e., tunneling) without incurring IPv6-layer fragmentation." This is the
  basis for ADR-011.
- RFC 791's 68-octet figure is the minimum an internet module must forward
  without further fragmentation; the 576-octet figure is the minimum every
  destination must be able to reassemble. RFC 8085 treats 576 as the practical
  IPv4 sending floor. Neither is a usable dual-stack tunnel MTU, so neither is
  used as one.
- RFC 9000 does not state a derivation for 1200 in section 14, so the common
  explanation that it follows from 1280 minus headers remains unsourced and is
  not asserted anywhere in these documents.
- Forged PTB attacks represented by CVE-2024-53259 require flow validation.
- RFC 4787 defines endpoint-independent UDP mapping, no port overloading, and a
  minimum two-minute mapping lifetime.
- RFC 9297, RFC 9298, and RFC 9484 define HTTP datagrams, CONNECT-UDP, and
  CONNECT-IP support and fallback behavior.
- RFC 9114 documents the non-trivial H2/H3 transition surface.
- WebTransport is structurally H3-specific; WebSocket extended CONNECT differs
  across RFC 8441 and RFC 9220; CONNECT SETTINGS gate validity.
- Alt-Svc and HTTPS/SVCB records drive H3 discovery and retain cache state.
- Cloudflare Radar protocol shares supported h2 and h3 prioritization.
- Chromium's user-certificate path does not provide target H3 interception.
- Browser fingerprint byte parity requires BoringSSL-class behaviour, which is
  why `boring` is now a direct dependency rather than only quiche's.
- Privaxy's memory profile and functionality were reviewed.

## Not Yet Verified

Do not rely on these without a targeted check. Other documents cite these items
by number, so a retired item leaves a reserved slot rather than renumbering the
list.

1. Whether Chrome bypasses every static certificate pin for a user-installed
   root. This determines which Google properties can be intercepted and needs a
   short device test in M3.
2. *Reserved.*
3. WebView user-root behavior across vendor builds and Android releases.
4. Exact per-egress overhead beyond the approximate 60-byte WireGuard budget.
   Partially answered 2026-08-11: `WireGuardEgress` reports 80 bytes, the IPv6
   underlay worst case (40 outer IPv6 + 8 UDP + 32 WireGuard), so the inner
   MTU is never optimistic; the per-family exact figure remains unmeasured.
5. GotaTun readiness on Windows. Related and unexercised locally: the Wintun
   adapter's cancel-safety fix of 2026-08-11 (retaining the `spawn_blocking`
   join handle across `recv` calls, so a dropped future no longer discards the
   packet the blocking read already consumed). Compile-checked in the Windows
   CI job only; the behaviour needs a device.
6. smoltcp behavior and socket-set cost at hundreds of concurrent sockets.
   **Measured 2026-08-11, smoltcp 0.13.1, aarch64 Linux VM, idle listening
   sockets, `examples/smoltcp_scaling.rs`:** poll cost scales linearly at
   roughly 5-25 ns per socket per poll across 100-2000 sockets (p50 2-14 µs
   total at 500-2000 sockets). p99 is dominated by 10 ms timer-wheel wakeups
   (retransmit/keepalive timers), not by socket count: single-digit µs typical,
   millisecond outliers when a timer fires. No superlinear socket-set cost
   observed at these counts. Caveat: idle listeners on an idle device; live
   data transfer and the mobile target remain unmeasured, so the verdict is
   provisional until P7's hot-path work re-measures under traffic.
7. SOCKS5 UDP ASSOCIATE support among servers users actually operate.
8. Claimed Hysteria2 throughput and P95 improvements on the Boreas workload.
9. Whether one TLS connection per DNS query is acceptable on a real page load.
   Measured 2026-08-11 against a live resolver (`examples/resolve.rs`, aarch64
   dev VM, release): Do53 1.9 ms; DoT 10.7 ms cold and 4.9 ms resumed; DoH
   10.3 ms cold and 9.7 ms resumed. Session resumption is doing the work on
   DoT; DoH gains less because `Connection: close` forgoes keep-alive.
   Persistent pipelined connections are the fix and are gated on the
   transaction-id rewriting in item 7 below, since a shared connection must
   demultiplex replies by an id that is currently the client's own. Measure a
   real page load before deciding whether the current cost is acceptable.
10. Whether DoH over HTTP/1.1 is accepted by the resolvers users configure.
    RFC 8484 section 5.2 requires client support for HTTP/2; this client speaks
    HTTP/1.1 and offers only `http/1.1` in ALPN, so a server that refuses it
    fails the handshake rather than the exchange. Verified against Cloudflare
    on 2026-08-11. The gap closes when P14's `h2` stack arrives.
11. Packets per wakeup and packets per syscall, the performance budget's primary
   derived metrics. The reactor reads one packet per wakeup; device batching
   needs a non-blocking read on `AsyncDevice` and can only be judged against a
   real device. Related: the egress tick is an unconditional 4 Hz wakeup, at
   parity with GotaTun's own device, and is the largest fixed wakeup cost in
   the shell. Both belong to the M1 on-device battery run.
12. Whether the DNS upstream socket is genuinely excluded from the tunnel. The
    `TunnelBypass` seam names the obligation — `VpnService.protect` on the
    descriptor on Android, binding the physical interface's address on Windows
    — and `DirectSockets` deliberately does not discharge it. A resolver
    reached through the tunnel that is resolving for it is a loop, and this
    environment has neither platform to prove the exclusion on. Device-bound,
    and a prerequisite for the M2 gate.
13. Whether a 1232-byte response budget is sufficient in practice. Responses
    are written uncompressed and capped at the DNS Flag Day 2020 size so a
    synthesized datagram never needs fragmentation on a `DF`-set path; an
    over-large answer becomes a `SERVFAIL` the stub retries. The correct answer
    is `TC=1` and TCP/53, which needs the local termination arriving at P14.
    Measure the `SERVFAIL` counter against a real corpus before deciding
    whether that wait is acceptable.
14. That the pooled fast path holds its budget under real traffic. Measured
    in-process 2026-08-11 (`examples/fusion.rs`, aarch64 dev VM, release):
    core 573 ns/packet against the ~1 µs allowance, 2 187 ns end to end, and
    every pool slice returned at rest across 10,000 packets. In-process only:
    the two-process baseline still needs two real devices.

## Inferred Engineering Judgments

These are deliberate hypotheses to test, not external facts:

- smoltcp should implement TCP only.
- L7 should receive a closed `Stream | DatagramFlow` sum.
- syscall batching will dominate mobile UDP throughput improvements.
- constructing rewriters only for HTML is the largest controllable memory win.
- 32 is a reasonable initial H2 concurrent-stream limit.
- the L3 fast path justifies maintaining dual packet and local-termination modes.
- one owner-thread state machine reduces deadlock and livelock risk compared
  with shared locks and detached per-flow tasks.

## Open Product and Architecture Questions

Numbered as above, with reserved slots for retired questions.

1. *Reserved.*
2. **Firefox for Android:** decide whether its different CA behavior and required
   H3 configuration belong in the parity target.
3. **WebView marketing:** advertise in-app browser filtering only after the
   vendor matrix proves consistency.
4. **Windows interception scope:** choose browser-only or system-wide CA use and
   account for CT and pinning consequences.
5. **QUIC migration:** decide whether v1 UDP state follows connection IDs or
   explicitly excludes migration from guarantees.
6. *Reserved.*
7. **Neutral exchange model:** decide whether v1 keeps the three-adapter
   `Exchange` core in [Filtering](filtering.md) or builds on `http`-crate types.
   Boreas never terminates HTTP/3 in v1, so the quiche-interoperability
   rationale does not apply. Raised by [Engineering Plan](engineering-plan.md)
   phase P14.
8. **smoltcp budget:** fixed 2026-08-11 from the item-6 measurement: at least
   1,000 concurrent TCP sockets, per-socket poll cost under 100 ns amortized
   (100 µs for a full set sweep), p99 poll under 1 ms excluding timer fires,
   RSS growth linear in socket count at no more than 2 KiB per socket (two
   1 KiB buffers plus socket state, per the workload's allocation). The
   integration must hold this under live traffic before merging, per phase P6.
9. **Timer-wheel granularity:** confirmed 2026-08-11. The shipped wheel is
   512 one-second buckets with an overflow list; `tests/scale.rs` holds at
   10,000 flows with one slot per flow under a 110k-packet refresh flood, and
   stale slots never evict a refreshed flow early.
10. **Reactor wakeup cost:** measured 2026-08-11 on the aarch64 dev VM, release
    build. The reactor arms one timer against `Datapath::poll_timeout`, so the
    cost of that call is paid once per iteration and must not scale with state.
    `UdpFlowTable::next_deadline` measures ~98 ns at 1 flow and ~99 ns at
    10,000 flows — flat, because `TimerWheel::next_due` scans at most 512
    buckets rather than every entry. `Reassembler::next_deadline` is one
    `BTreeMap::first_key_value`, measured at 2.3 ns after a 200,000-fragment
    flood. `tests/shell.rs` pins the wakeup rate itself on tokio's paused
    clock: an idle reactor wakes on its 500 ms reporting tick, not on a poll
    interval.
11. **Fragment-flood amplification:** measured 2026-08-11, release build. A
    64 KiB datagram delivered last-fragment-first costs 3.6 ms of `push` time
    against 0.94 ms in order — linear in bytes, with the residual gap being
    buffer growth and cache behaviour rather than fragment count. Before the
    O(1) completion counter the same input cost 36.7 ms, a 29x penalty for an
    ordering the sender chooses. The expiry index no longer grows with
    fragments at all: `src/reassembly.rs` asserts one slot per pending
    datagram after 10,000 rejected fragments.
12. **Fusion path cost:** measured 2026-08-11, release build, aarch64 dev VM,
    `examples/fusion.rs`: 10,000 packets driven tun → datapath → WireGuard →
    peer → back in-process. 2.1 µs per packet end to end; the datapath alone,
    same script, is 585 ns per packet — within the ~1 µs per-packet budget in
    [Engineering Plan](engineering-plan.md) — and the residual ~1.5 µs is ring
    AEAD in both directions on a VM without crypto acceleration evidence.
    The two-process baseline the M1 gate compares against needs real devices
    and remains outstanding. Wakeups and context switches, the budget's actual
    cost drivers, are kernel-visible and likewise belong to the device run.
13. **ECN over WireGuard:** unverified. The inner header's ECN survives
    encryption, but outer-header marking propagation through the UDP underlay
    is unimplemented and unmeasured, so `WireGuardEgress` claims
    `preserves_ecn: false`. Validate against packet captures before any claim.

## Updating This Ledger

For each new external claim, record the primary source, source date, observed
version, and whether the result is verified, unverified, or inferred. A crate
name in this file does not authorize adding it. Dependency admission still
requires a current release, maintenance, and transitive-graph check.