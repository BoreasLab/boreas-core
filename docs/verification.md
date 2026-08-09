# Verification and Dependency Ledger

This document separates evidence from design. A statement may motivate a
settled architecture while its operational limits still require measurement.
Update the date, source, and status whenever a claim is rechecked.

## Dependency Policy

Boreas is AGPLv3. Runtime dependencies must be AGPL-compatible, maintained, and
used by an immediate executable path. MPL-2.0 is GPL-compatible through its
secondary-license mechanism. Test fixtures and vendored data require their own
license review even when crate source is compatible.

Compatibility runs inbound, not outbound: an AGPL work may absorb a permissive
dependency, but a dependency under a licence imposing further restrictions —
GPL-2.0-only, EPL, CDDL, or any source-available licence such as SSPL, BUSL, or
the Elastic Licence — cannot be combined and distributed. Note also that AGPL
obligations attach on conveying the work, and section 13's network-source
requirement attaches on running a modified version for remote users; neither
waits for a third party to modify anything.

`deny.toml` encodes the allowlist and `cargo deny` runs in CI, so a
non-compliant dependency fails the build instead of waiting for review. The
allowlist is narrower than the legally compatible set on purpose: adding any
copyleft dependency requires editing that file, which forces the decision to be
explicit. It checks the crate graph only, so vendored data such as the
`adblock-rust` GPL test-data subtree still needs the manual packaging check.

### Current dependencies

| Crate | Version | Role | License |
|---|---:|---|---|
| `etherparse` | 0.21.0 | borrowed IPv4, IPv6, and transport parsing | MIT OR Apache-2.0 |
| `arrayvec` | 0.7.8, transitive | bounded parser storage | MIT OR Apache-2.0 |

### Planned and evaluated dependencies

Versions are deliberately omitted until first integration. Resolve the latest
compatible release and regenerate the license review at that time.

| Project | Role | License status | Evidence and caveat |
|---|---|---|---|
| `lol_html` | streaming HTML rewrite | BSD-compatible | Cloudflare Workers lineage; designed for bounded memory |
| `adblock` | network, cosmetic, and scriptlet rules | MPL-2.0 compatible | Brave production lineage; Firefox ships adblock-rust; supports uBO-style syntax and Apple content-blocking export |
| `rustls` | single v1 TLS stack | MIT OR Apache-2.0 | explicit crypto provider required from the 0.24 line; prior noted MSRV 1.83 |
| `rcgen` | leaf certificate generation | MIT OR Apache-2.0 | rustls organization; mature dependency surface |
| `hickory-resolver` | DNSSEC, DoT, DoH, DoQ | MIT OR Apache-2.0 | ISRG Prossimo-backed |
| `tokio-quiche` and quiche | MASQUE and later H3 | BSD-compatible | used by iCloud Private Relay Proxy B, Oxy, and WARP's MASQUE client |
| GotaTun | WireGuard | BSD-3-Clause | Mullvad project; audit and all-platform rollout were planned for 2026 |
| `smoltcp` | locally terminated TCP | BSD OR Apache-2.0 | vendored in AOSP; host-scale feature limits require testing |
| `shadowsocks-rust` | Shadowsocks egress | verify before use | mature and active, exact current license remains an action item |
| `wintun-bindings` | Windows Wintun loading | verify binding release | exposes Adapter and Session APIs |
| `wintun.dll` | signed Windows TUN driver | GPLv2 distribution terms | use WireGuard's authorized redistributable signed binary |
| Privaxy | vendorable prior art | AGPLv3 compatible | reference for MITM exclusion, WebSocket upgrades, and uBO scriptlet and redirect behavior |

The `adblock-rust` tree contains `data/test/fake-uBO-files/` material that
appears GPL-3.0-or-later and outside the top-level license. It is test data and
should not enter a shipped binary or vendored runtime source. Confirm packaging
before release.

Filter lists have independent terms. EasyList and similar compiled artifacts
may create distribution obligations separate from engine licensing. Obtain
legal review before shipping compiled lists.

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
  intercepted policy as described in the subsystem documents.
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
  CONNECT-IP capability and fallback behavior.
- RFC 9114 documents the non-trivial H2/H3 transition surface.
- WebTransport is structurally H3-specific; WebSocket extended CONNECT differs
  across RFC 8441 and RFC 9220; CONNECT SETTINGS gate validity.
- Alt-Svc and HTTPS/SVCB records drive H3 discovery and retain cache state.
- Cloudflare Radar protocol shares supported h2 and h3 prioritization.
- Chromium's user-certificate path does not provide target H3 interception.
- Browser fingerprint byte parity would require BoringSSL-class behavior.
- Privaxy's memory profile, functionality, and AGPLv3 status were reviewed.

## Not Yet Verified

Do not rely on these without a targeted check:

1. Whether Chrome bypasses every static certificate pin for a user-installed
   root. This determines which Google properties can be intercepted and needs a
   short device test in M3.
2. The current `shadowsocks-rust` license and distribution obligations.
3. WebView user-root behavior across vendor builds and Android releases.
4. Exact per-egress overhead beyond the approximate 60-byte WireGuard budget.
5. GotaTun readiness on Windows.
6. smoltcp behavior and socket-set cost at hundreds of concurrent sockets.
7. SOCKS5 UDP ASSOCIATE support among servers users actually operate.
8. Claimed Hysteria2 and TUIC throughput and P95 improvements on the Boreas
   workload.

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

1. **AGPLv3 and the App Store:** choose dual licensing, a permissive iOS
   component, or no iOS release before M5.
2. **Firefox for Android:** decide whether its different CA behavior and required
   H3 configuration belong in the parity target.
3. **WebView marketing:** advertise in-app browser filtering only after the
   vendor matrix proves consistency.
4. **Windows interception scope:** choose browser-only or system-wide CA use and
   account for CT and pinning consequences.
5. **QUIC migration:** decide whether v1 UDP state follows connection IDs or
   explicitly excludes migration from guarantees.
6. **Filter-list terms:** obtain legal advice for shipping compiled EasyList and
   related artifacts.
7. **Neutral exchange model:** decide whether v1 keeps the three-adapter
   `Exchange` core in [Filtering](filtering.md) or builds on `http`-crate types.
   Boreas never terminates HTTP/3 in v1, so the quiche-interoperability
   rationale does not apply. Raised by [Engineering Plan](engineering-plan.md)
   phase P14.
8. **smoltcp budget:** fix the socket-count, RSS, and p99 latency targets before
   integration merges, per phase P6.
9. **Timer-wheel granularity:** confirm that one-second buckets over a 512-bucket
   wheel hold at 10,000 flows, per phase P7.

## Updating This Ledger

For each new external claim, record the primary source, source date, observed
version, and whether the result is verified, unverified, or inferred. A crate
name in this file does not authorize adding it. Dependency admission still
requires a current release, license, maintenance, and transitive-graph check.