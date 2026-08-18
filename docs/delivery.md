# Delivery

## Constraints Register

| Constraint | v1 consequence |
|---|---|
| non-rooted Android CA trust | MITM is limited to eligible Chromium browsers and WebViews; native apps receive DNS and network filtering |
| Chromium user roots and HTTP/3 | inspection-required hosts must be steered from h3 to h2 |
| Certificate Transparency | Android user-store-only installation avoids the system-store CT path |
| TLS and H2 fingerprint mismatch | closed: BoringSSL mirrors the client's own hello and the HTTP/2 preface is Chrome's; automatic demotion remains the fail-open response |
| certificate pinning | reduced by browser scope but not absent; fail-open is mandatory |
| ECH adoption | passive SNI policy is not durable; DNS is the no-decryption signal |
| Windows driver signing | use the redistributable signed Wintun binary |
| one mobile VPN interface | filtering and egress must remain fused |

## Build Gaps

| # | Gap | Size |
|---:|---|:---:|
| 1 | Android VpnService/JNI and Windows Wintun adapters | M |
| 2 | connection classifier and policy router | M |
| 3 | pin-failure detection and automatic demotion | S |
| 4 | memory governor | S |
| 5 | protocol steering and transient UDP/443 backstop | S |
| 6 | ECH policy in the resolver | S |
| 7 | scriptlets and redirect resources; generic cosmetic rules | M |
| 8 | fragment reassembly and PMTU measurement on a real path | S |
| 9 | smoltcp socket-set scaling | M |
| 10 | RFC 4787 conformance measurement against a live STUN server | S |
| 12 | VLESS with the V2Ray transport family, and Hysteria2 | L |
| 13 | CA lifecycle and user-store installation UX | S |
| 14 | filter-list build pipeline | S |

Numbers are stable identifiers, so a closed gap leaves its row out rather than
renumbering the ones after it.

Gap 1 shrank because both v1 platforms share one raw-IP datapath. Gaps 3, 4,
and 13 shrank after arbitrary app interception and iOS left v1 scope.

Gap 11 closed: Shadowsocks carries SIP022 packets under all three methods,
Hysteria2 carries QUIC datagrams with fragmentation, and VLESS frames them over
a stream per destination — which is `Emulated` rather than `Native` and says so,
because boundaries survive a reliable ordered transport but loss tolerance does
not. Gap 10 is now only the measurement: the relay drives one association per
client mapping through whichever egress provides one, so what is left is
observing the mapping behaviour on a real network.

Gap 8 narrowed to measurement as well. ICMP crosses a packet egress whole, and
over-sized packets that forbid fragmentation are answered with a Packet Too Big
so a sender learns its path — which is what QUIC needs, since TCP is served by
the MSS clamp. Inbound PTB *validation* is deliberately not wired: on the fast
path the client's own stack holds the connection a message quotes and is the
better authenticator, and it receives the message because Boreas forwards it.

## Milestones

Milestones are product gates. The engineering phase order that reaches them,
including the dependency edges and per-phase checks, is owned by
[Engineering Plan](engineering-plan.md).

### M1: Datapath, weeks 1-4

Build Android TUN and Wintun adapters, L3, locally terminated TCP and UDP,
splice, and GotaTun. Do not add filtering or MITM. Run the fusion benchmark.

**Gate:** a working single-interface WireGuard client on Android and Windows.

### M2: Filtering Without Decryption, weeks 5-8

Add DNS interception, DoH and DoT upstreams, the `adblock` network engine,
filter-list builds, and blocking UX.

**Gate:** most visible ad blocking works across applications without a CA.

### M3: Browser HTTPS Filtering, weeks 9-14

Add user-store CA lifecycle, H1 and H2 MITM, cosmetic filtering, scriptlets,
protocol steering, challenge detection, and pin-failure demotion.

**Gate:** AdGuard parity on the fixed browser corpus.

The gate includes HTTPS/SVCB and Alt-Svc steering, cache-aware convergence, and
the transient UDP/443 backstop described in [Filtering](filtering.md). An
allowlisted host must not enter the MITM path over QUIC during cache expiry or
the browser's QUIC/TCP race.

### M4: Egress Breadth, weeks 15-20

Add MASQUE CONNECT-IP, SOCKS5, and Shadowsocks, followed by VLESS with its
transport family, and Hysteria2.

**Gate:** filtering composes with the target egress set.

### M5: iOS Separate Track

Build content-blocker compilation and a DNS-only VPN.

Research outputs such as ablations, fingerprint-breakage measurements, and a
pinning census come from milestone instrumentation rather than separate work.

## Acceptance Criteria

### Product parity

- On a fixed 200-site Chrome/Android corpus and identical filter lists, Boreas
  block rate is at least AdGuard for Android's.
- Measure Chrome, WebView, and one Chromium alternative separately.
- A top-500 crawl has zero Boreas-attributable breakage.
- Pin-failure automatic demotion succeeds at least 99 percent of the time.

### L3 and L4

- QUIC-enabled paths assert inner MTU of at least 1200 bytes.
- Forged PTB messages are rejected.
- ECN is preserved through every claiming egress.
- Fragment fuzzing is clean.
- STUN confirms endpoint-independent UDP mapping.
- UDP mappings survive at least two minutes.
- 10,000 flows remain within the defined resource budget.
- Congestion produces bounded latency and counted drops, never queue growth.
- Before smoltcp integration merges, define the M1 socket-count, RSS, and p99
  latency budget; the implementation must pass that fixed workload without
  panic or unbounded socket-set cost.

### L7

- The version-crossing exchange counter remains zero.
- QUIC never enters the MITM path while steering is enabled.
- With 32 streams and one stalled stream, other streams' p99 rises less than 10
  percent.
- HTTP/3 pass-through loses no more than 5 percent throughput.
- Steering converges within one Alt-Svc cache or UDP backstop window.

### Egress

- Non-native datagram fidelity tunnels zero QUIC datagrams.
- Chained overhead is summed correctly.
- A counter proves packet egress bypasses smoltcp.
- Mid-session MASQUE fallback to HTTP/2 re-steers without dropping flows.

### Performance

- Splice adds no more than 5 ms p95 latency.
- MITM adds no more than 50 ms p95 latency.
- A four-hour workload consumes no more than 8 percent additional battery over
  bare WireGuard.
- The fusion benchmark reports wakeups per second, context switches, RSS, and
  battery against a two-process chain.

## Risk Register

| Risk | Severity | Mitigation and falsifier |
|---|---|---|
| CDN fingerprint breakage | Medium | BoringSSL originates and the Akamai fingerprint is asserted on the wire; narrow allowlist, challenge detection, automatic demotion; measure the residue in M3 |
| smoltcp scaling | Medium-high | load test during M1; replace or specialize only on measured failure |
| GotaTun immaturity | Medium | narrow boundary and NepTUN fallback; verify on both v1 platforms |
| steering hysteresis | Medium | transient UDP/443 backstop and convergence telemetry |
| VLESS-family maintenance | Medium | retain late-M4 priority and isolate private protocol code |
| WebView vendor variation | Medium | early device and OS matrix before marketing claims |

CDN fingerprint-induced breakage was the top risk while both fingerprints were
`rustls`'s and `hyper`'s. Both are now the browser's, asserted by tests rather
than assumed, so what remains is residue — an unmirrored TLS extension, a
behavioural tell above the framing — measurable in M3 rather than architectural.
It stays on the register because it is observable and fail-open, not because it
is unaddressed.
