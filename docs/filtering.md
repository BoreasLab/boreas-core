# Filtering

## Enforcement Tiers

Boreas applies the least invasive enforcement point that can satisfy policy:

1. DNS resolution and filtering for all traffic visible to the VPN.
2. Network blocking from destination and protocol metadata.
3. Byte-for-byte splice for allowed opaque traffic.
4. TLS interception only for explicitly eligible browser and WebView traffic.

Native app traffic that rejects the Boreas CA still receives DNS and
network-level filtering. Optional interception failures must demote to splice,
not break connectivity.

## Android Trust Boundary

On non-rooted Android, Chrome trusts a user-installed CA for ordinary TLS
connections. Chromium-family browsers such as Brave and Edge commonly follow
the same model. WebViews can also use the user CA, bringing in-app browsers in
social and news applications into the intended product scope.

Modern native applications generally do not trust user-added roots. Apps
targeting Android 6.0, API 23, and lower trusted them by default; current apps
must opt in through network security configuration. Non-Chromium browsers vary
and must be treated as third-party applications unless a tested configuration
proves otherwise.

Install the Boreas root only in the user store. Never move it into the Android
system store. Chrome applies Certificate Transparency requirements to roots
found through the system-store path. AdGuard's rooted workaround uses
cross-signed user and system roots so Chrome can construct the shorter
user-store path. Boreas does not need that workaround because non-rooted,
user-store-only operation is the product boundary. This also removes all
Conscrypt APEX bind-mount work from scope.

The Android parity matrix must cover Chrome, WebView across representative
vendors and OS versions, and one Chromium alternative. Do not advertise
universal WebView support until that matrix passes.

## DNS and ECH

Intercept DNS and support encrypted upstream resolution through DoH, DoT, and
DoQ. Apply network rules and protocol steering to A, AAAA, HTTPS, and SVCB
answers while retaining enough provenance to explain a verdict.

ECH, standardized as RFC 9849 in March 2026, blinds passive SNI inspection and
is enabled by default in Chrome 122+, Firefox 119+, and Safari 17+. A proxy that
terminates TLS can still observe the inner connection, but passive policy
cannot rely on SNI. DNS is the durable no-decryption policy signal.

ECH policy must stay coupled to resolver control. Do not silently disable ECH
globally when host-level policy or steering is sufficient.

Implemented in `src/dns.rs`. `ech_policy` is the entire decision and its law is
that ECH is stripped if and only if the host is inspected, so an allowed host
in the same session keeps the configuration its authority published; there is
no global switch in the crate to reach for. Stripping removes the `ech`
SvcParam from that host's HTTPS or SVCB answer and nothing else, expressed as a
byte range so the rewrite copies no bytes it did not have to. Host rules are a
suffix index in which the most specific rule wins and, at equal specificity,
blocking beats inspection — a refused host is never also intercepted — and a
refused name is answered locally with `NXDOMAIN`, so the block costs no query
and leaks no name upstream. `NXDOMAIN` rather than a null address because a
client handed `0.0.0.0` opens a connection that fails on a timeout, while a
name error fails immediately down a path every browser already has.

Every answer carries a `Resolution`: the name, the rule that matched, the
transport that answered, and what happened to ECH. A verdict a user cannot see
the reason for is a verdict they cannot argue with.

Steering rides the same machinery. An inspected host's HTTPS and SVCB answers
lose their HTTP/3 advertisement as well as their ECH configuration, both
derived from the one verdict, because a locally added root can never validate
over QUIC: an inspected host reached over h3 is a host whose interception
silently never fires. Removing the `alpn` parameter leaves the record's default
ALPN, and TLS ALPN still negotiates h2 on the connection that follows.

DNS steering only reaches a browser that has no cached Alt-Svc entry for the
origin. The transient UDP/443 backstop covers the rest: the addresses an
inspected host resolves to refuse QUIC for a bounded window, so the browser's
QUIC-versus-TCP race resolves to TCP within its own 300-to-500 ms window. TCP
to the same address is untouched — it is the destination steering aims at — and
the drop counter is the convergence signal. Alt-Svc *header* rewriting waits on
interception, since the header only exists inside an HTTP response.

Encrypted upstreams are implemented in `src/upstream.rs`. DoT (RFC 7858) is
complete; DoH (RFC 8484) speaks HTTP/1.1 rather than the HTTP/2 the RFC
requires clients to support, an interim gap that closes when interception
brings an `h2` stack. DoQ waits on the QUIC stack that arrives with egress
breadth. The `Upstream` a verdict records distinguishes them precisely because
the privacy claim differs per transport: DoT is encrypted and authenticated but
runs on a port a hostile network can simply block, which is the difference DoH
exists to cover.

The resolver's trust anchors are Mozilla's bundle and not the platform store,
because Boreas installs its own root into the user store for interception and a
resolver trusting the OS store would trust the authority Boreas itself
controls.

## HTTP Priority

Cloudflare Radar Q2 2026 reported HTTP/2 at 51.16 percent, HTTP/1.x at 27.80
percent, and HTTP/3 at 21.04 percent, with HTTP/3 flat over the preceding year.
Because machine traffic is a substantial part of the total, browser h2 and h3
share exceeds the raw combined interpretation. Boreas treats:

- HTTP/2 as the primary interception protocol
- HTTP/3 as a co-primary pass-through protocol
- HTTP/1.1 as a legacy adapter

These external measurements belong to the verification ledger if refreshed.

## HTTP/2 Contract

- The stream is the unit of filtering, rewriting, budgeting, and cancellation.
- Start advertised `SETTINGS_MAX_CONCURRENT_STREAMS` at 32, then tune by data.
- Never grant a downstream flow-control window larger than bytes drained from
  upstream.
- Keep per-stream state independent so one stalled response cannot restore
  connection-level head-of-line blocking.
- Mirror negotiated ALPN into upstream pools. Never downgrade implicitly.
- Forward RFC 9218 priority through `PRIORITY_UPDATE` where supported.
- Construct an HTML rewriter only after a `text/html` response is confirmed.

## Neutral Exchange Model

quiche and `tokio-quiche` do not use the Rust `http` crate as their native
model. The core therefore uses a protocol-neutral exchange with three wire
adapters:

```rust
struct Exchange {
    request: Head,
    body_in: BodyStream,
    body_out: BodySink,
    protocol: Wire,
    priority: Option<Priority>,
    budget: StreamBudget,
}
```

`Wire` records H1, H2, or H3 for fidelity and observability. Filter rules never
branch on it. Each adapter preserves its protocol's native semantics and errors
without translating a live exchange to another version.

## Protocol Steering

Chromium does not provide the required user-root path for HTTP/3 interception.
Any host selected for MITM must connect over HTTP/2 instead. Clients discover
HTTP/3 through Alt-Svc and increasingly through HTTPS or SVCB records, both of
which Boreas can control.

| Host policy | HTTPS/SVCB response | Alt-Svc response | Outcome |
|---|---|---|---|
| pass-through | unchanged | unchanged | full HTTP/3 |
| MITM allowlist | remove `h3` | remove or empty | client selects HTTP/2 |
| non-native datagrams | remove `h3` | remove or empty | client selects HTTP/2 |

An HTTPS record with `alpn="h3,h2"` can enable HTTP/3 on a first visit. An empty
Alt-Svc tells a client to stop attempting the alternative service. Serving only
h2 prevents Firefox from initiating h3 in tested behavior.

Steering has hysteresis. Alt-Svc defaults can remain cached for 24 hours,
`persist=1` survives network changes, and production sites often advertise
`ma=2592000`. A newly allowlisted host therefore needs a transient UDP/443
backstop until the cached advertisement expires.

Steering is a hint, not a cryptographic control. Browsers may race QUIC and TCP
and choose QUIC if it answers within roughly 300 to 500 ms. The backstop closes
that transition window for inspection-required hosts.

## Body and Header Rewriting

Use `adblock` for network rules, cosmetic rules, uBlock Origin scriptlets, and
redirect syntax. Use `lol_html` for streaming body transformation.

Rewriting pipeline:

1. Confirm the host and stream are eligible.
2. Confirm `text/html` and a supported character encoding.
3. Decode content encoding and character encoding.
4. Rewrite under per-stream memory and strictness budgets.
5. Re-encode characters and recompress with the original algorithm when
   possible, otherwise gzip.
6. Remove `Content-Length` and emit protocol-appropriate streaming framing.

Supported text must use an ASCII-compatible encoding. UTF-16LE, UTF-16BE,
ISO-2022-JP, and `replacement` are unsupported and must splice unchanged.
Wire `lol_html` memory settings and strict bail-out to a fail-open path.

Relax CSP only as narrowly as required for injected content. Never modify an
`integrity=` protected subresource. Preserve WebSocket upgrades and exclude
hosts from MITM when policy or observed failures require it.

## Failure Policy and Gates

Pin failures, certificate errors attributable to interception, challenge pages,
unsupported encoding, memory exhaustion, and parser strictness failures demote
the host to splice. Challenge detection and automatic demotion belong in M3,
not as post-launch polish.

Acceptance:

- Boreas block rate is at least AdGuard's on the fixed 200-site corpus using
  identical lists.
- The top-500 crawl has zero Boreas-attributable breakage.
- Pin-failure automatic demotion succeeds at least 99 percent of the time.
- The version-crossing exchange counter remains zero.
- With 32 h2 streams and one stalled stream, other streams' p99 rises less than
  10 percent.
- HTTP/3 pass-through loses no more than 5 percent throughput.
- Steering converges within one cache or backstop window.
