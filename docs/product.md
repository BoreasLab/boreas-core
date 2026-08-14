# Product

## Definition

Boreas is a single-process Rust engine that fuses browser-grade content
filtering with user-selected encrypted egress on one system VPN interface.

The v1 target is feature parity with AdGuard for Android on non-rooted devices,
plus composition with any supported egress selected by the user, including a
self-hosted WireGuard server, MASQUE, VLESS, and SOCKS5. The user is not tied to
one vendor's proxy.

AdGuard documents the underlying product collision: on an unrooted device its
default VPN-mode blocker cannot run simultaneously with AdGuard VPN. Its
Integrated mode resolves this by making one first-party app an outbound proxy
for the other. Boreas resolves the collision inside one process, so filtering
can compose with third-party and self-hosted egress.

## v1 Scope

Platforms:

- non-rooted Android
- Windows

Capabilities:

- one unified TUN datapath
- IPv6-native and dual-stack operation from day one, not a later addition
- DNS filtering with DoH, DoT, and DoQ upstreams
- network-level blocking for all apps visible to the VPN
- TCP and UDP parity
- HTTP/1.1, HTTP/2, and HTTP/3 as first-class wire protocols
- browser-scope HTTPS filtering through a user-store CA
- Chromium-family browser and WebView coverage on Android
- pluggable L3 and L4 egress

The primary parity gate is measured on Chrome for Android. Chrome, WebView, and
one Chromium alternative are evaluated separately so aggregate results cannot
hide a platform-specific failure.

## v2 iOS Product

iOS is a separate architecture, not a reduced port. Safari already provides a
declarative content-blocking enforcement point. Boreas will compile standard
ABP-style rules to Apple's content-blocking format, using the `adblock`
`content-blocking` capability, and push them to a Content Blocker extension.
The packet tunnel performs DNS-level filtering only.

This preserves one filtering engine and one list pipeline while choosing the
native enforcement point on each platform. It also removes the 50 MB
`NEPacketTunnelProvider` memory ceiling from all v1 architecture decisions.

## v1 Non-Goals

- arbitrary native-app TLS interception on non-rooted Android
- TLS or HTTP fingerprint mimicry
- cross-version HTTP bridging
- HTTP/3 interception for Chromium
- iOS delivery
- Windows per-app policy through a custom WFP callout driver
- deferred egress protocols: VMess, mKCP, meek, and gRPC transport

## Product Principles

1. One interface must provide filtering and egress composition. Assembling a
   configured egress yields *both* effects a session needs — one that carries
   packets and one that carries re-originated flows — so the composition is a
   total function of the egress rather than a shape only some egresses admit.
2. The common path must stay packet-native and cheap.
3. Decryption is narrow, opt-in, browser-scoped, and fail-open.
4. DNS is the durable no-decryption policy signal as ECH adoption grows.
5. Product milestones produce research evidence; research does not block the
   product critical path.

## Success Definition

Boreas succeeds when a non-rooted Android or Windows user can select an egress,
enable system-wide DNS and network filtering, optionally enable browser HTTPS
filtering, and retain correct TCP, UDP, QUIC, and path-MTU behavior through one
VPN interface with acceptable battery and latency cost.

Detailed quantitative gates are in [Delivery](delivery.md). Platform trust
boundaries are in [Filtering](filtering.md) and [Platforms](platforms.md).
