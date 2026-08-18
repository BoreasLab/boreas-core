# Architecture Decisions

These decisions were accepted for design v2.0 on 2026-08-08. Change one only
through an explicit replacement decision that updates every affected subsystem
document and acceptance gate.

## ADR-001: Fused Single-Process Datapath

**Decision:** Filtering and encrypted egress run in one Rust process behind one
system VPN interface. Egress remains vendor-agnostic.

**Reason:** Mobile operating systems permit one active VPN. A two-application
design requires private IPC and a vendor-controlled proxy relationship. Fusion
allows any supported self-hosted or third-party egress while reducing context
switches, wakeups, memory, and duplicated packet traversal.

**Proof required:** benchmark against a two-process chain using wakeups per
second, context switches, RSS, and battery.

## ADR-002: Narrow Tiered Interception

**Decision:** DNS and network filtering apply broadly. TLS interception is
opt-in and limited to eligible browsers and WebViews. Failure demotes to splice.

**Reason:** Modern Android native apps do not generally trust user roots, and
arbitrary app interception is infeasible without root. Narrow scope reduces
pinning and fingerprint breakage while retaining browser-grade filtering.

## ADR-003: Strict L3, L4, and L7 Separation

**Decision:** L3 handles packets, L4 exposes streams or datagram flows, and L7
never sees packets. UDP is a NAT flow table, not a TCP-like stack.

**Reason:** The separation permits packet fast paths, makes transport semantics
explicit, and prevents packet concerns from contaminating HTTP policy. UDP
requires loss-oriented bounded behavior rather than reliable-stream machinery.

## ADR-004: HTTP/2 and HTTP/3 First-Class

**Decision:** HTTP/2 is the primary interception protocol. HTTP/3 is a
first-class pass-through protocol. Steering replaces blanket QUIC suppression.

**Reason:** Browser traffic is dominated by h2 and h3. Global QUIC blocking
throws away performance for flows that need no interception. Host policy and
egress fidelity determine whether h3 remains advertised.

## ADR-005: No Cross-Version HTTP Bridging

**Decision:** Mirror the negotiated HTTP version upstream. Never translate a
live exchange between H1, H2, and H3. Steering before connection establishment
is allowed because the client genuinely negotiates the selected version.

**Reason:** RFC 9114 requires a transition appendix covering streams, frame
types, prioritization, field compression, flow control, HTTP/2 SETTINGS, error
codes, and an explicit H2/H3 error mapping. A normative error mapping is
evidence that translation is lossy.

Non-portable cases include:

- WebTransport is structurally H3-only. A session ID is the QUIC stream ID of
  its CONNECT stream, uses RFC 9221 datagrams, and depends on three SETTINGS.
- WebSocket bootstrapping uses RFC 8441 on H2 and RFC 9220 on H3. As of early
  2026, no major browser or server had shipped RFC 9220.
- Extended CONNECT sent before
  `SETTINGS_ENABLE_CONNECT_PROTOCOL=1` is received is malformed.

**Invariant:** a version-crossing exchange counter exists and remains zero.

## ADR-006: Live Egress Capabilities Govern Policy

**Decision:** Route by current egress path properties, not configured protocol name.
Chaining takes minimum fidelity and datagram size, sums overhead, and intersects
ECN preservation.

**Reason:** RFC 9298 and RFC 9484 permit HTTP/2 fallback when QUIC is
unavailable. Shipping MASQUE systems use that fallback, which changes native
UDP semantics without changing the selected egress label.

## ADR-007: rustls Terminates, BoringSSL Originates

**Decision:** rustls serves the local client; every handshake Boreas *initiates*
is BoringSSL, shaped by the client's own ClientHello. The upstream HTTP/2 preface
is Chrome's.

**Supersedes** the original ADR-007, which chose rustls throughout and deferred
fingerprint parity until CDN breakage was measured.

**Reason:** A MITM creates two TLS connections, and the upstream one is
fingerprinted by whoever answers. rustls exposes no supported way to shape a
ClientHello — extension order, GREASE placement, and JA3/JA4-matching hellos are
long-standing open requests — so the deferral was not a schedule choice but a
dependency wall. `quiche` already linked BoringSSL, so adopting it directly added
an edge rather than a library.

**What made it worth doing before the measurement.** The gap was not a matter of
degree. BoringSSL's default groups cannot express `X25519MLKEM768`, which every
current Chrome offers; `hyper`'s HTTP/2 defaults matched Chrome on none of the
four Akamai fields, and its pseudo-header order matched no browser at all. A
client that differs in every field is not a near miss.

**Cost, stated:** two patched dependencies (`vendor/README.md`), and a mirror
that tracks BoringSSL's API rather than a fixed browser profile. The asymmetry is
what bounds it — the terminating leg keeps rustls and its memory safety, because
nothing fingerprints an application on the same device.

## ADR-008: Android User-Store CA Only

**Decision:** Install the Boreas CA only in the Android user store, never in the
system store.

**Reason:** This is the non-rooted path trusted by target browsers and WebViews.
It avoids Chrome's system-store Certificate Transparency path and removes
Conscrypt APEX modification from the backlog.

## ADR-009: Wintun on Windows

**Decision:** Use Wintun and its redistributed signed binary. Do not build a WFP
callout driver in v1.

**Reason:** Wintun supplies the same raw-IP abstraction as Android without a new
kernel driver, EV certificate, attestation process, or second datapath. Per-app
WFP policy does not justify those costs yet.

## ADR-010: iOS Is a Separate Declarative Product

**Decision:** Compile filter lists for an Apple Content Blocker extension and
use a DNS-only VPN. Do not port the Android HTTP interception datapath.

**Reason:** Safari offers the correct native enforcement point. The architecture
shares engine and lists while avoiding the packet-tunnel memory ceiling and an
inferior partial port.

## ADR-011: Dual-Stack Native from v1, with a 1280-Byte Inner MTU Floor

**Decision:** IPv6-native and dual-stack operation are day-one requirements, not
a later addition. Consequently the tunnel's inner MTU floor is 1280 bytes. A
chain whose inner MTU falls below 1280 is a rejected configuration, not a
degraded IPv4-only mode.

**Reason:** RFC 8200 requires every link carrying IPv6 to have an MTU of at
least 1280 octets, and recommends 1500 or greater specifically to accommodate
tunnelling without IPv6-layer fragmentation — which is exactly the Boreas case.
Boreas configures its own TUN MTU and the user selects the egress chain, so this
is an admission rule over configuration we control, not a guess about a hostile
path.

RFC 791's 68-octet IPv4 link minimum is explicitly not used. It bounds what a
router must forward without fragmenting, not what a tunnel must offer; the
practical IPv4 floor is the 576-octet reassembly minimum, and neither value
yields a usable dual-stack tunnel.

**Consequence:** 1280 sits above RFC 9000's 1200-byte QUIC floor, so every
admitted packet path clears QUIC by construction. MTU-driven steering can
therefore only originate from an egress datagram ceiling on a terminated path,
never from an admitted packet path. This is asserted at compile time.

**Corollary:** on a locally terminated path the client's packet size no longer
exists, so an inner MTU is meaningless there and local MSS clamping governs
instead. `TransportPath::PacketFastPath` carries the inner MTU and
`LocalTermination` does not, so the meaningless reading is unrepresentable. QUIC
admission on a terminated path uses the egress's declared datagram ceiling; an
egress that declares none cannot be shown to clear the floor and is steered.

## Deferred and Rejected Directions

- WFP waits for proven per-app policy demand.
- QUIC interception on Chromium is externally constrained and out of scope.
- `mitmproxy_rs` is OS-integration glue around PyO3, not the desired TLS core.
- `boringtun` carries upstream maintenance and restructuring risk.
- `tun2socks` adds a roughly 73K SLoC C core and duplicates the datapath.
- `hyperium/h3` remains experimental for this use.
- `quinn` maintenance concentration is too high for the selected QUIC core.
- `hudsucker` is reference material, not a strategic dependency.
