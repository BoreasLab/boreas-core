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

**Decision:** Route by current egress capability, not configured protocol name.
Chaining takes minimum fidelity and datagram size, sums overhead, and intersects
ECN preservation.

**Reason:** RFC 9298 and RFC 9484 permit HTTP/2 fallback when QUIC is
unavailable. Shipping MASQUE systems use that fallback, which changes native
UDP semantics without changing the selected egress label.

## ADR-007: One Rust TLS Stack in v1

**Decision:** Use rustls throughout v1. Do not mimic browser TLS or HTTP/2
fingerprints.

**Reason:** A MITM creates two TLS connections. The upstream connection exposes
a different TLS and H2 fingerprint, which some CDNs use to challenge or block.
Byte-level browser parity requires BoringSSL or equivalent browser behavior;
no Rust-native client currently promises it. Instrument failures before paying
the implementation and maintenance cost.

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

## Deferred and Rejected Directions

- TLS fingerprint mimicry waits for measured CDN breakage.
- WFP waits for proven per-app policy demand.
- QUIC interception on Chromium is externally constrained and out of scope.
- `mitmproxy_rs` is OS-integration glue around PyO3, not the desired TLS core.
- `boringtun` carries upstream maintenance and restructuring risk.
- `tun2socks` adds a roughly 73K SLoC C core and duplicates the datapath.
- `hyperium/h3` remains experimental for this use.
- `quinn` maintenance concentration is too high for the selected QUIC core.
- `hudsucker` is reference material, not a strategic dependency.
