# Egress

## Capability Before Protocol

Egress is selected and composed by live capability, not by protocol name or
static configuration. The same protocol can change capability during a session.
MASQUE, for example, can fall back from QUIC to HTTP/2, losing native UDP
semantics while remaining connected.

The capability product includes:

- accepted input layer: IP packets or L4 flows
- datagram fidelity: native, emulated, or none
- per-packet encapsulation overhead
- maximum datagram size when known
- ECN preservation
- NAT behavior

The current core models every field except NAT behavior, which must be added
with the first egress whose behavior affects routing.

For a chain, accepted layers must agree, fidelity takes the minimum, overhead
is summed with overflow checks, datagram size takes the tightest known ceiling,
and ECN survives only if every hop preserves it.

## Datagram Fidelity

Native datagrams preserve datagram boundaries and use datagram-appropriate
congestion behavior. Emulated datagrams carried over a reliable stream are
pathological for QUIC: they create double congestion control, double
retransmission, and restored head-of-line blocking. Shipping Shadowsocks
clients already warn that UDP-relayed QUIC reliability depends on the outbound
proxy and may fall back to TCP.

Rule: any fidelity below native forces HTTP/2 steering. No QUIC datagram may be
tunnelled over emulated or absent datagram capability.

## Tier 1: Packet Egress

Implement packet-native egress first. It is the simplest path and enables the
smoltcp bypass.

### WireGuard

Use GotaTun. Integrated 2026-08-11 at 0.8.1 as `WireGuardEgress` in
`src/egress.rs`: a sans-io wrapper over `Tunn`, driven by the shell through
`EgressEmit::{ToNetwork, ToTunnel}` and an explicit timer tick. The sans-io
methods live on the `PacketEgress` trait rather than on the concrete type, so
the reactor drives any packet egress without naming a protocol, and every
emission is a pooled buffer on the datapath's own budget — an egress sits on
the hottest path there is, and the performance budget forbids allocating per
packet. The reactor owns both the egress and the network seam
(`AsyncNetwork`), so the fused path never leaves one task. The reported
overhead is 80 bytes, the IPv6-underlay worst case (40 outer IPv6 + 8 UDP + 32
WireGuard header and tag); 60 bytes remains the IPv4 figure. Exact overhead is
a measured property of the address family and implementation, recorded in
[Verification](verification.md) item 4. Windows readiness and ECN behaviour
(item 13) remain verification items. Keep the egress boundary narrow enough to
substitute NepTUN if testing invalidates it.

### MASQUE CONNECT-IP

Use `tokio-quiche` and quiche. RFC 9484 carries arbitrary IP packets, updates
the HTTP datagram framework in RFC 9297 and CONNECT-UDP in RFC 9298, and
normatively references DPLPMTUD in RFC 8899 and ECN tunnelling in RFC 6040.

A correct CONNECT-IP implementation therefore preserves packet-level PMTU and
ECN semantics. QUIC unavailability can trigger HTTP/2 fallback, as shipping
Apple MASQUE relays do. That transition changes datagram fidelity and must
re-run policy immediately without dropping established flows.

## Tier 2: Flow Egress

Implementation order:

1. SOCKS5, including UDP ASSOCIATE
2. Shadowsocks
3. VLESS with TLS, Reality, and XTLS-Vision
4. Hysteria2

VLESS plus Reality is a priority for mainland China because it disguises
traffic as a normal HTTPS visit and is widely deployed. Hysteria2 is expected
to improve throughput by 10 to 30 percent and P95 latency by 20 to 40 percent
when loss is at least 1 percent and RTT is at least 100 ms. Those ranges are
claims to benchmark, not acceptance without local evidence.

Deferred:

- TUIC, because its authentication token is a TLS keying-material export and
  `quiche` exposes no exporter. Supporting it would mean either patching
  `quiche` upstream or shipping `quinn` as a second QUIC stack for one
  protocol. A tier-2 protocol does not earn either; see the engineering plan's
  P17 notes for the full finding.
- VMess
- mKCP, due to low performance and recognizable brute-force encryption
- meek, due to very low throughput
- gRPC transport

Many Xray-family transports are private, widely deployed protocols with
non-standard or invalid wire semantics. Support them for user value, but do not
mistake deployment popularity for standards quality.

## SOCKS5 Lifecycle

UDP ASSOCIATE retains a TCP control connection for the association lifetime.
Creating one association per DNS flow can produce hundreds of control
connections. Multiplex associations per configured egress where protocol and
server behavior permit it. Actual server support prevalence remains a field
verification item.

## Egress Acceptance Gates

- non-native fidelity produces zero tunneled QUIC datagrams
- chain overhead is checked and summed correctly
- chain fidelity and datagram size use the weakest member
- packet egress increments a fast-path counter and never enters smoltcp
- a MASQUE QUIC-to-HTTP/2 transition re-steers policy without dropping flows
- ECN and PMTU claims are validated against packet captures and path tests
- each protocol reports live capability changes to the planner
