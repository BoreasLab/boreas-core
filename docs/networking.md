# Networking

## L3 Responsibilities

L3 receives raw IPv4 or IPv6 packets from a platform adapter and owns:

- strict packet parsing and length validation
- IPv4 fragment reassembly before any L4 parse
- IPv6 extension and fragmentation handling
- path and inner MTU accounting
- TCP MSS clamping on SYN packets
- ICMP echo and Packet Too Big generation
- validation of inbound ICMP errors against known flows
- ECN preservation

Malformed input is an expected boundary failure, not a panic. A fragmented
packet is a distinct state and cannot be admitted as a TCP or UDP flow until
reassembly succeeds.

## MTU and QUIC

For an egress chain:

```text
inner_mtu = path_mtu - sum(egress_overhead)
```

The subtraction is checked. A zero or negative result rejects the plan.

QUIC requires UDP datagrams that are not fragmented at the IP layer and a path
that supports at least 1200 bytes. Initial packets are padded to 1200 bytes. If
the effective path falls below that floor, an endpoint must stop ordinary QUIC
transmission except path probes and `CONNECTION_CLOSE`, and may terminate the
connection. Boreas therefore steers the client to HTTP/2 whenever inner MTU is
below 1200 instead of creating a silent black hole.

Generate ICMP Fragmentation Needed or Packet Too Big toward the client when
appropriate. Accept an inbound PTB only when its quoted packet and path match a
known flow. Forged sub-1200 PTB messages can disable QUIC, as demonstrated by
CVE-2024-53259, so an unauthenticated ICMP message must never directly lower a
flow's path state.

For encapsulations with changing overhead or reachability, use packetization
layer PMTU discovery. MASQUE CONNECT-IP normatively composes with DPLPMTUD and
ECN tunnelling requirements.

## L4 TCP

Use smoltcp for locally terminated TCP only. Packet-native L3 egress bypasses
it completely.

smoltcp is designed for bare-metal real-time systems and lacks some widely
deployed host-stack features. Boreas owns socket-set scaling, load testing, and
any compatibility work needed for hundreds or thousands of concurrent browser
connections. This is a measured risk, not an assumption of host-stack parity.

L4 exposes a byte stream to L7. The upstream transport is re-originated rather
than encapsulating application TCP inside proxy TCP. Resource ownership,
cancellation, half-close behavior, and errors remain explicit at the stream
effect boundary.

## L4 UDP

UDP is a flow table, not a connection-oriented stack.

### NAT behavior

RFC 4787 requirements govern v1:

- REQ-1: endpoint-independent mapping, commonly called full-cone mapping
- REQ-3: no port overloading
- REQ-5: idle mappings live at least two minutes; five minutes is recommended

The mapping key is the internal endpoint, not the remote endpoint. A single
mapping must survive communication with multiple destinations. Failure to
provide endpoint-independent mapping forces impractical relays and breaks
common WebRTC, VoIP, and gaming behavior.

QUIC connection migration is not yet represented. The current flow identity is
endpoint and tuple based while QUIC identity is a connection ID. The v1 scope
decision is tracked in [Verification](verification.md).

### Scheduling

- one expiry structure serves all flows
- never spawn one timer task per mapping
- no shared queue across flows
- every per-flow queue has a fixed capacity
- send is non-blocking and reports `Buffered` or `Dropped`
- count drops with saturating counters
- batch syscalls using `sendmmsg` and `recvmmsg` where available
- use UDP GSO and GRO where platform support and measurement justify them

Backpressure is wrong for live UDP. Waiting converts bounded packet loss into
unbounded latency. Once a per-flow queue is full, drop immediately and expose
the event through telemetry.

The current expiry index uses a `BTreeMap<Instant, Vec<Endpoint>>`. Refreshes
may leave stale entries for one idle window. Replace it with a
generation-indexed timer wheel only if profiling shows refresh churn or 10,000
flow tests make the current cost material.

## Flow Interface Target

```rust
enum Flow {
    Stream(TcpStream),
    Datagram(DatagramFlow),
}

trait DatagramFlow {
    async fn recv(&mut self) -> Option<Bytes>;
    fn try_send(&mut self, message: Bytes) -> SendOutcome;
    fn mtu_budget(&self) -> usize;
}
```

This sketch describes the ownership contract, not a requirement to introduce a
trait before multiple implementations exist. `try_send` never waits.

## Networking Acceptance Gates

- QUIC is impossible to enable below a 1200-byte inner MTU.
- Chained overhead uses checked addition and subtraction.
- Forged PTB messages fail flow validation.
- ECN survives every egress that claims preservation.
- Fragment fuzzing produces no panic, out-of-bounds read, or premature L4 flow.
- STUN confirms endpoint-independent UDP mapping.
- Mapping lifetimes never fall below two minutes.
- 10,000 UDP flows remain inside the measured memory and scheduling budget.
- Congestion yields bounded latency and counted drops, never queue growth.
- Packet-mode egress bypasses smoltcp, verified by a counter.
