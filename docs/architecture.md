# Architecture

## System Shape

```text
[ Android VpnService fd | Windows Wintun ]
                    |
                 raw IP
                    v
+ L3 -------------------------------------------------------+
| parse | reassemble | MTU budget | ICMP/PTB | ECN          |
+-----------+----------------+------------------------------+
            | TCP            | UDP             | ICMP
            v                v                 v
         smoltcp       flow table + NAT    echo / PTB
            | Stream         | DatagramFlow
            +----------------+------------------------------+
                             v
+ L7 classifier and policy --------------------------------+
| DNS | block | splice | MITM h1/h2 | protocol steering     |
+-----------------------------------------------------------+
                             |
                             v
+ Capability-typed egress ---------------------------------+
| L3: WireGuard, MASQUE CONNECT-IP                          |
| L4: SOCKS5, Shadowsocks, VLESS, Hysteria2, TUIC           |
+-----------------------------------------------------------+
```

## Layer Contract

Platform adapters own OS handles and exchange raw IP packets with L3. L3 owns
packet validity, fragmentation, MTU, ECN, and ICMP. L4 converts transport state
into a `Stream` or `DatagramFlow`. L7 never receives a packet and never branches
on the transport implementation behind either type.

The application core computes decisions and state transitions. The runtime
shell interprets those decisions by reading or writing devices and sockets,
advancing clocks, spawning bounded work, and emitting telemetry. Pure code must
not acquire resources or hide effects behind policy interfaces.

## Datapath Modes

### Packet fast path

When egress accepts IP packets and inspection is not required, forward the
packet directly to the tunnel. Do not involve smoltcp. This is the default path
and should cover more than 90 percent of flows through splice or direct packet
forwarding.

The core states the destination rather than leaving the shell to infer it: a
transmit carries the `Side` it is bound for, and forwarding is defined as the
crossing from the side the packet arrived on. Without that, the only
destination a shell can name is the interface it already holds, which turns
the fast path into a loopback at the client.

### Local termination

L4 egress requires local TCP termination and re-origination. This avoids
TCP-over-TCP because the application's TCP state machine is not encapsulated in
another reliable byte stream. It also splits a long path into independently
controlled congestion domains with shorter local RTTs.

## Pure Planning Model

Egress capability is a live runtime value:

```rust
struct EgressCapabilities {
    accepts: Accepts,
    datagram_fidelity: DatagramFidelity,
    overhead_bytes: u16,
    max_datagram_size: Option<u16>,
    preserves_ecn: bool,
}
```

Chaining is a weakest-link operation:

- all members must accept the same layer
- datagram fidelity is the minimum in the chain
- overhead is the checked sum
- maximum datagram size is the minimum known ceiling
- ECN is preserved only if every member preserves it

The flow planner derives:

- packet fast path or local termination
- inner MTU after egress overhead
- QUIC pass-through or HTTP/2 steering with an explicit reason

Ingress parsing then yields a closed action:

- reassemble fragment
- forward packet
- open stream
- open datagram
- handle ICMP
- drop unsupported transport

This is an algebraic data type: each variant is one valid state, so callers
cannot accidentally combine packet forwarding with local stream termination.

## Classifier Dispositions

1. DNS: resolve, filter, and apply ECH policy.
2. Block: return an RST or protocol-appropriate null response.
3. Splice: copy bidirectionally without payload transformation.
4. MITM: terminate only eligible Chromium or WebView traffic for unpinned,
   HTML-serving hosts.

HTTP/3 and MITM are mutually exclusive for the Android target. Inspection
policy therefore changes connection discovery before a connection starts; it
never translates a live exchange between HTTP versions.

## Concurrency and Ownership

- one owner coordinates each mutable flow state machine
- no lock or blocking guard may cross an await point
- queues, concurrency, retries, and materialization are bounded
- cancellation remains structured under the owning flow or connection
- UDP uses one central expiry structure, not one task per flow
- independent HTTP streams retain independent state and flow control
- effect boundaries own logs, traces, counters, resource cleanup, and retries

## Current Code

- `src/lib.rs` implements capability composition, flow planning, and actions.
- `src/packet.rs` parses IPv4 and IPv6 without allocating and quarantines
  fragments before L4.
- `src/udp.rs` implements endpoint-independent mapping state and bounded
  per-flow datagram buffering.

The current code is a foundation, not the complete diagram. Missing work is
tracked in [Delivery](delivery.md).