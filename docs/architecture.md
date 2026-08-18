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
| L4: SOCKS5, Shadowsocks, VLESS, Hysteria2                 |
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

When egress accepts IP packets and inspection is not required *for this flow*,
forward the packet directly to the tunnel. Do not involve smoltcp. This is the
default path and should cover more than 90 percent of flows.

**Inspection is a per-flow property, not a session switch.** Enabling it
selects only TCP flows to an address an inspected host resolved to, on a port
interception serves; every other flow on the same session — UDP, SSH, IMAP, and
TCP to every host nobody asked to inspect — keeps the fast path. `Inspection` is
that verdict, computed by the datapath against the address index the resolver
fills, and passed to `plan_flow` as a value for the same reason `Backstop` is.
Collapsing it into `FilterPolicy` routed everything through termination, which
is both the opposite of this claim and, for a protocol the local stack does not
listen for, a refused connection.

The core states the destination rather than leaving the shell to infer it: a
transmit carries the `Side` it is bound for, and forwarding is defined as the
crossing from the side the packet arrived on. Without that, the only
destination a shell can name is the interface it already holds, which turns
the fast path into a loopback at the client.

### Local termination

An inspected flow, and every flow under an L4 egress, requires local TCP
termination and re-origination. This avoids TCP-over-TCP because the
application's TCP state machine is not encapsulated in another reliable byte
stream. It also splits a long path into independently controlled congestion
domains with shorter local RTTs.

**Re-origination composes with either egress, and `assemble` is where.** A
session needs two effects — one that carries packets and one that carries
re-originated flows — so assembling a configured `Egress` yields both. A stream
egress *is* the flow effect. A packet egress carries a flow the way it carries
everything else: `TunnelledDialer` opens the connection with the host's own TCP
stack, deliberately *not* excluded from the tunnel, so its packets enter the TUN
and take the fast path out. A reserved range of local source ports
(`OriginationPorts`) is excluded from inspection, which is what stops a
re-originated connection from being terminated and re-originated forever; the
dialer and the classifier read one value, so they cannot disagree.

### L4 datagrams

Under a flow egress a UDP datagram cannot be forwarded as a packet, so the
datapath queues it with the target the client addressed — a datagram is
`{ source, target, payload }`, never payload alone — and `run_relay` drives it
through the egress's `DatagramSink`. One association per client mapping, which
is what makes RFC 4787's endpoint-independent mapping a property of the
structure: a shared association could not attribute a reply to the client that
earned it. Replies re-enter the core as synthesized IP packets.

## Pure Planning Model

Egress path properties are a live runtime value:

```rust
struct PathProperties {
    datagram_fidelity: DatagramFidelity,
    overhead_bytes: u16,
    max_datagram_size: Option<u16>,
    preserves_ecn: bool,
    nat_behavior: NatBehavior,
}
```

There is deliberately no `accepts` field: the accepted layer is a property of
the `Egress` variant, so a claim can no longer disagree with the thing it
describes.

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

## Memory

Every payload the core holds is on one budget. `BufferPool` owns
`capacity x slice_size` bytes and nothing more; a packet that does not fit it is
a counted drop, never a wait and never an allocation. Four producers draw on it
— forwarded packets, queued datagrams, captured termination packets, and
synthesized DNS answers — and the local TCP stack's own device queues do too, so
a slow reactor cannot grow `smoltcp`'s outbound queue without limit: exhaustion
there is expressed as no transmit token, which is the backpressure a full NIC
ring already applies.

GotaTun keeps a second pool for the buffers `Tunn` owns while it encrypts and
decrypts. Two pools rather than one because the two allocators' buffer types and
lifetimes differ; one per-packet heap allocation on either would breach the
engineering plan's budget.

## Current Code

- `src/lib.rs` implements path composition, flow planning, and actions.
- `src/packet.rs` parses IPv4 and IPv6 without allocating and quarantines
  fragments before L4.
- `src/udp.rs` implements endpoint-independent mapping state and bounded
  per-flow datagram buffering.
- `src/origin.rs` assembles a configured egress into the packet effect and the
  flow effect a session runs on.
- `src/relay.rs` drives the L4 datagram associations a flow egress needs.

The current code is a foundation, not the complete diagram. Missing work is
tracked in [Delivery](delivery.md).