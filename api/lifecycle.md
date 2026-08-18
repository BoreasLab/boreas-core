# Running a tunnel

```rust
let mut tunnel = Tunnel::start(config, platform).await?;
while let Some(event) = tunnel.next_event().await { /* ... */ }
tunnel.stop().await?;
```

## Start

`Tunnel::start` builds and spawns everything on the current Tokio runtime: the
datapath, the reactor, the local TCP stack, the session driver, the datagram
relay, and the resolver. It is the only place the whole thing is assembled, and
that is deliberate — those are six components joined by nine channels whose
directions are not guessable.

The configuration is checked in full before a socket is opened. A `StartError`
therefore leaves nothing to unwind:

| Variant | Meaning |
| --- | --- |
| `Config(_)` | The combination would run and filter nothing. See [configuration.md](configuration.md). |
| `Authority(CaError::Material)` | Stored key material was lost or corrupted. Generate afresh and re-prompt. |
| `Authority(_)` | Key generation or signing failed. Not a routine condition. |
| `Egress(_)` | An egress could not be built from its configuration. |
| `Datapath(_)` | The core refused the combination. |
| `Io(kind)` | A socket the tunnel needs could not be opened through your bypass. |

Dropping a `Tunnel` does **not** stop it. The tasks own their own handles and
keep running until the process ends.

## Events

`next_event()` is cancel-safe and returns `None` once the tunnel has stopped.

```rust
enum Event {
    Resolved { name: String, blocked: bool, rule: Option<String> },
    Reloaded { allowed: usize, blocked: usize, inspected: usize },
    Counted(Counters),
}
```

`Resolved` is one per DNS question — this is what a "what did it block" screen
is built from. `blocked` means the answer came from policy without anything
leaving the device.

`Counted` arrives on a fixed interval and reports occurrences **since the
previous one**, so you sum rather than diff. A flood costs one message per
interval rather than one per packet.

| Counter | What a sustained non-zero value means |
| --- | --- |
| `datagrams_dropped` | `Ceilings` too small for this device's traffic. |
| `packets_rejected` | Something upstream is producing malformed packets. |
| `quic_steered` | Expected while intercepting — browsers are being pushed off HTTP/3 so their traffic is inspectable. Should fall as they cache the fallback. |
| `paths_reported` | **A misconfiguration.** Your TUN's MTU is wider than `Link::mtu`. |
| `events_lost` | You are not reading events fast enough. Counted so a gap never reads as quiet. |

A tunnel working normally reports zeroes, so you can surface any non-zero field
without knowing what it means.

## Reload

```rust
let now_in_force = tunnel.reload(&lists);
```

Replaces the rules in force without restarting the tunnel or dropping a
connection. Takes a **whole list set, never a delta**: a rebuild compiles a
fresh index and publishes it in one write, so every query is decided against
exactly one version — the one current when it was admitted. Applying edits
incrementally would make "which rules did this query see" a question with no
answer.

Cost is O(total list length). Returns an `Event::Reloaded` with what is now in
force.

**What reload does not cover:** the egress, the certificate authority, the
resolver, the ceilings, and the intercepted host list are fixed at start. Change
any of those by stopping and starting again.

## Stop

```rust
tunnel.stop().await?;
```

Ordered, and the order is the point: admission closes first, so nothing new is
accepted while what is in flight finishes. When it returns, every socket is
closed and every pooled buffer is back. Always call it — a tunnel that vanished
without one leaves the device's routes pointing at nothing.

## What to persist

**Exactly one thing: the certificate authority's material, and only if you
intercept.** Nothing else. Boreas opens no file and reads no environment;
persistence is a platform act and the platforms disagree about how to do it.

Durable state is what cannot be relearned cheaply and correctly, and by that
test there is one item. A user approved that root through a system dialog,
physically, once, and nothing in the process can reconstitute that approval.

Everything else the core learns — which hosts resisted interception, which
addresses belong to which name, the flow tables — is a cache with a lifetime
already on it, and is deliberately lost on restart. Relearning a demotion costs
a single connection that is spliced instead of intercepted, which no user
perceives. A *stale* one silently withholds filtering from a site that has since
become interceptable, which is worse and is discovered years later.

If you find yourself wanting to persist something else, that is the test to
apply to it.
