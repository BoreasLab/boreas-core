# Configuration reference

One `TunnelConfig` describes a tunnel completely. Five independent choices.

```rust
TunnelConfig { egress, resolver, filtering, link, ceilings }
```

The configuration is checked in full before a socket is opened, so a refusal
leaves nothing half-started. Every `ConfigError` names a combination that would
**run and filter nothing** — those are the dangerous ones, because such a tunnel
reports itself healthy.

---

## `egress` — where traffic leaves by

The variant decides the layer, and the layer decides everything downstream:
whether flows are terminated locally, whether datagrams need a relay, whether
QUIC survives or is steered to HTTP/2. You never state a layer.

| Variant | Carries | Datagrams | Notes |
| --- | --- | --- | --- |
| `Direct { nat_behavior }` | flows | native | Out by your own routes. The ordinary content-blocker configuration. |
| `WireGuard { peer, config }` | IP packets | native | `peer` is the socket address; `config` is the cryptographic peer. A peer that roams keeps its keys and changes its address. |
| `Socks5(config)` | flows | native, via UDP ASSOCIATE | |
| `Shadowsocks(config)` | flows | native, SIP022 packet format | All three 2022 methods. |
| `Hysteria2(config)` | flows | native, QUIC datagrams | Only if the server answers `Hysteria-UDP: true`; if it does not, datagram flows fail rather than disappearing into a relay that discards them. |
| `Vless { config, transport }` | flows | **emulated** | See below. |

**Native versus emulated is a real distinction and it decides QUIC.** A native
egress carries a client datagram as a datagram — unreliable and unordered, as it
was — so QUIC passes through. VLESS frames datagrams over a reliable ordered
stream: boundaries survive exactly, but a lost packet is retransmitted and
everything behind it waits. That is fine for DNS and wrong for QUIC, so QUIC
flows on a VLESS egress are steered to HTTP/2 while UDP flows are carried.

**`nat_behavior`** appears on most of these and is not something Boreas can
measure. It says what the NAT in front of you does to a mapping, and it is what
lets the planner decide whether a QUIC flow can survive. If unsure,
`AddressAndPortDependent` is the conservative answer: it never claims more than
is true, at the cost of steering some flows that would have worked.

**Where datagrams are steered rather than carried, sites still load.** A QUIC
attempt is refused so the browser falls back to HTTP/2 within its own race
window; the user sees the page, and you see it in
`Counters::quic_steered`.

### VLESS transports

VLESS has no framing and no encryption of its own; everything that makes it
survive a hostile network lives underneath. Pick one:

| `VlessTransport` | Shape |
| --- | --- |
| `Plain { server }` | TCP in the clear. Only correct under something that already provides confidentiality. |
| `Tls(TlsConfig)` | TLS over TCP, wearing Chrome's hello. |
| `WebSocket { tls, settings }` | A WebSocket over TLS. What a CDN-fronted deployment looks like to middleboxes. |
| `Grpc { tls, settings }` | gRPC over HTTP/2 over TLS. |

`TlsConfig::extra_roots` accepts DER trust anchors **in addition to** the
bundled Mozilla set, for a self-hosted server behind a private CA. There is
deliberately no "skip verification" switch: that is the same feature with no way
to tell a configured exception from an attack.

---

## `resolver` — how names are answered

| Variant | Meaning |
| --- | --- |
| `Passthrough` | Your stack resolves; queries cross the tunnel untouched. |
| `Local { upstream }` | Answered here against your lists, forwarding what policy allows. |

| `Upstream` | Fields |
| --- | --- |
| `Do53 { resolver }` | Cleartext. Readable by anything on the path. |
| `Dot { resolver, server_name }` | DNS over TLS. `server_name` is what the certificate must carry, which is not the address it lives at. |
| `Doh { url, resolver }` | DNS over HTTPS. |
| `Doq { resolver, server_name }` | DNS over QUIC. |

All four verify against the bundled Mozilla anchors rather than the platform
store, deliberately: the set your resolver is trusted against should not be one
a device owner or an MDM profile can widen.

> **`Passthrough` plus filtering is refused** (`ConfigError::NothingToFilter`).
> On the packet fast path, a flow is selected for inspection *because a DNS
> answer named its address*. A tunnel that never sees a question can never
> select one — it would carry traffic, filter nothing, and look configured.

---

## `filtering` — what is done to what crosses

The tiers are a chain and the nesting **is** the chain.

```rust
Filtering {
    lists: Vec<String>,                 // tier 1: names
    interception: Option<Interception>, // tier 2 lives here
}

Interception {
    hosts: Vec<String>,
    trust: Trust,
    documents: Option<Documents>,       // tier 3 lives here
}
```

You cannot ask for document rewriting without interception, or interception
without an authority — those are not representable, so nothing has to check.

| Field | Meaning |
| --- | --- |
| `lists` | Filter-list text, in the syntax [AdGuard and uBlock use](https://adguard.com/kb/general/ad-filtering/create-own-filters/). You fetch and store these; Boreas compiles them and keeps none. Malformed lines are counted and skipped — one bad line in fifty thousand must not cost a user their rule set. |
| `hosts` | The hosts to intercept. **An allowlist, never a pattern.** Interception forges a certificate, and the set of hosts that happens to should be one a user can read. |
| `trust` | `Trust::Generate` on first run, `Trust::Restore(material)` after. See [platform.md](platform.md#3-installing-the-root-certificate). |
| `documents.budget` | Memory one response may occupy while being rewritten. A document is transformed as it arrives rather than buffered whole; this is what makes that a bound rather than an intention. Default 2 MiB. |

Refusals: empty `hosts` with interception on is `NoHostsToIntercept` — forging
certificates for the empty set is the name tier with extra machinery. A host
that is not a name is `NotAHost(text)`, carrying the offending text so you can
tell the user which line to fix.

---

## `link` — your own interface

| Field | Default | Meaning |
| --- | --- | --- |
| `mtu` | 1280 | The MTU configured on your TUN. Set both to the same number; see [platform.md](platform.md#set-the-mtu-to-the-same-number-twice). Minimum 1280, the IPv6 floor. |
| `origination_ports` | 45000–45999 | Local ports reserved for re-originated connections, and therefore never themselves inspected. Without this reservation, a re-originated connection would be selected for inspection and re-originated again, forever. |

---

## `ceilings` — how much this tunnel may hold

Every number here is about the device, which is why you set them.
`Ceilings::default()` is sized for a phone, because that is where being wrong
gets the process killed. Raise them on a desktop.

| Field | Default | What it bounds |
| --- | --- | --- |
| `buffer_slices` | 2048 | Payload buffers, shared by everything in flight: forwarded packets, queued datagrams, terminated segments, synthesized replies. `slices × (mtu + 128)` is the **whole** traffic memory budget. Exhaustion is a counted drop, never a wait or an allocation. |
| `datagrams_per_flow` | 32 | Queued datagrams before one flow starts dropping. Per flow, so one noisy source cannot starve another. |
| `terminated_connections` | 512 | Live locally-terminated connections. Also sizes the forged-certificate cache. |
| `associations` | 256 | Datagram associations through a proxy egress. |
| `inspected_addresses` | 1024 | Addresses remembered as belonging to an intercepted host. |
| `pending_reassemblies` | 64 | Fragmented packets held awaiting the rest of themselves. |

Sustained non-zero `Counters::datagrams_dropped` means these are too small for
this device's traffic. See [lifecycle.md](lifecycle.md#events).
