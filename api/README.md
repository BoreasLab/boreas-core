# Integrating Boreas

Boreas is a filtering VPN core. It takes raw IP packets from a platform TUN
device, decides what to do with them, and sends them out by whatever egress you
configure. This folder is everything you need to embed it. It is self-contained
— the `docs/` folder next to it is internal design material and will change
without notice.

| Document | What it answers |
| --- | --- |
| [platform.md](platform.md) | What your app must supply, and what happens when it doesn't |
| [configuration.md](configuration.md) | Every knob, its default, and its constraint |
| [lifecycle.md](lifecycle.md) | Start, observe, reload, stop — and what to persist |
| [stability.md](stability.md) | What we promise not to break |

## The shape of it

Your application does four things. Nothing else is required and nothing else is
supported.

1. **Supply what only a platform can.** A TUN device and sockets that do not
   re-enter the tunnel.
2. **Describe the tunnel.** One configuration value.
3. **Run it**, and read events until you stop it.
4. **Keep one thing.** The certificate authority's material — and only if you
   intercept.

```rust
use boreas_core::api::*;

let tunnel = Tunnel::start(
    TunnelConfig {
        egress: Egress::Direct { nat_behavior: NatBehavior::AddressAndPortDependent },
        resolver: Resolver::Local {
            upstream: Upstream::Dot {
                resolver: "9.9.9.9:853".parse()?,
                server_name: "dns.quad9.net".to_owned(),
            },
        },
        filtering: Filtering {
            lists: vec![easylist_text],
            interception: Some(Interception {
                hosts: vec!["news.example.com".to_owned()],
                trust: stored_material.map_or(Trust::Generate, Trust::Restore),
                documents: Some(Documents { budget: StreamBudget::default() }),
            }),
        },
        link: Link { mtu: Mtu::new(1400)?, ..Link::default() },
        ceilings: Ceilings::default(),
    },
    Platform { device: tun, bypass: protected_sockets },
).await?;

if let Some(material) = tunnel.authority() {
    keystore.write(material.keys().as_bytes());       // secret
    trust_store.offer(material.root_certificate());   // public
}
```

Store and offer unconditionally in both branches. Storing what you just restored
is a no-op write, and offering a root the user already trusts shows no dialog —
so there is no branch here to get wrong.

## Not writing Rust?

Read [platform.md](platform.md#if-your-application-is-not-written-in-rust)
first. The `ffi/` crate carries a C ABI over everything on this page, and it
is the supported way in from Kotlin, Java, C#, or C.

## What you cannot configure, and why

Boreas exposes **policy**, not mechanism. You set what your product and your
user decide, and what depends on the device you are running on. You do not set:

- **The TLS or HTTP/2 fingerprint.** Looking exactly like Chrome on the wire is
  the feature. A knob there is a knob that breaks it.
- **Dial and handshake deadlines.** These come from what mobility measurements
  say — a client that roams between Wi-Fi and cellular loses paths silently, and
  the numbers are chosen so a dead path is noticed in seconds. A longer value
  reintroduces the leak they exist to close.
- **NAT mapping lifetime**, which has an RFC 4787 floor beneath which a live
  flow becomes a black hole.
- **Buffer slice size**, derived from your link MTU because a slice must hold
  the largest thing the core ever forwards.

You *do* set every ceiling that depends on the device, because a phone and a
desktop differ by an order of magnitude there and the core cannot tell which it
is on. See [configuration.md](configuration.md#ceilings).

## The three tiers

Filtering escalates, and each tier includes the ones below it. You choose how
far up to go; the type makes the tiers nest, so you cannot ask for a higher one
without the ones beneath.

| Tier | What it does | What it costs |
| --- | --- | --- |
| **Names** | Answers DNS locally against your lists; refuses blocked names | Nothing visible. No certificates, no termination. |
| **Requests** | Adds: terminates TLS for named hosts, filters the requests inside | A root certificate the user must install |
| **Documents** | Adds: rewrites HTML bodies as they stream | Memory per response, bounded by a budget you set |

Most products want **Names** everywhere and **Requests** for a short,
user-visible allowlist. Interception forges certificates, so the set of hosts it
applies to should be one a person can read.
