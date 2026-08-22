# Integrating Boreas

Boreas is a filtering VPN core. It takes raw IP packets from a platform TUN
device, decides what to do with them, and sends them out by whatever egress you
configure.

This folder is the whole contract. It is self-contained: the `docs/` folder next
to it is internal design material and changes without notice.

## Start here

**Boreas is consumed through a C ABI.** The two applications it exists for are
written in Kotlin and C#, so the C boundary is the interface — not a wrapper
over a "real" Rust one. The Rust API is a third consumer with the same standing
as the other two.

| You are writing | Start at |
| --- | --- |
| **Kotlin / Java** (Android) | [android.md](android.md) |
| **C# / .NET** (Windows) | [windows.md](windows.md) |
| C or C++ | [abi.md](abi.md) |
| Rust | [rust.md](rust.md) |

| Then read | What it answers |
| --- | --- |
| [obligations.md](obligations.md) | **What each side owes the other.** Threading, ownership, blocking, failure. Read this one whatever language you are in. |
| [abi.md](abi.md) | Every type, every function, every status code, and the exact width of every field |
| [configuration.md](configuration.md) | Every knob, its default, and its constraint |
| [lifecycle.md](lifecycle.md) | Start, observe, reload, stop — and what to persist |
| [stability.md](stability.md) | What we promise not to break |

## The shape of it

Your application does five things. Nothing else is required and nothing else is
supported.

1. **Supply what only a platform can.** A TUN device and a way to keep our own
   sockets out of the tunnel. Two vtables of function pointers.
2. **Describe the tunnel.** One `BoreasConfig`.
3. **Start it**, and read events on a thread of your own until you stop it.
4. **Keep one thing.** The certificate authority's material — and only if you
   intercept.
5. **Stop, join, free.** In that order, and they are three separate steps for a
   reason: see [obligations.md](obligations.md#teardown).

```c
BoreasTunnel *tunnel = NULL;
if (boreas_tunnel_start(&config, &device, &bypass, &tunnel)) {
    /* nothing was allocated; both release callbacks already ran */
}

/* on a thread of your own */
BoreasEvent event;
char name[256], rule[256];
while (!boreas_tunnel_next_event(tunnel, &event, name, sizeof name,
                                 rule, sizeof rule)) {
    /* ... */
}

/* from anywhere, at any time */
boreas_tunnel_shutdown(tunnel);   /* releases the reader */
join(reader_thread);              /* yours */
boreas_tunnel_free(tunnel);
```

That is the whole surface: six functions, two vtables, one config struct.

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
far up to go.

| Tier | What it does | What it costs |
| --- | --- | --- |
| **Names** | Answers DNS locally against your lists; refuses blocked names | Nothing visible. No certificates, no termination. |
| **Requests** | Adds: terminates TLS for named hosts, filters the requests inside | A root certificate the user must install |
| **Documents** | Adds: rewrites HTML bodies as they stream | Memory per response, bounded by a budget |

Most products want **Names** everywhere and **Requests** for a short,
user-visible allowlist. Interception forges certificates, so the set of hosts it
applies to should be one a person can read.
