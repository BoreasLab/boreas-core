# What each side owes the other

Read this one whatever language you are in. It is the part of the interface that
is easy to get subtly wrong, because most of it fails silently or only under
load.

- [What we promise you](#what-we-promise-you)
- [What you owe us](#what-you-owe-us)
- [Threading](#threading)
- [Ownership and lifetimes](#ownership-and-lifetimes)
- [Blocking](#blocking)
- [Teardown](#teardown)
- [Failure](#failure)
- [The two silent mistakes](#the-two-silent-mistakes)

## What we promise you

**We never unwind into your frame.** A Rust panic reaching an `extern "C"`
frame aborts the process — your whole application, not our call. Every entry
point catches and returns `BOREAS_PANIC` instead. You never need a guard around
a Boreas call for that reason.

**We never take a pointer you gave us past the call it was given in.** Every
string and byte array in `BoreasConfig` is copied before
`boreas_tunnel_start` returns. Free them immediately after if you like.

**We never hand you a pointer to free.** The only thing you own of ours is the
opaque `BoreasTunnel *`, and `boreas_tunnel_free` is the one call that takes it
back. Text comes to you by copy into buffers you supply.

**We call `release` exactly once per vtable**, on the success path and on every
failure path, including a configuration we refuse before building anything. A
context you hand over is always accounted for.

**We bound everything we hold.** Memory in flight is `buffer_slices ×
(mtu + 128)` and nothing else grows without a ceiling you set. Exhaustion is a
counted drop, never an allocation and never a wait.

**We open no files and read no environment variables.** Persistence is a
platform act; see [lifecycle.md](lifecycle.md#the-one-thing-you-persist).

**We do not log.** There is no logger to configure and no output to capture. The
event stream is the whole diagnostic surface, by design — see
[lifecycle.md](lifecycle.md#events).

## What you owe us

Two things, and both are things the core is structurally unable to do.

### 1. A TUN device

Fill in a [`BoreasDevice`](abi.md#boreasdevice): read one IP packet, write one
IP packet, report the MTU.

- **`recv` returns bytes, `0` for "nothing yet", or a negative errno.** There is
  no zero-length IP packet, so `0` is free to mean "ask again" — and it is what
  lets you avoid blocking indefinitely inside our callback. We simply call
  again; nothing is counted.
- **`send` is all-or-nothing.** The unit is the packet. Report a short write as
  an error (`-EIO` will do); there is no correct handling of half an IP packet,
  because the remainder carries no header.
- **`close` must be safe to call while `recv` is running.** It is how we
  release a blocked read at shutdown. It may be `NULL` if your `recv` never
  blocks indefinitely.

#### Set the MTU to the same number twice

Configure your TUN's MTU and set `BoreasConfig.mtu` to that same value. The
tunnel is narrower than the link by whatever your egress encapsulates, and
Boreas answers anything in between with an ICMP Packet Too Big so the sender
learns its path.

If the two numbers disagree, that answering never stops. Watch
`paths_reported`: it should fall to near zero once senders converge, and stays
high if you told the two sides different numbers.

### 2. Sockets that do not re-enter the tunnel

Fill in a [`BoreasBypass`](abi.md#boreasbypass). Every socket Boreas opens for
itself goes through it: the egress's, the resolver's, and any datagram relay's.

`protect` is required rather than defaultable, and that is deliberate. A default
would be "do nothing", which is correct on a desktop whose default route is not
the tunnel and catastrophically wrong everywhere else — see
[below](#the-two-silent-mistakes).

## Threading

**Boreas runs its own threads.** Starting a tunnel creates a multi-threaded
runtime; you do not supply an executor, a loop, or a dispatcher.

### Your callbacks

> **Every callback in both vtables is called from an arbitrary worker thread,
> and not always the same one.**

This is the assumption the library is built on and it is not something we can
check for you. Concretely:

| | |
| --- | --- |
| Which thread | Any of ours. Never yours. Never the one that called `boreas_tunnel_start`. |
| Concurrently with itself | `recv` and `send` are each called from one thread at a time. `protect` may be called concurrently with itself and with either of them. |
| Concurrently with `close` | **Yes** — that is what `close` is for. |
| Attached to a runtime | Not by us. A JVM thread must be attached before it can call Java; the CLR attaches automatically. See the platform pages. |

### Our functions

| Function | May be called while a reader is blocked in `next_event`? | Notes |
| --- | --- | --- |
| `boreas_tunnel_next_event` | one reader at a time | A second concurrent caller queues behind the first rather than racing it. |
| `boreas_tunnel_reload` | **yes** | |
| `boreas_tunnel_authority` | **yes** | |
| `boreas_tunnel_shutdown` | **yes** | This is how you release the reader. |
| `boreas_tunnel_free` | **no** | See [teardown](#teardown). |

The reason `reload` works while a reader is parked is worth knowing, because it
constrains what we can change: the handle holds two disjoint halves, an event
receiver and a command sender, and the tunnel itself lives in a task behind
them. A design that reached the tunnel directly could only promise one call at a
time — and that promise is useless, because the one thread allowed to call would
be parked in `next_event` forever.

## Ownership and lifetimes

| Object | Owner | Freed by | Valid for |
| --- | --- | --- | --- |
| `BoreasConfig` and everything it points at | you | you | the `boreas_tunnel_start` call |
| `BoreasDevice.context` | you | your `release`, called by us | until `release` returns |
| `BoreasBypass.context` | you | your `release`, called by us | until `release` returns |
| `BoreasTunnel *` | you | `boreas_tunnel_free` | until you free it |
| `name` / `rule` buffers | you | you | you allocate, we copy in |
| the certificate and key bytes | you | you | you allocate, we copy in |

**`release` is called after every other callback has returned**, including a
`recv` that was still running when the tunnel stopped. This is refcounted
internally rather than merely sequenced, because a blocking read cannot be
cancelled: a `recv` already inside your callback keeps running after its task is
abandoned, and freeing the context then would be a use-after-free. So the
release waits for it.

The practical consequence: **your `release` may run some time after
`boreas_tunnel_free` returns**, if a `recv` was still in flight. Do not assume
the context is gone the moment `free` returns; put the teardown of anything the
context owns inside `release` itself.

## Blocking

Every Boreas function blocks the calling thread. There is no async variant and
no callback-completion form. That is deliberate: the two consumers are a Kotlin
application with coroutine dispatchers and a C# application with the thread
pool, and both already know how to move a blocking call off the UI thread.

| Function | Blocks for |
| --- | --- |
| `boreas_tunnel_start` | as long as the first connection takes — a DNS lookup, a handshake |
| `boreas_tunnel_next_event` | **indefinitely.** A healthy idle tunnel emits nothing |
| `boreas_tunnel_reload` | proportional to total list length |
| `boreas_tunnel_authority` | a moment |
| `boreas_tunnel_shutdown` | as long as an ordered shutdown takes |
| `boreas_tunnel_free` | up to 250 ms, if a `recv` is still in flight |

The one that matters is `next_event`. Counters are reported only when non-zero,
so a tunnel with nothing to say says nothing — for hours. Give it a thread.

## Teardown

Three steps, in this order:

```
boreas_tunnel_shutdown(tunnel);   /* 1. stops traffic, releases the reader */
join(your_reader_thread);         /* 2. yours */
boreas_tunnel_free(tunnel);       /* 3. reclaims */
```

**Why `shutdown` and `free` are two calls.** A thread blocked in `next_event`
holds a borrow of the handle. Freeing it from another thread at that moment is a
use-after-free, and no amount of internal locking fixes that — the reader is
*inside* the call. So shutdown signals, the reader observes `BOREAS_STOPPED` and
returns, you join it, and only then is the handle unreferenced.

`shutdown` is idempotent and safe from any thread, so a teardown path never has
to remember whether it already ran.

Freeing without stopping still closes sockets — but a reader blocked at that
moment is a use-after-free, so do not rely on it as a shortcut.

**After teardown**, your `close` and then `release` callbacks have run (or will
shortly, if a `recv` was in flight). Only then should you close the TUN file
descriptor or end the Wintun session.

## Failure

**Nothing is half-started.** The configuration is checked in full before a
socket is opened, so a failing `boreas_tunnel_start` leaves nothing to unwind
and nothing to clean up but your own contexts, whose `release` we have already
called.

**A stopped tunnel answers, it does not crash.** Every call on a stopped handle
returns `BOREAS_STOPPED`. The handle remains valid to free.

**A failed call never leaves a partially written out-parameter**, except
`boreas_tunnel_authority` with `BOREAS_BUFFER_TOO_SMALL`, which is the whole
point of that status: the lengths are written so you can size a buffer and
retry.

There is no retry policy to configure and no backoff to tune. A failed dial
fails the flow that needed it; the next flow tries again.

## The two silent mistakes

Both of these produce a tunnel that starts, reports itself healthy, and does the
wrong thing. Neither produces an error. They are worth checking first whenever
something is inexplicable.

### Not protecting a socket

An unprotected socket works perfectly — until the tunnel comes up, at which
point every packet it sends re-enters the tunnel it was serving. The symptom is
a resolver that hangs and a proxy that never connects, and the cause is three
lines away in a different language.

This is why `protect` has no default. If you find yourself writing a `protect`
that returns `0` without doing anything, you are writing the bug.

### Telling the two sides different MTUs

Covered [above](#set-the-mtu-to-the-same-number-twice). The tunnel works; it
just spends its time answering Packet Too Big to senders that never converge.
`paths_reported` is the only symptom.
