# Running a tunnel

Start, observe, reload, stop — and the one thing you keep.

```
boreas_tunnel_start(...)          once
boreas_tunnel_next_event(...)     in a loop, on a thread of its own
boreas_tunnel_reload(...)         whenever your lists change
boreas_tunnel_shutdown(...)       once
join(reader)
boreas_tunnel_free(...)           once
```

Signatures are in [abi.md](abi.md#functions); threading and ownership rules are
in [obligations.md](obligations.md).

## Start

`boreas_tunnel_start` builds and spawns everything: the datapath, the reactor,
the local TCP stack, the session driver, the datagram relay, and the resolver.
It is the only place the whole thing is assembled.

**The configuration is checked in full before a socket is opened**, so a failure
leaves nothing to unwind. See [what produces
`BOREAS_CONFIG`](abi.md#what-produces-boreas_config) for which field is at
fault.

Whatever it returns, both your `release` callbacks have run.

It blocks for as long as the first connection takes. Call it off your UI thread.

## Events

`boreas_tunnel_next_event` blocks until there is something to say, and returns
`BOREAS_STOPPED` once nothing more can arrive — which is the normal way the loop
ends.

**A healthy idle tunnel says nothing.** Counters are reported only when
non-zero, so silence means "nothing went wrong", not "not running". This call
can block for hours. Give it a dedicated thread and do not treat a long silence
as a hang.

| `kind` | When | Meaningful fields |
| --- | --- | --- |
| `RESOLVED` | one per DNS question | `blocked`, plus your `name` and `rule` buffers |
| `RELOADED` | after a reload | `allowed`, `blocked_rules`, `inspected` |
| `COUNTED` | on a fixed interval, when something is non-zero | `counters` |

`RESOLVED` is what a "what did it block" screen is built from. `blocked` means
the answer came from policy without anything leaving the device.

`COUNTED` reports occurrences **since the previous one**, so you sum rather than
diff. A flood costs one message per interval rather than one per packet.

### Counters

A tunnel working normally reports zeroes, so you can surface any non-zero field
without knowing what it means.

| Counter | What a sustained non-zero value means |
| --- | --- |
| `datagrams_dropped` | Ceilings too small for this device's traffic. Raise `buffer_slices` or `datagrams_per_flow`. |
| `packets_rejected` | Something upstream is producing malformed packets. |
| `quic_steered` | **Expected while intercepting.** Browsers are being pushed off HTTP/3 so their traffic is inspectable. Should fall as they cache the fallback. |
| `paths_reported` | **A misconfiguration.** Your TUN's MTU is wider than the `mtu` you passed. See [obligations.md](obligations.md#set-the-mtu-to-the-same-number-twice). |
| `events_lost` | You are not reading events fast enough. Counted so a gap never reads as quiet. |
| `tasks_panicked` | **A defect in Boreas.** Every other counter here is something a peer, a path, or a ceiling caused; this one is a task that ended by panicking, which no input is supposed to be able to do. One means a connection died for a reason nothing else records. Sustained means a subsystem fails every time it is used. Please report it with what the device was doing. |

### Truncation

`name_len` and `rule_len` are the **full** lengths of the text, before
truncation. Larger than the capacity you passed means it did not all fit; the
buffer still holds a valid, NUL-terminated, UTF-8-boundary-aligned prefix.

256 bytes is comfortable for a hostname (DNS caps a name at 255) and generous
for a rule. Nothing is lost that matters if you size them that way.

## Reload

Replaces the rules in force without restarting the tunnel or dropping a
connection.

**A whole list set, never a delta.** A rebuild compiles a fresh index and
publishes it in one write, so every query is decided against exactly one
version — the one current when it was admitted. Applying edits incrementally
would make "which rules did this query see" a question with no answer.

Cost is proportional to total list length. Safe to call while a reader is
blocked in `next_event`, which is the case that matters, because that reader may
be blocked for a very long time.

> **A reload is reported twice.** Once as the `RELOADED` written through the
> call's own out-parameter, and once as a `RELOADED` on the event stream, which
> is how a reader parked in `next_event` learns that the rules changed under it.
> They describe the same reload. Drive your UI from one of the two — the event
> stream is the better choice, because it is also where a reload triggered from
> somewhere else in your application arrives.

**What reload does not cover:** the egress, the certificate authority, the
resolver, the ceilings, and the intercepted host list are fixed at start. Change
any of those by stopping and starting again.

## Stop

Three steps, in order. [obligations.md](obligations.md#teardown) explains why
they are three.

```
boreas_tunnel_shutdown(tunnel);   /* stops traffic; the reader gets BOREAS_STOPPED */
join(reader_thread);              /* yours */
boreas_tunnel_free(tunnel);       /* reclaims */
```

When `shutdown` returns, every socket is closed and every pooled buffer is back.
It is idempotent and safe from any thread.

Close your TUN file descriptor, or end your Wintun session, **after** this —
your `close` and `release` callbacks run as part of it.

## The one thing you persist

**Exactly one: the certificate authority's material, and only if you
intercept.** Nothing else. Boreas opens no file and reads no environment
variable; persistence is a platform act and the platforms disagree about how to
do it.

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

### Reading it out

`boreas_tunnel_authority` twice: once with both capacities zero to learn the
lengths, then again with buffers that size. Both lengths zero means this tunnel
does not intercept — an answer, not a failure.

- **The certificate is public**, DER. It goes to the platform's trust installer.
- **The keys are secret.** Android Keystore, or DPAPI. Treat them as you would a
  password. They are opaque and self-describing; you never look inside.

Store and offer unconditionally, every launch. Storing what you just restored is
a no-op write, and offering a root the user already trusts shows no dialog — so
there is no branch here to get wrong.

### Handing it back

Next launch, pass both through `root_certificate` / `authority_keys`. Both or
neither: supplying one is `BOREAS_CONFIG`.

Two failures are possible and they mean different things:

| | |
| --- | --- |
| `BOREAS_AUTHORITY` where the blob is malformed | Storage lost or corrupted the key material. |
| `BOREAS_AUTHORITY` where both halves parse | The two are **not two halves of the same authority**. They live in different stores, so one can be written without the other: an interrupted rotation, a restored backup, two slots keyed differently. |

The second is the one worth understanding. Nothing downstream can detect it —
every parse succeeds, the session starts, and it mints leaves the installed root
cannot vouch for, so the user sees a certificate error on every site and has
nothing to act on. Boreas checks the root's own signature against the stored key
at startup so it becomes one recoverable error instead.

Both recover the same way: generate a fresh authority (pass `NULL` for both) and
ask the user to trust it again. Boreas will **not** silently generate a
replacement, because a device whose store still trusts the old root would then
intercept nothing while reporting itself healthy.

### Known limitation

The private key lives in process memory while the tunnel runs, so a rooted or
compromised device can extract it. A hardware-backed signer — the key never
leaving a TEE — is the right destination, and is why the key material is opaque:
adding one will not change this interface.
