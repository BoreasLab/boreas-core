# The C ABI

Everything Boreas exposes, at the width it crosses at. If something is not on
this page it is not part of the interface.

The C declarations also ship as `ffi/include/boreas.h`. This page is the
normative description; the header is the same content in a form a compiler can
read. Their layouts are checked against the Rust types by a test that fails the
build if they drift, **and the header asserts the same layouts from the C side
when you compile it** — so a toolchain whose flags would move a field fails
your build with a message rather than reading the wrong bytes at run time.

- **Library name.** `libboreas.so` (Android), `boreas.dll` (Windows),
  `libboreas.a` if you would rather link statically.
- **Version check.** The header defines `BOREAS_ABI_VERSION` and the library
  exports `uint32_t boreas_abi_version(void)`. Compare them once at startup and
  refuse to run if they differ: a stale library beside a newer header reads
  fields at the wrong offsets, and this is the only cheap moment to notice.
- **Check every return.** Every function is declared with a `nodiscard`
  equivalent, so a dropped status is a compiler warning.
- **Calling convention.** C. On x86-64 and ARM64 there is only one, so you do
  not need to name it.
- **Symbol prefix.** `boreas_`. Nothing else is exported.
- **No global state, no initialiser.** There is nothing to call before
  `boreas_tunnel_start` and nothing to call after `boreas_tunnel_free`. Several
  tunnels may run at once in one process; they share nothing.

## Contents

- [Type widths](#type-widths)
- [`BoreasStatus`](#boreasstatus)
- [`BoreasDevice`](#boreasdevice) — you implement
- [`BoreasBypass`](#boreasbypass) — you implement
- [`BoreasConfig`](#boreasconfig) — you fill in
- [`BoreasEvent`](#boreasevent) — we fill in
- [Functions](#functions)
- [What the ABI does not expose yet](#what-the-abi-does-not-expose-yet)

## Type widths

Every scalar that crosses, and what to declare it as. **Get these wrong and the
struct after them is garbage**, silently — the mistakes here do not produce a
link error, they produce a field read from the middle of another field.

| C | Rust | C# | Kotlin (JNA) | Notes |
| --- | --- | --- | --- | --- |
| `uint8_t` | `u8` | `byte` | `Byte` | |
| `uint16_t` | `u16` | `ushort` | `Short` | |
| `int32_t` | `i32` | `int` | `Int` | |
| `uint64_t` | `u64` | `ulong` | `Long` | |
| `int64_t` | `i64` | `long` | `Long` | |
| `size_t` | `usize` | `nuint` / `UIntPtr` | `NativeLong`¹ | Pointer-width. Never `uint`. |
| `intptr_t` | `isize` | `nint` / `IntPtr` | `NativeLong`¹ | Pointer-width, signed. |
| `bool` (`_Bool`) | `bool` | **see below** | `Byte` | One byte. |
| `void *` | `*mut c_void` | `IntPtr` | `Pointer` | |
| `const char *` | `*const c_char` | `IntPtr`² | `Pointer` | NUL-terminated **UTF-8**. |
| enum | `#[repr(i32)]` | `enum : int` | `Int` | Always four bytes, signed. |

¹ JNA's `NativeLong` is pointer-width only where the platform's `long` is;
prefer `com.sun.jna.Native.SIZE_T_SIZE`-aware types, or use `Long` and target
64-bit only (Android's 32-bit ABIs are the exception — see
[android.md](android.md#abis)).

² Not `string`. See [strings](#strings).

### `bool` is the one that will bite you

A C# `bool` inside a struct marshals as a **four-byte** Windows `BOOL` by
default. Rust's `bool` and C's `_Bool` are **one byte**. Microsoft's own interop
guidance calls this out:

> Booleans are easy to mess up. By default, a .NET `bool` is marshalled to a
> Windows `BOOL`, where it's a 4-byte value. However, the `_Bool`, and `bool`
> types in C and C++ are a *single* byte.
>
> — [Native interoperability best practices](https://learn.microsoft.com/en-us/dotnet/standard/native-interop/best-practices)

Declare every `bool` field as `[MarshalAs(UnmanagedType.U1)] public bool x;`, or
as a plain `byte`. A bare `bool` shifts every field after it by three bytes.

Kotlin has no automatic marshalling to get wrong here — declare `Byte` and
compare against `0`.

### Strings

Every string crossing this ABI is **NUL-terminated UTF-8**, and every one of
them is **borrowed for the duration of the call**. We copy what we need before
returning; you may free your buffer as soon as the call returns.

Boreas never hands you a string it owns. Where we have text for you — an event's
name and rule — you supply the buffer and a capacity, and we copy into it with a
terminator, truncating on a UTF-8 character boundary if it does not fit. The
struct then tells you the length the text *would* have needed, so a truncation
is visible rather than silent.

A string that is not valid UTF-8 fails the call with `BOREAS_NOT_UTF8` rather
than being interpreted.

## `BoreasStatus`

```c
typedef enum { /* ... */ } BoreasStatus;   /* int32_t */
```

Zero is success, so `if (boreas_...(...)) { /* failed */ }` reads correctly.
Every function returns one; nothing signals failure any other way, and nothing
sets `errno`.

| Value | Name | Means | What to do |
| ---: | --- | --- | --- |
| 0 | `BOREAS_OK` | Succeeded; any out-parameter is written. | — |
| 1 | `BOREAS_NULL_ARGUMENT` | A required pointer was null. | Fix your call. Always your bug. |
| 2 | `BOREAS_NOT_UTF8` | A string argument was not valid UTF-8. | Fix the encoding. |
| 3 | `BOREAS_CONFIG` | The configuration describes a tunnel that cannot exist. | See [the table below](#what-produces-boreas_config). Nothing was built. |
| 4 | `BOREAS_AUTHORITY` | Stored CA material was lost, corrupted, or is not two halves of one authority. | Generate afresh and re-prompt the user. See [lifecycle.md](lifecycle.md#the-one-thing-you-persist). |
| 5 | `BOREAS_EGRESS` | An egress could not be built from its configuration. | Check keys and endpoint. |
| 6 | `BOREAS_TERMINATION` | `terminated_connections` cannot hold a listening backlog for every inspected port. | Raise it to at least 128. |
| 7 | `BOREAS_DATAPATH` | The datapath refused the combination it was handed. | Report it; this is close to a defect. |
| 8 | `BOREAS_IO` | A socket the tunnel needs could not be opened through your bypass, or shutdown reported an I/O failure. | Check the bypass. |
| 9 | `BOREAS_STOPPED` | The tunnel has stopped. | Expected during teardown. The handle is still valid to free. |
| 10 | `BOREAS_BUFFER_TOO_SMALL` | An output buffer was too small. | The length out-parameter says how large. Retry. |
| 11 | `BOREAS_PANIC` | **A defect in Boreas.** A panic was caught at the boundary. | Free the handle, do not retry on it, and report it. |
| 12 | `BOREAS_UNRECOGNISED` | A failure this header predates. | Update the header. |

**`BOREAS_PANIC` cannot reach you as a crash.** A Rust panic that escaped into
an `extern "C"` frame would abort your whole application — since Rust 1.81 that
abort is defined rather than undefined behaviour, which makes it predictable and
no less fatal. Every entry point catches instead. It should never happen; if it
does, the tunnel's internal state is whatever the failed call left behind, so
the only supported next call on that handle is `boreas_tunnel_free`.

### What produces `BOREAS_CONFIG`

So you can tell which of your fields is wrong without bisecting.

| Cause |
| --- |
| `device.recv` or `device.send` is `NULL` |
| `device.mtu` below 1280, the IPv6 minimum |
| `bypass.protect` is `NULL` — deliberately not defaultable, see [obligations.md](obligations.md#2-sockets-that-do-not-re-enter-the-tunnel) |
| `config.mtu` below 1280 |
| `wireguard.endpoint` is not `host:port` with a numeric address |
| `resolver` is non-`NULL` and not `host:port` with a numeric address |
| exactly one of `root_certificate` / `authority_keys` supplied — both or neither |
| filtering configured with `resolver == NULL` (see [configuration.md](configuration.md#resolver)) |
| interception configured with an empty host list |
| an intercepted host that is not a hostname |

## `BoreasDevice`

Your TUN. **You implement this.**

```c
typedef struct {
  void *context;
  intptr_t (*recv)(void *context, uint8_t *buf, size_t cap);
  intptr_t (*send)(void *context, const uint8_t *buf, size_t len);
  void (*close)(void *context);
  void (*release)(void *context);
  uint16_t mtu;
} BoreasDevice;
```

| Field | Required | Contract |
| --- | --- | --- |
| `context` | may be `NULL` | Passed back to every call, untouched. Yours. |
| `recv` | **yes** | Reads one IP packet into `buf` (capacity `cap`). Returns the byte count, **`0` for "nothing yet, ask again"**, or a negative errno. |
| `send` | **yes** | Writes one IP packet, whole. Returns `0`, or a negative errno. A short write is an **error**, not a success with a count. |
| `close` | may be `NULL` | Makes an in-flight `recv` return promptly. Called before `release`, possibly *while* a `recv` is running. |
| `release` | may be `NULL` | Releases `context`. Called exactly once, after every other callback has returned. |
| `mtu` | **yes** | The MTU the interface is configured with. Must be ≥ 1280. |

**`0` from `recv` means "ask again", not "an empty packet".** There is no
zero-length IP packet, so the value is free to mean something else, and this is
what lets a host wait for a bounded interval rather than parking in the callback
forever. A .NET host **must** use it — see
[windows.md](windows.md#never-block-in-a-callback). Boreas simply calls again;
nothing is counted and nothing is logged.

`send` is all-or-nothing because the unit is the packet. There is no correct
handling of "some of this IP packet reached the wire": the remainder carries no
header and cannot be sent as a second packet.

Threading, blocking, and lifetime rules for these callbacks are in
[obligations.md](obligations.md). Read them; they are the part of this interface
that is easy to get subtly wrong.

## `BoreasBypass`

Sockets that do not re-enter the tunnel. **You implement this.**

```c
typedef struct {
  void *context;
  int32_t (*protect)(void *context, BoreasSocket socket);
  void (*release)(void *context);
} BoreasBypass;

typedef int64_t BoreasSocket;
```

| Field | Required | Contract |
| --- | --- | --- |
| `context` | may be `NULL` | Yours, passed back untouched. |
| `protect` | **yes** | Excludes one socket from the tunnel. Returns `0` on success, negative on refusal. |
| `release` | may be `NULL` | Releases `context`. Called exactly once. |

`BoreasSocket` is signed 64-bit because a file descriptor is an `int` and a
Windows `SOCKET` is an unsigned pointer-width handle; one type has to hold both.
Cast it back to the platform's own type before using it.

Boreas creates the socket and hands it to you **before its first packet leaves**,
then connects or binds it. You never create a socket for us.

Android does not need you to implement `protect` at all —
`boreas_android_bypass` builds this vtable over a `VpnService`. See
[android.md](android.md#the-bypass).

## `BoreasConfig`

```c
typedef struct {
  BoreasEgress egress;
  BoreasWireGuard wireguard;
  BoreasNat nat_behavior;
  const char *resolver;
  const char *const *lists;
  size_t list_count;
  const char *const *intercept_hosts;
  size_t intercept_host_count;
  const uint8_t *root_certificate;
  size_t root_certificate_len;
  const uint8_t *authority_keys;
  size_t authority_keys_len;
  bool rewrite_documents;
  uint16_t mtu;
  BoreasCeilings ceilings;
} BoreasConfig;
```

Every pointer in it is borrowed for the duration of `boreas_tunnel_start` only.

| Field | Read when | Meaning |
| --- | --- | --- |
| `egress` | always | `BOREAS_EGRESS_DIRECT` (0) or `BOREAS_EGRESS_WIREGUARD` (1). |
| `wireguard` | `egress == WIREGUARD` | See below. |
| `nat_behavior` | `egress == DIRECT` | `0` endpoint-independent, `1` address-dependent, `2` address-and-port-dependent. What the NAT in front of you does. Boreas cannot measure this. If unsure, `2` — conservative, never claims more than is true. |
| `resolver` | always | `host:port` of a DNS upstream to filter through, or `NULL` to forward queries untouched. **`NULL` plus a non-empty `lists` is `BOREAS_CONFIG`** — see [configuration.md](configuration.md#resolver). |
| `lists`, `list_count` | always | Filter-list text, in [AdGuard/uBlock syntax](https://adguard.com/kb/general/ad-filtering/create-own-filters/). You fetch and store these; we compile them and keep none. Malformed lines are counted and skipped. |
| `intercept_hosts`, `intercept_host_count` | always | Hosts to intercept. Zero means no interception, which needs no certificate authority. **An allowlist, never a pattern.** |
| `root_certificate`, `authority_keys` (+ lengths) | interception on | Stored CA material, or all `NULL`/`0` to generate. Both halves together or neither. |
| `rewrite_documents` | interception on | Whether to rewrite HTML bodies as they stream. |
| `mtu` | always | The MTU configured on your TUN. Set both to the same number — see [obligations.md](obligations.md#set-the-mtu-to-the-same-number-twice). Minimum 1280. |
| `ceilings` | always | See [configuration.md](configuration.md#ceilings). |

```c
typedef struct {
  const char *endpoint;          /* "host:port", numeric address */
  uint8_t private_key[32];       /* raw, not base64 */
  uint8_t peer_public_key[32];   /* raw, not base64 */
  uint8_t preshared_key[32];
  bool has_preshared_key;
} BoreasWireGuard;
```

Keys are raw 32-byte arrays, not the base64 a WireGuard config file carries —
decode before you fill these in. `has_preshared_key` is a separate flag because
a key of thirty-two zeroes is a key someone may legitimately have configured, so
"all zero" cannot mean "absent".

`endpoint` is not part of the key material: a peer that roams keeps its keys and
changes its address.

```c
typedef struct {
  size_t buffer_slices;
  size_t datagrams_per_flow;
  size_t terminated_connections;
  size_t associations;
  size_t inspected_addresses;
  size_t pending_reassemblies;
} BoreasCeilings;
```

**Zero in any field means "use the default for it"**, so `{0}` is a valid
`BoreasCeilings` and gives you the phone-sized defaults. Defaults and what each
one bounds are in [configuration.md](configuration.md#ceilings).

## `BoreasEvent`

```c
typedef enum {
  BOREAS_EVENT_RESOLVED = 0,
  BOREAS_EVENT_RELOADED = 1,
  BOREAS_EVENT_COUNTED  = 2,
} BoreasEventKind;

typedef struct {
  uint64_t datagrams_dropped;
  uint64_t packets_rejected;
  uint64_t quic_steered;
  uint64_t paths_reported;
  uint64_t events_lost;
  uint64_t tasks_panicked;
} BoreasCounters;

typedef struct {
  BoreasEventKind kind;
  bool blocked;
  size_t name_len;
  size_t rule_len;
  size_t allowed;
  size_t blocked_rules;
  size_t inspected;
  BoreasCounters counters;
} BoreasEvent;
```

A tag and every arm's fields side by side rather than a union — a union would
save a few dozen bytes per event and cost every binding generator an unsafe
read. **Only the fields `kind` names carry meaning**; the rest are zero.

| `kind` | Meaningful fields |
| --- | --- |
| `RESOLVED` | `blocked`, and the `name` / `rule` buffers you passed, plus `name_len` / `rule_len` |
| `RELOADED` | `allowed`, `blocked_rules`, `inspected` |
| `COUNTED` | `counters` |

`name_len` and `rule_len` are the **full** byte lengths of the text, before
truncation. A value larger than the capacity you passed means it did not all
fit. `rule_len == 0` on a `RESOLVED` means no rule decided it.

What each counter means, and what a sustained non-zero value tells you, is in
[lifecycle.md](lifecycle.md#counters).

## Functions

All six. `handle` must have come from `boreas_tunnel_start` and must not have
been freed.

```c
BoreasStatus boreas_tunnel_start(const BoreasConfig *config,
                                 const BoreasDevice *device,
                                 const BoreasBypass *bypass,
                                 BoreasTunnel **out);
```

Builds and starts everything. Writes the handle through `out` on success; on any
failure `out` is untouched and nothing is allocated — **but both `release`
callbacks still run**, so a context you handed over is always accounted for and
you can retry with a fresh one.

Blocks for as long as the first connection takes to establish. Call it off your
UI thread.

---

```c
BoreasStatus boreas_tunnel_next_event(const BoreasTunnel *handle,
                                      BoreasEvent *event,
                                      char *name, size_t name_cap,
                                      char *rule, size_t rule_cap);
```

Blocks until the next event. `name` and `rule` may each be `NULL` to discard
that string; `name_cap`/`rule_cap` are then ignored.

Returns `BOREAS_STOPPED` once no further event can arrive — which is how a
reader learns that another thread called `boreas_tunnel_shutdown`. That is the
normal way this loop ends.

**This can block for a long time.** A healthy idle tunnel emits nothing at all:
counters are reported only when non-zero, so "nothing went wrong" is silence.
Give it a thread of its own. Every other function may be called while it is
blocked.

---

```c
BoreasStatus boreas_tunnel_reload(const BoreasTunnel *handle,
                                  const char *const *lists, size_t count,
                                  BoreasEvent *out);
```

Replaces the rules in force without restarting the tunnel or dropping a
connection. Takes a **whole list set, never a delta**. Writes a `RELOADED` event
through `out`. Cost is proportional to the total list length.

Safe to call while a reader is blocked in `boreas_tunnel_next_event`.

The same reload also arrives on the event stream as a `RELOADED`, so a parked
reader learns the rules changed. Count one or the other, not both — see
[lifecycle.md](lifecycle.md#reload).

---

```c
BoreasStatus boreas_tunnel_authority(const BoreasTunnel *handle,
                                     uint8_t *certificate, size_t certificate_cap,
                                     size_t *certificate_len,
                                     uint8_t *keys, size_t keys_cap,
                                     size_t *keys_len);
```

Copies out the certificate authority's material. **Call it twice**: once with
both capacities zero to learn the lengths, then again with buffers of that size.

A short buffer is `BOREAS_BUFFER_TOO_SMALL` with both lengths set to what would
be needed. A tunnel that does not intercept sets both lengths to `0` and returns
`BOREAS_OK` — an answer, not a failure.

Safe to call while a reader is blocked.

---

```c
BoreasStatus boreas_tunnel_shutdown(const BoreasTunnel *handle);
```

Stops carrying traffic and releases any thread blocked in
`boreas_tunnel_next_event`. When it returns, every socket is closed and every
pooled buffer is back.

Safe from any thread, concurrently with anything. **Idempotent** — calling it
twice is not an error, so a teardown path never has to remember whether it
already ran.

---

```c
BoreasStatus boreas_tunnel_free(BoreasTunnel *handle);
```

Frees the handle. Passing `NULL` is a no-op, so unconditionally freeing an
initialised pointer is safe.

Call `boreas_tunnel_shutdown` first and join your reader thread. See
[obligations.md](obligations.md#teardown) for why these are two calls.

---

```c
#if defined(__ANDROID__)
BoreasStatus boreas_android_bypass(void *env, void *service, BoreasBypass *out);
#endif
```

Builds a `BoreasBypass` over a `VpnService`. See
[android.md](android.md#the-bypass).

## Layout guarantees

- Every struct here is C layout: fields in declaration order, natural
  alignment, no reordering.
- **The header asserts these from the C side too.** A C enum's width is
  implementation-defined, and a toolchain built with `-fshort-enums` — the
  default on some ARM toolchains — makes every enum here one byte instead of
  four, which moves `BoreasEvent.blocked` from offset four to offset one while
  both sides still compile. Static assertions in the header fail that build
  instead.
- Every enum is a signed 32-bit integer with the values shown.
- `BoreasTunnel` is **opaque**. It has no declared size and you may not allocate
  one; the only valid pointer to it is what `boreas_tunnel_start` wrote.
- An absent callback is a null function pointer, and a null function pointer is
  all-zero bytes — so a zeroed vtable is a vtable with no callbacks, not
  undefined.

A test in the library asserts every offset and every enum value on this page
against the Rust types, so the two cannot drift apart silently.

## What the ABI does not expose yet

Deliberate omissions, so you do not go looking. The Rust API has these today and
the C ABI will grow them when a platform needs them; ask rather than working
around.

| Not exposed | Consequence |
| --- | --- |
| SOCKS5, Shadowsocks, VLESS, Hysteria2 egresses | `egress` is direct or WireGuard. |
| DoT, DoH, DoQ upstreams | `resolver` is cleartext DNS on port 53 or whatever port you name. Use one on the local device or a trusted link until this grows. |
| A custom rewriting memory budget | `rewrite_documents` uses the 2 MiB default. |
| Custom origination ports | Fixed at 45000–45999. |
| Per-egress NAT behaviour for WireGuard | `nat_behavior` is read for direct egress only. |

The cleartext-resolver limitation is the one with a security consequence: a
`resolver` reached across an untrusted network is readable by anything on the
path. That is a real gap, not a preference.
