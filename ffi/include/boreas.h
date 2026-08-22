/*
 * Boreas — the C boundary.
 *
 * Hand-written rather than generated, and the reason is narrower than "a
 * generator would lose the comments": cbindgen propagates Rust doc comments
 * into the header by default. What it has no equivalent for is everything in
 * this file that is not attached to one item — the type-width table and the
 * marshalling traps it names, the section structure, and the layout assertions
 * below, which fail a host's build when its flags would silently move a field.
 * cbindgen also emits C and C++ only, so it would not have reduced the work
 * for either language that actually consumes this.
 *
 * That trade is only worth it while the surface stays small. Six functions and
 * five structs is small. If this grows past what one person can hold in mind,
 * generate it and move these notes into Rust doc comments, where cbindgen will
 * carry them.
 *
 * Keep this in step with ffi/src/. `ffi/tests/header.rs` asserts every offset
 * and constant here against the Rust types, and the assertions further down
 * pin the same numbers from the C side, so both ends are held to one layout.
 */

#ifndef BOREAS_H
#define BOREAS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * The version of this ABI. Bumped when a symbol, a field, or the meaning of a
 * call changes; see api/stability.md for what "changes" is allowed to mean.
 *
 * The header and the library ship together and must be updated together.
 * `boreas_abi_version()` is how you prove they were: compare it against
 * BOREAS_ABI_VERSION once at startup and refuse to run if they differ. That
 * turns a stale library in an installer -- which otherwise reads fields at the
 * wrong offsets and behaves inexplicably -- into one clear message.
 */
#define BOREAS_ABI_VERSION 1u

/*
 * Warn when a status is dropped on the floor. Every function here returns one
 * and none of them can be safely ignored, so this is a real diagnostic rather
 * than decoration.
 */
#if defined(__cplusplus) && __cplusplus >= 201703L
#define BOREAS_MUST_USE [[nodiscard]]
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ > 201710L
#define BOREAS_MUST_USE [[nodiscard]]
#elif defined(__GNUC__) || defined(__clang__)
#define BOREAS_MUST_USE __attribute__((warn_unused_result))
#elif defined(_MSC_VER)
#define BOREAS_MUST_USE _Check_return_
#else
#define BOREAS_MUST_USE
#endif

/*
 * A compile-time check, where the language has one.
 *
 * Used below to pin every layout this ABI depends on. It is not decoration:
 * the width of a C enum is implementation-defined, and a toolchain built with
 * `-fshort-enums` -- the default on some ARM toolchains -- makes every enum
 * here one byte instead of four. That moves `BoreasEvent.blocked` from offset
 * four to offset one while both sides still compile, and a host then reads
 * every event field from the wrong place. Failing the host's build is the only
 * good outcome available.
 */
#if defined(__cplusplus) && __cplusplus >= 201103L
#define BOREAS_ASSERT_LAYOUT(condition, message) static_assert(condition, message)
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define BOREAS_ASSERT_LAYOUT(condition, message) _Static_assert(condition, message)
#else
/* C99 and older: a negative array bound is the portable stand-in. */
#define BOREAS_ASSERT_LAYOUT_(condition, line) \
  typedef char boreas_layout_##line[(condition) ? 1 : -1]
#define BOREAS_ASSERT_LAYOUT__(condition, line) BOREAS_ASSERT_LAYOUT_(condition, line)
#define BOREAS_ASSERT_LAYOUT(condition, message) \
  BOREAS_ASSERT_LAYOUT__(condition, __LINE__)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ status */

/*
 * Zero is success, so `if (boreas_...(...)) { fail; }` reads correctly.
 */
typedef enum {
  BOREAS_OK = 0,
  /* A required pointer was null. Always a bug in the caller. */
  BOREAS_NULL_ARGUMENT = 1,
  /* A string argument was not valid UTF-8. */
  BOREAS_NOT_UTF8 = 2,
  /* The configuration describes a tunnel that cannot exist. */
  BOREAS_CONFIG = 3,
  /*
   * Stored certificate authority material was lost, corrupted, or is not two
   * halves of one authority. Generate afresh and ask the user to trust the new
   * root; Boreas will not silently substitute one.
   */
  BOREAS_AUTHORITY = 4,
  /* An egress could not be built from its configuration. */
  BOREAS_EGRESS = 5,
  /*
   * The connection ceiling cannot hold a listening backlog for every inspected
   * port. Raise `terminated_connections`.
   */
  BOREAS_TERMINATION = 6,
  /* The datapath refused the combination it was handed. */
  BOREAS_DATAPATH = 7,
  /* A socket the tunnel needs could not be opened through the bypass. */
  BOREAS_IO = 8,
  /* The tunnel has stopped. The handle is still valid to free. */
  BOREAS_STOPPED = 9,
  /* An output buffer was too small; the length out-parameter says how small. */
  BOREAS_BUFFER_TOO_SMALL = 10,
  /*
   * A panic was caught at the boundary. Always a defect in Boreas. The
   * tunnel's state is whatever the failed call left it in, so free the handle
   * and report this; do not retry on it.
   */
  BOREAS_PANIC = 11,
  /* A failure this header predates. */
  BOREAS_UNRECOGNISED = 12,
} BoreasStatus;

/* ------------------------------------------------------------------- seams */

/*
 * A socket to exclude from the tunnel: a file descriptor on Unix, a SOCKET on
 * Windows. Signed 64-bit because the two platforms disagree about the width
 * and one of them uses the top bit.
 */
typedef int64_t BoreasSocket;

/*
 * The client's TUN.
 *
 * EVERY CALLBACK HERE IS CALLED FROM AN ARBITRARY WORKER THREAD, and not
 * always the same one. Your implementation must be safe to call from any
 * thread. This is not advisory: it is the assumption the library is built on.
 */
typedef struct {
  /* Passed back to every call, untouched. Yours. */
  void *context;
  /*
   * Reads one IP packet into `buf`. Returns the byte count, ZERO for "nothing
   * yet, ask again", or a negative errno.
   *
   * Blocking is expected but not required. There is no zero-length IP packet,
   * so zero is free to mean "ask again" — which is what lets a host that must
   * not sit in a callback indefinitely wait for a bounded interval instead.
   * A .NET host MUST work this way: an [UnmanagedCallersOnly] method runs in
   * the CLR's cooperative GC mode, and a thread blocked there prevents any
   * garbage collection from completing process-wide.
   */
  intptr_t (*recv)(void *context, uint8_t *buf, size_t cap);
  /*
   * Writes one IP packet, whole. Returns 0, or a negative errno. A short write
   * is an error, not a success with a count: the remainder of an IP packet
   * carries no header and cannot be sent as a second one.
   */
  intptr_t (*send)(void *context, const uint8_t *buf, size_t len);
  /*
   * Makes any in-flight `recv` return, promptly.
   *
   * CALLED BEFORE `release`, AND POSSIBLY WHILE A `recv` IS BLOCKED, so it
   * must be safe to call concurrently with one. A blocking read cannot be
   * cancelled, so `release` cannot run until the read returns and the read
   * does not return until you make it: if `release` were the only signal, the
   * two would wait for each other.
   *
   * DO NOT implement this by closing the file descriptor `recv` is blocked
   * on. close(2)'s own CAVEATS section calls that "probably unwise", and on
   * Linux the blocked read holds a reference to the open file description, so
   * it may not return at all until data arrives — while the descriptor number
   * is already free to be reused by another thread. Signal an eventfd(2) that
   * `recv` waits on with poll(2), or return zero from a bounded `recv` and
   * let this set a flag the next call sees.
   *
   * May be NULL if `recv` never blocks indefinitely — which, if it returns
   * zero on a timeout, it does not.
   */
  void (*close)(void *context);
  /* Releases `context`. Called once, after every callback has returned. */
  void (*release)(void *context);
  /* The MTU the interface is configured with. Set the TUN to this number and
   * pass the same one in BoreasConfig.mtu. */
  uint16_t mtu;
} BoreasDevice;

/*
 * Sockets that do not re-enter the tunnel.
 *
 * THIS IS THE OBLIGATION THAT IS SILENT WHEN YOU SKIP IT. An unprotected
 * socket works perfectly until the tunnel comes up, at which point every
 * packet it sends re-enters the tunnel it was serving. The symptom is a
 * resolver that hangs and a proxy that never connects.
 *
 * Boreas creates the socket and hands it to you before its first packet; you
 * exclude it. On Android that is VpnService.protect(fd) — see
 * `boreas_android_bypass`, which does the JNI for you. On Windows, bind the
 * physical interface's address or set its index.
 */
typedef struct {
  void *context;
  /* Excludes one socket. Returns 0 on success, negative on refusal. */
  int32_t (*protect)(void *context, BoreasSocket socket);
  /* Releases `context`. Called once. */
  void (*release)(void *context);
} BoreasBypass;

/* ----------------------------------------------------------- configuration */

typedef enum {
  /* Out by the host's own routes. Nothing is proxied. */
  BOREAS_EGRESS_DIRECT = 0,
  /* A WireGuard peer, carrying whole IP packets. */
  BOREAS_EGRESS_WIREGUARD = 1,
} BoreasEgress;

typedef enum {
  BOREAS_NAT_ENDPOINT_INDEPENDENT = 0,
  BOREAS_NAT_ADDRESS_DEPENDENT = 1,
  BOREAS_NAT_ADDRESS_AND_PORT_DEPENDENT = 2,
} BoreasNat;

typedef struct {
  /* "host:port" of the peer. Not part of the keys: a peer that roams keeps
   * its keys and changes its address. */
  const char *endpoint;
  uint8_t private_key[32];
  uint8_t peer_public_key[32];
  /* The flag distinguishes "no pre-shared key" from "a key of 32 zeroes". */
  uint8_t preshared_key[32];
  bool has_preshared_key;
} BoreasWireGuard;

/* Zero in any field means "use the default for it". */
typedef struct {
  size_t buffer_slices;
  size_t datagrams_per_flow;
  /* Must be at least (inspected ports x 64), or start fails with
   * BOREAS_TERMINATION. Below that, later ports get no listener at all. */
  size_t terminated_connections;
  size_t associations;
  size_t inspected_addresses;
  size_t pending_reassemblies;
} BoreasCeilings;

typedef struct {
  BoreasEgress egress;
  /* Read only when egress is BOREAS_EGRESS_WIREGUARD. */
  BoreasWireGuard wireguard;
  /* Read only when egress is BOREAS_EGRESS_DIRECT. */
  BoreasNat nat_behavior;
  /* "host:port" of a DNS upstream to filter through, or NULL to forward
   * queries untouched. Filtering with NULL here is BOREAS_CONFIG: on the
   * packet path a flow is selected for inspection because a DNS answer named
   * its address, so a tunnel that never sees a question can filter nothing. */
  const char *resolver;
  const char *const *lists;
  size_t list_count;
  /* Zero hosts means no interception, which needs no certificate authority. */
  const char *const *intercept_hosts;
  size_t intercept_host_count;
  /* Stored authority material, or NULL to generate. Both halves together. */
  const uint8_t *root_certificate;
  size_t root_certificate_len;
  const uint8_t *authority_keys;
  size_t authority_keys_len;
  bool rewrite_documents;
  uint16_t mtu;
  BoreasCeilings ceilings;
} BoreasConfig;

/* ------------------------------------------------------------------ events */

typedef enum {
  BOREAS_EVENT_RESOLVED = 0,
  BOREAS_EVENT_RELOADED = 1,
  BOREAS_EVENT_COUNTED = 2,
} BoreasEventKind;

/*
 * Occurrences since the previous BOREAS_EVENT_COUNTED. Every field is a thing
 * that went wrong or was refused, so a tunnel working normally reports zeroes
 * and you can surface any non-zero field without knowing what it means.
 */
typedef struct {
  uint64_t datagrams_dropped;
  uint64_t packets_rejected;
  uint64_t quic_steered;
  /* A misconfiguration: your TUN's MTU is wider than BoreasConfig.mtu. */
  uint64_t paths_reported;
  uint64_t events_lost;
  /* A DEFECT IN BOREAS, not a condition of the network. Please report it. */
  uint64_t tasks_panicked;
} BoreasCounters;

/* Only the fields `kind` names carry meaning. */
typedef struct {
  BoreasEventKind kind;
  bool blocked;
  /* The full length of the name before truncation; larger than your capacity
   * means it did not all fit. */
  size_t name_len;
  size_t rule_len;
  size_t allowed;
  size_t blocked_rules;
  size_t inspected;
  BoreasCounters counters;
} BoreasEvent;

/* ------------------------------------------------------------------ layout */

/*
 * Everything the ABI depends on, asserted where a host compiles rather than
 * where we do. A build whose flags produce a different layout fails here with
 * a message, instead of linking cleanly and reading the wrong bytes.
 *
 * The same offsets are asserted against the Rust types by `ffi/tests/header.rs`,
 * so both ends of the boundary are pinned to the same numbers.
 */

/* Enums are four bytes. See BOREAS_ASSERT_LAYOUT above for why this is here. */
BOREAS_ASSERT_LAYOUT(sizeof(BoreasStatus) == 4, "BoreasStatus must be 4 bytes");
BOREAS_ASSERT_LAYOUT(sizeof(BoreasEgress) == 4, "BoreasEgress must be 4 bytes");
BOREAS_ASSERT_LAYOUT(sizeof(BoreasNat) == 4, "BoreasNat must be 4 bytes");
BOREAS_ASSERT_LAYOUT(sizeof(BoreasEventKind) == 4, "BoreasEventKind must be 4 bytes");

/* `bool` is one byte, which is the assumption a C# host must be told twice. */
BOREAS_ASSERT_LAYOUT(sizeof(bool) == 1, "bool must be 1 byte");

/* Pointer-width scalars, so a 32-bit ABI is caught rather than assumed. */
BOREAS_ASSERT_LAYOUT(sizeof(size_t) == sizeof(void *), "size_t must be pointer-width");
BOREAS_ASSERT_LAYOUT(sizeof(intptr_t) == sizeof(void *), "intptr_t must be pointer-width");
BOREAS_ASSERT_LAYOUT(sizeof(BoreasSocket) == 8, "BoreasSocket must be 8 bytes");

/* The vtables a host fills in by hand, where a shifted field is a call
 * through the wrong function pointer rather than a compile error. */
BOREAS_ASSERT_LAYOUT(offsetof(BoreasDevice, context) == 0, "BoreasDevice.context moved");
BOREAS_ASSERT_LAYOUT(offsetof(BoreasDevice, mtu) == 5 * sizeof(void *), "BoreasDevice.mtu moved");
BOREAS_ASSERT_LAYOUT(offsetof(BoreasBypass, context) == 0, "BoreasBypass.context moved");
BOREAS_ASSERT_LAYOUT(sizeof(BoreasBypass) == 3 * sizeof(void *), "BoreasBypass resized");

/* The structs a host reads back. `blocked` is the one that moves under
 * `-fshort-enums`, which is what makes this block worth its lines. */
BOREAS_ASSERT_LAYOUT(offsetof(BoreasEvent, kind) == 0, "BoreasEvent.kind moved");
BOREAS_ASSERT_LAYOUT(offsetof(BoreasEvent, blocked) == 4, "BoreasEvent.blocked moved");
BOREAS_ASSERT_LAYOUT(sizeof(BoreasCounters) == 6 * sizeof(uint64_t), "BoreasCounters resized");
BOREAS_ASSERT_LAYOUT(sizeof(BoreasCeilings) == 6 * sizeof(size_t), "BoreasCeilings resized");
BOREAS_ASSERT_LAYOUT(offsetof(BoreasConfig, egress) == 0, "BoreasConfig.egress moved");

/* ------------------------------------------------------------------ tunnel */

typedef struct BoreasTunnel BoreasTunnel;

/*
 * The ABI version this library was built as. Compare against
 * BOREAS_ABI_VERSION at startup; a mismatch means the header and the library
 * came from different builds, and nothing below is safe to call.
 */
uint32_t boreas_abi_version(void);

/*
 * Starts a tunnel, writing its handle through `out`.
 *
 * On failure nothing is allocated and `out` is untouched — but both `release`
 * callbacks are still called, so a context you handed over is always
 * accounted for and you can retry.
 */
BOREAS_MUST_USE BoreasStatus boreas_tunnel_start(const BoreasConfig *config,
                                 const BoreasDevice *device,
                                 const BoreasBypass *bypass,
                                 BoreasTunnel **out);

/*
 * Blocks until the next event, or BOREAS_STOPPED once none can arrive.
 *
 * `name` and `rule` receive BOREAS_EVENT_RESOLVED's strings, truncated to
 * their capacities and always NUL-terminated. Either may be NULL to discard.
 *
 * One reader at a time; a second concurrent caller queues behind the first.
 * Every OTHER entry point is safe to call while a reader is blocked here —
 * that is what the const handle means, and reload in particular depends on it,
 * because a healthy idle tunnel emits nothing and this call can block for as
 * long as nothing goes wrong.
 */
BOREAS_MUST_USE BoreasStatus boreas_tunnel_next_event(const BoreasTunnel *handle,
                                      BoreasEvent *event,
                                      char *name, size_t name_cap, char *rule,
                                      size_t rule_cap);

/* Replaces the rules in force, without restarting or dropping a connection. */
BOREAS_MUST_USE BoreasStatus boreas_tunnel_reload(const BoreasTunnel *handle,
                                  const char *const *lists, size_t count,
                                  BoreasEvent *out);

/*
 * Copies out the certificate authority's material.
 *
 * Call once with zero capacities to size, then again to fill. Both lengths are
 * zero for a tunnel that does not intercept, which is an answer rather than a
 * failure. Store `certificate` where a trust installer can read it and `keys`
 * where you keep secrets; hand both back next launch.
 */
BOREAS_MUST_USE BoreasStatus boreas_tunnel_authority(const BoreasTunnel *handle,
                                     uint8_t *certificate,
                                     size_t certificate_cap,
                                     size_t *certificate_len, uint8_t *keys,
                                     size_t keys_cap, size_t *keys_len);

/*
 * Stops carrying traffic, and releases any thread blocked in
 * boreas_tunnel_next_event (which then returns BOREAS_STOPPED).
 *
 * Separate from boreas_tunnel_free because a blocked reader cannot be freed
 * out from under itself. Stop, join your reader thread, then free. Safe from
 * any thread, concurrently with anything, and calling it twice is not an
 * error. When it returns, every socket is closed and every pooled buffer is
 * back.
 */
BOREAS_MUST_USE BoreasStatus boreas_tunnel_shutdown(const BoreasTunnel *handle);

/*
 * Frees the handle. Passing NULL is a no-op.
 *
 * Call boreas_tunnel_shutdown first and join whatever thread was reading
 * events. A tunnel not already stopped is stopped here, so freeing without
 * stopping still closes sockets — but a reader blocked at that moment is a
 * use-after-free, which is why these are two calls.
 */
BOREAS_MUST_USE BoreasStatus boreas_tunnel_free(BoreasTunnel *handle);

/* ----------------------------------------------------------------- android */

#if defined(__ANDROID__)
/*
 * Builds a BoreasBypass over a VpnService, for a Java_... function you wrote.
 *
 * Call it from any JNI frame with that frame's JNIEnv and the service object;
 * it takes a global reference, so the object outlives the frame. Pass the
 * result straight to boreas_tunnel_start, which releases it exactly once — on
 * success and on failure alike.
 *
 * There is deliberately no Java_... symbol here: that name encodes the package
 * and class it belongs to, and those are yours to choose.
 */
BOREAS_MUST_USE BoreasStatus boreas_android_bypass(void *env, void *service, BoreasBypass *out);
#endif

#ifdef __cplusplus
}
#endif

#endif /* BOREAS_H */
