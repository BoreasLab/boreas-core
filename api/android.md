# Android (Kotlin)

End to end: packaging, the two vtables, the VPN lifecycle, and the certificate.

Read [obligations.md](obligations.md) alongside this — it carries the threading
and lifetime rules this page assumes. [abi.md](abi.md) is the field-by-field
reference.

- [Packaging the library](#packaging-the-library)
- [Calling in](#calling-in)
- [The device](#the-device)
- [The bypass](#the-bypass)
- [Putting it together](#putting-it-together)
- [The root certificate](#the-root-certificate)
- [Checklist](#checklist)

## Packaging the library

### ABIs

The NDK supports four: `armeabi-v7a`, `arm64-v8a`, `x86`, `x86_64`. The Play
Store and the package manager look for them at a fixed path inside the APK:

> Both the Play Store and Package Manager expect to find NDK-generated libraries
> on filepaths inside the APK matching the following pattern:
> `/lib/<abi>/lib<name>.so`
>
> — [Android ABIs](https://developer.android.com/ndk/guides/abis)

Gradle's `jniLibs` source set maps onto that, so build one `libboreas.so` per
ABI you ship and place each at `src/main/jniLibs/<abi>/libboreas.so`.

Ship `arm64-v8a` at minimum. `x86_64` is worth it for the emulator.

### 16 KB page sizes

This one has a deadline.

> To ensure your app works correctly on the latest versions of Android, all apps
> targeting Android 15 (API level 35) and higher must support 16 KB memory page
> sizes on 64-bit devices on Google Play. Starting February 1, 2027, if your app
> updates don't support 16 KB memory page sizes, you won't be able to release
> these updates.
>
> — [Support 16 KB page sizes](https://developer.android.com/guide/practices/page-sizes)

For a Rust `cdylib` this means either building with **NDK r28 or newer**, where
16 KB alignment is the default, or passing the linker flags explicitly on r27
and earlier:

```
-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384
```

Boreas itself contains no page-size assumption; this is purely a link-time
property of the `.so` you produce.

### Packaging flags

Leave `useLegacyPackaging` unset. Per the AGP reference, with `minSdk >= 23`
`.so` files are then stored uncompressed and page-aligned, which is what both
16 KB compliance and a direct `mmap` out of the APK need. Do not set
`android:extractNativeLibs` in the manifest; AGP replaced it with the DSL option
in 4.2.0.

Set `minSdk` to 23 or higher for the same reason.

## Calling in

**Kotlin cannot produce a C function pointer.** JNI's only pointer-passing
mechanism runs the other way — `RegisterNatives` lets *native* code hand the JVM
a function pointer for a Java-declared `native` method. There is no facility for
Java or Kotlin to synthesise an exportable C function pointer that native code
calls directly.

So you have two routes, and they differ in where the vtable is filled in:

| Route | Vtable filled in by | Good for |
| --- | --- | --- |
| **JNA** | Kotlin, using JNA callback objects (JNA builds the trampolines) | Getting running quickly; fine for a device whose `recv` blocks |
| **A small JNI shim** in C or Rust | your shim | Lowest overhead per packet; full control of the `recv` loop |

Both are supported. The examples below use JNA because it is the shorter path
and the per-packet cost is dominated by the syscall either way.

```kotlin
System.loadLibrary("boreas")
```

If you write a JNI shim and want `boreas_android_bypass`, the library's
`JNI_OnLoad` must have run — which `System.loadLibrary` guarantees:

> The VM calls `JNI_OnLoad` when the native library is loaded (for example,
> through `System.loadLibrary`).
>
> — [JNI Invocation API](https://docs.oracle.com/en/java/javase/21/docs/specs/jni/invocation.html)

That is where Boreas caches the `JavaVM`, and it is the only place it can be
had: a thread the JVM never created has no `JNIEnv` and no way to find one. If
you load the library some other way, `boreas_android_bypass` answers
`BOREAS_EGRESS` and `protect` reports `-2`.

## The device

`VpnService.Builder.establish()` gives you the interface:

> Create a VPN interface using the parameters supplied to this builder. The
> interface works on IP packets, and a file descriptor is returned for the
> application to access them.
>
> — [VpnService.Builder](https://developer.android.com/reference/android/net/VpnService.Builder)

It returns `null` if the app is not prepared or its VPN permission was revoked
in the interim — a documented path, not a theoretical one. Null-check it.

**Set the MTU explicitly.** `Builder.setMtu(int)`'s documentation says "If it is
not set, the default value in the operating system will be used", so an unset
MTU is not portably predictable. Set it, and pass the same number as
`BoreasConfig.mtu`.

### Who owns the file descriptor

This decides whether you get a double close.

| Method | Doc | Consequence |
| --- | --- | --- |
| `getFd()` | "The ParcelFileDescriptor still owns the fd, and it still must be closed through this API." | Keep the `ParcelFileDescriptor` alive for the whole tunnel and close it yourself, after teardown. |
| `detachFd()` | "Return the native fd int for this ParcelFileDescriptor and detach it from the object here. You are now responsible for closing the fd in native code." | You own it. Close it once, after teardown. The `ParcelFileDescriptor` is inert. |

Either works. Pick one and close exactly once, **after** your `release` callback
has run — see [obligations.md](obligations.md#teardown).

### Unblocking a blocked read

Your `close` callback must make an in-flight `recv` return. There is an obvious
way to do it that is wrong.

> It is probably unwise to close file descriptors while they may be in use by
> system calls in other threads in the same process. Since a file descriptor may
> be reused, there are some obscure race conditions that may cause unintended
> side effects.
>
> — [`close(2)`, CAVEATS](https://man7.org/linux/man-pages/man2/close.2.html)

And specifically on Linux — which Android is — closing does not reliably unblock
the read at all: the blocked call holds a reference to the open file description,
so it can keep waiting while the descriptor *number* is already free for another
thread to reuse.

Two correct options:

**A bounded read, which needs no `close` at all.** Return `0` after a short
timeout and let Boreas ask again. Simplest, and the only option if your `recv`
is written in Kotlin:

```kotlin
private val closed = AtomicBoolean(false)

// recv
if (closed.get()) return -5   // EIO
// poll the fd with a short timeout, or use a Selector; on timeout:
return 0                      // "nothing yet, ask again"
```

Set `close` to `null` in the vtable, or point it at something that sets
`closed`.

**`poll(2)` on the tun fd plus an `eventfd(2)`**, if your `recv` is in a native
shim. `eventfd` exists for exactly this:

> Applications can use an eventfd file descriptor instead of a pipe (see
> pipe(2)) in all cases where a pipe is used simply to signal events [...] can
> be monitored just like any other file descriptor using select(2), poll(2), or
> epoll(7).
>
> — [`eventfd(2)`](https://man7.org/linux/man-pages/man2/eventfd.2.html)

`close` writes to the eventfd; `recv` polls both and returns `-EIO` when the
eventfd fires. Close the tun fd only after the poll loop has exited.

### A JNA device

```kotlin
import com.sun.jna.*

@Structure.FieldOrder("context", "recv", "send", "close", "release", "mtu")
class BoreasDevice : Structure() {
    @JvmField var context: Pointer? = null
    @JvmField var recv: Recv? = null
    @JvmField var send: Send? = null
    @JvmField var close: Close? = null
    @JvmField var release: Release? = null
    @JvmField var mtu: Short = 0

    fun interface Recv : Callback { fun invoke(ctx: Pointer?, buf: Pointer, cap: NativeLong): NativeLong }
    fun interface Send : Callback { fun invoke(ctx: Pointer?, buf: Pointer, len: NativeLong): NativeLong }
    fun interface Close : Callback { fun invoke(ctx: Pointer?) }
    fun interface Release : Callback { fun invoke(ctx: Pointer?) }
}
```

> **Keep every callback object reachable from Kotlin for the whole life of the
> tunnel.** JNA's trampolines are collected with the objects they belong to. A
> callback that goes out of scope becomes a call through freed memory. Hold them
> in a field of the `VpnService`, not in a local.

Implementation over a `FileChannel` on the fd, with a bounded read:

```kotlin
class Tun(fd: Int, private val mtu: Int) {
    private val channel = FileInputStream(fromFd(fd)).channel
    private val out = FileOutputStream(fromFd(fd)).channel
    private val closed = AtomicBoolean(false)
    private val buffer = ByteBuffer.allocateDirect(mtu)

    val recv = BoreasDevice.Recv { _, dst, cap ->
        if (closed.get()) return@Recv NativeLong(-5)
        buffer.clear().limit(minOf(cap.toInt(), mtu))
        // A Selector on a non-blocking fd, or a short blocking read; either
        // way, return 0 rather than parking here forever.
        val read = readWithTimeout(channel, buffer, 100.milliseconds)
        if (read <= 0) return@Recv NativeLong(0)          // ask again
        dst.write(0, buffer.array(), 0, read)
        NativeLong(read.toLong())
    }

    val send = BoreasDevice.Send { _, src, len ->
        val n = len.toInt()
        val written = out.write(ByteBuffer.wrap(src.getByteArray(0, n)))
        if (written == n) NativeLong(0) else NativeLong(-5)   // all or nothing
    }

    val close = BoreasDevice.Close { closed.set(true) }
}
```

## The bypass

**You do not implement this on Android.** `protect` is a method on a Java
object, and Boreas has to call it from whichever worker thread is dialling — a
thread the JVM never created. That is the one obligation that cannot be a plain
function pointer, so the library does it:

```c
BoreasStatus boreas_android_bypass(void *env, void *service, BoreasBypass *out);
```

Call it from any JNI frame with that frame's `JNIEnv*` and your `VpnService`
object. It takes a global reference — a local one is valid only for the frame
that made it — attaches whichever worker thread later calls `protect`, and
invokes `VpnService.protect(int)`. Pass the filled-in vtable straight to
`boreas_tunnel_start`, which releases it exactly once, on success and on failure
alike.

There is deliberately **no `Java_...` symbol** for it: that name encodes the
package and class it belongs to, and those are yours to choose. A three-line
shim in your own JNI code is all it takes:

```c
JNIEXPORT jlong JNICALL
Java_com_example_boreas_Native_bypass(JNIEnv *env, jclass cls, jobject service) {
    BoreasBypass *out = malloc(sizeof *out);
    if (boreas_android_bypass(env, service, out)) { free(out); return 0; }
    return (jlong)(uintptr_t)out;
}
```

Failure codes from `protect`, should you see them in a capture: `-1` the
`VpnService` refused or threw, `-2` `JNI_OnLoad` never ran, `-3` the socket was
outside the Java `int` range.

`VpnService.protect(int)` returns a boolean and does not close the socket;
`false` means the app is not prepared or its permission was revoked. Boreas
treats that as a refusal and fails the dial rather than using an unprotected
socket.

## Putting it together

```kotlin
class BoreasVpnService : VpnService() {
    private var handle: Pointer? = null
    private var reader: Thread? = null
    private lateinit var tun: Tun            // holds the callbacks alive

    override fun onStartCommand(i: Intent?, flags: Int, id: Int): Int {
        val pfd = Builder()
            .setSession("Boreas")
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .setMtu(MTU)
            .establish() ?: return START_NOT_STICKY   // documented failure path

        tun = Tun(pfd.detachFd(), MTU)

        val config = BoreasConfig().apply {
            egress = 0                                // direct
            nat_behavior = 2                          // conservative
            resolver = "1.1.1.1:53"
            lists = toStringArray(filterLists); list_count = NativeLong(1)
            mtu = MTU.toShort()
            // ceilings left zeroed: phone-sized defaults
        }

        val out = PointerByReference()
        val status = Boreas.INSTANCE.boreas_tunnel_start(config, device(tun), bypass(), out)
        if (status != 0) { stopSelf(); return START_NOT_STICKY }
        handle = out.value

        reader = thread(name = "boreas-events") { readEvents(handle!!) }
        return START_STICKY
    }

    override fun onDestroy() {
        handle?.let { h ->
            Boreas.INSTANCE.boreas_tunnel_shutdown(h)   // releases the reader
            reader?.join()                              // yours
            Boreas.INSTANCE.boreas_tunnel_free(h)       // reclaims
        }
        // Only now: release ran, nothing is inside the callbacks.
        tun.dispose()
        super.onDestroy()
    }
}
```

The reader:

```kotlin
private fun readEvents(handle: Pointer) {
    val event = BoreasEvent()
    val name = Memory(256)
    val rule = Memory(256)
    while (true) {
        val status = Boreas.INSTANCE.boreas_tunnel_next_event(
            handle, event, name, NativeLong(256), rule, NativeLong(256)
        )
        if (status != 0) break            // BOREAS_STOPPED: normal end
        event.read()
        when (event.kind) {
            0 -> onResolved(name.getString(0), event.blocked != 0.toByte())
            1 -> onReloaded(event.allowed, event.blocked_rules)
            2 -> onCounters(event.counters)
        }
    }
}
```

Reloading a list, from anywhere, at any time — including while that reader is
parked:

```kotlin
Boreas.INSTANCE.boreas_tunnel_reload(handle, toStringArray(newLists), NativeLong(n), event)
```

## The root certificate

Only if you intercept. Call `boreas_tunnel_authority` twice — once to size, once
to fill:

```kotlin
val certLen = NativeLongByReference()
val keyLen = NativeLongByReference()
Boreas.INSTANCE.boreas_tunnel_authority(handle, null, NativeLong(0), certLen,
                                        null, NativeLong(0), keyLen)
if (certLen.value.toLong() == 0L) return    // this tunnel does not intercept

val cert = Memory(certLen.value.toLong())
val key = Memory(keyLen.value.toLong())
Boreas.INSTANCE.boreas_tunnel_authority(handle, cert, certLen.value, certLen,
                                        key, keyLen.value, keyLen)
```

- **The certificate is public**, DER. Offer it to the platform's trust
  installer.
- **The keys are secret.** Put them in the Android Keystore. Treat them as you
  would a password. They are opaque and self-describing; you never look inside.

Hand both back next launch through `root_certificate` / `authority_keys`. See
[lifecycle.md](lifecycle.md#the-one-thing-you-persist) for what the two failure
modes mean.

### Your app must opt into user CAs

Installing the root is not enough. Since API 24, apps do not trust user-added
CAs by default:

> By default, secure connections (using protocols like TLS and HTTPS) from all
> apps trust the pre-installed system CAs, and apps targeting Android 6.0 (API
> level 23) and lower also trust the user-added CA store by default.
>
> — [Network security configuration](https://developer.android.com/privacy-and-security/security-config)

If anything in *your own* app must trust the Boreas root, declare a network
security config with `<certificates src="user" />` in its trust anchors. This
does not affect other applications' traffic through the tunnel, which is
governed by each of their own configurations — which is exactly why interception
reaches browsers and not arbitrary apps.

`KeyChain.createInstallIntent()` with `EXTRA_CERTIFICATE` (a PEM or DER
`byte[]`) and `EXTRA_NAME` is the documented way to hand a certificate to the
installer.

> ⚠️ **Verify before you build UX on it.** There are widespread reports that
> from Android 11 this intent no longer installs *CA* certificates, leaving
> Settings → "Install from storage" as the only route. We were not able to
> confirm that against a primary Android source, so treat the one-tap flow as
> unverified and have the manual path ready. This is tracked in
> `docs/verification.md`.

## Checklist

- [ ] One `libboreas.so` per shipped ABI at `src/main/jniLibs/<abi>/`
- [ ] Built with NDK r28+, or with the 16 KB linker flags
- [ ] `minSdk >= 23`, `useLegacyPackaging` unset
- [ ] `Builder.setMtu(n)` and `BoreasConfig.mtu = n` — the same `n`
- [ ] `establish()` null-checked
- [ ] Every JNA callback object held in a long-lived field
- [ ] `recv` returns `0` on timeout rather than blocking forever, **or** polls
      an eventfd — never relies on `close(fd)` to unblock
- [ ] `send` returns an error on a short write
- [ ] Bypass built with `boreas_android_bypass`, not hand-written
- [ ] Events read on a thread of their own
- [ ] Teardown is shutdown → join → free, and the fd closes after that
- [ ] CA material stored in the Keystore, certificate offered to the installer
