# Windows (C#/.NET)

End to end: the P/Invoke declarations, the two vtables, Wintun, and the
certificate.

Read [obligations.md](obligations.md) alongside this — it carries the threading
and lifetime rules this page assumes. [abi.md](abi.md) is the field-by-field
reference.

- [Declaring the interface](#declaring-the-interface)
- [Never block in a callback](#never-block-in-a-callback)
- [The device, over Wintun](#the-device-over-wintun)
- [The bypass](#the-bypass)
- [Putting it together](#putting-it-together)
- [The root certificate](#the-root-certificate)
- [Checklist](#checklist)

## Declaring the interface

Use `[LibraryImport]`, the source-generated P/Invoke. Microsoft's own guidance:

> ✔️ DO use `[LibraryImport]`, if possible, when targeting .NET 7+.
>
> — [Native interoperability best practices](https://learn.microsoft.com/en-us/dotnet/standard/native-interop/best-practices)

It generates the marshalling at compile time, which is what makes it work under
trimming and AOT — and it pushes you toward blittable declarations, which is
what you want here anyway.

You do **not** need a calling convention. On x64 and ARM64 there is only one:

> On x64, ARM, and ARM64 architectures, there is only one calling convention, so
> specifying one explicitly is unnecessary.
>
> — [Calling conventions](https://learn.microsoft.com/en-us/dotnet/standard/native-interop/calling-conventions)

### Three type rules

**1. `bool` in a struct must be `[MarshalAs(UnmanagedType.U1)]`.** This is the
mistake that costs an afternoon:

> By default, a .NET `bool` is marshalled to a Windows `BOOL`, where it's a
> 4-byte value. However, the `_Bool`, and `bool` types in C and C++ are a
> *single* byte. This can lead to hard to track down bugs...
>
> — [Native interoperability best practices](https://learn.microsoft.com/en-us/dotnet/standard/native-interop/best-practices)

`BoreasConfig`, `BoreasDevice`, `BoreasWireGuard`, and `BoreasEvent` all contain
one. A bare `bool` shifts every field after it by three bytes and you read
garbage with no error anywhere.

**2. `size_t` is `nuint`, not `uint`.** Pointer-width. `int`/`uint` is right on
x86 and silently truncating on x64 and ARM64.

**3. Strings are UTF-8, not UTF-16.** Use `StringMarshalling.Utf8` or pass
`byte*` yourself. There is no `Ansi` option in `LibraryImport` and a UTF-16
string reaches us as mojibake or `BOREAS_NOT_UTF8`.

### The declarations

```csharp
using System.Runtime.InteropServices;

internal enum BoreasStatus
{
    Ok = 0, NullArgument = 1, NotUtf8 = 2, Config = 3, Authority = 4,
    Egress = 5, Termination = 6, Datapath = 7, Io = 8, Stopped = 9,
    BufferTooSmall = 10, Panic = 11, Unrecognised = 12,
}

[StructLayout(LayoutKind.Sequential)]
internal struct BoreasDevice
{
    public IntPtr Context;
    public IntPtr Recv;      // intptr_t (*)(void*, uint8_t*, size_t)
    public IntPtr Send;      // intptr_t (*)(void*, const uint8_t*, size_t)
    public IntPtr Close;     // void (*)(void*)
    public IntPtr Release;   // void (*)(void*)
    public ushort Mtu;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BoreasBypass
{
    public IntPtr Context;
    public IntPtr Protect;   // int32_t (*)(void*, int64_t)
    public IntPtr Release;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BoreasCeilings
{
    public nuint BufferSlices, DatagramsPerFlow, TerminatedConnections;
    public nuint Associations, InspectedAddresses, PendingReassemblies;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct BoreasWireGuard
{
    public IntPtr Endpoint;                                   // const char*
    public fixed byte PrivateKey[32];
    public fixed byte PeerPublicKey[32];
    public fixed byte PresharedKey[32];
    [MarshalAs(UnmanagedType.U1)] public bool HasPresharedKey;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BoreasConfig
{
    public int Egress;                    // 0 direct, 1 wireguard
    public BoreasWireGuard WireGuard;
    public int NatBehavior;               // 0 EI, 1 AD, 2 APD
    public IntPtr Resolver;               // const char* or null
    public IntPtr Lists;                  // const char* const*
    public nuint ListCount;
    public IntPtr InterceptHosts;
    public nuint InterceptHostCount;
    public IntPtr RootCertificate;
    public nuint RootCertificateLen;
    public IntPtr AuthorityKeys;
    public nuint AuthorityKeysLen;
    [MarshalAs(UnmanagedType.U1)] public bool RewriteDocuments;
    public ushort Mtu;
    public BoreasCeilings Ceilings;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BoreasCounters
{
    public ulong DatagramsDropped, PacketsRejected, QuicSteered;
    public ulong PathsReported, EventsLost, TasksPanicked;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BoreasEvent
{
    public int Kind;                      // 0 resolved, 1 reloaded, 2 counted
    [MarshalAs(UnmanagedType.U1)] public bool Blocked;
    public nuint NameLen, RuleLen, Allowed, BlockedRules, Inspected;
    public BoreasCounters Counters;
}

internal static unsafe partial class Boreas
{
    [LibraryImport("boreas")]
    internal static partial BoreasStatus boreas_tunnel_start(
        BoreasConfig* config, BoreasDevice* device, BoreasBypass* bypass,
        IntPtr* outHandle);

    [LibraryImport("boreas")]
    internal static partial BoreasStatus boreas_tunnel_next_event(
        IntPtr handle, BoreasEvent* @event,
        byte* name, nuint nameCap, byte* rule, nuint ruleCap);

    [LibraryImport("boreas")]
    internal static partial BoreasStatus boreas_tunnel_reload(
        IntPtr handle, byte** lists, nuint count, BoreasEvent* @out);

    [LibraryImport("boreas")]
    internal static partial BoreasStatus boreas_tunnel_authority(
        IntPtr handle, byte* certificate, nuint certificateCap, nuint* certificateLen,
        byte* keys, nuint keysCap, nuint* keysLen);

    [LibraryImport("boreas")]
    internal static partial BoreasStatus boreas_tunnel_shutdown(IntPtr handle);

    [LibraryImport("boreas")]
    internal static partial BoreasStatus boreas_tunnel_free(IntPtr handle);
}
```

Wrapping the handle in a `SafeHandle` is worth it — it ref-counts across each
P/Invoke, which closes the race where a finalizer frees a handle mid-call:

> Platform invoke operations automatically increment the reference count of
> handles encapsulated by a SafeHandle and decrement them upon completion. This
> ensures that the handle will not be recycled or closed unexpectedly.
>
> — [SafeHandle](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.safehandle)

Note that its `ReleaseHandle` should call `boreas_tunnel_free`, and that you
must still call `boreas_tunnel_shutdown` and join your reader **before**
disposing it — see [obligations.md](obligations.md#teardown).

### Callbacks

Use `[UnmanagedCallersOnly]` and `&Method`, not
`Marshal.GetFunctionPointerForDelegate`. The delegate route requires you to root
the delegate for as long as native code might call it, and a collected delegate
is a call through freed memory:

> You must manually keep the delegate from being collected by the garbage
> collector from managed code. The garbage collector does not track references to
> unmanaged code.
>
> — [Marshal.GetFunctionPointerForDelegate](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getfunctionpointerfordelegate)

`[UnmanagedCallersOnly]` has no such hazard because there is no heap object to
collect. Its constraints:

> Must be marked `static`. Must not be called from managed code. Must only have
> blittable arguments. Must not have generic type parameters or be contained
> within a generic class.
>
> — [UnmanagedCallersOnlyAttribute](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.unmanagedcallersonlyattribute)

Static and non-generic means the method cannot close over anything, so per-tunnel
state travels through the `void* context` — allocate a `GCHandle`, pass
`GCHandle.ToIntPtr`, and free it in `release`.

**Never let an exception escape one.** Wrap every body in `try`/`catch` and map
to a negative return. An unhandled managed exception crossing back into native
code is documented by the .NET team as crashing the host process.

You do not need to attach the calling thread: the CLR notices a native thread
the first time it calls managed code and attaches it for you. That is the one
place .NET is easier than JNI here.

## Never block in a callback

This is the Windows-specific trap and it does not look like one.

An `[UnmanagedCallersOnly]` method runs in the CLR's **cooperative** GC mode.
From the runtime's own design documentation:

> A thread in 'cooperative mode' holds its lock; it must 'cooperate' with the GC
> (by releasing the lock) in order for a GC to proceed [...] A GC may only
> proceed when all managed threads are in 'preemptive' mode [...] The thread
> should not be blocked in this mode, and in particular cannot generally acquire
> locks safely.
>
> — [Book of the Runtime: threading](https://github.com/dotnet/runtime/blob/main/docs/design/coreclr/botr/threading.md)

So a `recv` that parks for two seconds waiting for a packet **stalls every
garbage collection in your process for two seconds**. Your UI freezes and
nothing in the stack trace points at Boreas.

The ABI is built to let you avoid it. `recv` returning `0` means *"nothing yet,
ask again"* — there is no zero-length IP packet, so the value is free. Wait for
a bounded interval, return `0`, and Boreas calls again immediately. Each entry
into managed code is then short, and the thread spends the wait in native code,
in preemptive mode, where a collection can proceed.

```csharp
[UnmanagedCallersOnly]
private static nint Recv(IntPtr context, byte* buf, nuint cap)
{
    try
    {
        var self = (Tun)GCHandle.FromIntPtr(context).Target!;
        // Bounded. Never Timeout.Infinite.
        return self.TryReceive(new Span<byte>(buf, (int)cap), TimeSpan.FromMilliseconds(100));
        //  > 0  bytes read
        //  == 0 nothing yet, ask again      <-- the important one
        //  < 0  negative errno
    }
    catch { return -5; }   // EIO; never let this escape
}
```

## The device, over Wintun

[Wintun](https://www.wintun.net/) is Jason A. Donenfeld's TUN driver for
Windows, originally written for WireGuard. Current version 0.14.1.

**Ship the official signed DLL.** Not a self-build:

> Due to Microsoft's driver signing requirements, we provide precompiled and
> signed versions that may be distributed with your software. [...] the below
> signed DLLs are the *only supported way of distributing Wintun*.
>
> — [wintun.net](https://www.wintun.net/)

The API you need:

```c
WINTUN_ADAPTER_HANDLE WintunCreateAdapter(LPCWSTR Name, LPCWSTR TunnelType,
                                          const GUID *RequestedGUID);
WINTUN_SESSION_HANDLE WintunStartSession(WINTUN_ADAPTER_HANDLE Adapter, DWORD Capacity);
BYTE *WintunReceivePacket(WINTUN_SESSION_HANDLE Session, DWORD *PacketSize);
BYTE *WintunAllocateSendPacket(WINTUN_SESSION_HANDLE Session, DWORD PacketSize);
VOID  WintunSendPacket(WINTUN_SESSION_HANDLE Session, const BYTE *Packet);
HANDLE WintunGetReadWaitEvent(WINTUN_SESSION_HANDLE Session);
VOID  WintunEndSession(WINTUN_SESSION_HANDLE Session);
```

### The read loop

`WintunReceivePacket` returns `ERROR_NO_MORE_ITEMS` when the ring is empty, and
you wait on the read-wait event:

> Should WintunReceivePacket return ERROR_NO_MORE_ITEMS (after spinning on it
> for a while under heavy load), wait for this event to become signaled before
> retrying WintunReceivePacket. Do not call CloseHandle on this event - it is
> managed by the session.
>
> — `wintun.h`

Two things to get right:

**Wait with a timeout, not `INFINITE`.** The GC reason above. A 100 ms wait that
returns `0` on expiry is exactly what the ABI wants.

**Do not rely on `WintunEndSession` to wake a waiter.** Its documentation says
nothing about that, and Wintun's own example does not depend on it — it waits on
the read-wait event *and a quit event of its own*, and signals the quit event to
shut down:

```c
HANDLE WaitHandles[] = { WintunGetReadWaitEvent(Session), QuitEvent };
```

Do the same: your `close` callback signals your own `ManualResetEvent`.

```csharp
internal sealed class Tun
{
    private readonly IntPtr session;
    private readonly WaitHandle[] waits;   // [readWait, quit]
    private readonly ManualResetEvent quit = new(false);

    public int TryReceive(Span<byte> destination, TimeSpan timeout)
    {
        var packet = Wintun.WintunReceivePacket(session, out var size);
        if (packet == IntPtr.Zero)
        {
            if (Marshal.GetLastWin32Error() != ERROR_NO_MORE_ITEMS) return -5;
            var which = WaitHandle.WaitAny(waits, timeout);
            if (which == 1) return -5;               // quit signalled
            return 0;                                 // timeout: ask again
        }
        // ... copy min(size, destination.Length), WintunReleaseReceivePacket ...
    }

    public void Close() => quit.Set();
}
```

### The adapter's MTU

Wintun does not appear to configure one, and its documentation does not mention
MTU at all. Set it yourself after creating the adapter, through the IP Helper
API — `GetIpInterfaceEntry` / `SetIpInterfaceEntry`, field `NlMtu` — or with
`netsh interface ipv4 set subinterface ... mtu=`.

Then pass the same number as `BoreasConfig.Mtu`.

> This one we could not confirm from a primary Wintun source; it comes from the
> WireGuard mailing list. Verify against the current `wintun.h` before relying
> on it. Tracked in `docs/verification.md`.

## The bypass

There is no `VpnService.protect` here. Exclude a socket by naming the outgoing
physical interface with `IP_UNICAST_IF` / `IPV6_UNICAST_IF`.

**There is a byte-order asymmetry between the two, and it is documented.** For
IPv4:

> The input value for setting this option is a 4-byte IPv4 address in network
> byte order. This DWORD parameter must be an interface index in network byte
> order.
>
> — [IPPROTO_IP socket options](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options)

For IPv6:

> The input value for setting this option is a 4-byte interface index of the
> desired outgoing interface in host byte order.
>
> — [IPPROTO_IPV6 socket options](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ipv6-socket-options)

So: **IPv4 set takes network byte order, IPv6 set takes host byte order**, and
both *get* in host byte order. Byte-swapping one and not the other is the
classic "why doesn't binding work" bug.

```csharp
[UnmanagedCallersOnly]
private static int Protect(IntPtr context, long socket)
{
    try
    {
        var handle = (IntPtr)socket;                 // a SOCKET, not an fd
        var index = PhysicalInterfaceIndex;          // from GetAdaptersAddresses

        // IPv4: network byte order. IPv6: host byte order. Not a typo.
        var v4 = IPAddress.HostToNetworkOrder((int)index);
        if (setsockopt(handle, IPPROTO_IP, IP_UNICAST_IF, ref v4, 4) != 0) return -1;

        var v6 = (int)index;
        if (setsockopt(handle, IPPROTO_IPV6, IPV6_UNICAST_IF, ref v6, 4) != 0) return -1;
        return 0;
    }
    catch { return -1; }
}
```

Set both: Boreas may open either family and the socket is handed to you before
its family is fixed by a connect.

Get the physical interface index from `GetAdaptersAddresses`, and re-read it
when the adapter set changes — a laptop moving from Wi-Fi to Ethernet changes
it.

## Putting it together

```csharp
var config = new BoreasConfig
{
    Egress = 0,                              // direct
    NatBehavior = 2,                         // conservative
    Resolver = Utf8("1.1.1.1:53"),
    Lists = listsArray, ListCount = (nuint)lists.Length,
    Mtu = (ushort)Mtu,
    Ceilings = default,                      // all zero: defaults
};

IntPtr handle;
var status = Boreas.boreas_tunnel_start(&config, &device, &bypass, &handle);
if (status != BoreasStatus.Ok) throw new BoreasException(status);

var reader = new Thread(() => ReadEvents(handle)) { IsBackground = false };
reader.Start();

// ... later, from anywhere ...
Boreas.boreas_tunnel_shutdown(handle);       // releases the reader
reader.Join();                                // yours
Boreas.boreas_tunnel_free(handle);            // reclaims
// Only now: release ran. End the Wintun session and close the adapter.
```

```csharp
private static unsafe void ReadEvents(IntPtr handle)
{
    var name = stackalloc byte[256];
    var rule = stackalloc byte[256];
    BoreasEvent e;
    while (Boreas.boreas_tunnel_next_event(handle, &e, name, 256, rule, 256)
           == BoreasStatus.Ok)
    {
        switch (e.Kind)
        {
            case 0: OnResolved(Marshal.PtrToStringUTF8((IntPtr)name)!, e.Blocked); break;
            case 1: OnReloaded(e.Allowed, e.BlockedRules); break;
            case 2: OnCounters(e.Counters); break;
        }
    }
    // Loop ended: BOREAS_STOPPED. Normal.
}
```

Run the reader on a dedicated `Thread`, not the thread pool. It blocks
indefinitely and would occupy a pool thread for the life of the tunnel.

## The root certificate

Two calls — size, then fill:

```csharp
nuint certLen = 0, keyLen = 0;
Boreas.boreas_tunnel_authority(handle, null, 0, &certLen, null, 0, &keyLen);
if (certLen == 0) return;                     // this tunnel does not intercept

var cert = new byte[certLen];
var keys = new byte[keyLen];
fixed (byte* c = cert, k = keys)
    Boreas.boreas_tunnel_authority(handle, c, certLen, &certLen, k, keyLen, &keyLen);
```

- **The certificate is public**, DER. Install it in the current user's `ROOT`
  store via `X509Store`.
- **The keys are secret.** Protect them with DPAPI (`ProtectedData.Protect`,
  `DataProtectionScope.CurrentUser`) before writing them anywhere.

Hand both back next launch through `RootCertificate` / `AuthorityKeys`. See
[lifecycle.md](lifecycle.md#the-one-thing-you-persist) for what the two failure
modes mean.

## Checklist

- [ ] `boreas.dll` and the official signed `wintun.dll`, per architecture
- [ ] `[LibraryImport]`, no calling convention on x64/ARM64
- [ ] **Every `bool` field is `[MarshalAs(UnmanagedType.U1)]`**
- [ ] Every `size_t` is `nuint`, never `uint`
- [ ] Strings are UTF-8
- [ ] Callbacks are `[UnmanagedCallersOnly]` + `&Method`, each body in
      `try`/`catch`
- [ ] **No callback blocks for more than ~100 ms** — return `0` from `recv`
      instead
- [ ] The Wintun read waits on `[readWaitEvent, yourQuitEvent]` with a timeout,
      and `close` signals the quit event
- [ ] Adapter MTU set through IP Helper, and equal to `BoreasConfig.Mtu`
- [ ] `protect` sets IPv4 in **network** byte order and IPv6 in **host** byte
      order
- [ ] Events read on a dedicated `Thread`, not the pool
- [ ] Teardown is shutdown → join → free, and Wintun ends after that
- [ ] CA keys under DPAPI, certificate in the `ROOT` store
