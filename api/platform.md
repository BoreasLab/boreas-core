# What your application must supply

Two obligations. Both are things the core is structurally unable to do, and one
of them fails silently when you skip it.

## 1. The TUN device

Implement `AsyncDevice`: read one IP packet, write one IP packet, report the
MTU.

```rust
trait AsyncDevice {
    fn mtu(&self) -> Mtu;
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    async fn send(&mut self, buf: &[u8]) -> io::Result<()>;
}
```

Boreas ships adapters for both platforms, so you should not need to write one:

- **Android** — `AndroidTun::from_owned_fd(fd, mtu)`. Hand it the descriptor
  from `VpnService.Builder.establish()`. The adapter takes ownership and closes
  it on drop; `VpnService` keeps lifecycle and permissions.
- **Windows** — `WintunDevice::from_session(session, mtu)`, over a Wintun
  session your setup path opened.

**`recv` must be cancel-safe.** The reactor selects over it and drops the future
routinely, so a dropped future must consume nothing. Both shipped adapters do
this — the Windows one holds its in-flight blocking read across calls
specifically because `spawn_blocking` cannot be cancelled and dropping the join
handle would discard a packet.

**`send` is all-or-nothing.** A short write is an error, not a success with a
count. Report it as `io::ErrorKind::WriteZero`.

### Set the MTU to the same number twice

Configure the TUN's MTU and set `Link::mtu` to that same value. The tunnel is
narrower than the link by whatever your egress encapsulates, and Boreas answers
anything in between with an ICMP Packet Too Big so the sender learns its path.
If the two numbers disagree, that answering never stops: watch
`Counters::paths_reported`, which should fall to near zero once senders converge
and stays high if you told the two sides different numbers.

## 2. Sockets that do not re-enter the tunnel

Implement `TunnelBypass`. Every socket Boreas opens for itself goes through it:
the egress's, the resolver's, and any datagram relay's.

```rust
trait TunnelBypass {
    async fn udp(&self, peer: SocketAddr) -> io::Result<UdpSocket>;   // connected
    async fn tcp(&self, peer: SocketAddr) -> io::Result<TcpStream>;
    async fn unbound(&self) -> io::Result<UdpSocket>;                 // no peer
}
```

- **Android** — call `VpnService.protect(fd)` on each socket before use.
- **Windows** — bind the physical interface's address, or set the interface
  index.

**This is the obligation that is silent when it is skipped.** An unprotected
socket works fine — until the tunnel comes up, at which point every packet it
sends re-enters the tunnel it was serving. The symptom is a resolver that hangs
and a proxy that never connects; the cause is three lines away in a different
language. `DirectSockets` is the do-nothing implementation: correct on a desktop
whose default route is not the tunnel, and the deliberate wrong answer
everywhere else.

`unbound` is required rather than defaulted for exactly this reason. A default
would be an ordinary wildcard bind, which is right on a desktop and wrong on
Android, and a required method is what makes the compiler say so.

Your bypass must be `Clone`. A tunnel needs one per thing that dials; if yours
holds a JNI handle, clone the handle.

## 3. Installing the root certificate

Only if you intercept. `tunnel.authority()` returns:

- `root_certificate` — **public**, DER. Hand it to the platform's trust
  installer. On Android, `KeyChain.createInstallIntent()` with
  `EXTRA_CERTIFICATE`; the user must approve it, and on Android 7+ apps that do
  not opt into user certificates will still refuse it. On Windows, the
  `ROOT` store for the current user.
- `keys` — **private**. Store the bytes in the Android Keystore or under DPAPI.
  Treat them as you would a password. They are opaque and self-describing;
  you never need to look inside.

Hand `keys` back as `Trust::Restore` next launch. If restoring fails you get
`CaError::Material`, which means storage lost or corrupted the key: generate a
fresh authority and ask the user to trust it again. Boreas will **not** silently
generate a replacement, because a device whose store still trusts the old root
would then intercept nothing while reporting itself healthy.

### Known limitation

The private key lives in process memory while the tunnel runs, so a rooted or
compromised device can extract it. A hardware-backed signer — the key never
leaving a TEE — is the right destination and is why `CaKeys` is opaque: adding
it will not change this interface.
