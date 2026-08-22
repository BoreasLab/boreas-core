# Rust

The same tunnel, without the C boundary in between. Everything on this page is
the `boreas_core::api` module.

If you are writing Kotlin or C#, you want [android.md](android.md) or
[windows.md](windows.md) instead — this page describes two Rust traits, and
neither language can implement one.

## The shape of it

```rust
use boreas_core::api::*;

let mut tunnel = Tunnel::start(
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

while let Some(event) = tunnel.next_event().await { /* ... */ }
tunnel.stop().await?;
```

`Tunnel::start` spawns everything on the current Tokio runtime. Dropping a
`Tunnel` does **not** stop it; the tasks own their own handles and keep running
until the process ends.

Config fields are documented in [configuration.md](configuration.md), events and
persistence in [lifecycle.md](lifecycle.md). The obligations in
[obligations.md](obligations.md) apply here too — they are the same two
obligations, described in the language the core is written in.

## The two obligations

### 1. A TUN device

```rust
trait AsyncDevice {
    fn mtu(&self) -> Mtu;
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    async fn send(&mut self, buf: &[u8]) -> io::Result<()>;
}
```

Adapters ship for both platforms, so you should not need to write one:

- **Android** — `AndroidTun::from_owned_fd(fd, mtu)`. Hand it the descriptor
  from `VpnService.Builder.establish()`. The adapter takes ownership and closes
  it on drop. **The descriptor must already be non-blocking**; `establish`
  returns one that is not, so set `O_NONBLOCK` before handing it over. Must be
  constructed on a Tokio runtime.
- **Windows** — `WintunDevice::from_session(session, mtu)`, over a Wintun
  session your setup path opened.

**`recv` must be cancel-safe.** The reactor selects over it and drops the future
routinely, so a dropped future must consume nothing. A readiness-based read over
an OS handle satisfies this, as does awaiting a channel; an adapter that
dequeues before awaiting does not. Both shipped adapters do it — the Windows one
holds its in-flight blocking read across calls specifically because
`spawn_blocking` cannot be cancelled and dropping the join handle would discard
a packet.

**`send` is all-or-nothing.** A short write is an error, not a success with a
count. Report it as `io::ErrorKind::WriteZero`.

### 2. Sockets that do not re-enter the tunnel

```rust
trait TunnelBypass: Clone {
    async fn udp(&self, peer: SocketAddr) -> io::Result<UdpSocket>;   // connected
    async fn tcp(&self, peer: SocketAddr) -> io::Result<TcpStream>;
    async fn unbound(&self) -> io::Result<UdpSocket>;                 // no peer
}
```

- **Android** — call `VpnService.protect(fd)` on each socket before use.
- **Windows** — set `IP_UNICAST_IF` and `IPV6_UNICAST_IF` to the physical
  interface index. Note the byte-order asymmetry documented in
  [windows.md](windows.md#the-bypass).

`unbound` is required rather than defaulted, deliberately: a default would be an
ordinary wildcard bind, which is correct on a desktop and silently wrong on
Android, and a required method is what makes the compiler say so.

`DirectSockets` is the do-nothing implementation — correct on a desktop whose
default route is not the tunnel, and the deliberate wrong answer everywhere
else. See [the two silent
mistakes](obligations.md#the-two-silent-mistakes).

Your bypass must be `Clone`: a tunnel needs one per thing that dials.

## Where this differs from the C ABI

The Rust API is the wider of the two. It reaches things the C ABI has not grown
yet — every proxy egress, DoT/DoH/DoQ upstreams, a custom rewriting budget,
custom origination ports. [abi.md](abi.md#what-the-abi-does-not-expose-yet) is
the list.

It is also the one with fewer promises around it. The C ABI's layout is asserted
by a test; the Rust surface follows [stability.md](stability.md) but is
versioned as ordinary Rust API, which means an added struct field is a
compilation error rather than a field you can ignore. Build with
`..Default::default()` where a `Default` exists.
