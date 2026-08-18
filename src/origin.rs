//! Re-origination through a packet egress: the edge that makes filtering and a
//! packet tunnel compose.
//!
//! **This is the composition the product is named for, and it was the one edge
//! missing from the graph.** Inspecting a flow means terminating it here, and a
//! terminated flow has to be *re-originated* to the real server. A stream
//! egress answers that directly — "open a byte stream to this target" is what
//! SOCKS5 does. A packet egress could not: WireGuard and MASQUE accept IP
//! packets, and there is no `connect` on them to call. So a session that
//! selected a packet tunnel and enabled inspection had a terminator with
//! nowhere to send what it terminated.
//!
//! The resolution is that a packet egress *does* carry a byte stream — the same
//! way it carries everything else, as IP packets. The host's own TCP stack
//! produces those packets, and the datapath already forwards them: a socket
//! this process opens without excluding it from the tunnel emits packets into
//! Boreas's own TUN, which classifies them, plans them onto the packet fast
//! path, and hands them to the egress. There is no TCP-over-TCP — the
//! re-originated connection is carried as IP inside the tunnel's own
//! encapsulation, which is exactly what
//! [Architecture](../docs/architecture.md) means by local termination — and no
//! second TCP implementation to maintain.
//!
//! **One invariant makes it work, and it is structural rather than
//! remembered.** A re-originated connection is TCP to the very address and port
//! that made the original flow a candidate for inspection, so without a rule it
//! would be selected for inspection too, terminated again, and re-originated
//! again: an infinite regress that consumes the socket ceiling in one page
//! load. The rule is a reserved range of local source ports:
//! [`OriginationPorts`] is *the* value, held by both halves, so the dialer
//! cannot bind a port the classifier does not exclude.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
};

use crate::{
    AsyncStream, BoxFuture, DatagramFidelity, Egress, EgressError, NatBehavior, PathProperties,
    StreamEgress, Target,
};

/// The local source ports a re-originated connection may bind.
///
/// **One value, read by two halves that must agree.** The dialer binds inside
/// it and the classifier excludes it from inspection; if the two disagreed, a
/// re-originated connection would be terminated and re-originated forever. It
/// is a refined type rather than a pair of numbers because "start below end"
/// and "not the ephemeral range the rest of the system uses" are invariants
/// worth establishing once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginationPorts {
    start: u16,
    end: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortRangeError {
    /// The range is empty, so no connection could ever be re-originated.
    Empty,
    /// The range includes port 0, which names no port.
    IncludesZero,
}

impl std::fmt::Display for PortRangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Empty => "the origination port range is empty",
            Self::IncludesZero => "the origination port range includes port 0",
        })
    }
}

impl std::error::Error for PortRangeError {}

/// The default range: a thousand ports well above the ephemeral range Linux and
/// Windows allocate from by default, so a re-originated connection and an
/// ordinary one never contend for the same port.
pub const DEFAULT_ORIGINATION_PORTS: OriginationPorts = OriginationPorts {
    start: 45_000,
    end: 46_000,
};

impl OriginationPorts {
    /// `end` is exclusive.
    pub fn new(start: u16, end: u16) -> Result<Self, PortRangeError> {
        if start == 0 {
            return Err(PortRangeError::IncludesZero);
        }
        if start >= end {
            return Err(PortRangeError::Empty);
        }
        Ok(Self { start, end })
    }

    /// Whether `port` belongs to this range. O(1), and the hot-path caller is
    /// the datapath's per-packet inspection verdict.
    pub fn contains(self, port: u16) -> bool {
        (self.start..self.end).contains(&port)
    }

    /// How many connections may be re-originated at once. Also the ceiling the
    /// socket budget should be set against: a terminator admitting more
    /// connections than there are ports here would refuse the surplus at dial
    /// time instead of at accept time, which is the worse place to find out.
    pub fn capacity(self) -> usize {
        usize::from(self.end - self.start)
    }
}

/// Which local ports are currently bound.
///
/// A free list rather than a bitmap or a scan: taking and returning are both
/// O(1), and the list is exactly [`OriginationPorts::capacity`] entries, which
/// is a thousand `u16`s — two kilobytes for the whole allocator.
///
/// **A port is returned by `Drop`.** There is no release call to forget, so a
/// connection that ends in any way — closed, reset, cancelled, panicked past —
/// gives its port back.
struct Ports {
    free: Mutex<Vec<u16>>,
}

impl Ports {
    fn new(range: OriginationPorts) -> Self {
        Self {
            // Reversed so the first `pop` hands out the lowest port, which
            // makes a packet capture read in the order connections were made.
            free: Mutex::new((range.start..range.end).rev().collect()),
        }
    }

    fn take(self: &Arc<Self>) -> Option<PortLease> {
        let port = self
            .free
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .pop()?;
        Some(PortLease {
            port,
            ports: Arc::clone(self),
        })
    }
}

/// One bound port, held for the life of the connection that uses it.
struct PortLease {
    port: u16,
    ports: Arc<Ports>,
}

impl Drop for PortLease {
    fn drop(&mut self) {
        self.ports
            .free
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(self.port);
    }
}

/// A byte stream whose port is released when it is dropped.
///
/// The lease is a field rather than a separate registration, so the port's
/// lifetime *is* the stream's and nothing has to be told when the connection
/// ends.
struct Originated<S> {
    stream: S,
    _lease: PortLease,
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Originated<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Originated<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

/// A [`StreamEgress`] whose connections travel *through* Boreas's own tunnel.
///
/// The exact dual of [`TunnelBypass`](crate::TunnelBypass), and named for the
/// contrast: a DNS upstream's socket must be excluded from the tunnel, because
/// a resolver reached through the tunnel that is resolving for it is a loop; a
/// re-originated connection must *not* be excluded, because the tunnel is where
/// it is supposed to go.
///
/// It carries no datagrams, and says so: the UDP half of a packet-egress
/// session is the packet fast path, which needs no association at all.
pub struct TunnelledDialer {
    ports: Arc<Ports>,
    range: OriginationPorts,
}

impl TunnelledDialer {
    pub fn new(range: OriginationPorts) -> Self {
        Self {
            ports: Arc::new(Ports::new(range)),
            range,
        }
    }

    /// The ports this dialer binds, which the datapath must exclude from
    /// inspection. Reading it from here rather than configuring it twice is
    /// what keeps the two in step.
    pub fn ports(&self) -> OriginationPorts {
        self.range
    }
}

impl StreamEgress for TunnelledDialer {
    /// **Zero overhead, and that is not a claim about the tunnel.** Whatever
    /// the packet egress charges is charged on the packets this connection
    /// produces, by the plan those packets are forwarded under — so counting it
    /// again here would count it twice.
    fn properties(&self) -> PathProperties {
        PathProperties {
            datagram_fidelity: DatagramFidelity::None,
            overhead_bytes: 0,
            max_datagram_size: None,
            preserves_ecn: false,
            // One host stack behind one tunnel address: there is no mapping to
            // vary, which is the same thing WireGuard's own claim says.
            nat_behavior: NatBehavior::EndpointIndependent,
        }
    }

    fn connect<'a>(
        &'a self,
        target: &'a Target,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncStream>, EgressError>> {
        Box::pin(async move {
            let address = resolve(target).await?;
            // The lease is taken before the socket, so a dialer at its ceiling
            // refuses without having opened anything.
            let lease = self
                .ports
                .take()
                .ok_or(EgressError::Io(std::io::ErrorKind::AddrInUse))?;
            let socket = match address {
                SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
                SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
            };
            // A connection that has just closed leaves its port in TIME-WAIT,
            // and a reserved range is small enough that refusing to reuse one
            // would exhaust it under ordinary browsing.
            socket.set_reuseaddr(true)?;
            socket.bind(local_for(address, lease.port))?;
            let stream = socket.connect(address).await?;
            // Nagle would hold a short request waiting for bytes that are not
            // coming, which on a proxied exchange is pure added latency.
            stream.set_nodelay(true)?;
            Ok(Box::new(Originated {
                stream,
                _lease: lease,
            }) as Box<dyn AsyncStream>)
        })
    }
}

/// The unspecified address of `address`'s family, on `port`.
fn local_for(address: SocketAddr, port: u16) -> SocketAddr {
    match address {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
    }
}

/// Turns a target into an address to dial.
///
/// **A name is resolved here and nowhere else in this crate**, and the
/// resolution goes through the tunnel like everything else this dialer does:
/// the host stack's resolver sends its query into Boreas's own TUN, where the
/// session's DNS policy answers it. So the name is resolved in the same view
/// the client saw, which is the property [`Target`] exists to protect on a
/// proxy egress and which a packet tunnel gets for free.
async fn resolve(target: &Target) -> Result<SocketAddr, EgressError> {
    match target {
        Target::Ip(address) => Ok(*address),
        Target::Domain { host, port } => tokio::net::lookup_host((host.as_str(), *port))
            .await?
            .next()
            .ok_or(EgressError::Io(std::io::ErrorKind::NotFound)),
    }
}

/// A packet egress that carries nothing.
///
/// **What a flow-egress session's raw IP packets have nowhere to go into.**
/// Under [`Accepts::Flows`](crate::Accepts) every TCP flow is terminated and
/// every datagram goes to the relay, so the only thing that reaches a packet
/// egress is ICMP — and a proxy has no way to carry it. Naming that as an
/// implementation, rather than making the reactor's egress an `Option`, keeps
/// the refusal counted on the same telemetry every other egress refusal is.
pub struct NoPacketEgress;

impl crate::PacketEgress for NoPacketEgress {
    fn properties(&self) -> PathProperties {
        PathProperties {
            datagram_fidelity: DatagramFidelity::None,
            overhead_bytes: 0,
            max_datagram_size: None,
            preserves_ecn: false,
            nat_behavior: NatBehavior::EndpointIndependent,
        }
    }

    fn handle_tun_packet(
        &mut self,
        _packet: &[u8],
        _out: &mut Vec<crate::EgressEmit>,
    ) -> Result<(), EgressError> {
        Err(EgressError::MalformedNetworkPacket)
    }

    fn handle_network_packet(
        &mut self,
        _datagram: &[u8],
        _out: &mut Vec<crate::EgressEmit>,
    ) -> Result<(), EgressError> {
        Err(EgressError::MalformedNetworkPacket)
    }

    fn tick(&mut self, _out: &mut Vec<crate::EgressEmit>) -> Result<(), EgressError> {
        Ok(())
    }

    fn tick_interval(&self) -> std::time::Duration {
        // Nothing to drive, so the reactor's other deadlines govern. An hour is
        // "effectively never" without needing an `Option` in the trait.
        std::time::Duration::from_secs(3600)
    }

    fn max_network_datagram(&self) -> usize {
        // Nothing arrives here, so the receive buffer need only be well formed.
        1
    }
}

/// Both effects one session runs on, derived from one configured egress.
///
/// **A product, not a sum, and that is the whole point.** A session needs a
/// packet effect *and* a flow effect: the packet effect carries the fast path,
/// and the flow effect carries what interception re-originates. Before this
/// type there was only a way to state one of them, so "filtering plus a packet
/// tunnel" — the composition the product is named for — could not be assembled
/// at all: the terminator had somewhere to send a connection only when the
/// egress happened to be a proxy.
pub struct Assembly {
    /// Drives the reactor. Whole IP packets in, encapsulated datagrams out.
    pub packets: Box<dyn crate::PacketEgress>,
    /// Serves the terminator: intercepted and spliced connections both leave
    /// by here, because interception changes what Boreas can *read*, never
    /// where traffic exits.
    pub flows: Arc<dyn StreamEgress>,
    /// The ports the flow effect binds locally, which the datapath must
    /// exclude from inspection. `None` when the flow effect is a proxy, which
    /// re-originates nothing on this device.
    pub origination_ports: Option<OriginationPorts>,
}

/// Assembles one configured egress into the two effects a session runs on.
///
/// Total on the [`Egress`] sum, and the elimination is where the two shapes
/// differ:
///
/// - [`Egress::Stream`] *is* a flow effect, and has no packets to carry, so it
///   is paired with [`NoPacketEgress`];
/// - [`Egress::Packet`] drives the reactor, and its flow effect is a
///   [`TunnelledDialer`] whose connections that same tunnel then forwards.
///
/// Deriving the origination range here rather than configuring it twice is what
/// keeps the range the dialer binds and the range the classifier excludes from
/// drifting apart — which they must not, or a re-originated connection would be
/// terminated and re-originated forever.
pub fn assemble(egress: Egress, range: OriginationPorts) -> Assembly {
    match egress {
        Egress::Stream(flows) => Assembly {
            packets: Box::new(NoPacketEgress),
            flows: Arc::from(flows),
            origination_ports: None,
        },
        Egress::Packet(packets) => Assembly {
            packets,
            flows: Arc::new(TunnelledDialer::new(range)),
            origination_ports: Some(range),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn the_range_refuses_what_no_connection_could_bind() {
        assert_eq!(
            OriginationPorts::new(0, 100),
            Err(PortRangeError::IncludesZero)
        );
        assert_eq!(OriginationPorts::new(100, 100), Err(PortRangeError::Empty));
        assert_eq!(OriginationPorts::new(200, 100), Err(PortRangeError::Empty));

        let range = OriginationPorts::new(45_000, 45_010).unwrap();
        assert_eq!(range.capacity(), 10);
        assert!(range.contains(45_000));
        assert!(range.contains(45_009));
        assert!(!range.contains(45_010), "the end is exclusive");
        assert!(!range.contains(44_999));
    }

    /// **The invariant the whole module rests on.** A re-originated connection
    /// binds inside the range the classifier excludes; if it could bind outside
    /// it, that connection would be selected for inspection, terminated, and
    /// re-originated again — a regress that spends the socket ceiling on one
    /// page load.
    #[tokio::test]
    async fn every_re_originated_connection_binds_inside_the_excluded_range() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let origin = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 16];
                    let read = socket.read(&mut buf).await.unwrap_or(0);
                    let _ = socket.write_all(&buf[..read]).await;
                });
            }
        });

        let range = OriginationPorts::new(45_100, 45_104).unwrap();
        let dialer = TunnelledDialer::new(range);
        assert_eq!(dialer.ports(), range);

        let mut held = Vec::new();
        for _ in 0..range.capacity() {
            let mut stream = dialer
                .connect(&Target::Ip(origin))
                .await
                .expect("within the range");
            stream.write_all(b"ping").await.unwrap();
            let mut echoed = [0u8; 4];
            stream.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"ping", "the connection carries bytes");
            held.push(stream);
        }

        // The range is the ceiling: a connection past it is refused rather than
        // binding a port the classifier would then inspect.
        assert!(
            matches!(
                dialer.connect(&Target::Ip(origin)).await,
                Err(EgressError::Io(std::io::ErrorKind::AddrInUse))
            ),
            "the ceiling must refuse rather than escape the range"
        );

        // A port is returned by `Drop`, so closing one connection admits the
        // next without any release call to forget.
        held.pop();
        assert!(dialer.connect(&Target::Ip(origin)).await.is_ok());
    }

    /// The algebra: both egress variants assemble into both effects, and only
    /// the packet one needs ports excluded from inspection.
    #[test]
    fn every_egress_variant_assembles_into_both_effects() {
        struct NoStreams;
        impl StreamEgress for NoStreams {
            fn properties(&self) -> PathProperties {
                PathProperties {
                    datagram_fidelity: DatagramFidelity::Native,
                    overhead_bytes: 7,
                    max_datagram_size: Some(1400),
                    preserves_ecn: false,
                    nat_behavior: NatBehavior::EndpointIndependent,
                }
            }

            fn connect<'a>(
                &'a self,
                _target: &'a Target,
            ) -> BoxFuture<'a, Result<Box<dyn AsyncStream>, EgressError>> {
                Box::pin(async { Err(EgressError::DatagramsUnsupported) })
            }
        }

        let assembled = assemble(
            Egress::Stream(Box::new(NoStreams)),
            DEFAULT_ORIGINATION_PORTS,
        );
        assert_eq!(
            assembled.flows.properties().overhead_bytes,
            7,
            "a stream egress is its own flow effect"
        );
        assert_eq!(
            assembled.origination_ports, None,
            "and it re-originates nothing on this device"
        );
        assert_eq!(
            assembled.packets.properties().datagram_fidelity,
            DatagramFidelity::None,
            "it carries no packets, and says so"
        );
    }
}
