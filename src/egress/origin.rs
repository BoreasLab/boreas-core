//! Re-origination through packet egress for intercepted flows.
//!
//! A terminated flow returns to the origin through the host TCP stack. Its
//! packets enter Boreas's TUN and use packet egress, avoiding a second TCP
//! stack or TCP-over-TCP.
//!
//! [`OriginationPorts`] gives the dialer and classifier one shared range, so
//! re-originated connections avoid recursive interception.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::{
    AsyncStream, BoxFuture, DatagramFidelity, Egress, EgressError, NatBehavior, PathProperties,
    StreamEgress, Target,
};

/// Local source ports available to re-originated connections.
///
/// The dialer binds inside this range and the classifier excludes it from
/// inspection. The constructor establishes the range ordering and nonzero
/// source-port invariant once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OriginationPorts {
    start: u16,
    end: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortRangeError {
    Empty,
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

/// Default range above the usual Linux and Windows ephemeral range.
pub const DEFAULT_ORIGINATION_PORTS: OriginationPorts = OriginationPorts {
    start: 45_000,
    end: 46_000,
};

impl OriginationPorts {
    pub fn new(start: u16, end: u16) -> Result<Self, PortRangeError> {
        if start == 0 {
            return Err(PortRangeError::IncludesZero);
        }
        if start >= end {
            return Err(PortRangeError::Empty);
        }
        Ok(Self { start, end })
    }

    pub fn contains(self, port: u16) -> bool {
        (self.start..self.end).contains(&port)
    }

    pub fn capacity(self) -> usize {
        usize::from(self.end - self.start)
    }
}

/// A free list makes allocation and return constant time. `Drop` returns every
/// lease, including one released by close, reset, cancellation, or unwind.
struct Ports {
    free: Mutex<Vec<u16>>,
}

impl Ports {
    fn new(range: OriginationPorts) -> Self {
        Self {
            // Pop the lowest port first for predictable packet captures.
            free: Mutex::new((range.start..range.end).rev().collect()),
        }
    }

    fn take(self: &Arc<Self>) -> Option<PortLease> {
        let port = crate::locked(&self.free).pop()?;
        Some(PortLease {
            port,
            ports: Arc::clone(self),
        })
    }
}

struct PortLease {
    port: u16,
    ports: Arc<Ports>,
}

impl Drop for PortLease {
    fn drop(&mut self) {
        crate::locked(&self.ports.free).push(self.port);
    }
}

/// Keeps the port lease alive for the stream's lifetime.
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

/// [`StreamEgress`] whose connections travel through Boreas's tunnel.
///
/// Unlike [`TunnelBypass`](crate::TunnelBypass), this dialer must remain in the
/// tunnel. It carries no datagrams; packet egress handles the UDP fast path.
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

    pub fn ports(&self) -> OriginationPorts {
        self.range
    }
}

impl StreamEgress for TunnelledDialer {
    /// Reports no stream-level overhead because the packet plan accounts for
    /// the packets this connection produces.
    fn properties(&self) -> PathProperties {
        PathProperties {
            datagram_fidelity: DatagramFidelity::None,
            overhead_bytes: 0,
            max_datagram_size: None,
            preserves_ecn: false,
            // One host stack uses one tunnel address, so no mapping varies.
            nat_behavior: NatBehavior::EndpointIndependent,
        }
    }

    fn connect<'a>(
        &'a self,
        target: &'a Target,
    ) -> BoxFuture<'a, Result<Box<dyn AsyncStream>, EgressError>> {
        Box::pin(async move {
            // RFC 8305: every address gets a try, each a quarter second after
            // the last, and the first to connect wins. One dead AAAA no
            // longer costs the whole connect budget.
            let mut attempts = tokio::task::JoinSet::new();
            for (index, address) in resolve_all(target).await?.into_iter().enumerate() {
                let ports = Arc::clone(&self.ports);
                attempts.spawn(async move {
                    tokio::time::sleep(ATTEMPT_DELAY * index as u32).await;
                    dial(&ports, address).await
                });
            }
            let mut last = EgressError::Io(std::io::ErrorKind::NotFound);
            while let Some(joined) = attempts.join_next().await {
                match joined {
                    // Dropping the set aborts the attempts still running;
                    // their leases return with them.
                    Ok(Ok(stream)) => return Ok(stream),
                    Ok(Err(error)) => last = error,
                    Err(_) => {}
                }
            }
            Err(last)
        })
    }
}

/// RFC 8305 section 5: the next attempt starts this long after the previous.
const ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// One connection attempt from a leased port.
async fn dial(
    ports: &Arc<Ports>,
    address: SocketAddr,
) -> Result<Box<dyn AsyncStream>, EgressError> {
    // Refuse at the port ceiling before opening a socket.
    let lease = ports
        .take()
        .ok_or(EgressError::Io(std::io::ErrorKind::AddrInUse))?;
    let socket = match address {
        SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
        SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
    };
    // Allow reuse while a recently closed connection is in TIME-WAIT; the
    // reserved range is small under ordinary browsing.
    socket.set_reuseaddr(true)?;
    socket.bind(local_for(address, lease.port))?;
    let stream = crate::within(crate::Wait::TcpConnect, socket.connect(address)).await?;
    // Avoid delaying short requests for bytes that will not arrive.
    stream.set_nodelay(true)?;
    Ok(Box::new(Originated {
        stream,
        _lease: lease,
    }) as Box<dyn AsyncStream>)
}

/// Every address for `target`, families interleaved (RFC 8305 section 4).
async fn resolve_all(target: &Target) -> Result<Vec<SocketAddr>, EgressError> {
    match target {
        Target::Ip(address) => Ok(vec![*address]),
        Target::Domain { host, port } => {
            let all: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), *port))
                .await?
                .collect();
            if all.is_empty() {
                return Err(EgressError::Io(std::io::ErrorKind::NotFound));
            }
            Ok(interleaved(all))
        }
    }
}

/// IPv6 first, then the families alternate, each in resolver order.
fn interleaved(addresses: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let (v6, v4): (Vec<SocketAddr>, Vec<SocketAddr>) =
        addresses.into_iter().partition(SocketAddr::is_ipv6);
    let (mut v6, mut v4) = (v6.into_iter(), v4.into_iter());
    let mut out = Vec::new();
    loop {
        match (v6.next(), v4.next()) {
            (None, None) => break,
            (six, four) => out.extend(six.into_iter().chain(four)),
        }
    }
    out
}

fn local_for(address: SocketAddr, port: u16) -> SocketAddr {
    match address {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
    }
}

/// Name resolution occurs through the tunnel, so the host stack sees the same
/// DNS policy and view as the client.
pub(crate) async fn resolve(target: &Target) -> Result<SocketAddr, EgressError> {
    match target {
        Target::Ip(address) => Ok(*address),
        Target::Domain { host, port } => tokio::net::lookup_host((host.as_str(), *port))
            .await?
            .next()
            .ok_or(EgressError::Io(std::io::ErrorKind::NotFound)),
    }
}

/// Packet egress placeholder for a flow-only session.
///
/// Flow egress carries TCP and UDP associations directly, so no raw packet
/// operation is available. This implementation preserves uniform reactor
/// errors and telemetry.
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
        // Nothing needs driving; let other reactor deadlines govern.
        std::time::Duration::from_secs(3600)
    }

    fn max_network_datagram(&self) -> usize {
        // No datagram arrives here; one byte is enough for a valid buffer.
        1
    }
}

/// The packet and flow effects derived from one configured egress.
pub struct Assembly {
    /// Drives the reactor with whole IP packets and emits encapsulated datagrams.
    pub packets: Box<dyn crate::PacketEgress>,
    /// Carries intercepted and spliced connections to their egress.
    pub flows: Arc<dyn StreamEgress>,
    /// Local ports the datapath excludes from inspection, or `None` for a proxy
    /// flow effect that re-originates nothing locally.
    pub origination_ports: Option<OriginationPorts>,
}

/// Splits one configured egress into the packet and flow effects.
///
/// Stream egress pairs with [`NoPacketEgress`]. Packet egress drives the reactor
/// and uses a [`TunnelledDialer`] for re-originated flows. The shared range
/// keeps dialing and inspection exclusion aligned.
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

    /// RFC 8305 section 4: IPv6 first, then the families alternate.
    #[test]
    fn addresses_are_interleaved_by_family_with_ipv6_first() {
        let v4 = |last: u8| SocketAddr::from(([192, 0, 2, last], 443));
        let v6 = |last: u16| SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, last], 443));
        assert_eq!(
            interleaved(vec![v4(1), v4(2), v6(1), v4(3), v6(2)]),
            vec![v6(1), v4(1), v6(2), v4(2), v4(3)]
        );
        assert_eq!(interleaved(vec![v4(1)]), vec![v4(1)]);
        assert!(interleaved(Vec::new()).is_empty());
    }

    /// A name whose first address refuses is still reached through its next.
    #[tokio::test]
    async fn a_dead_first_address_does_not_fail_the_connect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let dialer = TunnelledDialer::new(OriginationPorts::new(46_000, 46_010).unwrap());
        // `localhost` commonly resolves to ::1 first, where nothing listens.
        let target = Target::Domain {
            host: crate::DomainName::new("localhost").unwrap(),
            port,
        };
        let connected = tokio::time::timeout(Duration::from_secs(5), dialer.connect(&target))
            .await
            .expect("well inside the budget");
        assert!(connected.is_ok(), "{:?}", connected.err());
        let (_accepted, from) = listener.accept().await.unwrap();
        assert!(
            OriginationPorts::new(46_000, 46_010)
                .unwrap()
                .contains(from.port())
        );
    }

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

        assert!(
            matches!(
                dialer.connect(&Target::Ip(origin)).await,
                Err(EgressError::Io(std::io::ErrorKind::AddrInUse))
            ),
            "the ceiling must refuse rather than escape the range"
        );

        held.pop();
        assert!(dialer.connect(&Target::Ip(origin)).await.is_ok());
    }

    /// Packet egress adds excluded origination ports; stream egress does not.
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
