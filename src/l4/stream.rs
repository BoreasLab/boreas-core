//! Sans-IO TCP termination backed by `smoltcp`.
//!
//! The packet path handles whole IP packets, while interception needs the
//! client's connection to terminate here as an ordered byte stream. Packets
//! enter and leave as pooled buffers; time is supplied to [`LocalStack::poll`].
//! No socket, task, or clock is owned by this module.
//!
//! Any-IP lets a listener accept a SYN for an address the interface does not
//! own. The destination from that SYN becomes the connection's local endpoint.
//! The socket ceiling bounds admission: once it is reached, no listener is
//! available for another SYN and `smoltcp` refuses the connection.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::IpAddr,
    num::NonZeroUsize,
    sync::Arc,
    time::Instant,
};

use smoltcp::{
    iface::{Config, Interface, PollResult, SocketHandle, SocketSet},
    phy::{Checksum, ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp::{RecvError, SendError, Socket, SocketBuffer, State},
    time::{Duration as SmolDuration, Instant as SmolInstant},
    wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv6Address},
};

use crate::{BufferPool, InternalEndpoint, Mtu, Pooled};

/// Opaque handle for an accepted connection.
///
/// Callers can only obtain one from [`LocalStack::poll_accept`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamId(SocketHandle);

/// Accepted connection and both endpoints recovered from its SYN.
///
/// `client` is the application-side peer. `server` is the original destination
/// and supplies the host identity used by interception.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Terminated {
    pub id: StreamId,
    pub client: InternalEndpoint,
    pub server: InternalEndpoint,
}

/// Why a stream operation could not proceed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamError {
    /// The id is not live.
    Unknown,
    /// The live stream has no immediate capacity. Retry after `poll`.
    WouldBlock,
    /// The peer has closed this direction.
    Closed,
    /// The peer reset the connection: bytes in flight are lost.
    Reset,
}

/// Memory and socket bounds for the terminator.
#[derive(Clone, Copy, Debug)]
pub struct TerminationLimits {
    /// Maximum listeners plus established connections.
    pub max_sockets: NonZeroUsize,
    /// Listening sockets maintained for each intercepted port.
    pub backlog: NonZeroUsize,
    /// Receive and send bytes reserved for each connection.
    pub socket_buffer: NonZeroUsize,
}

/// A socket ceiling that cannot provide the requested port backlogs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminationError {
    /// The ceiling is below one full backlog for every port. Replenishment is
    /// ordered, so accepting a partial configuration would leave later ports
    /// without listeners and refuse their SYNs indefinitely.
    SocketsBelowBacklog {
        ports: usize,
        backlog: usize,
        ceiling: usize,
    },
}

impl std::fmt::Display for TerminationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SocketsBelowBacklog {
                ports,
                backlog,
                ceiling,
            } => write!(
                f,
                "{ports} ports at a backlog of {backlog} need {} sockets, not {ceiling}",
                ports * backlog
            ),
        }
    }
}

impl std::error::Error for TerminationError {}

/// Queue-backed `smoltcp` device.
///
/// Both queues own [`BufferPool`] loans. Incoming packets move in without a
/// copy, outgoing packets retain their capacity, and pool exhaustion withholds
/// a transmit token instead of growing unbounded state.
struct QueueDevice {
    inbound: VecDeque<Pooled>,
    outbound: VecDeque<Pooled>,
    pool: Arc<BufferPool>,
    mtu: usize,
}

struct QueueRx(Pooled);

impl RxToken for QueueRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

/// Transmit token with a buffer reserved before issuance.
///
/// `smoltcp` treats an issued token as a promise that transmission can happen,
/// so the pool budget is checked before the token is returned.
struct QueueTx<'a> {
    buffer: Pooled,
    outbound: &'a mut VecDeque<Pooled>,
}

impl TxToken for QueueTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(mut self, len: usize, f: F) -> R {
        // The advertised MTU is bounded by the pool slice size.
        debug_assert!(len <= self.buffer.capacity_hint());
        let _ = self.buffer.resize(len);
        let result = f(&mut self.buffer);
        self.outbound.push_back(self.buffer);
        result
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = QueueRx;
    type TxToken<'a> = QueueTx<'a>;

    fn receive(&mut self, _now: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Reserve the reply buffer before removing an inbound packet.
        let buffer = self.pool.take_zeroed(0)?;
        let packet = self.inbound.pop_front()?;
        Some((
            QueueRx(packet),
            QueueTx {
                buffer,
                outbound: &mut self.outbound,
            },
        ))
    }

    fn transmit(&mut self, _now: SmolInstant) -> Option<Self::TxToken<'_>> {
        let buffer = self.pool.take_zeroed(0)?;
        Some(QueueTx {
            buffer,
            outbound: &mut self.outbound,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        // There is no hardware checksum offload behind this device.
        let mut checksum = ChecksumCapabilities::default();
        checksum.ipv4 = Checksum::Both;
        checksum.tcp = Checksum::Both;
        checksum.icmpv4 = Checksum::Both;
        capabilities.checksum = checksum;
        capabilities
    }
}

/// A listening socket and the port it accepts on, so the pool can replenish the
/// exact port a connection consumed.
struct Listener {
    handle: SocketHandle,
    port: u16,
}

/// Probe an idle peer this often (RFC 1122 section 4.2.3.6), and abort a
/// connection whose peer has said nothing for this long: an unanswered
/// SYN-ACK, unacknowledged data, or a missed probe.
const KEEPALIVE: SmolDuration = SmolDuration::from_secs(30);
const TIMEOUT: SmolDuration = SmolDuration::from_secs(60);

pub struct LocalStack {
    device: QueueDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    ports: Vec<u16>,
    /// Every TCP port is terminated: a SYN to a port without a listener
    /// gets one, kept only while a SYN wants it.
    every_port: bool,
    /// SYNs pushed since the last poll to ports outside `ports`.
    wanted: HashMap<u16, usize>,
    listeners: Vec<Listener>,
    limits: TerminationLimits,
    established: HashMap<SocketHandle, (InternalEndpoint, InternalEndpoint)>,
    /// Connections this side closed or aborted, so a CLOSED socket not in
    /// here was reset by the peer.
    closing: HashSet<SocketHandle>,
    accepted: VecDeque<Terminated>,
    closed: VecDeque<Ended>,
    base: Instant,
}

impl LocalStack {
    /// The device advertises the smaller of `mtu` and the pool slice size, so
    /// every segment smoltcp creates fits its reserved buffer.
    pub fn new(
        mtu: Mtu,
        ports: &[u16],
        limits: TerminationLimits,
        pool: Arc<BufferPool>,
        base: Instant,
    ) -> Result<Self, TerminationError> {
        // Reject a partial backlog before ordered replenishment can hide it.
        if ports.len() * limits.backlog.get() > limits.max_sockets.get() {
            return Err(TerminationError::SocketsBelowBacklog {
                ports: ports.len(),
                backlog: limits.backlog.get(),
                ceiling: limits.max_sockets.get(),
            });
        }
        let carried = usize::from(mtu.get()).min(pool.slice_size().get());
        let mut device = QueueDevice {
            inbound: VecDeque::new(),
            outbound: VecDeque::new(),
            pool,
            mtu: carried,
        };

        let config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut device, SmolInstant::ZERO);
        // Placeholder addresses mark both families up; any-IP supplies the
        // destination-specific endpoint from each SYN.
        iface.set_any_ip(true);
        iface.update_ip_addrs(|addresses| {
            let _ = addresses.push(IpCidr::new(IpAddress::v4(10, 0, 0, 1), 8));
            let _ = addresses.push(IpCidr::new(IpAddress::v6(0xfd00, 0, 0, 0, 0, 0, 0, 1), 64));
        });
        // Medium::Ip has no L2 neighbour resolution. These routes select the
        // interface for replies to client addresses outside the placeholders.
        let _ = iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(10, 0, 0, 254));
        let _ = iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 0xfffe));

        let mut stack = Self {
            device,
            iface,
            sockets: SocketSet::new(Vec::new()),
            ports: ports.to_vec(),
            every_port: false,
            wanted: HashMap::new(),
            listeners: Vec::new(),
            limits,
            established: HashMap::new(),
            closing: HashSet::new(),
            accepted: VecDeque::new(),
            closed: VecDeque::new(),
            base,
        };
        stack.replenish_listeners();
        Ok(stack)
    }

    /// Terminates every TCP port, not only the configured ones. A flow
    /// egress carries arbitrary TCP; a fixed listener set answers the rest
    /// with RST.
    pub fn terminate_every_port(&mut self) {
        self.every_port = true;
    }

    pub fn push(&mut self, packet: Pooled) {
        if self.every_port
            && let Some(port) = syn_destination(&packet)
            && !self.ports.contains(&port)
        {
            let wanted = self.wanted.entry(port).or_insert(0);
            *wanted += 1;
            let wanted = *wanted;
            if self.listening(port) < wanted {
                self.add_listener(port);
            }
        }
        self.device.inbound.push_back(packet);
    }

    pub fn poll_transmit(&mut self) -> Option<Pooled> {
        self.device.outbound.pop_front()
    }

    pub fn pool(&self) -> &Arc<BufferPool> {
        &self.device.pool
    }

    pub fn poll_accept(&mut self) -> Option<Terminated> {
        self.accepted.pop_front()
    }

    pub fn poll_closed(&mut self) -> Option<Ended> {
        self.closed.pop_front()
    }

    fn now(&self, now: Instant) -> SmolInstant {
        // Treat a pre-origin timestamp as zero elapsed time.
        let millis = now.saturating_duration_since(self.base).as_millis();
        SmolInstant::from_millis(i64::try_from(millis).unwrap_or(i64::MAX))
    }

    pub fn poll(&mut self, now: Instant) {
        let now = self.now(now);
        // Continue until smoltcp reports no more state changes.
        while self.iface.poll(now, &mut self.device, &mut self.sockets)
            == PollResult::SocketStateChanged
        {}
        self.wanted.clear();
        self.harvest();
        self.replenish_listeners();
    }

    pub fn poll_at(&mut self, now: Instant) -> Option<Instant> {
        let smol_now = self.now(now);
        self.iface.poll_at(smol_now, &self.sockets).map(|at| {
            // Clamp overdue work to the current caller instant.
            let ahead = (at.total_micros() - smol_now.total_micros()).max(0);
            now + std::time::Duration::from_micros(ahead as u64)
        })
    }

    pub fn recv(&mut self, id: StreamId, buf: &mut [u8]) -> Result<usize, StreamError> {
        let socket = self.socket_mut(id)?;
        if socket.can_recv() {
            return socket.recv_slice(buf).map_err(|error| match error {
                RecvError::Finished => StreamError::Closed,
                RecvError::InvalidState => StreamError::WouldBlock,
            });
        }
        // Handshaking sockets are not closed merely because no bytes are ready.
        if socket.may_recv() || handshaking(socket.state()) {
            Err(StreamError::WouldBlock)
        } else {
            Err(ended(socket.state()))
        }
    }

    pub fn send(&mut self, id: StreamId, buf: &[u8]) -> Result<usize, StreamError> {
        let socket = self.socket_mut(id)?;
        if !socket.may_send() {
            return Err(if handshaking(socket.state()) {
                StreamError::WouldBlock
            } else {
                ended(socket.state())
            });
        }
        match socket.send_slice(buf) {
            Ok(0) => Err(StreamError::WouldBlock),
            Ok(n) => Ok(n),
            Err(SendError::InvalidState) => Err(StreamError::Closed),
        }
    }

    pub fn can_recv(&self, id: StreamId) -> bool {
        self.socket(id).is_some_and(Socket::can_recv)
    }

    pub fn can_send(&self, id: StreamId) -> bool {
        self.socket(id).is_some_and(Socket::can_send)
    }

    pub fn close(&mut self, id: StreamId) {
        if let Ok(socket) = self.socket_mut(id) {
            socket.close();
            self.closing.insert(id.0);
        }
    }

    pub fn abort(&mut self, id: StreamId) {
        if let Ok(socket) = self.socket_mut(id) {
            socket.abort();
            self.closing.insert(id.0);
        }
    }

    pub fn socket_count(&self) -> usize {
        self.listeners.len() + self.established.len()
    }

    fn socket(&self, id: StreamId) -> Option<&Socket<'static>> {
        self.established
            .contains_key(&id.0)
            .then(|| self.sockets.get::<Socket>(id.0))
    }

    fn socket_mut(&mut self, id: StreamId) -> Result<&mut Socket<'static>, StreamError> {
        if !self.established.contains_key(&id.0) {
            return Err(StreamError::Unknown);
        }
        Ok(self.sockets.get_mut::<Socket>(id.0))
    }

    fn harvest(&mut self) {
        // A listener stays one through the handshake; only a completed
        // handshake is a connection (RFC 9293 section 3.10.1). One that
        // timed out in SYN-RECEIVED is closed and goes back to the budget.
        let mut converted = Vec::new();
        self.listeners.retain(|listener| {
            let socket = self.sockets.get::<Socket>(listener.handle);
            if matches!(socket.state(), State::Listen | State::SynReceived) {
                return true;
            }
            converted.push(listener.handle);
            false
        });
        for handle in converted {
            let socket = self.sockets.get::<Socket>(handle);
            // A socket that closed before it was established never became a
            // usable stream.
            let (Some(client), Some(server)) = (socket.remote_endpoint(), socket.local_endpoint())
            else {
                self.sockets.remove(handle);
                continue;
            };
            let terminated = Terminated {
                id: StreamId(handle),
                client: endpoint(client.addr.into(), client.port),
                server: endpoint(server.addr.into(), server.port),
            };
            self.established
                .insert(handle, (terminated.client, terminated.server));
            self.accepted.push_back(terminated);
        }

        // Remove closed sockets so their buffers and budget are released.
        // TIME-WAIT stays until smoltcp closes it, so a retransmitted FIN
        // meets the socket and not an RST (RFC 9293 section 3.6.1).
        let mut finished = Vec::new();
        for &handle in self.established.keys() {
            if self.sockets.get::<Socket>(handle).state() == State::Closed {
                finished.push(handle);
            }
        }
        for handle in finished {
            self.established.remove(&handle);
            self.sockets.remove(handle);
            let reset = !self.closing.remove(&handle);
            self.closed.push_back(Ended {
                id: StreamId(handle),
                reset,
            });
        }
    }

    /// Listeners on `port` still waiting for a SYN.
    fn listening(&self, port: u16) -> usize {
        self.listeners
            .iter()
            .filter(|l| {
                l.port == port && self.sockets.get::<Socket>(l.handle).state() == State::Listen
            })
            .count()
    }

    fn replenish_listeners(&mut self) {
        for index in 0..self.ports.len() {
            let port = self.ports[index];
            for _ in self.listening(port)..self.limits.backlog.get() {
                if !self.add_listener(port) {
                    return;
                }
            }
        }
    }

    /// One more listener on `port`, unless the budget is spent.
    fn add_listener(&mut self, port: u16) -> bool {
        if self.socket_count() >= self.limits.max_sockets.get() {
            return false;
        }
        let rx = SocketBuffer::new(vec![0u8; self.limits.socket_buffer.get()]);
        let tx = SocketBuffer::new(vec![0u8; self.limits.socket_buffer.get()]);
        let mut socket = Socket::new(rx, tx);
        socket.set_keep_alive(Some(KEEPALIVE));
        socket.set_timeout(Some(TIMEOUT));
        // An addressless listener accepts any destination under any-IP.
        if socket.listen(port).is_err() {
            return false;
        }
        let handle = self.sockets.add(socket);
        self.listeners.push(Listener { handle, port });
        true
    }
}

/// The destination port of a TCP SYN, read straight off the headers; any
/// other packet, or one behind IPv6 extension headers, is `None`.
fn syn_destination(packet: &[u8]) -> Option<u16> {
    let tcp_at = match packet.first()? >> 4 {
        4 if packet.get(9) == Some(&6) => usize::from(packet[0] & 0x0f) * 4,
        6 if packet.get(6) == Some(&6) => 40,
        _ => return None,
    };
    let header = packet.get(tcp_at..tcp_at + 14)?;
    // SYN set, ACK clear: an open, not the last step of one.
    (header[13] & 0x12 == 0x02).then(|| u16::from_be_bytes([header[2], header[3]]))
}

fn endpoint(address: IpAddr, port: u16) -> InternalEndpoint {
    InternalEndpoint { address, port }
}

/// A reaped connection: closed by both sides, or reset by the peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ended {
    pub id: StreamId,
    pub reset: bool,
}

/// How a connection that can no longer carry bytes ended. A socket in
/// CLOSED that was never closed by us was reset or timed out; every orderly
/// end passes through a FIN state first.
fn ended(state: State) -> StreamError {
    if state == State::Closed {
        StreamError::Reset
    } else {
        StreamError::Closed
    }
}

/// Whether the connection is still before `ESTABLISHED`.
///
/// Accepted sockets can remain in `SYN-RECEIVED`, where both capability checks
/// are false. Inspecting the state keeps that condition distinct from a closed
/// stream.
fn handshaking(state: State) -> bool {
    matches!(state, State::Listen | State::SynSent | State::SynReceived)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use smoltcp::wire::IpEndpoint;
    use std::{
        net::Ipv4Addr,
        time::{Duration, Instant},
    };

    const MTU: u16 = 1500;
    const SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 5);
    const HTTPS: u16 = 443;

    fn mtu() -> Mtu {
        Mtu::new(MTU).unwrap()
    }

    fn pool() -> Arc<BufferPool> {
        BufferPool::new(
            NonZeroUsize::new(usize::from(MTU)).unwrap(),
            NonZeroUsize::new(256).unwrap(),
        )
    }

    fn stack(ports: &[u16], limits: TerminationLimits, base: Instant) -> LocalStack {
        LocalStack::new(mtu(), ports, limits, pool(), base).expect("the fixture fits")
    }

    #[test]
    fn a_ceiling_that_cannot_hold_a_backlog_per_port_is_refused() {
        assert_eq!(
            LocalStack::new(mtu(), &[80, 443], limits(4, 4), pool(), Instant::now()).err(),
            Some(TerminationError::SocketsBelowBacklog {
                ports: 2,
                backlog: 4,
                ceiling: 4,
            })
        );
        // The exact required ceiling gives both ports their full backlog.
        let stack = LocalStack::new(mtu(), &[80, 443], limits(8, 4), pool(), Instant::now())
            .expect("eight sockets hold two backlogs of four");
        for port in [80, 443] {
            assert_eq!(
                stack.listeners.iter().filter(|l| l.port == port).count(),
                4,
                "port {port} must get its whole backlog"
            );
        }
    }

    fn limits(max_sockets: usize, backlog: usize) -> TerminationLimits {
        TerminationLimits {
            max_sockets: NonZeroUsize::new(max_sockets).unwrap(),
            backlog: NonZeroUsize::new(backlog).unwrap(),
            socket_buffer: NonZeroUsize::new(8192).unwrap(),
        }
    }

    fn v4(address: Ipv4Addr, port: u16) -> InternalEndpoint {
        InternalEndpoint {
            address: IpAddr::V4(address),
            port,
        }
    }

    pub(crate) struct Client {
        device: QueueDevice,
        iface: Interface,
        sockets: SocketSet<'static>,
        handle: SocketHandle,
        ms: u64,
    }

    impl Client {
        pub(crate) fn connect(
            source: Ipv4Addr,
            local_port: u16,
            server: Ipv4Addr,
            server_port: u16,
        ) -> Self {
            let mut device = QueueDevice {
                inbound: VecDeque::new(),
                outbound: VecDeque::new(),
                pool: pool(),
                mtu: usize::from(MTU),
            };
            let config = Config::new(HardwareAddress::Ip);
            let mut iface = Interface::new(config, &mut device, SmolInstant::ZERO);
            iface.update_ip_addrs(|addresses| {
                let _ = addresses.push(IpCidr::new(IpAddress::from(source), 24));
            });
            let _ = iface
                .routes_mut()
                .add_default_ipv4_route(Ipv4Address::new(192, 0, 2, 254));

            let mut sockets = SocketSet::new(Vec::new());
            let rx = SocketBuffer::new(vec![0u8; 8192]);
            let tx = SocketBuffer::new(vec![0u8; 8192]);
            let mut socket = Socket::new(rx, tx);
            let remote = IpEndpoint::new(IpAddress::from(server), server_port);
            socket
                .connect(iface.context(), remote, local_port)
                .expect("client connect");
            let handle = sockets.add(socket);
            Self {
                device,
                iface,
                sockets,
                handle,
                ms: 0,
            }
        }

        fn poll(&mut self, now: SmolInstant) {
            while self.iface.poll(now, &mut self.device, &mut self.sockets)
                == PollResult::SocketStateChanged
            {}
        }

        fn socket(&mut self) -> &mut Socket<'static> {
            self.sockets.get_mut::<Socket>(self.handle)
        }

        pub(crate) fn tick(&mut self) {
            self.ms += 20;
            let now = SmolInstant::from_millis(i64::try_from(self.ms).unwrap_or(i64::MAX));
            self.poll(now);
        }

        pub(crate) fn take_outbound(&mut self) -> Vec<Vec<u8>> {
            self.device.outbound.drain(..).map(|p| p.to_vec()).collect()
        }

        pub(crate) fn deliver(&mut self, packet: &[u8]) {
            let pooled = self
                .device
                .pool
                .take(packet)
                .expect("the client budget holds");
            self.device.inbound.push_back(pooled);
        }

        pub(crate) fn send(&mut self, bytes: &[u8]) -> Result<usize, SendError> {
            self.socket().send_slice(bytes)
        }

        pub(crate) fn take_received(&mut self) -> Vec<u8> {
            let mut buf = [0u8; 512];
            match self.socket().recv_slice(&mut buf) {
                Ok(read) => buf[..read].to_vec(),
                Err(_) => Vec::new(),
            }
        }
    }

    fn relay(server: &mut LocalStack, client: &mut Client, base: Instant, ms: u64) {
        let outbound: Vec<Vec<u8>> = client.take_outbound();
        for packet in outbound {
            let pooled = server.pool().take(&packet).expect("the budget holds");
            server.push(pooled);
        }
        server.poll(base + Duration::from_millis(ms));
        while let Some(packet) = server.poll_transmit() {
            client.deliver(&packet);
        }
        client.poll(SmolInstant::from_millis(i64::try_from(ms).unwrap()));
    }

    fn pump(
        server: &mut LocalStack,
        client: &mut Client,
        base: Instant,
        from_ms: u64,
        rounds: u64,
    ) -> u64 {
        let mut ms = from_ms;
        for _ in 0..rounds {
            relay(server, client, base, ms);
            ms += 20;
        }
        ms
    }

    #[test]
    fn handshake_recovers_endpoints_then_streams_both_ways() {
        let base = Instant::now();
        let mut server = stack(&[HTTPS], limits(64, 4), base);
        let mut client = Client::connect(Ipv4Addr::new(192, 0, 2, 10), 49152, SERVER, HTTPS);

        let mut ms = pump(&mut server, &mut client, base, 0, 6);

        // Any-IP preserves the dialled destination as the local endpoint.
        let accepted = server.poll_accept().expect("the connection is accepted");
        assert_eq!(accepted.client, v4(Ipv4Addr::new(192, 0, 2, 10), 49152));
        assert_eq!(accepted.server, v4(SERVER, HTTPS));
        assert_eq!(server.poll_accept(), None, "exactly one accept");
        let id = accepted.id;

        let request = b"GET / HTTP/1.1\r\nHost: example\r\n\r\n";
        assert_eq!(client.socket().send_slice(request), Ok(request.len()));
        ms = pump(&mut server, &mut client, base, ms, 4);
        let mut buf = [0u8; 128];
        let read = server.recv(id, &mut buf).expect("readable");
        assert_eq!(&buf[..read], request);

        let response = b"HTTP/1.1 204 No Content\r\n\r\n";
        assert_eq!(server.send(id, response), Ok(response.len()));
        pump(&mut server, &mut client, base, ms, 4);
        let mut client_buf = [0u8; 128];
        let read = client
            .socket()
            .recv_slice(&mut client_buf)
            .expect("client read");
        assert_eq!(&client_buf[..read], response);
    }

    /// A SYN is not a connection (RFC 9293 section 3.10.1): nothing is
    /// published until the handshake completes, the backlog stays whole
    /// meanwhile, and a handshake nobody finishes gives its socket back.
    #[test]
    fn a_half_open_connection_is_not_accepted_and_times_out() {
        let base = Instant::now();
        let mut server = stack(&[HTTPS], limits(64, 4), base);
        let mut client = Client::connect(Ipv4Addr::new(192, 0, 2, 10), 49152, SERVER, HTTPS);

        // Deliver the SYN without its ACK so the socket stays in SYN-RECEIVED.
        client.tick();
        for packet in client.take_outbound() {
            let pooled = server.pool().take(&packet).expect("the budget holds");
            server.push(pooled);
        }
        server.poll(base);
        assert_eq!(server.poll_accept(), None, "half open is not open");
        assert_eq!(server.listening(HTTPS), 4, "the backlog is whole");
        assert_eq!(server.socket_count(), 5, "plus the one handshaking");

        server.poll(base + Duration::from_secs(61));
        assert_eq!(server.socket_count(), 4, "the handshake gave up its socket");
        assert_eq!(server.poll_accept(), None);
    }

    /// Behind a flow egress every TCP port is a destination; a SYN to a port
    /// with no listener gets one for itself instead of an RST.
    #[test]
    fn every_port_mode_listens_for_the_port_a_syn_names() {
        const SSH: u16 = 22;
        let base = Instant::now();
        let mut fixed = stack(&[HTTPS], limits(64, 4), base);
        let mut client = Client::connect(Ipv4Addr::new(192, 0, 2, 10), 49152, SERVER, SSH);
        pump(&mut fixed, &mut client, base, 0, 6);
        assert_eq!(
            fixed.poll_accept(),
            None,
            "a fixed listener set refuses port 22"
        );

        let mut every = stack(&[HTTPS], limits(64, 4), base);
        every.terminate_every_port();
        let mut client = Client::connect(Ipv4Addr::new(192, 0, 2, 11), 49153, SERVER, SSH);
        pump(&mut every, &mut client, base, 0, 6);
        let accepted = every.poll_accept().expect("port 22 was listened for");
        assert_eq!(accepted.server, v4(SERVER, SSH));
        assert_eq!(every.listening(SSH), 0, "and nothing lingers for it");
        assert_eq!(every.listening(HTTPS), 4);
    }

    #[test]
    fn peer_close_is_observed_then_the_socket_is_reaped() {
        let base = Instant::now();
        let mut server = stack(&[HTTPS], limits(64, 4), base);
        let mut client = Client::connect(Ipv4Addr::new(192, 0, 2, 10), 49152, SERVER, HTTPS);
        let mut ms = pump(&mut server, &mut client, base, 0, 6);
        let id = server.poll_accept().expect("accepted").id;
        assert_eq!(server.socket_count(), 5);

        client.socket().close();
        ms = pump(&mut server, &mut client, base, ms, 4);
        let mut buf = [0u8; 16];
        assert_eq!(server.recv(id, &mut buf), Err(StreamError::Closed));

        // Closing the local half lets the connection finish and be reaped.
        server.close(id);
        pump(&mut server, &mut client, base, ms, 8);
        assert_eq!(server.poll_closed(), Some(Ended { id, reset: false }));
        assert_eq!(
            server.recv(id, &mut buf),
            Err(StreamError::Unknown),
            "a reaped id names no stream"
        );
        assert_eq!(
            server.socket_count(),
            4,
            "only the listener backlog remains"
        );
    }

    /// RFC 9293 section 3.6.1: a reset is not a close. The task learns which.
    #[test]
    fn a_reset_from_the_peer_is_reported_as_one() {
        let base = Instant::now();
        let mut server = stack(&[HTTPS], limits(64, 4), base);
        let mut client = Client::connect(Ipv4Addr::new(192, 0, 2, 10), 49154, SERVER, HTTPS);
        let ms = pump(&mut server, &mut client, base, 0, 6);
        let id = server.poll_accept().expect("accepted").id;

        client.socket().abort();
        pump(&mut server, &mut client, base, ms, 4);
        assert_eq!(server.poll_closed(), Some(Ended { id, reset: true }));
    }

    #[test]
    fn the_socket_ceiling_refuses_connections_beyond_the_budget() {
        let base = Instant::now();
        let mut server = stack(&[HTTPS], limits(3, 1), base);
        let mut clients: Vec<Client> = (0..5)
            .map(|i| Client::connect(Ipv4Addr::new(192, 0, 2, 10 + i), 49152, SERVER, HTTPS))
            .collect();

        let mut ms = 0;
        let mut accepted = 0;
        for _ in 0..10 {
            for client in &mut clients {
                relay(&mut server, client, base, ms);
            }
            ms += 20;
            while server.poll_accept().is_some() {
                accepted += 1;
            }
            assert!(
                server.socket_count() <= 3,
                "the set never exceeds its ceiling"
            );
        }

        assert_eq!(accepted, 3, "exactly the budget's worth are accepted");
        let mut established = 0;
        for client in &mut clients {
            if client.socket().state() == State::Established {
                established += 1;
            }
        }
        assert_eq!(established, 3, "the two beyond the budget were refused");
    }
}
