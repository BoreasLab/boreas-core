//! Local TCP termination: the substrate P14 MITM runs on.
//!
//! The packet fast path forwards whole IP packets and never sees a byte stream.
//! Interception needs the opposite: the client's TCP connection must *end here*,
//! so its plaintext (or, one TLS layer up, its ciphertext) becomes an ordered
//! byte stream the shell can read, filter, and re-originate upstream. This
//! module is that terminator.
//!
//! It is sans-io in exactly the sense the rest of the core is: it owns no
//! socket, no task, and no clock. Client packets enter as borrowed slices
//! ([`push`](LocalStack::push)); reply packets leave as owned buffers
//! ([`poll_transmit`](LocalStack::poll_transmit)); time enters as an `Instant`
//! argument to [`poll`](LocalStack::poll). A `smoltcp` socket set is the TCP
//! state machine underneath — the engineering plan's gap 9, admitted here for
//! real rather than measured in an example — and this type is the seam that
//! keeps `smoltcp`'s poll-driven, mutable world from leaking into the reactor
//! that drives it.
//!
//! **Any-IP is load-bearing.** A terminating proxy answers a SYN addressed to
//! an arbitrary upstream server, not to an address this interface owns. The
//! interface therefore runs with `smoltcp`'s any-IP mode and its listeners bind
//! the port with no local address, so the destination the client dialled is
//! taken from the SYN and used as the reply's source. Without it every
//! handshake would be answered from the wrong address and silently fail.
//!
//! **The socket set is the bound.** One listening socket accepts one
//! connection and becomes it, so the pool is replenished on every accept up to
//! a fixed ceiling ([`TerminationLimits::max_sockets`]). At the ceiling a new
//! SYN finds no listener and `smoltcp` refuses it with a RST — connection
//! refused, which a browser retries — rather than growing state without limit.
//! This is the P6 socket-count budget expressed as an admission rule.

use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    num::NonZeroUsize,
    time::Instant,
};

use smoltcp::{
    iface::{Config, Interface, PollResult, SocketHandle, SocketSet},
    phy::{Checksum, ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp::{RecvError, SendError, Socket, SocketBuffer, State},
    time::Instant as SmolInstant,
    wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv6Address},
};

use crate::{InternalEndpoint, Mtu};

/// Opaque handle to one terminated connection. A thin newtype over `smoltcp`'s
/// own handle so a caller cannot fabricate one or reach past it into the socket
/// set — the only way to name a stream is to have been handed it by
/// [`LocalStack::poll_accept`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamId(SocketHandle);

/// A connection the stack has accepted: the client's SYN was answered and an
/// ordered byte stream now exists in both directions.
///
/// `client` is the remote peer (the application behind the TUN) and `server` is
/// the original destination it dialled — the address any-IP recovered from the
/// SYN. The MITM layer needs both: `server` names the host whose certificate it
/// must present, and `client` addresses the connection for teardown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Terminated {
    pub id: StreamId,
    pub client: InternalEndpoint,
    pub server: InternalEndpoint,
}

/// Why a read or write against a stream could not proceed. Absence
/// (`WouldBlock`) is not an error: it is the ordinary "nothing to read yet" or
/// "peer window full" that a caller retries after the next [`poll`](LocalStack::poll).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamError {
    /// No live stream bears this id: it was never accepted, or it has closed
    /// and been reaped. Distinct from `WouldBlock`, which names a live stream.
    Unknown,
    /// The stream is live but cannot move bytes in this direction right now —
    /// an empty receive buffer or a full send window. Retry after `poll`.
    WouldBlock,
    /// The peer has closed its half: no more bytes will ever arrive (on `recv`)
    /// or be accepted (on `send`). A terminal condition, not a retry.
    Closed,
}

/// Memory and cardinality bounds for the terminator. Every field bounds state
/// fed by network input; none of them changes policy.
#[derive(Clone, Copy, Debug)]
pub struct TerminationLimits {
    /// Total `smoltcp` sockets — listeners plus established connections. The P6
    /// socket-count budget: a SYN arriving with the ceiling reached finds no
    /// listener and is refused with a RST rather than admitted.
    pub max_sockets: NonZeroUsize,
    /// Listening sockets held open per intercepted port. A backlog absorbs a
    /// burst of near-simultaneous connections without any being refused while
    /// the pool replenishes.
    pub backlog: NonZeroUsize,
    /// Bytes of receive and of send buffer per connection. The dominant memory
    /// term: peak is roughly `max_sockets * 2 * socket_buffer`, so on a mobile
    /// target this trades throughput per connection against how many connections
    /// fit the RSS budget.
    pub socket_buffer: NonZeroUsize,
}

/// A `smoltcp` device backed by two byte-buffer queues rather than a NIC.
/// `inbound` is what the client sent (consumed by `smoltcp` on receive);
/// `outbound` is what `smoltcp` produced for the client (drained by the shell).
/// The queues are the whole I/O surface, which is what keeps this sans-io.
struct QueueDevice {
    inbound: VecDeque<Vec<u8>>,
    outbound: VecDeque<Vec<u8>>,
    mtu: usize,
}

/// Owns the received packet outright, so the receive token holds no borrow of
/// the device and can be returned alongside a transmit token that does.
struct QueueRx(Vec<u8>);

impl RxToken for QueueRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

/// Borrows only the outbound queue, so it coexists with a receive token that
/// borrows nothing.
struct QueueTx<'a> {
    outbound: &'a mut VecDeque<Vec<u8>>,
}

impl TxToken for QueueTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        self.outbound.push_back(buf);
        result
    }
}

impl Device for QueueDevice {
    type RxToken<'a> = QueueRx;
    type TxToken<'a> = QueueTx<'a>;

    fn receive(&mut self, _now: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // `pop_front` releases the borrow on `inbound` before `outbound` is
        // borrowed, so the two tokens touch disjoint fields.
        let packet = self.inbound.pop_front()?;
        Some((
            QueueRx(packet),
            QueueTx {
                outbound: &mut self.outbound,
            },
        ))
    }

    fn transmit(&mut self, _now: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(QueueTx {
            outbound: &mut self.outbound,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        // The client's stack already checksummed what it sent and will verify
        // what we send, so both directions are computed and checked in full;
        // there is no hardware to offload either to.
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

pub struct LocalStack {
    device: QueueDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    /// The ports the terminator listens on. Under [`crate::FilterPolicy::InspectHttp`]
    /// the planner routes every TCP flow to termination; this narrows the ones
    /// this stack actually answers to the HTTP(S) ports interception is for.
    ports: Vec<u16>,
    listeners: Vec<Listener>,
    limits: TerminationLimits,
    /// Live connections and the endpoints they were accepted with. The endpoints
    /// are cached because a closing socket drops them before the shell reaps it.
    established: HashMap<SocketHandle, (InternalEndpoint, InternalEndpoint)>,
    accepted: VecDeque<Terminated>,
    closed: VecDeque<StreamId>,
    /// Virtual-time base: `smoltcp` counts milliseconds from an arbitrary epoch,
    /// so caller `Instant`s are mapped through this fixed origin. Deterministic
    /// given deterministic inputs, which is what lets the harness drive it.
    base: Instant,
}

impl LocalStack {
    /// Builds a terminator listening on `ports`. `mtu` must match the tunnel the
    /// client's packets arrive on, so a segment the stack emits fits the path
    /// the reply travels back down.
    pub fn new(mtu: Mtu, ports: &[u16], limits: TerminationLimits, base: Instant) -> Self {
        let mut device = QueueDevice {
            inbound: VecDeque::new(),
            outbound: VecDeque::new(),
            mtu: usize::from(mtu.get()),
        };

        let config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut device, SmolInstant::ZERO);
        // Any-IP: accept SYNs to addresses this interface does not own and reply
        // from the address the client dialled. The assigned addresses below are
        // only placeholders that mark the interface "up" for each family; the
        // real local address of every connection comes from its SYN.
        iface.set_any_ip(true);
        iface.update_ip_addrs(|addresses| {
            let _ = addresses.push(IpCidr::new(IpAddress::v4(10, 0, 0, 1), 8));
            let _ = addresses.push(IpCidr::new(IpAddress::v6(0xfd00, 0, 0, 0, 0, 0, 0, 1), 64));
        });
        // A client dials from an address off the placeholder subnets, so its
        // reply is off-link and egress needs a route to permit it. On Medium::Ip
        // there is no L2 and no neighbour to resolve: the gateway only selects
        // this one interface, and the datagram the device emits still carries
        // the client as its destination. Both gateways sit inside their
        // placeholder subnet so they are themselves on-link.
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
            listeners: Vec::new(),
            limits,
            established: HashMap::new(),
            accepted: VecDeque::new(),
            closed: VecDeque::new(),
            base,
        };
        stack.replenish_listeners();
        stack
    }

    /// Enqueues one client packet for the next [`poll`](Self::poll).
    pub fn push(&mut self, packet: &[u8]) {
        self.device.inbound.push_back(packet.to_vec());
    }

    /// The next reply packet bound for the client, if any. Terminal on the
    /// tunnel side: it goes straight to the device.
    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        self.device.outbound.pop_front()
    }

    /// A connection accepted since the last call.
    pub fn poll_accept(&mut self) -> Option<Terminated> {
        self.accepted.pop_front()
    }

    /// A connection that has fully closed since the last call. After this the
    /// id is [`StreamError::Unknown`] to every operation.
    pub fn poll_closed(&mut self) -> Option<StreamId> {
        self.closed.pop_front()
    }

    fn now(&self, now: Instant) -> SmolInstant {
        // Saturating: a caller that hands back an instant before `base` is a
        // defect, but the terminator answers it with "no time has passed"
        // rather than a panic on the datapath.
        let millis = now.saturating_duration_since(self.base).as_millis();
        SmolInstant::from_millis(i64::try_from(millis).unwrap_or(i64::MAX))
    }

    /// Advances the TCP state machines against `now`: drains queued client
    /// packets into `smoltcp`, produces reply packets, and harvests the
    /// connections that opened or closed as a result.
    pub fn poll(&mut self, now: Instant) {
        let now = self.now(now);
        // One `poll` drains all pending inbound and emits all pending outbound;
        // looping while it reports progress covers the case where accepting a
        // connection frees work that a single pass left pending.
        while self.iface.poll(now, &mut self.device, &mut self.sockets)
            == PollResult::SocketStateChanged
        {}
        self.harvest();
        self.replenish_listeners();
    }

    /// The earliest instant `smoltcp` wants servicing again (a retransmit, a
    /// delayed ACK, a TIME-WAIT expiry). The reactor folds this into the one
    /// timer it already arms against the datapath's own deadline, so there is
    /// never a timer per socket.
    pub fn poll_at(&mut self, now: Instant) -> Option<Instant> {
        let smol_now = self.now(now);
        self.iface.poll_at(smol_now, &self.sockets).map(|at| {
            // `at` may be at or before `smol_now`, meaning "service immediately".
            // Both directions map to a non-negative offset from the caller's own
            // clock, computed in microseconds to avoid the ambiguous `Instant +
            // Duration` impls that pulling in the `time` crate introduced.
            let ahead = (at.total_micros() - smol_now.total_micros()).max(0);
            now + std::time::Duration::from_micros(ahead as u64)
        })
    }

    /// Reads up to `buf.len()` bytes from the stream's receive buffer.
    ///
    /// `Ok(n)` moved `n` bytes; `WouldBlock` names a live stream with nothing
    /// buffered; `Closed` means the peer sent FIN and the buffer is drained, so
    /// no further bytes will ever arrive.
    pub fn recv(&mut self, id: StreamId, buf: &mut [u8]) -> Result<usize, StreamError> {
        let socket = self.socket_mut(id)?;
        if socket.can_recv() {
            return socket.recv_slice(buf).map_err(|error| match error {
                RecvError::Finished => StreamError::Closed,
                RecvError::InvalidState => StreamError::WouldBlock,
            });
        }
        // No buffered bytes: distinguish "not yet" from "never again".
        if socket.may_recv() {
            Err(StreamError::WouldBlock)
        } else {
            Err(StreamError::Closed)
        }
    }

    /// Writes up to `buf.len()` bytes into the stream's send buffer, returning
    /// how many were accepted. A full window is `WouldBlock`, not an error.
    pub fn send(&mut self, id: StreamId, buf: &[u8]) -> Result<usize, StreamError> {
        let socket = self.socket_mut(id)?;
        if !socket.may_send() {
            return Err(StreamError::Closed);
        }
        match socket.send_slice(buf) {
            Ok(0) => Err(StreamError::WouldBlock),
            Ok(n) => Ok(n),
            Err(SendError::InvalidState) => Err(StreamError::Closed),
        }
    }

    /// Whether a `recv` would return bytes right now.
    pub fn can_recv(&self, id: StreamId) -> bool {
        self.socket(id).is_some_and(Socket::can_recv)
    }

    /// Whether a `send` would accept bytes right now.
    pub fn can_send(&self, id: StreamId) -> bool {
        self.socket(id).is_some_and(Socket::can_send)
    }

    /// Closes this half of the connection: a FIN after the send buffer drains.
    /// The peer may keep sending until it closes too.
    pub fn close(&mut self, id: StreamId) {
        if let Ok(socket) = self.socket_mut(id) {
            socket.close();
        }
    }

    /// Aborts the connection with a RST. Used for fail-fast teardown when a
    /// graceful close would strand the peer.
    pub fn abort(&mut self, id: StreamId) {
        if let Ok(socket) = self.socket_mut(id) {
            socket.abort();
        }
    }

    /// The number of live `smoltcp` sockets, listeners included. The quantity
    /// the P6 budget bounds.
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

    /// Moves listeners that accepted a connection into `established`, and reaps
    /// established sockets that have fully closed.
    fn harvest(&mut self) {
        // A listener whose socket has left `Listen` has committed to a
        // connection. Record its endpoints and stop treating it as a listener;
        // `replenish_listeners` will restore the backlog for its port.
        let mut converted = Vec::new();
        self.listeners.retain(|listener| {
            let socket = self.sockets.get::<Socket>(listener.handle);
            if socket.state() == State::Listen {
                return true;
            }
            converted.push(listener.handle);
            false
        });
        for handle in converted {
            let socket = self.sockets.get::<Socket>(handle);
            // Endpoints are present from SYN-RECEIVED onward. A socket that
            // reached a terminal state before we looked never became a usable
            // stream, so it is simply dropped rather than surfaced.
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

        // Reap connections `smoltcp` has finished with: a closed socket holds a
        // buffer, and leaving it in the set would spend the budget on a corpse.
        let mut finished = Vec::new();
        for &handle in self.established.keys() {
            if !self.sockets.get::<Socket>(handle).is_active() {
                finished.push(handle);
            }
        }
        for handle in finished {
            self.established.remove(&handle);
            self.sockets.remove(handle);
            self.closed.push_back(StreamId(handle));
        }
    }

    /// Restores the per-port listening backlog up to the socket ceiling. A port
    /// that cannot be replenished because the ceiling is reached simply refuses
    /// new connections until an established one closes — the P6 admission rule.
    fn replenish_listeners(&mut self) {
        for &port in &self.ports {
            let live = self.listeners.iter().filter(|l| l.port == port).count();
            for _ in live..self.limits.backlog.get() {
                if self.socket_count() >= self.limits.max_sockets.get() {
                    return;
                }
                let rx = SocketBuffer::new(vec![0u8; self.limits.socket_buffer.get()]);
                let tx = SocketBuffer::new(vec![0u8; self.limits.socket_buffer.get()]);
                let mut socket = Socket::new(rx, tx);
                // Bind the port with no address: any-IP then accepts a SYN to
                // any destination on it. `listen` fails only on a bad endpoint
                // or a busy socket, and a freshly built one is neither.
                if socket.listen(port).is_err() {
                    return;
                }
                let handle = self.sockets.add(socket);
                self.listeners.push(Listener { handle, port });
            }
        }
    }
}

fn endpoint(address: IpAddr, port: u16) -> InternalEndpoint {
    InternalEndpoint { address, port }
}

#[cfg(test)]
mod tests {
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

    /// A bare smoltcp client stack with one connecting TCP socket. It owns its
    /// source address and dials a concrete destination, so — unlike the
    /// terminator — it needs no any-IP, only a route to reach the off-link
    /// server. This is a real peer performing a real handshake; the test asserts
    /// nothing the TCP state machine did not actually produce.
    struct Client {
        device: QueueDevice,
        iface: Interface,
        sockets: SocketSet<'static>,
        handle: SocketHandle,
    }

    impl Client {
        fn connect(source: Ipv4Addr, local_port: u16, server: Ipv4Addr, server_port: u16) -> Self {
            let mut device = QueueDevice {
                inbound: VecDeque::new(),
                outbound: VecDeque::new(),
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
    }

    /// One packet-exchange round: client segments to the server, the server
    /// advances and replies, the client advances. Both clocks are the same
    /// millisecond offset, so the terminator's `Instant`-to-`smoltcp` mapping is
    /// exercised rather than bypassed.
    fn relay(server: &mut LocalStack, client: &mut Client, base: Instant, ms: u64) {
        let outbound: Vec<Vec<u8>> = client.device.outbound.drain(..).collect();
        for packet in outbound {
            server.push(&packet);
        }
        server.poll(base + Duration::from_millis(ms));
        while let Some(packet) = server.poll_transmit() {
            client.device.inbound.push_back(packet);
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
        let mut server = LocalStack::new(mtu(), &[HTTPS], limits(64, 4), base);
        let mut client = Client::connect(Ipv4Addr::new(192, 0, 2, 10), 49152, SERVER, HTTPS);

        let mut ms = pump(&mut server, &mut client, base, 0, 6);

        // Any-IP recovered the destination the client dialled as the local
        // endpoint, and the client's own address:port as the remote.
        let accepted = server.poll_accept().expect("the connection is accepted");
        assert_eq!(accepted.client, v4(Ipv4Addr::new(192, 0, 2, 10), 49152));
        assert_eq!(accepted.server, v4(SERVER, HTTPS));
        assert_eq!(server.poll_accept(), None, "exactly one accept");
        let id = accepted.id;

        // Client to server: the terminator surfaces the bytes in order.
        let request = b"GET / HTTP/1.1\r\nHost: example\r\n\r\n";
        assert_eq!(client.socket().send_slice(request), Ok(request.len()));
        ms = pump(&mut server, &mut client, base, ms, 4);
        let mut buf = [0u8; 128];
        let read = server.recv(id, &mut buf).expect("readable");
        assert_eq!(&buf[..read], request);

        // Server to client: the reply travels back down the same connection.
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

    #[test]
    fn peer_close_is_observed_then_the_socket_is_reaped() {
        let base = Instant::now();
        let mut server = LocalStack::new(mtu(), &[HTTPS], limits(64, 4), base);
        let mut client = Client::connect(Ipv4Addr::new(192, 0, 2, 10), 49152, SERVER, HTTPS);
        let mut ms = pump(&mut server, &mut client, base, 0, 6);
        let id = server.poll_accept().expect("accepted").id;
        // The backlog is restored after the accept, so the set holds the four
        // listeners plus this one established connection.
        assert_eq!(server.socket_count(), 5);

        // The client closes its half. Once the FIN is processed the terminator
        // reports the receive half as closed, distinct from "nothing yet".
        client.socket().close();
        ms = pump(&mut server, &mut client, base, ms, 4);
        let mut buf = [0u8; 16];
        assert_eq!(server.recv(id, &mut buf), Err(StreamError::Closed));

        // The terminator closes its half; the connection drains to completion
        // and is reaped, returning its buffers and its id.
        server.close(id);
        pump(&mut server, &mut client, base, ms, 8);
        assert_eq!(server.poll_closed(), Some(id));
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

    #[test]
    fn the_socket_ceiling_refuses_connections_beyond_the_budget() {
        // Three sockets total, one listener at a time: the set can hold at most
        // three established connections, and there is no listener to accept a
        // fourth. This is the P6 admission rule as a test.
        let base = Instant::now();
        let mut server = LocalStack::new(mtu(), &[HTTPS], limits(3, 1), base);
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
