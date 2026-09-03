//! QUIC client whose bidirectional streams are async byte streams.
//!
//! Hysteria2 multiplexes its streams and datagrams inside one QUIC connection.
//! This module owns the UDP socket and `quiche::Connection`, while
//! [`crate::bridge`] exposes bounded stream channels to each consumer.
//!
//! [`Handshake::establish`], [`Handshake::http3`], and [`Handshake::drive`] are
//! separate phases. Authentication completes before a [`QuicConnection`] can
//! open proxy streams. HTTP/3 is dropped after its one authentication request;
//! proxy framing must never be parsed as HTTP/3, while leftover control and
//! QPACK streams are drained by id to maintain flow control.

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use quiche::h3::NameValue;
use ring::rand::SecureRandom;
use tokio::{
    net::UdpSocket,
    sync::{Notify, mpsc, oneshot},
    time::{Instant as TokioInstant, sleep_until},
};
use tokio_util::sync::CancellationToken;

use crate::{
    EgressError,
    bridge::{BridgedStream, CHUNK, Plumbing, pair},
};

/// Maximum UDP datagram buffer.
const MAX_DATAGRAM: usize = 1500;

/// Deadline for handshake, HTTP/3 settings, and authentication.
const HANDSHAKE_TIMEOUT: Duration = crate::Wait::ProxyDial.budget();

/// Bounded command queue for the driver.
const COMMAND_DEPTH: usize = 16;

/// Bounded inbound datagram queue. A slow claimant loses packets rather than
/// blocking other flows on the connection.
pub(crate) const DATAGRAM_DEPTH: usize = 256;

/// Builds a QUIC client configuration for stream traffic.
///
/// Certificate verification remains the caller's choice. `quiche` verifies by
/// default; tests may explicitly disable it.
pub fn client_config(
    alpn: &[&[u8]],
    idle_timeout: Duration,
) -> Result<quiche::Config, EgressError> {
    let mut config =
        quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(|_| EgressError::Quic)?;
    config
        .set_application_protos(alpn)
        .map_err(|_| EgressError::Quic)?;
    config.set_max_idle_timeout(idle_timeout.as_millis() as u64);
    // Accept up to an Ethernet frame; send at the 1200-byte floor until a
    // probe proves the path takes more (RFC 9000 section 14). A fixed 1500
    // stalled after the handshake on every path with a smaller MTU.
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM);
    config.discover_pmtu(true);
    // Set connection and stream flow-control windows for bulk transfer.
    config.set_initial_max_data(16 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_local(4 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_remote(4 * 1024 * 1024);
    config.set_initial_max_stream_data_uni(1024 * 1024);
    // Peers cannot open request streams, but HTTP/3 still needs uni streams.
    config.set_initial_max_streams_bidi(0);
    config.set_initial_max_streams_uni(8);
    Ok(config)
}

fn no_deadline() -> TokioInstant {
    TokioInstant::now() + Duration::from_secs(3600)
}

/// Handshaken QUIC connection not yet owned by a driver.
///
/// The type boundary prevents proxy streams from opening before authentication.
pub struct Handshake {
    conn: quiche::Connection,
    socket: UdpSocket,
    peer: SocketAddr,
    local: SocketAddr,
    /// Next client bidirectional stream id. HTTP/3 authentication advances it
    /// before proxy streams are allocated.
    next_stream_id: u64,
}

/// Response headers from the HTTP/3 authentication request.
#[derive(Clone, Debug)]
pub struct H3Response {
    pub status: u16,
    /// Non-pseudo headers in arrival order.
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
}

impl H3Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name.as_bytes())
            .and_then(|(_, value)| std::str::from_utf8(value).ok())
    }
}

impl Handshake {
    pub async fn establish(
        socket: UdpSocket,
        peer: SocketAddr,
        server_name: &str,
        mut config: quiche::Config,
    ) -> Result<Self, EgressError> {
        let local = socket.local_addr()?;
        let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
        ring::rand::SystemRandom::new()
            .fill(&mut scid)
            .map_err(|_| EgressError::Quic)?;
        let conn = quiche::connect(
            Some(server_name),
            &quiche::ConnectionId::from_ref(&scid),
            local,
            peer,
            &mut config,
        )
        .map_err(|_| EgressError::Quic)?;

        let mut handshake = Self {
            conn,
            socket,
            peer,
            local,
            next_stream_id: 0,
        };
        handshake
            .pump_until(|this| this.conn.is_established())
            .await?;
        Ok(handshake)
    }

    /// Sends the header-only HTTP/3 authentication request.
    ///
    /// The HTTP/3 connection is dropped after the response so proxy framing is
    /// not parsed as HTTP/3.
    pub async fn http3(
        &mut self,
        headers: &[quiche::h3::Header],
    ) -> Result<H3Response, EgressError> {
        let h3_config = quiche::h3::Config::new().map_err(|_| EgressError::Quic)?;
        let mut h3 = quiche::h3::Connection::with_transport(&mut self.conn, &h3_config)
            .map_err(|_| EgressError::Quic)?;
        let stream_id = h3
            .send_request(&mut self.conn, headers, true)
            .map_err(|_| EgressError::Quic)?;
        // Reserve stream ids after the authentication request.
        self.next_stream_id = stream_id + 4;

        let mut response = None;
        self.pump_until(|this| {
            // Keep the HTTP/3 borrow local to this polling closure.
            loop {
                match h3.poll(&mut this.conn) {
                    Ok((_, quiche::h3::Event::Headers { list, .. })) => {
                        let status = list
                            .iter()
                            .find(|header| header.name() == b":status")
                            .and_then(|header| std::str::from_utf8(header.value()).ok())
                            .and_then(|value| value.parse::<u16>().ok());
                        let Some(status) = status else {
                            // Ignore headers without a parseable status.
                            continue;
                        };
                        response = Some(H3Response {
                            status,
                            headers: list
                                .iter()
                                .filter(|header| !header.name().starts_with(b":"))
                                .map(|header| (header.name().to_vec(), header.value().to_vec()))
                                .collect(),
                        });
                        return true;
                    }
                    Ok(_) => {}
                    Err(_) => return response.is_some(),
                }
            }
        })
        .await?;
        response.ok_or(EgressError::Quic)
    }

    /// Starts the background driver and returns its stream handle.
    ///
    /// The driver stops on cancellation, connection close, or after all handles
    /// are dropped and open streams finish.
    pub fn drive(self, shutdown: CancellationToken) -> QuicConnection {
        let (commands, receiver) = mpsc::channel(COMMAND_DEPTH);
        let wake = Arc::new(Notify::new());
        let driver = Driver {
            conn: self.conn,
            socket: self.socket,
            peer: self.peer,
            local: self.local,
            next_stream_id: self.next_stream_id,
            streams: HashMap::new(),
            commands: receiver,
            datagrams: None,
            wake: Arc::clone(&wake),
            shutdown,
        };
        tokio::spawn(driver.run());
        QuicConnection { commands }
    }

    /// Drives pre-driver I/O until `ready`, connection close, or timeout.
    async fn pump_until(
        &mut self,
        mut ready: impl FnMut(&mut Self) -> bool,
    ) -> Result<(), EgressError> {
        // Locals avoid overlapping borrows of the connection during `select!`.
        let mut inbound = [0u8; MAX_DATAGRAM];
        let mut outbound = [0u8; MAX_DATAGRAM];
        let deadline = TokioInstant::now() + HANDSHAKE_TIMEOUT;
        loop {
            self.flush(&mut outbound).await?;
            if ready(self) {
                return Ok(());
            }
            if self.conn.is_closed() {
                return Err(EgressError::Quic);
            }
            // Honor QUIC loss recovery without exceeding the dial deadline.
            let timer = self
                .conn
                .timeout()
                .map(|timeout| TokioInstant::now() + timeout)
                .unwrap_or(deadline)
                .min(deadline);
            tokio::select! {
                result = self.socket.recv(&mut inbound) => {
                    let read = result?;
                    let info = quiche::RecvInfo { from: self.peer, to: self.local };
                    // Ignore datagrams that this connection cannot parse.
                    let _ = self.conn.recv(&mut inbound[..read], info);
                }
                () = sleep_until(timer) => {
                    if TokioInstant::now() >= deadline {
                        return Err(EgressError::Quic);
                    }
                    self.conn.on_timeout();
                }
            }
        }
    }

    async fn flush(&mut self, scratch: &mut [u8]) -> Result<(), EgressError> {
        while !flush(&mut self.conn, &self.socket, scratch).await? {}
        Ok(())
    }
}

/// Datagrams sent per pass before receives get a turn.
const FLUSH_BURST: usize = 64;

/// Sends what the connection has ready, at most a burst. `Ok(true)` when it
/// is drained; `Ok(false)` when more waits, so the caller comes straight back.
/// A datagram the socket refuses (an ICMP unreachable relayed as
/// ConnectionRefused, a full queue) is one lost packet QUIC recovers from,
/// not the end of every stream on the connection.
async fn flush(
    conn: &mut quiche::Connection,
    socket: &UdpSocket,
    scratch: &mut [u8],
) -> Result<bool, EgressError> {
    for _ in 0..FLUSH_BURST {
        let (written, _info) = match conn.send(scratch) {
            Ok(sent) => sent,
            Err(quiche::Error::Done) => return Ok(true),
            Err(_) => return Err(EgressError::Quic),
        };
        match socket.send(&scratch[..written]).await {
            Ok(_) => {}
            Err(error) if crate::host::shell::transient(&error) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(false)
}

/// Cloneable handle for opening streams and using datagrams on one connection.
#[derive(Clone)]
pub struct QuicConnection {
    commands: mpsc::Sender<Command>,
}

enum Command {
    OpenBidi {
        reply: oneshot::Sender<BridgedStream>,
    },
    /// Owned datagram for the driver to send.
    Send(Vec<u8>),
    /// Claims the single inbound datagram receiver.
    Receive {
        reply: oneshot::Sender<Option<mpsc::Receiver<Vec<u8>>>>,
    },
}

impl QuicConnection {
    pub async fn open_bidi(&self) -> Result<BridgedStream, EgressError> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::OpenBidi { reply })
            .await
            .map_err(|_| EgressError::Masque)?;
        response.await.map_err(|_| EgressError::Masque)
    }

    /// Queues one unreliable QUIC datagram.
    ///
    /// Oversized or transport-rejected datagrams are dropped because the payload
    /// is a client's UDP packet.
    pub async fn send_datagram(&self, payload: Vec<u8>) -> Result<(), EgressError> {
        self.commands
            .send(Command::Send(payload))
            .await
            .map_err(|_| EgressError::Quic)
    }

    /// Claims the inbound datagram stream once.
    ///
    /// A second claimant receives `None`; demultiplexing remains the caller's
    /// responsibility.
    pub async fn receive_datagrams(&self) -> Option<mpsc::Receiver<Vec<u8>>> {
        let (reply, response) = oneshot::channel();
        self.commands.send(Command::Receive { reply }).await.ok()?;
        response.await.ok().flatten()
    }

    /// Advisory driver liveness check. The connection may close immediately
    /// after this returns.
    pub fn is_alive(&self) -> bool {
        !self.commands.is_closed()
    }
}

struct Driver {
    conn: quiche::Connection,
    socket: UdpSocket,
    peer: SocketAddr,
    local: SocketAddr,
    next_stream_id: u64,
    streams: HashMap<u64, Plumbing>,
    commands: mpsc::Receiver<Command>,
    /// Inbound datagram sink after a receiver claims it.
    datagrams: Option<mpsc::Sender<Vec<u8>>>,
    wake: Arc<Notify>,
    shutdown: CancellationToken,
}

impl Driver {
    async fn run(mut self) {
        let mut inbound = vec![0u8; MAX_DATAGRAM];
        let mut outbound = vec![0u8; MAX_DATAGRAM];
        let mut chunk = vec![0u8; CHUNK];
        // Stop accepting streams after the last connection handle is dropped.
        let mut closing = false;

        loop {
            self.service(&mut chunk);
            match flush(&mut self.conn, &self.socket, &mut outbound).await {
                Ok(true) => {}
                // More to send: take the receive turn, then come back.
                Ok(false) => self.wake.notify_one(),
                Err(_) => break,
            }
            if self.conn.is_closed() {
                break;
            }
            if closing && self.streams.is_empty() {
                break;
            }

            let timer = self
                .conn
                .timeout()
                .map(|timeout| TokioInstant::now() + timeout)
                .unwrap_or_else(no_deadline);

            tokio::select! {
                () = self.shutdown.cancelled() => break,
                result = self.socket.recv(&mut inbound) => {
                    let Ok(read) = result else { break };
                    let info = quiche::RecvInfo { from: self.peer, to: self.local };
                    let _ = self.conn.recv(&mut inbound[..read], info);
                }
                command = self.commands.recv(), if !closing => match command {
                    Some(command) => self.dispatch(command),
                    // Keep existing streams alive after all handles disappear.
                    None => closing = true,
                },
                () = self.wake.notified() => {}
                () = sleep_until(timer) => self.conn.on_timeout(),
            }
        }

        // Send an application close so the peer releases connection state.
        let _ = self.conn.close(true, 0x00, b"done");
        let _ = flush(&mut self.conn, &self.socket, &mut outbound).await;
    }

    fn dispatch(&mut self, command: Command) {
        match command {
            Command::Send(payload) => {
                // QUIC rejects oversized or unavailable datagrams; UDP loss is
                // the expected result for this payload.
                let _ = self.conn.dgram_send(&payload);
            }
            Command::Receive { reply } => {
                if self.datagrams.is_some() {
                    let _ = reply.send(None);
                    return;
                }
                let (sender, receiver) = mpsc::channel(DATAGRAM_DEPTH);
                // Do not retain a sender when the claimant has already gone.
                if reply.send(Some(receiver)).is_ok() {
                    self.datagrams = Some(sender);
                }
            }
            Command::OpenBidi { reply } => {
                // Report an exhausted peer stream limit immediately.
                if self.conn.peer_streams_left_bidi() == 0 {
                    return; // dropping `reply` is the refusal
                }
                let id = self.next_stream_id;
                self.next_stream_id += 4;
                let (stream, plumbing) = pair(Arc::clone(&self.wake));
                if reply.send(stream).is_ok() {
                    self.streams.insert(id, plumbing);
                }
            }
        }
    }

    fn service(&mut self, chunk: &mut [u8]) {
        // Drain the transport queue; a slow claimant loses packets rather than
        // blocking streams on the same connection.
        if let Some(sink) = &self.datagrams {
            while let Ok(len) = self.conn.dgram_recv(chunk) {
                if sink.try_send(chunk[..len].to_vec()).is_err() {
                    break;
                }
            }
        }

        // The owned iterator permits stream mutation during the sweep.
        for id in self.conn.readable() {
            match self.streams.get_mut(&id) {
                Some(plumbing) => pump_in(&mut self.conn, id, plumbing, chunk),
                // Drain leftover HTTP/3 control and QPACK streams by id.
                None => while self.conn.stream_recv(id, chunk).is_ok() {},
            }
        }

        for (&id, plumbing) in self.streams.iter_mut() {
            pump_out(&mut self.conn, id, plumbing);
        }

        // Retain only streams with an active consumer or unfinished output.
        self.streams
            .retain(|_, plumbing| plumbing.to_task.is_some() || !plumbing.finished);
    }
}

/// Moves peer bytes to the consumer without exceeding channel capacity.
///
/// Reserving before reading lets QUIC flow control stop the peer when the
/// consumer is full.
fn pump_in(conn: &mut quiche::Connection, id: u64, plumbing: &mut Plumbing, buf: &mut [u8]) {
    let mut finished = false;
    let mut abandoned = false;
    let mut reset = false;
    while let Some(sender) = plumbing.to_task.as_ref() {
        let permit = match sender.try_reserve() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Full(())) => break,
            // Stop receiving bytes no consumer can use.
            Err(mpsc::error::TrySendError::Closed(())) => {
                abandoned = true;
                break;
            }
        };
        match conn.stream_recv(id, buf) {
            Ok((read, fin)) => {
                if read > 0 {
                    permit.send(Bytes::copy_from_slice(&buf[..read]));
                }
                if fin {
                    finished = true;
                    break;
                }
            }
            Err(quiche::Error::Done) => break,
            // A reset stream: the consumer's next read is an error.
            Err(_) => {
                reset = true;
                break;
            }
        }
    }
    if abandoned {
        let _ = conn.stream_shutdown(id, quiche::Shutdown::Read, 0);
    }
    // Drop the sender after any reserved permit is released.
    if reset {
        plumbing.reset();
    } else if finished || abandoned {
        plumbing.to_task = None;
    }
}

/// Moves consumer bytes to the peer without dropping partial writes.
fn pump_out(conn: &mut quiche::Connection, id: u64, plumbing: &mut Plumbing) {
    if plumbing.finished {
        return;
    }
    loop {
        let chunk = match plumbing.pending_out.take() {
            Some(chunk) => chunk,
            None => match plumbing.from_task.try_recv() {
                Ok(chunk) => chunk,
                Err(mpsc::error::TryRecvError::Empty) => return,
                // Close the peer write half after queued input is exhausted.
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    plumbing.finished = true;
                    let _ = conn.stream_send(id, &[], true);
                    return;
                }
            },
        };
        match conn.stream_send(id, &chunk, false) {
            Ok(written) if written < chunk.len() => {
                // Preserve the unwritten tail for the next pass.
                plumbing.pending_out = Some(chunk.slice(written..));
                return;
            }
            Ok(_) => {}
            // `Done` wrote nothing, so retry the complete chunk later.
            Err(quiche::Error::Done) => {
                plumbing.pending_out = Some(chunk);
                return;
            }
            // Stop retrying a reset or closed stream.
            Err(_) => {
                plumbing.finished = true;
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Loopback QUIC server fixture for one connection.
    ///
    /// It echoes streams and datagrams so both driver directions use a real
    /// socket and timer loop.
    struct Echo {
        address: SocketAddr,
        shutdown: CancellationToken,
    }

    impl Echo {
        async fn start(datagrams: bool) -> Self {
            let (cert, key, dir) = crate::testing::self_signed("quic.example");
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = socket.local_addr().unwrap();
            let shutdown = CancellationToken::new();
            let cancelled = shutdown.clone();

            let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
            config
                .load_cert_chain_from_pem_file(cert.to_str().unwrap())
                .unwrap();
            config
                .load_priv_key_from_pem_file(key.to_str().unwrap())
                .unwrap();
            config.set_application_protos(&[b"echo"]).unwrap();
            config.set_max_idle_timeout(10_000);
            config.set_initial_max_data(1_000_000);
            config.set_initial_max_stream_data_bidi_local(100_000);
            config.set_initial_max_stream_data_bidi_remote(100_000);
            config.set_initial_max_stream_data_uni(100_000);
            config.set_initial_max_streams_bidi(16);
            config.set_initial_max_streams_uni(16);
            if datagrams {
                config.enable_dgram(true, 64, 64);
            }

            tokio::spawn(async move {
                // Keep certificate files alive for the server task.
                let _dir = dir;
                let mut config = config;
                let mut inbound = vec![0u8; 2048];
                let mut outbound = vec![0u8; 2048];
                let mut conn: Option<quiche::Connection> = None;
                let mut peer: Option<SocketAddr> = None;
                let mut chunk = vec![0u8; 2048];

                loop {
                    if let Some(established) = conn.as_mut() {
                        // Echo readable streams.
                        for id in established.readable() {
                            while let Ok((read, fin)) = established.stream_recv(id, &mut chunk) {
                                let _ = established.stream_send(id, &chunk[..read], fin);
                            }
                        }
                        // Echo datagrams.
                        while let Ok(read) = established.dgram_recv(&mut chunk) {
                            let _ = established.dgram_send(&chunk[..read]);
                        }
                        while let Ok((written, info)) = established.send(&mut outbound) {
                            let _ = socket.send_to(&outbound[..written], info.to).await;
                        }
                    }

                    let timer = conn
                        .as_ref()
                        .and_then(|established| established.timeout())
                        .map(|left| TokioInstant::now() + left)
                        .unwrap_or_else(no_deadline);

                    tokio::select! {
                        () = cancelled.cancelled() => break,
                        result = socket.recv_from(&mut inbound) => {
                            let Ok((read, from)) = result else { break };
                            if conn.is_none() {
                                let header = quiche::Header::from_slice(
                                    &mut inbound[..read],
                                    quiche::MAX_CONN_ID_LEN,
                                );
                                let Ok(header) = header else { continue };
                                let scid = quiche::ConnectionId::from_ref(&[0xcd; 16]);
                                conn = quiche::accept(
                                    &scid,
                                    Some(&header.dcid),
                                    address,
                                    from,
                                    &mut config,
                                )
                                .ok();
                                peer = Some(from);
                            }
                            if let (Some(established), Some(peer)) = (conn.as_mut(), peer) {
                                let info = quiche::RecvInfo { from: peer, to: address };
                                let _ = established.recv(&mut inbound[..read], info);
                            }
                        }
                        () = sleep_until(timer) => {
                            if let Some(established) = conn.as_mut() {
                                established.on_timeout();
                            }
                        }
                    }
                }
            });

            Self { address, shutdown }
        }

        fn config(datagrams: bool) -> quiche::Config {
            let mut config = client_config(&[b"echo"], Duration::from_secs(10)).unwrap();
            config.verify_peer(false);
            if datagrams {
                config.enable_dgram(true, 64, 64);
            }
            config
        }

        async fn dial(&self, datagrams: bool) -> Result<Handshake, EgressError> {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            socket.connect(self.address).await.unwrap();
            Handshake::establish(
                socket,
                self.address,
                "quic.example",
                Self::config(datagrams),
            )
            .await
        }
    }

    impl Drop for Echo {
        fn drop(&mut self) {
            self.shutdown.cancel();
        }
    }

    #[tokio::test]
    async fn a_stream_carries_bytes_through_a_real_connection() {
        let echo = Echo::start(false).await;
        let connection = echo
            .dial(false)
            .await
            .expect("the handshake completes")
            .drive(CancellationToken::new());

        let mut stream = connection.open_bidi().await.expect("a stream opens");
        stream.write_all(b"question").await.unwrap();
        stream.flush().await.unwrap();

        let mut back = [0u8; 8];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut back))
            .await
            .expect("the echo returns")
            .unwrap();
        assert_eq!(&back, b"question");
    }

    #[tokio::test]
    async fn a_datagram_crosses_and_comes_back() {
        let echo = Echo::start(true).await;
        let connection = echo
            .dial(true)
            .await
            .expect("the handshake completes")
            .drive(CancellationToken::new());

        let mut inbound = connection
            .receive_datagrams()
            .await
            .expect("nothing has claimed them");
        connection
            .send_datagram(b"one datagram".to_vec())
            .await
            .expect("it queues");

        let back = tokio::time::timeout(Duration::from_secs(10), inbound.recv())
            .await
            .expect("the echo returns")
            .expect("the channel is open");
        assert_eq!(back, b"one datagram");
    }

    /// RFC 9221: a peer sends DATAGRAM frames only to a client that advertised
    /// them. Hysteria2's UDP relay is that client.
    #[tokio::test]
    async fn the_hysteria2_configuration_advertises_datagrams() {
        let echo = Echo::start(true).await;
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(echo.address).await.unwrap();
        let mut config = crate::Hysteria2Egress::<crate::DirectSockets>::quic_config().unwrap();
        config.verify_peer(false);
        config.set_application_protos(&[b"echo"]).unwrap();
        let connection = Handshake::establish(socket, echo.address, "quic.example", config)
            .await
            .expect("the handshake completes")
            .drive(CancellationToken::new());

        let mut inbound = connection.receive_datagrams().await.unwrap();
        connection
            .send_datagram(b"relayed".to_vec())
            .await
            .expect("datagrams were negotiated");
        let back = tokio::time::timeout(Duration::from_secs(10), inbound.recv())
            .await
            .expect("the echo returns")
            .expect("the channel is open");
        assert_eq!(back, b"relayed");
    }

    #[tokio::test]
    async fn the_datagram_stream_is_claimed_exactly_once() {
        let echo = Echo::start(true).await;
        let connection = echo
            .dial(true)
            .await
            .unwrap()
            .drive(CancellationToken::new());

        assert!(connection.receive_datagrams().await.is_some());
        assert!(
            connection.receive_datagrams().await.is_none(),
            "a second claimant is refused rather than given a queue that will \
             see half the packets"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_handshake_to_a_black_hole_gives_up_on_its_deadline() {
        // The OS accepts packets, but no peer reads or answers them.
        let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = sink.local_addr().unwrap();

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(address).await.unwrap();
        let attempt = Handshake::establish(socket, address, "quic.example", Echo::config(false));

        let outcome = tokio::time::timeout(HANDSHAKE_TIMEOUT * 2, attempt)
            .await
            .expect("the deadline fires well inside twice itself");
        assert!(matches!(outcome, Err(EgressError::Quic)));
    }

    #[tokio::test]
    async fn cancelling_the_driver_closes_the_connection() {
        let echo = Echo::start(false).await;
        let shutdown = CancellationToken::new();
        let connection = echo.dial(false).await.unwrap().drive(shutdown.clone());
        assert!(connection.is_alive());

        shutdown.cancel();
        // The handle observes the driver's closed command channel.
        for _ in 0..100 {
            if !connection.is_alive() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the driver did not stop");
    }
}
