//! A QUIC client connection whose bidirectional streams are ordinary async
//! byte streams.
//!
//! Every stream egress so far obtains its byte stream from
//! [`TunnelBypass::tcp`](crate::TunnelBypass) — one socket, one connection, and
//! the kernel does the multiplexing. Hysteria2's streams live *inside* a QUIC
//! connection, so something has to own the UDP socket and the
//! `quiche::Connection` and hand out each bidirectional stream separately. That
//! is what this module is.
//!
//! **It is the same bridge `src/terminate.rs` builds, against a different state
//! machine.** `quiche` is sans-io exactly as `smoltcp` is, so both need a task
//! that owns the I/O, both hand each stream to a consumer over bounded
//! channels, and both take backpressure from the transport's own flow control
//! rather than by dropping bytes. The channels and the stream type are
//! [`crate::bridge`]'s, shared; only the pump differs, because the two stacks
//! disagree about how a peer's FIN and a partial write are reported and
//! flattening that difference would obscure both.
//!
//! **Three phases, and each is a separate type, so a connection cannot be used
//! out of order.** [`Handshake::establish`] returns only once the peer has
//! completed the TLS handshake; [`Handshake::http3`] performs the one request a
//! protocol authenticates with; [`Handshake::drive`] consumes the handshake and
//! yields a [`QuicConnection`] that opens streams. There is no way to open a
//! stream before authentication because [`QuicConnection`] does not exist until
//! the value that could authenticate has been consumed.
//!
//! **HTTP/3 is left behind deliberately once it has done its job.** `quiche`'s
//! `h3::Connection` parses every readable stream as HTTP/3, and Hysteria2's
//! proxy framing would be mistaken for HTTP/3 frames if it saw one — its
//! `0x401` frame type is an *unknown* HTTP/3 frame type, which HTTP/3 requires
//! be skipped along with its length, so the parser would silently consume the
//! address and padding as an extension frame it was told to ignore. So the h3
//! layer is dropped after the response arrives, before any proxy stream exists,
//! and the driver never constructs another. The server's control and QPACK
//! streams that h3 leaves behind are drained and discarded by stream id, which
//! keeps their flow control moving without interpreting them.

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

/// The largest UDP payload the driver will read or write. QUIC's own path MTU
/// discovery keeps sent datagrams below the path's limit; this only has to be
/// large enough not to truncate what arrives, and 1500 is the largest a peer
/// can send over an ordinary Ethernet path without fragmenting.
const MAX_DATAGRAM: usize = 1500;

/// How long [`Handshake::establish`] and [`Handshake::http3`] wait before
/// giving up. QUIC retransmits inside this window; the deadline exists so a
/// black-holed path fails a connection instead of hanging one.
///
/// It is a whole dial rather than a bare handshake — the QUIC handshake, the
/// HTTP/3 settings under it, and the egress's own authentication all happen
/// inside it — so it takes the same budget every other whole dial does rather
/// than a number of its own.
const HANDSHAKE_TIMEOUT: Duration = crate::Wait::ProxyDial.budget();

/// Commands in flight toward the driver. Bounded, because an unbounded command
/// queue is an unbounded number of half-open streams.
const COMMAND_DEPTH: usize = 16;

/// A `quiche::Config` with the transport limits a stream-carrying connection
/// needs.
///
/// **Certificate verification is the caller's to set**, exactly as it is for
/// [`MasqueEgress::client_config`](crate::MasqueEgress::client_config), and for
/// the same reason: a test proxy and a production one differ there and nowhere
/// else. `quiche` verifies by default, so a caller that does nothing gets the
/// safe behaviour and a caller that wants otherwise has to say so.
///
/// The stream windows are sized for bulk transfer rather than for control
/// traffic, because unlike MASQUE's request stream these carry the payload.
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
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM);
    // Connection and stream windows. The connection window is the ceiling on
    // all streams at once; the per-stream window is what one transfer can have
    // in flight, and it must exceed the bandwidth-delay product or a single
    // download stalls waiting for window updates on a long path.
    config.set_initial_max_data(16 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_local(4 * 1024 * 1024);
    config.set_initial_max_stream_data_bidi_remote(4 * 1024 * 1024);
    config.set_initial_max_stream_data_uni(1024 * 1024);
    // These bound what the *peer* may open toward us. A proxy has no business
    // opening request streams back, but HTTP/3 needs its unidirectional control
    // and QPACK streams, so uni is not zero.
    config.set_initial_max_streams_bidi(0);
    config.set_initial_max_streams_uni(8);
    Ok(config)
}

/// A far-future wake for a connection with no timer pending. Keeps the
/// `select!` arm well formed without waking the task to find nothing to do.
fn no_deadline() -> TokioInstant {
    TokioInstant::now() + Duration::from_secs(3600)
}

/// A QUIC connection that has completed its handshake and is not yet owned by a
/// driver task.
///
/// It exists as a separate type so that the authentication a protocol performs
/// before carrying traffic happens somewhere that *cannot* also open a proxy
/// stream — see the module note on why HTTP/3 and proxy streams must not share
/// a connection's readable set.
pub struct Handshake {
    conn: quiche::Connection,
    socket: UdpSocket,
    peer: SocketAddr,
    local: SocketAddr,
    /// The next client-initiated bidirectional stream id to hand out. Client
    /// bidi ids are `0, 4, 8, …` (RFC 9000 §2.1); this advances past whatever
    /// [`Handshake::http3`] consumed, so a proxy stream can never collide with
    /// the authentication request's.
    next_stream_id: u64,
}

/// What an HTTP/3 request on a fresh connection answered.
#[derive(Clone, Debug)]
pub struct H3Response {
    pub status: u16,
    /// Every other header, lowercased by HTTP/3 itself, in arrival order.
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
}

impl H3Response {
    /// The first value for `name`, as UTF-8. `None` when absent or not UTF-8,
    /// which a caller treats as "the server did not say", because a header a
    /// peer garbled is not information.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name.as_bytes())
            .and_then(|(_, value)| std::str::from_utf8(value).ok())
    }
}

impl Handshake {
    /// Opens a QUIC connection to `peer` over `socket` and returns once the
    /// handshake has completed.
    ///
    /// `socket` must already be connected to `peer` — that is what
    /// [`TunnelBypass::udp`](crate::TunnelBypass) returns, and it is also what
    /// makes the socket exempt from Boreas's own tunnel, which a connection
    /// carrying the tunnel's traffic must be.
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

    /// Performs one HTTP/3 request and returns its response headers.
    ///
    /// The request carries no body and is finished immediately, because the one
    /// caller for this is an authentication exchange whose entire content is in
    /// its headers. The h3 connection is dropped before returning: see the
    /// module note on why it must not outlive its single use.
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
        // Everything h3 opened is now spoken for. A proxy stream starts after
        // it, so the two framings never share an id.
        self.next_stream_id = stream_id + 4;

        let mut response = None;
        self.pump_until(|this| {
            // Borrowing `h3` inside a closure that also takes `this` would
            // conflict, so the poll happens here and the predicate only reports
            // what it found.
            loop {
                match h3.poll(&mut this.conn) {
                    Ok((_, quiche::h3::Event::Headers { list, .. })) => {
                        let status = list
                            .iter()
                            .find(|header| header.name() == b":status")
                            .and_then(|header| std::str::from_utf8(header.value()).ok())
                            .and_then(|value| value.parse::<u16>().ok());
                        let Some(status) = status else {
                            // A response without a parseable status is not a
                            // response; stopping here surfaces it as a timeout
                            // rather than as a wrong success.
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

    /// Hands the connection to a background task and returns the handle that
    /// opens streams on it.
    ///
    /// The task ends when `shutdown` is cancelled, when the connection closes,
    /// or when the last handle is dropped — whichever happens first.
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
            wake: Arc::clone(&wake),
            shutdown,
        };
        tokio::spawn(driver.run());
        QuicConnection { commands }
    }

    /// Drives the socket and the connection until `ready` reports satisfaction,
    /// the connection closes, or the handshake deadline passes.
    ///
    /// This is the pre-task loop: it exists because both establishing and
    /// authenticating need I/O before there is anywhere to spawn it, and
    /// because both want a deadline rather than a background lifetime.
    async fn pump_until(
        &mut self,
        mut ready: impl FnMut(&mut Self) -> bool,
    ) -> Result<(), EgressError> {
        // The scratch buffers are locals rather than fields on purpose: a
        // `select!` arm reading into `self.recv_scratch` and a handler writing
        // through `self.conn` would be two borrows of `self`, and hoisting them
        // out is cheaper than the dance required to keep them inside.
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
            // The earlier of QUIC's own timer and the handshake deadline, so a
            // loss recovery timeout still fires inside a bounded wait.
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
                    // A datagram this connection cannot parse is not fatal: on
                    // a shared path it may not even be addressed to us.
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

    /// Sends everything `quiche` has queued.
    async fn flush(&mut self, scratch: &mut [u8]) -> Result<(), EgressError> {
        flush(&mut self.conn, &self.socket, scratch).await
    }
}

/// Drains `quiche`'s send queue onto the socket.
///
/// Free rather than a method because both the pre-task handshake loop and the
/// driver need it and they do not share a `self`.
async fn flush(
    conn: &mut quiche::Connection,
    socket: &UdpSocket,
    scratch: &mut [u8],
) -> Result<(), EgressError> {
    loop {
        let (written, _info) = match conn.send(scratch) {
            Ok(sent) => sent,
            Err(quiche::Error::Done) => return Ok(()),
            Err(_) => return Err(EgressError::Quic),
        };
        socket.send(&scratch[..written]).await?;
    }
}

/// A handle to a live QUIC connection. Cloneable, and every clone opens streams
/// on the same connection — which is the point, because a proxy protocol
/// multiplexes every flow it carries over one.
#[derive(Clone)]
pub struct QuicConnection {
    commands: mpsc::Sender<Command>,
}

enum Command {
    OpenBidi {
        reply: oneshot::Sender<BridgedStream>,
    },
}

impl QuicConnection {
    /// Opens a bidirectional stream.
    ///
    /// Fails when the driver has stopped, which is how a closed connection
    /// reaches a caller: there is no separate liveness flag to consult and then
    /// race against.
    pub async fn open_bidi(&self) -> Result<BridgedStream, EgressError> {
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command::OpenBidi { reply })
            .await
            .map_err(|_| EgressError::Masque)?;
        response.await.map_err(|_| EgressError::Masque)
    }

    /// Whether the driver is still running. Advisory only — a connection can
    /// close between this returning `true` and the next call to
    /// [`Self::open_bidi`] — and useful for deciding whether to reuse a pooled
    /// connection or dial a new one.
    pub fn is_alive(&self) -> bool {
        !self.commands.is_closed()
    }
}

/// The task that owns the socket and the connection.
struct Driver {
    conn: quiche::Connection,
    socket: UdpSocket,
    peer: SocketAddr,
    local: SocketAddr,
    next_stream_id: u64,
    streams: HashMap<u64, Plumbing>,
    commands: mpsc::Receiver<Command>,
    wake: Arc<Notify>,
    shutdown: CancellationToken,
}

impl Driver {
    async fn run(mut self) {
        let mut inbound = vec![0u8; MAX_DATAGRAM];
        let mut outbound = vec![0u8; MAX_DATAGRAM];
        let mut chunk = vec![0u8; CHUNK];
        // Set once every handle is gone: the driver stops accepting new streams
        // but keeps serving the ones already open, because a caller still
        // holding a stream is still entitled to its bytes.
        let mut closing = false;

        loop {
            self.service(&mut chunk);
            if flush(&mut self.conn, &self.socket, &mut outbound)
                .await
                .is_err()
                || self.conn.is_closed()
            {
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
                    // Every handle is gone, so no new stream can ever be asked
                    // for. The open ones are still served until they finish;
                    // breaking here would cut them off mid-response.
                    None => closing = true,
                },
                () = self.wake.notified() => {}
                () = sleep_until(timer) => self.conn.on_timeout(),
            }
        }

        // Say goodbye rather than vanishing: an application close lets the peer
        // release the connection's state now instead of on its idle timer.
        let _ = self.conn.close(true, 0x00, b"done");
        let _ = flush(&mut self.conn, &self.socket, &mut outbound).await;
    }

    fn dispatch(&mut self, command: Command) {
        match command {
            Command::OpenBidi { reply } => {
                // The peer's stream limit is a real refusal, not a wait: a
                // caller that cannot have a stream now should learn it now and
                // fail the flow, rather than block behind an unknown number of
                // other flows finishing.
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

    /// One servicing pass: move bytes in both directions for every live stream,
    /// then retire the ones that finished in both.
    ///
    /// O(readable streams) for the inbound half and O(live streams) for the
    /// outbound half. The latter is a sweep for the same reason the terminator's
    /// is — at the stream counts one connection carries, probing a channel is
    /// cheaper than maintaining a ready list.
    fn service(&mut self, chunk: &mut [u8]) {
        // `readable()` yields an owned iterator, so the connection is free to
        // be mutated inside the loop.
        for id in self.conn.readable() {
            match self.streams.get_mut(&id) {
                Some(plumbing) => pump_in(&mut self.conn, id, plumbing, chunk),
                // A stream we do not own: HTTP/3's leftover control and QPACK
                // streams. Draining keeps their flow control moving and keeps
                // them out of the readable set; nothing interprets the bytes.
                None => while self.conn.stream_recv(id, chunk).is_ok() {},
            }
        }

        for (&id, plumbing) in self.streams.iter_mut() {
            pump_out(&mut self.conn, id, plumbing);
        }

        // A stream is done when the peer has finished sending and we have
        // finished sending. Retiring it here is what bounds the map by live
        // flows rather than by flows ever opened.
        self.streams
            .retain(|_, plumbing| plumbing.to_task.is_some() || !plumbing.finished);
    }
}

/// Peer to consumer. A permit is taken *before* the stream is read, so bytes
/// leave `quiche`'s receive buffer only when there is somewhere to put them;
/// when there is not, the stream's window closes and the peer stops sending.
fn pump_in(conn: &mut quiche::Connection, id: u64, plumbing: &mut Plumbing, buf: &mut [u8]) {
    let mut finished = false;
    let mut abandoned = false;
    while let Some(sender) = plumbing.to_task.as_ref() {
        let permit = match sender.try_reserve() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Full(())) => break,
            // The consumer dropped the stream. Nothing will ever read these
            // bytes, so tell the peer to stop producing them rather than
            // letting the window hold data no one wants.
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
            // A reset stream. The consumer sees end of stream, which is what
            // `AsyncRead` can express; the distinction is documented on
            // `BridgedStream` rather than smuggled into a byte count.
            Err(_) => {
                finished = true;
                break;
            }
        }
    }
    if abandoned {
        let _ = conn.stream_shutdown(id, quiche::Shutdown::Read, 0);
    }
    if finished || abandoned {
        // Dropping the sender gives the consumer its end of stream. Done
        // outside the loop because a reserved permit borrows the very field
        // being cleared.
        plumbing.to_task = None;
    }
}

/// Consumer to peer, without ever dropping a byte: the loop stops at the first
/// sign of a full send buffer and resumes from the same chunk next pass.
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
                // The consumer shut down its write half and everything it wrote
                // is already queued, so the stream's write half closes now.
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    plumbing.finished = true;
                    let _ = conn.stream_send(id, &[], true);
                    return;
                }
            },
        };
        match conn.stream_send(id, &chunk, false) {
            Ok(written) if written < chunk.len() => {
                // A partial write is the flow control window filling up. Keep
                // the tail exactly, and resume from it next pass.
                plumbing.pending_out = Some(chunk.slice(written..));
                return;
            }
            Ok(_) => {}
            // No capacity at all. The chunk goes back untouched; `Done` here
            // means nothing was written, so keeping the whole chunk is correct
            // rather than merely safe.
            Err(quiche::Error::Done) => {
                plumbing.pending_out = Some(chunk);
                return;
            }
            // The peer reset the stream or the connection is gone. Marking it
            // finished stops the sweep from retrying forever.
            Err(_) => {
                plumbing.finished = true;
                return;
            }
        }
    }
}
