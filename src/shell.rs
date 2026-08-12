//! The tokio runtime shell. It interprets the pure [`Datapath`]: one reactor
//! task owns the core by value (no `Arc<Mutex<Datapath>>`), one timer is armed
//! against the core's own next deadline, and every channel is bounded.
//!
//! Three properties carry the design.
//!
//! **Backpressure is asymmetric, so the channels are separate.** Control
//! messages are policy: a slow control plane should block its producer, so
//! [`Control`] is awaited. Datagrams are traffic: blocking a UDP source turns
//! loss into head-of-line delay, so [`Datagram`] is offered with `try_send`
//! and a refusal is a drop. One channel cannot honour both disciplines, which
//! is why there are two.
//!
//! **A packet is not an error.** Every [`DatapathError`] describes one packet
//! that did not make it — malformed input, a configuration that cannot plan,
//! a clock past the end of time. None of them is a reason to stop interpreting
//! the core, so the reactor counts them and continues. Only the device itself
//! can fail fatally.
//!
//! **Telemetry is aggregated, not per-event.** A per-occurrence message would
//! make the telemetry stream O(packets) under exactly the floods that matter
//! most, which is the defect P7 removed from the core's event stream. Counters
//! are folded here and reported on a fixed interval, and telemetry the channel
//! could not accept is itself counted so a gap never reads as quiet.
//!
//! **The egress is inside the reactor, not beside it.** The fused product is
//! one interface: a packet from the client's TUN is encapsulated and put on
//! the network without leaving this task, and a datagram from the network is
//! decapsulated and re-enters the core the same way. Each transmit names the
//! side it belongs on ([`crate::Side`]), so the reactor routes rather than
//! guesses; a shell that owned only a device could do nothing with a fast-path
//! packet but send it back where it came from.

use std::{
    io,
    net::SocketAddr,
    num::NonZeroU64,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::{
    sync::{Semaphore, mpsc},
    time::{Instant as TokioInstant, sleep_until},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    Accepts, Datapath, DnsQuery, EchOutcome, EgressCapabilities, EgressEmit, FlowEvent, HostPolicy,
    InternalEndpoint, Message, PacketEgress, Pooled, Provenance, QueryPlan, Rcode, Resolution,
    SendOutcome, Side, Transmit, Upstream, plan_query, write_failure, write_refusal,
    write_response,
};

/// Depth of both reactor channels. Bounded is the point; the exact depth trades
/// burst tolerance against queueing delay and is not load-bearing.
const CHANNEL_DEPTH: usize = 256;

/// Resolutions in flight at once. A browser opening one page asks for tens of
/// names at the same moment, so serializing them would add a round trip per
/// name; leaving it unbounded would let one page open unbounded upstream
/// state. A query that cannot get a permit waits at the resolver, which backs
/// the bounded query channel up, which turns into a drop at the reactor — and
/// a stub resolver retries a dropped query, which is exactly what it already
/// does for a lost datagram.
const MAX_INFLIGHT_QUERIES: usize = 64;

/// The largest response this shell will build.
///
/// 1232 bytes is the DNS Flag Day 2020 recommendation: it clears the IPv6
/// minimum MTU with room for headers, so a synthesized answer never needs IP
/// fragmentation — which matters because these datagrams are written with the
/// Don't Fragment bit set. A rewritten response that will not fit becomes a
/// `SERVFAIL` rather than a truncated answer.
///
/// ponytail: the correct answer for an over-large response is `TC=1` and a
/// retry over TCP/53, which needs the local termination that arrives with
/// P14. Until then a `SERVFAIL` is the visible failure, and the counter says
/// how often it happens.
const MAX_DNS_RESPONSE: usize = 1232;

/// The largest upstream reply this shell will read. EDNS0 permits more; a
/// resolver answering a stub does not need it.
const MAX_DNS_MESSAGE: usize = 4096;

/// How often accumulated counters are reported. Reporting on a clock rather
/// than per occurrence is what keeps the telemetry stream O(time) instead of
/// O(packets).
const TELEMETRY_INTERVAL: Duration = Duration::from_millis(500);

/// Control messages into the reactor. Bounded and **awaited**: a slow control
/// plane is backpressure on its producer, which is correct for a stream of
/// policy.
#[derive(Debug)]
pub enum Control {
    /// The layer travels with the claim because both are derived from the
    /// same [`crate::Egress`] variant by the sender; apart they could drift.
    CapabilityChange(Accepts, EgressCapabilities),
    /// Ordered shutdown: control messages queued ahead of this one are applied
    /// first. [`Shell::shutdown`] uses the cancellation token instead, which
    /// needs no channel capacity and therefore cannot be refused.
    Shutdown,
}

/// A datagram bound for a flow. Bounded and **never awaited**: see the module
/// documentation for why this is not a `Control` variant.
#[derive(Debug)]
pub struct Datagram {
    pub endpoint: InternalEndpoint,
    pub bytes: Pooled,
}

/// Telemetry out of the reactor. Bounded and best-effort: telemetry loss under
/// saturation is acceptable, flow correctness is not.
///
/// Every counting variant reports occurrences *since the previous report*, so
/// an observer sums rather than diffs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Telemetry {
    /// A per-flow lifecycle event, passed through one for one because the flow
    /// count bounds it.
    Event(FlowEvent),
    /// Datagrams a full per-flow queue refused. Aggregated rather than carrying
    /// an endpoint: the storm is the signal, and a message per drop would be
    /// the very thing the queue exists to bound.
    DatagramsDropped(u64),
    /// Packets the core refused: malformed input, an unplannable flow, or a
    /// deadline past the end of the clock.
    PacketsRejected(u64),
    /// Fragments discarded by reassembly.
    ReassemblyDiscarded(u64),
    /// Packets the core planned to forward but had no pooled buffer for. The
    /// signal that the shared budget, not the network, is the bottleneck.
    TransmitsDropped(u64),
    /// Datagrams the egress refused: not a WireGuard packet, or no buffer for
    /// the emission. Routine on a public port, so counted, not fatal.
    EgressRejected(u64),
    /// One resolved query, with everything needed to explain its verdict.
    ///
    /// Passed through whole rather than folded: a query is a flow-scale event,
    /// not a packet-scale one, and a verdict a user cannot see the reason for
    /// is a verdict they cannot argue with. Boxed so the common counting
    /// variants stay small.
    Resolved(Box<Resolution>),
    /// Queries dropped because the resolver was saturated. The client's stub
    /// resolver retries; this is how an operator sees that it had to.
    QueriesDropped(u64),
    /// Telemetry observations this channel could not accept.
    Lost(u64),
}

/// The effectful half of a session: the four seams the reactor drives, and the
/// host rules the resolver applies. The pure half is the [`Datapath`].
///
/// Grouped rather than passed positionally because they are configuration, and
/// because the set grows with each egress and filtering phase; a constructor
/// that reads as a record does not become a nine-argument call.
pub struct Session<D, N, E, U> {
    /// The client's TUN.
    pub device: D,
    /// The socket carrying the egress's encapsulated datagrams.
    pub network: N,
    /// The packet egress.
    pub egress: E,
    /// The DNS upstream. Never consulted by a session configured with
    /// [`crate::DnsPolicy::Forward`], because the core emits no queries.
    pub upstream: U,
    /// Host rules. Shared rather than owned because P12 swaps them under a
    /// running reactor.
    pub policy: Arc<HostPolicy>,
}

/// A running reactor and the handles that talk to it.
pub struct Shell {
    control: mpsc::Sender<Control>,
    datagrams: mpsc::Sender<Datagram>,
    telemetry: mpsc::Receiver<Telemetry>,
    shutdown: CancellationToken,
    reactor: tokio::task::JoinHandle<io::Result<()>>,
    resolver: tokio::task::JoinHandle<()>,
}

impl Shell {
    /// Starts the reactor on the current runtime. `device` is a
    /// file-descriptor-like async reader/writer of raw IP packets, which P9's
    /// platform adapters supply. The reactor owns the datapath by value, so no
    /// lock guards it and none can be held across an `await`.
    ///
    /// Payload buffers are the caller's concern: a producer takes a [`Pooled`]
    /// from its [`BufferPool`](crate::BufferPool) and hands it to
    /// [`try_send_datagram`](Self::try_send_datagram). The reactor never
    /// allocates payload bytes, which is what makes the pool's budget the real
    /// bound on queue memory.
    /// The reactor and the resolver are two tasks, and the split is
    /// load-bearing: a resolution is a network round trip, and awaiting one
    /// inside the reactor would stall every packet behind a slow upstream.
    /// They meet over two bounded channels, so a saturated resolver becomes a
    /// dropped query — which a stub resolver retries — and never a stalled
    /// datapath.
    pub fn start<D, N, E, U>(datapath: Datapath, session: Session<D, N, E, U>) -> Self
    where
        D: AsyncDevice + Send + 'static,
        N: AsyncNetwork + Send + 'static,
        E: PacketEgress + 'static,
        U: DnsUpstream + 'static,
    {
        let (control_tx, control_rx) = mpsc::channel(CHANNEL_DEPTH);
        let (datagram_tx, datagram_rx) = mpsc::channel(CHANNEL_DEPTH);
        let (telemetry_tx, telemetry_rx) = mpsc::channel(CHANNEL_DEPTH);
        let (query_tx, query_rx) = mpsc::channel(CHANNEL_DEPTH);
        let (answer_tx, answer_rx) = mpsc::channel(CHANNEL_DEPTH);
        let shutdown = CancellationToken::new();

        let Session {
            device,
            network,
            egress,
            upstream,
            policy,
        } = session;

        let resolver = tokio::spawn(resolver_loop(
            Arc::new(upstream),
            policy,
            query_rx,
            answer_tx,
            shutdown.clone(),
        ));

        let reactor = tokio::spawn(reactor_loop(
            datapath,
            device,
            network,
            egress,
            Queries {
                out: query_tx,
                back: answer_rx,
            },
            control_rx,
            datagram_rx,
            TelemetrySink {
                channel: telemetry_tx,
                lost: 0,
            },
            shutdown.clone(),
        ));

        Self {
            control: control_tx,
            datagrams: datagram_tx,
            telemetry: telemetry_rx,
            shutdown,
            reactor,
            resolver,
        }
    }

    /// A control-plane handle. Cloning a `Sender` is how tokio models multiple
    /// producers; the channel stays bounded however many exist.
    pub fn control(&self) -> mpsc::Sender<Control> {
        self.control.clone()
    }

    /// A datagram handle for a producer that wants to own its own `try_send`.
    pub fn datagrams(&self) -> mpsc::Sender<Datagram> {
        self.datagrams.clone()
    }

    /// Offers a datagram to the reactor without waiting. A full queue is a
    /// drop, never a wait.
    ///
    /// The refused `Pooled` handle is dropped here, which returns its bytes to
    /// the pool, so a saturated reactor cannot leak the budget. The outcome is
    /// the caller's to count: the producer knows which flow it belongs to, and
    /// the reactor never sees it.
    pub fn try_send_datagram(&self, endpoint: InternalEndpoint, bytes: Pooled) -> SendOutcome {
        match self.datagrams.try_send(Datagram { endpoint, bytes }) {
            Ok(()) => SendOutcome::Buffered,
            Err(_) => SendOutcome::Dropped,
        }
    }

    /// The next telemetry observation, or `None` once the reactor has stopped.
    pub async fn next_telemetry(&mut self) -> Option<Telemetry> {
        self.telemetry.recv().await
    }

    /// Stops the reactor and drains it: no task outlives this call.
    ///
    /// Cancellation rather than an in-band message, because the token needs no
    /// channel capacity and so cannot be refused by a saturated reactor. A
    /// caller who instead needs shutdown ordered behind queued policy sends
    /// [`Control::Shutdown`] through [`control`](Self::control) first.
    ///
    /// A panic in the reactor is a defect, not an I/O failure, so it is
    /// re-raised here rather than laundered into an `io::Error`.
    pub async fn shutdown(self) -> io::Result<()> {
        self.shutdown.cancel();
        // The resolver is joined too, and it joins its own in-flight
        // resolutions, so no task and no pooled buffer outlives this call.
        let resolver = self.resolver.await;
        let reactor = self.reactor.await;
        if let Err(error) = resolver
            && error.is_panic()
        {
            std::panic::resume_unwind(error.into_panic());
        }
        match reactor {
            Ok(result) => result,
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(error) => Err(io::Error::other(error)),
        }
    }
}

/// The async side of the device seam: raw IP packets with readiness, supplied
/// by P9's platform adapters. Futures must be `Send` so the reactor can live on
/// a multi-threaded runtime; the trait is written with explicit future types
/// because `async fn` in a public trait cannot promise that.
pub trait AsyncDevice {
    /// Reads one packet into `buf`, returning its length.
    ///
    /// **Must be cancel-safe.** The reactor selects over this future alongside
    /// its timer and channels, so a future that is polled and then dropped is
    /// routine, not exceptional. An implementation that has already consumed a
    /// packet when its future is dropped loses that packet. A readiness-based
    /// read over an OS handle satisfies this, as does awaiting a tokio channel;
    /// an adapter that dequeues before awaiting does not.
    fn recv<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = io::Result<usize>> + Send + 'a;

    /// Writes one packet. Called only from the reactor's drain phase, never
    /// concurrently with itself, and never inside a `select!`.
    fn send<'a>(&'a mut self, buf: &'a [u8])
    -> impl Future<Output = io::Result<usize>> + Send + 'a;
}

/// The network side of the fused interface: encapsulated datagrams to and from
/// the egress's peer. Shaped like [`AsyncDevice`] and deliberately a separate
/// trait, because the bytes are not IP packets and the two seams are never
/// interchangeable — crossing them is the loopback defect [`Side`] exists to
/// prevent.
///
/// A connected `tokio::net::UdpSocket` is the production implementation and is
/// provided below; tests supply a scripted one.
pub trait AsyncNetwork {
    /// Reads one datagram into `buf`, returning its length.
    ///
    /// **Must be cancel-safe**, for the same reason as
    /// [`AsyncDevice::recv`]: the reactor selects over this future and drops
    /// it routinely.
    fn recv<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = io::Result<usize>> + Send + 'a;

    /// Writes one datagram to the peer. Called only from the drain phase.
    fn send<'a>(&'a mut self, buf: &'a [u8])
    -> impl Future<Output = io::Result<usize>> + Send + 'a;
}

/// A UDP socket already connected to the egress peer's endpoint. `recv` and
/// `send` on a connected socket are cancel-safe by tokio's own contract: they
/// are readiness-driven and consume nothing until the syscall succeeds.
impl AsyncNetwork for tokio::net::UdpSocket {
    fn recv<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = io::Result<usize>> + Send + 'a {
        tokio::net::UdpSocket::recv(self, buf)
    }

    fn send<'a>(
        &'a mut self,
        buf: &'a [u8],
    ) -> impl Future<Output = io::Result<usize>> + Send + 'a {
        tokio::net::UdpSocket::send(self, buf)
    }
}

/// One DNS upstream transport.
///
/// Only the wire. The policy that decides whether to consult an upstream at
/// all, and what to do with what it says, is pure and lives in
/// [`crate::dns`](crate); the single thing this trait contributes to a verdict
/// is which [`Upstream`] it was.
pub trait DnsUpstream: Send + Sync {
    /// The transport kind, which is what a verdict's provenance records.
    fn kind(&self) -> Upstream;

    /// Sends one DNS message and returns the reply.
    ///
    /// Called from a task of its own, never from the reactor, so it may await
    /// as long as it likes without stalling the datapath. It must impose its
    /// own timeout: the resolver bounds how many of these run at once, not how
    /// long any one of them takes.
    fn query(&self, message: &[u8]) -> impl Future<Output = io::Result<Vec<u8>>> + Send;
}

/// Creates the sockets a DNS upstream uses.
///
/// It exists because those sockets must not travel through Boreas's own TUN —
/// a resolver reached through the tunnel that is resolving for it is a loop —
/// and excluding them is a platform act this crate cannot perform:
/// `VpnService.protect` on the descriptor on Android, binding the physical
/// interface's address on Windows. The seam names the obligation so that no
/// implementation can quietly skip it.
pub trait TunnelBypass: Send + Sync {
    fn udp(
        &self,
        peer: SocketAddr,
    ) -> impl Future<Output = io::Result<tokio::net::UdpSocket>> + Send;
}

/// The bypass for a host where nothing is in the way: an ordinary ephemeral
/// socket on the default route.
///
/// Correct on a desktop whose default route is not the tunnel, and the
/// deliberate wrong answer on Android, where the socket must be protected
/// before it is connected. Named for what it does not do.
pub struct DirectSockets;

impl TunnelBypass for DirectSockets {
    // Written as an explicit future type for the same reason `AsyncDevice` is:
    // the trait promises `Send`, and only the explicit form states it.
    #[allow(clippy::manual_async_fn)]
    fn udp(
        &self,
        peer: SocketAddr,
    ) -> impl Future<Output = io::Result<tokio::net::UdpSocket>> + Send {
        async move {
            let bind: SocketAddr = if peer.is_ipv4() {
                ([0, 0, 0, 0], 0).into()
            } else {
                ([0u16; 8], 0).into()
            };
            let socket = tokio::net::UdpSocket::bind(bind).await?;
            socket.connect(peer).await?;
            Ok(socket)
        }
    }
}

/// Plain DNS over UDP to one resolver.
///
/// One ephemeral socket per query, which is what makes concurrent queries
/// correlate without a transaction-id demultiplexer: a connected socket
/// receives exactly its own reply, and the random source port is the entropy a
/// spoofing attacker has to beat.
///
/// Do53 is readable by anything on the path, which is why [`Upstream`]
/// distinguishes it. It is the transport that needs no TLS stack, and so the
/// one that can exist before the crate admits one.
pub struct Do53Upstream<B> {
    resolver: SocketAddr,
    bypass: B,
    timeout: Duration,
}

impl<B: TunnelBypass> Do53Upstream<B> {
    /// Two seconds matches what stub resolvers already assume; a longer wait
    /// holds a permit that another query could be using.
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

    pub fn new(resolver: SocketAddr, bypass: B) -> Self {
        Self {
            resolver,
            bypass,
            timeout: Self::DEFAULT_TIMEOUT,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl<B: TunnelBypass> DnsUpstream for Do53Upstream<B> {
    fn kind(&self) -> Upstream {
        Upstream::Do53
    }

    #[allow(clippy::manual_async_fn)]
    fn query(&self, message: &[u8]) -> impl Future<Output = io::Result<Vec<u8>>> + Send {
        async move {
            let socket = self.bypass.udp(self.resolver).await?;
            socket.send(message).await?;
            let mut reply = vec![0u8; MAX_DNS_MESSAGE];
            let len = tokio::time::timeout(self.timeout, socket.recv(&mut reply))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "upstream did not answer")
                })??;
            reply.truncate(len);
            Ok(reply)
        }
    }
}

/// One resolved query, on its way back to the reactor that will address it.
struct Answer {
    client: InternalEndpoint,
    resolver: InternalEndpoint,
    message: Vec<u8>,
    resolution: Resolution,
}

/// The reactor's half of the resolver channels.
struct Queries {
    out: mpsc::Sender<DnsQuery>,
    back: mpsc::Receiver<Answer>,
}

/// Resolves intercepted queries until cancelled.
///
/// Concurrency is bounded by a semaphore rather than by the channel alone: a
/// permit is the admission to hold upstream state, and a query that cannot get
/// one waits here, which backs the query channel up, which becomes a counted
/// drop at the reactor. Every spawned resolution is tracked, so shutdown joins
/// them and no pooled buffer outlives the shell.
async fn resolver_loop<U: DnsUpstream + 'static>(
    upstream: Arc<U>,
    policy: Arc<HostPolicy>,
    mut queries: mpsc::Receiver<DnsQuery>,
    answers: mpsc::Sender<Answer>,
    shutdown: CancellationToken,
) {
    let permits = Arc::new(Semaphore::new(MAX_INFLIGHT_QUERIES));
    let tracker = TaskTracker::new();

    loop {
        let query = tokio::select! {
            _ = shutdown.cancelled() => break,
            query = queries.recv() => match query {
                Some(query) => query,
                None => break,
            },
        };
        let Ok(permit) = Arc::clone(&permits).acquire_owned().await else {
            break;
        };
        let upstream = Arc::clone(&upstream);
        let policy = Arc::clone(&policy);
        let answers = answers.clone();
        tracker.spawn(async move {
            let _permit = permit;
            if let Some(answer) = resolve(upstream.as_ref(), policy.as_ref(), query).await {
                // Best-effort: a reactor that cannot accept the answer is one
                // whose client has long since retried.
                let _ = answers.try_send(answer);
            }
        });
    }

    tracker.close();
    tracker.wait().await;
}

/// Resolves one query: plan, consult (or do not), rewrite, explain.
///
/// `None` only when the query is not a DNS message at all, which is a drop
/// rather than an answer — there is no question to put in a response.
async fn resolve<U: DnsUpstream>(
    upstream: &U,
    policy: &HostPolicy,
    query: DnsQuery,
) -> Option<Answer> {
    let DnsQuery {
        client,
        resolver,
        payload,
    } = query;
    let request = Message::parse(&payload).ok()?;
    let question = *request.question();
    let mut message = vec![0u8; MAX_DNS_RESPONSE];

    let (len, resolution) = match plan_query(&question, policy) {
        // A refused name never leaves the device, so the block costs no query
        // and leaks no name to any upstream.
        QueryPlan::Refuse { rule } => (
            write_refusal(&mut message, &request).ok()?,
            Resolution {
                name: question.name,
                qtype: question.qtype,
                rcode: Rcode::NameError,
                answers: 0,
                provenance: Provenance::Policy,
                rule: Some(rule),
                ech: EchOutcome::Absent,
            },
        ),
        QueryPlan::Forward { ech } => {
            let kind = upstream.kind();
            let rewritten = match upstream.query(&payload).await {
                Ok(reply) => Message::parse(&reply).and_then(|reply| {
                    write_response(&mut message, &request, &reply, ech)
                        .map(|rewritten| (rewritten, reply.rcode()))
                }),
                Err(_) => Err(crate::DnsError::Truncated),
            };
            match rewritten {
                Ok((rewritten, rcode)) => (
                    rewritten.len,
                    Resolution {
                        name: question.name,
                        qtype: question.qtype,
                        rcode,
                        answers: rewritten.answers,
                        provenance: Provenance::Upstream(kind),
                        rule: None,
                        ech: rewritten.ech,
                    },
                ),
                // An upstream that did not answer, answered with something
                // unparseable, or answered with more than this shell will
                // carry, all reach the client the same visible way: a
                // `SERVFAIL` its stub resolver retries, never a silent drop
                // that stalls the application until its own timeout.
                Err(_) => (
                    write_failure(&mut message, &request).ok()?,
                    Resolution {
                        name: question.name,
                        qtype: question.qtype,
                        rcode: Rcode::ServerFailure,
                        answers: 0,
                        provenance: Provenance::Upstream(kind),
                        rule: None,
                        ech: EchOutcome::Absent,
                    },
                ),
            }
        }
    };

    message.truncate(len);
    Some(Answer {
        client,
        resolver,
        message,
        resolution,
    })
}

/// Best-effort telemetry with visible loss. Never awaits: telemetry must not be
/// able to stall the datapath.
struct TelemetrySink {
    channel: mpsc::Sender<Telemetry>,
    lost: u64,
}

impl TelemetrySink {
    /// Offers one observation. A refusal increments `lost`, which is flushed as
    /// [`Telemetry::Lost`] on the next send that succeeds, so an observer never
    /// mistakes a gap in the stream for quiet.
    fn emit(&mut self, observation: Telemetry) {
        if self.channel.try_send(observation).is_err() {
            self.lost = self.lost.saturating_add(1);
            return;
        }
        if let Some(lost) = NonZeroU64::new(self.lost)
            && self.channel.try_send(Telemetry::Lost(lost.get())).is_ok()
        {
            self.lost = 0;
        }
    }
}

/// Occurrences the reactor folds between reports. The identity is zero and the
/// operation is addition, so a report is a fold that resets its accumulator.
#[derive(Default)]
struct Counters {
    datagrams_dropped: u64,
    packets_rejected: u64,
    reassembly_discarded: u64,
    transmits_dropped: u64,
    egress_rejected: u64,
    queries_dropped: u64,
}

impl Counters {
    /// Reports every non-zero counter and resets it. `NonZeroU64` is doing the
    /// work of the `> 0` test, so "report nothing when nothing happened" is a
    /// property of the type rather than a branch to keep in step.
    fn flush(&mut self, sink: &mut TelemetrySink) {
        let mut report = |count: &mut u64, into: fn(u64) -> Telemetry| {
            if let Some(total) = NonZeroU64::new(*count) {
                sink.emit(into(total.get()));
                *count = 0;
            }
        };
        report(&mut self.datagrams_dropped, Telemetry::DatagramsDropped);
        report(&mut self.packets_rejected, Telemetry::PacketsRejected);
        report(
            &mut self.reassembly_discarded,
            Telemetry::ReassemblyDiscarded,
        );
        report(&mut self.transmits_dropped, Telemetry::TransmitsDropped);
        report(&mut self.egress_rejected, Telemetry::EgressRejected);
        report(&mut self.queries_dropped, Telemetry::QueriesDropped);
    }
}

/// Interprets the pure core until cancelled or until its owner drops.
///
/// One iteration is: wait for the earliest of cancellation, a control message,
/// a datagram, a packet from either seam, or the next deadline; advance the
/// core; then drain whatever the core and the egress produced. The wait is
/// `select!` without `biased`, so a saturated device cannot starve the control
/// plane; cancellation is re-polled every pass and therefore wins within a
/// small, bounded number of them.
///
/// Three deadlines share one `Sleep`: the core's own (`poll_timeout`), the
/// telemetry report, and the egress's tick. The minimum of the three is what
/// the timer is armed against, so an idle tunnel still wakes on WireGuard's
/// cadence and nothing wakes on a poll interval.
#[allow(clippy::too_many_arguments)]
async fn reactor_loop<D: AsyncDevice, N: AsyncNetwork, E: PacketEgress>(
    mut datapath: Datapath,
    mut device: D,
    mut network: N,
    mut egress: E,
    mut queries: Queries,
    mut control: mpsc::Receiver<Control>,
    mut datagrams: mpsc::Receiver<Datagram>,
    mut telemetry: TelemetrySink,
    shutdown: CancellationToken,
) -> io::Result<()> {
    let mut tun_buf = vec![0u8; MAX_PACKET_BYTES];
    let mut net_buf = vec![0u8; MAX_PACKET_BYTES];
    // One emission sink for the life of the reactor. The egress appends and
    // the drain phase empties it, so a packet costs no allocation for the
    // container it travels in.
    let mut emits: Vec<EgressEmit> = Vec::new();
    let mut counters = Counters::default();
    let mut next_flush = TokioInstant::now() + TELEMETRY_INTERVAL;
    let tick_interval = egress.tick_interval();
    let mut next_tick = TokioInstant::now() + tick_interval;

    // One `Sleep`, reset per iteration rather than reallocated: re-arming an
    // existing timer entry is what keeps the wait off the per-packet cost.
    let sleep = sleep_until(next_flush);
    tokio::pin!(sleep);

    loop {
        // The core's own next deadline, not a poll interval. `None` means no
        // state machine has pending work, so the reactor waits only for its
        // reporting tick, the egress's tick, and its input sources.
        let core_deadline = datapath.poll_timeout().map(TokioInstant::from_std);
        let wake = core_deadline
            .into_iter()
            .chain([next_flush, next_tick])
            .min()
            .unwrap_or(next_flush);
        sleep.as_mut().reset(wake);

        tokio::select! {
            _ = shutdown.cancelled() => break,

            message = control.recv() => match message {
                Some(Control::CapabilityChange(accepts, next)) => {
                    datapath.on_capability_change(accepts, next);
                }
                // An explicit shutdown and a dropped owner are the same
                // request: nobody is left to steer this reactor.
                Some(Control::Shutdown) | None => break,
            },

            Some(datagram) = datagrams.recv() => {
                let Datagram { endpoint, bytes } = datagram;
                match datapath.send_datagram(endpoint, bytes, Instant::now()) {
                    Ok(SendOutcome::Buffered) => {}
                    // The core already emitted `DatagramDropped`; the drain
                    // phase below folds it into the counter.
                    Ok(SendOutcome::Dropped) => {}
                    Err(_) => counters.packets_rejected += 1,
                }
            }

            result = device.recv(&mut tun_buf) => match result {
                Ok(len) => {
                    // Untrusted input: a rejected packet is an observation, not
                    // a reason to stop interpreting the core.
                    if datapath.on_tun_packet(&tun_buf[..len], Instant::now()).is_err() {
                        counters.packets_rejected += 1;
                    }
                }
                // A signal interrupted the read; the packet is still there.
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                // The device itself failed. That is not recoverable here.
                Err(error) => return Err(error),
            },

            // A resolved query. Bounded by the answer channel, and addressed
            // back to the client from the resolver address it asked.
            Some(answer) = queries.back.recv() => {
                let Answer { client, resolver, message, resolution } = answer;
                if datapath.answer_dns(client, resolver, &message).is_err() {
                    counters.packets_rejected += 1;
                }
                telemetry.emit(Telemetry::Resolved(Box::new(resolution)));
            }

            result = network.recv(&mut net_buf) => match result {
                // Anything can arrive on a public UDP port. A datagram the
                // egress refuses is counted, exactly like a malformed packet.
                Ok(len) => {
                    if egress.handle_network_packet(&net_buf[..len], &mut emits).is_err() {
                        counters.egress_rejected += 1;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            },

            () = &mut sleep => {}
        }

        let now = Instant::now();
        if core_deadline.is_some_and(|deadline| deadline <= TokioInstant::from_std(now)) {
            datapath.on_timeout(now);
        }
        if TokioInstant::from_std(now) >= next_tick {
            if egress.tick(&mut emits).is_err() {
                counters.egress_rejected += 1;
            }
            next_tick = TokioInstant::from_std(now) + tick_interval;
        }

        drain(
            &mut datapath,
            &mut device,
            &mut network,
            &mut egress,
            &mut emits,
            &mut queries.out,
            &mut telemetry,
            &mut counters,
        )
        .await?;

        if TokioInstant::from_std(now) >= next_flush {
            counters.flush(&mut telemetry);
            next_flush = TokioInstant::from_std(now) + TELEMETRY_INTERVAL;
        }
    }

    // Everything the core has already decided still belongs on the wire.
    drain(
        &mut datapath,
        &mut device,
        &mut network,
        &mut egress,
        &mut emits,
        &mut queries.out,
        &mut telemetry,
        &mut counters,
    )
    .await?;
    counters.flush(&mut telemetry);
    Ok(())
}

/// Moves what the core and the egress produced to where each belongs.
///
/// The two producers feed each other: an egress emission bound for the tunnel
/// re-enters the core and becomes a transmit, and a transmit bound for the
/// egress becomes an emission. Neither chain extends further — a tunnel-bound
/// transmit goes to the device and a network-bound emission goes to the socket,
/// and both are terminal — so alternating the two drains reaches a fixpoint in
/// at most two passes and the loop needs no separate iteration limit.
#[allow(clippy::too_many_arguments)]
async fn drain<D: AsyncDevice, N: AsyncNetwork, E: PacketEgress>(
    datapath: &mut Datapath,
    device: &mut D,
    network: &mut N,
    egress: &mut E,
    emits: &mut Vec<EgressEmit>,
    queries: &mut mpsc::Sender<DnsQuery>,
    telemetry: &mut TelemetrySink,
    counters: &mut Counters,
) -> io::Result<()> {
    loop {
        for emit in emits.drain(..) {
            match emit {
                EgressEmit::ToNetwork(bytes) => {
                    network.send(&bytes).await?;
                }
                // A decapsulated packet is ordinary untrusted input on the
                // egress side of the core, and is classified there.
                EgressEmit::ToTunnel(bytes) => {
                    if datapath.on_egress_packet(&bytes, Instant::now()).is_err() {
                        counters.packets_rejected += 1;
                    }
                }
            }
        }

        while let Some(Transmit { to, bytes }) = datapath.poll_transmit() {
            match to {
                Side::Tunnel => {
                    device.send(&bytes).await?;
                }
                Side::Egress => {
                    if egress.handle_tun_packet(&bytes, emits).is_err() {
                        counters.egress_rejected += 1;
                    }
                }
            }
        }

        if emits.is_empty() {
            break;
        }
    }

    // Intercepted queries go to the resolver without waiting. Blocking here
    // would put a slow upstream in front of every packet, which is the whole
    // reason the resolver is a separate task; a refusal is a drop the client's
    // stub resolver retries.
    while let Some(query) = datapath.poll_query() {
        if queries.try_send(query).is_err() {
            counters.queries_dropped += 1;
        }
    }

    while let Some(event) = datapath.poll_event() {
        match event {
            // All three are per-packet under a flood, so all three are folded
            // rather than forwarded; see the module documentation.
            FlowEvent::ReassemblyDiscarded => counters.reassembly_discarded += 1,
            FlowEvent::DatagramDropped(_) => counters.datagrams_dropped += 1,
            FlowEvent::TransmitDropped => counters.transmits_dropped += 1,
            // Flow lifecycle events are bounded by the flow count, so they
            // pass through one for one.
            event @ (FlowEvent::StreamOpened(_)
            | FlowEvent::DatagramOpened(_)
            | FlowEvent::Resteered(_)
            | FlowEvent::FlowTornDown(_)) => telemetry.emit(Telemetry::Event(event)),
        }
    }

    Ok(())
}

/// Receive buffer size. A TUN device never presents more than its own MTU, and
/// the largest MTU an IP header can describe is 65 535 bytes; 2 KiB covers
/// every configuration Boreas sets up and is what the harness already assumes.
const MAX_PACKET_BYTES: usize = 2048;
