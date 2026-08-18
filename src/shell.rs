//! The tokio runtime shell. It interprets the pure [`Datapath`]: one reactor
//! task owns the core by value (no `Arc<Mutex<Datapath>>`), one timer is armed
//! against the core's own next deadline, and every channel is bounded.
//!
//! Three properties carry the design.
//!
//! **Backpressure is asymmetric, so the channels are separate.** Control
//! messages are policy: a slow control plane should block its producer, so
//! [`Control`] is awaited. Datagrams are traffic: blocking a UDP source turns
//! loss into head-of-line delay, so every datagram channel is offered with
//! `try_send` and a refusal is a drop. One channel cannot honour both
//! disciplines, which is why they are separate.
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
    num::NonZeroU64,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::{
    sync::{Semaphore, mpsc, watch},
    time::{Instant as TokioInstant, sleep_until},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    Accepts, AlpnOutcome, Datapath, DnsQuery, EchOutcome, EgressEmit, FlowEvent, HostPolicy,
    Inbound, InternalEndpoint, Message, PacketEgress, PathProperties, Pooled, Provenance,
    QueryPlan, Rcode, Relay, Resolution, RuleCounts, SendOutcome, Side, Transmit, answer_addresses,
    plan_query, upstream::DnsUpstream, write_failure, write_refusal, write_response,
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
    PathChange(Accepts, PathProperties),
    /// Ordered shutdown: control messages queued ahead of this one are applied
    /// first. [`Shell::shutdown`] uses the cancellation token instead, which
    /// needs no channel capacity and therefore cannot be refused.
    Shutdown,
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
    /// QUIC attempts the steering backstop refused. Convergence is this
    /// falling back to zero once the browser has re-raced to TCP.
    QuicSteered(u64),
    /// Over-sized packets answered with an ICMP Packet Too Big. A count that
    /// stays high past a client's path discovery is a link MTU configured
    /// wider than the tunnel can carry, which is a configuration fault this
    /// number is the only visible symptom of.
    PathsReported(u64),
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
    /// A new host policy took effect, with the rules it holds. Emitted on the
    /// swap rather than counted, because a reload is an operator action and
    /// there is one of them, not one per packet.
    PolicyReloaded(RuleCounts),
    /// Packets of terminated flows the local TCP stack could not accept: its
    /// queue was full, or the session routed a flow to termination without a
    /// terminator configured. TCP retransmits, so this is congestion or
    /// misconfiguration rather than data loss.
    TerminationDropped(u64),
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
    /// Host rules, hot-swappable.
    ///
    /// A `watch` channel rather than an `Arc` because a filter-list build
    /// replaces the whole index at once and must not stall the datapath doing
    /// it: the sender publishes a freshly compiled policy, and each query is
    /// decided against exactly one version — the one current when it was
    /// admitted — so a reload mid-flight cannot split a decision in half.
    ///
    /// Both tasks hold a receiver, which is what a `watch` channel is for: the
    /// resolver reads it to decide, and the reactor observes the change to
    /// report it.
    pub policy: watch::Receiver<Arc<HostPolicy>>,
    /// The local TCP terminator, when this session terminates flows.
    pub termination: Option<Termination>,
    /// The datagram relay, when this session's egress accepts flows rather
    /// than packets.
    ///
    /// An option for the same reason [`Termination`] is: a packet egress
    /// carries a datagram as the packet it already is, so it needs no
    /// association and no second task. A flow egress that carries no datagrams
    /// at all also carries `None`, and its path properties
    /// (`datagram_fidelity: None`) is what already said so.
    pub relay: Option<Relay>,
}

/// The local TCP terminator's two channels, from the reactor's side.
///
/// Present only for a session that terminates flows. A pure packet-path
/// session never routes a flow to [`crate::TransportPath::LocalTermination`],
/// so it needs no stack and carries `None` — which is why this is an option
/// rather than a always-present pair of idle channels.
pub struct Termination {
    /// Packets of terminated flows, offered to the terminator without waiting:
    /// a full queue is a counted drop, and TCP retransmits, exactly as the
    /// forward path treats congestion.
    pub packets: mpsc::Sender<Pooled>,
    /// Segments the terminator produced for the client. The reactor owns the
    /// device, so they are written here rather than there — and dropping one
    /// after the write is what returns its buffer to the shared budget.
    pub replies: mpsc::Receiver<Pooled>,
}

/// A running reactor and the handles that talk to it.
pub struct Shell {
    control: mpsc::Sender<Control>,
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
    /// Payload buffers are never allocated here: every one of them is on loan
    /// from the [`BufferPool`](crate::BufferPool) the datapath already owns,
    /// which is what makes that budget the real bound on queue memory.
    ///
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
            termination,
            relay,
        } = session;

        let resolver = tokio::spawn(resolver_loop(
            Arc::new(upstream),
            Arc::clone(datapath.pool()),
            policy.clone(),
            query_rx,
            answer_tx,
            shutdown.clone(),
        ));

        let reactor = tokio::spawn(reactor_loop(
            datapath,
            device,
            network,
            egress,
            policy,
            Queries {
                out: query_tx,
                back: answer_rx,
            },
            control_rx,
            TelemetrySink {
                channel: telemetry_tx,
                lost: 0,
            },
            termination,
            relay,
            shutdown.clone(),
        ));

        Self {
            control: control_tx,
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
    /// The MTU the interface is configured with. It sizes the reactor's receive
    /// buffer, so a packet this device can legitimately present always fits:
    /// a fixed constant would either waste memory on a small tunnel or truncate
    /// a valid packet on a large one, and only the adapter knows which.
    fn mtu(&self) -> crate::Mtu;

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

    /// Writes one packet **whole**. Called only from the reactor's drain phase,
    /// never concurrently with itself, and never inside a `select!`.
    ///
    /// **The unit is the packet, so the result carries no byte count.** A TUN
    /// write and a datagram send are both all-or-nothing at the OS boundary,
    /// and there is no correct handling of "some of this IP packet reached the
    /// wire": the remainder cannot be re-sent as a second packet, because it
    /// carries no header. An implementation that observes a short write must
    /// therefore report [`io::ErrorKind::WriteZero`] rather than return, which
    /// is what makes the absent `usize` a guarantee instead of an omission.
    fn send<'a>(&'a mut self, buf: &'a [u8]) -> impl Future<Output = io::Result<()>> + Send + 'a;
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

    /// Writes one datagram to the peer, whole. Called only from the drain
    /// phase. See [`AsyncDevice::send`] for why the byte count is absent.
    fn send<'a>(&'a mut self, buf: &'a [u8]) -> impl Future<Output = io::Result<()>> + Send + 'a;
}

/// Reports a short write as the failure it is.
///
/// The one place the `usize` an OS returns is turned back into the total
/// contract the seams declare, so no caller downstream has to remember that
/// "wrote some bytes" and "sent the packet" are different statements.
pub(crate) fn whole(written: usize, expected: usize) -> io::Result<()> {
    if written == expected {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::WriteZero,
        format!("wrote {written} of {expected} packet bytes"),
    ))
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

    // Written out rather than as an `async fn` so the returned future's `Send`
    // bound is stated in the signature, which is what the trait requires.
    #[allow(clippy::manual_async_fn)]
    fn send<'a>(&'a mut self, buf: &'a [u8]) -> impl Future<Output = io::Result<()>> + Send + 'a {
        async move { whole(tokio::net::UdpSocket::send(self, buf).await?, buf.len()) }
    }
}

/// One resolved query, on its way back to the reactor that will address it.
struct Answer {
    client: InternalEndpoint,
    resolver: InternalEndpoint,
    /// The response bytes, on the same budget as every other payload the
    /// session holds. A `Vec` here would be per-query memory outside every
    /// bound the crate states, which is precisely the memory a query flood
    /// grows.
    message: Pooled,
    resolution: Resolution,
    /// Addresses this answer resolved to for a steered host. Empty for every
    /// other verdict, so the index grows only by what inspection put in it.
    steered: Vec<std::net::IpAddr>,
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
    pool: Arc<crate::BufferPool>,
    policy: watch::Receiver<Arc<HostPolicy>>,
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
        let pool = Arc::clone(&pool);
        // One snapshot, taken as the query is admitted. The borrow is released
        // before the task is spawned, so no guard crosses an `await` and a
        // reload cannot change a decision half-way through it.
        let policy = Arc::clone(&policy.borrow());
        let answers = answers.clone();
        tracker.spawn(async move {
            let _permit = permit;
            if let Some(answer) = resolve(upstream.as_ref(), &pool, policy.as_ref(), query).await {
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
/// `None` when the query is not a DNS message at all, or when the shared budget
/// has no room to build a response — both are drops rather than answers, and a
/// stub resolver retries a dropped query exactly as it does a lost datagram.
async fn resolve<U: DnsUpstream>(
    upstream: &U,
    pool: &Arc<crate::BufferPool>,
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
    let mut message = pool.take_zeroed(MAX_DNS_RESPONSE)?;
    let mut steered = Vec::new();

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
                alpn: AlpnOutcome::Absent,
            },
        ),
        QueryPlan::Forward { policy } => {
            let kind = upstream.kind();
            let rewritten = match upstream.query(&payload).await {
                Ok(reply) => Message::parse(&reply).and_then(|reply| {
                    // The steering index is fed from the upstream's own
                    // answers, before the rewrite, so extracting it costs no
                    // second parse of what this shell just wrote.
                    if policy.steers() {
                        answer_addresses(&reply, &mut steered)?;
                    }
                    write_response(&mut message, &request, &reply, policy)
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
                        alpn: rewritten.alpn,
                    },
                ),
                // An upstream that did not answer, answered with something
                // unparseable, or answered with more than this shell will
                // carry, all reach the client the same visible way: a
                // `SERVFAIL` its stub resolver retries, never a silent drop
                // that stalls the application until its own timeout.
                Err(_) => {
                    // A failed rewrite must not leave half an index behind.
                    steered.clear();
                    (
                        write_failure(&mut message, &request).ok()?,
                        Resolution {
                            name: question.name,
                            qtype: question.qtype,
                            rcode: Rcode::ServerFailure,
                            answers: 0,
                            provenance: Provenance::Upstream(kind),
                            rule: None,
                            ech: EchOutcome::Absent,
                            alpn: AlpnOutcome::Absent,
                        },
                    )
                }
            }
        }
    };

    // Never grows: `len` is a prefix of the buffer just written, so the resize
    // is a truncation and the pool's slice bound is already satisfied.
    let _ = message.resize(len);
    Some(Answer {
        client,
        resolver,
        message,
        resolution,
        steered,
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
    quic_steered: u64,
    paths_reported: u64,
    termination_dropped: u64,
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
        report(&mut self.quic_steered, Telemetry::QuicSteered);
        report(&mut self.paths_reported, Telemetry::PathsReported);
        report(&mut self.termination_dropped, Telemetry::TerminationDropped);
    }
}

/// The terminator's next segment for the client, or a future that never
/// completes when this session has no terminator.
///
/// `recv` is cancel-safe, so losing this arm of the reactor's `select!` to a
/// busier one costs nothing: the next pass still sees the segment.
async fn next_reply(termination: &mut Option<Termination>) -> Option<Pooled> {
    match termination {
        Some(termination) => termination.replies.recv().await,
        None => std::future::pending().await,
    }
}

/// The relay's next datagram from the egress, or a future that never completes
/// when this session has no relay. `recv` is cancel-safe, so losing this arm
/// costs nothing.
async fn next_inbound(relay: &mut Option<Relay>) -> Option<Inbound> {
    match relay {
        Some(relay) => relay.inbound.recv().await,
        None => std::future::pending().await,
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
    mut policy: watch::Receiver<Arc<HostPolicy>>,
    mut queries: Queries,
    mut control: mpsc::Receiver<Control>,
    mut telemetry: TelemetrySink,
    mut termination: Option<Termination>,
    mut relay: Option<Relay>,
    shutdown: CancellationToken,
) -> io::Result<()> {
    // Both buffers are sized from the seam that fills them rather than from a
    // constant: the device states its own MTU, and the egress states the
    // largest datagram its peer can send it. A fixed 2 KiB was correct for a
    // 1500-byte tunnel and silently wrong for anything larger.
    let mut tun_buf = vec![0u8; usize::from(device.mtu().get())];
    let mut net_buf = vec![0u8; egress.max_network_datagram()];
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
        let mut reply: Option<Pooled> = None;
        let core_deadline = datapath.poll_timeout().map(TokioInstant::from_std);
        // The egress may name a deadline more precisely than its cadence —
        // QUIC's loss-recovery timer moves, where WireGuard's rounds to the
        // second — so it joins the fold rather than being approximated by the
        // tick interval. One timer still serves every deadline in the session.
        let egress_deadline = egress.next_deadline().map(TokioInstant::from_std);
        let wake = core_deadline
            .into_iter()
            .chain(egress_deadline)
            .chain([next_flush, next_tick])
            .min()
            .unwrap_or(next_flush);
        sleep.as_mut().reset(wake);

        tokio::select! {
            _ = shutdown.cancelled() => break,

            message = control.recv() => match message {
                Some(Control::PathChange(accepts, next)) => {
                    datapath.on_path_change(accepts, next);
                }
                // An explicit shutdown and a dropped owner are the same
                // request: nobody is left to steer this reactor.
                Some(Control::Shutdown) | None => break,
            },

            // A datagram the relay carried back from the egress. It becomes
            // a synthesized IP packet addressed to the mapping that sent it,
            // which is the one place the core originates a packet for a flow
            // rather than forwarding one.
            Some(Inbound { client, peer, payload }) = next_inbound(&mut relay) => {
                match datapath.deliver_datagram(client, peer, &payload, Instant::now()) {
                    Ok(SendOutcome::Buffered) => {}
                    // The core already counted the reason; a datagram whose
                    // mapping has expired has no client left to receive it.
                    Ok(SendOutcome::Dropped) => counters.datagrams_dropped += 1,
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

            // A filter-list build replaced the policy. `changed` is
            // cancel-safe, so losing this arm to a busier one costs nothing:
            // the next pass still sees the change.
            Ok(()) = policy.changed() => {
                let counts = policy.borrow_and_update().len();
                telemetry.emit(Telemetry::PolicyReloaded(counts));
            }

            // A resolved query. Bounded by the answer channel, and addressed
            // back to the client from the resolver address it asked.
            Some(answer) = queries.back.recv() => {
                let Answer { client, resolver, message, resolution, steered } = answer;
                if !steered.is_empty() {
                    datapath.inspect_addresses(&steered, Instant::now());
                }
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

            // A segment the terminator produced. It is only captured here:
            // another arm holds `device` for its read, so the write happens
            // after the `select!` rather than inside this handler.
            Some(segment) = next_reply(&mut termination) => {
                reply = Some(segment);
            }

            () = &mut sleep => {}
        }

        // The terminator's segments are the client's own connection being
        // served, so they go straight down the device: they are already IP
        // packets addressed to the client and the core has nothing to add.
        if let Some(segment) = reply.take() {
            device.send(&segment).await?;
        }

        let now = Instant::now();
        if core_deadline.is_some_and(|deadline| deadline <= TokioInstant::from_std(now)) {
            datapath.on_timeout(now);
        }
        // Tick on the egress's own deadline as well as its cadence: a QUIC
        // retransmission missed because the fixed interval had not elapsed is
        // a stalled tunnel, and the cadence remains the worst-case bound.
        let egress_due = egress
            .next_deadline()
            .is_some_and(|deadline| deadline <= now);
        if TokioInstant::from_std(now) >= next_tick || egress_due {
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
            &mut termination,
            &mut relay,
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
        &mut termination,
        &mut relay,
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
    termination: &mut Option<Termination>,
    relay: &mut Option<Relay>,
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

    // Client datagrams of terminated flows go to the relay, which lives in its
    // own task because opening and writing an association awaits. Offered
    // without waiting: a full queue is a counted drop, which is what a UDP
    // source already expects.
    //
    // A session with no relay is one whose egress carries datagrams as packets
    // — nothing is ever queued there — or one whose egress carries none at all,
    // which its path properties already state. Both are counted rather than
    // silently discarded, because the second is a misconfiguration.
    while let Some(datagram) = datapath.poll_datagram() {
        match relay {
            Some(relay) => {
                if relay.outbound.try_send(datagram).is_err() {
                    counters.datagrams_dropped += 1;
                }
            }
            None => counters.datagrams_dropped += 1,
        }
    }

    // Packets of terminated flows go to the local TCP stack, which lives in
    // its own task for the same reason the resolver does: serving a connection
    // awaits, and the reactor must not. A full queue is a counted drop and TCP
    // retransmits, which is the discipline the forward path already uses.
    while let Some(packet) = datapath.poll_terminate() {
        match termination {
            Some(termination) => {
                if termination.packets.try_send(packet).is_err() {
                    counters.termination_dropped += 1;
                }
            }
            // A flow planned for termination with no terminator configured is a
            // misconfiguration, and counting it is how an operator sees it.
            None => counters.termination_dropped += 1,
        }
    }

    // Whatever the terminator has ready beyond the one the `select!` captured.
    if let Some(termination) = termination {
        while let Ok(segment) = termination.replies.try_recv() {
            device.send(&segment).await?;
        }
    }

    while let Some(event) = datapath.poll_event() {
        match event {
            // All three are per-packet under a flood, so all three are folded
            // rather than forwarded; see the module documentation.
            FlowEvent::ReassemblyDiscarded => counters.reassembly_discarded += 1,
            FlowEvent::DatagramDropped(_) => counters.datagrams_dropped += 1,
            FlowEvent::TransmitDropped => counters.transmits_dropped += 1,
            FlowEvent::QuicSteered => counters.quic_steered += 1,
            FlowEvent::PathReported(_) => counters.paths_reported += 1,
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
