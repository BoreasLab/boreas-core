//! Tokio shell for the pure [`Datapath`]. One reactor owns the core by value,
//! all channels are bounded, and one timer serves core, telemetry, and egress
//! deadlines.
//!
//! Control messages await capacity; traffic uses `try_send` and drops on
//! saturation. A packet error is counted and does not stop the reactor, while
//! device and network failures remain fatal. The reactor also owns egress
//! interpretation so each [`crate::Side`] is routed explicitly.

use std::{
    io,
    num::NonZeroU64,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
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
    plan_query, policy::upstream::DnsUpstream, write_failure, write_refusal, write_response,
};

/// Capacity of reactor channels.
const CHANNEL_DEPTH: usize = 256;

/// Maximum concurrent upstream resolutions.
const MAX_INFLIGHT_QUERIES: usize = 64;

/// Largest DNS response built by the shell. This stays below the IPv6 MTU;
/// oversized rewritten responses become `SERVFAIL`.
const MAX_DNS_RESPONSE: usize = 1232;

/// Telemetry reporting interval.
const TELEMETRY_INTERVAL: Duration = Duration::from_millis(500);

/// Control messages into the reactor. Producers await bounded capacity.
#[derive(Debug)]
pub enum Control {
    /// Updated accepted layer and path properties.
    PathChange(Accepts, PathProperties),
    /// Ordered shutdown after preceding control messages.
    Shutdown,
}

/// Bounded, best-effort reactor telemetry. Counting variants are deltas.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Telemetry {
    /// Per-flow lifecycle event.
    Event(FlowEvent),
    /// Datagrams refused by per-flow queues.
    DatagramsDropped(u64),
    /// Packets refused by the core.
    PacketsRejected(u64),
    /// Reassembly discards.
    ReassemblyDiscarded(u64),
    /// Planned transmits refused by the shared buffer pool.
    TransmitsDropped(u64),
    /// Datagrams refused by the egress.
    EgressRejected(u64),
    /// QUIC attempts steered to HTTP/2.
    QuicSteered(u64),
    /// Oversized packets answered with ICMP Packet Too Big.
    PathsReported(u64),
    /// Resolved query and its verdict.
    Resolved(Box<Resolution>),
    /// Queries dropped because the resolver was saturated.
    QueriesDropped(u64),
    /// Complete host policy replacement.
    PolicyReloaded(RuleCounts),
    /// Termination packets refused by the local stack.
    TerminationDropped(u64),
    /// Tasks that ended by unwinding; this indicates an internal defect.
    TasksPanicked(u64),
    /// Telemetry observations lost to channel saturation.
    Lost(u64),
}

/// Effectful seams driven by the reactor and the resolver's live policy.
pub struct Session<D, N, E, U> {
    /// Client TUN.
    pub device: D,
    /// Egress network socket.
    pub network: N,
    /// Packet egress.
    pub egress: E,
    /// DNS upstream, unused when DNS passes through.
    pub upstream: U,
    /// Shared task-panic counter.
    pub panics: Panics,
    /// Atomically replaceable host rules.
    pub policy: watch::Receiver<Arc<HostPolicy>>,
    /// Local TCP terminator, if flow termination is enabled.
    pub termination: Option<Termination>,
    /// Datagram relay, if the egress carries flow datagrams.
    pub relay: Option<Relay>,
}

/// Reactor-facing channels for local TCP termination.
pub struct Termination {
    /// Terminated packets offered without waiting.
    pub packets: mpsc::Sender<Pooled>,
    /// Segments produced for the client.
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
    /// Starts the reactor and resolver on the current runtime. The reactor owns
    /// the datapath by value; resolver work stays on a separate bounded path.
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
            panics,
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
            panics.clone(),
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
            panics,
        ));

        Self {
            control: control_tx,
            telemetry: telemetry_rx,
            shutdown,
            reactor,
            resolver,
        }
    }

    /// Returns a bounded control-plane handle.
    pub fn control(&self) -> mpsc::Sender<Control> {
        self.control.clone()
    }

    /// Returns the next telemetry observation, or `None` after shutdown.
    pub async fn next_telemetry(&mut self) -> Option<Telemetry> {
        self.telemetry.recv().await
    }

    /// Cancels and joins the reactor and resolver. Reactor panics are resumed.
    pub async fn shutdown(self) -> io::Result<()> {
        self.shutdown.cancel();
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

/// Async raw-IP device seam supplied by platform adapters.
pub trait AsyncDevice {
    /// Configured interface MTU, used to size the receive buffer.
    fn mtu(&self) -> crate::Mtu;

    /// Reads one packet. Must be cancel-safe because the reactor routinely drops
    /// this future after polling it in `select!`.
    fn recv<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = io::Result<usize>> + Send + 'a;

    /// Writes one complete packet. Short writes must return
    /// [`io::ErrorKind::WriteZero`]; an IP packet cannot be resumed as a second packet.
    fn send<'a>(&'a mut self, buf: &'a [u8]) -> impl Future<Output = io::Result<()>> + Send + 'a;
}

/// Async seam for encapsulated datagrams to and from the egress peer.
pub trait AsyncNetwork {
    /// Reads one datagram. Must be cancel-safe because the reactor may drop the
    /// future after polling it in `select!`.
    fn recv<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = io::Result<usize>> + Send + 'a;

    /// Writes one complete datagram. Short writes are reported as errors.
    fn send<'a>(&'a mut self, buf: &'a [u8]) -> impl Future<Output = io::Result<()>> + Send + 'a;
}

/// Converts an OS short write into the seam's whole-packet error.
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

    // The explicit future keeps the trait's `Send` bound visible.
    #[allow(clippy::manual_async_fn)]
    fn send<'a>(&'a mut self, buf: &'a [u8]) -> impl Future<Output = io::Result<()>> + Send + 'a {
        async move { whole(tokio::net::UdpSocket::send(self, buf).await?, buf.len()) }
    }
}

/// Resolved query returned to the reactor for addressing.
struct Answer {
    client: InternalEndpoint,
    resolver: InternalEndpoint,
    /// Response bytes charged to the shared pool.
    message: Pooled,
    resolution: Resolution,
    /// Resolved addresses used by inspection steering.
    steered: Vec<std::net::IpAddr>,
}

/// Reactor side of the resolver channels.
struct Queries {
    out: mpsc::Sender<DnsQuery>,
    back: mpsc::Receiver<Answer>,
}

/// Resolves intercepted queries until cancellation. Upstream concurrency and
/// spawned work are bounded and joined before shutdown.
async fn resolver_loop<U: DnsUpstream + 'static>(
    upstream: Arc<U>,
    pool: Arc<crate::BufferPool>,
    policy: watch::Receiver<Arc<HostPolicy>>,
    mut queries: mpsc::Receiver<DnsQuery>,
    answers: mpsc::Sender<Answer>,
    shutdown: CancellationToken,
    panics: Panics,
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
        // Snapshot policy before spawning; no borrow crosses an await.
        let policy = Arc::clone(&policy.borrow());
        let answers = answers.clone();
        tracker.spawn(panics.watch(async move {
            let _permit = permit;
            if let Some(answer) = resolve(upstream.as_ref(), &pool, policy.as_ref(), query).await {
                // A saturated reactor means the client can retry the query.
                let _ = answers.try_send(answer);
            }
        }));
    }

    tracker.close();
    tracker.wait().await;
}

/// Plans, resolves, rewrites, and explains one query. Returns `None` for invalid
/// input or a response that cannot fit the shared budget.
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
        // Refused names never leave the device.
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
                Err(_) => {
                    // Do not retain addresses from a failed response rewrite.
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

    let _ = message.resize(len);
    Some(Answer {
        client,
        resolver,
        message,
        resolution,
        steered,
    })
}

/// Shared count of tasks that ended by unwinding.
#[derive(Clone, Debug, Default)]
pub struct Panics(Arc<AtomicU64>);

impl Panics {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Wraps `work` so unwinding is counted without requiring `UnwindSafe`.
    /// A drop guard distinguishes unwinding from cancellation.
    pub fn watch<F: Future>(&self, work: F) -> impl Future<Output = F::Output> + use<F> {
        let counter = Arc::clone(&self.0);
        async move {
            let _guard = Sentinel(counter);
            work.await
        }
    }

    /// Takes the count since the last call.
    fn take(&self) -> u64 {
        self.0.swap(0, Ordering::Relaxed)
    }
}

/// Shared cancellation and panic accounting for spawned subsystems.
#[derive(Clone, Debug, Default)]
pub struct Supervision {
    /// Shared cancellation token.
    pub shutdown: CancellationToken,
    /// Shared panic counter.
    pub panics: Panics,
}

impl Supervision {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Spawns `work` under this supervision's panic counter.
    pub fn watch<F: Future<Output = ()> + Send + 'static>(&self, tracker: &TaskTracker, work: F) {
        tracker.spawn(self.panics.watch(work));
    }
}

struct Sentinel(Arc<AtomicU64>);

impl Drop for Sentinel {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Best-effort telemetry sink. It never awaits or stalls the datapath.
struct TelemetrySink {
    channel: mpsc::Sender<Telemetry>,
    lost: u64,
}

impl TelemetrySink {
    /// Offers one observation and reports later channel loss explicitly.
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

/// Reactor counters folded between telemetry reports.
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
    /// Read from the shared counter at flush time.
    panics: Panics,
}

impl Counters {
    /// Reports and resets each non-zero counter.
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
        let mut panicked = self.panics.take();
        report(&mut panicked, Telemetry::TasksPanicked);
    }
}

/// Awaits the next termination reply, or remains pending without a terminator.
async fn next_reply(termination: &mut Option<Termination>) -> Option<Pooled> {
    match termination {
        Some(termination) => termination.replies.recv().await,
        None => std::future::pending().await,
    }
}

/// Awaits the next relay datagram, or remains pending without a relay.
async fn next_inbound(relay: &mut Option<Relay>) -> Option<Inbound> {
    match relay {
        Some(relay) => relay.inbound.recv().await,
        None => std::future::pending().await,
    }
}

/// Runs the reactor until cancellation or owner drop. One timer serves core,
/// telemetry, and egress deadlines.
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
    panics: Panics,
) -> io::Result<()> {
    // Size buffers from the device MTU and egress datagram limit.
    let mut tun_buf = vec![0u8; usize::from(device.mtu().get())];
    let mut net_buf = vec![0u8; egress.max_network_datagram()];
    // Reuse one emission container for the reactor lifetime.
    let mut emits: Vec<EgressEmit> = Vec::new();
    let mut counters = Counters {
        panics,
        ..Counters::default()
    };
    let mut next_flush = TokioInstant::now() + TELEMETRY_INTERVAL;
    let tick_interval = egress.tick_interval();
    let mut next_tick = TokioInstant::now() + tick_interval;

    // Re-arm one timer instead of allocating per iteration.
    let sleep = sleep_until(next_flush);
    tokio::pin!(sleep);

    loop {
        let mut reply: Option<Pooled> = None;
        let core_deadline = datapath.poll_timeout().map(TokioInstant::from_std);
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
                Some(Control::Shutdown) | None => break,
            },

            Some(Inbound { client, peer, payload }) = next_inbound(&mut relay) => {
                match datapath.deliver_datagram(client, peer, &payload, Instant::now()) {
                    Ok(SendOutcome::Buffered) => {}
                    Ok(SendOutcome::Dropped) => counters.datagrams_dropped += 1,
                    Err(_) => counters.packets_rejected += 1,
                }
            }

            result = device.recv(&mut tun_buf) => match result {
                Ok(len) => {
                    if datapath.on_tun_packet(&tun_buf[..len], Instant::now()).is_err() {
                        counters.packets_rejected += 1;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            },

            Ok(()) = policy.changed() => {
                let counts = policy.borrow_and_update().len();
                telemetry.emit(Telemetry::PolicyReloaded(counts));
            }

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
                Ok(len) => {
                    if egress.handle_network_packet(&net_buf[..len], &mut emits).is_err() {
                        counters.egress_rejected += 1;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            },

            Some(segment) = next_reply(&mut termination) => {
                reply = Some(segment);
            }

            () = &mut sleep => {}
        }

        if let Some(segment) = reply.take() {
            device.send(&segment).await?;
        }

        let now = Instant::now();
        if core_deadline.is_some_and(|deadline| deadline <= TokioInstant::from_std(now)) {
            datapath.on_timeout(now);
        }
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

/// Moves core and egress output to their terminal seams. Cross-fed output
/// reaches a fixpoint in at most two passes.
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

    // Never put a slow DNS upstream in front of packet processing.
    while let Some(query) = datapath.poll_query() {
        if queries.try_send(query).is_err() {
            counters.queries_dropped += 1;
        }
    }

    // Datagram traffic is offered without waiting; saturation is counted.
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

    // Termination traffic is offered without waiting; TCP retransmits drops.
    while let Some(packet) = datapath.poll_terminate() {
        match termination {
            Some(termination) => {
                if termination.packets.try_send(packet).is_err() {
                    counters.termination_dropped += 1;
                }
            }
            None => counters.termination_dropped += 1,
        }
    }

    if let Some(termination) = termination {
        while let Ok(segment) = termination.replies.try_recv() {
            device.send(&segment).await?;
        }
    }

    while let Some(event) = datapath.poll_event() {
        match event {
            FlowEvent::ReassemblyDiscarded => counters.reassembly_discarded += 1,
            FlowEvent::DatagramDropped(_) => counters.datagrams_dropped += 1,
            FlowEvent::TransmitDropped => counters.transmits_dropped += 1,
            FlowEvent::QuicSteered => counters.quic_steered += 1,
            FlowEvent::PathReported(_) => counters.paths_reported += 1,
            event @ (FlowEvent::StreamOpened(_)
            | FlowEvent::DatagramOpened(_)
            | FlowEvent::Resteered(_)
            | FlowEvent::FlowTornDown(_)) => telemetry.emit(Telemetry::Event(event)),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the distinction between Tokio task unwinding and cancellation.
    #[tokio::test]
    async fn a_panicking_task_is_counted_and_a_cancelled_one_is_not() {
        let panics = Panics::new();

        let handle = tokio::spawn(panics.watch(async { panic!("a defect") }));
        assert!(handle.await.is_err(), "the task ended by unwinding");

        // Cancellation is not an unwind.
        let handle = tokio::spawn(panics.watch(std::future::pending::<()>()));
        handle.abort();
        assert!(handle.await.is_err(), "the task was cancelled");

        tokio::spawn(panics.watch(async {})).await.unwrap();

        assert_eq!(panics.take(), 1, "exactly the panicking one");
        assert_eq!(panics.take(), 0, "and taking it resets the count");
    }
}
