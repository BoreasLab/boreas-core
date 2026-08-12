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
    num::NonZeroU64,
    time::{Duration, Instant},
};

use tokio::{
    sync::mpsc,
    time::{Instant as TokioInstant, sleep_until},
};
use tokio_util::sync::CancellationToken;

use crate::{
    Accepts, Datapath, EgressCapabilities, EgressEmit, FlowEvent, InternalEndpoint, PacketEgress,
    Pooled, SendOutcome, Side, Transmit,
};

/// Depth of both reactor channels. Bounded is the point; the exact depth trades
/// burst tolerance against queueing delay and is not load-bearing.
const CHANNEL_DEPTH: usize = 256;

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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    /// Telemetry observations this channel could not accept.
    Lost(u64),
}

/// A running reactor and the handles that talk to it.
pub struct Shell {
    control: mpsc::Sender<Control>,
    datagrams: mpsc::Sender<Datagram>,
    telemetry: mpsc::Receiver<Telemetry>,
    shutdown: CancellationToken,
    reactor: tokio::task::JoinHandle<io::Result<()>>,
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
    /// `network` and `egress` are the outward half of the fused interface: the
    /// egress encapsulates, and the network carries what it produced. They are
    /// not optional, because a shell without them has nowhere to put a
    /// fast-path packet except back down the interface it came from.
    pub fn start<D, N, E>(datapath: Datapath, device: D, network: N, egress: E) -> Self
    where
        D: AsyncDevice + Send + 'static,
        N: AsyncNetwork + Send + 'static,
        E: PacketEgress + 'static,
    {
        let (control_tx, control_rx) = mpsc::channel(CHANNEL_DEPTH);
        let (datagram_tx, datagram_rx) = mpsc::channel(CHANNEL_DEPTH);
        let (telemetry_tx, telemetry_rx) = mpsc::channel(CHANNEL_DEPTH);
        let shutdown = CancellationToken::new();

        let reactor = tokio::spawn(reactor_loop(
            datapath,
            device,
            network,
            egress,
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
        match self.reactor.await {
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
