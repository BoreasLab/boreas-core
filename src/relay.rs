//! The L4 datagram relay: what carries UDP when the egress accepts flows
//! rather than packets.
//!
//! A packet egress carries a UDP datagram as what it already is — an IP packet
//! on the fast path — and this module never runs. A *stream* egress cannot:
//! SOCKS5, Shadowsocks, and VLESS all relay datagrams through an association
//! that must be opened, framed, and kept alive. The datapath queues the client's
//! datagrams and their targets ([`Outbound`]); this drives them through that
//! association and synthesizes the replies back.
//!
//! **One association per client mapping is the NAT model.** A shared association
//! cannot attribute replies when two clients contact the same peer; keying by
//! client endpoint makes RFC 4787 endpoint independence structural.
//!
//! **The receive half is owned, the send half is shared, and the types say
//! so.** [`DatagramSource`] takes `&mut self`, so exactly one task reads each
//! association and there is no race for an arriving datagram; [`DatagramSink`]
//! is `Sync` and shared, so anything holding the association may send. That
//! split is why an association can be driven by a single `select!` without a
//! lock.
//!
//! **Everything is bounded.** Associations are capped, each one's outbound
//! queue is bounded, payload bytes are on the shared [`BufferPool`] budget, and
//! an idle association is closed on the same timeout the flow table uses. A
//! refusal at any of those is a counted drop, never a wait — which is the
//! discipline UDP already has and every consumer of it already recovers from.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::sync::mpsc;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    Association, BufferPool, EgressError, InternalEndpoint, Outbound, StreamEgress, Target,
};

/// Depth of one association's outbound queue, in datagrams. The fairness bound
/// beyond the datapath's own per-flow queue; a full one is a drop.
const ASSOCIATION_DEPTH: usize = 32;

/// What one relay may hold.
#[derive(Clone, Copy, Debug)]
pub struct RelayLimits {
    /// Live associations. A bound on state fed by network input: one client
    /// opening ports in a loop must not open proxy state in a loop.
    pub max_associations: std::num::NonZeroUsize,
    /// How long an association survives with no datagram in either direction.
    /// Matches the flow table's own idle timeout, so a mapping and the
    /// association serving it expire together rather than one outliving the
    /// other.
    pub idle_timeout: Duration,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_associations: std::num::NonZeroUsize::new(512).expect("512 is not zero"),
            // RFC 4787 REQ-5's floor, which is also the flow table's.
            idle_timeout: Duration::from_secs(120),
        }
    }
}

/// One datagram coming back from the egress, addressed to the client whose
/// mapping it belongs to.
#[derive(Debug)]
pub struct Inbound {
    pub client: InternalEndpoint,
    /// The peer it came from, which becomes the synthesized packet's source: a
    /// client that sent to one address and heard from another discards the
    /// reply.
    pub peer: InternalEndpoint,
    pub payload: crate::Pooled,
}

/// The relay's two channels, from the reactor's side. Present only for a
/// session whose egress accepts flows; a packet egress carries datagrams as
/// packets and needs none of this.
pub struct Relay {
    /// Client datagrams the datapath drained, offered without waiting: a full
    /// queue is a counted drop, exactly as a full per-flow queue is.
    pub outbound: mpsc::Sender<Outbound>,
    /// Replies, to be synthesized back into IP packets.
    pub inbound: mpsc::Receiver<Inbound>,
}

/// Why a datagram did not cross. Counted rather than logged per occurrence,
/// because under a flood each of these is per packet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelayCounts {
    /// Clients refused at the association ceiling.
    pub associations_refused: u64,
    /// Datagrams a full association queue, an exhausted budget, or a failed
    /// send could not carry.
    pub datagrams_dropped: u64,
    /// Associations that could not be opened at all: the proxy refused, or the
    /// egress carries no datagrams.
    pub associations_failed: u64,
}

impl RelayCounts {
    /// The monoid a caller folds reports with: the identity is
    /// [`Default`](Self::default) and the operation is field-wise addition, so
    /// summing a stream of reports is a fold rather than a diff.
    pub fn add(&mut self, other: Self) {
        self.associations_refused += other.associations_refused;
        self.datagrams_dropped += other.datagrams_dropped;
        self.associations_failed += other.associations_failed;
    }
}

/// Drives every client mapping's association until cancelled.
///
/// Time is O(1) per datagram — a hash probe and a channel offer — and space is
/// O(live associations) plus the shared budget the payloads sit on.
pub async fn run_relay(
    egress: Arc<dyn StreamEgress>,
    pool: Arc<BufferPool>,
    mut outbound: mpsc::Receiver<Outbound>,
    inbound: mpsc::Sender<Inbound>,
    limits: RelayLimits,
    counts: mpsc::Sender<RelayCounts>,
    shutdown: CancellationToken,
) {
    let mut live: HashMap<InternalEndpoint, mpsc::Sender<Outbound>> = HashMap::new();
    let tracker = TaskTracker::new();
    let mut pending = RelayCounts::default();
    let mut reported = Instant::now();

    loop {
        let datagram = tokio::select! {
            () = shutdown.cancelled() => break,
            next = outbound.recv() => match next {
                Some(next) => next,
                None => break,
            },
        };

        // A closed sender is an association whose task has ended — an idle
        // timeout, or a proxy that went away. Reaping it here rather than on a
        // sweep is what keeps the map's size a function of live mappings.
        if live
            .get(&datagram.client)
            .is_some_and(mpsc::Sender::is_closed)
        {
            live.remove(&datagram.client);
        }

        let client = datagram.client;
        let sender = match live.get(&client) {
            Some(sender) => sender,
            None if live.len() >= limits.max_associations.get() => {
                pending.associations_refused += 1;
                continue;
            }
            None => {
                let (sender, receiver) = mpsc::channel(ASSOCIATION_DEPTH);
                let egress = Arc::clone(&egress);
                let pool = Arc::clone(&pool);
                let inbound = inbound.clone();
                let counts = counts.clone();
                let shutdown = shutdown.clone();
                tracker.spawn(async move {
                    let report = serve_association(
                        egress.as_ref(),
                        &pool,
                        client,
                        receiver,
                        inbound,
                        limits.idle_timeout,
                        shutdown,
                    )
                    .await;
                    let _ = counts.try_send(report);
                });
                live.entry(client).or_insert(sender)
            }
        };
        // Never awaited: a slow association must not stall the reactor's drain,
        // and a dropped datagram is what a UDP source already handles.
        if sender.try_send(datagram).is_err() {
            pending.datagrams_dropped += 1;
        }

        // Folded and reported on a clock, so the counter stream stays O(time)
        // rather than O(datagrams).
        if reported.elapsed() >= Duration::from_millis(500) {
            let _ = counts.try_send(std::mem::take(&mut pending));
            reported = Instant::now();
        }
    }

    let _ = counts.try_send(pending);
    // Admission closes, every association observes the token, and the wait is
    // the proof that no proxy socket outlives this call.
    tracker.close();
    shutdown.cancel();
    tracker.wait().await;
}

/// Serves one client mapping: open the association, then move datagrams in both
/// directions until it goes idle or is cancelled.
async fn serve_association(
    egress: &dyn StreamEgress,
    pool: &Arc<BufferPool>,
    client: InternalEndpoint,
    mut outbound: mpsc::Receiver<Outbound>,
    inbound: mpsc::Sender<Inbound>,
    idle_timeout: Duration,
    shutdown: CancellationToken,
) -> RelayCounts {
    let mut counts = RelayCounts::default();
    let Ok(Association { sink, mut source }) =
        crate::within(crate::Wait::ProxyDial, egress.associate()).await
    else {
        // The egress said so in its path properties, or the proxy refused.
        // Either way there is nothing to serve and the queued datagrams are
        // dropped with the receiver.
        counts.associations_failed += 1;
        counts.datagrams_dropped += outbound.len() as u64;
        return counts;
    };

    // One receive buffer for the association's life, sized to the largest
    // payload a UDP datagram can carry, so a reply costs no allocation and a
    // payload this cannot hold does not exist.
    let mut buf = vec![0u8; usize::from(u16::MAX)];

    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,

            next = outbound.recv() => match next {
                Some(Outbound { target, payload, .. }) => {
                    if sink.send_to(&payload, &Target::Ip(target)).await.is_err() {
                        counts.datagrams_dropped += 1;
                    }
                }
                // The relay dropped this association's sender: the mapping is
                // gone, so the association goes with it.
                None => break,
            },

            // **Cancel safety.** Losing this arm to the outbound one drops the
            // future mid-read. An implementation that had already taken a
            // datagram off its socket would lose it, which is why
            // `DatagramSource` is documented as readiness-driven and why the
            // buffer is owned by the source rather than by the future.
            received = source.recv_from(&mut buf) => match received {
                Ok((len, from)) => {
                    let Target::Ip(peer) = from else {
                        // A relay that named a peer by domain gives no address
                        // to write into the reply's source, and a client
                        // discards a reply from an address it did not dial.
                        counts.datagrams_dropped += 1;
                        continue;
                    };
                    let Some(payload) = pool.take(&buf[..len]) else {
                        counts.datagrams_dropped += 1;
                        continue;
                    };
                    let delivery = Inbound {
                        client,
                        peer: InternalEndpoint { address: peer.ip(), port: peer.port() },
                        payload,
                    };
                    if inbound.try_send(delivery).is_err() {
                        counts.datagrams_dropped += 1;
                    }
                }
                // An oversized datagram is the relay's fault, not this flow's:
                // count it and keep the association.
                Err(EgressError::DatagramTooLarge { .. }) => counts.datagrams_dropped += 1,
                Err(_) => break,
            },

            // Idleness is measured by the absence of both arms, which is what
            // this timer is: it fires only when neither has for the whole
            // window, because any arm that wins restarts the `select!`.
            () = tokio::time::sleep(idle_timeout) => break,
        }
    }

    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        num::NonZeroUsize,
        sync::Mutex,
    };

    use crate::{
        AsyncStream, BoxFuture, DatagramFidelity, DatagramSink, DatagramSource, NatBehavior,
        PathProperties,
    };

    fn pool() -> Arc<BufferPool> {
        BufferPool::new(
            NonZeroUsize::new(2048).unwrap(),
            NonZeroUsize::new(64).unwrap(),
        )
    }

    fn client(port: u16) -> InternalEndpoint {
        InternalEndpoint {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            port,
        }
    }

    fn target() -> SocketAddr {
        SocketAddr::from(([198, 51, 100, 2], 53))
    }

    /// An association that records what it was sent and echoes each payload
    /// back from the target it was addressed to — the smallest thing that is
    /// still a real relay in both directions.
    #[derive(Default)]
    struct Echo {
        sent: Mutex<Vec<(SocketAddr, Vec<u8>)>>,
        replies: Mutex<std::collections::VecDeque<(SocketAddr, Vec<u8>)>>,
        notify: tokio::sync::Notify,
    }

    impl DatagramSink for Echo {
        fn send_to<'a>(
            &'a self,
            payload: &'a [u8],
            target: &'a Target,
        ) -> BoxFuture<'a, Result<(), EgressError>> {
            Box::pin(async move {
                let Target::Ip(address) = target else {
                    return Err(EgressError::Proxy(crate::ProxyError::Address));
                };
                self.sent.lock().unwrap().push((*address, payload.to_vec()));
                self.replies
                    .lock()
                    .unwrap()
                    .push_back((*address, payload.to_vec()));
                self.notify.notify_one();
                Ok(())
            })
        }
    }

    struct EchoSource(Arc<Echo>);

    impl DatagramSource for EchoSource {
        fn recv_from<'a>(
            &'a mut self,
            buf: &'a mut [u8],
        ) -> BoxFuture<'a, Result<(usize, Target), EgressError>> {
            Box::pin(async move {
                loop {
                    let next = self.0.replies.lock().unwrap().pop_front();
                    if let Some((address, payload)) = next {
                        if payload.len() > buf.len() {
                            return Err(EgressError::DatagramTooLarge {
                                required: payload.len(),
                            });
                        }
                        buf[..payload.len()].copy_from_slice(&payload);
                        return Ok((payload.len(), Target::Ip(address)));
                    }
                    self.0.notify.notified().await;
                }
            })
        }
    }

    struct EchoEgress(Arc<Echo>);

    impl StreamEgress for EchoEgress {
        fn properties(&self) -> PathProperties {
            PathProperties {
                datagram_fidelity: DatagramFidelity::Native,
                overhead_bytes: 0,
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

        fn associate(&self) -> BoxFuture<'_, Result<Association, EgressError>> {
            Box::pin(async move {
                Ok(Association {
                    sink: Arc::clone(&self.0) as Arc<dyn DatagramSink>,
                    source: Box::new(EchoSource(Arc::clone(&self.0))),
                })
            })
        }
    }

    /// Client datagram reaches its target and the reply returns to its mapping.
    #[tokio::test]
    async fn a_client_datagram_crosses_the_association_and_its_reply_returns() {
        let echo = Arc::new(Echo::default());
        let pool = pool();
        let (out_tx, out_rx) = mpsc::channel(8);
        let (in_tx, mut in_rx) = mpsc::channel(8);
        let (count_tx, _count_rx) = mpsc::channel(8);
        let shutdown = CancellationToken::new();

        let relay = tokio::spawn(run_relay(
            Arc::new(EchoEgress(Arc::clone(&echo))),
            Arc::clone(&pool),
            out_rx,
            in_tx,
            RelayLimits::default(),
            count_tx,
            shutdown.clone(),
        ));

        out_tx
            .send(Outbound {
                client: client(49152),
                target: target(),
                payload: pool.take(b"query").unwrap(),
            })
            .await
            .unwrap();

        let reply = tokio::time::timeout(Duration::from_secs(5), in_rx.recv())
            .await
            .expect("the reply returns")
            .expect("the channel is open");
        assert_eq!(reply.client, client(49152), "attributed to its mapping");
        assert_eq!(reply.peer.address, target().ip());
        assert_eq!(reply.peer.port, target().port());
        assert_eq!(&*reply.payload, b"query");
        assert_eq!(
            echo.sent.lock().unwrap().as_slice(),
            &[(target(), b"query".to_vec())],
            "the target the client addressed reached the egress"
        );

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .expect("no association outlives the relay")
            .unwrap();
    }

    /// One association per client mapping prevents replies crossing clients.
    #[tokio::test]
    async fn each_client_mapping_gets_its_own_association() {
        let echo = Arc::new(Echo::default());
        let pool = pool();
        let (out_tx, out_rx) = mpsc::channel(8);
        let (in_tx, mut in_rx) = mpsc::channel(8);
        let (count_tx, _count_rx) = mpsc::channel(8);
        let shutdown = CancellationToken::new();
        let relay = tokio::spawn(run_relay(
            Arc::new(EchoEgress(Arc::clone(&echo))),
            Arc::clone(&pool),
            out_rx,
            in_tx,
            RelayLimits::default(),
            count_tx,
            shutdown.clone(),
        ));

        for port in [49152, 49153] {
            out_tx
                .send(Outbound {
                    client: client(port),
                    target: target(),
                    payload: pool.take(&port.to_be_bytes()).unwrap(),
                })
                .await
                .unwrap();
        }

        let mut seen = Vec::new();
        for _ in 0..2 {
            let reply = tokio::time::timeout(Duration::from_secs(5), in_rx.recv())
                .await
                .expect("both replies return")
                .expect("the channel is open");
            seen.push((reply.client.port, reply.payload.to_vec()));
        }
        seen.sort();
        assert_eq!(
            seen,
            vec![
                (49152u16, 49152u16.to_be_bytes().to_vec()),
                (49153, 49153u16.to_be_bytes().to_vec()),
            ],
            "each reply came back on the mapping that sent it"
        );

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .expect("clean shutdown")
            .unwrap();
    }

    /// The association ceiling bounds network-fed state; excess ports become
    /// counted drops, not proxy sockets.
    #[tokio::test]
    async fn the_association_ceiling_refuses_rather_than_grows() {
        let echo = Arc::new(Echo::default());
        let pool = pool();
        let (out_tx, out_rx) = mpsc::channel(8);
        let (in_tx, _in_rx) = mpsc::channel(64);
        let (count_tx, mut count_rx) = mpsc::channel(64);
        let shutdown = CancellationToken::new();
        let relay = tokio::spawn(run_relay(
            Arc::new(EchoEgress(Arc::clone(&echo))),
            Arc::clone(&pool),
            out_rx,
            in_tx,
            RelayLimits {
                max_associations: NonZeroUsize::new(1).unwrap(),
                ..RelayLimits::default()
            },
            count_tx,
            shutdown.clone(),
        ));

        for port in 49152..49156 {
            out_tx
                .send(Outbound {
                    client: client(port),
                    target: target(),
                    payload: pool.take(b"x").unwrap(),
                })
                .await
                .unwrap();
        }

        // Drain queued datagrams before reporting; cancellation would race the
        // admission decisions under test.
        drop(out_tx);
        tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .expect("clean shutdown")
            .unwrap();

        let mut total = RelayCounts::default();
        while let Ok(report) = count_rx.try_recv() {
            total.add(report);
        }
        assert_eq!(
            total.associations_refused, 3,
            "one mapping was admitted and three were refused: {total:?}"
        );
    }

    /// An egress that accepts the connection and then says nothing — the shape
    /// a path takes when the handset walked out of Wi-Fi range mid-dial. No RST
    /// arrives, no ICMP, no FIN; the association simply never opens.
    struct NeverAnswers;

    impl StreamEgress for NeverAnswers {
        fn properties(&self) -> PathProperties {
            PathProperties {
                datagram_fidelity: DatagramFidelity::Native,
                overhead_bytes: 0,
                max_datagram_size: Some(1400),
                preserves_ecn: false,
                nat_behavior: NatBehavior::EndpointIndependent,
            }
        }

        fn connect<'a>(
            &'a self,
            _target: &'a Target,
        ) -> BoxFuture<'a, Result<Box<dyn AsyncStream>, EgressError>> {
            Box::pin(std::future::pending())
        }

        fn associate(&self) -> BoxFuture<'_, Result<Association, EgressError>> {
            Box::pin(std::future::pending())
        }
    }

    /// **Nothing but a deadline ends a connection whose path stopped
    /// existing.** Without one, this association holds a task, a queue, and
    /// every pooled payload queued behind it for as long as the process runs —
    /// and a client that roams does this several times an hour, so the leak is
    /// ordinary rather than adversarial.
    #[tokio::test(start_paused = true)]
    async fn an_egress_that_never_answers_gives_the_association_up() {
        let pool = pool();
        let (out_tx, out_rx) = mpsc::channel(8);
        let (in_tx, _in_rx) = mpsc::channel(8);
        let (count_tx, mut count_rx) = mpsc::channel(8);
        let shutdown = CancellationToken::new();

        let relay = tokio::spawn(run_relay(
            Arc::new(NeverAnswers),
            Arc::clone(&pool),
            out_rx,
            in_tx,
            RelayLimits::default(),
            count_tx,
            shutdown.clone(),
        ));

        out_tx
            .send(Outbound {
                client: client(49152),
                target: target(),
                payload: pool.take(b"query").unwrap(),
            })
            .await
            .unwrap();

        // Well past the dial budget and far short of forever, which is what the
        // absence of a bound would have cost.
        let counts = tokio::time::timeout(crate::Wait::ProxyDial.budget() * 2, count_rx.recv())
            .await
            .expect("the association gives up on its own")
            .expect("the channel is open");
        assert_eq!(counts.associations_failed, 1);
        assert_eq!(
            counts.datagrams_dropped, 1,
            "and the queued payload with it"
        );

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .expect("no association outlives the relay")
            .unwrap();
    }
}
