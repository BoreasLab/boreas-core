//! L4 datagram relay for flow-oriented egresses.
//!
//! Packet egresses carry UDP as IP packets on the fast path, so this module does
//! not run for them. Flow egresses such as SOCKS5, Shadowsocks, and VLESS use
//! an opened and framed association instead. The datapath supplies queued
//! client datagrams and targets ([`Outbound`]); this module forwards them and
//! synthesizes replies.
//!
//! One association serves one client mapping. A shared association could
//! not attribute replies when clients contact the same peer. Keying by client
//! endpoint preserves RFC 4787 endpoint independence.
//!
//! Receive ownership and send sharing are explicit in the types.
//! [`DatagramSource`] takes `&mut self`, so one task reads each association;
//! [`DatagramSink`] is shared, so association holders may send. A single
//! `select!` can drive both directions without a lock.
//!
//! Every resource is bounded. Association count, per-association queues,
//! payload storage, and idle lifetime all have limits. Refusals become counted
//! drops rather than waits.

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

const ASSOCIATION_DEPTH: usize = 32;

/// Resource limits for one relay.
#[derive(Clone, Copy, Debug)]
pub struct RelayLimits {
    /// Maximum live associations created from client input.
    pub max_associations: std::num::NonZeroUsize,
    /// Maximum idle interval in either direction. It matches the flow table so
    /// the mapping and its association expire together.
    pub idle_timeout: Duration,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_associations: std::num::NonZeroUsize::new(512).expect("512 is not zero"),
            // RFC 4787 REQ-5's minimum, also used by the flow table.
            idle_timeout: Duration::from_secs(120),
        }
    }
}

/// One datagram returned for a client mapping.
#[derive(Debug)]
pub struct Inbound {
    pub client: InternalEndpoint,
    /// The peer address used as the synthesized packet's source.
    pub peer: InternalEndpoint,
    pub payload: crate::Pooled,
}

/// Channels between the reactor and a flow-oriented relay.
pub struct Relay {
    /// Client datagrams offered without waiting; a full queue is a counted drop.
    pub outbound: mpsc::Sender<Outbound>,
    /// Replies to synthesize into IP packets.
    pub inbound: mpsc::Receiver<Inbound>,
}

/// Per-datagram and per-association relay outcomes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelayCounts {
    /// Client mappings refused at the association ceiling.
    pub associations_refused: u64,
    /// Datagrams rejected by a full queue, exhausted budget, or failed send.
    pub datagrams_dropped: u64,
    /// Associations refused by the proxy or unsupported by the egress.
    pub associations_failed: u64,
}

impl RelayCounts {
    /// Adds another report field by field for aggregate accounting.
    pub fn add(&mut self, other: Self) {
        self.associations_refused += other.associations_refused;
        self.datagrams_dropped += other.datagrams_dropped;
        self.associations_failed += other.associations_failed;
    }
}

/// Drives client associations until cancellation.
///
/// Each datagram performs one hash lookup and one bounded channel offer; state
/// is proportional to live associations and the shared payload budget.
pub async fn run_relay(
    egress: Arc<dyn StreamEgress>,
    pool: Arc<BufferPool>,
    mut outbound: mpsc::Receiver<Outbound>,
    inbound: mpsc::Sender<Inbound>,
    limits: RelayLimits,
    counts: mpsc::Sender<RelayCounts>,
    supervision: crate::Supervision,
) {
    let crate::Supervision { shutdown, panics } = supervision;
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

        // Reap associations whose tasks ended before checking the admission
        // limit, keeping the map proportional to live mappings.
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
                tracker.spawn(panics.watch(async move {
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
                }));
                live.entry(client).or_insert(sender)
            }
        };
        // Do not await a slow association; UDP handles a dropped datagram.
        if sender.try_send(datagram).is_err() {
            pending.datagrams_dropped += 1;
        }

        // Report aggregates periodically instead of once per datagram.
        if reported.elapsed() >= Duration::from_millis(500) {
            let _ = counts.try_send(std::mem::take(&mut pending));
            reported = Instant::now();
        }
    }

    let _ = counts.try_send(pending);
    // Stop admission, cancel associations, and wait for every proxy task.
    tracker.close();
    shutdown.cancel();
    tracker.wait().await;
}

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
        // The egress cannot provide an association or the proxy refused it; the
        // receiver drop releases all queued datagrams.
        counts.associations_failed += 1;
        counts.datagrams_dropped += outbound.len() as u64;
        return counts;
    };

    // Reuse one maximum-sized receive buffer for the association's lifetime.
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
                None => break,
            },

            // The source owns its receive buffer and is readiness-driven, so
            // cancelling this future cannot discard a datagram already read.
            received = source.recv_from(&mut buf) => match received {
                Ok((len, from)) => {
                    let Target::Ip(peer) = from else {
                        // A domain-only peer cannot provide the source address
                        // required by the synthesized client packet.
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
                // An oversized datagram is a relay error; keep the association.
                Err(EgressError::DatagramTooLarge { .. }) => counts.datagrams_dropped += 1,
                Err(_) => break,
            },

            // The timer restarts whenever send or receive wins, so it measures
            // inactivity in both directions.
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

    #[tokio::test]
    async fn a_client_datagram_crosses_the_association_and_its_reply_returns() {
        let echo = Arc::new(Echo::default());
        let pool = pool();
        let (out_tx, out_rx) = mpsc::channel(8);
        let (in_tx, mut in_rx) = mpsc::channel(8);
        let (count_tx, _count_rx) = mpsc::channel(8);

        let supervision = crate::Supervision::new();
        let relay = tokio::spawn(run_relay(
            Arc::new(EchoEgress(Arc::clone(&echo))),
            Arc::clone(&pool),
            out_rx,
            in_tx,
            RelayLimits::default(),
            count_tx,
            supervision.clone(),
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

        supervision.shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .expect("no association outlives the relay")
            .unwrap();
    }

    #[tokio::test]
    async fn each_client_mapping_gets_its_own_association() {
        let echo = Arc::new(Echo::default());
        let pool = pool();
        let (out_tx, out_rx) = mpsc::channel(8);
        let (in_tx, mut in_rx) = mpsc::channel(8);
        let (count_tx, _count_rx) = mpsc::channel(8);
        let supervision = crate::Supervision::new();
        let relay = tokio::spawn(run_relay(
            Arc::new(EchoEgress(Arc::clone(&echo))),
            Arc::clone(&pool),
            out_rx,
            in_tx,
            RelayLimits::default(),
            count_tx,
            supervision.clone(),
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

        supervision.shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .expect("clean shutdown")
            .unwrap();
    }

    #[tokio::test]
    async fn the_association_ceiling_refuses_rather_than_grows() {
        let echo = Arc::new(Echo::default());
        let pool = pool();
        let (out_tx, out_rx) = mpsc::channel(8);
        let (in_tx, _in_rx) = mpsc::channel(64);
        let (count_tx, mut count_rx) = mpsc::channel(64);
        let supervision = crate::Supervision::new();
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
            supervision.clone(),
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

        // Let admission finish before cancellation so all decisions are counted.
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

    #[tokio::test(start_paused = true)]
    async fn an_egress_that_never_answers_gives_the_association_up() {
        let pool = pool();
        let (out_tx, out_rx) = mpsc::channel(8);
        let (in_tx, _in_rx) = mpsc::channel(8);
        let (count_tx, mut count_rx) = mpsc::channel(8);

        let supervision = crate::Supervision::new();
        let relay = tokio::spawn(run_relay(
            Arc::new(NeverAnswers),
            Arc::clone(&pool),
            out_rx,
            in_tx,
            RelayLimits::default(),
            count_tx,
            supervision.clone(),
        ));

        out_tx
            .send(Outbound {
                client: client(49152),
                target: target(),
                payload: pool.take(b"query").unwrap(),
            })
            .await
            .unwrap();

        // The association must fail within a finite multiple of the dial budget.
        let counts = tokio::time::timeout(crate::Wait::ProxyDial.budget() * 2, count_rx.recv())
            .await
            .expect("the association gives up on its own")
            .expect("the channel is open");
        assert_eq!(counts.associations_failed, 1);
        assert_eq!(
            counts.datagrams_dropped, 1,
            "and the queued payload with it"
        );

        supervision.shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .expect("no association outlives the relay")
            .unwrap();
    }
}
