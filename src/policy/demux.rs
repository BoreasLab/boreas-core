//! One upstream connection, many queries in flight.
//!
//! A driver task owns the transport, rewrites each query's transaction id to
//! one unused on this connection, and routes the reply back by that id. The
//! caller sees its own id again. A transport failure fails every waiter with
//! `ConnectionAborted`, which is the one error a caller may retry once.
//!
//! A reply is claimed only when its question matches the one asked under that
//! id (RFC 5452 section 9.1), so a guessed id is not enough to answer a query.
//! A caller that stops waiting frees its id at the next sweep, so abandoned
//! queries neither hold ids nor keep the connection alive.

use std::{
    collections::HashMap,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use ring::rand::SecureRandom;
use tokio::sync::{mpsc, oneshot};

use crate::{Message, Question, policy::upstream::MAX_DNS_MESSAGE};

/// A connection that carries whole DNS messages in both directions.
///
/// `recv` must be cancel-safe: the driver polls it against new requests, and a
/// dropped `recv` must not lose a partial reply.
pub(crate) trait Transport: Send + 'static {
    fn send(&mut self, message: &[u8]) -> impl Future<Output = io::Result<()>> + Send;
    fn recv(&mut self) -> impl Future<Output = io::Result<Vec<u8>>> + Send;
}

/// Queries the driver can hold before `query` waits.
const DEPTH: usize = 64;

/// Waiters one connection holds before refusing more. Live waiters are bounded
/// by their callers' timeouts; this bounds the id search when they are not.
const MAX_PENDING: usize = 1024;

/// How often abandoned waiters are dropped.
const SWEEP: Duration = Duration::from_secs(1);

pub(crate) const ID_BYTES: usize = 2;

struct Request {
    message: Vec<u8>,
    question: Question,
    reply: oneshot::Sender<Vec<u8>>,
}

/// A handle to one driven connection. Cheap to clone; every clone shares it.
#[derive(Clone)]
pub(crate) struct Demux {
    requests: mpsc::Sender<Request>,
    alive: Arc<AtomicBool>,
}

impl Demux {
    /// Drives `transport` on a task until it fails or sits idle for `idle`.
    pub(crate) fn spawn<T: Transport>(transport: T, idle: Duration) -> Self {
        let (requests, receiver) = mpsc::channel(DEPTH);
        let alive = Arc::new(AtomicBool::new(true));
        tokio::spawn(drive(transport, receiver, idle, Arc::clone(&alive)));
        Self { requests, alive }
    }

    pub(crate) fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    /// Sends one query and waits for its reply, id restored.
    pub(crate) async fn query(&self, message: &[u8]) -> io::Result<Vec<u8>> {
        let question = *Message::parse(message)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "not a DNS query"))?
            .question();
        let (reply, answer) = oneshot::channel();
        let request = Request {
            message: message.to_vec(),
            question,
            reply,
        };
        self.requests.send(request).await.map_err(|_| ended())?;
        answer.await.map_err(|_| ended())
    }
}

fn ended() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "the upstream connection ended before the reply",
    )
}

/// Waiter and the id it asked with, keyed by the id used on the wire.
struct Waiter {
    original: [u8; ID_BYTES],
    question: Question,
    reply: oneshot::Sender<Vec<u8>>,
}

/// Queries in flight on one connection, keyed by wire id.
///
/// Ids are sequential from a random start: unpredictable to a third party,
/// never reused while a caller still waits.
struct Pending {
    by_id: HashMap<u16, Waiter>,
    next: u16,
}

impl Pending {
    fn new() -> Self {
        Self {
            by_id: HashMap::new(),
            next: random_id(),
        }
    }

    fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Admits `waiter` under a fresh id, or `None` when the table is full.
    /// An id whose caller stopped waiting counts as free.
    fn admit(&mut self, waiter: Waiter) -> Option<u16> {
        if self.by_id.len() >= MAX_PENDING {
            self.sweep();
            if self.by_id.len() >= MAX_PENDING {
                return None;
            }
        }
        let id = loop {
            let candidate = self.next;
            self.next = self.next.wrapping_add(1);
            if self
                .by_id
                .get(&candidate)
                .is_none_or(|held| held.reply.is_closed())
            {
                break candidate;
            }
        };
        self.by_id.insert(id, waiter);
        Some(id)
    }

    /// The waiter a reply answers: same wire id, same question. Anything else
    /// is late, forged, or malformed, and stays unclaimed.
    fn claim(&mut self, reply: &[u8]) -> Option<Waiter> {
        let parsed = Message::parse(reply).ok()?;
        if !parsed.is_response() {
            return None;
        }
        let id = parsed.id();
        if self.by_id.get(&id)?.question != *parsed.question() {
            return None;
        }
        self.by_id.remove(&id)
    }

    /// Drops waiters whose callers stopped waiting.
    fn sweep(&mut self) {
        self.by_id.retain(|_, waiter| !waiter.reply.is_closed());
    }
}

async fn drive<T: Transport>(
    mut transport: T,
    mut requests: mpsc::Receiver<Request>,
    idle: Duration,
    alive: Arc<AtomicBool>,
) {
    let mut pending = Pending::new();
    let mut sweep = tokio::time::interval(SWEEP);
    let mut last_traffic = Instant::now();
    loop {
        tokio::select! {
            request = requests.recv() => {
                let Some(Request { mut message, question, reply }) = request else { break };
                last_traffic = Instant::now();
                let original = [message[0], message[1]];
                // A refused waiter is dropped, which its caller sees as `ended`.
                let Some(id) = pending.admit(Waiter { original, question, reply }) else { continue };
                message[..ID_BYTES].copy_from_slice(&id.to_be_bytes());
                if transport.send(&message).await.is_err() {
                    break;
                }
            }
            received = transport.recv() => {
                let Ok(mut reply) = received else { break };
                last_traffic = Instant::now();
                if let Some(waiter) = pending.claim(&reply) {
                    reply[..ID_BYTES].copy_from_slice(&waiter.original);
                    let _ = waiter.reply.send(reply);
                }
            }
            _ = sweep.tick() => pending.sweep(),
            () = tokio::time::sleep_until((last_traffic + idle).into()), if pending.is_empty() => break,
        }
    }
    // Dropping `pending` fails every waiter; `alive` stops new callers joining.
    alive.store(false, Ordering::Release);
}

fn random_id() -> u16 {
    let mut bytes = [0u8; ID_BYTES];
    // A failed read leaves zero, which is a valid if predictable start.
    let _ = ring::rand::SystemRandom::new().fill(&mut bytes);
    u16::from_be_bytes(bytes)
}

/// Refuses a length no DNS message reaches, before any allocation of it.
pub(crate) fn bounded(length: usize) -> io::Result<usize> {
    if length > MAX_DNS_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "reply exceeds the accepted message size",
        ));
    }
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::dns::query;

    /// A wire the test drives: sent queries appear on `sent`; replies the test
    /// pushes onto `replies` are what `recv` returns.
    struct Wire {
        sent: mpsc::UnboundedSender<Vec<u8>>,
        replies: mpsc::UnboundedReceiver<io::Result<Vec<u8>>>,
    }

    impl Transport for Wire {
        async fn send(&mut self, message: &[u8]) -> io::Result<()> {
            self.sent
                .send(message.to_vec())
                .map_err(|_| io::Error::other("test closed"))
        }

        async fn recv(&mut self) -> io::Result<Vec<u8>> {
            self.replies
                .recv()
                .await
                .unwrap_or_else(|| Err(io::Error::other("test closed")))
        }
    }

    type Sent = mpsc::UnboundedReceiver<Vec<u8>>;
    type Replies = mpsc::UnboundedSender<io::Result<Vec<u8>>>;

    fn wire() -> (Wire, Sent, Replies) {
        let (sent_tx, sent_rx) = mpsc::unbounded_channel();
        let (reply_tx, reply_rx) = mpsc::unbounded_channel();
        (
            Wire {
                sent: sent_tx,
                replies: reply_rx,
            },
            sent_rx,
            reply_tx,
        )
    }

    fn id_of(message: &[u8]) -> u16 {
        u16::from_be_bytes([message[0], message[1]])
    }

    /// The query as a resolver would answer it: response bit set, one marker
    /// answer byte appended so replies are telling apart.
    fn reply_to(sent: &[u8], marker: u8) -> Vec<u8> {
        let mut reply = sent.to_vec();
        reply[2] |= 0x80;
        reply.push(marker);
        reply
    }

    #[tokio::test]
    async fn two_queries_with_one_client_id_travel_under_distinct_ids_and_come_back_as_their_own() {
        let (wire, mut sent, replies) = wire();
        let demux = Demux::spawn(wire, Duration::from_secs(60));

        let first = tokio::spawn({
            let demux = demux.clone();
            async move { demux.query(&query("a.example", 0x1234)).await }
        });
        let second = tokio::spawn({
            let demux = demux.clone();
            async move { demux.query(&query("b.example", 0x1234)).await }
        });
        let a = sent.recv().await.unwrap();
        let b = sent.recv().await.unwrap();
        assert_ne!(id_of(&a), id_of(&b), "one connection, two ids in flight");

        // Reply out of order, each under its wire id.
        replies.send(Ok(reply_to(&b, b'B'))).unwrap();
        replies.send(Ok(reply_to(&a, b'A'))).unwrap();

        let mut expected_a = reply_to(&query("a.example", 0x1234), b'A');
        let mut expected_b = reply_to(&query("b.example", 0x1234), b'B');
        // The wire id differs; the caller's own comes back.
        expected_a[..2].copy_from_slice(&0x1234u16.to_be_bytes());
        expected_b[..2].copy_from_slice(&0x1234u16.to_be_bytes());
        let (got_a, got_b) = (
            first.await.unwrap().unwrap(),
            second.await.unwrap().unwrap(),
        );
        assert_eq!(&got_a[2..], &expected_a[2..]);
        assert_eq!(&got_b[2..], &expected_b[2..]);
        assert_eq!(id_of(&got_a), 0x1234);
        assert_eq!(id_of(&got_b), 0x1234);
        assert!(demux.is_alive());
    }

    /// RFC 5452 section 9.1: an id alone does not claim a reply.
    #[tokio::test]
    async fn a_reply_with_the_right_id_and_the_wrong_question_is_not_an_answer() {
        let (wire, mut sent, replies) = wire();
        let demux = Demux::spawn(wire, Duration::from_secs(60));
        let waiting = tokio::spawn({
            let demux = demux.clone();
            async move { demux.query(&query("bank.example", 7)).await }
        });
        let on_wire = sent.recv().await.unwrap();

        let mut forged = query("evil.example", id_of(&on_wire));
        forged[2] |= 0x80;
        replies.send(Ok(forged)).unwrap();
        replies.send(Ok(b"junk".to_vec())).unwrap();
        // The query itself echoed back: not a response.
        replies.send(Ok(on_wire.clone())).unwrap();
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished(), "the forged reply was not accepted");

        replies.send(Ok(reply_to(&on_wire, b'!'))).unwrap();
        let answer = waiting.await.unwrap().unwrap();
        assert_eq!(id_of(&answer), 7);
        assert_eq!(*answer.last().unwrap(), b'!');
    }

    #[tokio::test]
    async fn a_transport_failure_aborts_every_waiter_and_marks_the_connection_dead() {
        let (wire, mut sent, replies) = wire();
        let demux = Demux::spawn(wire, Duration::from_secs(60));
        let waiting = tokio::spawn({
            let demux = demux.clone();
            async move { demux.query(&query("a.example", 1)).await }
        });
        sent.recv().await.unwrap();
        replies.send(Err(io::Error::other("reset"))).unwrap();

        let outcome = waiting.await.unwrap();
        assert_eq!(
            outcome.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
        assert!(!demux.is_alive());
        assert!(
            demux.query(&query("a.example", 2)).await.is_err(),
            "nothing joins a dead connection"
        );
    }

    /// A caller that gave up neither holds its id nor keeps the connection
    /// open: the connection still ends idle.
    #[tokio::test(start_paused = true)]
    async fn an_abandoned_query_does_not_keep_the_connection_alive() {
        let (wire, mut sent, replies) = wire();
        let demux = Demux::spawn(wire, Duration::from_secs(30));
        let abandoned = tokio::time::timeout(
            Duration::from_millis(10),
            demux.query(&query("slow.example", 3)),
        )
        .await;
        assert!(abandoned.is_err(), "the caller gave up");
        sent.recv().await.unwrap();
        replies.send(Ok(b"unclaimed".to_vec())).unwrap();

        tokio::time::sleep(Duration::from_secs(31)).await;
        assert!(
            !demux.is_alive(),
            "idle with nothing pending ends the connection"
        );
    }

    #[tokio::test]
    async fn a_message_that_is_not_a_query_is_refused_before_it_is_sent() {
        let (wire, mut sent, _replies) = wire();
        let demux = Demux::spawn(wire, Duration::from_secs(60));
        assert_eq!(
            demux.query(&[0, 1, 2]).await.unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(sent.try_recv().is_err(), "nothing reached the wire");
    }
}
