//! One upstream connection, many queries in flight.
//!
//! A driver task owns the transport, rewrites each query's transaction id to
//! one unused on this connection, and routes the reply back by that id. The
//! caller sees its own id again. A transport failure fails every waiter with
//! `ConnectionAborted`, which is the one error a caller may retry once.

use std::{
    collections::HashMap,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use ring::rand::SecureRandom;
use tokio::sync::{mpsc, oneshot};

use crate::policy::upstream::MAX_DNS_MESSAGE;

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

pub(crate) const ID_BYTES: usize = 2;

struct Request {
    message: Vec<u8>,
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
        if message.len() < ID_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a DNS message",
            ));
        }
        let (reply, answer) = oneshot::channel();
        let request = Request {
            message: message.to_vec(),
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
    reply: oneshot::Sender<Vec<u8>>,
}

async fn drive<T: Transport>(
    mut transport: T,
    mut requests: mpsc::Receiver<Request>,
    idle: Duration,
    alive: Arc<AtomicBool>,
) {
    let mut pending: HashMap<u16, Waiter> = HashMap::new();
    let mut next = random_id();
    loop {
        tokio::select! {
            request = requests.recv() => {
                let Some(Request { mut message, reply }) = request else { break };
                let id = unused(&mut next, &pending);
                let original = [message[0], message[1]];
                message[..ID_BYTES].copy_from_slice(&id.to_be_bytes());
                if transport.send(&message).await.is_err() {
                    break;
                }
                pending.insert(id, Waiter { original, reply });
            }
            received = transport.recv() => {
                let Ok(mut reply) = received else { break };
                let Some(id) = reply.get(..ID_BYTES) else { continue };
                let id = u16::from_be_bytes([id[0], id[1]]);
                // An id nobody waits for is a late or forged reply; drop it.
                if let Some(waiter) = pending.remove(&id) {
                    reply[..ID_BYTES].copy_from_slice(&waiter.original);
                    let _ = waiter.reply.send(reply);
                }
            }
            () = tokio::time::sleep(idle), if pending.is_empty() => break,
        }
    }
    // Dropping `pending` fails every waiter; `alive` stops new callers joining.
    alive.store(false, Ordering::Release);
}

/// The next id not in flight. Sequential from a random start, so ids are
/// unpredictable to a third party yet never reused while pending.
fn unused(next: &mut u16, pending: &HashMap<u16, Waiter>) -> u16 {
    loop {
        let candidate = *next;
        *next = next.wrapping_add(1);
        if !pending.contains_key(&candidate) {
            return candidate;
        }
    }
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

    #[tokio::test]
    async fn two_queries_with_one_client_id_travel_under_distinct_ids_and_come_back_as_their_own() {
        let (wire, mut sent, replies) = wire();
        let demux = Demux::spawn(wire, Duration::from_secs(60));

        let first = tokio::spawn({
            let demux = demux.clone();
            async move { demux.query(&[0x12, 0x34, b'a']).await }
        });
        let second = tokio::spawn({
            let demux = demux.clone();
            async move { demux.query(&[0x12, 0x34, b'b']).await }
        });
        let a = sent.recv().await.unwrap();
        let b = sent.recv().await.unwrap();
        assert_ne!(id_of(&a), id_of(&b), "one connection, two ids in flight");

        // Reply out of order, each under its wire id.
        let mut reply_b = b.clone();
        reply_b.push(b'B');
        let mut reply_a = a.clone();
        reply_a.push(b'A');
        replies.send(Ok(reply_b)).unwrap();
        replies.send(Ok(reply_a)).unwrap();

        assert_eq!(first.await.unwrap().unwrap(), [0x12, 0x34, b'a', b'A']);
        assert_eq!(second.await.unwrap().unwrap(), [0x12, 0x34, b'b', b'B']);
        assert!(demux.is_alive());
    }

    #[tokio::test]
    async fn a_transport_failure_aborts_every_waiter_and_marks_the_connection_dead() {
        let (wire, mut sent, replies) = wire();
        let demux = Demux::spawn(wire, Duration::from_secs(60));
        let waiting = tokio::spawn({
            let demux = demux.clone();
            async move { demux.query(&[0, 1]).await }
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
            demux.query(&[0, 2]).await.is_err(),
            "nothing joins a dead connection"
        );
    }

    #[tokio::test]
    async fn an_unclaimed_reply_is_dropped_and_an_idle_connection_ends() {
        let (wire, _sent, replies) = wire();
        let demux = Demux::spawn(wire, Duration::from_millis(50));
        replies.send(Ok(vec![9, 9, b'?'])).unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !demux.is_alive(),
            "idle with nothing pending ends the connection"
        );
    }
}
