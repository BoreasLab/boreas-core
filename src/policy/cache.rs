//! A memo of upstream replies, bounded by count and by the answers' own TTL.
//!
//! Time is an argument: the cache holds no clock, so expiry is a pure function
//! of what was admitted and when it was asked. Failures are never admitted; a
//! name that failed is asked again.

use std::{
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{Message, Name, Rcode, RecordType, fifo::BoundedFifo};

/// Below this, a TTL is treated as this. Resolvers hand out 0 to 5 s TTLs for
/// load balancing; honouring them makes the cache pointless.
const MIN_TTL: Duration = Duration::from_secs(30);
/// Above this, a TTL is treated as this. Bounds how stale a rebound can be.
const MAX_TTL: Duration = Duration::from_secs(3600);
/// RFC 2308 negative caching, without reading the SOA minimum.
const NEGATIVE_TTL: Duration = Duration::from_secs(60);

#[derive(Clone)]
struct Cached {
    reply: Arc<[u8]>,
    admitted: Instant,
    expires: Instant,
}

pub struct DnsCache {
    entries: BoundedFifo<(Name, RecordType), Cached>,
}

impl DnsCache {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            entries: BoundedFifo::new(capacity),
        }
    }

    /// The remembered reply and its age, while its answers are still live.
    /// TTLs served from it count down by the age (RFC 2181 section 8).
    pub fn get(
        &self,
        name: Name,
        qtype: RecordType,
        now: Instant,
    ) -> Option<(Arc<[u8]>, Duration)> {
        self.entries
            .get(&(name, qtype))
            .filter(|cached| cached.expires > now)
            .map(|cached| (cached.reply, now.saturating_duration_since(cached.admitted)))
    }

    /// Remembers a reply for as long as its shortest answer allows. Replies
    /// that cannot be parsed or that report a server failure are not kept.
    pub fn admit(&mut self, name: Name, qtype: RecordType, reply: &[u8], now: Instant) {
        let Some(lifetime) = Message::parse(reply)
            .ok()
            .and_then(|message| lifetime(&message))
        else {
            return;
        };
        let cached = Cached {
            reply: reply.into(),
            admitted: now,
            expires: now + lifetime,
        };
        self.entries.insert((name, qtype), cached);
    }

    /// Forgets everything: policy changed, so every remembered verdict may have.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// How long a reply may be served, or `None` for a reply not worth keeping.
fn lifetime(message: &Message<'_>) -> Option<Duration> {
    let raw = match message.rcode() {
        Rcode::NoError => {
            let mut shortest: Option<u32> = None;
            for record in message.answers() {
                let record = record.ok()?;
                shortest = Some(shortest.map_or(record.ttl, |ttl| ttl.min(record.ttl)));
            }
            shortest.map_or(NEGATIVE_TTL, |ttl| Duration::from_secs(u64::from(ttl)))
        }
        Rcode::NameError => NEGATIVE_TTL,
        _ => return None,
    };
    Some(raw.clamp(MIN_TTL, MAX_TTL))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    /// A response to `name`/A with one address answer per TTL given.
    fn response(name: &str, rcode: Rcode, ttls: &[u32]) -> Vec<u8> {
        let mut out = 0x1234u16.to_be_bytes().to_vec();
        out.extend_from_slice(&(0x8180 | rcode.to_wire()).to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&(ttls.len() as u16).to_be_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&wire_name(name));
        out.extend_from_slice(&RecordType::A.to_wire().to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        for ttl in ttls {
            out.extend_from_slice(&wire_name(name));
            out.extend_from_slice(&RecordType::A.to_wire().to_be_bytes());
            out.extend_from_slice(&1u16.to_be_bytes());
            out.extend_from_slice(&ttl.to_be_bytes());
            out.extend_from_slice(&4u16.to_be_bytes());
            out.extend_from_slice(&[192, 0, 2, 1]);
        }
        out
    }

    fn name(text: &str) -> Name {
        Name::parse(text).unwrap()
    }

    fn cache() -> DnsCache {
        DnsCache::new(NonZeroUsize::new(2).unwrap())
    }

    #[test]
    fn a_reply_is_served_until_its_shortest_answer_expires_and_not_after() {
        let mut cache = cache();
        let t0 = Instant::now();
        let reply = response("a.example", Rcode::NoError, &[300, 120]);
        cache.admit(name("a.example"), RecordType::A, &reply, t0);

        let (hit, age) = cache
            .get(
                name("a.example"),
                RecordType::A,
                t0 + Duration::from_secs(119),
            )
            .expect("still live");
        assert_eq!(&*hit, reply.as_slice());
        assert_eq!(age, Duration::from_secs(119), "served with its age");
        assert!(
            cache
                .get(
                    name("a.example"),
                    RecordType::A,
                    t0 + Duration::from_secs(120)
                )
                .is_none(),
            "the 120 s answer decides, not the 300 s one"
        );
        assert!(
            cache.get(name("a.example"), RecordType::Aaaa, t0).is_none(),
            "a different type is a different key"
        );
    }

    #[test]
    fn ttls_are_clamped_and_negative_answers_live_for_the_negative_ttl() {
        let mut cache = cache();
        let t0 = Instant::now();

        cache.admit(
            name("short.example"),
            RecordType::A,
            &response("short.example", Rcode::NoError, &[0]),
            t0,
        );
        assert!(
            cache
                .get(
                    name("short.example"),
                    RecordType::A,
                    t0 + MIN_TTL - Duration::from_secs(1)
                )
                .is_some()
        );

        cache.admit(
            name("long.example"),
            RecordType::A,
            &response("long.example", Rcode::NoError, &[86_400]),
            t0,
        );
        assert!(
            cache
                .get(name("long.example"), RecordType::A, t0 + MAX_TTL)
                .is_none()
        );

        cache.admit(
            name("gone.example"),
            RecordType::A,
            &response("gone.example", Rcode::NameError, &[]),
            t0,
        );
        assert!(
            cache
                .get(
                    name("gone.example"),
                    RecordType::A,
                    t0 + NEGATIVE_TTL - Duration::from_secs(1)
                )
                .is_some()
        );
        assert!(
            cache
                .get(name("gone.example"), RecordType::A, t0 + NEGATIVE_TTL)
                .is_none()
        );
    }

    #[test]
    fn a_failure_is_not_remembered_and_a_reply_replaces_its_predecessor() {
        let mut cache = cache();
        let t0 = Instant::now();

        cache.admit(
            name("a.example"),
            RecordType::A,
            &response("a.example", Rcode::ServerFailure, &[]),
            t0,
        );
        assert!(cache.get(name("a.example"), RecordType::A, t0).is_none());
        cache.admit(name("a.example"), RecordType::A, b"not a message", t0);
        assert!(cache.get(name("a.example"), RecordType::A, t0).is_none());

        let first = response("a.example", Rcode::NoError, &[60]);
        let second = response("a.example", Rcode::NoError, &[60, 60]);
        cache.admit(name("a.example"), RecordType::A, &first, t0);
        cache.admit(
            name("a.example"),
            RecordType::A,
            &second,
            t0 + Duration::from_secs(10),
        );
        assert_eq!(
            cache
                .get(
                    name("a.example"),
                    RecordType::A,
                    t0 + Duration::from_secs(69)
                )
                .map(|(reply, _)| reply)
                .as_deref(),
            Some(second.as_slice()),
            "the newer reply and its newer expiry win"
        );
    }

    #[test]
    fn the_cache_is_bounded_and_clears_whole() {
        let mut cache = cache();
        let t0 = Instant::now();
        for host in ["a.example", "b.example", "c.example"] {
            cache.admit(
                name(host),
                RecordType::A,
                &response(host, Rcode::NoError, &[60]),
                t0,
            );
        }
        assert!(
            cache.get(name("a.example"), RecordType::A, t0).is_none(),
            "oldest evicted"
        );
        assert!(cache.get(name("c.example"), RecordType::A, t0).is_some());

        cache.clear();
        assert!(cache.get(name("c.example"), RecordType::A, t0).is_none());
    }
}
