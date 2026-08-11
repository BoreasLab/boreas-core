use std::{
    collections::{HashMap, VecDeque, hash_map::Entry},
    error::Error,
    fmt,
    net::IpAddr,
    num::NonZeroUsize,
    time::{Duration, Instant},
};

/// One-second buckets, 512 of them: RFC 4787 REQ-5 sets a 120-second floor and
/// recommends 300, so the wheel covers the legal idle-timeout range with
/// headroom. Deadlines past the horizon land in `overflow`, scanned once per
/// expiry pass and re-bucketed lazily. Memory is O(flows + buckets), never
/// O(packets): a refresh mutates only the flow's deadline; the wheel slot
/// inserted at last touch is a hint that expiry re-validates.
const WHEEL_BUCKETS: usize = 512;

struct TimerWheel<T> {
    /// Absolute-second keyed: bucket `s % 512` holds entries whose deadline is
    /// in second `s`. A full rotation apart, entries share a bucket, so every
    /// surfaced entry is re-checked against its real deadline and re-inserted
    /// when it has not arrived yet.
    buckets: [Vec<(u64, T)>; WHEEL_BUCKETS],
    overflow: Vec<(u64, T)>,
    /// Seconds since the wheel's epoch. The epoch is fixed at construction;
    /// `Instant` subtraction does the rest.
    epoch: Instant,
    /// Highest bucket-second drained so far.
    drained: u64,
}

impl<T: Copy> TimerWheel<T> {
    fn new(epoch: Instant) -> Self {
        Self {
            buckets: std::array::from_fn(|_| Vec::new()),
            overflow: Vec::new(),
            epoch,
            drained: 0,
        }
    }

    fn second(&self, deadline: Instant) -> u64 {
        deadline
            .saturating_duration_since(self.epoch)
            .as_secs()
            .min(u64::MAX - 1)
    }

    fn insert(&mut self, deadline: Instant, entry: T) {
        let second = self.second(deadline);
        if second >= self.drained + WHEEL_BUCKETS as u64 {
            self.overflow.push((second, entry));
        } else {
            self.buckets[(second % WHEEL_BUCKETS as u64) as usize].push((second, entry));
        }
    }

    /// Surfaces every entry whose deadline second is at or before `now`'s.
    /// Entries a full rotation early are re-inserted rather than surfaced, so
    /// the caller only sees slots whose deadline may have arrived; the caller
    /// still checks each entry's true deadline.
    fn take_due(&mut self, now: Instant, surfaced: &mut Vec<T>) {
        let horizon = self.second(now);

        let mut overflow = std::mem::take(&mut self.overflow);
        overflow.retain(|(second, entry)| {
            if *second <= horizon {
                surfaced.push(*entry);
                false
            } else if *second < self.drained + WHEEL_BUCKETS as u64 {
                self.buckets[(*second % WHEEL_BUCKETS as u64) as usize].push((*second, *entry));
                false
            } else {
                true
            }
        });
        self.overflow = overflow;

        while self.drained <= horizon {
            let bucket = (self.drained % WHEEL_BUCKETS as u64) as usize;
            for (second, entry) in std::mem::take(&mut self.buckets[bucket]) {
                if second <= horizon {
                    surfaced.push(entry);
                } else {
                    // A rotation-collision entry: its second is in the future.
                    // Re-insert at its own bucket; it survives until drained.
                    self.buckets[(second % WHEEL_BUCKETS as u64) as usize].push((second, entry));
                }
            }
            self.drained += 1;
        }
    }

    /// The earliest second that may contain a live entry. Conservative when
    /// buckets hold rotation-collided or stale entries; always an under-
    /// estimate-safe lower bound for the caller's own deadline check.
    fn next_due(&self) -> Option<u64> {
        let bucket_min = self
            .buckets
            .iter()
            .flatten()
            .map(|(second, _)| *second)
            .min();
        let overflow_min = self.overflow.iter().map(|(second, _)| *second).min();
        bucket_min.into_iter().chain(overflow_min).min()
    }
}

const MIN_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InternalEndpoint {
    pub address: IpAddr,
    pub port: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowTableError {
    IdleTimeoutTooShort,
    DeadlineOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendOutcome {
    Buffered,
    Dropped,
}

impl fmt::Display for FlowTableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdleTimeoutTooShort => write!(
                f,
                "idle timeout is below the {}-second RFC 4787 REQ-5 minimum",
                MIN_IDLE_TIMEOUT.as_secs()
            ),
            Self::DeadlineOverflow => f.write_str("mapping deadline overflows the clock"),
        }
    }
}

impl Error for FlowTableError {}

pub struct DatagramBuffer<T> {
    capacity: NonZeroUsize,
    datagrams: VecDeque<T>,
    dropped: u64,
}

impl<T> DatagramBuffer<T> {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity,
            // Idle flows pay nothing; the queue allocates on first datagram.
            datagrams: VecDeque::new(),
            dropped: 0,
        }
    }

    pub fn try_send(&mut self, datagram: T) -> SendOutcome {
        if self.datagrams.len() == self.capacity.get() {
            self.dropped = self.dropped.saturating_add(1);
            return SendOutcome::Dropped;
        }

        self.datagrams.push_back(datagram);
        SendOutcome::Buffered
    }

    pub fn recv(&mut self) -> Option<T> {
        self.datagrams.pop_front()
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

struct EntryState<V> {
    value: V,
    deadline: Instant,
}

pub struct UdpFlowTable<V> {
    idle_timeout: Duration,
    flows: HashMap<InternalEndpoint, EntryState<V>>,
    wheel: TimerWheel<InternalEndpoint>,
}

impl<V> UdpFlowTable<V> {
    /// `epoch` anchors the timer wheel; pass the first `now` the table sees,
    /// or `Instant::now()` when no better anchor exists.
    pub fn new(idle_timeout: Duration, epoch: Instant) -> Result<Self, FlowTableError> {
        if idle_timeout < MIN_IDLE_TIMEOUT {
            return Err(FlowTableError::IdleTimeoutTooShort);
        }

        Ok(Self {
            idle_timeout,
            flows: HashMap::new(),
            wheel: TimerWheel::new(epoch),
        })
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub fn contains(&self, endpoint: &InternalEndpoint) -> bool {
        self.flows.contains_key(endpoint)
    }

    /// The earliest instant that may contain an expired flow. Conservative:
    /// wheel slots are deadline hints, so the answer can be early but never
    /// late. O(buckets) worst case, O(1) when the wheel is empty.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.wheel
            .next_due()
            .map(|second| self.wheel.epoch + Duration::from_secs(second))
    }

    /// Drops flows failing `keep`, returning the number removed. Stale
    /// expiration entries die with the flows they point at on the next
    /// `expire`, at no extra cost.
    pub fn retain(&mut self, mut keep: impl FnMut(&InternalEndpoint, &mut V) -> bool) -> usize {
        let before = self.flows.len();
        self.flows
            .retain(|endpoint, state| keep(endpoint, &mut state.value));
        before - self.flows.len()
    }

    pub fn get_or_insert_with(
        &mut self,
        endpoint: InternalEndpoint,
        now: Instant,
        create: impl FnOnce() -> V,
    ) -> Result<&mut V, FlowTableError> {
        let deadline = now
            .checked_add(self.idle_timeout)
            .ok_or(FlowTableError::DeadlineOverflow)?;

        let state = match self.flows.entry(endpoint) {
            Entry::Occupied(mut occupied) => {
                // Refresh mutates only the deadline; the wheel slot from the
                // last touch is a hint expiry re-validates, so a packet flood
                // adds zero expiry-index memory.
                occupied.get_mut().deadline = deadline;
                occupied.into_mut()
            }
            Entry::Vacant(vacant) => {
                self.wheel.insert(deadline, endpoint);
                vacant.insert(EntryState {
                    value: create(),
                    deadline,
                })
            }
        };
        Ok(&mut state.value)
    }

    pub fn expire(&mut self, now: Instant) -> Vec<V> {
        let mut surfaced = Vec::new();
        self.wheel.take_due(now, &mut surfaced);

        let mut expired = Vec::new();
        let mut reinsert = Vec::new();
        for endpoint in surfaced {
            match self.flows.get(&endpoint) {
                // The real deadline governs: a refreshed flow whose stale slot
                // surfaced early is re-bucketed, not evicted.
                Some(state) if state.deadline <= now => {
                    expired.push(self.flows.remove(&endpoint).expect("checked above").value);
                }
                Some(state) => reinsert.push((state.deadline, endpoint)),
                None => {}
            }
        }
        for (deadline, endpoint) in reinsert {
            self.wheel.insert(deadline, endpoint);
        }
        expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn datagram_buffer_drops_instead_of_waiting() {
        let mut buffer = DatagramBuffer::new(NonZeroUsize::new(1).unwrap());
        assert_eq!(buffer.try_send(1), SendOutcome::Buffered);
        assert_eq!(buffer.try_send(2), SendOutcome::Dropped);
        assert_eq!(buffer.dropped(), 1);
        assert_eq!(buffer.recv(), Some(1));
        assert_eq!(buffer.recv(), None);
    }

    #[test]
    fn refresh_flood_does_not_grow_the_expiry_index() {
        // Regression for the P7 defect: 10,000 refreshes of one mapping must
        // cost one wheel slot, not 10,000. Refresh mutates the deadline; only
        // a vacant entry inserts.
        let start = Instant::now();
        let endpoint = InternalEndpoint {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            port: 12_345,
        };
        let mut table = UdpFlowTable::new(Duration::from_secs(120), start).unwrap();
        for tick in 0..10_000 {
            let now = start + Duration::from_millis(tick);
            let _ = table.get_or_insert_with(endpoint, now, || 1_u16);
        }
        assert_eq!(table.len(), 1);
        let wheel_slots: usize =
            table.wheel.buckets.iter().map(Vec::len).sum::<usize>() + table.wheel.overflow.len();
        assert_eq!(wheel_slots, 1, "one flow, one wheel slot");

        // The flow still expires exactly once, at its real deadline.
        assert!(table.expire(start + Duration::from_secs(119)).is_empty());
        assert_eq!(table.expire(start + Duration::from_secs(130)), vec![1]);
        assert!(table.is_empty());
    }

    #[test]
    fn stale_wheel_slots_never_evict_a_refreshed_flow() {
        let start = Instant::now();
        let endpoint = InternalEndpoint {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            port: 12_345,
        };
        let mut table = UdpFlowTable::new(Duration::from_secs(120), start).unwrap();
        let _ = table.get_or_insert_with(endpoint, start, || 7_u16);
        // Refresh one second before the deadline; the original slot surfaces
        // at second 120 and must be re-bucketed, not evicted.
        let _ = table.get_or_insert_with(endpoint, start + Duration::from_secs(119), || 7);
        assert!(table.expire(start + Duration::from_secs(120)).is_empty());
        assert!(table.expire(start + Duration::from_secs(238)).is_empty());
        assert_eq!(table.expire(start + Duration::from_secs(240)), vec![7]);
    }

    #[test]
    fn next_deadline_tracks_the_earliest_flow() {
        let start = Instant::now();
        let mut table = UdpFlowTable::new(Duration::from_secs(120), start).unwrap();
        assert_eq!(table.next_deadline(), None);
        let endpoint = InternalEndpoint {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            port: 12_345,
        };
        let _ = table.get_or_insert_with(endpoint, start, || 1_u16);
        let deadline = table.next_deadline().expect("one live flow");
        // Conservative at second granularity: never later than the true
        // deadline, never earlier than the floor of its second.
        assert!(deadline <= start + Duration::from_secs(120));
        assert!(deadline >= start);
    }
}
