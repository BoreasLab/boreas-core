use std::{
    collections::{HashMap, VecDeque, hash_map::Entry},
    error::Error,
    fmt,
    net::IpAddr,
    num::NonZeroUsize,
    time::{Duration, Instant},
};

/// A 512-second timer wheel for RFC 4787's two-minute minimum idle timeout.
/// Deadlines beyond the horizon stay in `overflow` until they enter range.
/// Refreshes change only the flow deadline, so index memory depends on flows,
/// not packets.
const WHEEL_BUCKETS: usize = 512;

struct TimerWheel<T> {
    /// Bucket `s % 512` holds entries whose deadline is in second `s`. Entries
    /// a full rotation apart collide, so expiry rechecks each real deadline.
    buckets: [Vec<(u64, T)>; WHEEL_BUCKETS],
    overflow: Vec<(u64, T)>,
    /// Seconds since the fixed construction epoch.
    epoch: Instant,
    /// Highest bucket second already drained.
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

    /// Places `entry` in its deadline bucket, never before `drained`.
    ///
    /// Entries in an already-drained second are due by definition. Expiry
    /// still checks the exact deadline, so this clamp cannot evict early.
    fn insert(&mut self, deadline: Instant, entry: T) {
        let second = self.second(deadline).max(self.drained);
        if second >= self.drained + WHEEL_BUCKETS as u64 {
            self.overflow.push((second, entry));
        } else {
            self.buckets[(second % WHEEL_BUCKETS as u64) as usize].push((second, entry));
        }
    }

    /// Surfaces entries whose deadline second has arrived by `now`.
    /// Rotation collisions are reinserted, and callers still check exact
    /// deadlines before eviction.
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
                    // A colliding entry is still in the future; keep it in its
                    // own bucket until that second is drained.
                    self.buckets[(second % WHEEL_BUCKETS as u64) as usize].push((second, entry));
                }
            }
            self.drained += 1;
        }
    }

    /// Returns a lower bound for the earliest live deadline second.
    ///
    /// Occupied buckets before the result are absent, while later buckets and
    /// `overflow` cannot contain an earlier entry. The bound can be early due
    /// to collisions but never late, and its scan cost is independent of flow
    /// count.
    fn next_due(&self) -> Option<u64> {
        let horizon = self.drained + WHEEL_BUCKETS as u64;
        (self.drained..horizon)
            .find(|second| !self.bucket(*second).is_empty())
            .or_else(|| (!self.overflow.is_empty()).then_some(horizon))
    }

    fn bucket(&self, second: u64) -> &[(u64, T)] {
        &self.buckets[(second % WHEEL_BUCKETS as u64) as usize]
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

    pub fn is_empty(&self) -> bool {
        self.datagrams.is_empty()
    }

    pub fn len(&self) -> usize {
        self.datagrams.len()
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
    /// Scratch reused across `expire` calls. The reactor arms a timer against
    /// `next_deadline` and calls `expire` on every fire, so a per-call
    /// allocation would be a steady-state cost with no steady-state work.
    surfaced: Vec<InternalEndpoint>,
}

impl<V> UdpFlowTable<V> {
    /// Constructs a flow table whose timer wheel uses `epoch` as its origin.
    pub fn new(idle_timeout: Duration, epoch: Instant) -> Result<Self, FlowTableError> {
        if idle_timeout < MIN_IDLE_TIMEOUT {
            return Err(FlowTableError::IdleTimeoutTooShort);
        }

        Ok(Self {
            idle_timeout,
            flows: HashMap::new(),
            wheel: TimerWheel::new(epoch),
            surfaced: Vec::new(),
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

    /// Returns the live value without refreshing its deadline.
    ///
    /// Callers refresh through [`get_or_insert_with`](Self::get_or_insert_with)
    /// once per packet; refreshing again during lookup would make expiry
    /// depend on how often the path inspected the flow.
    pub fn get_mut(&mut self, endpoint: &InternalEndpoint) -> Option<&mut V> {
        self.flows.get_mut(endpoint).map(|state| &mut state.value)
    }

    /// Returns a conservative earliest expiry instant. Wheel slots are hints,
    /// so the result may be early but never late and does not scan live flows.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.wheel
            .next_due()
            .map(|second| self.wheel.epoch + Duration::from_secs(second))
    }

    /// Removes flows rejected by `keep`, returning the number removed.
    /// Stale wheel entries are ignored during the next expiry pass.
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
                // Refreshing the deadline does not add another wheel entry.
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

    /// Evicts flows whose exact deadline has arrived and returns their values.
    /// Refreshed flows from stale wheel slots are re-bucketed.
    pub fn expire(&mut self, now: Instant) -> Vec<V> {
        // Temporarily owning the scratch buffer permits independent borrows of
        // the wheel and flow map.
        let mut surfaced = std::mem::take(&mut self.surfaced);
        surfaced.clear();
        self.wheel.take_due(now, &mut surfaced);

        let mut expired = Vec::new();
        for endpoint in surfaced.drain(..) {
            match self.flows.entry(endpoint) {
                Entry::Occupied(occupied) if occupied.get().deadline <= now => {
                    expired.push(occupied.remove().value);
                }
                // A stale slot is harmless; the exact deadline governs.
                Entry::Occupied(occupied) => {
                    let deadline = occupied.get().deadline;
                    self.wheel.insert(deadline, endpoint);
                }
                Entry::Vacant(_) => {}
            }
        }

        self.surfaced = surfaced;
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
    fn next_deadline_cost_is_independent_of_flow_count() {
        // The audited defect: `next_due` scanned every entry in every bucket,
        // so the reactor paid O(flows) to arm one timer. The structural proof
        // is that the answer depends only on which buckets are occupied, so a
        // table holding one flow and a table holding ten thousand, all in the
        // same second, must agree exactly.
        let start = Instant::now();
        let mut one = UdpFlowTable::new(Duration::from_secs(120), start).unwrap();
        let mut many = UdpFlowTable::new(Duration::from_secs(120), start).unwrap();

        let endpoint = |index: u32| InternalEndpoint {
            address: IpAddr::V4(Ipv4Addr::from(index)),
            port: 12_345,
        };
        let _ = one.get_or_insert_with(endpoint(0), start, || 1_u16);
        for index in 0..10_000 {
            let _ = many.get_or_insert_with(endpoint(index), start, || 1_u16);
        }

        assert_eq!(one.next_deadline(), many.next_deadline());
        assert_eq!(many.len(), 10_000);
    }

    #[test]
    fn a_rotation_collision_never_reports_a_deadline_late() {
        // Entries a full wheel rotation apart share a bucket. `next_due` may
        // answer early; the caller re-checks the real deadline, but it must
        // never answer late, or a flow would outlive its mapping.
        let start = Instant::now();
        let mut table = UdpFlowTable::new(Duration::from_secs(600), start).unwrap();
        let near = InternalEndpoint {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            port: 1,
        };
        let far = InternalEndpoint {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            port: 2,
        };

        // 600 s is past the 512-bucket horizon, so `far` starts in overflow;
        // `near`, inserted 88 s later, lands a full rotation away in the wheel.
        let _ = table.get_or_insert_with(far, start, || 1_u16);
        let _ = table.get_or_insert_with(near, start + Duration::from_secs(88), || 2_u16);

        let reported = table.next_deadline().expect("two live flows");
        assert!(
            reported <= start + Duration::from_secs(600),
            "reported {reported:?} is later than the earliest real deadline"
        );

        assert_eq!(
            table.expire(start + Duration::from_secs(599)),
            Vec::<u16>::new()
        );
        assert_eq!(table.expire(start + Duration::from_secs(601)), vec![1]);
        assert_eq!(table.expire(start + Duration::from_secs(689)), vec![2]);
        assert!(table.is_empty());
        assert_eq!(table.next_deadline(), None);
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
