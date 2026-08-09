use std::{
    collections::{BTreeMap, HashMap, VecDeque, hash_map::Entry},
    net::IpAddr,
    num::NonZeroUsize,
    time::{Duration, Instant},
};

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

pub struct DatagramBuffer<T> {
    capacity: NonZeroUsize,
    datagrams: VecDeque<T>,
    dropped: u64,
}

impl<T> DatagramBuffer<T> {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity,
            datagrams: VecDeque::with_capacity(capacity.get()),
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
    expirations: BTreeMap<Instant, Vec<InternalEndpoint>>,
}

impl<V> UdpFlowTable<V> {
    pub fn new(idle_timeout: Duration) -> Result<Self, FlowTableError> {
        if idle_timeout < MIN_IDLE_TIMEOUT {
            return Err(FlowTableError::IdleTimeoutTooShort);
        }

        Ok(Self {
            idle_timeout,
            flows: HashMap::new(),
            expirations: BTreeMap::new(),
        })
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
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

        // ponytail: stale refresh entries live for one idle window; use a
        // generation-indexed timer wheel if refresh churn becomes material.
        self.expirations.entry(deadline).or_default().push(endpoint);

        let state = match self.flows.entry(endpoint) {
            Entry::Occupied(mut occupied) => {
                occupied.get_mut().deadline = deadline;
                occupied.into_mut()
            }
            Entry::Vacant(vacant) => vacant.insert(EntryState {
                value: create(),
                deadline,
            }),
        };
        Ok(&mut state.value)
    }

    pub fn expire(&mut self, now: Instant) -> Vec<V> {
        let mut expired = Vec::new();
        while self
            .expirations
            .first_key_value()
            .is_some_and(|(deadline, _)| *deadline <= now)
        {
            let Some((_, endpoints)) = self.expirations.pop_first() else {
                break;
            };
            for endpoint in endpoints {
                if self
                    .flows
                    .get(&endpoint)
                    .is_some_and(|state| state.deadline <= now)
                    && let Some(state) = self.flows.remove(&endpoint)
                {
                    expired.push(state.value);
                }
            }
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
    fn mappings_are_endpoint_independent_and_expire_in_batches() {
        assert!(matches!(
            UdpFlowTable::<u16>::new(Duration::from_secs(119)),
            Err(FlowTableError::IdleTimeoutTooShort)
        ));

        let start = Instant::now();
        let endpoint = InternalEndpoint {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            port: 12_345,
        };
        let mut table = UdpFlowTable::new(Duration::from_secs(120)).unwrap();
        assert_eq!(
            table.get_or_insert_with(endpoint, start, || 40_000),
            Ok(&mut 40_000)
        );

        let refreshed = start.checked_add(Duration::from_secs(60)).unwrap();
        assert_eq!(
            table.get_or_insert_with(endpoint, refreshed, || panic!("mapping replaced")),
            Ok(&mut 40_000)
        );
        assert!(
            table
                .expire(start.checked_add(Duration::from_secs(120)).unwrap())
                .is_empty()
        );
        assert_eq!(
            table.expire(start.checked_add(Duration::from_secs(180)).unwrap()),
            vec![40_000]
        );
        assert!(table.is_empty());
    }
}
