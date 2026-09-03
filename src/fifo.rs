//! A bounded memo: a map that forgets its oldest entry at capacity.
//!
//! FIFO rather than LRU because every caller here memoizes a pure function of
//! the key, so a stale eviction costs one recomputation and never a wrong
//! answer.

use std::{
    collections::{HashMap, VecDeque},
    hash::Hash,
    num::NonZeroUsize,
};

pub(crate) struct BoundedFifo<K, V> {
    entries: HashMap<K, V>,
    order: VecDeque<K>,
    capacity: NonZeroUsize,
}

impl<K: Clone + Eq + Hash, V: Clone> BoundedFifo<K, V> {
    pub(crate) fn new(capacity: NonZeroUsize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    pub(crate) fn get<Q>(&self, key: &Q) -> Option<V>
    where
        K: std::borrow::Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.entries.get(key).cloned()
    }

    /// Returns the memoized value, computing and storing it on a miss and
    /// evicting the oldest entry at capacity.
    pub(crate) fn get_or_insert_with(&mut self, key: K, make: impl FnOnce() -> V) -> V {
        if let Some(existing) = self.entries.get(&key) {
            return existing.clone();
        }
        let value = make();
        if self.entries.len() >= self.capacity.get()
            && let Some(oldest) = self.order.pop_front()
        {
            self.entries.remove(&oldest);
        }
        self.entries.insert(key.clone(), value.clone());
        self.order.push_back(key);
        value
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_memo_never_exceeds_its_capacity_and_forgets_oldest_first() {
        let mut memo = BoundedFifo::new(NonZeroUsize::new(2).unwrap());
        let made = std::cell::Cell::new(0);
        let make = |k: u32| {
            made.set(made.get() + 1);
            k * 10
        };

        assert_eq!(memo.get_or_insert_with(1, || make(1)), 10);
        assert_eq!(memo.get_or_insert_with(1, || make(1)), 10);
        assert_eq!(made.get(), 1, "a hit computes nothing");

        memo.get_or_insert_with(2, || make(2));
        memo.get_or_insert_with(3, || make(3));
        assert_eq!(memo.len(), 2);
        assert_eq!(memo.get(&1), None, "the oldest entry is gone");
        assert_eq!(memo.get(&3), Some(30));
    }
}
