//! Bounded, recycled payload buffers.
//!
//! Queued datagrams need storage until their egress consumes them. A pool of
//! fixed-size buffers turns per-datagram allocation into one bounded budget:
//! memory is at most `capacity x slice_size`, exhaustion drops immediately,
//! and returned buffers retain their allocations.
//!
//! The pool owns no I/O, so it belongs beside the pure core. Two properties
//! define ownership:
//!
//! - `Pooled` is not `Clone`, so each payload has one owner.
//! - `Drop` releases the allocation, including when a flow expires.

use std::{
    num::NonZeroUsize,
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex, MutexGuard},
};

/// A bounded pool of equally sized byte buffers.
///
/// Allocation is lazy and buffers are recycled, so an idle pool holds no
/// buffers and a busy pool stops at its high-water mark.
pub struct BufferPool {
    slice_size: NonZeroUsize,
    capacity: NonZeroUsize,
    state: Mutex<PoolState>,
}

/// `live` counts allocated buffers, whether on loan or cached. `free` is only
/// the recycling cache, and `free.len() <= live <= capacity` always holds.
struct PoolState {
    free: Vec<Vec<u8>>,
    live: usize,
    exhausted: u64,
}

impl BufferPool {
    /// Creates a pool for datagrams up to `slice_size`, with at most `capacity`
    /// allocated buffers. Nonzero inputs make an unusable pool unrepresentable.
    pub fn new(slice_size: NonZeroUsize, capacity: NonZeroUsize) -> Arc<Self> {
        Arc::new(Self {
            slice_size,
            capacity,
            state: Mutex::new(PoolState {
                free: Vec::new(),
                live: 0,
                exhausted: 0,
            }),
        })
    }

    /// Copies `bytes` into a pooled buffer. `None` means the datagram is too
    /// large or the budget is exhausted; neither case waits.
    pub fn take(self: &Arc<Self>, bytes: &[u8]) -> Option<Pooled> {
        let mut pooled = self.reserve(bytes.len())?;
        pooled.bytes.extend_from_slice(bytes);
        Some(pooled)
    }

    /// Builds a zeroed pooled buffer for synthesized IP datagrams.
    pub fn take_zeroed(self: &Arc<Self>, len: usize) -> Option<Pooled> {
        let mut pooled = self.reserve(len)?;
        pooled.bytes.resize(len, 0);
        Some(pooled)
    }

    /// Reserves one budget unit and returns an empty buffer. This is the only
    /// method that increases the live allocation count.
    fn reserve(self: &Arc<Self>, len: usize) -> Option<Pooled> {
        if len > self.slice_size.get() {
            return None;
        }

        let recycled = {
            let mut state = self.state();
            match state.free.pop() {
                Some(buffer) => Some(buffer),
                None if state.live >= self.capacity.get() => {
                    state.exhausted = state.exhausted.saturating_add(1);
                    return None;
                }
                // Reserve under the lock, then allocate outside it.
                None => {
                    state.live += 1;
                    None
                }
            }
        };

        Some(Pooled {
            pool: Arc::clone(self),
            bytes: recycled.unwrap_or_else(|| Vec::with_capacity(self.slice_size.get())),
        })
    }

    /// Returns the number of additional buffers the pool can provide.
    pub fn available(&self) -> usize {
        let state = self.state();
        self.capacity.get() - state.live + state.free.len()
    }

    /// Returns the number of datagrams dropped for budget exhaustion.
    pub fn exhausted(&self) -> u64 {
        self.state().exhausted
    }

    /// Returns the largest datagram size this pool admits.
    pub fn slice_size(&self) -> NonZeroUsize {
        self.slice_size
    }

    /// Recovers a poisoned lock because each critical section changes only the
    /// pool invariant's guarded vector and counters. The shared rationale is
    /// in [`crate::locked`].
    fn state(&self) -> MutexGuard<'_, PoolState> {
        crate::locked(&self.state)
    }
}

/// A buffer loaned from a [`BufferPool`]. Deref exposes its written bytes and
/// `Drop` returns its allocation.
///
/// Not `Clone`: see the module documentation.
pub struct Pooled {
    pool: Arc<BufferPool>,
    bytes: Vec<u8>,
}

impl Deref for Pooled {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Provides unique mutable access to the loaned bytes. `Pooled` is affine, so
/// no other handle can alias this view.
impl DerefMut for Pooled {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

impl Pooled {
    /// Resizes the loan in place, zero-filling growth, and rejects lengths past
    /// the pool slice size without reallocating.
    #[must_use]
    pub fn resize(&mut self, len: usize) -> bool {
        if len > self.pool.slice_size.get() {
            return false;
        }
        self.bytes.resize(len, 0);
        true
    }

    /// Returns the largest length [`Self::resize`] accepts.
    pub fn capacity_hint(&self) -> usize {
        self.pool.slice_size.get()
    }
}

impl PartialEq for Pooled {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl Eq for Pooled {}

impl PartialEq<[u8]> for Pooled {
    fn eq(&self, other: &[u8]) -> bool {
        **self == *other
    }
}

impl std::fmt::Debug for Pooled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Pooled({} bytes)", self.bytes.len())
    }
}

impl Drop for Pooled {
    fn drop(&mut self) {
        // Move the allocation back while leaving the dropped value empty.
        let mut buffer = std::mem::take(&mut self.bytes);
        buffer.clear();
        self.pool.state().free.push(buffer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sizes(slice_size: usize, capacity: usize) -> (NonZeroUsize, NonZeroUsize) {
        (
            NonZeroUsize::new(slice_size).unwrap(),
            NonZeroUsize::new(capacity).unwrap(),
        )
    }

    #[test]
    fn the_budget_bounds_live_buffers_and_exhaustion_is_a_drop() {
        let (slice_size, capacity) = sizes(8, 4);
        let pool = BufferPool::new(slice_size, capacity);
        assert_eq!(pool.available(), 4);

        let held: Vec<Pooled> = (0..4)
            .map(|_| pool.take(b"12345678").expect("within budget"))
            .collect();
        assert_eq!(pool.available(), 0);

        // Exhaustion drops immediately and is counted.
        assert!(pool.take(b"x").is_none());
        assert_eq!(pool.exhausted(), 1);
        // An oversized datagram does not spend budget.
        assert!(pool.take(b"far too large for this pool").is_none());
        assert_eq!(pool.exhausted(), 1);

        drop(held);
        assert_eq!(pool.available(), 4);
    }

    #[test]
    fn a_returned_buffer_serves_new_data_without_leaking_the_old() {
        let (slice_size, capacity) = sizes(8, 1);
        let pool = BufferPool::new(slice_size, capacity);

        let first = pool.take(b"aaaaaaaa").expect("within budget");
        assert_eq!(&*first, b"aaaaaaaa");
        drop(first);

        // Reuse must not expose bytes beyond the new length.
        let second = pool.take(b"bb").expect("recycled");
        assert_eq!(&*second, b"bb");
        assert_eq!(second.len(), 2);
    }

    #[test]
    fn allocation_is_lazy_so_an_idle_pool_costs_nothing() {
        let (slice_size, capacity) = sizes(1500, 10_000);
        let pool = BufferPool::new(slice_size, capacity);
        assert_eq!(pool.available(), 10_000);
        // An untouched pool has allocated nothing.
        assert_eq!(pool.state().live, 0);

        let held = pool.take(b"one datagram").expect("within budget");
        assert_eq!(pool.state().live, 1);
        drop(held);
        assert_eq!(pool.state().live, 1, "a returned buffer stays allocated");
        assert_eq!(pool.state().free.len(), 1);
    }
}
