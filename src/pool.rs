//! Recycled payload buffers.
//!
//! A datagram queued for a flow must live somewhere until the egress takes it.
//! Owning a fresh `Vec<u8>` per queued datagram makes that cost the product
//! `flows x queue depth x MTU`: about 120 MB at the 10,000-flow acceptance
//! target with a depth of eight. A fixed pool of MTU-sized buffers replaces the
//! product with a single budget. Memory is `capacity x slice_size` and never
//! more, exhaustion is a drop rather than a wait, and a returned buffer keeps
//! its allocation for the next datagram.
//!
//! The pool owns no bytes and performs no I/O, so it belongs beside the pure
//! core rather than inside the runtime shell. Two properties carry the design:
//!
//! - `Pooled` is affine. It is deliberately not `Clone`, so a payload has
//!   exactly one owner from the producer to the wire and two handles onto the
//!   same bytes are unrepresentable rather than merely discouraged.
//! - `Drop` is the release. There is no separate `release` call to forget, and
//!   an expiring flow returns its whole queue by dropping it.

use std::{
    num::NonZeroUsize,
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

/// A bounded budget of equally sized byte buffers.
///
/// Buffers are allocated lazily and recycled forever after: an idle system
/// holds nothing, and a busy one converges on its own high-water mark.
pub struct BufferPool {
    slice_size: NonZeroUsize,
    capacity: NonZeroUsize,
    state: Mutex<PoolState>,
}

/// Invariant, established at construction and preserved by every method:
/// `free.len() <= live <= capacity`. `live` counts every buffer that exists,
/// on loan or cached, and is what bounds memory; `free` is only the recycling
/// cache.
struct PoolState {
    free: Vec<Vec<u8>>,
    live: usize,
    exhausted: u64,
}

impl BufferPool {
    /// `slice_size` is the largest datagram the pool will carry, normally the
    /// path MTU; `capacity` is how many such buffers may exist at once.
    /// Both are `NonZeroUsize` because a pool of zero buffers, or of buffers
    /// holding zero bytes, admits nothing and would only fail later.
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

    /// Copies `bytes` into a pooled buffer. `None` means the datagram exceeds
    /// the slice size, or the budget is spent; both are drops, never waits.
    ///
    /// O(`bytes.len()`) copy, O(1) accounting; recycled buffers never
    /// reallocate.
    pub fn take(self: &Arc<Self>, bytes: &[u8]) -> Option<Pooled> {
        let mut pooled = self.reserve(bytes.len())?;
        pooled.bytes.extend_from_slice(bytes);
        Some(pooled)
    }

    /// Builds a zeroed pooled buffer; the datapath uses it for synthesized IP
    /// datagrams without an extra allocation.
    pub fn take_zeroed(self: &Arc<Self>, len: usize) -> Option<Pooled> {
        let mut pooled = self.reserve(len)?;
        pooled.bytes.resize(len, 0);
        Some(pooled)
    }

    /// Reserves one budget unit and returns an empty buffer. Sole mutation
    /// point for `free.len() <= live <= capacity`.
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
                // Reserve under lock; allocate outside it.
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

    /// How many further `take` calls can succeed before the budget is spent.
    pub fn available(&self) -> usize {
        let state = self.state();
        self.capacity.get() - state.live + state.free.len()
    }

    /// Datagrams dropped because the budget was spent. The producer sees its
    /// own `None`; this is the aggregate an operator reads.
    pub fn exhausted(&self) -> u64 {
        self.state().exhausted
    }

    /// The largest datagram this pool admits.
    pub fn slice_size(&self) -> NonZeroUsize {
        self.slice_size
    }

    /// Every critical section is a `Vec` push/pop plus integer arithmetic, so
    /// none of them can unwind while the invariant is broken. A poisoned lock
    /// therefore carries no corrupted state and recovering from it is sound —
    /// which matters because the alternative, failing closed, would silently
    /// drop every datagram for the rest of the process's life.
    fn state(&self) -> MutexGuard<'_, PoolState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A buffer on loan from a [`BufferPool`]. Derefs to the bytes written into
/// it; `Drop` returns the allocation to the pool.
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

/// In-place rewriting of the bytes on loan. Sound precisely because `Pooled`
/// is affine: one handle, one writer, so `&mut` here cannot alias another view
/// of the same payload. `clamp_mss` is the caller this exists for.
impl DerefMut for Pooled {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

impl Pooled {
    /// Resizes the buffer in place, zero-filling any growth.
    ///
    /// For a producer that spends its budget *before* it knows how many bytes
    /// it will write — a `smoltcp` transmit token is handed out first and told
    /// its length second — so the reservation and the length are two steps
    /// rather than one. Never reallocates: the buffer already carries the
    /// pool's slice capacity, and `len` beyond it is refused rather than grown
    /// past the budget.
    ///
    /// Returns whether the length was admitted. O(len) for the fill, O(1)
    /// otherwise.
    #[must_use]
    pub fn resize(&mut self, len: usize) -> bool {
        if len > self.pool.slice_size.get() {
            return false;
        }
        self.bytes.resize(len, 0);
        true
    }

    /// The largest length [`Self::resize`] will admit.
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
        // `mem::take` leaves an empty `Vec`, which owns no allocation, so the
        // capacity travels back to the pool intact and `live` is unchanged.
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

        // Exhaustion returns `None` rather than waiting, and is counted.
        assert!(pool.take(b"x").is_none());
        assert_eq!(pool.exhausted(), 1);
        // A datagram larger than a slice is refused without spending budget.
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

        // Recycled, not reallocated: the shorter datagram must not inherit the
        // previous contents past its own length.
        let second = pool.take(b"bb").expect("recycled");
        assert_eq!(&*second, b"bb");
        assert_eq!(second.len(), 2);
    }

    #[test]
    fn allocation_is_lazy_so_an_idle_pool_costs_nothing() {
        let (slice_size, capacity) = sizes(1500, 10_000);
        let pool = BufferPool::new(slice_size, capacity);
        assert_eq!(pool.available(), 10_000);
        // `live` is the allocation count; an untouched pool has allocated
        // nothing, which is what makes a 15 MB budget free until it is used.
        assert_eq!(pool.state().live, 0);

        let held = pool.take(b"one datagram").expect("within budget");
        assert_eq!(pool.state().live, 1);
        drop(held);
        assert_eq!(pool.state().live, 1, "a returned buffer stays allocated");
        assert_eq!(pool.state().free.len(), 1);
    }
}
