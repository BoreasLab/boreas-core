//! Fragment reassembly for IPv4 and IPv6. Boreas's TUN adapter receives
//! packets destined for this node, so RFC 8200's reassembly requirement
//! applies in full; dropping fragments or answering them with a sub-1280 PTB
//! black-holes senders that are already at the IPv6 minimum.
//!
//! Validation-first rules, per RFC 8200 section 4.5 and RFC 5722:
//! - overlapping fragments are forbidden in IPv6 and an attack in IPv4, so any
//!   overlapping byte silently discards the whole pending datagram, for both
//!   families, whether the overlap agrees or not;
//! - a non-final fragment must fill whole 8-byte blocks (RFC 791 / RFC 8200);
//! - the completed datagram must fit the 64 KiB ceiling;
//! - capacity and timeouts bound memory; a poisoned or evicted key admits
//!   nothing until it expires.
//!
//! Time enters only through `now`, and the expiry index follows the same
//! discipline as `UdpFlowTable`'s timer wheel: **one slot per pending
//! datagram, inserted once**. A later fragment refreshes the datagram's
//! deadline in place, `expire` re-validates each surfaced slot against the
//! real deadline and re-buckets it, and a datagram that completes early takes
//! its slot with it. The index is therefore O(pending), bounded by
//! `max_pending`, never O(fragments) — which matters because fragments are
//! attacker-chosen and pending datagrams are not.

use std::{
    collections::{BTreeMap, HashMap, btree_map, hash_map::Entry},
    net::IpAddr,
    num::NonZeroUsize,
    time::{Duration, Instant},
};

use etherparse::{Ipv6ExtensionSlice, NetSlice, SlicedPacket};

use crate::PacketError;

const MAX_DATAGRAM_BYTES: usize = u16::MAX as usize;
/// The wire offset unit is 8 bytes, so reassembly tracks one bit per block.
const BLOCK_BITS: usize = MAX_DATAGRAM_BYTES / 8 + 1;
const BITMAP_WORDS: usize = BLOCK_BITS.div_ceil(64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fragment<'a> {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: u8,
    pub identification: u32,
    /// Payload offset in bytes; wire units already decoded.
    pub offset: u16,
    pub more_fragments: bool,
    pub payload: &'a [u8],
}

impl<'a> Fragment<'a> {
    /// `Ok(None)` when the packet carries no fragment boundary.
    pub fn parse(packet: &'a [u8]) -> Result<Option<Self>, PacketError> {
        let sliced = SlicedPacket::from_ip(packet).map_err(PacketError::Malformed)?;
        let Some(net) = sliced.net else {
            return Ok(None);
        };

        match net {
            NetSlice::Ipv4(ipv4) => {
                if !ipv4.is_payload_fragmented() {
                    return Ok(None);
                }
                let header = ipv4.header();
                Ok(Some(Self {
                    source: IpAddr::V4(header.source_addr()),
                    destination: IpAddr::V4(header.destination_addr()),
                    protocol: header.protocol().0,
                    identification: u32::from(header.identification()),
                    offset: header.fragments_offset().value() * 8,
                    more_fragments: header.more_fragments(),
                    payload: ipv4.payload().payload,
                }))
            }
            NetSlice::Ipv6(ipv6) => {
                if !ipv6.is_payload_fragmented() {
                    return Ok(None);
                }
                // A fragmented IPv6 packet has exactly one Fragment header.
                let Some(Ipv6ExtensionSlice::Fragment(header)) = ipv6
                    .extensions()
                    .clone()
                    .into_iter()
                    .find(|extension| matches!(extension, Ipv6ExtensionSlice::Fragment(_)))
                else {
                    return Ok(None);
                };
                Ok(Some(Self {
                    source: IpAddr::V6(ipv6.header().source_addr()),
                    destination: IpAddr::V6(ipv6.header().destination_addr()),
                    protocol: header.next_header().0,
                    identification: header.identification(),
                    offset: header.fragment_offset().value() * 8,
                    more_fragments: header.more_fragments(),
                    payload: ipv6.payload().payload,
                }))
            }
            NetSlice::Arp(_) => Ok(None),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum PushOutcome {
    /// Buffered.
    Pending,
    /// Every block of the datagram arrived exactly once.
    Complete(Vec<u8>),
    /// Malformed, overlapping, poisoned, or over capacity.
    Discarded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Key {
    source: IpAddr,
    destination: IpAddr,
    identification: u32,
    protocol: u8,
}

struct Pending {
    /// Grows to the largest extent seen; the final fragment supplies total,
    /// avoiding a 64 KiB upfront allocation.
    data: Vec<u8>,
    received: [u64; BITMAP_WORDS],
    /// Incremental block count makes completion O(1); overlap rejection keeps
    /// the count exact.
    received_blocks: u32,
    total: Option<usize>,
    deadline: Instant,
    poisoned: bool,
}

impl Pending {
    fn new(deadline: Instant) -> Self {
        Self {
            data: Vec::new(),
            received: [0; BITMAP_WORDS],
            received_blocks: 0,
            total: None,
            deadline,
            poisoned: false,
        }
    }

    fn block_received(&self, block: usize) -> bool {
        self.received[block / 64] & (1 << (block % 64)) != 0
    }

    /// Marks `first_block ..= last_block`, all of which the caller has already
    /// shown to be unset. O(blocks in the fragment), dominated by the payload
    /// copy that accompanies it.
    fn mark_received(&mut self, first_block: usize, last_block: usize) {
        for block in first_block..=last_block {
            self.received[block / 64] |= 1 << (block % 64);
        }
        self.received_blocks += (last_block - first_block + 1) as u32;
    }

    /// O(1); overlap and known-total checks make block-count equality
    /// sufficient.
    fn is_complete(&self) -> bool {
        self.total
            .is_some_and(|total| usize::try_from(self.received_blocks) == Ok(total.div_ceil(8)))
    }
}

pub struct Reassembler {
    timeout: Duration,
    max_pending: NonZeroUsize,
    pending: HashMap<Key, Pending>,
    expirations: BTreeMap<Instant, Vec<Key>>,
    discarded: u64,
}

impl Reassembler {
    pub fn new(timeout: Duration, max_pending: NonZeroUsize) -> Self {
        Self {
            timeout,
            max_pending,
            pending: HashMap::new(),
            expirations: BTreeMap::new(),
            discarded: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub fn discarded(&self) -> u64 {
        self.discarded
    }

    /// A lower bound on the earliest live deadline: never later than the true
    /// one, because a refreshed datagram's slot still sits at its former
    /// deadline until `expire` re-buckets it. The caller's own deadline check
    /// stays authoritative, so an early answer costs one extra `expire` pass
    /// and nothing else.
    ///
    /// O(log pending), and every slot points at a live entry — which is what
    /// makes this safe to call once per reactor iteration.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.expirations
            .first_key_value()
            .map(|(deadline, _)| *deadline)
    }

    pub fn push(&mut self, fragment: Fragment<'_>, now: Instant) -> PushOutcome {
        let offset = usize::from(fragment.offset);
        let extent = offset + fragment.payload.len();

        // An empty fragment carries no data, so the block arithmetic below
        // has nothing to operate on and the datagram gains nothing.
        if fragment.payload.is_empty()
            || extent > MAX_DATAGRAM_BYTES
            || (fragment.more_fragments && !fragment.payload.len().is_multiple_of(8))
        {
            self.discarded = self.discarded.saturating_add(1);
            return PushOutcome::Discarded;
        }

        let key = Key {
            source: fragment.source,
            destination: fragment.destination,
            identification: fragment.identification,
            protocol: fragment.protocol,
        };

        if !self.pending.contains_key(&key) && self.pending.len() == self.max_pending.get() {
            self.expire(now);
            if self.pending.len() == self.max_pending.get() {
                self.discarded = self.discarded.saturating_add(1);
                return PushOutcome::Discarded;
            }
        }

        // Instant overflow is not a real clock; an entry expiring at `now` is
        // the conservative answer.
        let deadline = now.checked_add(self.timeout).unwrap_or(now);

        let pending = match self.pending.entry(key) {
            Entry::Occupied(occupied) => occupied.into_mut(),
            Entry::Vacant(vacant) => {
                // One index slot per pending datagram, inserted exactly once.
                // A later fragment only refreshes `deadline` below, so a
                // fragment flood adds no expiry-index memory at all.
                self.expirations.entry(deadline).or_default().push(key);
                vacant.insert(Pending::new(deadline))
            }
        };
        pending.deadline = deadline;

        if pending.poisoned {
            self.discarded = self.discarded.saturating_add(1);
            return PushOutcome::Discarded;
        }

        if let Some(total) = pending.total
            && (!fragment.more_fragments && extent != total || extent > total)
        {
            pending.poisoned = true;
            self.discarded = self.discarded.saturating_add(1);
            return PushOutcome::Discarded;
        }

        // RFC 5722: any overlap discards the whole datagram, for both
        // families. Identical retransmits are the only overlap a benign path
        // produces, and they are discarded with the rest, which is safe: the
        // sender will retry from a clean key.
        let first_block = offset / 8;
        let last_block = (extent - 1) / 8;
        if (first_block..=last_block).any(|block| pending.block_received(block)) {
            pending.poisoned = true;
            self.discarded = self.discarded.saturating_add(1);
            return PushOutcome::Discarded;
        }

        if extent > pending.data.len() {
            pending.data.resize(extent, 0);
        }
        pending.data[offset..extent].copy_from_slice(fragment.payload);
        pending.mark_received(first_block, last_block);

        if !fragment.more_fragments {
            // The final fragment fixes the datagram's length, so a byte
            // already received beyond it contradicts the declaration exactly
            // as a later fragment past a known total does. `data.len()` is the
            // largest extent seen, which makes the check O(1). Without it,
            // `received_blocks` could count blocks outside `total` and the
            // completion test would lose its soundness argument.
            if pending.data.len() > extent {
                pending.poisoned = true;
                self.discarded = self.discarded.saturating_add(1);
                return PushOutcome::Discarded;
            }
            pending.total = Some(extent);
        }

        if !pending.is_complete() {
            return PushOutcome::Pending;
        }

        // A completed datagram leaves `pending`, so its slot leaves the index
        // with it; the index never outlives its entries.
        let deadline = pending.deadline;
        let Some(mut pending) = self.pending.remove(&key) else {
            return PushOutcome::Discarded;
        };
        self.forget_slot(deadline, &key);
        pending.data.truncate(pending.total.unwrap_or(0));
        PushOutcome::Complete(pending.data)
    }

    /// Removes one key from its expiry bucket. O(keys sharing the bucket),
    /// bounded by `max_pending`; buckets are sets, so `swap_remove`'s
    /// reordering is unobservable.
    fn forget_slot(&mut self, deadline: Instant, key: &Key) {
        let btree_map::Entry::Occupied(mut bucket) = self.expirations.entry(deadline) else {
            return;
        };
        let keys = bucket.get_mut();
        if let Some(at) = keys.iter().position(|candidate| candidate == key) {
            keys.swap_remove(at);
        }
        if keys.is_empty() {
            bucket.remove();
        }
    }

    /// Evicts every pending datagram whose real deadline has arrived, and
    /// re-buckets the slots of those refreshed since their slot was written.
    ///
    /// O(surfaced slots x log pending). Re-bucketing happens after the drain
    /// so a re-inserted slot, whose deadline is by construction later than
    /// `now`, cannot be re-surfaced by the same pass.
    pub fn expire(&mut self, now: Instant) -> usize {
        let mut evicted = 0;
        let mut rebucket: Vec<(Instant, Key)> = Vec::new();

        while self
            .expirations
            .first_key_value()
            .is_some_and(|(deadline, _)| *deadline <= now)
        {
            let Some((_, keys)) = self.expirations.pop_first() else {
                break;
            };
            for key in keys {
                // The slot is a hint; the entry's real deadline governs, so a
                // refreshed datagram is re-bucketed rather than evicted early.
                match self.pending.entry(key) {
                    Entry::Occupied(occupied) if occupied.get().deadline <= now => {
                        occupied.remove();
                        evicted += 1;
                    }
                    Entry::Occupied(occupied) => rebucket.push((occupied.get().deadline, key)),
                    Entry::Vacant(_) => {}
                }
            }
        }

        for (deadline, key) in rebucket {
            self.expirations.entry(deadline).or_default().push(key);
        }
        evicted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const NOW: fn() -> Instant = Instant::now;

    fn fragment(offset: u16, more_fragments: bool, payload: &'static [u8]) -> Fragment<'static> {
        Fragment {
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            protocol: 17,
            identification: 0xbeef,
            offset,
            more_fragments,
            payload,
        }
    }

    fn fresh_reassembler() -> Reassembler {
        Reassembler::new(Duration::from_secs(30), NonZeroUsize::new(8).unwrap())
    }

    #[test]
    fn reassembles_out_of_order_fragments() {
        let mut reassembler = fresh_reassembler();
        let now = NOW();
        let message: &[u8] = b"a datagram split across three whole blocks!";

        assert_eq!(
            reassembler.push(fragment(16, false, &message[16..]), now),
            PushOutcome::Pending
        );
        assert_eq!(
            reassembler.push(fragment(0, true, &message[..8]), now),
            PushOutcome::Pending
        );
        assert_eq!(
            reassembler.push(fragment(8, true, &message[8..16]), now),
            PushOutcome::Complete(message.to_vec())
        );
        assert!(reassembler.is_empty());
    }

    #[test]
    fn any_overlap_discards_the_datagram() {
        let now = NOW();
        let first = fragment(0, true, b"12345678");

        let mut reassembler = fresh_reassembler();
        assert_eq!(reassembler.push(first, now), PushOutcome::Pending);
        // Even a byte-identical retransmit is an overlap, and RFC 5722's
        // whole-datagram discard applies to IPv4 as defense in depth.
        assert_eq!(reassembler.push(first, now), PushOutcome::Discarded);
        // A conflicting overlap poisons the same way, and the key stays
        // poisoned until expiry.
        let mut fresh = fresh_reassembler();
        assert_eq!(
            fresh.push(fragment(0, true, b"12345678"), now),
            PushOutcome::Pending
        );
        assert_eq!(
            fresh.push(fragment(0, true, b"1234567X"), now),
            PushOutcome::Discarded
        );
        assert_eq!(
            fresh.push(fragment(0, true, b"12345678"), now),
            PushOutcome::Discarded
        );
        assert_eq!(
            fresh.push(fragment(8, false, b"87654321"), now),
            PushOutcome::Discarded
        );
        assert_eq!(fresh.discarded(), 3);
    }

    #[test]
    fn rejects_malformed_fragments_and_bounds_capacity() {
        let mut reassembler = fresh_reassembler();
        let now = NOW();

        // Non-final fragment not filling whole blocks.
        assert_eq!(
            reassembler.push(fragment(0, true, b"short"), now),
            PushOutcome::Discarded
        );
        // Two conflicting final fragments disagree on the total.
        assert_eq!(
            reassembler.push(fragment(8, false, b"tail"), now),
            PushOutcome::Pending
        );
        assert_eq!(
            reassembler.push(fragment(16, false, b"tail"), now),
            PushOutcome::Discarded
        );

        let mut tiny = Reassembler::new(Duration::from_secs(30), NonZeroUsize::new(1).unwrap());
        let first = fragment(0, true, b"12345678");
        assert_eq!(tiny.push(first, now), PushOutcome::Pending);
        let mut second = fragment(0, true, b"12345678");
        second.identification = 0xcafe;
        assert_eq!(tiny.push(second, now), PushOutcome::Discarded);
        // Expiry frees capacity for the same key later.
        assert_eq!(tiny.expire(now + Duration::from_secs(31)), 1);
        assert_eq!(tiny.push(second, now), PushOutcome::Pending);
    }

    /// Total slots in the expiry index. The invariant under test is that this
    /// tracks pending datagrams, never fragments.
    fn index_slots(reassembler: &Reassembler) -> usize {
        reassembler.expirations.values().map(Vec::len).sum()
    }

    #[test]
    fn a_fragment_flood_does_not_grow_the_expiry_index() {
        // The P7 defect, in the module P7 did not reach. `max_pending` bounds
        // `pending`; nothing bounded the index, and every fragment — including
        // the ones immediately rejected as overlapping — used to add a slot.
        let start = NOW();
        let mut reassembler = fresh_reassembler();
        assert_eq!(
            reassembler.push(fragment(0, true, b"aaaaaaaa"), start),
            PushOutcome::Pending
        );

        for tick in 0..10_000 {
            let now = start + Duration::from_millis(tick);
            assert_eq!(
                reassembler.push(fragment(0, true, b"aaaaaaaa"), now),
                PushOutcome::Discarded,
                "an overlapping fragment is refused"
            );
        }

        assert_eq!(reassembler.len(), 1, "one pending datagram");
        assert_eq!(index_slots(&reassembler), 1, "one datagram, one slot");
    }

    #[test]
    fn a_completed_datagram_takes_its_index_slot_with_it() {
        // Without this, the index would grow with completions instead of
        // fragments — the same unbounded shape wearing a different hat.
        let now = NOW();
        let mut reassembler = fresh_reassembler();
        assert_eq!(
            reassembler.push(fragment(0, true, b"aaaaaaaa"), now),
            PushOutcome::Pending
        );
        assert_eq!(index_slots(&reassembler), 1);
        assert_eq!(
            reassembler.push(fragment(8, false, b"bb"), now),
            PushOutcome::Complete(b"aaaaaaaabb".to_vec())
        );
        assert!(reassembler.is_empty());
        assert_eq!(index_slots(&reassembler), 0, "the slot left with the entry");
        assert_eq!(reassembler.next_deadline(), None);
    }

    #[test]
    fn a_refreshed_datagram_is_rebucketed_rather_than_evicted() {
        // A slot is only a hint. The entry's real deadline governs, so the
        // stale slot must survive expiry as a re-insertion, or the datagram
        // would become invisible to every later pass.
        let start = NOW();
        let mut reassembler = fresh_reassembler();
        assert_eq!(
            reassembler.push(fragment(0, true, b"aaaaaaaa"), start),
            PushOutcome::Pending
        );
        // Refresh at t+20s: real deadline moves to t+50s, slot stays at t+30s.
        assert_eq!(
            reassembler.push(
                fragment(8, true, b"bbbbbbbb"),
                start + Duration::from_secs(20)
            ),
            PushOutcome::Pending
        );

        assert_eq!(reassembler.expire(start + Duration::from_secs(31)), 0);
        assert_eq!(reassembler.len(), 1, "the refreshed datagram survived");
        assert_eq!(index_slots(&reassembler), 1, "and is still indexed");
        assert_eq!(
            reassembler.next_deadline(),
            Some(start + Duration::from_secs(50)),
            "re-bucketed at its real deadline"
        );
        assert_eq!(reassembler.expire(start + Duration::from_secs(51)), 1);
        assert!(reassembler.is_empty());
    }

    #[test]
    fn a_fragment_beyond_the_declared_total_poisons_the_datagram() {
        // The soundness condition for the O(1) completion test: a block may
        // never be counted outside `total`. The final fragment arriving last
        // is caught by the extent check; arriving first, by this one.
        let now = NOW();
        let mut reassembler = fresh_reassembler();
        // Data at offset 1000 first, then a final fragment declaring total 8.
        assert_eq!(
            reassembler.push(fragment(1000, true, b"aaaaaaaa"), now),
            PushOutcome::Pending
        );
        assert_eq!(
            reassembler.push(fragment(0, false, b"bbbbbbbb"), now),
            PushOutcome::Discarded,
            "a declared total cannot be shorter than what already arrived"
        );
        // Poisoned: nothing further is admitted under this key until it expires.
        assert_eq!(
            reassembler.push(fragment(0, false, b"bbbbbbbb"), now),
            PushOutcome::Discarded
        );
    }

    #[test]
    fn rejects_empty_payload_fragments() {
        // Regression: the fuzzer drove a zero-length fragment into
        // `(extent - 1) / 8` and subtracted with overflow.
        let mut reassembler = fresh_reassembler();
        assert_eq!(
            reassembler.push(fragment(0, false, b""), NOW()),
            PushOutcome::Discarded
        );
        assert_eq!(reassembler.discarded(), 1);
    }

    #[test]
    fn parses_ipv4_and_ipv6_wire_fragments() {
        let ipv4 = [
            0x45, 0x00, 0x00, 0x1c, 0xbe, 0xef, 0x20, 0x01, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51,
            100, 2, 1, 2, 3, 4, 5, 6, 7, 8,
        ];
        assert_eq!(
            Fragment::parse(&ipv4),
            Ok(Some(Fragment {
                source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
                protocol: 17,
                identification: 0xbeef,
                offset: 8,
                more_fragments: true,
                payload: &[1, 2, 3, 4, 5, 6, 7, 8],
            }))
        );

        let ipv6 = [
            0x60, 0, 0, 0, 0, 16, 44, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 17, 0, 0, 9, 0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4,
            5, 6, 7, 8,
        ];
        assert_eq!(
            Fragment::parse(&ipv6),
            Ok(Some(Fragment {
                source: IpAddr::V6(Ipv6Addr::LOCALHOST),
                destination: IpAddr::V6(Ipv6Addr::LOCALHOST),
                protocol: 17,
                identification: 0xdeadbeef,
                offset: 8,
                more_fragments: true,
                payload: &[1, 2, 3, 4, 5, 6, 7, 8],
            }))
        );

        let mut whole = ipv4;
        whole[6] = 0;
        whole[7] = 0;
        whole[24..26].copy_from_slice(&8_u16.to_be_bytes()); // valid UDP length
        assert_eq!(Fragment::parse(&whole), Ok(None));
        assert!(matches!(
            Fragment::parse(&[0x45]),
            Err(PacketError::Malformed(_))
        ));
    }
}
