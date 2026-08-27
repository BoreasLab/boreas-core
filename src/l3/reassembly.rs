//! Bounded IPv4 and IPv6 fragment reassembly.
//!
//! Validation follows RFC 8200 section 4.5 and RFC 5722: overlaps discard the
//! whole datagram, non-final fragments use complete 8-byte blocks, completed
//! packets fit within 64 KiB, and capacity plus expiry bound memory.
//!
//! Reassembly returns a complete IP packet, retaining the offset-zero headers
//! and rebuilding the transport data behind them. The expiry index has one slot
//! per pending datagram. Refreshes update a deadline in place; expiry rechecks
//! stale slots before re-bucketing them.

use std::{
    collections::{BTreeMap, HashMap, btree_map, hash_map::Entry},
    net::IpAddr,
    num::NonZeroUsize,
    time::{Duration, Instant},
};

use etherparse::{Ipv6ExtensionSlice, NetSlice, SlicedPacket};

use crate::{PacketError, wire::checksum};

const MAX_DATAGRAM_BYTES: usize = u16::MAX as usize;
/// One bitmap bit per 8-byte wire offset block.
const BLOCK_BITS: usize = MAX_DATAGRAM_BYTES / 8 + 1;
const BITMAP_WORDS: usize = BLOCK_BITS.div_ceil(64);

/// IPv6 Fragment header value and fixed length from RFC 8200 section 4.5.
const IPV6_FRAGMENT: u8 = 44;
const IPV6_FRAGMENT_BYTES: usize = 8;
const IPV6_HEADER_BYTES: usize = 40;

/// Parsed fragment and the headers inherited by its reassembled packet.
///
/// [`Self::parse`] is the only constructor because the wire establishes the
/// aligned offset and the header prefix used by reassembly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fragment<'a> {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    identification: u32,
    /// Payload offset in bytes, always aligned to eight.
    offset: u16,
    more_fragments: bool,
    payload: &'a [u8],
    /// Header prefix inherited from the offset-zero fragment.
    headers: &'a [u8],
    /// IPv6 Next Header position to replace; absent for IPv4.
    next_header_at: Option<usize>,
}

impl<'a> Fragment<'a> {
    /// Parses a fragment, or returns `None` for an unfragmented packet.
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
                // etherparse has validated the complete IPv4 header.
                let header_bytes = usize::from(header.ihl()) * 4;
                Ok(Some(Self {
                    source: IpAddr::V4(header.source_addr()),
                    destination: IpAddr::V4(header.destination_addr()),
                    protocol: header.protocol().0,
                    identification: u32::from(header.identification()),
                    offset: header.fragments_offset().value() * 8,
                    more_fragments: header.more_fragments(),
                    payload: ipv4.payload().payload,
                    headers: packet.get(..header_bytes).unwrap_or_default(),
                    next_header_at: None,
                }))
            }
            NetSlice::Ipv6(ipv6) => {
                if !ipv6.is_payload_fragmented() {
                    return Ok(None);
                }
                // A fragmented IPv6 packet has one Fragment header.
                let Some(Ipv6ExtensionSlice::Fragment(header)) = ipv6
                    .extensions()
                    .clone()
                    .into_iter()
                    .find(|extension| matches!(extension, Ipv6ExtensionSlice::Fragment(_)))
                else {
                    return Ok(None);
                };
                // Headers after the Fragment header are fragmentable data and
                // must be retained for reassembly.
                let Some((next_header_at, fragment_at)) = ipv6_fragment_header(packet) else {
                    return Ok(None);
                };
                Ok(Some(Self {
                    source: IpAddr::V6(ipv6.header().source_addr()),
                    destination: IpAddr::V6(ipv6.header().destination_addr()),
                    protocol: header.next_header().0,
                    identification: header.identification(),
                    offset: header.fragment_offset().value() * 8,
                    more_fragments: header.more_fragments(),
                    payload: packet
                        .get(fragment_at + IPV6_FRAGMENT_BYTES..)
                        .unwrap_or_default(),
                    headers: packet.get(..fragment_at).unwrap_or_default(),
                    next_header_at: Some(next_header_at),
                }))
            }
            NetSlice::Arp(_) => Ok(None),
        }
    }

    pub fn source(&self) -> IpAddr {
        self.source
    }

    pub fn destination(&self) -> IpAddr {
        self.destination
    }

    /// Transport protocol carried by the fragment.
    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    /// Payload offset, always a multiple of eight.
    pub fn offset(&self) -> u16 {
        self.offset
    }

    pub fn more_fragments(&self) -> bool {
        self.more_fragments
    }

    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

/// Finds an IPv6 Fragment header and the preceding Next Header byte.
///
/// Headers before the Fragment header are inherited; later extension headers
/// are fragmentable data.
fn ipv6_fragment_header(packet: &[u8]) -> Option<(usize, usize)> {
    // Byte 6 is the fixed header's Next Header field.
    let mut next_header_at = 6;
    let mut at = IPV6_HEADER_BYTES;

    loop {
        let next = *packet.get(next_header_at)?;
        if next == IPV6_FRAGMENT {
            // The Fragment header must be complete before its value is used.
            packet.get(at..at + IPV6_FRAGMENT_BYTES)?;
            return Some((next_header_at, at));
        }
        let length = match next {
            // These extension headers encode length in 8-byte units after the
            // first 8 bytes (RFC 8200 sections 4.3, 4.4, and 4.6).
            0 | 43 | 60 => (usize::from(*packet.get(at + 1)?) + 1) * 8,
            // Authentication Header length uses 4-byte units (RFC 4302 section
            // 2.2), unlike the other extension headers here.
            51 => (usize::from(*packet.get(at + 1)?) + 2) * 4,
            // No supported extension means no Fragment header in this chain.
            _ => return None,
        };
        next_header_at = at;
        at = at.checked_add(length)?;
    }
}

/// Complete IP packet rebuilt from received fragments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReassembledPacket(Vec<u8>);

impl ReassembledPacket {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl std::ops::Deref for ReassembledPacket {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

/// Rebuilds a packet from offset-zero headers and reassembled data.
///
/// Returns `None` when family or length fields cannot represent the result.
fn rebuild(
    headers: &[u8],
    next_header_at: Option<usize>,
    protocol: u8,
    data: &[u8],
) -> Option<Vec<u8>> {
    let mut packet = Vec::with_capacity(headers.len() + data.len());
    packet.extend_from_slice(headers);
    packet.extend_from_slice(data);

    match next_header_at {
        None => {
            // Restore IPv4 total length and clear fragmentation fields.
            if packet.len() < 20 || packet[0] >> 4 != 4 {
                return None;
            }
            let total = u16::try_from(packet.len()).ok()?;
            packet[2..4].copy_from_slice(&total.to_be_bytes());
            // Clear More Fragments and the offset, preserving the other flags.
            packet[6] &= 0b1100_0000;
            packet[7] = 0;
            // Total Length changed, so recompute the IPv4 header checksum.
            packet[10..12].copy_from_slice(&[0, 0]);
            let checksum = checksum(&[&packet[..(usize::from(packet[0] & 0x0f) * 4)]]);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        }
        Some(next_header_at) => {
            // Omit the Fragment header and splice its Next Header value into
            // the inherited prefix (RFC 8200 section 4.5).
            if packet.len() < IPV6_HEADER_BYTES || packet[0] >> 4 != 6 {
                return None;
            }
            *packet.get_mut(next_header_at)? = protocol;
            // Payload Length counts all bytes after the fixed IPv6 header.
            let payload = u16::try_from(packet.len() - IPV6_HEADER_BYTES).ok()?;
            packet[4..6].copy_from_slice(&payload.to_be_bytes());
        }
    }
    Some(packet)
}

#[derive(Debug, PartialEq, Eq)]
pub enum PushOutcome {
    /// Fragment accepted; more data is required.
    Pending,
    /// Every block arrived exactly once.
    Complete(ReassembledPacket),
    /// Fragment rejected or datagram poisoned.
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
    /// Data up to the largest extent seen; the final fragment supplies total.
    data: Vec<u8>,
    received: [u64; BITMAP_WORDS],
    /// Received block count for constant-time completion checks.
    received_blocks: u32,
    total: Option<usize>,
    expiry: Expiry,
    poisoned: bool,
    /// Inherited headers and IPv6 Next Header splice position.
    headers: Vec<u8>,
    next_header_at: Option<usize>,
}

/// Authoritative expiry and the bucket currently indexing a pending datagram.
///
/// Refreshes change `at` but leave `slot` until expiry re-buckets the key. Any
/// removal must use `slot`, or a stale index entry remains after completion.
#[derive(Clone, Copy, Debug)]
struct Expiry {
    /// Deadline compared with `now`.
    at: Instant,
    /// Bucket currently containing the key.
    slot: Instant,
}

impl Expiry {
    fn filed(at: Instant) -> Self {
        Self { at, slot: at }
    }

    /// Refreshes the deadline without moving the bucket.
    fn refresh(&mut self, at: Instant) {
        self.at = at;
    }

    /// Moves the bucket to the current deadline, returning the old bucket.
    fn refiled(&mut self) -> Option<Instant> {
        (self.slot != self.at).then(|| std::mem::replace(&mut self.slot, self.at))
    }
}

impl Pending {
    fn new(expiry: Expiry) -> Self {
        Self {
            data: Vec::new(),
            received: [0; BITMAP_WORDS],
            received_blocks: 0,
            total: None,
            expiry,
            poisoned: false,
            headers: Vec::new(),
            next_header_at: None,
        }
    }

    fn block_received(&self, block: usize) -> bool {
        self.received[block / 64] & (1 << (block % 64)) != 0
    }

    fn mark_received(&mut self, first_block: usize, last_block: usize) {
        for block in first_block..=last_block {
            self.received[block / 64] |= 1 << (block % 64);
        }
        self.received_blocks += (last_block - first_block + 1) as u32;
    }

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

    /// Returns the earliest indexed deadline.
    ///
    /// A refreshed entry may be reported early; [`Self::expire`] validates its
    /// authoritative deadline before evicting it.
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
                vacant.insert(Pending::new(Expiry::filed(deadline)))
            }
        };
        pending.expiry.refresh(deadline);

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

        if offset == 0 {
            // RFC 791 section 3.2 and RFC 8200 section 4.5 both name the
            // fragment at offset zero as the one whose headers the reassembled
            // datagram inherits, so only this one is kept.
            pending.headers.clear();
            pending.headers.extend_from_slice(fragment.headers);
            pending.next_header_at = fragment.next_header_at;
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
        let slot = pending.expiry.slot;
        let Some(mut pending) = self.pending.remove(&key) else {
            return PushOutcome::Discarded;
        };
        // The slot, not the deadline: they diverge on every refresh, and
        // unfiling under the wrong one leaves the index holding a key whose
        // entry is gone. See [`Expiry`].
        self.forget_slot(slot, &key);
        pending.data.truncate(pending.total.unwrap_or(0));
        let Some(packet) = rebuild(
            &pending.headers,
            pending.next_header_at,
            key.protocol,
            &pending.data,
        ) else {
            self.discarded = self.discarded.saturating_add(1);
            return PushOutcome::Discarded;
        };
        PushOutcome::Complete(ReassembledPacket(packet))
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
                    Entry::Occupied(occupied) if occupied.get().expiry.at <= now => {
                        occupied.remove();
                        evicted += 1;
                    }
                    Entry::Occupied(mut occupied) => {
                        // The slot moves with the key, so the entry and the
                        // index agree again from here.
                        occupied.get_mut().expiry.refiled();
                        rebucket.push((occupied.get().expiry.at, key));
                    }
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

    /// The IPv4 header every synthetic fragment below carries, with More
    /// Fragments set and a length that reassembly must correct.
    const HEADER: [u8; 20] = [
        0x45, 0x00, 0x00, 0x1c, 0xbe, 0xef, 0x20, 0x00, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2,
    ];

    fn fragment(offset: u16, more_fragments: bool, payload: &'static [u8]) -> Fragment<'static> {
        Fragment {
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            protocol: 17,
            identification: 0xbeef,
            offset,
            more_fragments,
            payload,
            headers: &HEADER,
            next_header_at: None,
        }
    }

    /// The datagram [`HEADER`]'s fragments must reassemble into: the same
    /// header with Total Length corrected, the fragment fields cleared, and the
    /// checksum recomputed over the result.
    fn datagram(payload: &[u8]) -> ReassembledPacket {
        let mut packet = HEADER.to_vec();
        packet.extend_from_slice(payload);
        let total = u16::try_from(packet.len()).unwrap();
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        packet[6] = 0;
        packet[7] = 0;
        packet[10..12].copy_from_slice(&[0, 0]);
        let checksum = checksum(&[&packet[..20]]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        ReassembledPacket(packet)
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
            PushOutcome::Complete(datagram(message))
        );
        assert!(reassembler.is_empty());
    }

    #[test]
    fn any_overlap_discards_the_datagram() {
        let now = NOW();
        let first = fragment(0, true, b"12345678");

        let mut reassembler = fresh_reassembler();
        assert_eq!(reassembler.push(first, now), PushOutcome::Pending);
        // Identical retransmits are overlaps and poison the datagram.
        assert_eq!(reassembler.push(first, now), PushOutcome::Discarded);
        // Conflicting overlaps poison the key until expiry.
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

        // Non-final payloads must fill complete 8-byte blocks.
        assert_eq!(
            reassembler.push(fragment(0, true, b"short"), now),
            PushOutcome::Discarded
        );
        // Fragments beyond a known total are rejected.
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
        // Expiry frees the capacity slot.
        assert_eq!(tiny.expire(now + Duration::from_secs(31)), 1);
        assert_eq!(tiny.push(second, now), PushOutcome::Pending);
    }

    /// Counts expiry slots; one slot must represent one pending datagram.
    fn index_slots(reassembler: &Reassembler) -> usize {
        reassembler.expirations.values().map(Vec::len).sum()
    }

    #[test]
    fn a_fragment_flood_does_not_grow_the_expiry_index() {
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
        let now = NOW();
        let mut reassembler = fresh_reassembler();
        assert_eq!(
            reassembler.push(fragment(0, true, b"aaaaaaaa"), now),
            PushOutcome::Pending
        );
        assert_eq!(index_slots(&reassembler), 1);
        assert_eq!(
            reassembler.push(fragment(8, false, b"bb"), now),
            PushOutcome::Complete(datagram(b"aaaaaaaabb"))
        );
        assert!(reassembler.is_empty());
        assert_eq!(index_slots(&reassembler), 0, "the slot left with the entry");
        assert_eq!(reassembler.next_deadline(), None);
    }

    #[test]
    fn a_refreshed_datagram_that_completes_leaves_no_slot_behind() {
        let start = NOW();
        let mut reassembler = fresh_reassembler();
        assert_eq!(
            reassembler.push(fragment(0, true, b"aaaaaaaa"), start),
            PushOutcome::Pending
        );
        assert_eq!(
            reassembler.push(fragment(8, false, b"bb"), start + Duration::from_secs(5)),
            PushOutcome::Complete(datagram(b"aaaaaaaabb"))
        );
        assert!(reassembler.is_empty());
        assert_eq!(index_slots(&reassembler), 0, "the slot left with the entry");
        assert_eq!(reassembler.next_deadline(), None);
    }

    #[test]
    fn an_ipv6_datagram_is_rebuilt_without_its_fragment_header() {
        // Reassembly omits the Fragment header and restores its Next Header.
        let mut first = vec![
            0x60, 0, 0, 0, 0, 16, 44, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 17, 0, 0, 1, 0xde, 0xad, 0xbe, 0xef,
        ];
        first.extend_from_slice(b"aaaaaaaa");
        let mut second = first[..48].to_vec();
        second[5] = 10; // payload length: the Fragment header plus two bytes
        second[42] = 0; // fragment offset 8 bytes, more fragments clear
        second[43] = 8;
        second.extend_from_slice(b"bb");

        let mut reassembler = fresh_reassembler();
        let first = Fragment::parse(&first).unwrap().unwrap();
        assert_eq!(reassembler.push(first, NOW()), PushOutcome::Pending);
        let second = Fragment::parse(&second).unwrap().unwrap();
        let PushOutcome::Complete(packet) = reassembler.push(second, NOW()) else {
            panic!("every fragment arrived");
        };

        assert_eq!(packet.len(), 50, "40-byte header plus ten bytes of payload");
        assert_eq!(&packet[40..], b"aaaaaaaabb");
        assert_eq!(packet[6], 17, "the Fragment header's Next Header, spliced");
        assert_eq!(
            u16::from_be_bytes([packet[4], packet[5]]),
            10,
            "Payload Length counts the reassembled data, not the fragment"
        );
    }

    #[test]
    fn a_refreshed_datagram_is_rebucketed_rather_than_evicted() {
        // A stale slot is reinserted until the authoritative deadline.
        let start = NOW();
        let mut reassembler = fresh_reassembler();
        assert_eq!(
            reassembler.push(fragment(0, true, b"aaaaaaaa"), start),
            PushOutcome::Pending
        );
        // Refresh the deadline while leaving the original slot in place.
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
        // Completion accounting must never count blocks beyond the total.
        let now = NOW();
        let mut reassembler = fresh_reassembler();
        // Receive data beyond the total declared by a later final fragment.
        assert_eq!(
            reassembler.push(fragment(1000, true, b"aaaaaaaa"), now),
            PushOutcome::Pending
        );
        assert_eq!(
            reassembler.push(fragment(0, false, b"bbbbbbbb"), now),
            PushOutcome::Discarded,
            "a declared total cannot be shorter than what already arrived"
        );
        // A poisoned key admits nothing until expiry.
        assert_eq!(
            reassembler.push(fragment(0, false, b"bbbbbbbb"), now),
            PushOutcome::Discarded
        );
    }

    #[test]
    fn rejects_empty_payload_fragments() {
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
                headers: &ipv4[..20],
                next_header_at: None,
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
                // The Fragment header starts at byte 40 and is omitted.
                headers: &ipv6[..40],
                next_header_at: Some(6),
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
