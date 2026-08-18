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
//! **What completes is a packet, not a payload.** The fragments carry
//! transport bytes, but a consumer re-parses an IP datagram — so the headers of
//! the fragment at offset zero are kept and the datagram is rebuilt behind
//! them, per RFC 791 section 3.2 for IPv4 and RFC 8200 section 4.5 for IPv6.
//! [`ReassembledPacket`] is what says which of the two came out; when it was
//! `Vec<u8>` the two were the same type and the datapath parsed the wrong one.
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

/// The IPv6 Fragment header's Next Header value and fixed length (RFC 8200
/// section 4.5: "The Fragment header is identified by a Next Header value of 44",
/// and its format is two 32-bit words).
const IPV6_FRAGMENT: u8 = 44;
const IPV6_FRAGMENT_BYTES: usize = 8;
const IPV6_HEADER_BYTES: usize = 40;

/// One fragment of one datagram, and the headers the whole datagram will
/// inherit from it.
///
/// **Fields are private because two of them are refinements the wire
/// establishes and nothing else can.** `offset` is a multiple of eight, because
/// it is decoded from a field counted in 8-byte units; `headers` is the exact
/// prefix `payload` was carved out of. Reassembly's block accounting depends on
/// the first and its output depends on the second, so [`Self::parse`] is the
/// only way to make one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fragment<'a> {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    identification: u32,
    /// Payload offset in bytes; wire units already decoded, hence a multiple
    /// of eight.
    offset: u16,
    more_fragments: bool,
    payload: &'a [u8],
    /// What the reassembled datagram is rebuilt behind, taken from this
    /// fragment when its offset is zero and ignored otherwise. RFC 791
    /// section 3.2 files the first fragment's internet header in the header
    /// buffer; RFC 8200 section 4.5 says the reassembled packet's Per-Fragment
    /// headers are "all headers up to, but not including, the Fragment header
    /// of the first fragment packet".
    headers: &'a [u8],
    /// For IPv6, where in `headers` the Next Header byte sits that reassembly
    /// must overwrite: RFC 8200 section 4.5 requires that "the Next Header
    /// field of the last header of the Per-Fragment headers is obtained from
    /// the Next Header field of the first fragment's Fragment header". `None`
    /// for IPv4, which has no such splice.
    next_header_at: Option<usize>,
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
                // etherparse has already proven the header is well formed and
                // wholly present, so its declared length is a valid index.
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
                // A fragmented IPv6 packet has exactly one Fragment header.
                let Some(Ipv6ExtensionSlice::Fragment(header)) = ipv6
                    .extensions()
                    .clone()
                    .into_iter()
                    .find(|extension| matches!(extension, Ipv6ExtensionSlice::Fragment(_)))
                else {
                    return Ok(None);
                };
                // **The chain is walked again here, and etherparse cannot do
                // it for us.** `Ipv6Slice::payload` skips every extension
                // header, but RFC 8200 section 4.5 puts the headers after the
                // Fragment header in the *Fragmentable* Part — "These headers
                // must be in the first fragment" — so they are payload to be
                // reassembled, not headers to be re-emitted. Taking
                // etherparse's payload would drop them from the datagram.
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

    /// The transport this datagram carries: IPv4's Protocol field, or the
    /// Fragment header's Next Header for IPv6.
    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    /// Always a multiple of eight.
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

/// Walks an IPv6 header chain to its Fragment header, returning the index of
/// the Next Header byte that precedes it and the index of the header itself.
///
/// RFC 8200 section 4.5 defines the Per-Fragment headers as "the IPv6 header
/// plus any extension headers that must be processed by nodes en route to the
/// destination, that is, all headers up to and including the Routing header if
/// present, else the Hop-by-Hop Options header if present" — so the walk stops
/// at the first Fragment header and treats everything before it as inherited.
///
/// O(extension headers), which RFC 8200 section 4.1 bounds at one Hop-by-Hop,
/// one Routing, and two Destination Options in a conforming packet; a
/// non-conforming chain terminates all the same because every step advances
/// `at` by at least eight bytes.
fn ipv6_fragment_header(packet: &[u8]) -> Option<(usize, usize)> {
    // Byte 6 of the fixed header is its Next Header field.
    let mut next_header_at = 6;
    let mut at = IPV6_HEADER_BYTES;

    loop {
        let next = *packet.get(next_header_at)?;
        if next == IPV6_FRAGMENT {
            // The Fragment header must be wholly present for its Next Header
            // to be spliceable.
            packet.get(at..at + IPV6_FRAGMENT_BYTES)?;
            return Some((next_header_at, at));
        }
        let length = match next {
            // Hop-by-Hop Options, Routing, Destination Options: "Length ... in
            // 8-octet units, not including the first 8 octets" (RFC 8200
            // sections 4.3, 4.4, 4.6).
            0 | 43 | 60 => (usize::from(*packet.get(at + 1)?) + 1) * 8,
            // The Authentication Header is the exception RFC 4302 section 2.2
            // names: its length is "in 32-bit words (4-byte units), minus 2",
            // explicitly not the 8-byte convention the others use.
            51 => (usize::from(*packet.get(at + 1)?) + 2) * 4,
            // Anything else is an upper-layer header, so there is no Fragment
            // header in this chain.
            _ => return None,
        };
        next_header_at = at;
        at = at.checked_add(length)?;
    }
}

/// A datagram every fragment of which arrived, rebuilt into the packet its
/// sender wrote.
///
/// **The type exists because `Vec<u8>` did not distinguish the two things
/// reassembly could plausibly return.** What the fragments carry is transport
/// payload; what a consumer re-parses is an IP packet; both are bytes, so the
/// compiler had nothing to say when reassembly handed out the first and the
/// datapath parsed the second. Every completed datagram failed with
/// `UnsupportedIpVersion` and the error was indistinguishable from a malformed
/// packet.
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

/// Rebuilds the datagram from the headers of its first fragment and the
/// reassembled data.
///
/// Returns `None` when the result cannot be a packet — a header that is not
/// the family it claimed, or a datagram whose length no longer fits the field
/// that has to state it. O(headers + data), one allocation sized exactly once.
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
            // IPv4. RFC 791 section 3.2 files the first fragment's header and
            // sets `TL <- TDL+(IHL*4)`; the fragment fields go with the
            // fragmentation they described.
            if packet.len() < 20 || packet[0] >> 4 != 4 {
                return None;
            }
            let total = u16::try_from(packet.len()).ok()?;
            packet[2..4].copy_from_slice(&total.to_be_bytes());
            // Clear More Fragments and the offset, keeping the two high flag
            // bits: Don't Fragment on a reassembled datagram is not something
            // RFC 791, RFC 815, or RFC 1122 section 3.3.2 speaks to, so it is
            // left exactly as the sender set it rather than invented here.
            packet[6] &= 0b1100_0000;
            packet[7] = 0;
            // **Recomputed, though no reassembly text demands it.** RFC 791
            // lists the header checksum among the "fields which may be
            // affected by fragmentation" but its reassembly procedure never
            // says to recompute one; only the fragmentation procedure does.
            // Total Length just changed, so the inherited checksum is stale
            // and every downstream parser that verifies it would reject the
            // datagram.
            packet[10..12].copy_from_slice(&[0, 0]);
            let checksum = ones_complement(&packet[..(usize::from(packet[0] & 0x0f) * 4)]);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        }
        Some(next_header_at) => {
            // IPv6. The Fragment header "is not present in the final,
            // reassembled packet" (RFC 8200 section 4.5), which `headers`
            // already reflects, and the Next Header it carried is spliced into
            // the last Per-Fragment header.
            if packet.len() < IPV6_HEADER_BYTES || packet[0] >> 4 != 6 {
                return None;
            }
            *packet.get_mut(next_header_at)? = protocol;
            // Equivalent to RFC 8200's `PL.orig = PL.first - FL.first - 8 +
            // (8 * FO.last) + FL.last`: both name the bytes after the fixed
            // header, and this side has the reassembled length directly.
            let payload = u16::try_from(packet.len() - IPV6_HEADER_BYTES).ok()?;
            packet[4..6].copy_from_slice(&payload.to_be_bytes());
        }
    }
    Some(packet)
}

/// The internet checksum of `header`: the one's complement of the one's
/// complement sum of its 16-bit words (RFC 1071). O(header bytes).
fn ones_complement(header: &[u8]) -> u16 {
    let sum = header
        .chunks(2)
        .map(|word| u32::from(u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)])))
        .sum::<u32>();
    let folded = (sum & 0xffff) + (sum >> 16);
    !u16::try_from((folded & 0xffff) + (folded >> 16)).unwrap_or(u16::MAX)
}

#[derive(Debug, PartialEq, Eq)]
pub enum PushOutcome {
    /// Buffered.
    Pending,
    /// Every block of the datagram arrived exactly once.
    Complete(ReassembledPacket),
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
    expiry: Expiry,
    poisoned: bool,
    /// The headers of the fragment at offset zero, and where IPv6's Next
    /// Header splice lands in them. Empty until that fragment arrives, which
    /// is why completion cannot be reached without it: the datagram is not
    /// complete while block zero is missing.
    headers: Vec<u8>,
    next_header_at: Option<usize>,
}

/// When a pending datagram expires, and which bucket its key currently sits in.
///
/// **The two diverge, and conflating them leaks the index.** Every fragment
/// refreshes `at`, but re-filing the key on each one would cost a bucket scan
/// per fragment — so the slot stays where it was written and `expire`
/// re-validates it. That is sound only while removal names the *slot*: unfiling
/// a completed datagram under its refreshed `at` looks in a bucket the key was
/// never in, and leaves a slot behind for an entry that is gone. `max_pending`
/// bounds the entries, not the index, so those slots accumulate for a whole
/// timeout at whatever rate datagrams complete.
#[derive(Clone, Copy, Debug)]
struct Expiry {
    /// Authoritative. What `expire` compares against `now`.
    at: Instant,
    /// Where the key is filed. Always a valid key into `expirations`.
    slot: Instant,
}

impl Expiry {
    fn filed(at: Instant) -> Self {
        Self { at, slot: at }
    }

    /// Moves the deadline without moving the slot, which is what makes a
    /// refresh O(1).
    fn refresh(&mut self, at: Instant) {
        self.at = at;
    }

    /// Records that the key has been re-filed under its current deadline,
    /// returning the slot it left. `None` when the two already agreed.
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
        // The *slot*, not the deadline: they diverge on every refresh, and
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
        let checksum = ones_complement(&packet[..20]);
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
            PushOutcome::Complete(datagram(b"aaaaaaaabb"))
        );
        assert!(reassembler.is_empty());
        assert_eq!(index_slots(&reassembler), 0, "the slot left with the entry");
        assert_eq!(reassembler.next_deadline(), None);
    }

    #[test]
    fn a_refreshed_datagram_that_completes_leaves_no_slot_behind() {
        // **The divergence the same-instant tests could not see.** Every
        // fragment refreshes the deadline but not the slot, so a datagram
        // completed after a refresh was unfiled under a bucket it had never
        // been in — leaving one orphan slot per completion, for a whole
        // timeout, in an index `max_pending` does not bound.
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
        // RFC 8200 section 4.5: the Fragment header "is not present in the
        // final, reassembled packet", the last Per-Fragment header's Next
        // Header comes from it, and Payload Length counts what follows the
        // fixed header.
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
                // The Per-Fragment headers stop before the Fragment header,
                // which sits at byte 40 and does not survive reassembly.
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
