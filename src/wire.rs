//! The crate's byte alphabet: one reader, one writer, one checksum.
//!
//! DNS, TLS, proxy, framing, and IP code share the same bounds and length
//! arithmetic here. Centralizing it prevents a checked index or length prefix
//! from being assumed differently by the next parser.
//!
//! # Why no extra dependency
//!
//! `bytes::Buf` is total but cannot return a borrowed subslice with the
//! required lifetime; `copy_to_bytes` allocates. `Bytes` remains useful for
//! owned payloads, but not for these parsers. `octets` stays for RFC 9000
//! varints, where its existing implementation is worth reusing; its unsafe
//! integer accessors are unnecessary for the fixed-width reads here. `zerocopy`
//! targets fixed representations, while these formats are variable-length and
//! `etherparse` already handles the fixed IP headers. `nom` and `winnow` would
//! replace this crate's `Decoded::Incomplete` model across every parser. The
//! derive-oriented `scroll`, `deku`, and `binrw` target file-format concerns
//! absent from these network encodings.
//!
//! # Why there is no SIMD path
//!
//! This module handles headers and bounded messages rather than bulk data.
//! AEAD, TLS records, and HTML scanning already reach vectorized code through
//! `ring`, BoringSSL, and `memchr`; dispatching here would add a branch without
//! a bulk workload.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Forward cursor over untrusted bytes.
///
/// Accessors return `None` instead of panicking on short input, and borrowed
/// results retain the caller's buffer lifetime. Parsers map missing bytes to
/// [`Decoded::Incomplete`](crate::sansio::Decoded) and reserve protocol errors
/// for bytes that are present.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// Creates a cursor at `at`, or returns `None` past the buffer.
    ///
    /// DNS compression pointers use this to seek within the message.
    pub(crate) fn at(bytes: &'a [u8], at: usize) -> Option<Self> {
        (at <= bytes.len()).then_some(Self { bytes, at })
    }

    pub(crate) fn position(&self) -> usize {
        self.at
    }

    pub(crate) fn rest(&self) -> &'a [u8] {
        &self.bytes[self.at..]
    }

    pub(crate) fn remaining(&self) -> usize {
        self.bytes.len() - self.at
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub(crate) fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let taken = self.rest().get(..length)?;
        self.at += length;
        Some(taken)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Option<&'a [u8; N]> {
        let taken = self.rest().first_chunk::<N>()?;
        self.at += N;
        Some(taken)
    }

    pub(crate) fn skip(&mut self, length: usize) -> Option<()> {
        self.take(length).map(drop)
    }

    pub(crate) fn u8(&mut self) -> Option<u8> {
        self.array::<1>().map(|byte| byte[0])
    }

    pub(crate) fn u16(&mut self) -> Option<u16> {
        self.array().copied().map(u16::from_be_bytes)
    }

    /// A 24-bit network-order integer used by TLS handshakes.
    pub(crate) fn u24(&mut self) -> Option<u32> {
        self.array::<3>()
            .map(|bytes| u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]))
    }

    pub(crate) fn u32(&mut self) -> Option<u32> {
        self.array().copied().map(u32::from_be_bytes)
    }

    pub(crate) fn u64(&mut self) -> Option<u64> {
        self.array().copied().map(u64::from_be_bytes)
    }

    /// Reads one RFC 9000 section 16 variable-length integer.
    ///
    /// `octets` supplies the shared varint implementation. A partial encoding
    /// returns `None` like every other reader accessor.
    pub(crate) fn varint(&mut self) -> Option<u64> {
        let mut octets = octets::Octets::with_slice(self.rest());
        let value = octets.get_varint().ok()?;
        self.at += octets.off();
        Some(value)
    }

    pub(crate) fn vector_u8(&mut self) -> Option<&'a [u8]> {
        let length = usize::from(self.u8()?);
        self.take(length)
    }

    /// Reads a vector with a two-byte network-order length prefix.
    ///
    /// The prefix is consumed even when the body is short; callers abandon an
    /// incomplete parse rather than resume a partially consumed vector.
    pub(crate) fn vector_u16(&mut self) -> Option<&'a [u8]> {
        let length = usize::from(self.u16()?);
        self.take(length)
    }

    pub(crate) fn ipv4(&mut self) -> Option<Ipv4Addr> {
        self.array::<4>().copied().map(Ipv4Addr::from)
    }

    pub(crate) fn ipv6(&mut self) -> Option<Ipv6Addr> {
        self.array::<16>().copied().map(Ipv6Addr::from)
    }
}

/// Append-only cursor over a growing buffer.
///
/// Length-prefixed helpers write each prefix with its body. Width checks are
/// debug assertions because their inputs are derived from locally sized data.
pub(crate) struct Writer<'a> {
    out: &'a mut Vec<u8>,
}

impl<'a> Writer<'a> {
    pub(crate) fn new(out: &'a mut Vec<u8>) -> Self {
        Self { out }
    }

    pub(crate) fn u8(&mut self, value: u8) -> &mut Self {
        self.out.push(value);
        self
    }

    pub(crate) fn u16(&mut self, value: u16) -> &mut Self {
        self.bytes(&value.to_be_bytes())
    }

    pub(crate) fn u32(&mut self, value: u32) -> &mut Self {
        self.bytes(&value.to_be_bytes())
    }

    pub(crate) fn u64(&mut self, value: u64) -> &mut Self {
        self.bytes(&value.to_be_bytes())
    }

    /// Writes an RFC 9000 section 16 varint in its shortest form.
    ///
    /// Values above 2^62 - 1 are rejected by a debug assertion.
    pub(crate) fn varint(&mut self, value: u64) -> &mut Self {
        debug_assert!(
            value <= octets::MAX_VAR_INT,
            "{value} does not fit in a 62-bit varint"
        );
        let start = self.out.len();
        self.out.resize(start + octets::varint_len(value), 0);
        octets::OctetsMut::with_slice(&mut self.out[start..])
            .put_varint(value)
            .expect("the buffer was sized by varint_len");
        self
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) -> &mut Self {
        self.out.extend_from_slice(value);
        self
    }

    pub(crate) fn vector_u8(&mut self, value: &[u8]) -> &mut Self {
        debug_assert!(value.len() <= usize::from(u8::MAX), "vector overruns u8");
        self.u8(value.len() as u8).bytes(value)
    }

    pub(crate) fn vector_u16(&mut self, value: &[u8]) -> &mut Self {
        debug_assert!(value.len() <= usize::from(u16::MAX), "vector overruns u16");
        self.u16(value.len() as u16).bytes(value)
    }

    pub(crate) fn vector_u32(&mut self, value: &[u8]) -> &mut Self {
        debug_assert!(
            u32::try_from(value.len()).is_ok(),
            "vector overruns u32: {}",
            value.len()
        );
        self.u32(value.len() as u32).bytes(value)
    }

    pub(crate) fn vector_varint(&mut self, value: &[u8]) -> &mut Self {
        self.varint(value.len() as u64).bytes(value)
    }
}

/// Append-only cursor over a fixed-capacity buffer.
///
/// Writes that do not fit set a sticky overflow flag and write nothing;
/// [`Bounded::finish`] converts that state to `None`. This keeps bounded DNS
/// response construction chainable without hiding partial output.
pub(crate) struct Bounded<'a> {
    out: &'a mut [u8],
    at: usize,
    overflowed: bool,
}

impl<'a> Bounded<'a> {
    /// Creates a cursor at `at`, or returns `None` past the buffer.
    pub(crate) fn at(out: &'a mut [u8], at: usize) -> Option<Self> {
        (at <= out.len()).then_some(Self {
            out,
            at,
            overflowed: false,
        })
    }

    /// Returns the next position, or `None` after any overflow.
    pub(crate) fn finish(self) -> Option<usize> {
        (!self.overflowed).then_some(self.at)
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) -> &mut Self {
        match self.out.get_mut(self.at..self.at + value.len()) {
            Some(slot) if !self.overflowed => {
                slot.copy_from_slice(value);
                self.at += value.len();
            }
            _ => self.overflowed = true,
        }
        self
    }

    pub(crate) fn u8(&mut self, value: u8) -> &mut Self {
        self.bytes(&[value])
    }

    pub(crate) fn u16(&mut self, value: u16) -> &mut Self {
        self.bytes(&value.to_be_bytes())
    }

    pub(crate) fn u32(&mut self, value: u32) -> &mut Self {
        self.bytes(&value.to_be_bytes())
    }

    pub(crate) fn zeros(&mut self, count: usize) -> &mut Self {
        match self.out.get_mut(self.at..self.at + count) {
            Some(slot) if !self.overflowed => {
                slot.fill(0);
                self.at += count;
            }
            _ => self.overflowed = true,
        }
        self
    }

    pub(crate) fn vector_u8(&mut self, value: &[u8]) -> &mut Self {
        debug_assert!(value.len() <= usize::from(u8::MAX), "vector overruns u8");
        self.u8(value.len() as u8).bytes(value)
    }
}

pub(crate) fn varint_len(value: u64) -> usize {
    octets::varint_len(value)
}

/// Computes the RFC 1071 section 1 Internet checksum over concatenated parts.
///
/// Odd-length parts carry their trailing byte into the next part; the final odd
/// byte is padded with zero. Parts avoid assembling pseudo-headers first.
pub(crate) fn checksum(parts: &[&[u8]]) -> u16 {
    let mut bytes = parts.iter().copied().flatten().copied();
    let mut sum = 0_u32;
    while let Some(high) = bytes.next() {
        sum += u32::from(u16::from_be_bytes([high, bytes.next().unwrap_or(0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test input is literal wire data, not output from [`Writer`].
    #[test]
    fn every_accessor_is_total_on_a_short_buffer() {
        for length in 0..8 {
            let bytes = vec![0xff; length];
            let mut reader = Reader::new(&bytes);
            // Failed reads must leave the cursor unchanged.
            assert_eq!(reader.take(length + 1), None);
            assert_eq!(reader.array::<9>(), None);
            assert_eq!(reader.skip(length + 1), None);
            assert_eq!(reader.position(), 0);
            assert_eq!(reader.remaining(), length);
        }

        assert!(Reader::new(&[]).is_empty());
        assert_eq!(Reader::new(&[]).u8(), None);
        assert_eq!(Reader::new(&[0]).u16(), None);
        assert_eq!(Reader::new(&[0, 0]).u24(), None);
        assert_eq!(Reader::new(&[0, 0, 0]).u32(), None);
        assert_eq!(Reader::new(&[0; 7]).u64(), None);
        assert_eq!(Reader::new(&[0; 3]).ipv4(), None);
        assert_eq!(Reader::new(&[0; 4]).ipv4(), Some(Ipv4Addr::UNSPECIFIED));
        assert_eq!(Reader::new(&[0; 15]).ipv6(), None);
    }

    #[test]
    fn every_width_reads_in_network_order() {
        let mut reader = Reader::new(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12,
        ]);
        assert_eq!(reader.u8(), Some(0x01));
        assert_eq!(reader.u16(), Some(0x0203));
        assert_eq!(reader.u24(), Some(0x040506));
        assert_eq!(reader.u32(), Some(0x0708_090a));
        assert_eq!(reader.u64(), Some(0x0b0c_0d0e_0f10_1112));
        assert!(reader.is_empty());
    }

    #[test]
    fn a_read_borrows_rather_than_copies() {
        let bytes = [0x00, 0x03, b'a', b'b', b'c', b'd'];
        let mut reader = Reader::new(&bytes);
        let body = reader.vector_u16().expect("three bytes follow the prefix");
        assert!(std::ptr::eq(body.as_ptr(), bytes[2..].as_ptr()));
        assert_eq!(body, b"abc");
        assert_eq!(reader.rest(), b"d");
    }

    #[test]
    fn a_vector_longer_than_its_buffer_is_refused() {
        assert_eq!(Reader::new(&[4, 1, 2]).vector_u8(), None);
        assert_eq!(Reader::new(&[0, 4, 1, 2]).vector_u16(), None);
        assert_eq!(Reader::new(&[0, 0]).vector_u16(), Some(&[][..]));
    }

    #[test]
    fn a_seek_lands_where_it_was_told_or_nowhere() {
        let bytes = [1, 2, 3, 4];
        assert_eq!(Reader::at(&bytes, 2).map(|r| r.rest()), Some(&[3, 4][..]));
        assert_eq!(Reader::at(&bytes, 4).map(|r| r.rest()), Some(&[][..]));
        assert!(Reader::at(&bytes, 5).is_none());
    }

    #[test]
    fn each_varint_uses_the_shortest_form_that_holds_it() {
        for (value, width) in [
            (0u64, 1usize),
            (63, 1),
            (64, 2),
            (16_383, 2),
            (16_384, 4),
            (1_073_741_823, 4),
            (1_073_741_824, 8),
            (octets::MAX_VAR_INT, 8),
            // Keep a representative application value in the boundary set.
            (0x401, 2),
        ] {
            let mut encoded = Vec::new();
            Writer::new(&mut encoded).varint(value);
            assert_eq!(encoded.len(), width, "{value} encoded to {encoded:?}");

            let mut reader = Reader::new(&encoded);
            assert_eq!(reader.varint(), Some(value));
            assert!(reader.is_empty());
        }
    }

    #[test]
    fn every_varint_prefix_is_incomplete_and_the_tail_is_preserved() {
        for value in [0u64, 63, 64, 16_384, 1_073_741_824, octets::MAX_VAR_INT] {
            let mut encoded = Vec::new();
            Writer::new(&mut encoded).varint(value);
            for cut in 0..encoded.len() {
                let mut short = Reader::new(&encoded[..cut]);
                assert_eq!(short.varint(), None, "{value} decoded from a prefix");
                assert_eq!(short.position(), 0, "a failed varint moved the cursor");
            }

            encoded.extend_from_slice(b"tail");
            let mut reader = Reader::new(&encoded);
            assert_eq!(reader.varint(), Some(value));
            assert_eq!(reader.rest(), b"tail");
        }
    }

    #[test]
    fn a_written_vector_reads_back_as_itself() {
        let body = b"boreas";
        let mut out = Vec::new();
        Writer::new(&mut out)
            .vector_u8(body)
            .vector_u16(body)
            .vector_u32(body)
            .vector_varint(body);

        let mut reader = Reader::new(&out);
        assert_eq!(reader.vector_u8(), Some(&body[..]));
        assert_eq!(reader.vector_u16(), Some(&body[..]));
        assert_eq!(reader.u32().map(|n| n as usize), Some(body.len()));
        assert_eq!(reader.take(body.len()), Some(&body[..]));
        assert_eq!(reader.varint().map(|n| n as usize), Some(body.len()));
        assert_eq!(reader.take(body.len()), Some(&body[..]));
        assert!(reader.is_empty());
    }

    #[test]
    fn a_bounded_overflow_is_sticky() {
        let mut out = [0u8; 4];
        let mut writer = Bounded::at(&mut out, 0).expect("zero is inside any buffer");
        writer.u16(0x0102).u32(0x0304_0506).u8(0xff);
        assert_eq!(writer.finish(), None, "the u32 did not fit");
        assert_eq!(out, [0x01, 0x02, 0, 0], "nothing after the overflow landed");

        // An exact fit succeeds.
        let mut out = [0u8; 4];
        let mut writer = Bounded::at(&mut out, 0).expect("zero is inside any buffer");
        writer.u16(0x0102).u16(0x0304);
        assert_eq!(writer.finish(), Some(4));
        assert_eq!(out, [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn a_bounded_cursor_starts_inside_its_buffer_or_not_at_all() {
        let mut out = [0u8; 2];
        assert!(Bounded::at(&mut out, 3).is_none());
        assert_eq!(
            Bounded::at(&mut out, 2).and_then(Bounded::finish),
            Some(2),
            "the far end is a legal position holding no room"
        );
        let mut writer = Bounded::at(&mut out, 2).expect("the far end is inside");
        writer.zeros(1);
        assert_eq!(writer.finish(), None);
    }

    /// Matches RFC 1071's worked checksum example.
    #[test]
    fn the_checksum_matches_rfc_1071s_worked_example() {
        assert_eq!(
            checksum(&[&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]]),
            0x220d
        );
    }

    #[test]
    fn the_split_between_parts_does_not_change_the_sum() {
        let stream: Vec<u8> = (0..=60u8).collect();
        let whole = checksum(&[&stream]);
        for cut in 0..=stream.len() {
            let (head, tail) = stream.split_at(cut);
            assert_eq!(checksum(&[head, tail]), whole, "split at {cut}");
            assert_eq!(checksum(&[head, &[], tail]), whole, "empty part at {cut}");
        }
    }

    #[test]
    fn an_odd_length_stream_pads_with_zero() {
        assert_eq!(checksum(&[&[0xab]]), checksum(&[&[0xab, 0x00]]));
        assert_eq!(checksum(&[]), u16::MAX);
    }
}
