//! The crate's byte alphabet: one reader, one writer, one checksum.
//!
//! Nine wire formats are decoded here — DNS, TLS, SOCKS5, VLESS, Shadowsocks
//! 2022, Hysteria2, MASQUE, gRPC framing, and the IP headers the datapath
//! rewrites — and until this module existed each carried its own arithmetic.
//! The arithmetic was the same every time and the mistakes it invites are the
//! same every time: an index that is checked in one place and assumed in the
//! next, a length prefix that disagrees with what follows it, an
//! `expect("2 bytes")` standing in for a proof.
//!
//! # Why nothing was added to `Cargo.toml`
//!
//! The obvious candidates were weighed against what this crate actually does
//! with bytes, and each fails on a property rather than on taste:
//!
//! - **`bytes` (already here, 225M downloads/quarter).** [`bytes::Buf`] is the
//!   ecosystem's buffer trait and its `try_get_*` family (1.10.0, February
//!   2025) is total. But `Buf` cannot hand back a subslice that outlives the
//!   borrow: `chunk` returns `&[u8]` tied to `&self`, and `copy_to_bytes`
//!   allocates. Every parser below returns borrowed views of the caller's
//!   buffer, so the one property that is not negotiable is the one `Buf` does
//!   not have. It stays where it belongs — `Bytes` as an owned, refcounted
//!   payload in the relay and transport layers.
//! - **`octets` (already here).** quiche's own reader, and the closest match
//!   by API: `get_bytes` really does return `Octets<'a>` at the buffer's
//!   lifetime. It is kept for the one encoding that is genuinely subtle — the
//!   RFC 9000 varint, see [`Reader::varint`] — and not for the rest, because
//!   its integer accessors are `ptr::copy_nonoverlapping` behind a bounds
//!   check. `src/` contains no `unsafe` at all today. Routing every untrusted
//!   parse in a security product through unsafe pointer arithmetic, to reach
//!   the same `bswap` the safe form compiles to, is a trade with nothing on
//!   the near side.
//! - **`zerocopy` (already here, transitively).** Genuinely zero-copy and the
//!   right tool for a fixed `#[repr(C)]` header. Every format below is
//!   variable-length and length-prefixed, so the parts it could type are the
//!   IPv4 and UDP headers — which `etherparse` already types.
//! - **`nom` 8 / `winnow` 1.0.** Both excellent, both zero-copy. Both would
//!   replace this crate's `Decoded::Incomplete` protocol with their own
//!   streaming model across ten parsers, which is a paradigm import rather
//!   than the "immediate executable need" the dependency rule asks for.
//! - **`scroll`, `deku`, `binrw`.** Derive-driven, and aimed at file formats
//!   with dynamic endianness. Nothing on a network is little-endian here.
//!
//! # Why there is no SIMD path
//!
//! A vector unit amortizes over bulk data, and this module never sees any. The
//! largest thing [`checksum`] covers is one TCP segment on a SYN — once per
//! connection — and the largest thing [`Reader`] walks is a DNS message, which
//! its own transport caps at 65535 bytes and typically holds under 512. The
//! places in this crate that *are* bulk — AEAD, TLS records, HTML scanning —
//! reach vector code already, inside `ring`, BoringSSL, and `memchr` beneath
//! `lol_html`. Adding a dispatch here would buy a branch.

use std::net::{Ipv4Addr, Ipv6Addr};

/// A forward cursor over untrusted bytes.
///
/// Two properties carry the weight. **Every accessor is total**: a short
/// buffer is `None`, never a panic, so a parser written against this type
/// cannot be made to index out of bounds by a peer. And **everything handed
/// back borrows the original buffer**, at `'a` rather than at the lifetime of
/// the `&mut self` that produced it, so a parse costs no copy — the returned
/// slices *are* the caller's bytes.
///
/// `None` means "not enough bytes", which is why it is `Option` rather than a
/// `Result` with an error type: absence of length is the only way any of these
/// can fail, and a protocol error is the caller's judgement about bytes that
/// were present. Parsers that must distinguish the two — every
/// [`Codec`](crate::sansio::Codec) — turn `None` into
/// [`Decoded::Incomplete`](crate::sansio::Decoded) and reserve their own error
/// type for the rest.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// A cursor positioned `at` bytes into `bytes`, for a format that names
    /// offsets rather than reading straight through.
    ///
    /// DNS is the only such format here: RFC 1035 §4.1.4 compression makes a
    /// name a pointer to somewhere earlier in the *message*, so following one
    /// means seeking rather than advancing. `None` for an offset past the end,
    /// which is how a pointer into nothing is rejected.
    pub(crate) fn at(bytes: &'a [u8], at: usize) -> Option<Self> {
        (at <= bytes.len()).then_some(Self { bytes, at })
    }

    /// How far in the cursor has reached. Meaningful only against the buffer
    /// it was built from.
    pub(crate) fn position(&self) -> usize {
        self.at
    }

    /// Everything not yet read, at the buffer's own lifetime.
    pub(crate) fn rest(&self) -> &'a [u8] {
        &self.bytes[self.at..]
    }

    pub(crate) fn remaining(&self) -> usize {
        self.bytes.len() - self.at
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// The next `length` bytes, or `None` if fewer remain.
    pub(crate) fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let taken = self.rest().get(..length)?;
        self.at += length;
        Some(taken)
    }

    /// The next `N` bytes as a fixed-size array.
    ///
    /// This is what replaces `slice.try_into().expect("N bytes")`: the width
    /// is in the type, so the proof that the conversion cannot fail is the
    /// signature rather than a message nobody reads until it fires.
    pub(crate) fn array<const N: usize>(&mut self) -> Option<&'a [u8; N]> {
        let taken = self.rest().first_chunk::<N>()?;
        self.at += N;
        Some(taken)
    }

    /// Advances past `length` bytes, or `None` if fewer remain.
    pub(crate) fn skip(&mut self, length: usize) -> Option<()> {
        self.take(length).map(drop)
    }

    pub(crate) fn u8(&mut self) -> Option<u8> {
        self.array::<1>().map(|byte| byte[0])
    }

    pub(crate) fn u16(&mut self) -> Option<u16> {
        self.array().copied().map(u16::from_be_bytes)
    }

    /// A 24-bit network-order integer, which is TLS's handshake length and
    /// nothing else here.
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

    /// One RFC 9000 §16 variable-length integer.
    ///
    /// **Delegated to `octets` rather than written here**, which is the one
    /// exception this module makes to its own no-dependency argument. The
    /// crate is quiche's buffer reader, so it is in the graph regardless and
    /// already carries whatever quiche has learned about this encoding; the
    /// two-bit width prefix and the shortest-form rule are exactly the kind of
    /// thing worth having exactly one implementation of. Every other accessor
    /// above is a bounds check and a `from_be_bytes`, which is not.
    ///
    /// `None` for a proper prefix as well as for an empty buffer, so a header
    /// that arrived in pieces reads as incomplete rather than as invalid —
    /// three protocols here (MASQUE, Hysteria2, and QUIC beneath both) decode
    /// from streams that can deliver one.
    pub(crate) fn varint(&mut self) -> Option<u64> {
        let mut octets = octets::Octets::with_slice(self.rest());
        let value = octets.get_varint().ok()?;
        self.at += octets.off();
        Some(value)
    }

    /// A length-prefixed vector's body, the prefix being one byte.
    pub(crate) fn vector_u8(&mut self) -> Option<&'a [u8]> {
        let length = usize::from(self.u8()?);
        self.take(length)
    }

    /// A length-prefixed vector's body, the prefix being two network-order
    /// bytes.
    ///
    /// **The prefix is consumed even when the body is short**, which is
    /// deliberate: a cursor that half-read a vector is not reusable, and every
    /// caller here abandons the parse on `None`. The alternative — rewinding —
    /// would offer a resumption none of them want.
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

/// An append-only cursor over a growing buffer.
///
/// Every method is infallible, because a `Vec` cannot refuse. What the type
/// buys is not safety but agreement: a length prefix and the body it counts
/// are written by one call, so the two cannot drift apart in a later edit.
///
/// **Widths are a debug assertion, not a `Result`.** A body too long for its
/// prefix is a defect in this crate rather than something a peer can provoke —
/// every length written here is derived from a buffer this crate sized — so
/// the check goes where the other derived-value checks in this crate go. See
/// the same argument at [`Writer::varint`], which inherited it from the
/// `varint::put` this module replaced.
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

    /// One RFC 9000 §16 variable-length integer, in the shortest form the
    /// encoding allows.
    ///
    /// O(1): at most eight bytes, and the buffer is extended in one `resize`.
    ///
    /// Values above 2^62 - 1 are outside the encoding entirely. No caller in
    /// this crate can produce one — every value is a stream id, a length
    /// bounded by a buffer, or a constant — so this is a debug assertion
    /// rather than a `Result` every call site would discharge with an
    /// `expect`.
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

    /// `value`, behind a one-byte length.
    pub(crate) fn vector_u8(&mut self, value: &[u8]) -> &mut Self {
        debug_assert!(value.len() <= usize::from(u8::MAX), "vector overruns u8");
        self.u8(value.len() as u8).bytes(value)
    }

    /// `value`, behind a two-byte network-order length.
    pub(crate) fn vector_u16(&mut self, value: &[u8]) -> &mut Self {
        debug_assert!(value.len() <= usize::from(u16::MAX), "vector overruns u16");
        self.u16(value.len() as u16).bytes(value)
    }

    /// `value`, behind a four-byte network-order length.
    pub(crate) fn vector_u32(&mut self, value: &[u8]) -> &mut Self {
        debug_assert!(
            u32::try_from(value.len()).is_ok(),
            "vector overruns u32: {}",
            value.len()
        );
        self.u32(value.len() as u32).bytes(value)
    }

    /// `value`, behind a varint length.
    pub(crate) fn vector_varint(&mut self, value: &[u8]) -> &mut Self {
        self.varint(value.len() as u64).bytes(value)
    }
}

/// An append-only cursor over a buffer that cannot grow.
///
/// The bounded counterpart of [`Writer`], for the one caller that writes into
/// a slice it was handed rather than a `Vec` it owns: the DNS responder, which
/// composes its answer directly into the datagram buffer the pool lent it.
/// Kept separate rather than folded into `Writer` because the difference is
/// exactly whether a write can fail, and unifying them would put a failure
/// path on the `Vec` side that cannot occur.
///
/// **The overflow is sticky.** Every method returns `&mut Self` so fields
/// chain, and a write that does not fit sets a flag, writes nothing, and
/// leaves the position where it was; [`Bounded::finish`] is where that becomes
/// a `None`. The alternative — a `?` on all fifteen field writes in
/// `dns::write_response` and the functions beneath it — is fifteen chances to
/// forget one, to reach the same answer.
pub(crate) struct Bounded<'a> {
    out: &'a mut [u8],
    at: usize,
    overflowed: bool,
}

impl<'a> Bounded<'a> {
    /// A cursor over `out`, positioned `at` bytes in.
    ///
    /// `None` for a starting offset past the end, which is how a caller
    /// threading a running cursor through several of these reports a buffer
    /// that ran out between them.
    pub(crate) fn at(out: &'a mut [u8], at: usize) -> Option<Self> {
        (at <= out.len()).then_some(Self {
            out,
            at,
            overflowed: false,
        })
    }

    /// Where the next write would land, or `None` if any write overflowed.
    ///
    /// Consuming, so a position can only be read once nothing more will be
    /// written through this cursor — which is what stops a partial write from
    /// being mistaken for a complete one.
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

    /// `count` zero bytes: a field group written as absent rather than left as
    /// whatever the buffer last held.
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

    /// `value`, behind a one-byte length.
    pub(crate) fn vector_u8(&mut self, value: &[u8]) -> &mut Self {
        debug_assert!(value.len() <= usize::from(u8::MAX), "vector overruns u8");
        self.u8(value.len() as u8).bytes(value)
    }
}

/// How many bytes [`Writer::varint`] spends on `value`.
///
/// Hysteria2 needs this *before* it writes: a UDP frame's payload budget is the
/// datagram ceiling minus its own header, and a header predicted one byte short
/// overflows the frame's last fragment. Delegated for the same reason the
/// encoder is — a second table of width boundaries is a second thing that can
/// disagree with the encoder, and this one would disagree silently.
pub(crate) fn varint_len(value: u64) -> usize {
    octets::varint_len(value)
}

/// The internet checksum of `parts` taken as one byte stream: the one's
/// complement of the one's complement sum of its 16-bit words, RFC 1071 §1.
///
/// **A sequence of parts rather than a slice**, because both callers that
/// matter checksum a pseudo-header they never assemble: RFC 793 and RFC 8200
/// §8.1 both define the sum over addresses, a protocol number, and a length
/// that exist in three different places. Concatenating them to sum them would
/// be a copy of the whole segment to produce a number.
///
/// A part of odd length carries its trailing byte into the next part, which is
/// what makes this the sum over the concatenation rather than the sum of the
/// sums. The final byte of an odd-length stream is padded with zero, as §1
/// requires.
///
/// O(total bytes), no allocation. The largest stream any caller passes is one
/// TCP segment during MSS clamping, which happens once per connection.
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

    /// Wire bytes in these tests are written as literals rather than through
    /// [`Writer`]. A test that builds its input with the code under test
    /// proves the two agree, not that either is right.
    #[test]
    fn every_accessor_is_total_on_a_short_buffer() {
        for length in 0..8 {
            let bytes = vec![0xff; length];
            let mut reader = Reader::new(&bytes);
            // Read the widest thing that does not fit, and check the cursor
            // did not move: a failed read must leave the parse where it was.
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

    /// Network order, at every width, from bytes written out by hand.
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

    /// The property the whole module exists for: what comes back *is* the
    /// caller's buffer, not a copy of it.
    #[test]
    fn a_read_borrows_rather_than_copies() {
        let bytes = [0x00, 0x03, b'a', b'b', b'c', b'd'];
        let mut reader = Reader::new(&bytes);
        let body = reader.vector_u16().expect("three bytes follow the prefix");
        assert!(std::ptr::eq(body.as_ptr(), bytes[2..].as_ptr()));
        assert_eq!(body, b"abc");
        assert_eq!(reader.rest(), b"d");
    }

    /// A vector whose prefix promises more than the buffer holds is refused,
    /// which is the shape every length-prefixed format here shares.
    #[test]
    fn a_vector_longer_than_its_buffer_is_refused() {
        assert_eq!(Reader::new(&[4, 1, 2]).vector_u8(), None);
        assert_eq!(Reader::new(&[0, 4, 1, 2]).vector_u16(), None);
        assert_eq!(Reader::new(&[0, 0]).vector_u16(), Some(&[][..]));
    }

    /// `at` is what a DNS compression pointer needs, including the rejection
    /// of one that points past the message.
    #[test]
    fn a_seek_lands_where_it_was_told_or_nowhere() {
        let bytes = [1, 2, 3, 4];
        assert_eq!(Reader::at(&bytes, 2).map(|r| r.rest()), Some(&[3, 4][..]));
        assert_eq!(Reader::at(&bytes, 4).map(|r| r.rest()), Some(&[][..]));
        assert!(Reader::at(&bytes, 5).is_none());
    }

    /// The width boundaries of the varint encoding, from both sides. A
    /// shortest-form violation is legal to decode under RFC 9000 but wrong to
    /// emit, and a peer that checks would reject us, so the emitted width is
    /// the property under test.
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
            // The constant this crate actually encodes, so a change to it
            // shows up here as a width change rather than on the wire.
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

    /// The law the streaming decoders depend on: nothing short of a complete
    /// encoding decodes, and anything longer leaves the excess untouched.
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

    /// Every prefix width, written and read back, against literal bodies.
    ///
    /// There is deliberately no `Reader::vector_varint`: the two protocols
    /// with varint-prefixed vectors both check the declared length against a
    /// protocol ceiling *before* taking that many bytes, so a combinator that
    /// did both at once would be one they could not use.
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

    /// The law the DNS responder leans on: once a write has overflowed, no
    /// later write lands and `finish` cannot report a position — so a partial
    /// answer can never be mistaken for a whole one.
    #[test]
    fn a_bounded_overflow_is_sticky() {
        let mut out = [0u8; 4];
        let mut writer = Bounded::at(&mut out, 0).expect("zero is inside any buffer");
        writer.u16(0x0102).u32(0x0304_0506).u8(0xff);
        assert_eq!(writer.finish(), None, "the u32 did not fit");
        assert_eq!(out, [0x01, 0x02, 0, 0], "nothing after the overflow landed");

        // And the exact fit succeeds, so the refusal above is about capacity
        // rather than about the writer refusing its last byte.
        let mut out = [0u8; 4];
        let mut writer = Bounded::at(&mut out, 0).expect("zero is inside any buffer");
        writer.u16(0x0102).u16(0x0304);
        assert_eq!(writer.finish(), Some(4));
        assert_eq!(out, [0x01, 0x02, 0x03, 0x04]);
    }

    /// A cursor placed past the end is `None` rather than a writer that
    /// refuses everything, which is what lets a caller threading one offset
    /// through several writers report the buffer running out between them.
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

    /// RFC 1071 §3's own worked example, byte for byte: the sum of
    /// `00 01 f2 03 f4 f5 f6 f7` is `dd f2`, so the checksum is its
    /// complement, `220d`.
    #[test]
    fn the_checksum_matches_rfc_1071s_worked_example() {
        assert_eq!(
            checksum(&[&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]]),
            0x220d
        );
    }

    /// The property that makes the pseudo-header callers correct: how the
    /// stream is divided cannot change its sum, including divisions that fall
    /// between the two halves of a word.
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

    /// A stream of odd length is padded with a zero byte, not with the byte
    /// that happens to follow it.
    #[test]
    fn an_odd_length_stream_pads_with_zero() {
        assert_eq!(checksum(&[&[0xab]]), checksum(&[&[0xab, 0x00]]));
        assert_eq!(checksum(&[]), u16::MAX);
    }
}
