//! RFC 9000 §16 variable-length integers, which three protocols in this crate
//! share: MASQUE's Quarter Stream ID and datagram context, Hysteria2's frame
//! headers, and QUIC itself underneath both.
//!
//! **`octets` rather than a hand-rolled pair.** The crate is `quiche`'s own
//! buffer reader, so it is already in the dependency graph and already carries
//! whatever `quiche` has learned about this encoding; writing a second
//! implementation would mean a second thing to get wrong for no saved bytes.
//! What is added here is the two shapes this crate actually wants and `octets`
//! does not offer: appending to a `Vec` that grows, and reporting a truncated
//! encoding as *incomplete* rather than as an error.
//!
//! **Incompleteness is not failure.** Every decoder in this crate reads from a
//! stream that may deliver a header in pieces, so [`get`] answers `None` for a
//! proper prefix — the same signal
//! [`Decoded::Incomplete`](crate::socks5::Decoded) carries one level up. A
//! caller that treats `None` as a protocol error would reject valid traffic
//! that merely arrived slowly.

/// The largest value the encoding can represent: two bits of every encoding
/// select its width, leaving 62.
pub(crate) const MAX: u64 = (1 << 62) - 1;

/// Appends `value` in the shortest form RFC 9000 allows.
///
/// O(1): at most eight bytes, and the `Vec` is extended in one `resize`.
///
/// Values above [`MAX`] are outside the encoding entirely. No caller in this
/// crate can produce one — every value is a stream id, a length bounded by a
/// buffer, or a constant — so this is a debug assertion rather than a `Result`
/// that every call site would have to discharge with an `expect`.
pub(crate) fn put(value: u64, out: &mut Vec<u8>) {
    debug_assert!(value <= MAX, "{value} does not fit in a 62-bit varint");
    let start = out.len();
    out.resize(start + octets::varint_len(value), 0);
    octets::OctetsMut::with_slice(&mut out[start..])
        .put_varint(value)
        .expect("the buffer was sized by varint_len");
}

/// Decodes one varint, returning it and the bytes that follow it.
///
/// `None` means `bytes` holds a proper prefix of an encoding and the caller
/// should read more — never that the input is invalid, because every byte
/// sequence long enough is a valid varint.
///
/// O(1), and it copies nothing: the tail is a subslice of the input.
pub(crate) fn get(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let mut reader = octets::Octets::with_slice(bytes);
    let value = reader.get_varint().ok()?;
    Some((value, &bytes[reader.off()..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The width boundaries, from both sides. A shortest-form violation is
    /// legal to *decode* under RFC 9000 but wrong to *emit*, and a peer that
    /// checks would reject us, so the emitted width is the property under test.
    #[test]
    fn each_value_uses_the_shortest_form_that_holds_it() {
        for (value, width) in [
            (0u64, 1usize),
            (63, 1),
            (64, 2),
            (16_383, 2),
            (16_384, 4),
            (1_073_741_823, 4),
            (1_073_741_824, 8),
            (MAX, 8),
            // The two constants this crate actually encodes, so a change to
            // either shows up here as a width change rather than on the wire.
            (0x401, 2),
        ] {
            let mut encoded = Vec::new();
            put(value, &mut encoded);
            assert_eq!(encoded.len(), width, "{value} encoded to {encoded:?}");
            assert_eq!(get(&encoded), Some((value, &[][..])));
        }
    }

    /// The law the streaming decoders depend on: nothing short of a complete
    /// encoding decodes, and anything longer leaves the excess untouched.
    #[test]
    fn every_proper_prefix_is_incomplete_and_the_tail_is_preserved() {
        for value in [0u64, 63, 64, 16_384, 1_073_741_824, MAX] {
            let mut encoded = Vec::new();
            put(value, &mut encoded);
            for cut in 0..encoded.len() {
                assert_eq!(get(&encoded[..cut]), None, "{value} decoded from a prefix");
            }
            encoded.extend_from_slice(b"tail");
            assert_eq!(get(&encoded), Some((value, &b"tail"[..])));
        }
    }
}
