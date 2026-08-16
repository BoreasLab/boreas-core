//! BOREAS: documented rather than exempted. This module is `cfg(fuzzing)`-gated
//! and upstream's `allow(missing_docs)` for it is gated on the unrelated
//! `unstable` feature, so the crate's own `deny(missing_docs)` stays live under
//! cargo-fuzz -- which a path dependency feels and a registry one does not,
//! being capped to `allow`. Satisfying the lint keeps it working: a future
//! undocumented item here still fails, where an exemption would hide it.

#[cfg(fuzzing)]
/// Entry points a fuzz target calls, over internals that are otherwise private
/// to the crate.
pub mod fuzz_logic {
    use crate::hpack;
    use bytes::BytesMut;
    use http::header::HeaderName;
    use std::io::Cursor;
    use std::ops::ControlFlow;

    /// Decodes `data_` as an HPACK block, then, when it also spells a valid
    /// method, round-trips that back through the encoder. Both results are
    /// discarded: what a fuzz target is looking for is the panic, not the
    /// value.
    pub fn fuzz_hpack(data_: &[u8]) {
        let mut decoder_ = hpack::Decoder::new(0);
        let mut buf = BytesMut::new();
        buf.extend(data_);
        let _dec_res = decoder_.decode(&mut Cursor::new(&mut buf), |_h| ControlFlow::Continue(()));

        if let Ok(s) = std::str::from_utf8(data_) {
            if let Ok(h) = http::Method::from_bytes(s.as_bytes()) {
                let m_ = hpack::Header::Method(h);
                let mut encoder = hpack::Encoder::new(0, 0);
                let _res = encode(&mut encoder, vec![m_]);
            }
        }
    }

    fn encode(e: &mut hpack::Encoder, hdrs: Vec<hpack::Header<Option<HeaderName>>>) -> BytesMut {
        let mut dst = BytesMut::with_capacity(1024);
        e.encode(&mut hdrs.into_iter(), &mut dst);
        dst
    }
}
