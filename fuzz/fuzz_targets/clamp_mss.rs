//! Feeds arbitrary bytes through the SYN MSS clamp. This is the trust boundary
//! a crafted TCP option list attacks: the option region is attacker-chosen TLV
//! data, and the clamp must read it without ever leaving the header the data
//! offset declares.
//!
//! Invariants under test:
//! - no panic and no out-of-bounds access, for any input;
//! - clamping is length-preserving — it rewrites two bytes and a checksum, so
//!   it can never resize the packet;
//! - declining is total — a refused packet is returned byte-identical, which
//!   is what lets the datapath forward it unharmed.

#![no_main]

use boreas_core::{Mtu, clamp_mss};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The floor, a typical tunnel budget, and the ceiling: the clamp value is
    // derived from the MTU, so the interesting edges are at both ends.
    for mtu in [1280u16, 1500, u16::MAX] {
        let Ok(inner_mtu) = Mtu::new(mtu) else {
            continue;
        };

        let mut packet = data.to_vec();
        let before = packet.clone();
        let clamped = clamp_mss(&mut packet, inner_mtu);

        assert_eq!(
            packet.len(),
            before.len(),
            "the clamp rewrites in place and must never resize"
        );
        if !clamped {
            assert_eq!(packet, before, "a declined packet must pass unmodified");
        }
    }
});
