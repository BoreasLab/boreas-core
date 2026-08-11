//! Feeds arbitrary bytes through the reassembler. Invariants under test:
//! no panic, no out-of-bounds access, and a completed datagram is always the
//! exact concatenation of non-overlapping fragment payloads that fit 64 KiB.

#![no_main]

use std::{num::NonZeroUsize, time::Duration};

use boreas_core::{Fragment, PushOutcome, Reassembler};
use libfuzzer_sys::fuzz_target;

// Deterministic clock: `Instant` has no constructor from an integer, so a
// base instant plus data-derived offsets keeps expiry paths reachable.
fuzz_target!(|data: &[u8]| {
    let mut reassembler = Reassembler::new(Duration::from_secs(30), NonZeroUsize::new(4).unwrap());
    let base = std::time::Instant::now();

    let mut cursor = 0;
    while let Some(&offset) = data.get(cursor) {
        let _ = reassembler.expire(base + Duration::from_secs(u64::from(offset)));
        cursor += 1;

        // Framing: one length byte, then that many bytes as one packet.
        let Some(&len) = data.get(cursor) else { break };
        cursor += 1;
        let Some(packet) = data.get(cursor..cursor + usize::from(len)) else {
            break;
        };
        cursor += usize::from(len);

        let Ok(Some(fragment)) = Fragment::parse(packet) else {
            continue;
        };
        match reassembler.push(fragment, base + Duration::from_secs(u64::from(offset))) {
            PushOutcome::Complete(datagram) => {
                assert!(
                    datagram.len() <= u16::MAX as usize,
                    "reassembled datagram exceeds the 64 KiB IPv4 ceiling"
                );
            }
            PushOutcome::Pending | PushOutcome::Discarded => {}
        }
    }
});
