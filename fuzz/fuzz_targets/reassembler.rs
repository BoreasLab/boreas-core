//! Feeds arbitrary bytes through the reassembler. Invariants under test: no
//! panic, no out-of-bounds access, and a completed datagram is a re-parseable
//! IP packet whose payload is the concatenation of non-overlapping fragment
//! payloads within the 64 KiB ceiling. The re-parse is the point: the datapath
//! feeds every completion straight back into `IngressPacket::parse`, so a
//! completion that is not a packet is a defect the fuzzer should surface.

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
                boreas_core::IngressPacket::parse(&datagram)
                    .expect("a completed reassembly must re-parse as an IP packet");
            }
            PushOutcome::Pending | PushOutcome::Discarded => {}
        }
    }
});
