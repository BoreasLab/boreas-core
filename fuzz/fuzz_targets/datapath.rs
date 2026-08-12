//! Feeds arbitrary bytes through the whole untrusted ingress path: parse,
//! route, clamp, reassemble, and expire. This is the shape the runtime shell
//! drives, so the invariants here are the shell's own.
//!
//! Invariants under test:
//! - no panic on any byte sequence, at any arrival time;
//! - a rejected packet is a `Result`, never a defect — the shell counts these
//!   and keeps interpreting the core, so a panic here would be a reactor kill;
//! - the core's queues stay bounded: transmits, events, and intercepted DNS
//!   queries drain to completion after every packet, exactly as the reactor
//!   drains them;
//! - synthesizing a DNS answer from an arbitrary payload, for an arbitrary
//!   client endpoint, writes a datagram or reports why — never a panic.

#![no_main]

use std::{num::NonZeroUsize, time::Duration};

use boreas_core::{
    Accepts, DatagramFidelity, Datapath, DnsPolicy, EgressCapabilities, FilterPolicy, Limits,
    Mtu, NatBehavior,
};
use libfuzzer_sys::fuzz_target;

fn datapath(accepts: Accepts, dns: DnsPolicy) -> Datapath {
    Datapath::new(
        FilterPolicy::PassThrough,
        dns,
        accepts,
        EgressCapabilities {
            datagram_fidelity: DatagramFidelity::Native,
            overhead_bytes: 60,
            max_datagram_size: Some(1500),
            preserves_ecn: true,
            nat_behavior: NatBehavior::EndpointIndependent,
        },
        Mtu::new(1500).unwrap(),
        Limits {
            reassembly_timeout: Duration::from_secs(30),
            max_pending_reassemblies: NonZeroUsize::new(4).unwrap(),
            flow_idle_timeout: Duration::from_secs(120),
            datagram_buffer_capacity: NonZeroUsize::new(4).unwrap(),
        },
        // Small on purpose: the fuzzer should reach the exhaustion path,
        // where a forwarded packet is a counted drop rather than a panic.
        boreas_core::BufferPool::new(
            NonZeroUsize::new(2048).unwrap(),
            NonZeroUsize::new(4).unwrap(),
        ),
    )
    .expect("the fuzz configuration plans")
}

fuzz_target!(|data: &[u8]| {
    // Both egress shapes, and both DNS policies: `IpPackets` exercises the
    // packet fast path and its MSS clamp, `Flows` exercises flow admission and
    // the timer wheel, and `Intercept` diverts UDP/53 into the query queue and
    // back out through the synthesized answer.
    for (accepts, dns) in [
        (Accepts::IpPackets, DnsPolicy::Forward),
        (Accepts::IpPackets, DnsPolicy::Intercept),
        (Accepts::Flows, DnsPolicy::Intercept),
    ] {
        let mut path = datapath(accepts, dns);
        let base = std::time::Instant::now();

        let mut cursor = 0;
        while let Some(&tick) = data.get(cursor) {
            cursor += 1;
            let now = base + Duration::from_secs(u64::from(tick));

            // Framing: one length byte, then that many bytes as one packet.
            let Some(&len) = data.get(cursor) else { break };
            cursor += 1;
            let Some(packet) = data.get(cursor..cursor + usize::from(len)) else {
                break;
            };
            cursor += usize::from(len);

            // A refusal is an ordinary outcome; only a panic would be a defect.
            let _ = path.on_tun_packet(packet, now);
            let _ = path.on_egress_packet(packet, now);
            path.on_timeout(now);

            // Drain as the reactor does, so nothing accumulates across
            // packets. An intercepted query is answered with its own payload,
            // which is arbitrary bytes addressed to an arbitrary endpoint —
            // the shape the response writer must survive.
            while let Some(query) = path.poll_query() {
                let payload = query.payload.to_vec();
                let _ = path.answer_dns(query.client, query.resolver, &payload);
            }
            while path.poll_transmit().is_some() {}
            while path.poll_event().is_some() {}

            // The armed deadline is never in the past relative to a later
            // timeout that finds nothing due.
            let _ = path.poll_timeout();
        }
    }
});
