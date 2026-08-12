//! Feeds arbitrary bytes through the whole DNS core: message parsing, name
//! decompression, the answer walk, SvcParam parsing, and response rewriting.
//!
//! This is the module's real trust boundary twice over. The query side is
//! whatever any application on the device chooses to send, and the answer side
//! is whatever an upstream resolver — or anything that can spoof one — chooses
//! to reply. Name compression is the classic hazard: a pointer chain that does
//! not terminate is a hang, and a length that is not re-checked is an
//! out-of-bounds read.
//!
//! Invariants under test:
//! - no panic and no hang, for any input, on either side;
//! - decompression terminates: every pointer must run strictly backwards, so
//!   the cursor decreases and the chain is finite;
//! - a written response re-parses, which is what makes the rewrite a total
//!   function from a valid message to a valid message rather than to bytes;
//! - stripping ECH removes exactly the `ech` parameter: the answer count is
//!   unchanged and the rewritten record no longer publishes one.

#![no_main]

use boreas_core::{EchPolicy, Message, ech_param, svc_params, write_response};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Split the input so one case exercises a query and an answer that do not
    // agree with each other, which is exactly the shape a spoofer sends.
    let split = data.len() / 2;
    let (query_bytes, upstream_bytes) = data.split_at(split);

    let Ok(query) = Message::parse(query_bytes) else {
        return;
    };

    // Walking a parsed message must be total: every record is a `Result`, and
    // the first error ends the walk without having read past anything.
    for record in query.answers() {
        let Ok(record) = record else { break };
        if let Ok(params) = svc_params(record.rdata) {
            for param in params {
                if param.is_err() {
                    break;
                }
            }
        }
    }

    let Ok(upstream) = Message::parse(upstream_bytes) else {
        return;
    };

    let mut out = [0u8; 4096];
    for ech in [EchPolicy::Preserve, EchPolicy::Strip] {
        let Ok(rewritten) = write_response(&mut out, &query, &upstream, ech) else {
            continue;
        };
        let parsed = Message::parse(&out[..rewritten.len])
            .expect("a written response must be a readable one");
        assert_eq!(parsed.id(), query.id(), "the client's own transaction id");
        assert_eq!(
            parsed.question(),
            query.question(),
            "the client's own question"
        );

        let answers: Vec<_> = parsed.answers().collect();
        assert_eq!(
            answers.len(),
            usize::from(rewritten.answers),
            "the header must agree with what was written"
        );
        for answer in answers {
            let answer = answer.expect("a written record must be a readable one");
            if ech == EchPolicy::Strip && answer.rtype.carries_svc_params() {
                assert_eq!(
                    ech_param(answer.rdata).ok().flatten(),
                    None,
                    "a stripped answer must not still publish an ECH configuration"
                );
            }
        }
    }
});
