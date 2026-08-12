//! Resolves one name through each transport against a live resolver.
//!
//! Evidence rather than assertion: the unit tests exercise the framing, the
//! bounds, and the refusals against in-memory streams, and nothing in them
//! proves that a real resolver accepts what this crate sends. This does, and
//! it is an example rather than a test because it needs the network and would
//! otherwise make `cargo test` depend on somebody else's uptime.
//!
//! Run it with `cargo run --release --example resolve -- [name]`.

use std::{net::SocketAddr, time::Instant};

use boreas_core::{
    DOT_PORT, DirectSockets, DnsUpstream, Do53Upstream, DohUpstream, DotUpstream, Message,
    RecordType, ResourceRecord,
};

/// Cloudflare's public resolver: one address, three transports, so the only
/// variable between the runs below is the transport itself.
const RESOLVER: [u8; 4] = [1, 1, 1, 1];
const CERTIFICATE_NAME: &str = "one.one.one.one";
const DOH_URL: &str = "https://one.one.one.one/dns-query";

fn query(name: &str, qtype: RecordType) -> Vec<u8> {
    let mut out = 0x2b1au16.to_be_bytes().to_vec();
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // recursion desired
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[0; 6]);
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_wire().to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out
}

fn report(label: &str, name: &str, reply: std::io::Result<Vec<u8>>, elapsed: std::time::Duration) {
    let bytes = match reply {
        Ok(bytes) => bytes,
        Err(error) => {
            println!("  {label:<5} FAILED in {elapsed:>8.2?}: {error}");
            return;
        }
    };
    let Ok(message) = Message::parse(&bytes) else {
        println!("  {label:<5} unparseable reply of {} bytes", bytes.len());
        return;
    };
    let answers: Vec<ResourceRecord<'_>> = message.answers().filter_map(Result::ok).collect();
    let summary: Vec<String> = answers
        .iter()
        .map(|record| match record.rtype {
            RecordType::A => record
                .rdata
                .first_chunk::<4>()
                .map_or_else(|| "A?".into(), |o| std::net::Ipv4Addr::from(*o).to_string()),
            other => format!("{other:?}"),
        })
        .collect();
    println!(
        "  {label:<5} {:>8.2?}  {:?}  {} answers for {name}: {}",
        elapsed,
        message.rcode(),
        answers.len(),
        summary.join(", ")
    );
}

#[tokio::main]
async fn main() {
    let name = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "example.com".into());
    let message = query(&name, RecordType::A);
    let bypass = || DirectSockets;

    println!("resolving {name} through each transport against {CERTIFICATE_NAME}");

    let do53 = Do53Upstream::new(SocketAddr::from((RESOLVER, 53)), bypass());
    let started = Instant::now();
    report("Do53", &name, do53.query(&message).await, started.elapsed());

    let dot = DotUpstream::new(
        SocketAddr::from((RESOLVER, DOT_PORT)),
        CERTIFICATE_NAME,
        bypass(),
    )
    .expect("a valid server name");
    for round in 0..2 {
        let started = Instant::now();
        let label = if round == 0 { "DoT" } else { "DoT'" };
        report(label, &name, dot.query(&message).await, started.elapsed());
    }

    let doh = DohUpstream::new(DOH_URL, SocketAddr::from((RESOLVER, 443)), bypass())
        .expect("a valid URL");
    for round in 0..2 {
        let started = Instant::now();
        let label = if round == 0 { "DoH" } else { "DoH'" };
        report(label, &name, doh.query(&message).await, started.elapsed());
    }

    // The primed rows are the point: one configuration per upstream holds the
    // rustls session cache, so the second query to the same resolver resumes
    // rather than handshaking again.
    println!("  (primed rows resume the TLS session established by the first)");
}
