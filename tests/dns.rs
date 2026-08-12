//! The P11 gate, driven through the whole shell: a client's UDP/53 query
//! enters the device, the core intercepts it, the resolver applies host policy
//! and ECH policy, and the answer comes back addressed from the resolver the
//! client asked.
//!
//! Two properties close the phase:
//!
//! 1. answers for A, AAAA, HTTPS, and SVCB carry provenance sufficient to
//!    explain a verdict — which rule matched, which transport answered, and
//!    what happened to ECH;
//! 2. ECH is not disabled globally when host policy suffices: an inspected
//!    host loses its ECH configuration and an allowed host, in the same
//!    session, on the same run, keeps it.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use boreas_core::{
    Accepts, AsyncDevice, AsyncNetwork, BufferPool, DNS_PORT, DatagramFidelity, Datapath,
    DnsPolicy, DnsUpstream, EchOutcome, EgressCapabilities, EgressEmit, EgressError, FilterPolicy,
    HostPolicy, IngressPacket, InternalEndpoint, Message, Mtu, NatBehavior, PacketEgress,
    Provenance, Rcode, RecordType, ResourceRecord, SVCPARAM_ALPN, SVCPARAM_ECH, Session, Shell,
    Telemetry, Transport, Upstream, ech_param, svc_params, write_udp,
};

const CLIENT: InternalEndpoint = InternalEndpoint {
    address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
    port: 40_000,
};
const RESOLVER: InternalEndpoint = InternalEndpoint {
    address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
    port: DNS_PORT,
};
const ECH_CONFIG: &[u8] = b"\xfe\x0d\x00\x3a fake ech configuration bytes ...";

// ---------------------------------------------------------------- DNS wire --

fn wire_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

fn query(id: u16, name: &str, qtype: RecordType) -> Vec<u8> {
    let mut out = id.to_be_bytes().to_vec();
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // recursion desired
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[0; 6]);
    out.extend_from_slice(&wire_name(name));
    out.extend_from_slice(&qtype.to_wire().to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out
}

/// An upstream reply to `request`, echoing its question and appending answers.
fn reply(request: &[u8], answers: &[(&str, RecordType, Vec<u8>)]) -> Vec<u8> {
    let mut out = request.to_vec();
    out[2..4].copy_from_slice(&0x8180u16.to_be_bytes()); // response, RD, RA
    out[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
    for (owner, rtype, rdata) in answers {
        out.extend_from_slice(&wire_name(owner));
        out.extend_from_slice(&rtype.to_wire().to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&300u32.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
    }
    out
}

fn https_rdata(target: &str, ech: bool) -> Vec<u8> {
    let mut out = 1u16.to_be_bytes().to_vec();
    out.extend_from_slice(&wire_name(target));
    out.extend_from_slice(&SVCPARAM_ALPN.to_be_bytes());
    out.extend_from_slice(&3u16.to_be_bytes());
    out.extend_from_slice(b"\x02h2");
    if ech {
        out.extend_from_slice(&SVCPARAM_ECH.to_be_bytes());
        out.extend_from_slice(&(ECH_CONFIG.len() as u16).to_be_bytes());
        out.extend_from_slice(ECH_CONFIG);
    }
    out
}

// -------------------------------------------------------------------- seams --

struct MockDevice {
    inbound: tokio::sync::mpsc::Receiver<Vec<u8>>,
    sent: tokio::sync::mpsc::Sender<Vec<u8>>,
}

impl AsyncDevice for MockDevice {
    #[allow(clippy::manual_async_fn)]
    fn recv<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = std::io::Result<usize>> + Send + 'a {
        async move {
            match self.inbound.recv().await {
                Some(packet) if packet.len() <= buf.len() => {
                    buf[..packet.len()].copy_from_slice(&packet);
                    Ok(packet.len())
                }
                Some(_) => Err(std::io::Error::other("oversized")),
                None => std::future::pending().await,
            }
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn send<'a>(
        &'a mut self,
        buf: &'a [u8],
    ) -> impl Future<Output = std::io::Result<usize>> + Send + 'a {
        async move {
            let _ = self.sent.send(buf.to_vec()).await;
            Ok(buf.len())
        }
    }
}

/// A network seam nothing arrives on: this session's traffic is DNS, which
/// never reaches the egress.
struct SilentNetwork;

impl AsyncNetwork for SilentNetwork {
    #[allow(clippy::manual_async_fn)]
    fn recv<'a>(
        &'a mut self,
        _buf: &'a mut [u8],
    ) -> impl Future<Output = std::io::Result<usize>> + Send + 'a {
        async { std::future::pending().await }
    }

    #[allow(clippy::manual_async_fn)]
    fn send<'a>(
        &'a mut self,
        buf: &'a [u8],
    ) -> impl Future<Output = std::io::Result<usize>> + Send + 'a {
        async move { Ok(buf.len()) }
    }
}

struct NullEgress;

impl PacketEgress for NullEgress {
    fn capabilities(&self) -> EgressCapabilities {
        capabilities()
    }

    fn handle_tun_packet(
        &mut self,
        _packet: &[u8],
        _out: &mut Vec<EgressEmit>,
    ) -> Result<(), EgressError> {
        Ok(())
    }

    fn handle_network_packet(
        &mut self,
        _datagram: &[u8],
        _out: &mut Vec<EgressEmit>,
    ) -> Result<(), EgressError> {
        Ok(())
    }

    fn tick(&mut self, _out: &mut Vec<EgressEmit>) -> Result<(), EgressError> {
        Ok(())
    }

    fn tick_interval(&self) -> Duration {
        Duration::from_secs(3600)
    }
}

/// An upstream that answers from a script and counts every time it is asked.
/// The count is what proves a blocked name never leaves the device.
struct ScriptedUpstream {
    consulted: Arc<AtomicU64>,
}

impl DnsUpstream for ScriptedUpstream {
    fn kind(&self) -> Upstream {
        Upstream::DoH
    }

    #[allow(clippy::manual_async_fn)]
    fn query(&self, message: &[u8]) -> impl Future<Output = std::io::Result<Vec<u8>>> + Send {
        self.consulted.fetch_add(1, Ordering::Relaxed);
        let request = message.to_vec();
        async move {
            let parsed = Message::parse(&request).expect("a well-formed query");
            let name = parsed.question().name.to_string();
            // The owner name is the queried name, which is what an authority
            // answers with and what makes the rewrite path realistic.
            let answers: Vec<(&str, RecordType, Vec<u8>)> = match parsed.question().qtype {
                RecordType::Https => vec![(
                    name.as_str(),
                    RecordType::Https,
                    https_rdata("target.example", true),
                )],
                RecordType::A => vec![(name.as_str(), RecordType::A, vec![203, 0, 113, 7])],
                RecordType::Aaaa => vec![(name.as_str(), RecordType::Aaaa, vec![0x20; 16])],
                _ => Vec::new(),
            };
            Ok(reply(&request, &answers))
        }
    }
}

// ------------------------------------------------------------------ harness --

fn capabilities() -> EgressCapabilities {
    EgressCapabilities {
        datagram_fidelity: DatagramFidelity::Native,
        overhead_bytes: 80,
        max_datagram_size: Some(1400),
        preserves_ecn: false,
        nat_behavior: NatBehavior::EndpointIndependent,
    }
}

fn pool() -> Arc<BufferPool> {
    BufferPool::new(
        NonZeroUsize::new(2048).unwrap(),
        NonZeroUsize::new(64).unwrap(),
    )
}

fn datapath(pool: Arc<BufferPool>) -> Datapath {
    Datapath::new(
        FilterPolicy::PassThrough,
        DnsPolicy::Intercept,
        Accepts::IpPackets,
        capabilities(),
        Mtu::new(1500).unwrap(),
        boreas_core::Limits {
            reassembly_timeout: Duration::from_secs(30),
            max_pending_reassemblies: NonZeroUsize::new(8).unwrap(),
            flow_idle_timeout: Duration::from_secs(120),
            datagram_buffer_capacity: NonZeroUsize::new(8).unwrap(),
        },
        pool,
    )
    .unwrap()
}

fn dns_packet(message: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 2048];
    let len = write_udp(&mut out, CLIENT, RESOLVER, message).expect("a client query fits");
    out.truncate(len);
    out
}

/// Unwraps one datagram the shell sent to the device back into its DNS
/// message, checking it is addressed the way a stub resolver requires.
fn dns_answer(packet: &[u8]) -> Vec<u8> {
    let parsed = IngressPacket::parse(packet).expect("a well-formed datagram");
    assert_eq!(
        parsed.source, RESOLVER.address,
        "answered from the resolver"
    );
    assert_eq!(parsed.destination, CLIENT.address);
    assert_eq!(
        parsed.transport,
        Transport::Udp {
            source_port: RESOLVER.port,
            destination_port: CLIENT.port,
        },
        "a stub resolver discards a reply from anywhere else"
    );
    parsed.payload(packet).expect("its own bytes").to_vec()
}

// -------------------------------------------------------------------- tests --

#[tokio::test]
async fn host_policy_decides_dns_and_every_verdict_explains_itself() {
    let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(16);
    let (sent_tx, mut sent_rx) = tokio::sync::mpsc::channel(16);
    let consulted = Arc::new(AtomicU64::new(0));

    let mut policy = HostPolicy::new();
    assert!(policy.block("tracker.example"));
    assert!(policy.inspect("shop.example"));

    let pool = pool();
    let mut shell = Shell::start(
        datapath(Arc::clone(&pool)),
        Session {
            device: MockDevice {
                inbound: inbound_rx,
                sent: sent_tx,
            },
            network: SilentNetwork,
            egress: NullEgress,
            upstream: ScriptedUpstream {
                consulted: Arc::clone(&consulted),
            },
            policy: Arc::new(policy),
        },
    );

    // Three queries in one session: a blocked name, an inspected one, and an
    // allowed one. The third is the control for the ECH property — if ECH were
    // a session switch rather than a host rule, it would move with the second.
    let script = [
        (0x0001u16, "ads.tracker.example", RecordType::A),
        (0x0002, "www.shop.example", RecordType::Https),
        (0x0003, "www.other.example", RecordType::Https),
        (0x0004, "www.other.example", RecordType::Aaaa),
    ];
    for (id, name, qtype) in script {
        inbound_tx
            .send(dns_packet(&query(id, name, qtype)))
            .await
            .unwrap();
    }

    let mut answers = Vec::new();
    for _ in 0..script.len() {
        let packet = tokio::time::timeout(Duration::from_secs(5), sent_rx.recv())
            .await
            .expect("the shell answered")
            .expect("device channel open");
        let message = dns_answer(&packet);
        let parsed = Message::parse(&message).expect("a well-formed answer");
        answers.push((
            parsed.id(),
            parsed.rcode(),
            parsed
                .answers()
                .collect::<Result<Vec<ResourceRecord<'_>>, _>>()
                .expect("well-formed answers")
                .into_iter()
                .map(|record| (record.rtype, record.rdata.to_vec()))
                .collect::<Vec<_>>(),
        ));
    }
    answers.sort_by_key(|(id, ..)| *id);

    // 1. The blocked name is refused locally, and nothing left the device for
    //    it: three queries reached the upstream, not four.
    assert_eq!(answers[0].0, 0x0001);
    assert_eq!(answers[0].1, Rcode::NameError);
    assert!(answers[0].2.is_empty());
    assert_eq!(consulted.load(Ordering::Relaxed), 3);

    // 2. The inspected host's HTTPS answer lost exactly its ECH parameter.
    let (_, rcode, records) = &answers[1];
    assert_eq!(*rcode, Rcode::NoError);
    assert_eq!(records[0].0, RecordType::Https);
    assert_eq!(ech_param(&records[0].1).unwrap(), None, "ECH was stripped");
    let keys: Vec<u16> = svc_params(&records[0].1)
        .unwrap()
        .map(|param| param.unwrap().key)
        .collect();
    assert_eq!(keys, vec![SVCPARAM_ALPN], "only ECH was removed");

    // 3. The allowed host, in the same session and the same run, keeps its ECH
    //    configuration. This is the gate: policy is per host, never global.
    let (_, _, records) = &answers[2];
    assert_eq!(records[0].0, RecordType::Https);
    assert!(
        ech_param(&records[0].1).unwrap().is_some(),
        "an allowed host must not pay for an inspected one"
    );

    // 4. AAAA answers cross unchanged; only SVCB-shaped records are touched.
    let (_, _, records) = &answers[3];
    assert_eq!(records[0].0, RecordType::Aaaa);
    assert_eq!(records[0].1.len(), 16);

    // 5. Every verdict is explainable after the fact: the rule that matched,
    //    the transport that answered, and what happened to ECH.
    let mut reports = Vec::new();
    while reports.len() < script.len() {
        match tokio::time::timeout(Duration::from_secs(5), shell.next_telemetry())
            .await
            .expect("telemetry flowed")
            .expect("telemetry open")
        {
            Telemetry::Resolved(resolution) => reports.push(*resolution),
            _ => continue,
        }
    }
    reports.sort_by_key(|report| (report.name.to_string(), report.qtype.to_wire()));

    let blocked = &reports[0];
    assert_eq!(blocked.name.to_string(), "ads.tracker.example");
    assert_eq!(blocked.provenance, Provenance::Policy);
    assert_eq!(
        blocked.rule.map(|rule| rule.to_string()).as_deref(),
        Some("tracker.example"),
        "a verdict that cannot name its rule cannot be argued with"
    );
    assert_eq!(blocked.rcode, Rcode::NameError);

    let inspected = reports
        .iter()
        .find(|report| report.name.to_string() == "www.shop.example")
        .expect("the inspected host reported");
    assert_eq!(inspected.provenance, Provenance::Upstream(Upstream::DoH));
    assert_eq!(inspected.ech, EchOutcome::Stripped { count: 1 });
    assert_eq!(inspected.answers, 1);

    let allowed = reports
        .iter()
        .find(|report| {
            report.name.to_string() == "www.other.example" && report.qtype == RecordType::Https
        })
        .expect("the allowed host reported");
    assert_eq!(allowed.ech, EchOutcome::Preserved);
    assert_eq!(allowed.rule, None);

    let aaaa = reports
        .iter()
        .find(|report| report.qtype == RecordType::Aaaa)
        .expect("the AAAA query reported");
    assert_eq!(aaaa.ech, EchOutcome::Absent, "no SVCB record, no ECH");

    shell.shutdown().await.expect("clean shutdown");
    // Every pooled buffer the queries and answers borrowed has come back.
    assert_eq!(pool.available(), 64);
}

#[tokio::test]
async fn a_forwarding_session_never_intercepts() {
    // The other half of the policy: with `DnsPolicy::Forward` the same packet
    // is ordinary traffic. It reaches the egress and produces no query, so the
    // upstream is never asked and no answer is synthesized.
    let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(16);
    let (sent_tx, mut sent_rx) = tokio::sync::mpsc::channel(16);
    let consulted = Arc::new(AtomicU64::new(0));
    let pool = pool();

    let forwarding = Datapath::new(
        FilterPolicy::PassThrough,
        DnsPolicy::Forward,
        Accepts::IpPackets,
        capabilities(),
        Mtu::new(1500).unwrap(),
        boreas_core::Limits {
            reassembly_timeout: Duration::from_secs(30),
            max_pending_reassemblies: NonZeroUsize::new(8).unwrap(),
            flow_idle_timeout: Duration::from_secs(120),
            datagram_buffer_capacity: NonZeroUsize::new(8).unwrap(),
        },
        Arc::clone(&pool),
    )
    .unwrap();

    let shell = Shell::start(
        forwarding,
        Session {
            device: MockDevice {
                inbound: inbound_rx,
                sent: sent_tx,
            },
            network: SilentNetwork,
            egress: NullEgress,
            upstream: ScriptedUpstream {
                consulted: Arc::clone(&consulted),
            },
            policy: Arc::new(HostPolicy::new()),
        },
    );

    inbound_tx
        .send(dns_packet(&query(9, "ads.tracker.example", RecordType::A)))
        .await
        .unwrap();
    // Nothing comes back down the device: the packet went outward.
    assert!(
        tokio::time::timeout(Duration::from_millis(200), sent_rx.recv())
            .await
            .is_err()
    );
    assert_eq!(consulted.load(Ordering::Relaxed), 0);

    shell.shutdown().await.expect("clean shutdown");
    assert_eq!(pool.available(), 64);
}

/// Resolver addresses are ordinary `SocketAddr`s; this only pins that the
/// constructor is usable without a running upstream.
#[test]
fn a_do53_upstream_names_its_transport() {
    let upstream = boreas_core::Do53Upstream::new(
        SocketAddr::from(([9, 9, 9, 9], 53)),
        boreas_core::DirectSockets,
    );
    assert_eq!(upstream.kind(), Upstream::Do53);
}
