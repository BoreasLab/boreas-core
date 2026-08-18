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
    Accepts, AlpnOutcome, AsyncDevice, AsyncNetwork, BufferPool, DNS_PORT, DatagramFidelity,
    Datapath, DnsPolicy, DnsUpstream, EchOutcome, EgressEmit, EgressError, FilterPolicy,
    HTTPS_PORT, HostPolicy, IngressPacket, InternalEndpoint, Message, Mtu, NatBehavior,
    PacketEgress, PathProperties, Provenance, Rcode, RecordType, ResourceRecord, RuleCounts,
    SVCPARAM_ALPN, SVCPARAM_ECH, Session, Shell, Telemetry, Transport, Upstream, ech_param,
    h3_alpn_param, svc_params, write_udp,
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
    // The shape a real HTTPS record has today: h3 first, then h2.
    out.extend_from_slice(&SVCPARAM_ALPN.to_be_bytes());
    out.extend_from_slice(&6u16.to_be_bytes());
    out.extend_from_slice(b"\x02h3\x02h2");
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
    fn mtu(&self) -> Mtu {
        Mtu::new(1500).unwrap()
    }

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
    ) -> impl Future<Output = std::io::Result<()>> + Send + 'a {
        async move {
            let _ = self.sent.send(buf.to_vec()).await;
            Ok(())
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
        _buf: &'a [u8],
    ) -> impl Future<Output = std::io::Result<()>> + Send + 'a {
        async move { Ok(()) }
    }
}

struct NullEgress;

impl PacketEgress for NullEgress {
    fn properties(&self) -> PathProperties {
        properties()
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
                RecordType::Svcb => vec![(
                    name.as_str(),
                    RecordType::Svcb,
                    https_rdata("target.example", true),
                )],
                RecordType::Aaaa => vec![(name.as_str(), RecordType::Aaaa, vec![0x20; 16])],
                _ => Vec::new(),
            };
            Ok(reply(&request, &answers))
        }
    }
}

// ------------------------------------------------------------------ harness --

fn properties() -> PathProperties {
    PathProperties {
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
        properties(),
        Mtu::new(1500).unwrap(),
        boreas_core::Limits {
            reassembly_timeout: Duration::from_secs(30),
            max_pending_reassemblies: NonZeroUsize::new(8).unwrap(),
            flow_idle_timeout: Duration::from_secs(120),
            datagram_buffer_capacity: NonZeroUsize::new(8).unwrap(),
            // Long enough to outlast a browser's cached Alt-Svc entry for
            // an origin, which is what the DNS rewrite alone cannot reach.
            inspection_window: Duration::from_secs(60),
            max_inspected_addresses: NonZeroUsize::new(256).unwrap(),
            inspected_ports: boreas_core::DEFAULT_INSPECTED_PORTS,
            origination_ports: None,
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
            policy: tokio::sync::watch::channel(Arc::new(policy)).1,
            termination: None,
            relay: None,
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

    // 2. The inspected host's HTTPS answer lost its ECH parameter, and since
    //    the upstream advertised h3, its ALPN block as well: both rewrites
    //    follow from the one verdict.
    let (_, rcode, records) = &answers[1];
    assert_eq!(*rcode, Rcode::NoError);
    assert_eq!(records[0].0, RecordType::Https);
    assert_eq!(ech_param(&records[0].1).unwrap(), None, "ECH was stripped");
    assert_eq!(
        h3_alpn_param(&records[0].1).unwrap(),
        None,
        "h3 was steered"
    );
    let keys: Vec<u16> = svc_params(&records[0].1)
        .unwrap()
        .map(|param| param.unwrap().key)
        .collect();
    assert!(keys.is_empty(), "only the two parameters were removed");

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
    assert_eq!(inspected.alpn, AlpnOutcome::Steered { count: 1 });
    assert_eq!(inspected.answers, 1);

    let allowed = reports
        .iter()
        .find(|report| {
            report.name.to_string() == "www.other.example" && report.qtype == RecordType::Https
        })
        .expect("the allowed host reported");
    assert_eq!(allowed.ech, EchOutcome::Preserved);
    assert_eq!(allowed.alpn, AlpnOutcome::Preserved);
    assert_eq!(allowed.rule, None);

    let aaaa = reports
        .iter()
        .find(|report| report.qtype == RecordType::Aaaa)
        .expect("the AAAA query reported");
    assert_eq!(aaaa.ech, EchOutcome::Absent, "no SVCB record, no ECH");
    assert_eq!(aaaa.alpn, AlpnOutcome::Absent, "and nothing to steer");

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
        properties(),
        Mtu::new(1500).unwrap(),
        boreas_core::Limits {
            reassembly_timeout: Duration::from_secs(30),
            max_pending_reassemblies: NonZeroUsize::new(8).unwrap(),
            flow_idle_timeout: Duration::from_secs(120),
            datagram_buffer_capacity: NonZeroUsize::new(8).unwrap(),
            // Long enough to outlast a browser's cached Alt-Svc entry for
            // an origin, which is what the DNS rewrite alone cannot reach.
            inspection_window: Duration::from_secs(60),
            max_inspected_addresses: NonZeroUsize::new(256).unwrap(),
            inspected_ports: boreas_core::DEFAULT_INSPECTED_PORTS,
            origination_ports: None,
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
            policy: tokio::sync::watch::channel(Arc::new(HostPolicy::new())).1,
            termination: None,
            relay: None,
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

#[tokio::test]
async fn a_filter_list_build_takes_effect_without_restarting_the_session() {
    // The M2 mechanism: a compiled list replaces the whole index under a live
    // reactor, and the next query is decided by the new one. This is the P8
    // `watch` channel finally carrying what it was built for.
    let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(16);
    let (sent_tx, mut sent_rx) = tokio::sync::mpsc::channel(16);
    let consulted = Arc::new(AtomicU64::new(0));
    let (publish, policy) = tokio::sync::watch::channel(Arc::new(HostPolicy::new()));

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
            policy,
            termination: None,
            relay: None,
        },
    );

    let mut ask = async |id: u16| {
        inbound_tx
            .send(dns_packet(&query(id, "ads.tracker.example", RecordType::A)))
            .await
            .unwrap();
        let packet = tokio::time::timeout(Duration::from_secs(5), sent_rx.recv())
            .await
            .expect("the shell answered")
            .expect("device channel open");
        Message::parse(&dns_answer(&packet))
            .expect("a well-formed answer")
            .rcode()
    };

    // An empty policy blocks nothing, so the name resolves upstream.
    assert_eq!(ask(1).await, Rcode::NoError);
    assert_eq!(consulted.load(Ordering::Relaxed), 1);

    // Compile a list and publish it. Adblock Plus and hosts-file syntax in one
    // build, with an exception that must survive the more specific block.
    let mut built = HostPolicy::new();
    let report = built.extend_from_list(
        "! test list\n\
         ||tracker.example^\n\
         0.0.0.0 beacon.example\n\
         ||tracker.example^$third-party\n\
         @@||safe.tracker.example^\n\
         tracker.example##.ad\n",
    );
    assert_eq!(report.blocked, 2);
    assert_eq!(report.allowed, 1);
    assert_eq!(report.deferred.needs_request_context, 1);
    assert_eq!(report.deferred.cosmetic, 1);
    let counts = built.len();
    publish
        .send(Arc::new(built))
        .expect("the reactor is running");

    // The same query is now refused, and nothing left the device for it.
    assert_eq!(ask(2).await, Rcode::NameError);
    assert_eq!(
        consulted.load(Ordering::Relaxed),
        1,
        "a blocked name costs no upstream query"
    );

    // The exception in the same list still wins over the block above it.
    inbound_tx
        .send(dns_packet(&query(3, "safe.tracker.example", RecordType::A)))
        .await
        .unwrap();
    let packet = tokio::time::timeout(Duration::from_secs(5), sent_rx.recv())
        .await
        .expect("the shell answered")
        .expect("device channel open");
    assert_eq!(
        Message::parse(&dns_answer(&packet)).unwrap().rcode(),
        Rcode::NoError
    );
    assert_eq!(consulted.load(Ordering::Relaxed), 2);

    // And the swap was reported, with what the new policy holds.
    let reported = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match shell.next_telemetry().await {
                Some(Telemetry::PolicyReloaded(counts)) => return counts,
                Some(_) => continue,
                None => panic!("telemetry closed"),
            }
        }
    })
    .await
    .expect("a reload report");
    assert_eq!(
        reported,
        RuleCounts {
            allowed: 1,
            blocked: 2,
            inspected: 0,
        }
    );
    assert_eq!(reported, counts);

    shell.shutdown().await.expect("clean shutdown");
    assert_eq!(pool.available(), 64);
}

/// A UDP datagram from the client to `destination` on `port`, which is how a
/// browser opens a QUIC connection.
fn udp_to(destination: IpAddr, port: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 2048];
    let len = write_udp(
        &mut out,
        CLIENT,
        InternalEndpoint {
            address: destination,
            port,
        },
        payload,
    )
    .expect("a client datagram fits");
    out.truncate(len);
    out
}

#[tokio::test]
async fn steering_removes_h3_at_discovery_and_the_backstop_covers_the_stale_cache() {
    // The P13 gate. Steering acts at discovery, before a connection exists,
    // so an inspected host's answer loses its HTTP/3 advertisement; the
    // transient UDP/443 backstop covers the window in which a browser still
    // holds a cached Alt-Svc entry and would race QUIC anyway.
    let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(16);
    let (sent_tx, mut sent_rx) = tokio::sync::mpsc::channel(16);
    let consulted = Arc::new(AtomicU64::new(0));

    let mut policy = HostPolicy::new();
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
            policy: tokio::sync::watch::channel(Arc::new(policy)).1,
            termination: None,
            relay: None,
        },
    );

    let mut next = async |id: u16| {
        let packet = tokio::time::timeout(Duration::from_secs(5), sent_rx.recv())
            .await
            .unwrap_or_else(|_| panic!("no answer for query {id}"))
            .expect("device channel open");
        dns_answer(&packet)
    };

    // HTTPS and SVCB both carry SvcParams, so both are steered.
    for (id, qtype) in [(1u16, RecordType::Https), (2, RecordType::Svcb)] {
        inbound_tx
            .send(dns_packet(&query(id, "www.shop.example", qtype)))
            .await
            .unwrap();
        let message = next(id).await;
        let parsed = Message::parse(&message).expect("a well-formed answer");
        let answers: Vec<ResourceRecord<'_>> = parsed
            .answers()
            .collect::<Result<_, _>>()
            .expect("well formed");
        assert_eq!(answers[0].rtype, qtype);
        assert_eq!(
            h3_alpn_param(answers[0].rdata).unwrap(),
            None,
            "{qtype:?} still advertises HTTP/3"
        );
        assert_eq!(
            ech_param(answers[0].rdata).unwrap(),
            None,
            "an inspected host loses ECH as well"
        );
        assert!(
            svc_params(answers[0].rdata)
                .unwrap()
                .all(|param| param.unwrap().key != SVCPARAM_ALPN)
        );
    }

    // An allowed host in the same session keeps its HTTP/3 advertisement:
    // steering is per host, exactly as ECH policy is.
    inbound_tx
        .send(dns_packet(&query(
            3,
            "www.other.example",
            RecordType::Https,
        )))
        .await
        .unwrap();
    let parsed_bytes = next(3).await;
    let parsed = Message::parse(&parsed_bytes).unwrap();
    let answers: Vec<ResourceRecord<'_>> = parsed.answers().collect::<Result<_, _>>().unwrap();
    assert!(
        h3_alpn_param(answers[0].rdata).unwrap().is_some(),
        "an allowed host must not pay for an inspected one"
    );

    // Resolve the inspected host's address, which is what opens the backstop.
    inbound_tx
        .send(dns_packet(&query(4, "www.shop.example", RecordType::A)))
        .await
        .unwrap();
    let _ = next(4).await;

    // A QUIC attempt to that address is now refused, so the browser's race
    // resolves to TCP. TCP to the same address and port is untouched — it is
    // the destination steering is trying to reach.
    let steered: IpAddr = Ipv4Addr::new(203, 0, 113, 7).into();
    inbound_tx
        .send(udp_to(steered, HTTPS_PORT, b"\x00fake quic initial"))
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(200), sent_rx.recv())
            .await
            .is_err(),
        "a steered QUIC attempt must not be answered or looped back"
    );

    // A QUIC attempt to any other address crosses normally, which the egress
    // sees rather than the device.
    inbound_tx
        .send(udp_to(
            Ipv4Addr::new(198, 51, 100, 9).into(),
            HTTPS_PORT,
            b"x",
        ))
        .await
        .unwrap();

    // The drops are counted, which is the convergence signal.
    let steered_count = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match shell.next_telemetry().await {
                Some(Telemetry::QuicSteered(count)) => return count,
                Some(_) => continue,
                None => panic!("telemetry closed"),
            }
        }
    })
    .await
    .expect("a steering report");
    assert_eq!(
        steered_count, 1,
        "exactly the attempt to the steered address"
    );

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
