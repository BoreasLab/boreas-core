//! Public host-facing construction and lifecycle API.
//!
//! Hosts provide a [`Platform`], construct a checked [`TunnelConfig`], run a
//! [`Tunnel`], and persist certificate-authority material when interception is
//! enabled. The API does not expose implementation-crate types.
//!
//! The public contract is the configuration reachable from [`TunnelConfig`],
//! [`Platform`], [`Tunnel`], [`Event`], and the error sums. `#[non_exhaustive]`
//! applies to types hosts eliminate, not structs they construct; adding a
//! field to a constructed struct remains source-compatible through
//! [`Default`] where provided.
//!
//! Other crate exports are internal implementation surfaces. Hosts configure
//! policy here; protocol fingerprints, deadlines, NAT floors, and pool slice
//! sizes remain owned by the implementation, while device-dependent ceilings
//! remain configurable.

use std::{net::SocketAddr, num::NonZeroUsize, sync::Arc, time::Instant};

use tokio::sync::{mpsc, watch};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    Accepts, AsyncDevice, BufferPool, CaError, CaMaterial, CertificateAuthority, Datapath,
    DatapathError, DirectEgress, DnsPolicy, DomainName, EgressError, FilterPolicy, HostPolicy,
    Hysteria2Config, Hysteria2Egress, InterceptPolicy, Interceptor, Limits, LocalStack,
    MitmResolver, Mtu, NatBehavior, OriginationPorts, RuleEngine, ShadowsocksConfig,
    ShadowsocksEgress, Shell, Socks5Config, Socks5Egress, StreamBudget, StreamEgress,
    TerminationLimits, Trust, TunnelBypass, VlessConfig, VlessEgress, WireGuardConfig,
    WireGuardEgress,
};

// ---------------------------------------------------------- Platform

/// Platform-owned device and tunnel-bypass capabilities.
///
/// The crate cannot open platform TUN devices or make sockets bypass the
/// tunnel. A missing bypass is a routing loop once the tunnel is active.
pub struct Platform<D, B> {
    /// Client TUN carrying raw IP packets.
    pub device: D,
    /// Sockets excluded from the tunnel for egress, DNS, and relay traffic.
    pub bypass: B,
}

// ------------------------------------------------------ Configuration

pub struct TunnelConfig {
    pub egress: Egress,
    pub resolver: Resolver,
    pub filtering: Filtering,
    pub link: Link,
    pub ceilings: Ceilings,
}

/// Egress choice; the variant determines the accepted layer and flow behavior.
#[non_exhaustive]
pub enum Egress {
    /// Direct host routing and NAT.
    Direct {
        /// Host NAT behavior, supplied because only the host can observe it.
        nat_behavior: NatBehavior,
    },
    /// WireGuard peer carrying whole IP packets.
    WireGuard {
        /// Peer socket address; cryptographic configuration can remain stable while it roams.
        peer: SocketAddr,
        config: WireGuardConfig,
    },
    Socks5(Socks5Config),
    Shadowsocks(ShadowsocksConfig),
    Vless {
        config: VlessConfig,
        transport: VlessTransport,
    },
    Hysteria2(Hysteria2Config),
}

/// VLESS transport. Framing and confidentiality belong to the selected transport.
#[non_exhaustive]
pub enum VlessTransport {
    /// Clear TCP; use only beneath an already confidential path.
    Plain { server: SocketAddr },
    /// TLS over TCP with the browser-shaped handshake.
    Tls(crate::TlsConfig),
    /// WebSocket over TLS.
    WebSocket {
        tls: crate::TlsConfig,
        settings: crate::WebSocketConfig,
    },
    /// gRPC over HTTP/2 over TLS.
    Grpc {
        tls: crate::TlsConfig,
        settings: crate::GrpcConfig,
    },
    /// HTTP/1.1 Upgrade over TLS; raw bytes follow the handshake.
    HttpUpgrade {
        tls: crate::TlsConfig,
        settings: crate::HttpUpgradeConfig,
    },
    /// HTTP/2 request whose body carries the byte stream.
    Http {
        tls: crate::TlsConfig,
        settings: crate::HttpConfig,
    },
}

/// Name-resolution mode.
#[non_exhaustive]
pub enum Resolver {
    /// Client resolution; incompatible with filtering on a packet egress.
    Passthrough,
    /// Local policy evaluation and configured upstream forwarding.
    Local { upstream: Upstream },
}

/// Upstream for allowed DNS questions; encrypted modes use bundled trust anchors.
#[non_exhaustive]
pub enum Upstream {
    /// Cleartext DNS.
    Do53 { resolver: SocketAddr },
    /// DNS over TLS; `server_name` is checked against the certificate.
    Dot {
        resolver: SocketAddr,
        server_name: String,
    },
    /// DNS over HTTPS.
    Doh { url: String, resolver: SocketAddr },
    /// DNS over QUIC; `server_name` is checked against the certificate.
    Doq {
        resolver: SocketAddr,
        server_name: String,
    },
}

/// Filtering policy. Optional nesting enforces the rule-to-interception-to-body
/// tier dependency at construction time.
pub struct Filtering {
    /// Filter-list text compiled when the tunnel starts or reloads.
    pub lists: Vec<String>,
    /// Optional interception tier.
    pub interception: Option<Interception>,
}

/// Terminating TLS for an explicit host allowlist.
pub struct Interception {
    /// Hostnames to intercept; patterns are not accepted because certificates are forged.
    pub hosts: Vec<String>,
    /// Authority material and its trust source.
    pub trust: Trust,
    /// Optional HTML body rewriting tier.
    pub documents: Option<Documents>,
}

/// Streaming HTML body rewriting configuration.
pub struct Documents {
    /// Per-response memory budget; bodies are not buffered whole.
    pub budget: StreamBudget,
}

/// Client link parameters.
pub struct Link {
    /// MTU configured on the client TUN; the device must use the same value.
    pub mtu: Mtu,
    /// Reserved source ports for re-originated connections.
    pub origination_ports: OriginationPorts,
}

impl Default for Link {
    fn default() -> Self {
        Self {
            mtu: Mtu::new(crate::MIN_IPV6_MTU).expect("the floor is a valid MTU"),
            origination_ports: crate::DEFAULT_ORIGINATION_PORTS,
        }
    }
}

/// Device-dependent resource ceilings.
#[derive(Clone, Copy, Debug)]
pub struct Ceilings {
    /// Shared payload buffers; exhaustion is counted rather than allocated.
    pub buffer_slices: NonZeroUsize,
    /// Queued datagrams per flow.
    pub datagrams_per_flow: NonZeroUsize,
    /// Live terminated connections.
    pub terminated_connections: NonZeroUsize,
    /// Datagram associations through a proxy egress.
    pub associations: NonZeroUsize,
    /// Remembered addresses for inspected hosts.
    pub inspected_addresses: NonZeroUsize,
    /// Pending fragment reassemblies.
    pub pending_reassemblies: NonZeroUsize,
}

impl Default for Ceilings {
    /// Defaults target a memory-constrained mobile host.
    fn default() -> Self {
        let at_least = |count: usize| NonZeroUsize::new(count).expect("a positive constant");
        Self {
            buffer_slices: at_least(2048),
            datagrams_per_flow: at_least(32),
            terminated_connections: at_least(512),
            associations: at_least(256),
            inspected_addresses: at_least(1024),
            pending_reassemblies: at_least(64),
        }
    }
}

/// Extra capacity required beyond the link MTU for local framing.
const SLICE_HEADROOM: usize = 128;

// ------------------------------------------------------------ Errors

/// A configuration this crate refuses to run.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// Filtering cannot observe names when DNS passes through a packet egress.
    NothingToFilter,
    /// Interception was requested without hosts.
    NoHostsToIntercept,
    /// An interception entry is not a valid hostname; the offending text is retained.
    NotAHost(String),
    /// Link MTU cannot absorb egress overhead.
    LinkTooNarrow,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NothingToFilter => f.write_str(
                "filtering with a pass-through resolver and a packet egress would inspect nothing",
            ),
            Self::NoHostsToIntercept => f.write_str("interception was asked for with no hosts"),
            Self::NotAHost(text) => write!(f, "not a host name: {text}"),
            Self::LinkTooNarrow => f.write_str("the egress's overhead exceeds the link's MTU"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Why tunnel startup failed.
#[non_exhaustive]
#[derive(Debug)]
pub enum StartError {
    /// Configuration failed before construction.
    Config(ConfigError),
    /// Certificate authority opening failed; material errors require regeneration and re-trust.
    Authority(CaError),
    /// Egress construction failed.
    Egress(EgressError),
    /// Datapath construction failed.
    Datapath(DatapathError),
    /// A required bypass socket could not be opened.
    Io(std::io::ErrorKind),
    /// Termination limits cannot support the configured inspected ports.
    Termination(crate::TerminationError),
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(error) => write!(f, "{error}"),
            Self::Authority(error) => write!(f, "certificate authority: {error}"),
            Self::Egress(error) => write!(f, "egress: {error}"),
            Self::Datapath(error) => write!(f, "datapath: {error}"),
            Self::Io(kind) => write!(f, "socket: {kind}"),
            Self::Termination(error) => write!(f, "local termination: {error}"),
        }
    }
}

impl std::error::Error for StartError {}

impl From<ConfigError> for StartError {
    fn from(error: ConfigError) -> Self {
        Self::Config(error)
    }
}

impl From<CaError> for StartError {
    fn from(error: CaError) -> Self {
        Self::Authority(error)
    }
}

impl From<EgressError> for StartError {
    fn from(error: EgressError) -> Self {
        Self::Egress(error)
    }
}

impl From<DatapathError> for StartError {
    fn from(error: DatapathError) -> Self {
        Self::Datapath(error)
    }
}

impl From<std::io::Error> for StartError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.kind())
    }
}

// ----------------------------------------------------- The checked plan

/// Checked configuration with construction decisions derived once.
#[derive(Debug)]
struct Plan {
    filter: FilterPolicy,
    dns: DnsPolicy,
    accepts: Accepts,
    /// Whether local TCP termination is required.
    terminates: bool,
    /// Whether datagrams require proxy associations.
    relays: bool,
}

impl TunnelConfig {
    /// Validates configuration and derives construction decisions. O(hosts + lists).
    fn plan(&self) -> Result<Plan, ConfigError> {
        let accepts = self.egress.accepts();
        let intercepts = self.filtering.interception.is_some();

        if let Some(interception) = &self.filtering.interception {
            if interception.hosts.is_empty() {
                return Err(ConfigError::NoHostsToIntercept);
            }
            for host in &interception.hosts {
                DomainName::new(host.as_str()).map_err(|_| ConfigError::NotAHost(host.clone()))?;
            }
        }

        let dns = match self.resolver {
            Resolver::Local { .. } => DnsPolicy::Intercept,
            Resolver::Passthrough => DnsPolicy::Forward,
        };
        let filter = if intercepts {
            FilterPolicy::InspectHttp
        } else {
            FilterPolicy::PassThrough
        };

        if filter == FilterPolicy::InspectHttp
            && dns == DnsPolicy::Forward
            && accepts == Accepts::IpPackets
        {
            return Err(ConfigError::NothingToFilter);
        }
        if dns == DnsPolicy::Forward && !self.filtering.lists.is_empty() {
            return Err(ConfigError::NothingToFilter);
        }

        Ok(Plan {
            filter,
            dns,
            accepts,
            terminates: accepts == Accepts::Flows || intercepts,
            relays: accepts == Accepts::Flows,
        })
    }
}

impl Egress {
    fn accepts(&self) -> Accepts {
        match self {
            Self::WireGuard { .. } => Accepts::IpPackets,
            Self::Direct { .. }
            | Self::Socks5(_)
            | Self::Shadowsocks(_)
            | Self::Vless { .. }
            | Self::Hysteria2(_) => Accepts::Flows,
        }
    }
}

// ------------------------------------------------------------- Events

/// Host-visible tunnel telemetry. Counting variants report occurrences since
/// the previous report.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A name-resolution decision.
    Resolved {
        name: String,
        /// Whether policy refused the name.
        blocked: bool,
        /// Matching rule, if any.
        rule: Option<String>,
    },
    /// Rule counts after an atomic reload.
    Reloaded {
        allowed: usize,
        blocked: usize,
        inspected: usize,
    },
    /// Aggregated counters since the previous report.
    Counted(Counters),
}

/// Counted drops and failures since the previous [`Event::Counted`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    /// Datagrams dropped by queue or buffer limits.
    pub datagrams_dropped: u64,
    /// Packets rejected during parsing.
    pub packets_rejected: u64,
    /// QUIC attempts steered to HTTP/2 for inspection.
    pub quic_steered: u64,
    /// Oversized packets answered with ICMP Packet Too Big.
    pub paths_reported: u64,
    /// Events lost because the host did not consume them fast enough.
    pub events_lost: u64,
    /// Tasks that ended by panicking; this indicates an internal defect.
    pub tasks_panicked: u64,
}

// ------------------------------------------------------- Running tunnel

/// A running tunnel. Dropping it does not stop its tasks; call [`Self::stop`]
/// for ordered cancellation and resource cleanup.
pub struct Tunnel {
    shell: Shell,
    /// Publishes complete compiled rule sets atomically.
    policy: watch::Sender<Arc<HostPolicy>>,
    /// Tasks owned by the tunnel.
    tasks: TaskTracker,
    shutdown: CancellationToken,
    /// Authority retained when interception is enabled.
    authority: Option<Arc<CertificateAuthority>>,
}

impl Tunnel {
    /// Returns material the host must persist for future interception.
    pub fn authority(&self) -> Option<CaMaterial> {
        self.authority.as_ref().map(|ca| ca.material())
    }

    /// Returns the next host-visible event, or `None` after shutdown.
    pub async fn next_event(&mut self) -> Option<Event> {
        loop {
            let telemetry = self.shell.next_telemetry().await?;
            if let Some(event) = project(telemetry) {
                return Some(event);
            }
        }
    }

    /// Atomically replaces the rules without restarting connections. O(total list length).
    pub fn reload(&self, lists: &[String]) -> Event {
        let policy = compile(lists);
        let counts = policy.len();
        let _ = self.policy.send(Arc::new(policy));
        Event::Reloaded {
            allowed: counts.allowed,
            blocked: counts.blocked,
            inspected: counts.inspected,
        }
    }

    /// Cancels the tunnel and waits for its tasks and resources to close.
    pub async fn stop(self) -> std::io::Result<()> {
        self.shutdown.cancel();
        self.tasks.close();
        self.tasks.wait().await;
        self.shell.shutdown().await
    }
}

fn compile(lists: &[String]) -> HostPolicy {
    let mut policy = HostPolicy::new();
    for list in lists {
        let _ = policy.extend_from_list(list);
    }
    policy
}

fn project(telemetry: crate::Telemetry) -> Option<Event> {
    use crate::Telemetry;
    Some(match telemetry {
        Telemetry::Resolved(resolution) => Event::Resolved {
            name: resolution.name.to_string(),
            blocked: resolution.provenance == crate::Provenance::Policy,
            rule: resolution.rule.as_ref().map(ToString::to_string),
        },
        Telemetry::PolicyReloaded(counts) => Event::Reloaded {
            allowed: counts.allowed,
            blocked: counts.blocked,
            inspected: counts.inspected,
        },
        Telemetry::DatagramsDropped(count) => Event::Counted(Counters {
            datagrams_dropped: count,
            ..Counters::default()
        }),
        Telemetry::PacketsRejected(count) => Event::Counted(Counters {
            packets_rejected: count,
            ..Counters::default()
        }),
        Telemetry::QuicSteered(count) => Event::Counted(Counters {
            quic_steered: count,
            ..Counters::default()
        }),
        Telemetry::PathsReported(count) => Event::Counted(Counters {
            paths_reported: count,
            ..Counters::default()
        }),
        Telemetry::Lost(count) => Event::Counted(Counters {
            events_lost: count,
            ..Counters::default()
        }),
        Telemetry::TasksPanicked(count) => Event::Counted(Counters {
            tasks_panicked: count,
            ..Counters::default()
        }),
        // Keep internal lifecycle and refusal telemetry out of the public API.
        Telemetry::Event(_)
        | Telemetry::ReassemblyDiscarded(_)
        | Telemetry::TransmitsDropped(_)
        | Telemetry::EgressRejected(_)
        | Telemetry::QueriesDropped(_)
        | Telemetry::TerminationDropped(_)
        | Telemetry::DeviceErrors(_)
        | Telemetry::NetworkErrors(_)
        | Telemetry::PoolExhausted(_) => return None,
    })
}

// ------------------------------------------------------ Composition

enum AnyUpstream<B> {
    Do53(crate::Do53Upstream<B>),
    Dot(crate::DotUpstream<B>),
    Doh(crate::DohUpstream<B>),
    Doq(crate::DoqUpstream<B>),
    Unused,
}

impl<B: TunnelBypass + 'static> crate::DnsUpstream for AnyUpstream<B> {
    fn kind(&self) -> crate::Upstream {
        match self {
            Self::Do53(upstream) => upstream.kind(),
            Self::Dot(upstream) => upstream.kind(),
            Self::Doh(upstream) => upstream.kind(),
            Self::Doq(upstream) => upstream.kind(),
            Self::Unused => crate::Upstream::Do53,
        }
    }

    async fn query(&self, message: &[u8]) -> std::io::Result<Vec<u8>> {
        match self {
            Self::Do53(upstream) => upstream.query(message).await,
            Self::Dot(upstream) => upstream.query(message).await,
            Self::Doh(upstream) => upstream.query(message).await,
            Self::Doq(upstream) => upstream.query(message).await,
            Self::Unused => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "this tunnel forwards questions rather than answering them",
            )),
        }
    }
}

impl Upstream {
    fn build<B: TunnelBypass + 'static>(self, bypass: B) -> Result<AnyUpstream<B>, StartError> {
        Ok(match self {
            Self::Do53 { resolver } => {
                AnyUpstream::Do53(crate::Do53Upstream::new(resolver, bypass))
            }
            Self::Dot {
                resolver,
                server_name,
            } => AnyUpstream::Dot(
                crate::DotUpstream::new(resolver, &server_name, bypass)
                    .map_err(|_| ConfigError::NotAHost(server_name))?,
            ),
            Self::Doh { url, resolver } => AnyUpstream::Doh(
                crate::DohUpstream::new(&url, resolver, bypass)
                    .map_err(|_| ConfigError::NotAHost(url))?,
            ),
            Self::Doq {
                resolver,
                server_name,
            } => AnyUpstream::Doq(crate::DoqUpstream::new(
                resolver,
                &server_name,
                bypass,
                Box::new(crate::DoqUpstream::<B>::quic_config),
            )),
        })
    }
}

/// Underlay for packet-egress datagrams.
enum Underlay {
    Peer(tokio::net::UdpSocket),
    /// No underlay exists for a flow egress.
    Absent,
}

impl crate::AsyncNetwork for Underlay {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Peer(socket) => socket.recv(buf).await,
            Self::Absent => std::future::pending().await,
        }
    }

    async fn send(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Peer(socket) => {
                let sent = tokio::net::UdpSocket::send(socket, buf).await?;
                crate::host::shell::whole(sent, buf.len())
            }
            Self::Absent => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "this tunnel's egress carries flows, not packets",
            )),
        }
    }
}

impl Tunnel {
    /// Validates, assembles, and starts a tunnel on the current Tokio runtime.
    /// Configuration is checked before any socket is opened.
    pub async fn start<D, B>(
        config: TunnelConfig,
        platform: Platform<D, B>,
    ) -> Result<Self, StartError>
    where
        D: AsyncDevice + Send + 'static,
        B: TunnelBypass + Clone + 'static,
    {
        let plan = config.plan()?;
        let TunnelConfig {
            egress,
            resolver,
            filtering,
            link,
            ceilings,
        } = config;
        let Platform { device, bypass } = platform;

        let pool = BufferPool::new(
            NonZeroUsize::new(usize::from(link.mtu.get()) + SLICE_HEADROOM)
                .expect("an MTU is positive"),
            ceilings.buffer_slices,
        );

        let (egress, underlay) = build_egress(egress, &bypass, &pool).await?;
        let properties = egress.properties();
        let assembly = crate::assemble(egress, link.origination_ports);

        let datapath = Datapath::new(
            plan.filter,
            plan.dns,
            plan.accepts,
            properties,
            link.mtu,
            limits(&link, &ceilings, &plan),
            Arc::clone(&pool),
        )?;

        let shutdown = CancellationToken::new();
        let tasks = TaskTracker::new();
        let supervision = crate::Supervision {
            shutdown: shutdown.clone(),
            panics: crate::Panics::new(),
        };
        let (policy_tx, policy_rx) = watch::channel(Arc::new(compile(&filtering.lists)));

        let (termination, authority) = if plan.terminates {
            let (built, authority) = start_termination(
                filtering,
                plan.accepts,
                &link,
                &ceilings,
                Arc::clone(&assembly.flows),
                Arc::clone(&pool),
                &tasks,
                &supervision,
            )?;
            (Some(built), authority)
        } else {
            (None, None)
        };

        let relay = plan.relays.then(|| {
            let (outbound_tx, outbound_rx) = mpsc::channel(CHANNEL_DEPTH);
            let (inbound_tx, inbound_rx) = mpsc::channel(CHANNEL_DEPTH);
            let (counts_tx, _counts_rx) = mpsc::channel(CHANNEL_DEPTH);
            tasks.spawn(crate::run_relay(
                Arc::clone(&assembly.flows),
                Arc::clone(&pool),
                outbound_rx,
                inbound_tx,
                crate::RelayLimits {
                    max_associations: ceilings.associations,
                    ..crate::RelayLimits::default()
                },
                counts_tx,
                supervision.clone(),
            ));
            crate::Relay {
                outbound: outbound_tx,
                inbound: inbound_rx,
            }
        });

        let shell = Shell::start(
            datapath,
            crate::Session {
                device,
                network: underlay,
                egress: assembly.packets,
                upstream: match resolver {
                    Resolver::Local { upstream } => upstream.build(bypass)?,
                    Resolver::Passthrough => AnyUpstream::Unused,
                },
                panics: supervision.panics.clone(),
                policy: policy_rx,
                termination,
                relay,
            },
        );

        Ok(Self {
            shell,
            policy: policy_tx,
            tasks,
            shutdown,
            authority,
        })
    }
}

const CHANNEL_DEPTH: usize = 256;

/// Live flows across every transport. A constant rather than a ceiling because
/// a field on `BoreasCeilings` is an ABI change; conntrack tables on phones
/// default to a few thousand.
const MAX_FLOWS: NonZeroUsize = NonZeroUsize::new(4096).expect("nonzero");

#[allow(clippy::too_many_arguments)]
fn start_termination(
    filtering: Filtering,
    accepts: Accepts,
    link: &Link,
    ceilings: &Ceilings,
    flows: Arc<dyn StreamEgress>,
    pool: Arc<BufferPool>,
    tasks: &TaskTracker,
    supervision: &crate::Supervision,
) -> Result<(crate::Termination, Option<Arc<CertificateAuthority>>), StartError> {
    let mut stack = LocalStack::new(
        link.mtu,
        crate::DEFAULT_INSPECTED_PORTS,
        TerminationLimits {
            max_sockets: ceilings.terminated_connections,
            backlog: NonZeroUsize::new(64).expect("a positive constant"),
            socket_buffer: NonZeroUsize::new(64 * 1024).expect("a positive constant"),
        },
        pool,
        Instant::now(),
    )
    .map_err(StartError::Termination)?;
    // A flow egress terminates every TCP connection, whatever its port.
    if accepts == Accepts::Flows {
        stack.terminate_every_port();
    }

    let (packets_tx, packets_rx) = mpsc::channel(CHANNEL_DEPTH);
    let (replies_tx, replies_rx) = mpsc::channel(CHANNEL_DEPTH);
    let (accepted_tx, accepted_rx) = mpsc::channel(CHANNEL_DEPTH);

    tasks.spawn(supervision.panics.watch(crate::run_terminator(
        stack,
        packets_rx,
        replies_tx,
        accepted_tx,
        supervision.shutdown.clone(),
    )));

    let Filtering {
        lists,
        interception,
    } = filtering;
    let Some(interception) = interception else {
        let sessions = build_sessions(lists, None, ceilings, flows, None)?;
        tasks.spawn(crate::run_sessions(
            accepted_rx,
            sessions,
            supervision.clone(),
        ));
        return Ok((
            crate::Termination {
                packets: packets_tx,
                replies: replies_rx,
            },
            None,
        ));
    };

    let Interception {
        hosts,
        trust,
        documents,
    } = interception;
    let authority = Arc::new(CertificateAuthority::open(trust)?);
    let sessions = build_sessions(
        lists,
        Some((hosts, documents)),
        ceilings,
        flows,
        Some(Arc::clone(&authority)),
    )?;
    tasks.spawn(crate::run_sessions(
        accepted_rx,
        sessions,
        supervision.clone(),
    ));

    Ok((
        crate::Termination {
            packets: packets_tx,
            replies: replies_rx,
        },
        Some(authority),
    ))
}

fn build_sessions(
    lists: Vec<String>,
    intercepted: Option<(Vec<String>, Option<Documents>)>,
    ceilings: &Ceilings,
    flows: Arc<dyn StreamEgress>,
    authority: Option<Arc<CertificateAuthority>>,
) -> Result<Arc<crate::Sessions>, StartError> {
    let authority = match authority {
        Some(authority) => authority,
        None => Arc::new(CertificateAuthority::generate()?),
    };
    let resolver = Arc::new(MitmResolver::new(
        authority,
        ceilings.terminated_connections,
    ));
    let interceptor = Arc::new(Interceptor::new(resolver).map_err(|_| CaError::Material)?);
    let (hosts, documents) = intercepted.unzip();

    let engine = Arc::new(RuleEngine::from_lists(lists));
    let sessions = crate::Sessions::new(
        interceptor,
        Arc::new(InterceptPolicy::new(hosts.unwrap_or_default())),
        flows,
        Arc::clone(&engine) as Arc<dyn crate::RequestFilter>,
        crate::SessionLimits::default(),
    )?;
    let sessions = match documents.flatten() {
        Some(documents) => sessions.with_cosmetic_rules(engine, documents.budget),
        None => sessions,
    };
    Ok(Arc::new(sessions))
}

fn limits(link: &Link, ceilings: &Ceilings, plan: &Plan) -> Limits {
    Limits {
        reassembly_timeout: std::time::Duration::from_secs(30),
        max_pending_reassemblies: ceilings.pending_reassemblies,
        flow_idle_timeout: std::time::Duration::from_secs(120),
        max_flows: MAX_FLOWS,
        datagram_buffer_capacity: ceilings.datagrams_per_flow,
        inspection_window: std::time::Duration::from_secs(60),
        max_inspected_addresses: ceilings.inspected_addresses,
        inspected_ports: crate::DEFAULT_INSPECTED_PORTS,
        origination_ports: plan.terminates.then_some(link.origination_ports),
    }
}

async fn build_egress<B: TunnelBypass + Clone + 'static>(
    choice: Egress,
    bypass: &B,
    pool: &Arc<BufferPool>,
) -> Result<(crate::Egress, Underlay), StartError> {
    Ok(match choice {
        Egress::Direct { nat_behavior } => (
            crate::Egress::Stream(Box::new(DirectEgress::new(bypass.clone(), nat_behavior))),
            Underlay::Absent,
        ),
        Egress::WireGuard { peer, config } => {
            let socket = bypass.udp(peer).await?;
            (
                crate::Egress::Packet(Box::new(WireGuardEgress::new(config, Arc::clone(pool)))),
                Underlay::Peer(socket),
            )
        }
        Egress::Socks5(config) => (
            crate::Egress::Stream(Box::new(Socks5Egress::new(config, bypass.clone()))),
            Underlay::Absent,
        ),
        Egress::Shadowsocks(config) => (
            crate::Egress::Stream(Box::new(ShadowsocksEgress::new(config, bypass.clone()))),
            Underlay::Absent,
        ),
        Egress::Hysteria2(config) => (
            crate::Egress::Stream(Box::new(Hysteria2Egress::new(
                config,
                bypass.clone(),
                Box::new(Hysteria2Egress::<B>::quic_config),
            ))),
            Underlay::Absent,
        ),
        Egress::Vless { config, transport } => {
            let transport = transport.build(bypass.clone())?;
            (
                crate::Egress::Stream(Box::new(VlessEgress::new(config, transport))),
                Underlay::Absent,
            )
        }
    })
}

impl VlessTransport {
    fn build<B: TunnelBypass + 'static>(
        self,
        bypass: B,
    ) -> Result<Box<dyn crate::ProxyTransport>, StartError> {
        Ok(match self {
            Self::Plain { server } => Box::new(crate::PlainTransport::new(server, bypass)),
            Self::Tls(tls) => Box::new(crate::TlsTransport::new(tls, bypass)?),
            Self::WebSocket { tls, settings } => Box::new(crate::WebSocketTransport::new(
                settings,
                crate::TlsTransport::new(tls, bypass)?,
            )),
            Self::Grpc { tls, settings } => Box::new(crate::GrpcTransport::new(
                settings,
                crate::TlsTransport::new(tls, bypass)?,
            )),
            Self::HttpUpgrade { tls, settings } => Box::new(crate::HttpUpgradeTransport::new(
                settings,
                crate::TlsTransport::new(tls, bypass)?,
            )),
            Self::Http { tls, settings } => Box::new(crate::HttpTransport::new(
                settings,
                crate::TlsTransport::new(tls, bypass)?,
            )),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DirectSockets;

    fn ceilings() -> Ceilings {
        Ceilings::default()
    }

    fn filtering(interception: Option<Interception>) -> Filtering {
        Filtering {
            lists: vec!["||ads.example.com^\n".to_owned()],
            interception,
        }
    }

    fn intercepting() -> Interception {
        Interception {
            hosts: vec!["example.com".to_owned()],
            trust: Trust::Generate,
            documents: None,
        }
    }

    fn local() -> Resolver {
        Resolver::Local {
            upstream: Upstream::Do53 {
                resolver: "198.51.100.53:53".parse().unwrap(),
            },
        }
    }

    fn config(egress: Egress, resolver: Resolver, filtering: Filtering) -> TunnelConfig {
        TunnelConfig {
            egress,
            resolver,
            filtering,
            link: Link::default(),
            ceilings: ceilings(),
        }
    }

    struct Silent;

    impl AsyncDevice for Silent {
        fn mtu(&self) -> Mtu {
            Link::default().mtu
        }

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
            async { Ok(()) }
        }
    }

    fn platform() -> Platform<Silent, DirectSockets> {
        Platform {
            device: Silent,
            bypass: DirectSockets,
        }
    }

    #[tokio::test]
    async fn a_filtering_tunnel_over_a_direct_egress_starts_and_stops() {
        let tunnel = Tunnel::start(
            config(
                Egress::Direct {
                    nat_behavior: NatBehavior::EndpointIndependent,
                },
                local(),
                filtering(Some(intercepting())),
            ),
            platform(),
        )
        .await
        .expect("the ordinary configuration starts");

        assert!(
            tunnel.authority().is_some(),
            "a tunnel that intercepts has material for the host to keep"
        );
        tunnel.stop().await.expect("and it stops in order");
    }

    #[tokio::test]
    async fn a_tunnel_that_does_not_intercept_has_nothing_to_keep() {
        let tunnel = Tunnel::start(
            config(
                Egress::Direct {
                    nat_behavior: NatBehavior::EndpointIndependent,
                },
                local(),
                filtering(None),
            ),
            platform(),
        )
        .await
        .unwrap();
        assert!(tunnel.authority().is_none());
        tunnel.stop().await.unwrap();
    }

    #[tokio::test]
    async fn a_restarted_tunnel_keeps_the_root_the_user_trusted() {
        let first = Tunnel::start(
            config(
                Egress::Direct {
                    nat_behavior: NatBehavior::EndpointIndependent,
                },
                local(),
                filtering(Some(intercepting())),
            ),
            platform(),
        )
        .await
        .unwrap();
        let kept = first.authority().expect("it intercepts");
        first.stop().await.unwrap();

        let second = Tunnel::start(
            config(
                Egress::Direct {
                    nat_behavior: NatBehavior::EndpointIndependent,
                },
                local(),
                filtering(Some(Interception {
                    trust: Trust::Restore(kept.clone()),
                    ..intercepting()
                })),
            ),
            platform(),
        )
        .await
        .unwrap();
        assert_eq!(
            second.authority().unwrap().root_certificate(),
            kept.root_certificate(),
            "the second tunnel mints under the root already in the device's store"
        );
        second.stop().await.unwrap();
    }

    #[test]
    fn a_configuration_that_would_filter_nothing_is_refused_before_anything_is_built() {
        let cases = [
            (
                "inspecting with a pass-through resolver over a packet egress",
                config(
                    Egress::WireGuard {
                        peer: "198.51.100.1:51820".parse().unwrap(),
                        config: WireGuardConfig {
                            private_key: [1u8; 32],
                            peer_public_key: [2u8; 32],
                            preshared_key: None,
                            persistent_keepalive: None,
                            inner_mtu: Link::default().mtu,
                        },
                    },
                    Resolver::Passthrough,
                    filtering(Some(intercepting())),
                ),
                ConfigError::NothingToFilter,
            ),
            (
                "rules that no question will ever reach",
                config(
                    Egress::Direct {
                        nat_behavior: NatBehavior::EndpointIndependent,
                    },
                    Resolver::Passthrough,
                    filtering(None),
                ),
                ConfigError::NothingToFilter,
            ),
            (
                "forging certificates for the empty set",
                config(
                    Egress::Direct {
                        nat_behavior: NatBehavior::EndpointIndependent,
                    },
                    local(),
                    filtering(Some(Interception {
                        hosts: Vec::new(),
                        ..intercepting()
                    })),
                ),
                ConfigError::NoHostsToIntercept,
            ),
        ];

        for (label, config, expected) in cases {
            assert_eq!(config.plan().unwrap_err(), expected, "{label}");
        }
    }

    #[test]
    fn an_intercepted_host_that_is_not_a_name_names_itself() {
        let config = config(
            Egress::Direct {
                nat_behavior: NatBehavior::EndpointIndependent,
            },
            local(),
            filtering(Some(Interception {
                hosts: vec!["example.com".to_owned(), String::new()],
                ..intercepting()
            })),
        );
        assert_eq!(
            config.plan().unwrap_err(),
            ConfigError::NotAHost(String::new())
        );
    }

    #[test]
    fn the_layer_follows_from_the_egress_and_the_rest_follows_from_the_layer() {
        let packets = config(
            Egress::WireGuard {
                peer: "198.51.100.1:51820".parse().unwrap(),
                config: WireGuardConfig {
                    private_key: [1u8; 32],
                    peer_public_key: [2u8; 32],
                    preshared_key: None,
                    persistent_keepalive: None,
                    inner_mtu: Link::default().mtu,
                },
            },
            local(),
            filtering(None),
        )
        .plan()
        .unwrap();
        assert_eq!(packets.accepts, Accepts::IpPackets);
        assert!(
            !packets.terminates,
            "a packet path forwards rather than terminates"
        );
        assert!(
            !packets.relays,
            "and carries a datagram as the packet it is"
        );

        let flows = config(
            Egress::Direct {
                nat_behavior: NatBehavior::EndpointIndependent,
            },
            local(),
            filtering(None),
        )
        .plan()
        .unwrap();
        assert_eq!(flows.accepts, Accepts::Flows);
        assert!(flows.terminates, "a flow egress has no packet to forward");
        assert!(flows.relays, "so its datagrams need an association");
    }
}
