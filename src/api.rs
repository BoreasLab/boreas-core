//! The interface a host application builds a tunnel through.
//!
//! Everything else in this crate is machinery. This module is the contract:
//! what a host must provide, what it may choose, what it gets back, and what it
//! must keep. Nothing here exposes a type from `quiche`, `rustls`, `boring`,
//! `hyper`, or `smoltcp`, which is the whole point — those are how Boreas is
//! built today and a host that named one would be pinned to that choice.
//!
//! # The four things a host does
//!
//! 1. **Provide what only a platform can.** A TUN device, and sockets that do
//!    not re-enter the tunnel. Both are [`Platform`].
//! 2. **Describe the tunnel.** One [`TunnelConfig`] value, total and checked in
//!    one place.
//! 3. **Run it.** [`Tunnel::start`], then read [`Tunnel::next_event`] until it
//!    stops.
//! 4. **Keep what cannot be relearned.** Exactly one thing: the certificate
//!    authority's material. See [`crate::ca`] for why that is the only one.
//!
//! # What is stable and what is not
//!
//! **Stable:** the shape of [`TunnelConfig`] and everything reachable from it,
//! [`Platform`], [`Tunnel`]'s methods, [`Event`], and the error sums. A field
//! may be added to a struct here; a variant may be added to an enum here; both
//! are minor changes and both are why the enums a host matches on are
//! `#[non_exhaustive]`.
//!
//! **Not stable, and not reachable from here:** every other item this crate
//! exports. `Datapath`, `Shell`, `Session`, the egress traits, the DNS message
//! codec, and the rewriting tier are all public because this crate's own tests
//! and examples drive them directly, and all of them will change. A host that
//! reaches past this module is choosing to track that.
//!
//! # What a host cannot set, and why
//!
//! Configuration here is *policy* — what a product or a user decides. It is not
//! *mechanism*. A host cannot set the TLS or HTTP/2 fingerprint, because
//! matching a browser exactly is the feature and a knob there is a knob that
//! breaks it. It cannot set the dial deadlines in [`crate::Wait`], which come
//! from what mobility measurements say rather than from taste, nor lengthen a
//! NAT mapping below RFC 4787's floor, nor size the buffer pool's slices. It
//! *can* set every ceiling that depends on the device it runs on, because a
//! phone and a desktop differ by an order of magnitude there and only the host
//! knows which one it is.

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

/// What only the platform can supply.
///
/// Two obligations, and each is a thing this crate is structurally unable to
/// do. It cannot open the TUN, because on Android `VpnService` owns the
/// descriptor's lifecycle and permissions and on Windows the Wintun session
/// comes from a signed driver. And it cannot make a socket that leaves by a
/// route other than the tunnel, because excluding one is `VpnService.protect`
/// on Android and binding the physical interface's address on Windows.
///
/// **The second obligation is the one that is silent when it is skipped.** A
/// socket that was not excluded still works — until the tunnel comes up, at
/// which point every packet it sends re-enters the tunnel it was serving. The
/// symptom is a resolver that hangs and a proxy that never connects, and the
/// cause is three lines away in a different language. [`TunnelBypass`] exists
/// to give that obligation a name.
pub struct Platform<D, B> {
    /// The client's TUN. Raw IP packets in and out.
    pub device: D,
    /// Sockets excluded from the tunnel: the egress's own, the resolver's, and
    /// any relay's.
    pub bypass: B,
}

// ------------------------------------------------------ Configuration

/// One tunnel, described completely.
///
/// Five independent choices, which is why this is a product: where traffic
/// leaves, how names are answered, what is done to what crosses, what the
/// client's own link looks like, and how much this instance may hold. Nothing
/// here is optional in the sense of "leave it out and something sensible
/// happens" except where a `Default` says exactly what that something is.
#[non_exhaustive]
pub struct TunnelConfig {
    pub egress: Egress,
    pub resolver: Resolver,
    pub filtering: Filtering,
    pub link: Link,
    pub ceilings: Ceilings,
}

/// Where traffic leaves by.
///
/// **The variant decides the layer, and the layer decides everything
/// downstream** — whether flows are terminated locally, whether datagrams need
/// a relay, whether QUIC survives or is steered to HTTP/2. A host picks a
/// variant; it never states a layer, because a variant that could disagree with
/// its own layer is the defect [`crate::Egress`] was built to remove.
#[non_exhaustive]
pub enum Egress {
    /// Out by the host's own routes, unchanged.
    ///
    /// **The ordinary configuration for a content blocker**, and the only one
    /// in which nothing is proxied: connections are re-originated to the
    /// address the client asked for, which is what lets filtering happen
    /// without moving where traffic goes.
    Direct {
        /// What the host's own NAT does to a mapping. A phone behind
        /// carrier-grade NAT and a desktop with a public address are the same
        /// code and different answers, and only the host can tell which.
        nat_behavior: NatBehavior,
    },
    /// A WireGuard peer, carrying whole IP packets.
    WireGuard {
        /// Where the peer is reached. **Not part of [`WireGuardConfig`]**,
        /// because that value describes the cryptographic peer and this one
        /// describes a socket: a peer that roams keeps its keys and changes
        /// its address.
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

/// How a VLESS stream is carried.
///
/// VLESS has no framing and no encryption of its own — everything that makes it
/// survive a hostile network lives underneath it — so the transport is a
/// separate choice rather than a field on [`VlessConfig`].
#[non_exhaustive]
pub enum VlessTransport {
    /// TCP, in the clear. Correct only underneath something that already
    /// provides confidentiality, and named `Plain` so it cannot be mistaken for
    /// something that does.
    Plain { server: SocketAddr },
    /// TLS over TCP, wearing Chrome's hello.
    Tls(crate::TlsConfig),
    /// A WebSocket over TLS, which is what a CDN-fronted deployment looks like
    /// to whatever is in the way.
    WebSocket {
        tls: crate::TlsConfig,
        settings: crate::WebSocketConfig,
    },
    /// gRPC over HTTP/2 over TLS.
    Grpc {
        tls: crate::TlsConfig,
        settings: crate::GrpcConfig,
    },
    /// An HTTP/1.1 Upgrade over TLS, and **raw bytes after it**.
    ///
    /// The same handshake a WebSocket performs — which is the part a CDN
    /// inspects — without the per-message header and masking a WebSocket pays
    /// for every frame afterwards. Choose it over [`Self::WebSocket`] wherever
    /// the infrastructure in the way proxies an upgrade transparently, which is
    /// what it was invented for.
    HttpUpgrade {
        tls: crate::TlsConfig,
        settings: crate::HttpUpgradeConfig,
    },
    /// An ordinary HTTP/2 request whose body is the byte stream.
    Http {
        tls: crate::TlsConfig,
        settings: crate::HttpConfig,
    },
}

/// How names are answered.
#[non_exhaustive]
pub enum Resolver {
    /// The client's own stack resolves; queries cross the tunnel untouched.
    ///
    /// **Incompatible with filtering under a packet egress**, and
    /// [`ConfigError::NothingToFilter`] says so at construction: on the packet
    /// fast path a flow is selected for inspection because a DNS answer named
    /// its address, so a tunnel that never sees a question can never select
    /// one. It would carry traffic and filter nothing while reporting health.
    Passthrough,
    /// Answered here, against the rules in [`Filtering`], forwarding what
    /// policy allows.
    Local { upstream: Upstream },
}

/// Where an allowed question goes.
///
/// All four verify against the bundled Mozilla anchors rather than the platform
/// store, deliberately: the set a resolver is trusted against should not be one
/// a device owner or an MDM profile can widen.
#[non_exhaustive]
pub enum Upstream {
    /// Cleartext DNS. Readable by anything on the path, and the only one that
    /// needs no TLS.
    Do53 { resolver: SocketAddr },
    /// DNS over TLS. `server_name` is what the certificate must carry, which is
    /// not the address it lives at.
    Dot {
        resolver: SocketAddr,
        server_name: String,
    },
    /// DNS over HTTPS.
    Doh { url: String, resolver: SocketAddr },
    /// DNS over QUIC.
    Doq {
        resolver: SocketAddr,
        server_name: String,
    },
}

/// What this tunnel does to what it carries.
///
/// **The tiers are a chain, and the nesting is the chain.** Rules over names
/// are the floor: everything above needs them. Interception is rules plus
/// terminated TLS, so it cannot be configured without them and it carries the
/// authority it mints under. Document rewriting is interception plus a body
/// tier, so it lives inside interception and cannot be reached without it.
///
/// Written as three flat fields, "rewrite documents" and "do not intercept"
/// would be a representable pair with no meaning, and something would have to
/// notice at runtime. Here there is nothing to notice.
#[non_exhaustive]
pub struct Filtering {
    /// Filter-list text, in the syntax [`crate::parse_rule`] accepts. The host
    /// fetches and stores these; this crate compiles them and never keeps them.
    ///
    /// Empty means a tunnel that resolves locally and blocks nothing, which is
    /// a real configuration: it is what encrypted DNS with no filtering is.
    pub lists: Vec<String>,
    /// Termination, when this tunnel intercepts. `None` stops at the name tier.
    pub interception: Option<Interception>,
}

/// Terminating TLS for named hosts, and filtering the requests inside.
#[non_exhaustive]
pub struct Interception {
    /// The hosts a person chose to intercept. **An allowlist, never a
    /// pattern**: interception forges a certificate, and the set of hosts that
    /// happens to should be one a user can read.
    pub hosts: Vec<String>,
    /// The authority to mint under, and whether it is new. See [`Trust`].
    pub trust: Trust,
    /// Body rewriting, when this tunnel rewrites. `None` stops at requests.
    pub documents: Option<Documents>,
}

/// Rewriting HTML bodies as they stream past.
#[non_exhaustive]
pub struct Documents {
    /// Memory one response may occupy while being rewritten. The ceiling is the
    /// point: a document is transformed as it arrives rather than buffered
    /// whole, and this is what makes that a bound rather than an intention.
    pub budget: StreamBudget,
}

/// The client's own interface.
#[non_exhaustive]
pub struct Link {
    /// The MTU configured on the TUN.
    ///
    /// **Set the TUN to this and tell this the same number.** The tunnel is
    /// narrower than the link by whatever the egress encapsulates, so a packet
    /// between the two is one the client may legitimately send and the session
    /// cannot carry — those are answered with an ICMP Packet Too Big, and a
    /// [`Event::Counted`] whose `paths_reported` stays high is the symptom of
    /// having told the two different numbers.
    pub mtu: Mtu,
    /// Local ports reserved for re-originated connections, and therefore never
    /// themselves inspected.
    pub origination_ports: OriginationPorts,
}

impl Default for Link {
    fn default() -> Self {
        Self {
            // The IPv6 minimum, which every path carries and no egress's
            // overhead can push below the floor.
            mtu: Mtu::new(crate::MIN_IPV6_MTU).expect("the floor is a valid MTU"),
            origination_ports: crate::DEFAULT_ORIGINATION_PORTS,
        }
    }
}

/// How much one tunnel may hold.
///
/// **Every number here is about the device, which is why the host sets them.**
/// A handset with 2 GB of RAM running a VPN service that Android will kill for
/// using too much, and a desktop with 32 GB, want different answers, and
/// nothing in this crate can tell which it is on.
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub struct Ceilings {
    /// Payload buffers, shared by everything: forwarded packets, queued
    /// datagrams, terminated segments, synthesized replies. `slices x
    /// slice_size` is the whole memory budget for traffic in flight, and
    /// exhaustion is a counted drop rather than a wait or an allocation.
    pub buffer_slices: NonZeroUsize,
    /// Datagrams one flow may have queued before further ones are dropped.
    pub datagrams_per_flow: NonZeroUsize,
    /// Live terminated connections. Each is a socket in the local stack.
    pub terminated_connections: NonZeroUsize,
    /// Datagram associations through a proxy egress, when there is one.
    pub associations: NonZeroUsize,
    /// Addresses remembered as belonging to an inspected host.
    pub inspected_addresses: NonZeroUsize,
    /// Fragmented packets held awaiting the rest of themselves.
    pub pending_reassemblies: NonZeroUsize,
}

impl Default for Ceilings {
    /// Sized for a phone, because that is where this runs and where being wrong
    /// gets the process killed. A desktop host should raise them.
    fn default() -> Self {
        let at_least = |count: usize| NonZeroUsize::new(count).expect("a positive constant");
        Self {
            // 2048 x 2 KiB is about 4 MiB of traffic in flight.
            buffer_slices: at_least(2048),
            datagrams_per_flow: at_least(32),
            terminated_connections: at_least(512),
            associations: at_least(256),
            inspected_addresses: at_least(1024),
            pending_reassemblies: at_least(64),
        }
    }
}

/// The size of one pooled buffer.
///
/// **Not configurable, and the reason is a correctness argument rather than a
/// preference.** A slice must hold the largest thing this crate ever forwards —
/// a full-MTU packet plus the local stack's framing — so a host that set it
/// small would not save memory, it would turn every large packet into a counted
/// drop. It is derived from [`Link::mtu`] instead.
const SLICE_HEADROOM: usize = 128;

// ------------------------------------------------------------ Errors

/// A configuration this crate will not run, and why.
///
/// **Every variant is a combination that would run and do nothing**, rather
/// than one that would crash. Those are the dangerous ones: a tunnel that
/// carries traffic while filtering none of it reports itself healthy, and the
/// user discovers it months later.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// Filtering was asked for, names are passed through, and the egress
    /// carries packets. On the fast path a flow is inspected because a DNS
    /// answer named its address, so this combination would inspect nothing
    /// while looking configured. Give it a [`Resolver::Local`].
    NothingToFilter,
    /// Interception was asked for with no hosts. Forging certificates for the
    /// empty set is the DNS tier with extra machinery, so say that instead.
    NoHostsToIntercept,
    /// A host in the interception list is not a name. The offending text is
    /// carried so the host can tell the user which line to fix.
    NotAHost(String),
    /// The link's MTU cannot absorb the egress's own overhead.
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

/// Why a tunnel did not start.
#[non_exhaustive]
#[derive(Debug)]
pub enum StartError {
    /// The configuration was refused before anything was built.
    Config(ConfigError),
    /// The certificate authority could not be opened. A
    /// [`CaError::Material`] here means stored key material was lost or
    /// corrupted, and the host's recovery is to generate afresh and ask the
    /// user to trust the new root.
    Authority(CaError),
    /// An egress could not be constructed from its configuration.
    Egress(EgressError),
    /// The datapath refused the combination it was handed. Distinct from
    /// [`Self::Config`] because it comes from the layer that owns the
    /// invariant rather than from this one's restatement of it.
    Datapath(DatapathError),
    /// A socket the tunnel needs could not be opened through the bypass.
    Io(std::io::ErrorKind),
    /// The local terminator cannot serve every inspected port under the
    /// [`Ceilings::terminated_connections`] it was given. Raise it.
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

/// A configuration that has been checked, with everything the builder needs
/// derived once.
///
/// **The point of parsing into this is that the builder below is total.** Every
/// question a builder would otherwise ask mid-construction — does this
/// terminate, does it need a relay, does it need an authority — is answered
/// here, before a socket exists, so there is no half-built tunnel to unwind.
#[derive(Debug)]
struct Plan {
    filter: FilterPolicy,
    dns: DnsPolicy,
    accepts: Accepts,
    /// Flows are terminated locally, so a TCP stack and a session driver are
    /// needed. True whenever the egress carries flows — there is no packet to
    /// forward — and whenever anything is intercepted.
    terminates: bool,
    /// Datagrams need an association through the egress rather than a packet
    /// on the fast path. Exactly when the egress carries flows: a datagram is
    /// never itself inspected, so interception does not move this.
    relays: bool,
}

impl TunnelConfig {
    /// The one boundary an untrusted configuration crosses to become a running
    /// tunnel.
    ///
    /// O(hosts + lists), dominated by compiling the rules.
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

        // The datapath refuses this combination too, and rightly — but it
        // refuses it after a pool, an egress, and a device have been built,
        // and with a name that describes the core rather than the choice a
        // person made. Saying it here is what makes the message actionable.
        if filter == FilterPolicy::InspectHttp
            && dns == DnsPolicy::Forward
            && accepts == Accepts::IpPackets
        {
            return Err(ConfigError::NothingToFilter);
        }
        // Filtering names without seeing questions is the same emptiness one
        // tier down, and it is worth the same refusal.
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
    /// The layer this choice implies. Derived rather than configured, which is
    /// what keeps a variant from disagreeing with its own layer.
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

/// What a host learns while a tunnel runs.
///
/// **Deliberately narrower than the core's own telemetry**, which names DNS
/// record types, steering reasons, and per-flow endpoints. Those are how Boreas
/// works today; a host that displayed them would be pinned to that. What is
/// here is what a user interface can show and an operator can act on.
///
/// Counting variants report occurrences *since the previous report*, on a fixed
/// interval, so an observer sums rather than diffs — and so a flood costs one
/// message per interval rather than one per packet.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// One name was decided.
    Resolved {
        name: String,
        /// Whether the answer was refused rather than forwarded.
        blocked: bool,
        /// The rule that decided it, when one did.
        rule: Option<String>,
    },
    /// Rules were reloaded, and how many of each are now in force.
    Reloaded {
        allowed: usize,
        blocked: usize,
        inspected: usize,
    },
    /// Aggregated counters since the previous one of these.
    Counted(Counters),
}

/// Occurrences since the previous [`Event::Counted`].
///
/// **Every field is a thing that went wrong or a thing that was refused.** A
/// tunnel working normally reports zeroes, so a host can treat any non-zero
/// field as worth showing without knowing what any of them mean.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    /// Datagrams dropped because a queue was full or the buffer budget was
    /// spent. Ordinary under load; sustained means [`Ceilings`] is too small
    /// for this device's traffic.
    pub datagrams_dropped: u64,
    /// Packets that did not parse. Sustained means something upstream is
    /// producing malformed traffic.
    pub packets_rejected: u64,
    /// QUIC attempts refused so the browser falls back to HTTP/2, which is what
    /// makes an inspected host inspectable. Expected to be non-zero whenever
    /// interception is on, and expected to fall as browsers cache the fallback.
    pub quic_steered: u64,
    /// Over-sized packets answered with an ICMP Packet Too Big. **A number that
    /// stays high is a misconfiguration**: the TUN's MTU was set wider than
    /// [`Link::mtu`] says, so the client keeps sending what the tunnel cannot
    /// carry.
    pub paths_reported: u64,
    /// Events this tunnel produced and could not deliver, because the host was
    /// not reading them fast enough. Counted so a gap never reads as quiet.
    pub events_lost: u64,
}

// ------------------------------------------------------- Running tunnel

/// A running tunnel.
///
/// Dropping this does **not** stop it: the tasks own their own handles and a
/// dropped `Tunnel` leaves them running until the process ends. Call
/// [`Self::stop`], which cancels and waits — an ordered shutdown is what
/// returns every pooled buffer and closes every socket, and a tunnel that
/// vanished without one would leave the device's routes pointing at nothing.
pub struct Tunnel {
    shell: Shell,
    /// Republishes compiled rules to the resolver without restarting anything.
    /// A rebuild replaces the whole index at once, so no query is ever decided
    /// against half a list.
    policy: watch::Sender<Arc<HostPolicy>>,
    /// The tasks this tunnel spawned besides the shell's two: the terminator,
    /// the session driver, the relay.
    tasks: TaskTracker,
    shutdown: CancellationToken,
    /// Present exactly when this tunnel intercepts, which is exactly when there
    /// is an authority to keep.
    authority: Option<Arc<CertificateAuthority>>,
}

impl Tunnel {
    /// The material a host must store, and the root a user must trust.
    ///
    /// `None` when this tunnel does not intercept, which is also when there is
    /// nothing to store: a host can call this unconditionally and write
    /// whatever it gets.
    pub fn authority(&self) -> Option<CaMaterial> {
        self.authority.as_ref().map(|ca| ca.material())
    }

    /// The next thing worth telling a user, or `None` once the tunnel has
    /// stopped.
    ///
    /// Cancel-safe: dropping the future loses nothing, because the event stays
    /// in the channel until it is taken.
    pub async fn next_event(&mut self) -> Option<Event> {
        loop {
            let telemetry = self.shell.next_telemetry().await?;
            if let Some(event) = project(telemetry) {
                return Some(event);
            }
        }
    }

    /// Replaces the rules in force, without restarting the tunnel or dropping a
    /// connection.
    ///
    /// **A whole list set, never a delta.** A rebuild compiles a fresh index
    /// and publishes it in one write, so every query is decided against exactly
    /// one version — the one current when it was admitted. Applying edits
    /// incrementally would make "which rules did this query see" a question
    /// with no answer.
    ///
    /// O(total list length). Returns what is now in force.
    pub fn reload(&self, lists: &[String]) -> Event {
        let policy = compile(lists);
        let counts = policy.len();
        // The receiver is held by tasks this tunnel owns, so a send fails only
        // after `stop`, where a reload is a no-op rather than an error.
        let _ = self.policy.send(Arc::new(policy));
        Event::Reloaded {
            allowed: counts.allowed,
            blocked: counts.blocked,
            inspected: counts.inspected,
        }
    }

    /// Stops the tunnel and waits for every task it started.
    ///
    /// Ordered, and the order is the point: admission closes first, so nothing
    /// new is accepted while what is in flight finishes. When this returns,
    /// every socket is closed and every pooled buffer is back.
    pub async fn stop(self) -> std::io::Result<()> {
        self.shutdown.cancel();
        self.tasks.close();
        self.tasks.wait().await;
        self.shell.shutdown().await
    }
}

/// Compiles filter-list text into the index a query is decided against.
///
/// Malformed lines are counted and skipped rather than refused: a list is
/// fetched from the internet and one bad line in fifty thousand must not cost a
/// user their whole rule set.
fn compile(lists: &[String]) -> HostPolicy {
    let mut policy = HostPolicy::new();
    for list in lists {
        let _ = policy.extend_from_list(list);
    }
    policy
}

/// Narrows the core's telemetry to what a host should see.
///
/// `None` for everything that is an implementation detail, which is most of it:
/// a variant that is not projected is one a host was never told about and
/// therefore one this crate is free to change.
fn project(telemetry: crate::Telemetry) -> Option<Event> {
    use crate::Telemetry;
    Some(match telemetry {
        Telemetry::Resolved(resolution) => Event::Resolved {
            name: resolution.name.to_string(),
            // A refusal is answered from policy without anything leaving the
            // device, which is exactly what `Provenance::Policy` records --
            // and it is a stronger test than reading the response code, since
            // a forwarded answer can carry NXDOMAIN for reasons of its own.
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
        // Per-flow lifecycle, reassembly, and the internal refusal counters are
        // this crate's business. A host that needed one of them would be
        // debugging Boreas rather than running it.
        Telemetry::Event(_)
        | Telemetry::ReassemblyDiscarded(_)
        | Telemetry::TransmitsDropped(_)
        | Telemetry::EgressRejected(_)
        | Telemetry::QueriesDropped(_)
        | Telemetry::TerminationDropped(_) => return None,
    })
}

// ------------------------------------------------------ Composition

/// The DNS upstreams, as one type.
///
/// [`crate::DnsUpstream`] returns `impl Future`, so it is not object-safe and a
/// runtime-chosen upstream cannot be a `Box<dyn _>`. Dispatching over a closed
/// sum is the standard answer and the better one here anyway: the set of
/// transports is fixed by what DNS has, not by what a host might invent.
enum AnyUpstream<B> {
    Do53(crate::Do53Upstream<B>),
    Dot(crate::DotUpstream<B>),
    Doh(crate::DohUpstream<B>),
    Doq(crate::DoqUpstream<B>),
    /// A tunnel that forwards questions never asks one, so this is never
    /// consulted. It exists because [`Shell`] takes an upstream by value and
    /// `Option` there would put a branch on a path that has none.
    Unused,
}

impl<B: TunnelBypass> crate::DnsUpstream for AnyUpstream<B> {
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
                // Verification stays at quiche's default, which verifies. The
                // factory exists so this crate's own tests can point at a
                // throwaway resolver; a host has no business relaxing it.
                Box::new(crate::DoqUpstream::<B>::quic_config),
            )),
        })
    }
}

/// The network socket a packet egress's encapsulated datagrams travel on.
///
/// A flow egress has none — its bytes go out through the proxy's own
/// connections — but [`Shell`] takes one by value, so the absence is a variant
/// rather than an `Option` the reactor would have to branch on per datagram.
enum Underlay {
    Peer(tokio::net::UdpSocket),
    /// Never ready, never writable. A reactor selecting over it simply never
    /// wins that arm.
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
                crate::shell::whole(sent, buf.len())
            }
            Self::Absent => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "this tunnel's egress carries flows, not packets",
            )),
        }
    }
}

impl Tunnel {
    /// Builds and starts everything, on the current tokio runtime.
    ///
    /// **This is the only place the whole thing is assembled**, and that is
    /// deliberate: a datapath, a reactor, a TCP stack, a session driver, a
    /// datagram relay, and a resolver are six components joined by nine
    /// channels whose directions are not guessable, and every host that had to
    /// wire them itself would wire them slightly differently.
    ///
    /// The configuration is checked in full before a socket is opened, so a
    /// refusal leaves nothing to unwind and nothing half-started.
    pub async fn start<D, B>(
        config: TunnelConfig,
        platform: Platform<D, B>,
    ) -> Result<Self, StartError>
    where
        D: AsyncDevice + Send + 'static,
        B: TunnelBypass + Clone + 'static,
    {
        let plan = config.plan()?;
        // Destructured once, so every step below moves what it needs instead of
        // borrowing a whole configuration and cloning out of it. A pre-shared
        // key that was cloned would outlive the value the host meant to hand
        // over exactly once.
        let TunnelConfig {
            egress,
            resolver,
            filtering,
            link,
            ceilings,
        } = config;
        let Platform { device, bypass } = platform;

        // One budget for everything in flight. The slice holds a full-MTU
        // packet plus the local stack's framing, which is why it is derived
        // from the link rather than configured.
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
        let (policy_tx, policy_rx) = watch::channel(Arc::new(compile(&filtering.lists)));

        // The terminator and the session driver, when flows are terminated.
        let (termination, authority) = if plan.terminates {
            let (built, authority) = start_termination(
                filtering,
                &link,
                &ceilings,
                Arc::clone(&assembly.flows),
                Arc::clone(&pool),
                &tasks,
                &shutdown,
            )?;
            (Some(built), authority)
        } else {
            (None, None)
        };

        // The datagram relay, when datagrams travel as associations rather than
        // as packets.
        let relay = plan.relays.then(|| {
            let (outbound_tx, outbound_rx) = mpsc::channel(CHANNEL_DEPTH);
            let (inbound_tx, inbound_rx) = mpsc::channel(CHANNEL_DEPTH);
            // The relay reports its own refusals on a channel of its own; they
            // are folded into the same counters everything else is.
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
                shutdown.clone(),
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

/// Depth of the channels joining this tunnel's tasks. Bounded is the point; the
/// exact depth trades burst tolerance against queueing delay, and the shell
/// uses the same number for the same reason.
const CHANNEL_DEPTH: usize = 256;

/// Spawns the local TCP stack and the session driver, and opens the authority
/// if this tunnel intercepts.
///
/// Returns the reactor's half of the terminator's channels, and the authority
/// to keep. The authority is `None` for a tunnel that terminates without
/// intercepting — a flow egress with no interception still needs a TCP stack,
/// because there is no packet to forward, but it forges no certificates.
fn start_termination(
    filtering: Filtering,
    link: &Link,
    ceilings: &Ceilings,
    flows: Arc<dyn StreamEgress>,
    pool: Arc<BufferPool>,
    tasks: &TaskTracker,
    shutdown: &CancellationToken,
) -> Result<(crate::Termination, Option<Arc<CertificateAuthority>>), StartError> {
    let stack = LocalStack::new(
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

    let (packets_tx, packets_rx) = mpsc::channel(CHANNEL_DEPTH);
    let (replies_tx, replies_rx) = mpsc::channel(CHANNEL_DEPTH);
    let (accepted_tx, accepted_rx) = mpsc::channel(CHANNEL_DEPTH);

    tasks.spawn(crate::run_terminator(
        stack,
        packets_rx,
        replies_tx,
        accepted_tx,
        shutdown.clone(),
    ));

    let Filtering {
        lists,
        interception,
    } = filtering;
    let Some(interception) = interception else {
        // Terminated but not intercepted: the session driver still runs,
        // because a terminated flow needs re-originating whether or not anyone
        // reads it, and its allowlist is empty so every host is spliced.
        let sessions = build_sessions(lists, None, ceilings, flows, None)?;
        tasks.spawn(crate::run_sessions(accepted_rx, sessions, shutdown.clone()));
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
    tasks.spawn(crate::run_sessions(accepted_rx, sessions, shutdown.clone()));

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
    // An authority is needed to build an interceptor at all, so a tunnel that
    // terminates without intercepting gets a throwaway one whose leaves are
    // never minted: the allowlist below is empty, so every host is spliced
    // before a certificate is asked for.
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

/// Turns the configuration's ceilings into the core's own limits.
fn limits(link: &Link, ceilings: &Ceilings, plan: &Plan) -> Limits {
    Limits {
        reassembly_timeout: std::time::Duration::from_secs(30),
        max_pending_reassemblies: ceilings.pending_reassemblies,
        // RFC 4787 REQ-5's floor. Not configurable: a shorter mapping is one a
        // NAT on the path would outlive, which turns a live flow into a black
        // hole, and `UdpFlowTable` refuses it anyway.
        flow_idle_timeout: std::time::Duration::from_secs(120),
        datagram_buffer_capacity: ceilings.datagrams_per_flow,
        // Long enough to outlast a browser's cached Alt-Svc entry for an
        // origin, which the DNS rewrite alone cannot reach.
        inspection_window: std::time::Duration::from_secs(60),
        max_inspected_addresses: ceilings.inspected_addresses,
        inspected_ports: crate::DEFAULT_INSPECTED_PORTS,
        origination_ports: plan.terminates.then_some(link.origination_ports),
    }
}

/// Builds the configured egress, and the network socket a packet egress needs.
async fn build_egress<B: TunnelBypass + Clone + 'static>(
    choice: Egress,
    bypass: &B,
    pool: &Arc<BufferPool>,
) -> Result<(crate::Egress, Underlay), StartError> {
    // Every arm moves its configuration in rather than cloning it: a
    // configuration is consumed to build a tunnel, and the one thing a host
    // would notice about a clone here is the copy of its pre-shared key that
    // stayed alive afterwards.
    Ok(match choice {
        Egress::Direct { nat_behavior } => (
            crate::Egress::Stream(Box::new(DirectEgress::new(bypass.clone(), nat_behavior))),
            Underlay::Absent,
        ),
        Egress::WireGuard { peer, config } => {
            // The socket the peer is reached on. Through the bypass, because a
            // tunnel whose own underlay went through itself is the loop this
            // crate exists on the other side of.
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

    /// A device that never produces a packet and swallows what it is given.
    /// Enough to start a tunnel, which is what these tests are about.
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

    /// **The composition nothing in this repository did before.** A datapath, a
    /// reactor, a TCP stack, a session driver, a datagram relay, and a resolver
    /// are six components joined by nine channels; this is the test that says
    /// they join.
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

    /// The same tunnel with nothing intercepted: it still terminates, because a
    /// flow egress has no packet to forward, but it forges nothing and so has
    /// nothing for the host to store.
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

    /// **The root a user trusted comes back.** This is the whole persistence
    /// story observed from the outside: a host stores what the first tunnel
    /// handed it, and the second mints under the same root.
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

    /// **Every refusal here is a configuration that would run and filter
    /// nothing.** Those are the dangerous ones: the tunnel reports itself
    /// healthy and the user finds out months later.
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

    /// A host that is not a name is a line in a settings screen the user
    /// mistyped, so the offending text comes back with the error rather than
    /// being silently dropped from the list.
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

    /// The layer follows from the variant and cannot be stated separately,
    /// which is what stops a configuration from claiming a layer its egress
    /// does not accept.
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
