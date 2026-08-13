//! Session assembly: what actually happens to a terminated connection.
//!
//! Everything below this module produces a part — `LocalStack` terminates a
//! TCP connection, `Interceptor` forges a leaf, `run_exchange` serves an HTTP
//! exchange, `StreamEgress` opens a byte stream to a target — and none of them
//! decides. This is the decision, and it is the last edge in P14's graph: it
//! consumes an [`Accepted`] connection, applies [`InterceptPolicy`], and either
//! terminates and inspects or splices byte for byte.
//!
//! **The host is not known when the connection arrives, and that is the whole
//! problem this module solves.** A terminated flow carries an IP address and a
//! port; the allowlist names *hosts*. The name lives in the TLS ClientHello's
//! SNI extension, which arrives in the client's first bytes — before any
//! handshake this process participates in. So the first thing here is a parser
//! that reads those bytes without consuming them, and the rest follows from
//! what it finds.
//!
//! **Fail open is a property of the type, not of the control flow.**
//! [`Introduction`] has exactly three shapes and only one of them can lead to
//! interception: a TLS record, carrying an SNI, naming a host the policy
//! admits. Everything else — a name that is not allowlisted, a ClientHello with
//! no SNI, bytes that are not TLS at all, a client that says nothing before the
//! deadline — reaches [`Handling::Spliced`] with a reason attached. There is no
//! path on which a parse failure intercepts, because the parser has no failure
//! case: it can only fail to *recognise*, and non-recognition is splice.
//!
//! **No version is crossed, by construction rather than by agreement.** The
//! client's ALPN settles the wire; the upstream connection is then offered that
//! one protocol and no other. A server that will not speak it fails the
//! handshake, which is a visible error, rather than negotiating something else
//! and leaving the exchange to bridge between versions.
//!   [`VersionCrossings`] still counts, because a gate that can only be
//! satisfied and never checked is not a gate.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncReadExt, copy_bidirectional},
    sync::mpsc,
};
use tokio_util::sync::CancellationToken;

use crate::{
    Accepted, CosmeticSource, Demotion, Demotions, DomainName, EgressError, InterceptDecision,
    InterceptPolicy, Interceptor, Leg, NoCosmetics, Prefixed, RequestFilter, RewriteFailures,
    Rewriting, Standing, StreamBudget, StreamEgress, Target, Tier, VersionCrossings, Wire,
    classify, run_exchange, transport::client_tls_config,
};

/// A TLS record carrying handshake messages.
const RECORD_HANDSHAKE: u8 = 0x16;
/// The major version byte every TLS record since 1.0 carries, including 1.3,
/// whose real version lives in an extension.
const RECORD_MAJOR: u8 = 0x03;
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const EXTENSION_SERVER_NAME: u16 = 0x0000;
const NAME_TYPE_HOST: u8 = 0x00;

/// A TLS record's payload cannot exceed 2^14 bytes, so a ClientHello that has
/// not arrived within one record plus its header is one this module will not
/// wait for.
const MAX_RECORD: usize = (1 << 14) + 5;

/// What the client's first bytes reveal.
///
/// Three states, and the sum is the safety argument: only [`Self::Tls`] with a
/// name can lead to interception, so every other outcome — including every
/// malformed input — splices without a branch having to remember to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Introduction {
    /// Not enough bytes to tell yet. The caller reads more and asks again.
    Incomplete,
    /// A TLS handshake record. `host` is the SNI when one is present and
    /// well-formed, and `None` when the ClientHello carries no server name,
    /// spans more than one record, or is malformed inside a complete record —
    /// all of which are indistinguishable to a policy that needs a name.
    Tls { host: Option<DomainName> },
    /// The first bytes are not a TLS handshake record: cleartext HTTP, or any
    /// other protocol on a port the datapath routed here.
    Plain,
}

/// Reads the client's first bytes without consuming them.
///
/// Total on untrusted input: there is no error case, because every byte
/// sequence is *some* [`Introduction`], and the ones this cannot interpret are
/// the ones that splice. That is deliberate — a parser with an error case would
/// force every caller to choose a fallback, and one of them would eventually
/// choose to intercept.
///
/// O(n) in the bytes examined, bounded by one TLS record, with one allocation
/// for the returned name and none otherwise.
pub fn introduce(bytes: &[u8]) -> Introduction {
    // TLS record header: type(1), legacy version(2), length(2).
    let Some(header) = bytes.get(..5) else {
        return Introduction::Incomplete;
    };
    if header[0] != RECORD_HANDSHAKE || header[1] != RECORD_MAJOR {
        return Introduction::Plain;
    }
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    let Some(record) = bytes.get(5..5 + length) else {
        return Introduction::Incomplete;
    };
    Introduction::Tls {
        host: server_name(record),
    }
}

/// Pulls the SNI out of one handshake record, or `None` for every reason a name
/// might not be there.
///
/// One forward pass over the record; each step either advances or gives up, so
/// this terminates on any input.
fn server_name(record: &[u8]) -> Option<DomainName> {
    let mut reader = Reader::new(record);
    if reader.u8()? != HANDSHAKE_CLIENT_HELLO {
        return None;
    }
    // A handshake body longer than this record is a ClientHello fragmented
    // across records. Legal, vanishingly rare, and not reassembled here: the
    // result is a splice, which is the safe answer rather than a wrong one.
    let body = reader.u24().and_then(|length| reader.take(length))?;

    let mut hello = Reader::new(body);
    hello.take(2)?; // legacy_version
    hello.take(32)?; // random
    hello.vector_u8()?; // legacy_session_id
    hello.vector_u16()?; // cipher_suites
    hello.vector_u8()?; // legacy_compression_methods
    let extensions = hello.vector_u16()?;

    // Extensions are a sequence, not a map, so this is a scan. It is O(bytes)
    // rather than O(extensions) times anything: each header is read once and
    // its body skipped by length.
    let mut reader = Reader::new(extensions);
    while let Some(kind) = reader.u16() {
        let body = reader.vector_u16()?;
        if kind != EXTENSION_SERVER_NAME {
            continue;
        }
        // ServerNameList: a vector of (name_type, opaque name). RFC 6066 allows
        // at most one entry per type, and `host_name` is the only type defined,
        // so the first one that matches is the answer.
        let mut names = Reader::new(body.get(2..)?);
        while let Some(name_type) = names.u8() {
            let name = names.vector_u16()?;
            if name_type == NAME_TYPE_HOST {
                // The name crosses into the domain through the same smart
                // constructor every other host does, so an over-long or
                // NUL-bearing SNI is rejected here rather than downstream.
                return std::str::from_utf8(name)
                    .ok()
                    .and_then(|host| DomainName::new(host).ok());
            }
        }
        return None;
    }
    None
}

/// A forward cursor over untrusted bytes. Every accessor is total: it returns
/// `None` rather than panicking, so the parser above never indexes.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let taken = self.bytes.get(..length)?;
        self.bytes = &self.bytes[length..];
        Some(taken)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|byte| byte[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u24(&mut self) -> Option<usize> {
        self.take(3).map(|bytes| {
            usize::from(bytes[0]) << 16 | usize::from(bytes[1]) << 8 | usize::from(bytes[2])
        })
    }

    /// A length-prefixed vector with a one-byte length, returning its body.
    fn vector_u8(&mut self) -> Option<&'a [u8]> {
        let length = usize::from(self.u8()?);
        self.take(length)
    }

    /// A length-prefixed vector with a two-byte length, returning its body.
    fn vector_u16(&mut self) -> Option<&'a [u8]> {
        let length = usize::from(self.u16()?);
        self.take(length)
    }
}

/// Why a connection was spliced. Recorded rather than discarded: "spliced"
/// alone cannot distinguish a working allowlist from a parser that stopped
/// recognising TLS, and those need different responses from an operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpliceReason {
    /// TLS naming a host the policy does not admit. The ordinary case.
    NotAllowlisted,
    /// TLS with no usable server name, so no policy decision is possible.
    Unnamed,
    /// Not a TLS handshake.
    NotTls,
    /// The client said nothing conclusive before the deadline, or sent more
    /// than one record's worth without completing one.
    Undecided,
    /// Allowlisted, and interception is known not to work here. The
    /// machine-maintained half of the decision, and the one that lets the
    /// hand-maintained half grow.
    Demoted(Demotion),
}

/// What became of one connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Handling {
    /// Terminated and served, at the tier the host's history permitted.
    Intercepted {
        host: DomainName,
        wire: Wire,
        tier: Tier,
    },
    Spliced {
        reason: SpliceReason,
    },
    /// The connection failed in a way that proved interception cannot work
    /// here, and the proof was recorded. Not an error: the connection is lost
    /// either way, and what distinguishes this from a failure is that the next
    /// one will not repeat it.
    Demoted {
        host: DomainName,
        cause: Demotion,
    },
}

#[derive(Debug)]
pub enum SessionError {
    /// The upstream could not be reached, or refused the protocol the client
    /// settled on.
    Upstream(EgressError),
    /// The client's TLS handshake failed against the forged leaf. Routine: it
    /// is what a client that pins, or that rejects the local root, does.
    ClientHandshake(std::io::Error),
    /// Copying failed mid-flow.
    Transfer(std::io::Error),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Upstream(error) => write!(f, "upstream unreachable: {error}"),
            Self::ClientHandshake(error) => write!(f, "client handshake failed: {error}"),
            Self::Transfer(error) => write!(f, "transfer failed: {error}"),
        }
    }
}

impl std::error::Error for SessionError {}

/// Bounds on the part of a session that happens before any policy applies.
#[derive(Clone, Copy, Debug)]
pub struct SessionLimits {
    /// How long a client may take to say something conclusive.
    ///
    /// It exists because a connection that sends nothing would otherwise hold a
    /// task and a socket indefinitely, which is a denial of service that costs
    /// an attacker one `connect`. On expiry the connection is spliced, not
    /// dropped: a silent client may simply be a protocol whose server speaks
    /// first.
    pub peek_timeout: Duration,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            // Long enough for a first packet on a slow mobile path, short
            // enough that holding one costs an attacker more than it costs us.
            peek_timeout: Duration::from_secs(5),
        }
    }
}

/// Everything a session needs that is the same for every session.
///
/// One value, shared by `Arc` across connections, because each field is
/// expensive to build and immutable in use: the anchor set is parsed once, the
/// forged-leaf cache is shared so a second connection to a host reuses the
/// first's certificate, and the crossing counter must be one counter.
pub struct Sessions {
    pub interceptor: Arc<Interceptor>,
    pub policy: Arc<InterceptPolicy>,
    /// Where both spliced and intercepted flows leave by. An intercepted
    /// connection's upstream leg goes through the same egress as everything
    /// else — interception changes what Boreas can *read*, never where traffic
    /// exits.
    pub egress: Arc<dyn StreamEgress>,
    pub filter: Arc<dyn RequestFilter>,
    pub crossings: Arc<VersionCrossings>,
    /// What interception has been observed to fail at, per host. The
    /// machine-maintained counterpart to `policy`: that one says which hosts a
    /// human chose to intercept, this one says which of them it turned out to
    /// work for.
    pub demotions: Arc<Demotions>,
    pub limits: SessionLimits,
    /// Where element-hiding rules come from. [`NoCosmetics`] by default, which
    /// makes the HTML tier inert rather than absent — a deployment with no
    /// cosmetic lists pays one virtual call per intercepted response and
    /// nothing else. In production this is the same
    /// [`RuleEngine`](crate::RuleEngine) that answers `filter`, so both tiers
    /// read one compiled index.
    cosmetic: Arc<dyn CosmeticSource>,
    budget: StreamBudget,
    /// One client configuration per wire, so the upstream leg can offer
    /// exactly the protocol the client settled on. Built once: a `ClientConfig`
    /// parses the trust anchors, which is not a per-connection cost.
    upstream: [Arc<rustls::ClientConfig>; 2],
}

impl Sessions {
    pub fn new(
        interceptor: Arc<Interceptor>,
        policy: Arc<InterceptPolicy>,
        egress: Arc<dyn StreamEgress>,
        filter: Arc<dyn RequestFilter>,
        limits: SessionLimits,
    ) -> Result<Self, EgressError> {
        Ok(Self {
            interceptor,
            policy,
            egress,
            filter,
            crossings: Arc::new(VersionCrossings::new()),
            demotions: Arc::new(Demotions::new()),
            limits,
            cosmetic: Arc::new(NoCosmetics),
            budget: StreamBudget::default(),
            upstream: [
                client_tls_config(&[b"http/1.1".to_vec()], &[])?,
                client_tls_config(&[b"h2".to_vec()], &[])?,
            ],
        })
    }

    /// Trusts `extra_roots` in addition to the bundled anchors on the upstream
    /// leg. For a test origin, or a deployment behind a private CA.
    pub fn with_upstream_roots(mut self, extra_roots: &[Vec<u8>]) -> Result<Self, EgressError> {
        self.upstream = [
            client_tls_config(&[b"http/1.1".to_vec()], extra_roots)?,
            client_tls_config(&[b"h2".to_vec()], extra_roots)?,
        ];
        Ok(self)
    }

    /// Applies compiled cosmetic rules to intercepted responses.
    ///
    /// Separate from [`Self::new`] because the rule set is swapped rather than
    /// edited: a list rebuild produces a new [`RuleEngine`](crate::RuleEngine)
    /// and a new `Sessions`, so no connection ever observes a half-applied list.
    #[must_use]
    pub fn with_cosmetic_rules(
        mut self,
        cosmetic: Arc<dyn CosmeticSource>,
        budget: StreamBudget,
    ) -> Self {
        self.cosmetic = cosmetic;
        self.budget = budget;
        self
    }

    /// The HTML tier this connection gets, given what the host's history
    /// permits. [`Tier::Splice`] cannot reach here — it is answered before any
    /// termination — and maps to the same inert value as [`Tier::Inspect`].
    fn rewriting(&self, tier: Tier, failures: &Arc<RewriteFailures>) -> Rewriting {
        match tier {
            Tier::Rewrite => Rewriting::On {
                source: Arc::clone(&self.cosmetic),
                budget: self.budget,
                failures: Arc::clone(failures),
            },
            Tier::Inspect | Tier::Splice => Rewriting::Off,
        }
    }

    fn upstream_config(&self, wire: Wire) -> Arc<rustls::ClientConfig> {
        match wire {
            Wire::Http1 => Arc::clone(&self.upstream[0]),
            Wire::Http2 => Arc::clone(&self.upstream[1]),
        }
    }
}

/// Serves one terminated connection to completion.
///
/// `server` is where the client was trying to go, which the datapath knows and
/// the stream does not. It takes the stream and that address rather than an
/// [`Accepted`] because the stream *id* is the terminator's bookkeeping and
/// means nothing here — and because a function that needs only what it uses can
/// be driven by a test without standing up a socket set.
///
/// Returns what was decided, which is the value a caller counts; an `Err` means
/// the connection could not be served at all, not that it was spliced.
pub async fn serve_session(
    stream: crate::TerminatedStream,
    server: std::net::SocketAddr,
    sessions: Arc<Sessions>,
) -> Result<Handling, SessionError> {
    let port = server.port();
    let (introduction, peeked, stream) = peek(stream, sessions.limits.peek_timeout).await;

    let host = match introduction {
        Introduction::Tls { host: Some(host) } => host,
        Introduction::Tls { host: None } => {
            return splice(sessions, server, peeked, stream, SpliceReason::Unnamed).await;
        }
        Introduction::Plain => {
            return splice(sessions, server, peeked, stream, SpliceReason::NotTls).await;
        }
        Introduction::Incomplete => {
            return splice(sessions, server, peeked, stream, SpliceReason::Undecided).await;
        }
    };
    if sessions.policy.decide(host.as_str()) == InterceptDecision::Splice {
        return splice(
            sessions,
            server,
            peeked,
            stream,
            SpliceReason::NotAllowlisted,
        )
        .await;
    }
    // **The allowlist says a human chose this host; the standing says whether
    // that choice worked.** P14 could only ask the first question, which is why
    // its list had to stay short enough to maintain by hand.
    let standing = sessions.demotions.standing(host.as_str(), Instant::now());
    if let Standing::Limited(cause) = standing
        && cause.tier() == Tier::Splice
    {
        return splice(
            sessions,
            server,
            peeked,
            stream,
            SpliceReason::Demoted(cause),
        )
        .await;
    }
    let tier = standing.tier();

    // **The client's handshake comes first, and the order is forced.** The
    // upstream leg must offer exactly one ALPN — that is what makes a crossed
    // version unrepresentable rather than merely counted — and the protocol to
    // offer is the one the client settles on, which is not known until its
    // handshake completes.
    //
    // It is also what makes the first failed connection unrecoverable: by the
    // time the client rejects the forged leaf, the leaf has been sent, and no
    // bytes remain to splice with. That cost is stated in [`crate::Demotions`]
    // and is the reason demotion is measured on the *retry*.
    let replayed = Prefixed::new(peeked, stream);
    let (client, wire) = match sessions.interceptor.terminate(replayed).await {
        Ok(terminated) => terminated,
        Err(error) => {
            return learn(&sessions, &host, Leg::Client, error, |error| {
                SessionError::ClientHandshake(error)
            });
        }
    };

    let target = Target::Domain {
        host: host.clone(),
        port,
    };
    let upstream = sessions
        .egress
        .connect(&target)
        .await
        .map_err(SessionError::Upstream)?;
    let server_name = rustls::pki_types::ServerName::try_from(host.as_str().to_owned())
        .map_err(|_| SessionError::Upstream(EgressError::Proxy(crate::ProxyError::Address)))?;
    let upstream = match tokio_rustls::TlsConnector::from(sessions.upstream_config(wire))
        .connect(server_name, upstream)
        .await
    {
        Ok(upstream) => upstream,
        Err(error) => {
            return learn(&sessions, &host, Leg::Upstream, error, |error| {
                SessionError::Upstream(EgressError::Io(error.kind()))
            });
        }
    };

    // An error here is the exchange ending, which includes every ordinary way a
    // connection closes, so it is reported as the handling that happened rather
    // than as a failure of the session.
    let failures = Arc::new(RewriteFailures::new());
    let _ = run_exchange(
        host.as_str(),
        wire,
        client,
        upstream,
        Arc::clone(&sessions.filter),
        Arc::clone(&sessions.crossings),
        sessions.rewriting(tier, &failures),
    )
    .await;
    // A rewrite that gave up is the last thing this connection proved, and it
    // is read once here rather than reported from inside a body poll — the
    // exchange has ended, which is the first moment acting on it is possible.
    if failures.count() > 0 {
        sessions
            .demotions
            .record(host.as_str(), Demotion::RewriteExhausted, Instant::now());
    }
    Ok(Handling::Intercepted { host, wire, tier })
}

/// Records what a failed handshake proved, if it proved anything.
///
/// A conclusive failure is not an error of the session. The connection is lost
/// either way; what distinguishes the two outcomes is whether the next
/// connection to this host will repeat it, and a recorded demotion is exactly
/// the promise that it will not. Everything else — a reset, a timeout, a peer
/// that vanished — proves nothing and stays an error.
fn learn(
    sessions: &Sessions,
    host: &DomainName,
    leg: Leg,
    error: std::io::Error,
    otherwise: impl FnOnce(std::io::Error) -> SessionError,
) -> Result<Handling, SessionError> {
    match classify(leg, &error) {
        Some(cause) => {
            sessions
                .demotions
                .record(host.as_str(), cause, Instant::now());
            Ok(Handling::Demoted {
                host: host.clone(),
                cause,
            })
        }
        None => Err(otherwise(error)),
    }
}

/// Reads until the client's first bytes are conclusive, the deadline passes, or
/// the client stops talking.
///
/// Returns the verdict, the bytes consumed to reach it, and the stream. The
/// bytes come back because a spliced connection must deliver them unchanged and
/// an intercepted one must let `rustls` read the very ClientHello this parsed:
/// peeking is a read that is put back, and [`Prefixed`] is how it is put back.
async fn peek(
    mut stream: crate::TerminatedStream,
    timeout: Duration,
) -> (Introduction, Vec<u8>, crate::TerminatedStream) {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        match introduce(&buf) {
            Introduction::Incomplete if buf.len() < MAX_RECORD => {}
            // A record header promised more than a record may hold, or the
            // client is silent past the cap. Either way there is nothing more
            // to learn by waiting.
            Introduction::Incomplete => return (Introduction::Incomplete, buf, stream),
            conclusive => return (conclusive, buf, stream),
        }
        let read = match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => return (introduce(&buf), buf, stream),
            Ok(Ok(read)) => read,
            // A failed read is a dead connection; the caller's splice will find
            // the same thing and end.
            Ok(Err(_)) => return (introduce(&buf), buf, stream),
        };
        buf.extend_from_slice(&chunk[..read]);
    }
}

/// Passes a connection through untouched.
///
/// **To the address the client chose, not to a name.** A splice is meant to be
/// indistinguishable from no proxy at all, and re-resolving the host would
/// substitute this process's view of DNS for the client's — which is a
/// different server, occasionally a different site, and never something the
/// client asked for. The name is used only where Boreas is already terminating.
async fn splice(
    sessions: Arc<Sessions>,
    server: std::net::SocketAddr,
    peeked: Vec<u8>,
    stream: crate::TerminatedStream,
    reason: SpliceReason,
) -> Result<Handling, SessionError> {
    let mut upstream = sessions
        .egress
        .connect(&Target::Ip(server))
        .await
        .map_err(SessionError::Upstream)?;
    let mut client = Prefixed::new(peeked, stream);
    copy_bidirectional(&mut client, &mut upstream)
        .await
        .map_err(SessionError::Transfer)?;
    Ok(Handling::Spliced { reason })
}

/// Serves every accepted connection until cancelled.
///
/// One task per connection, which is affordable here and nowhere else in this
/// crate: the cost is a wakeup per *connection*, not per packet, and the count
/// is already bounded by
/// [`TerminationLimits::max_sockets`](crate::TerminationLimits) — the same
/// admission rule that bounds the socket set. Nothing is spawned that the
/// terminator has not already admitted.
pub async fn run_sessions(
    mut accepted: mpsc::Receiver<Accepted>,
    sessions: Arc<Sessions>,
    shutdown: CancellationToken,
) {
    loop {
        let next = tokio::select! {
            () = shutdown.cancelled() => break,
            next = accepted.recv() => next,
        };
        let Some(Accepted { terminated, stream }) = next else {
            break;
        };
        let server = std::net::SocketAddr::new(terminated.server.address, terminated.server.port);
        let sessions = Arc::clone(&sessions);
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            tokio::select! {
                () = shutdown.cancelled() => {}
                _ = serve_session(stream, server, sessions) => {}
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real ClientHello, assembled field by field so the test states the
    /// layout rather than trusting an opaque blob.
    pub(super) fn client_hello(server_name: Option<&str>) -> Vec<u8> {
        let mut extensions = Vec::new();
        if let Some(name) = server_name {
            let mut entry = vec![NAME_TYPE_HOST];
            entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
            entry.extend_from_slice(name.as_bytes());

            let mut list = (entry.len() as u16).to_be_bytes().to_vec();
            list.extend_from_slice(&entry);

            extensions.extend_from_slice(&EXTENSION_SERVER_NAME.to_be_bytes());
            extensions.extend_from_slice(&(list.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&list);
        }
        // An extension that is not SNI, always present, so the scan is exercised
        // rather than finding its answer first.
        extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0x11; 32]); // random
        body.push(0); // legacy_session_id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites
        body.extend_from_slice(&[0x01, 0x00]); // compression methods
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);

        let mut record = vec![RECORD_HANDSHAKE, RECORD_MAJOR, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn a_client_hello_yields_its_server_name() {
        let hello = client_hello(Some("example.com"));
        assert_eq!(
            introduce(&hello),
            Introduction::Tls {
                host: Some(DomainName::new("example.com").unwrap()),
            }
        );
    }

    /// The law the peek loop depends on: no proper prefix of a ClientHello may
    /// decide anything, or a connection would be classified on a fragment and
    /// the classification could change when the rest arrived.
    #[test]
    fn every_proper_prefix_of_a_client_hello_is_incomplete() {
        let hello = client_hello(Some("example.com"));
        for cut in 0..hello.len() {
            assert_eq!(
                introduce(&hello[..cut]),
                Introduction::Incomplete,
                "a {cut}-byte prefix decided"
            );
        }
    }

    /// TLS without SNI must be distinguishable from "not TLS": both splice, but
    /// they are different facts about the connection and an operator diagnosing
    /// an allowlist needs to tell them apart.
    #[test]
    fn tls_without_a_server_name_is_tls_with_no_host() {
        assert_eq!(
            introduce(&client_hello(None)),
            Introduction::Tls { host: None }
        );
    }

    #[test]
    fn cleartext_is_recognised_as_not_tls() {
        assert_eq!(introduce(b"GET / HTTP/1.1\r\n"), Introduction::Plain);
        // A first byte that is a TLS record type but a version that is not
        // TLS 1.x: SSL 2.0's header, and anything else that happens to start
        // with 0x16.
        assert_eq!(
            introduce(&[0x16, 0x00, 0x01, 0x00, 0x05]),
            Introduction::Plain
        );
    }

    /// **The property that matters most.** No byte sequence may make the parser
    /// panic or hang, because every one of them is reachable from the network.
    /// Truncations, corruptions, and absurd lengths all have to land in the sum.
    #[test]
    fn no_mutation_of_a_client_hello_escapes_the_sum() {
        let hello = client_hello(Some("example.com"));
        for index in 0..hello.len() {
            for patch in [0x00u8, 0x01, 0x7f, 0xff] {
                let mut corrupted = hello.clone();
                corrupted[index] = patch;
                // The assertion is that this returns at all, in bounded time,
                // for every corruption of every byte.
                let _ = introduce(&corrupted);
            }
        }
        // A record header claiming far more than it carries stays incomplete
        // rather than reading past the buffer.
        assert_eq!(
            introduce(&[RECORD_HANDSHAKE, RECORD_MAJOR, 0x01, 0xff, 0xff, 0x01]),
            Introduction::Incomplete
        );
    }

    /// An SNI too long for a name, or carrying a NUL, must not become a
    /// `DomainName`: the refined type is the boundary, and an attacker chooses
    /// this string.
    #[test]
    fn a_hostile_server_name_is_refused_rather_than_admitted() {
        let long = "a".repeat(300);
        assert_eq!(
            introduce(&client_hello(Some(&long))),
            Introduction::Tls { host: None }
        );
        assert_eq!(
            introduce(&client_hello(Some("bad\0host"))),
            Introduction::Tls { host: None }
        );
    }
}

#[cfg(test)]
mod end_to_end {
    use super::*;
    use std::{
        net::{Ipv4Addr, SocketAddr},
        num::NonZeroUsize,
        sync::Arc,
    };

    use http_body_util::{BodyExt, Empty};
    use hyper_util::rt::TokioIo;
    use tokio::{
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream},
    };

    use crate::{
        AllowAll, AsyncStream, BoxFuture, CertificateAuthority, DatagramFidelity,
        EgressCapabilities, Interceptor, MitmResolver, NatBehavior, bridge,
    };

    const ALLOWED: &str = "allowed.example";
    const OTHER: &str = "other.example";

    /// A CA and a leaf for `host`, as DER. The origin presents the leaf; the
    /// session's upstream leg is told to trust the CA, exactly as a deployment
    /// behind a private CA would be.
    fn origin_certificate(
        host: &str,
    ) -> (
        Vec<u8>,
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ) {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.clone().self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);

        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec![host.to_owned()])
            .unwrap()
            .signed_by(&leaf_key, &issuer)
            .unwrap();

        (
            ca.der().to_vec(),
            vec![leaf.der().clone()],
            rustls::pki_types::PrivateKeyDer::try_from(leaf_key.serialize_der()).unwrap(),
        )
    }

    /// A real TLS origin answering `200 origin` to anything, on a real socket.
    async fn start_tls_origin(host: &str) -> (SocketAddr, Vec<u8>) {
        let (authority, chain, key) = origin_certificate(host);
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let service = hyper::service::service_fn(|_| async {
                        Ok::<_, std::convert::Infallible>(hyper::Response::new(
                            http_body_util::Full::new(bytes::Bytes::from_static(b"origin")),
                        ))
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                });
            }
        });
        (address, authority)
    }

    /// An origin that records the first bytes it is sent and echoes them, for
    /// proving a splice is byte-exact.
    async fn start_recording_origin() -> (SocketAddr, Arc<tokio::sync::Mutex<Vec<u8>>>) {
        let seen = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let recorded = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((mut tcp, _)) = listener.accept().await {
                let recorded = Arc::clone(&recorded);
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    while let Ok(read) = tcp.read(&mut buf).await {
                        if read == 0 {
                            break;
                        }
                        recorded.lock().await.extend_from_slice(&buf[..read]);
                        if tcp.write_all(&buf[..read]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        (address, seen)
    }

    /// An egress that dials one fixed address whatever it is asked for.
    ///
    /// It stands in for a configured proxy without needing one: what these
    /// tests exercise is the *assembly*, and a real egress is already verified
    /// against a reference server elsewhere.
    struct ToOrigin(SocketAddr);

    impl StreamEgress for ToOrigin {
        fn capabilities(&self) -> EgressCapabilities {
            EgressCapabilities {
                datagram_fidelity: DatagramFidelity::None,
                overhead_bytes: 0,
                max_datagram_size: None,
                preserves_ecn: false,
                nat_behavior: NatBehavior::EndpointIndependent,
            }
        }

        fn connect<'a>(
            &'a self,
            _target: &'a Target,
        ) -> BoxFuture<'a, Result<Box<dyn AsyncStream>, EgressError>> {
            Box::pin(async move {
                let stream = TcpStream::connect(self.0).await?;
                Ok(Box::new(stream) as Box<dyn AsyncStream>)
            })
        }
    }

    fn sessions_for(
        authority: Arc<CertificateAuthority>,
        allow: &[&str],
        origin: SocketAddr,
        upstream_roots: &[Vec<u8>],
    ) -> Arc<Sessions> {
        let resolver = Arc::new(MitmResolver::new(authority, NonZeroUsize::new(8).unwrap()));
        Arc::new(
            Sessions::new(
                Arc::new(Interceptor::new(resolver).unwrap()),
                Arc::new(InterceptPolicy::new(
                    allow.iter().map(|host| (*host).to_owned()),
                )),
                Arc::new(ToOrigin(origin)),
                Arc::new(AllowAll),
                SessionLimits::default(),
            )
            .unwrap()
            .with_upstream_roots(upstream_roots)
            .unwrap(),
        )
    }

    /// **The P14 through-line, in one test.** A real `rustls` client that trusts
    /// only the Boreas root speaks TLS to a connection this module classified
    /// from its SNI alone; the forged leaf validates, the request crosses an
    /// upstream TLS connection to a real origin, and the origin's body comes
    /// back. Nothing here is a stub except the egress's choice of address.
    #[tokio::test]
    async fn an_allowlisted_host_is_intercepted_end_to_end() {
        let (origin, origin_ca) = start_tls_origin(ALLOWED).await;
        let authority = Arc::new(CertificateAuthority::generate().unwrap());
        let root = authority.root_der().clone();
        let sessions = sessions_for(authority, &[ALLOWED], origin, &[origin_ca]);

        let (client_side, terminated) = bridge::duplex();
        let served = tokio::spawn(serve_session(terminated, origin, Arc::clone(&sessions)));

        // A client that trusts the Boreas root and nothing else, so a leaf this
        // process did not forge would fail here.
        let mut roots = rustls::RootCertStore::empty();
        roots.add(root).unwrap();
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(
                rustls::pki_types::ServerName::try_from(ALLOWED).unwrap(),
                client_side,
            )
            .await
            .expect("the forged leaf validates against the Boreas root");

        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(connection);
        let response = sender
            .send_request(
                hyper::Request::builder()
                    .uri("/")
                    .header(hyper::header::HOST, ALLOWED)
                    .body(Empty::<bytes::Bytes>::new())
                    .unwrap(),
            )
            .await
            .expect("the exchange reaches the origin");
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"origin", "the real origin answered");

        drop(sender);
        let handling = tokio::time::timeout(Duration::from_secs(5), served)
            .await
            .expect("the session finishes")
            .unwrap()
            .expect("the session succeeds");
        assert_eq!(
            handling,
            Handling::Intercepted {
                host: DomainName::new(ALLOWED).unwrap(),
                wire: Wire::Http1,
                tier: Tier::Rewrite,
            }
        );
        assert_eq!(
            sessions.crossings.count(),
            0,
            "no exchange may cross HTTP versions"
        );
    }

    /// A host that is not on the allowlist must reach the origin *unaltered*,
    /// ClientHello included. This is the fail-open default, and the assertion is
    /// on the bytes rather than on the decision, because a splice that rewrote
    /// anything would still report itself as a splice.
    #[tokio::test]
    async fn an_unlisted_host_is_spliced_byte_for_byte() {
        let (origin, seen) = start_recording_origin().await;
        let authority = Arc::new(CertificateAuthority::generate().unwrap());
        let sessions = sessions_for(authority, &[ALLOWED], origin, &[]);

        let (mut client_side, terminated) = bridge::duplex();
        let served = tokio::spawn(serve_session(terminated, origin, Arc::clone(&sessions)));

        let hello = super::tests::client_hello(Some(OTHER));
        client_side.write_all(&hello).await.unwrap();
        client_side.flush().await.unwrap();

        let mut echoed = vec![0u8; hello.len()];
        tokio::time::timeout(
            Duration::from_secs(5),
            tokio::io::AsyncReadExt::read_exact(&mut client_side, &mut echoed),
        )
        .await
        .expect("the origin answers")
        .unwrap();
        assert_eq!(echoed, hello, "the splice altered the client's bytes");
        assert_eq!(
            *seen.lock().await,
            hello,
            "the origin received exactly what the client sent"
        );

        drop(client_side);
        let handling = tokio::time::timeout(Duration::from_secs(5), served)
            .await
            .expect("the session finishes")
            .unwrap()
            .expect("the session succeeds");
        assert_eq!(
            handling,
            Handling::Spliced {
                reason: SpliceReason::NotAllowlisted
            }
        );
    }

    /// **The P15 through-line.** A client that does not trust the Boreas root —
    /// a pinned app, or any client the user did not install the root into —
    /// rejects the forged leaf. That first connection is lost and cannot be
    /// otherwise: the leaf has been sent by the time the alert arrives. What
    /// P15 buys is the *second* connection, which splices, and the assertion is
    /// on the bytes that reach the origin rather than on the decision.
    #[tokio::test]
    async fn a_client_that_refuses_the_forged_leaf_demotes_the_host() {
        let (origin, seen) = start_recording_origin().await;
        let authority = Arc::new(CertificateAuthority::generate().unwrap());
        let sessions = sessions_for(authority, &[ALLOWED], origin, &[]);

        // A client trusting only an unrelated root, which is what a pinned
        // client looks like from here.
        let (unrelated, ..) = origin_certificate("elsewhere.example");
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(unrelated))
            .unwrap();
        let config = Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
        );

        let (client_side, terminated) = bridge::duplex();
        let served = tokio::spawn(serve_session(terminated, origin, Arc::clone(&sessions)));
        let refused = tokio_rustls::TlsConnector::from(Arc::clone(&config))
            .connect(
                rustls::pki_types::ServerName::try_from(ALLOWED).unwrap(),
                client_side,
            )
            .await;
        assert!(refused.is_err(), "the client must reject an unknown root");

        let handling = tokio::time::timeout(Duration::from_secs(5), served)
            .await
            .expect("the session finishes")
            .unwrap()
            .expect("a refusal is a handling, not a failure of the session");
        assert_eq!(
            handling,
            Handling::Demoted {
                host: DomainName::new(ALLOWED).unwrap(),
                cause: Demotion::LeafRejected,
            }
        );
        assert_eq!(
            sessions.demotions.standing(ALLOWED, Instant::now()).tier(),
            Tier::Splice,
            "the host must stop being intercepted"
        );

        // **The retry, which is what the gate measures.** The same allowlisted
        // host now passes through untouched, so the client speaks to the origin
        // itself and the pin it was protecting is never challenged again.
        let (mut client_side, terminated) = bridge::duplex();
        let served = tokio::spawn(serve_session(terminated, origin, Arc::clone(&sessions)));
        let hello = super::tests::client_hello(Some(ALLOWED));
        client_side.write_all(&hello).await.unwrap();

        let mut echoed = vec![0u8; hello.len()];
        tokio::time::timeout(
            Duration::from_secs(5),
            tokio::io::AsyncReadExt::read_exact(&mut client_side, &mut echoed),
        )
        .await
        .expect("the origin answers")
        .unwrap();
        assert_eq!(
            echoed, hello,
            "the demoted splice altered the client's bytes"
        );
        assert_eq!(*seen.lock().await, hello);

        drop(client_side);
        let handling = tokio::time::timeout(Duration::from_secs(5), served)
            .await
            .expect("the session finishes")
            .unwrap()
            .expect("the session succeeds");
        assert_eq!(
            handling,
            Handling::Spliced {
                reason: SpliceReason::Demoted(Demotion::LeafRejected),
            }
        );
    }

    /// Transport trouble must not demote, or a bad minute of network would
    /// disable filtering for half a day. A client that opens a TLS record and
    /// vanishes is exactly that case.
    #[tokio::test]
    async fn a_client_that_vanishes_mid_handshake_proves_nothing() {
        let (origin, _) = start_recording_origin().await;
        let authority = Arc::new(CertificateAuthority::generate().unwrap());
        let sessions = sessions_for(authority, &[ALLOWED], origin, &[]);

        let (mut client_side, terminated) = bridge::duplex();
        let served = tokio::spawn(serve_session(terminated, origin, Arc::clone(&sessions)));
        client_side
            .write_all(&super::tests::client_hello(Some(ALLOWED)))
            .await
            .unwrap();
        drop(client_side);

        let outcome = tokio::time::timeout(Duration::from_secs(5), served)
            .await
            .expect("the session finishes")
            .unwrap();
        assert!(
            outcome.is_err(),
            "a dead connection is an error, not a lesson"
        );
        assert_eq!(
            sessions.demotions.standing(ALLOWED, Instant::now()),
            Standing::Unrestricted,
            "nothing may be recorded against the host"
        );
    }

    /// Cleartext on an intercepted port is spliced, and says why. An allowlist
    /// keyed on SNI has nothing to decide with when there is no TLS at all.
    #[tokio::test]
    async fn cleartext_is_spliced_with_its_reason() {
        let (origin, seen) = start_recording_origin().await;
        let authority = Arc::new(CertificateAuthority::generate().unwrap());
        let sessions = sessions_for(authority, &[ALLOWED], origin, &[]);

        let (mut client_side, terminated) = bridge::duplex();
        let served = tokio::spawn(serve_session(terminated, origin, Arc::clone(&sessions)));

        client_side
            .write_all(b"GET / HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut echoed = vec![0u8; 18];
        tokio::time::timeout(
            Duration::from_secs(5),
            tokio::io::AsyncReadExt::read_exact(&mut client_side, &mut echoed),
        )
        .await
        .expect("the origin answers")
        .unwrap();
        assert_eq!(&echoed, b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(*seen.lock().await, b"GET / HTTP/1.1\r\n\r\n".to_vec());

        drop(client_side);
        let handling = tokio::time::timeout(Duration::from_secs(5), served)
            .await
            .expect("the session finishes")
            .unwrap()
            .expect("the session succeeds");
        assert_eq!(
            handling,
            Handling::Spliced {
                reason: SpliceReason::NotTls
            }
        );
    }
}
