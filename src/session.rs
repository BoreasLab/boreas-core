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
//! port; the allowlist names *hosts*. The name arrives in the client's first
//! bytes, before any handshake this process participates in — in a TLS
//! ClientHello's SNI extension, or, on a site that never got a certificate, in
//! a cleartext request's `Host` field. So the first thing here is a parser that
//! reads those bytes without consuming them, and the rest follows from what it
//! finds.
//!
//! **Fail open is a property of the type, not of the control flow.**
//! [`Introduction`] has exactly four shapes and only two of them can lead to
//! interception: a TLS record carrying an SNI, or a complete request head
//! carrying a `Host`, either one naming a host the policy admits. Everything
//! else — a name that is not allowlisted, a ClientHello with no SNI, a request
//! with no `Host`, bytes that are neither protocol, a client that says nothing
//! before the deadline — reaches [`Handling::Spliced`] with a reason attached.
//! There is no path on which a parse failure intercepts, because the parser has
//! no failure case: it can only fail to *recognise*, and non-recognition is
//! splice.
//!
//! **No version is crossed, and the origin is what settles it.** The upstream
//! handshake runs first, offering the client's own ALPN list; the origin picks
//! from it, and the client's handshake is then offered that one protocol and no
//! other — so both legs agree by construction. Letting the client's *preference*
//! settle it instead would offer `h2` alone to an origin that speaks only
//! HTTP/1.1 and be refused outright, losing a site a browser loads without
//! complaint. [`VersionCrossings`] still counts, because a gate that can only be
//! satisfied and never checked is not a gate.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncReadExt, copy_bidirectional},
    sync::mpsc,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    Accepted, CosmeticSource, Demotion, Demotions, DomainName, EgressError, Either, Hello,
    InterceptDecision, InterceptPolicy, Interceptor, Leg, NoCosmetics, Originator, Prefixed,
    RequestFilter, RewriteFailures, Rewriting, Standing, StreamBudget, StreamEgress, Target, Tier,
    VersionCrossings, Wire, classify, run_exchange,
};

/// A TLS record carrying handshake messages.
const RECORD_HANDSHAKE: u8 = 0x16;
/// The major version byte every TLS record since 1.0 carries, including 1.3,
/// whose real version lives in an extension.
const RECORD_MAJOR: u8 = 0x03;

/// A TLS record's payload cannot exceed 2^14 bytes, so a ClientHello that has
/// not arrived within one record plus its header is one this module will not
/// wait for.
const MAX_RECORD: usize = (1 << 14) + 5;

/// How many header fields a cleartext request head may carry before this stops
/// reading it. A browser sends fewer than twenty; the cap is here because the
/// bytes are untrusted, and a head that exceeds it splices rather than being
/// read further.
const MAX_REQUEST_HEADERS: usize = 64;

/// What the client's first bytes reveal.
///
/// Four states, and the sum is the safety argument: only [`Self::Tls`] or
/// [`Self::Http`] *with a name* can lead to interception, so every other
/// outcome — including every malformed input — splices without a branch having
/// to remember to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Introduction {
    /// Not enough bytes to tell yet. The caller reads more and asks again.
    Incomplete,
    /// A TLS handshake record, and everything it revealed. `host` is the SNI
    /// when one is present and well-formed, and `None` when the ClientHello
    /// carries no server name, spans more than one record, or is malformed
    /// inside a complete record — all indistinguishable to a policy that needs
    /// a name. The [`ClientProfile`] alongside it shapes the upstream hello and
    /// the [`Offer`](crate::Offer) is what that hello proposes, both from these
    /// same bytes, so none of the three can disagree.
    Tls(Hello),
    /// A complete cleartext HTTP/1.x request head, and the `Host` it named.
    ///
    /// **The blind spot this closes is a site with no HTTPS at all.** Port 80 is
    /// inspected for the redirects that lead to 443, but a redirect is not the
    /// only thing served there, and a host reached only over cleartext was
    /// passing through unfiltered. `Host` is the cleartext analogue of SNI, and
    /// `None` — absent, unparseable, or an address rather than a name — is the
    /// same non-decision an absent SNI is.
    Http { host: Option<DomainName> },
    /// Neither a TLS record nor an HTTP request: any other protocol on a port
    /// the datapath routed here.
    Plain,
}

/// How a session reaches the origin, once a host is known.
///
/// The two arms are the two things port 443 and port 80 are: a connection to
/// re-originate under the client's own hello, and one that was never encrypted
/// and needs no handshake at all.
enum Approach {
    Tls {
        profile: crate::ClientProfile,
        alpn: crate::Offer,
    },
    Cleartext,
}

/// Reads the client's first bytes without consuming them.
///
/// Total on untrusted input: there is no error case, because every byte
/// sequence is *some* [`Introduction`], and the ones this cannot interpret are
/// the ones that splice. That is deliberate — a parser with an error case would
/// force every caller to choose a fallback, and one of them would eventually
/// choose to intercept.
///
/// O(n) in the bytes examined, bounded by [`MAX_RECORD`], with one allocation
/// for the returned name and none otherwise.
pub fn introduce(bytes: &[u8]) -> Introduction {
    // TLS record header: type(1), legacy version(2), length(2). Too few bytes
    // to recognise one is also too few to hold a request line.
    let Some(header) = bytes.get(..5) else {
        return Introduction::Incomplete;
    };
    if header[0] != RECORD_HANDSHAKE || header[1] != RECORD_MAJOR {
        return request_head(bytes);
    }
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    let Some(record) = bytes.get(5..5 + length) else {
        return Introduction::Incomplete;
    };
    Introduction::Tls(crate::read_hello(record))
}

/// Reads a cleartext HTTP/1.x request head for the `Host` it names.
///
/// `httparse` does the reading: it is already in the graph beneath `hyper`, it
/// borrows rather than allocates, and it is tolerant in exactly the places a
/// hand-rolled scan would be strict. Anything it refuses is [`Introduction::Plain`],
/// which splices — so a protocol that merely resembles HTTP costs one parse.
fn request_head(bytes: &[u8]) -> Introduction {
    let mut fields = [httparse::EMPTY_HEADER; MAX_REQUEST_HEADERS];
    let mut request = httparse::Request::new(&mut fields);
    match request.parse(bytes) {
        Ok(httparse::Status::Complete(_)) => Introduction::Http {
            host: host_field(request.headers),
        },
        Ok(httparse::Status::Partial) => Introduction::Incomplete,
        Err(_) => Introduction::Plain,
    }
}

/// The `Host` field's name, without its port.
///
/// Parsed as an authority rather than split on the last colon, because an IPv6
/// literal is full of colons and `[::1]:80` would otherwise yield `[::1`. Both
/// forms end at the same place: an address is not a name, so
/// [`DomainName`] refuses it and the connection splices.
fn host_field(fields: &[httparse::Header<'_>]) -> Option<DomainName> {
    let value = fields
        .iter()
        .find(|field| field.name.eq_ignore_ascii_case("host"))?
        .value;
    let authority: http::uri::Authority = std::str::from_utf8(value).ok()?.parse().ok()?;
    DomainName::new(authority.host()).ok()
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
    /// The handshake *to the origin* failed, so there was nothing to intercept.
    /// Distinct from [`Self::Demoted`] because it is what was just learned
    /// rather than what was already known — and reachable at all only because
    /// that handshake runs before any forged leaf is sent.
    OriginHandshake,
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
    /// The originating TLS client. **BoringSSL, not rustls**, and the split is
    /// the point: the terminating side faces an application on this device and
    /// nothing fingerprints it, while this side faces an origin and a CDN. It
    /// is one value because it memoises a built connector per profile and ALPN,
    /// and parsing the trust anchors is not a per-connection cost.
    originator: Arc<Originator>,
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
            originator: Arc::new(Originator::new()),
        })
    }

    /// Trusts `extra_roots` in addition to the bundled anchors on the upstream
    /// leg. For a test origin, or a deployment behind a private CA.
    pub fn with_upstream_roots(mut self, extra_roots: &[Vec<u8>]) -> Result<Self, EgressError> {
        self.originator = Arc::new(Originator::new().with_extra_roots(extra_roots));
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

    let (host, approach) = match introduction {
        Introduction::Tls(Hello {
            host: Some(host),
            profile,
            alpn,
        }) => (host, Approach::Tls { profile, alpn }),
        Introduction::Http { host: Some(host) } => (host, Approach::Cleartext),
        Introduction::Tls(Hello { host: None, .. }) | Introduction::Http { host: None } => {
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

    let target = Target::Domain {
        host: host.clone(),
        port,
    };
    let transport = sessions
        .egress
        .connect(&target)
        .await
        .map_err(SessionError::Upstream)?;

    // Both approaches end with the same pair of byte streams and a wire; what
    // differs is how many handshakes stand between them.
    let (client, upstream, wire) = match approach {
        // **The upstream handshake comes first, and that is what fixes the
        // wire.** The origin picks from the client's own ALPN list, and the
        // client is then offered exactly what the origin picked — so a crossed
        // version stays unrepresentable *and* an origin that speaks only
        // HTTP/1.1 is still served. Settling on the client's choice instead
        // would offer `h2` alone to such an origin and be refused outright,
        // losing a site Chrome loads.
        //
        // The order also buys back the failure case the client-first order
        // could not have: no forged leaf has been sent yet, so an upstream
        // handshake that fails still has a whole connection left to splice.
        Approach::Tls { profile, alpn } => {
            // **The hello Boreas sends is the one it just read.** `profile` came
            // out of the client's own ClientHello, so this connection looks like
            // the application that made it rather than like a proxy — or like a
            // canonical Chrome, which on a WebView or Cronet device would be a
            // fresh mismatch.
            let upstream = match sessions
                .originator
                .connect(host.as_str(), &profile, &alpn.encode(), transport)
                .await
            {
                Ok(upstream) => upstream,
                Err(error) => {
                    if let Some(cause) = classify(Leg::Upstream, &error) {
                        sessions
                            .demotions
                            .record(host.as_str(), cause, Instant::now());
                    }
                    return splice(
                        sessions,
                        server,
                        peeked,
                        stream,
                        SpliceReason::OriginHandshake,
                    )
                    .await;
                }
            };
            let wire = Wire::from_alpn(upstream.ssl().selected_alpn_protocol());

            let replayed = Prefixed::new(peeked, stream);
            let client = match sessions.interceptor.terminate(replayed, wire).await {
                Ok(client) => client,
                Err(error) => {
                    // Here the leaf *has* been sent, so a client that rejects it
                    // leaves nothing to splice with. That cost is stated in
                    // [`crate::Demotions`] and is why demotion is measured on
                    // the retry.
                    return learn(&sessions, &host, Leg::Client, error, |error| {
                        SessionError::ClientHandshake(error)
                    });
                }
            };
            (Either::Left(client), Either::Left(upstream), wire)
        }
        // No handshake on either leg, so there is nothing to fingerprint and
        // nothing to demote — and only one wire cleartext HTTP/1.x has.
        Approach::Cleartext => (
            Either::Right(Prefixed::new(peeked, stream)),
            Either::Right(transport),
            Wire::Http1,
        ),
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
///
/// **Every task is tracked, and this function does not return while one is
/// alive.** A count bounded by the socket ceiling is not the same statement as
/// a lifetime bounded by this call: detached tasks hold forged leaves, upstream
/// TLS connections, and egress sockets, so a shutdown that merely stopped
/// accepting would leave those open with nothing left to close them. Closing
/// the tracker stops admission, the token cancels the children, and the wait is
/// the proof — O(live connections) work, and the same space that was already
/// admitted.
pub async fn run_sessions(
    mut accepted: mpsc::Receiver<Accepted>,
    sessions: Arc<Sessions>,
    shutdown: CancellationToken,
) {
    let tracker = TaskTracker::new();
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
        tracker.spawn(async move {
            tokio::select! {
                () = shutdown.cancelled() => {}
                _ = serve_session(stream, server, sessions) => {}
            }
        });
    }

    // Admission closes first, so nothing joins the set after the wait begins;
    // then every child observes the same token this loop did.
    tracker.close();
    shutdown.cancel();
    tracker.wait().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real ClientHello, assembled field by field so the test states the
    /// layout rather than trusting an opaque blob.
    const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
    const EXTENSION_SERVER_NAME: u16 = 0x0000;
    const NAME_TYPE_HOST: u8 = 0x00;

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
            Introduction::Tls(Hello {
                host: Some(DomainName::new("example.com").unwrap()),
                profile: crate::ClientProfile::default(),
                alpn: crate::Offer::default(),
            })
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
            Introduction::Tls(Hello::default())
        );
    }

    /// Cleartext HTTP is read for its `Host`, which is the cleartext analogue
    /// of SNI. A head without one decides nothing, exactly as a hello without
    /// an SNI decides nothing.
    #[test]
    fn cleartext_http_is_read_for_its_host() {
        assert_eq!(
            introduce(b"GET / HTTP/1.1\r\nHost: example.com:80\r\n\r\n"),
            Introduction::Http {
                host: Some(DomainName::new("example.com").unwrap())
            }
        );
        assert_eq!(
            introduce(b"GET / HTTP/1.1\r\n\r\n"),
            Introduction::Http { host: None }
        );
        // An address is carried like any other authority; an allowlist that
        // does not name it splices on the ordinary path rather than here. The
        // bracketed form is why the port is removed by parsing the authority
        // rather than by splitting on the last colon, which would leave `[::1`.
        for (head, expected) in [
            ("Host: 203.0.113.4", "203.0.113.4"),
            ("Host: [::1]:80", "[::1]"),
        ] {
            assert_eq!(
                introduce(format!("GET / HTTP/1.1\r\n{head}\r\n\r\n").as_bytes()),
                Introduction::Http {
                    host: Some(DomainName::new(expected).unwrap())
                }
            );
        }
        // A head that has not ended yet must decide nothing, or the `Host`
        // could still be in the bytes that have not arrived.
        assert_eq!(
            introduce(b"GET / HTTP/1.1\r\nHost: exa"),
            Introduction::Incomplete
        );
    }

    #[test]
    fn what_is_neither_tls_nor_http_is_plain() {
        assert_eq!(introduce(b"\x00\x01\x02\x03\x04\x05"), Introduction::Plain);
        assert_eq!(
            introduce(b"SSH-2.0-OpenSSH_9.6 Ubuntu\r\n"),
            Introduction::Plain
        );
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
            Introduction::Tls(Hello::default())
        );
        assert_eq!(
            introduce(&client_hello(Some("bad\0host"))),
            Introduction::Tls(Hello::default())
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
        // A distinct subject, because rcgen gives every certificate the same
        // default one — which would make the leaf's issuer equal to its own
        // subject and so indistinguishable from a self-signed certificate. The
        // old rustls upstream matched anchors by signature and did not care;
        // BoringSSL reports it as `DEPTH_ZERO_SELF_SIGNED_CERT`, and is right
        // to, so the fixture is what changes.
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "boreas test origin ca");
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
    /// An origin with no TLS at all, which is what a site that never got a
    /// certificate looks like. Answers every request with its own path.
    async fn start_cleartext_origin() -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(
                        |request: hyper::Request<hyper::body::Incoming>| async move {
                            let path = request.uri().path().to_owned();
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(
                                http_body_util::Full::new(bytes::Bytes::from(format!(
                                    "cleartext:{path}"
                                ))),
                            ))
                        },
                    );
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tcp), service)
                        .await;
                });
            }
        });
        address
    }

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
        // **Chrome's own list, against an origin that speaks only http/1.1.**
        // The origin picks, so this is served over http/1.1 on both legs. Were
        // the client's preference what settled it, the upstream leg would offer
        // `h2` alone and the origin would refuse it outright.
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(
                rustls::pki_types::ServerName::try_from(ALLOWED).unwrap(),
                client_side,
            )
            .await
            .expect("the forged leaf validates against the Boreas root");
        assert_eq!(
            tls.get_ref().1.alpn_protocol(),
            Some(b"http/1.1".as_slice()),
            "the origin's choice is what the client is offered"
        );

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

    /// **A site with no HTTPS is still filtered.** Port 80 is inspected for the
    /// redirects that lead to 443, but a host that never got a certificate
    /// serves its content there, and it used to pass through untouched for want
    /// of an SNI to read. `Host` is what names it, and neither leg handshakes.
    #[tokio::test]
    async fn a_cleartext_host_is_intercepted_through_its_host_header() {
        let origin = start_cleartext_origin().await;
        let authority = Arc::new(CertificateAuthority::generate().unwrap());
        let sessions = sessions_for(authority, &[ALLOWED], origin, &[]);

        let (client_side, terminated) = bridge::duplex();
        let served = tokio::spawn(serve_session(terminated, origin, Arc::clone(&sessions)));

        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(client_side))
                .await
                .unwrap();
        tokio::spawn(connection);
        let response = sender
            .send_request(
                hyper::Request::builder()
                    .uri("/page")
                    .header(hyper::header::HOST, ALLOWED)
                    .body(Empty::<bytes::Bytes>::new())
                    .unwrap(),
            )
            .await
            .expect("the exchange reaches the origin");
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"cleartext:/page", "the real origin answered");

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
                tier: Tier::TOP,
            }
        );
    }

    /// **The P15 through-line.** A client that does not trust the Boreas root —
    /// a pinned app, or any client the user did not install the root into —
    /// rejects the forged leaf. That connection is lost and cannot be
    /// otherwise: the leaf has been sent by the time the alert arrives, which
    /// is the one failure the upstream-first order does not recover. What P15
    /// buys is the next connection, which
    /// [`a_demoted_host_splices_the_next_connection_byte_for_byte`] covers.
    ///
    /// The origin here is a real TLS server because the upstream handshake now
    /// runs first: reaching the client's leg at all means the origin's leg
    /// already succeeded.
    #[tokio::test]
    async fn a_client_that_refuses_the_forged_leaf_demotes_the_host() {
        let (origin, origin_ca) = start_tls_origin(ALLOWED).await;
        let authority = Arc::new(CertificateAuthority::generate().unwrap());
        let sessions = sessions_for(authority, &[ALLOWED], origin, &[origin_ca]);

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
    }

    /// **What the demotion buys, which is the gate P15 measures.** An
    /// allowlisted host whose standing has fallen to splice passes through
    /// untouched, so the client speaks to the origin itself and the pin it was
    /// protecting is never challenged again. Asserted on the bytes that reach
    /// the origin rather than on the decision.
    #[tokio::test]
    async fn a_demoted_host_splices_the_next_connection_byte_for_byte() {
        let (origin, seen) = start_recording_origin().await;
        let authority = Arc::new(CertificateAuthority::generate().unwrap());
        let sessions = sessions_for(authority, &[ALLOWED], origin, &[]);
        sessions
            .demotions
            .record(ALLOWED, Demotion::LeafRejected, Instant::now());

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

    /// A cleartext request naming no host is spliced, and says why: `Host` is
    /// what the allowlist reads on this path, and a head without one is the
    /// same non-decision a hello without an SNI is.
    #[tokio::test]
    async fn cleartext_without_a_host_is_spliced_with_its_reason() {
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
                reason: SpliceReason::Unnamed
            }
        );
    }
}
