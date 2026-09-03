//! Machine-maintained demotion state for interception.
//!
//! Recorded evidence only reduces interception. TLS refusals are evidence;
//! resets, timeouts, and other transport failures are not. Causes combine by a
//! three-level meet, so rewriting can be disabled without losing URL filtering.
//! Entries are bounded by the interception allowlist; pruning only reclaims
//! expired memory.

use std::{
    collections::HashMap,
    fmt, io,
    sync::RwLock,
    time::{Duration, Instant},
};

use rustls::{AlertDescription, Error as TlsError};

use crate::{HandshakeFailure, Refusal};

/// Maximum interception tier still allowed for a host.
///
/// The order is `Splice < Inspect < Rewrite`; [`Self::meet`] selects the lower
/// tier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    /// Leave the connection byte-for-byte spliced.
    Splice,
    /// Terminate and filter URLs without rewriting bodies.
    Inspect,
    /// Terminate, filter URLs, and rewrite HTML bodies.
    Rewrite,
}

/// Valid tiers for an already terminated connection.
///
/// `Splice` is absent because a spliced connection is never terminated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterceptedTier {
    /// Terminate and filter URLs without rewriting bodies.
    Inspect,
    /// Terminate, filter URLs, and rewrite HTML bodies.
    Rewrite,
}

impl InterceptedTier {
    /// Default tier for a host with no demotion.
    pub const TOP: Self = Self::Rewrite;
}

impl Tier {
    /// Identity of [`Self::meet`] and default tier.
    pub const TOP: Self = Self::Rewrite;

    /// Converts an allowed tier to a terminated-connection tier.
    #[must_use]
    pub fn intercepted(self) -> Option<InterceptedTier> {
        match self {
            Self::Splice => None,
            Self::Inspect => Some(InterceptedTier::Inspect),
            Self::Rewrite => Some(InterceptedTier::Rewrite),
        }
    }

    /// Returns the lower of two allowed tiers.
    #[must_use]
    pub fn meet(self, other: Self) -> Self {
        self.min(other)
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Splice => "splice",
            Self::Inspect => "inspect",
            Self::Rewrite => "rewrite",
        })
    }
}

/// Observable evidence that interception failed for a host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Demotion {
    /// The client rejected the forged leaf certificate.
    LeafRejected,
    /// The server refused the connection originated by Boreas.
    UpstreamRefusedProxy,
    /// The server certificate did not validate.
    UpstreamUntrusted,
    /// The peers rejected the negotiated application protocol.
    ProtocolRefused,
    /// An HTML rewrite exceeded its per-stream budget.
    RewriteExhausted,
}

impl Demotion {
    /// All causes in deterministic tie-breaking order.
    pub const ALL: [Self; 5] = [
        Self::LeafRejected,
        Self::UpstreamRefusedProxy,
        Self::UpstreamUntrusted,
        Self::ProtocolRefused,
        Self::RewriteExhausted,
    ];

    const COUNT: usize = Self::ALL.len();

    const fn slot(self) -> usize {
        match self {
            Self::LeafRejected => 0,
            Self::UpstreamRefusedProxy => 1,
            Self::UpstreamUntrusted => 2,
            Self::ProtocolRefused => 3,
            Self::RewriteExhausted => 4,
        }
    }

    /// Tier allowed after this cause is observed.
    #[must_use]
    pub const fn tier(self) -> Tier {
        match self {
            Self::LeafRejected
            | Self::UpstreamRefusedProxy
            | Self::UpstreamUntrusted
            | Self::ProtocolRefused => Tier::Splice,
            Self::RewriteExhausted => Tier::Inspect,
        }
    }

    /// How long this cause remains active.
    #[must_use]
    pub const fn ttl(self) -> Duration {
        const HOUR: u64 = 60 * 60;
        Duration::from_secs(match self {
            // Software updates change pins and server protocol policy.
            Self::LeafRejected | Self::UpstreamRefusedProxy | Self::ProtocolRefused => 12 * HOUR,
            // Network state and certificate validity can recover quickly.
            Self::UpstreamUntrusted => 5 * 60,
            // A later document may fit the rewrite budget.
            Self::RewriteExhausted => HOUR,
        })
    }
}

impl fmt::Display for Demotion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::LeafRejected => "the client refused the forged leaf",
            Self::UpstreamRefusedProxy => "the server refused the proxied connection",
            Self::UpstreamUntrusted => "the server's certificate did not validate",
            Self::ProtocolRefused => "no shared application protocol",
            Self::RewriteExhausted => "the rewrite exceeded its budget",
        })
    }
}

/// What a host's live evidence permits.
///
/// The tier is derived from the cause, so the two values cannot disagree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// No live demotion exists.
    Unrestricted,
    /// A live cause caps the permitted tier.
    Limited(Demotion),
}

impl Standing {
    #[must_use]
    pub fn tier(self) -> Tier {
        match self {
            Self::Unrestricted => Tier::TOP,
            Self::Limited(cause) => cause.tier(),
        }
    }

    pub fn permits(self) -> Result<InterceptedTier, Demotion> {
        match self {
            Self::Unrestricted => Ok(InterceptedTier::TOP),
            Self::Limited(cause) => cause.tier().intercepted().ok_or(cause),
        }
    }

    #[must_use]
    pub fn cause(self) -> Option<Demotion> {
        match self {
            Self::Unrestricted => None,
            Self::Limited(cause) => Some(cause),
        }
    }
}

/// Side of the intercepted connection that produced a failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Leg {
    /// Boreas terminates the client TLS.
    Client,
    /// Boreas originates TLS to the upstream server.
    Upstream,
}

/// Classifies a TLS handshake failure as demotion evidence.
///
/// Transport errors return `None`. The two legs use different TLS error types,
/// so classification selects the leg before downcasting.
#[must_use]
pub fn classify(leg: Leg, error: &io::Error) -> Option<Demotion> {
    let inner = error.get_ref()?;
    match leg {
        Leg::Client => terminating(inner.downcast_ref::<TlsError>()?),
        Leg::Upstream => originating(inner.downcast_ref::<HandshakeFailure>()?.refusal?),
    }
}

/// Classifies rustls evidence from the client leg.
fn terminating(tls: &TlsError) -> Option<Demotion> {
    match tls {
        TlsError::NoApplicationProtocol
        | TlsError::AlertReceived(AlertDescription::NoApplicationProtocol) => {
            Some(Demotion::ProtocolRefused)
        }
        TlsError::AlertReceived(alert) => conclusive(*alert).then_some(Demotion::LeafRejected),
        _ => None,
    }
}

/// Classifies BoringSSL evidence from the upstream leg.
fn originating(refusal: Refusal) -> Option<Demotion> {
    match refusal {
        // Either leg can report the same protocol refusal.
        Refusal::NoProtocol | Refusal::Alert(ALERT_NO_APPLICATION_PROTOCOL) => {
            Some(Demotion::ProtocolRefused)
        }
        // The upstream certificate failed validation locally.
        Refusal::Untrusted => Some(Demotion::UpstreamUntrusted),
        Refusal::Alert(alert) => conclusive_alert(alert).then_some(Demotion::UpstreamRefusedProxy),
    }
}

const ALERT_CLOSE_NOTIFY: u8 = 0;
const ALERT_USER_CANCELED: u8 = 90;
const ALERT_NO_APPLICATION_PROTOCOL: u8 = 120;

fn conclusive(alert: AlertDescription) -> bool {
    !matches!(
        alert,
        AlertDescription::CloseNotify | AlertDescription::UserCanceled
    )
}

fn conclusive_alert(alert: u8) -> bool {
    !matches!(alert, ALERT_CLOSE_NOTIFY | ALERT_USER_CANCELED)
}

/// Conclusive failures of one cause, within one TTL of each other, before
/// the cause counts. One is what any app on the device can stage by sending
/// an alert; three from separate connections is a host that really refuses.
const STRIKES: u8 = 3;

/// One cause's evidence for a host: how many times, and until when.
#[derive(Clone, Copy, Default)]
struct Strike {
    count: u8,
    expiry: Option<Instant>,
}

type Expiries = [Strike; Demotion::COUNT];

const PRUNE_AT: usize = 1024;

struct Table {
    hosts: HashMap<String, Expiries>,
    /// Next sweep threshold, raised past the live set after each sweep.
    prune_at: usize,
}

/// Per-host interception demotion table.
///
/// Reads use a shared lock and one hash lookup; writes hold no asynchronous
/// boundary. SipHash protects attacker-chosen host names.
#[derive(Default)]
pub struct Demotions {
    table: RwLock<Table>,
}

impl Default for Table {
    fn default() -> Self {
        Self {
            hosts: HashMap::new(),
            prune_at: PRUNE_AT,
        }
    }
}

impl fmt::Debug for Demotions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Demotions")
            .field("len", &self.len())
            .finish()
    }
}

impl Demotions {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the tier currently permitted for `host`.
    #[must_use]
    pub fn standing(&self, host: &str, now: Instant) -> Standing {
        let table = self
            .table
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        let Some(expiries) = table.hosts.get(host) else {
            return Standing::Unrestricted;
        };
        Demotion::ALL
            .into_iter()
            .filter(|cause| live(expiries[cause.slot()], now))
            .min_by_key(|cause| cause.tier())
            .map_or(Standing::Unrestricted, Standing::Limited)
    }

    /// Records a cause and returns the resulting standing.
    pub fn record(&self, host: &str, cause: Demotion, now: Instant) -> Standing {
        let expiry = now.checked_add(cause.ttl());
        let mut table = self
            .table
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        if table.hosts.len() >= table.prune_at && !table.hosts.contains_key(host) {
            table
                .hosts
                .retain(|_, expiries| expiries.iter().any(|strike| unlapsed(*strike, now)));
            table.prune_at = PRUNE_AT.max(table.hosts.len().saturating_mul(2));
        }
        let expiries = table.hosts.entry(host.to_owned()).or_default();
        let strike = &mut expiries[cause.slot()];
        // Strikes older than one TTL are forgotten; a fresh one starts over.
        if !unlapsed(*strike, now) {
            strike.count = 0;
        }
        strike.count = strike.count.saturating_add(1);
        strike.expiry = expiry;

        Demotion::ALL
            .into_iter()
            .filter(|cause| live(expiries[cause.slot()], now))
            .min_by_key(|cause| cause.tier())
            .map_or(Standing::Unrestricted, Standing::Limited)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.table
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
            .hosts
            .len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A strike within its TTL, however few there are: evidence worth keeping.
fn unlapsed(strike: Strike, now: Instant) -> bool {
    strike.expiry.is_some_and(|expiry| expiry > now)
}

/// Enough strikes, the latest not yet lapsed. An absent expiry is a cause
/// never observed; a saturated one is an interval past the end of the clock,
/// which cannot arrive and so is treated as expired.
fn live(strike: Strike, now: Instant) -> bool {
    strike.count >= STRIKES && unlapsed(strike, now)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "pinned.example";

    /// Shared test instant for deterministic expiry checks.
    fn epoch() -> Instant {
        Instant::now()
    }

    /// Exhaustively checks the three-point lattice laws.
    #[test]
    fn the_tier_meet_is_a_semilattice_with_rewrite_as_identity() {
        let tiers = [Tier::Splice, Tier::Inspect, Tier::Rewrite];
        for a in tiers {
            assert_eq!(a.meet(a), a, "idempotent");
            assert_eq!(a.meet(Tier::TOP), a, "TOP is the identity");
            for b in tiers {
                assert_eq!(a.meet(b), b.meet(a), "commutative");
                for c in tiers {
                    assert_eq!(a.meet(b).meet(c), a.meet(b.meet(c)), "associative");
                }
            }
        }
    }

    /// Each cause must occupy a distinct expiry slot.
    #[test]
    fn every_cause_occupies_a_distinct_slot() {
        let mut slots: Vec<usize> = Demotion::ALL.iter().map(|cause| cause.slot()).collect();
        slots.sort_unstable();
        slots.dedup();
        assert_eq!(slots.len(), Demotion::COUNT);
        assert!(slots.iter().all(|slot| *slot < Demotion::COUNT));
    }

    #[test]
    fn an_unknown_host_is_unrestricted() {
        let demotions = Demotions::new();
        assert_eq!(demotions.standing(HOST, epoch()), Standing::Unrestricted);
        assert_eq!(demotions.standing(HOST, epoch()).tier(), Tier::TOP);
        assert!(demotions.is_empty());
    }

    /// Records `cause` enough times to count.
    fn demote(demotions: &Demotions, host: &str, cause: Demotion, now: Instant) -> Standing {
        (1..STRIKES).for_each(|_| {
            demotions.record(host, cause, now);
        });
        demotions.record(host, cause, now)
    }

    /// One conclusive failure is what any app can stage; three within a TTL
    /// demote the host from the next connection onward, and strikes older
    /// than a TTL do not add up.
    #[test]
    fn three_conclusive_failures_demote_the_host_and_one_does_not() {
        let now = epoch();
        let demotions = Demotions::new();
        assert_eq!(
            demotions.record(HOST, Demotion::LeafRejected, now),
            Standing::Unrestricted
        );
        assert_eq!(
            demotions.record(HOST, Demotion::LeafRejected, now),
            Standing::Unrestricted
        );
        let standing = demotions.record(HOST, Demotion::LeafRejected, now);
        assert_eq!(standing, Standing::Limited(Demotion::LeafRejected));
        assert_eq!(standing.tier(), Tier::Splice);
        assert_eq!(demotions.standing(HOST, now).tier(), Tier::Splice);
        // Demotion is scoped to the recorded host.
        assert_eq!(
            demotions.standing("other.example", now),
            Standing::Unrestricted
        );

        let stale = Demotions::new();
        let gap = Demotion::LeafRejected.ttl() + Duration::from_secs(1);
        stale.record(HOST, Demotion::LeafRejected, now);
        stale.record(HOST, Demotion::LeafRejected, now + gap);
        assert_eq!(
            stale.record(HOST, Demotion::LeafRejected, now + gap + gap),
            Standing::Unrestricted,
            "a strike per TTL never adds up"
        );
    }

    /// Rewrite exhaustion removes rewriting but preserves URL filtering.
    #[test]
    fn an_exhausted_rewrite_stops_rewriting_and_nothing_else() {
        let now = epoch();
        let demotions = Demotions::new();
        assert_eq!(
            demote(&demotions, HOST, Demotion::RewriteExhausted, now).tier(),
            Tier::Inspect
        );
    }

    /// Recording causes is order-independent and idempotent.
    #[test]
    fn recording_is_idempotent_and_order_independent() {
        let now = epoch();
        let ordered = Demotions::new();
        demote(&ordered, HOST, Demotion::RewriteExhausted, now);
        demote(&ordered, HOST, Demotion::LeafRejected, now);

        let reversed = Demotions::new();
        demote(&reversed, HOST, Demotion::LeafRejected, now);
        demote(&reversed, HOST, Demotion::RewriteExhausted, now);
        demote(&reversed, HOST, Demotion::LeafRejected, now);

        assert_eq!(ordered.standing(HOST, now), reversed.standing(HOST, now));
        assert_eq!(ordered.standing(HOST, now).tier(), Tier::Splice);

        // The recorded witness matches the lattice fold.
        let folded = [Demotion::RewriteExhausted, Demotion::LeafRejected]
            .into_iter()
            .fold(Tier::TOP, |tier, cause| tier.meet(cause.tier()));
        assert_eq!(ordered.standing(HOST, now).tier(), folded);
    }

    /// An expired cause must stop hiding a still-live cause.
    #[test]
    fn a_lapsed_cause_stops_applying_without_hiding_a_live_one() {
        let now = epoch();
        let demotions = Demotions::new();
        demote(&demotions, HOST, Demotion::UpstreamUntrusted, now);
        demote(&demotions, HOST, Demotion::RewriteExhausted, now);
        assert_eq!(demotions.standing(HOST, now).tier(), Tier::Splice);

        // Only the longer-lived rewrite demotion remains.
        let later = now + Demotion::UpstreamUntrusted.ttl() + Duration::from_secs(1);
        assert_eq!(
            demotions.standing(HOST, later),
            Standing::Limited(Demotion::RewriteExhausted)
        );

        let much_later = now + Demotion::RewriteExhausted.ttl() + Duration::from_secs(1);
        assert_eq!(demotions.standing(HOST, much_later), Standing::Unrestricted);
    }

    /// Pruning removes expired hosts and retains live ones.
    #[test]
    fn pruning_reclaims_dead_hosts_and_keeps_live_ones() {
        let now = epoch();
        let demotions = Demotions::new();
        for index in 0..PRUNE_AT {
            demotions.record(
                &format!("dead-{index}.example"),
                Demotion::LeafRejected,
                now,
            );
        }
        assert_eq!(demotions.len(), PRUNE_AT);

        // A fresh record triggers pruning after the entries expire.
        let later = now + Demotion::LeafRejected.ttl() + Duration::from_secs(1);
        demote(&demotions, HOST, Demotion::LeafRejected, later);
        assert_eq!(demotions.len(), 1, "the sweep reclaimed the lapsed hosts");
        assert_eq!(demotions.standing(HOST, later).tier(), Tier::Splice);
    }

    fn tls_error(error: TlsError) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, error)
    }

    fn boring_error(refusal: Refusal) -> io::Error {
        io::Error::other(HandshakeFailure::new(Some(refusal), "synthesized"))
    }

    /// Classifies conclusive TLS refusals and ignores transport failures.
    #[test]
    fn only_conclusive_tls_refusals_are_evidence() {
        assert_eq!(
            classify(
                Leg::Client,
                &tls_error(TlsError::AlertReceived(AlertDescription::UnknownCA))
            ),
            Some(Demotion::LeafRejected)
        );
        // Upstream evidence uses `Refusal`, not `rustls::Error`.
        assert_eq!(
            classify(Leg::Upstream, &boring_error(Refusal::Alert(116))),
            Some(Demotion::UpstreamRefusedProxy)
        );
        assert_eq!(
            classify(Leg::Upstream, &boring_error(Refusal::Untrusted)),
            Some(Demotion::UpstreamUntrusted)
        );
        assert_eq!(
            classify(Leg::Upstream, &boring_error(Refusal::NoProtocol)),
            Some(Demotion::ProtocolRefused)
        );
        assert_eq!(
            classify(
                Leg::Upstream,
                &boring_error(Refusal::Alert(ALERT_NO_APPLICATION_PROTOCOL))
            ),
            Some(Demotion::ProtocolRefused)
        );
        // Each leg accepts only its own TLS error representation.
        assert_eq!(
            classify(Leg::Upstream, &tls_error(TlsError::NoApplicationProtocol)),
            None
        );
        assert_eq!(
            classify(Leg::Client, &boring_error(Refusal::Untrusted)),
            None
        );

        // Transport trouble is not evidence for demotion.
        for kind in [
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::TimedOut,
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::BrokenPipe,
        ] {
            assert_eq!(
                classify(Leg::Client, &io::Error::from(kind)),
                None,
                "{kind}"
            );
            assert_eq!(classify(Leg::Upstream, &io::Error::from(kind)), None);
        }
        // Close and cancellation alerts are not refusals.
        for alert in [
            AlertDescription::CloseNotify,
            AlertDescription::UserCanceled,
        ] {
            assert_eq!(
                classify(Leg::Client, &tls_error(TlsError::AlertReceived(alert))),
                None,
                "{alert:?}"
            );
        }
        for alert in [ALERT_CLOSE_NOTIFY, ALERT_USER_CANCELED] {
            assert_eq!(
                classify(Leg::Upstream, &boring_error(Refusal::Alert(alert))),
                None,
                "{alert}"
            );
        }
    }

    /// The same handshake alert maps differently on the two legs.
    #[test]
    fn the_two_legs_read_the_same_alert_as_different_evidence() {
        // Alert 40 is represented by different TLS error types on each leg.
        assert_eq!(
            classify(
                Leg::Client,
                &tls_error(TlsError::AlertReceived(AlertDescription::HandshakeFailure))
            ),
            Some(Demotion::LeafRejected)
        );
        assert_eq!(
            classify(Leg::Upstream, &boring_error(Refusal::Alert(40))),
            Some(Demotion::UpstreamRefusedProxy)
        );
    }
}
