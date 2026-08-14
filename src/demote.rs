//! P15 demotion: the machine-maintained half of the interception decision.
//!
//! P14 ships an allowlist a human types. That is only tractable while the list
//! is short, and the list has to grow toward the parity corpus — so something
//! has to notice, without being told, that interception does not work for a
//! host and stop attempting it. That is this module, and it is what makes
//! broadening the allowlist safe rather than reckless.
//!
//! **Demotion only ever does less, which decides how evidence is weighed.** A
//! false positive costs coverage on one host until the entry expires; a false
//! negative leaves a site broken for as long as the user keeps visiting it.
//! Those are not comparable, so the rule here is generous about *which*
//! failures count and strict about *what counts as a failure*: every TLS alert
//! but two is admitted, and nothing that merely looks like bad luck — a reset,
//! a timeout, a refused connection — is admitted at all. A network blip proves
//! nothing about whether interception works, and treating it as proof would
//! let a bad minute of Wi-Fi silently disable filtering.
//!
//! **The remedy is a lattice, not a switch.** [`Tier`] is a three-point chain:
//! rewrite bodies, inspect requests without touching bodies, or stand aside
//! entirely. Recording an observation is a meet, so it is idempotent,
//! commutative, and associative — the order failures arrive in cannot change
//! where a host ends up. The middle point earns its place: an HTML rewrite that
//! blows its memory budget should stop the rewriting, not the URL filtering
//! that is the more valuable tier by far.
//!
//! **One connection is the price, and it cannot be less.** The evidence that
//! interception fails for a host *is* the failed handshake, and by the time it
//! arrives Boreas has already sent a forged certificate or already terminated
//! the client. Nothing can un-send those. So the first attempt after a host
//! becomes unworkable is lost and the retry succeeds — which is what the
//! product gate measures, since browsers and apps retry.
//!
//! **The table cannot outgrow the allowlist.** Only an allowlisted host is
//! intercepted, and only an intercepted host can fail in a way recorded here,
//! so the key space is bounded by a set a human maintains. Pruning exists to
//! return memory, not to bound it.

use std::{
    collections::HashMap,
    fmt, io,
    sync::RwLock,
    time::{Duration, Instant},
};

use rustls::{AlertDescription, Error as TlsError};

use crate::{HandshakeFailure, Refusal};

/// How much of the interception stack a host tolerates.
///
/// A three-point chain ordered by how much Boreas does, so `Splice < Inspect <
/// Rewrite` and the derived [`Ord`] *is* the lattice order. [`Self::meet`] is
/// the greatest lower bound, and it is how two observations about the same host
/// combine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    /// Do not terminate. The connection passes through byte for byte, which is
    /// what a host with no policy at all gets.
    Splice,
    /// Terminate and filter by URL, but forward bodies untouched.
    Inspect,
    /// Terminate, filter, and rewrite HTML bodies.
    Rewrite,
}

impl Tier {
    /// The identity of [`Self::meet`], and what a host with nothing recorded
    /// against it gets.
    pub const TOP: Self = Self::Rewrite;

    /// Greatest lower bound: the most Boreas may do given both observations.
    ///
    /// Idempotent, commutative, associative, with [`Self::TOP`] as identity —
    /// which is precisely why the order failures arrive in cannot matter.
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

/// What a host proved about interception.
///
/// Each variant names an observation Boreas can actually make, not a cause it
/// infers. That matters: several distinct server behaviours — a client
/// certificate challenge, address reputation, TLS fingerprinting — are
/// indistinguishable from here and share one remedy, so they share one variant
/// rather than being guessed apart into three.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Demotion {
    /// The client refused the leaf Boreas forged: a pinned client, or one that
    /// does not trust the locally installed root. Nothing Boreas can do makes
    /// this client accept a certificate it did not expect.
    LeafRejected,
    /// The server refused the connection Boreas made in the client's place.
    /// The canonical case is a client-certificate challenge — terminating puts
    /// Boreas between the challenge and the key that answers it — and every
    /// other case has the same remedy: stand aside and let the client connect
    /// for itself.
    UpstreamRefusedProxy,
    /// The server's own certificate did not validate here. Boreas will not
    /// stand in for a server it cannot authenticate, and the client is better
    /// equipped to judge than this process is: splicing hands the decision back
    /// to the party that owns it.
    UpstreamUntrusted,
    /// One side would not speak the single protocol the other settled on.
    /// Offering exactly one ALPN upstream is what makes a crossed HTTP version
    /// unrepresentable; this is what that invariant costs when a server and a
    /// client disagree, and standing aside lets them negotiate directly.
    ProtocolRefused,
    /// An HTML rewrite exceeded its per-stream budget. The only observation
    /// here that does not reach [`Tier::Splice`]: the body could not be
    /// rewritten, which says nothing about whether requests can be filtered.
    RewriteExhausted,
}

impl Demotion {
    /// Every variant, in the order ties are broken when several are live.
    pub const ALL: [Self; 5] = [
        Self::LeafRejected,
        Self::UpstreamRefusedProxy,
        Self::UpstreamUntrusted,
        Self::ProtocolRefused,
        Self::RewriteExhausted,
    ];

    const COUNT: usize = Self::ALL.len();

    /// This cause's slot in a host's expiry array. Total by construction: the
    /// sum is closed and every arm names a distinct index below [`Self::COUNT`].
    const fn slot(self) -> usize {
        match self {
            Self::LeafRejected => 0,
            Self::UpstreamRefusedProxy => 1,
            Self::UpstreamUntrusted => 2,
            Self::ProtocolRefused => 3,
            Self::RewriteExhausted => 4,
        }
    }

    /// The most Boreas may do for a host this was observed against.
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

    /// How long this observation stays believable.
    ///
    /// The trade is one-sided in both directions, so it is set per cause rather
    /// than globally: too short and the user meets the same broken page again,
    /// too long and coverage never returns after the world changes. What
    /// changes the world differs by cause — an app ships a new pin set in days,
    /// a captive portal clears in minutes — so the interval follows the cause
    /// that would have to change.
    #[must_use]
    pub const fn ttl(self) -> Duration {
        const HOUR: u64 = 60 * 60;
        Duration::from_secs(match self {
            // A pin set or a server's certificate policy changes when software
            // ships, which is days; re-probing sooner only re-breaks the page.
            Self::LeafRejected | Self::UpstreamRefusedProxy | Self::ProtocolRefused => 12 * HOUR,
            // A portal, a skewed clock, or an expired chain resolves in
            // minutes, and re-probing costs exactly one connection.
            Self::UpstreamUntrusted => 5 * 60,
            // A document changes when the site deploys.
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

/// What a host's recorded history permits.
///
/// The tier is *derived* from the cause rather than stored beside it, so a
/// standing that claims a tier its cause does not justify cannot be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// Nothing live is recorded: the whole stack applies.
    Unrestricted,
    /// A recorded observation caps what Boreas may do, and names itself.
    Limited(Demotion),
}

impl Standing {
    /// The cap. [`Tier::TOP`] exactly when nothing is recorded.
    #[must_use]
    pub fn tier(self) -> Tier {
        match self {
            Self::Unrestricted => Tier::TOP,
            Self::Limited(cause) => cause.tier(),
        }
    }

    /// The cause, for a caller that needs to say *why* rather than *how much*.
    #[must_use]
    pub fn cause(self) -> Option<Demotion> {
        match self {
            Self::Unrestricted => None,
            Self::Limited(cause) => Some(cause),
        }
    }
}

/// Which side of an intercepted connection a failure came from.
///
/// The legs produce disjoint evidence — the client can only reject the leaf
/// Boreas forged, and only the server can refuse the proxy or present a
/// certificate that does not validate — so classification is a function of both
/// the error and the leg, and neither alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Leg {
    /// Boreas as the server, terminating the client's TLS.
    Client,
    /// Boreas as the client, opening TLS to the real server.
    Upstream,
}

/// Reads a handshake failure as evidence, or as nothing.
///
/// Total, with `None` meaning "this proves nothing about interception" — which
/// is the answer for every I/O error, every timeout, and every reset, because
/// none of them will recur predictably and demoting on them would let a bad
/// minute of network disable filtering for half a day.
///
/// O(1): one downcast and one match. No allocation.
/// **The two legs run different TLS implementations, so they carry different
/// evidence.** Boreas terminates the client with rustls and originates upstream
/// with BoringSSL — see [`mirror`](crate::Originator) for why the asymmetry is
/// deliberate — so this dispatches on the leg first and reads each side's own
/// error type. A single downcast would silently classify nothing on whichever
/// leg it did not name, which is exactly how half a demotion lattice stops
/// working without anything failing.
#[must_use]
pub fn classify(leg: Leg, error: &io::Error) -> Option<Demotion> {
    let inner = error.get_ref()?;
    match leg {
        Leg::Client => terminating(inner.downcast_ref::<TlsError>()?),
        Leg::Upstream => originating(inner.downcast_ref::<HandshakeFailure>()?.refusal?),
    }
}

/// Evidence from rustls, terminating the client.
///
/// `tokio-rustls` reports a protocol failure as `InvalidData` wrapping the
/// `rustls::Error`, which is the only place the alert survives; anything else
/// is transport trouble and not evidence.
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

/// Evidence from BoringSSL, originating to the server.
///
/// Total over [`Refusal`], which is the point of that sum: the three arms are
/// the three distinguishable outcomes, and each maps to exactly one remedy.
fn originating(refusal: Refusal) -> Option<Demotion> {
    match refusal {
        // Either side may be the one that finds no shared protocol, and the
        // remedy is the same from both.
        Refusal::NoProtocol | Refusal::Alert(ALERT_NO_APPLICATION_PROTOCOL) => {
            Some(Demotion::ProtocolRefused)
        }
        // Boreas rejected the server, rather than the server rejecting Boreas.
        Refusal::Untrusted => Some(Demotion::UpstreamUntrusted),
        Refusal::Alert(alert) => conclusive_alert(alert).then_some(Demotion::UpstreamRefusedProxy),
    }
}

/// RFC 8446's alert descriptions this module names.
const ALERT_CLOSE_NOTIFY: u8 = 0;
const ALERT_USER_CANCELED: u8 = 90;
const ALERT_NO_APPLICATION_PROTOCOL: u8 = 120;

/// Whether an alert will recur on the next attempt.
///
/// Almost all of them will: an alert is a peer deliberately refusing *this*
/// handshake, and the next one presents the same certificate from the same
/// address to the same peer. The two exceptions are the alerts that are not
/// refusals at all — an orderly close, and a peer that changed its mind.
fn conclusive(alert: AlertDescription) -> bool {
    !matches!(
        alert,
        AlertDescription::CloseNotify | AlertDescription::UserCanceled
    )
}

/// The same question asked of BoringSSL's raw description byte, which is what
/// [`Refusal::Alert`] carries. Kept beside [`conclusive`] so the two exceptions
/// are stated once and cannot drift apart.
fn conclusive_alert(alert: u8) -> bool {
    !matches!(alert, ALERT_CLOSE_NOTIFY | ALERT_USER_CANCELED)
}

/// When each cause was last observed against one host, as the instant it stops
/// counting. Storing the expiry rather than the observation keeps the read path
/// to a single comparison and independent of the TTL table.
type Expiries = [Option<Instant>; Demotion::COUNT];

/// Hosts to prune at. Not a bound — the key space is already bounded by the
/// allowlist — just the size at which returning memory is worth a sweep.
const PRUNE_AT: usize = 1024;

struct Table {
    hosts: HashMap<String, Expiries>,
    /// The size that triggers the next sweep, raised past the live set each
    /// time so a table that cannot shrink is not swept on every write. This is
    /// what makes pruning amortized $O(1)$ rather than $O(n)$ per record.
    prune_at: usize,
}

/// What interception has been observed to fail at, per host.
///
/// Reads dominate by orders of magnitude — one per connection against one per
/// failure — so this is an `RwLock` over a `HashMap` rather than anything
/// cleverer. The critical sections hold no `await` and perform one hash probe,
/// so a contended writer cannot stall a reader for longer than that probe.
///
/// `HashMap`'s SipHash matters here for the same reason it does in
/// [`InterceptPolicy`](crate::InterceptPolicy): the key is a name an attacker
/// chooses.
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

    /// What `host` currently permits.
    ///
    /// The meet over every live cause, witnessed by the cause that achieves it;
    /// ties go to the earlier member of [`Demotion::ALL`], so the answer is
    /// deterministic rather than dependent on iteration order.
    ///
    /// $O(1)$ expected: one hash probe under a shared lock, then a fold over a
    /// constant number of slots, one per variant of [`Demotion`].
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

    /// Records one observation and reports the standing that results.
    ///
    /// Idempotent in the lattice: recording the same cause twice refreshes its
    /// expiry and changes nothing else, and recording two causes in either
    /// order reaches the same standing.
    ///
    /// $O(1)$ amortized under an exclusive lock; the periodic sweep is $O(n)$
    /// in hosts but its threshold rises past the live set each time.
    pub fn record(&self, host: &str, cause: Demotion, now: Instant) -> Standing {
        let expiry = now.checked_add(cause.ttl());
        let mut table = self
            .table
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        if table.hosts.len() >= table.prune_at && !table.hosts.contains_key(host) {
            table
                .hosts
                .retain(|_, expiries| expiries.iter().any(|slot| live(*slot, now)));
            table.prune_at = PRUNE_AT.max(table.hosts.len().saturating_mul(2));
        }
        let expiries = table.hosts.entry(host.to_owned()).or_default();
        expiries[cause.slot()] = expiry;

        Demotion::ALL
            .into_iter()
            .filter(|cause| live(expiries[cause.slot()], now))
            .min_by_key(|cause| cause.tier())
            .map_or(Standing::Unrestricted, Standing::Limited)
    }

    /// Hosts with an entry, live or not. For observability; an operator reading
    /// a growing number here is reading a growing allowlist.
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

/// A recorded expiry that has not passed. An absent expiry is a cause never
/// observed; a saturated one is an interval past the end of the clock, which
/// cannot arrive and so is treated as expired.
fn live(expiry: Option<Instant>, now: Instant) -> bool {
    expiry.is_some_and(|expiry| expiry > now)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "pinned.example";

    /// A base instant every test measures from, so no test reads the clock
    /// twice and none of them can be flaky about elapsed real time.
    fn epoch() -> Instant {
        Instant::now()
    }

    /// The lattice laws, checked exhaustively rather than by sampling: three
    /// points means 27 triples, which is cheaper to enumerate than to generate.
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

    /// Every cause must have its own slot, or two causes would overwrite each
    /// other's expiry and one would silently never apply.
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

    /// The observable P15 behaviour: one conclusive failure is enough, and the
    /// host stops being intercepted from the next connection onward.
    #[test]
    fn one_conclusive_failure_demotes_the_host_to_splice() {
        let now = epoch();
        let demotions = Demotions::new();
        let standing = demotions.record(HOST, Demotion::LeafRejected, now);
        assert_eq!(standing, Standing::Limited(Demotion::LeafRejected));
        assert_eq!(standing.tier(), Tier::Splice);
        assert_eq!(demotions.standing(HOST, now).tier(), Tier::Splice);
        // Other hosts are untouched: demotion is per host, never global.
        assert_eq!(
            demotions.standing("other.example", now),
            Standing::Unrestricted
        );
    }

    /// The reason [`Tier`] has three points rather than two: a rewrite that
    /// blew its budget must not cost the URL filtering, which is the tier that
    /// carries most of the product's value.
    #[test]
    fn an_exhausted_rewrite_stops_rewriting_and_nothing_else() {
        let now = epoch();
        let demotions = Demotions::new();
        assert_eq!(
            demotions
                .record(HOST, Demotion::RewriteExhausted, now)
                .tier(),
            Tier::Inspect
        );
    }

    /// Recording is a meet, so the order two failures arrive in cannot change
    /// where the host ends up, and repeating one changes nothing.
    #[test]
    fn recording_is_idempotent_and_order_independent() {
        let now = epoch();
        let ordered = Demotions::new();
        ordered.record(HOST, Demotion::RewriteExhausted, now);
        ordered.record(HOST, Demotion::LeafRejected, now);

        let reversed = Demotions::new();
        reversed.record(HOST, Demotion::LeafRejected, now);
        reversed.record(HOST, Demotion::RewriteExhausted, now);
        reversed.record(HOST, Demotion::LeafRejected, now);

        assert_eq!(ordered.standing(HOST, now), reversed.standing(HOST, now));
        assert_eq!(ordered.standing(HOST, now).tier(), Tier::Splice);

        // And the witness agrees with the fold the lattice defines.
        let folded = [Demotion::RewriteExhausted, Demotion::LeafRejected]
            .into_iter()
            .fold(Tier::TOP, |tier, cause| tier.meet(cause.tier()));
        assert_eq!(ordered.standing(HOST, now).tier(), folded);
    }

    /// Expiry is per cause, and a lapsed cause must stop hiding a live one —
    /// which is exactly what a single "worst tier so far" field would get wrong.
    #[test]
    fn a_lapsed_cause_stops_applying_without_hiding_a_live_one() {
        let now = epoch();
        let demotions = Demotions::new();
        demotions.record(HOST, Demotion::UpstreamUntrusted, now);
        demotions.record(HOST, Demotion::RewriteExhausted, now);
        assert_eq!(demotions.standing(HOST, now).tier(), Tier::Splice);

        // Past the short-lived cause but not the long-lived one: the host is
        // intercepted again, and still not rewritten.
        let later = now + Demotion::UpstreamUntrusted.ttl() + Duration::from_secs(1);
        assert_eq!(
            demotions.standing(HOST, later),
            Standing::Limited(Demotion::RewriteExhausted)
        );

        let much_later = now + Demotion::RewriteExhausted.ttl() + Duration::from_secs(1);
        assert_eq!(demotions.standing(HOST, much_later), Standing::Unrestricted);
    }

    /// A sweep must reclaim dead hosts and must never drop a live one, or a
    /// demoted host would silently come back before its interval.
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

        // Every entry above has lapsed by now; one fresh record triggers the
        // sweep that reclaims them.
        let later = now + Demotion::LeafRejected.ttl() + Duration::from_secs(1);
        demotions.record(HOST, Demotion::LeafRejected, later);
        assert_eq!(demotions.len(), 1, "the sweep reclaimed the lapsed hosts");
        assert_eq!(demotions.standing(HOST, later).tier(), Tier::Splice);
    }

    fn tls_error(error: TlsError) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, error)
    }

    /// The upstream leg's shape: BoringSSL's verdict, as `mirror` wraps it.
    fn boring_error(refusal: Refusal) -> io::Error {
        io::Error::other(HandshakeFailure::new(Some(refusal), "synthesized"))
    }

    /// The classifier's whole job: name conclusive TLS refusals, and refuse to
    /// read anything into transport trouble.
    #[test]
    fn only_conclusive_tls_refusals_are_evidence() {
        assert_eq!(
            classify(
                Leg::Client,
                &tls_error(TlsError::AlertReceived(AlertDescription::UnknownCA))
            ),
            Some(Demotion::LeafRejected)
        );
        // The upstream leg is BoringSSL, so its evidence is a `Refusal` and
        // not a `rustls::Error`. Alert 116 is `certificate_required`.
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
        // Each leg reads only its own implementation's errors: a rustls error
        // arriving from the upstream leg is not evidence, and vice versa.
        assert_eq!(
            classify(Leg::Upstream, &tls_error(TlsError::NoApplicationProtocol)),
            None
        );
        assert_eq!(
            classify(Leg::Client, &boring_error(Refusal::Untrusted)),
            None
        );

        // Transport trouble proves nothing, and this is the half that matters:
        // a flaky network must not disable filtering for half a day.
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
        // An orderly close and a peer that changed its mind are not refusals.
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

    /// The legs read the same error differently, and must: only the server can
    /// refuse the proxy, and only the client can refuse the forged leaf.
    #[test]
    fn the_two_legs_read_the_same_alert_as_different_evidence() {
        // `handshake_failure`, alert 40, seen from each side. The legs run
        // different TLS implementations, so the same alert arrives in two
        // shapes — and still has to mean two different things.
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
