//! Every wait this crate performs on a network peer, named and bounded.
//!
//! **The clients this serves move.** A handset walks out of Wi-Fi range and
//! onto cellular, and the path it was using does not close — it stops
//! existing. Nothing arrives to say so: no RST, no ICMP, no FIN. The peer is
//! still holding its half, and this side is still holding a task, a socket, and
//! whatever buffer the connection had reserved. A deadline is the only thing
//! that ever ends such a connection, which is why an unbounded wait here is not
//! a latency question but a leak.
//!
//! **The values are aggressive on purpose, and that is a deliberate departure
//! from what browsers ship.** Chromium's own transport connect job allows four
//! minutes (`TcpConnectJob::ConnectionTimeout`) and its TLS handshake thirty
//! seconds (`kSSLHandshakeTimeout`); those are anti-hang backstops layered under
//! a 300 ms fallback timer, and they are survivable in a browser because a
//! person can close the tab. Nothing closes a tab here. The numbers below come
//! instead from the proxies that live under the same constraint — HAProxy's and
//! Envoy's 5 s connect defaults — and from the measurement that governs mobile:
//! 74% of carrier NATs expire idle state within a minute, with a cellular
//! median mapping lifetime of 65 s (Richter et al., IMC'16), so a path that has
//! not answered in seconds is gone rather than slow.
//!
//! Idle timeouts are *not* here, and the omission is the point. RFC 4787 REQ-5
//! binds a mapping to at least two minutes and [`crate::UdpFlowTable`] refuses
//! anything shorter, so those bounds belong to the state that expires rather
//! than to a wait that never returns.

use std::{io, time::Duration};

/// What a bounded wait is waiting for.
///
/// A sum rather than a struct of durations because the budget is a property of
/// the *kind* of wait, not of a configuration: a caller names what it is doing
/// and the number follows. That is what keeps a new dial path from inventing a
/// fifth number, and what makes an expiry legible in a log — the error carries
/// the name, so "which of the four handshakes stalled" is answered without a
/// span.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wait {
    /// One TCP connect. Covers a single SYN retransmission (Linux's first RTO
    /// is 1 s, its second 3 s) with slack; past that the SYN is not being
    /// answered rather than being answered slowly. HAProxy's `timeout connect`
    /// and Envoy's cluster `connect_timeout` both default here, and HAProxy's
    /// manual asks for "slightly above multiples of 3 seconds" for exactly this
    /// reason.
    TcpConnect,
    /// One TLS handshake over a connection that is already up. Chromium allows
    /// 30 s and arms the timer only when the handshake starts rather than
    /// sharing a budget with the connect beneath it; this keeps that structure
    /// and tightens the number, because a handshake still unfinished after ten
    /// seconds on a mobile path is one whose path went away mid-flight.
    TlsHandshake,
    /// A whole dial through an egress: the connect, the TLS under it, the
    /// transport's own upgrade, and the proxy protocol's negotiation. The
    /// backstop for the sum, and the only bound that catches a proxy which
    /// accepts the connection and then never speaks — the shape a stalled
    /// cellular path takes most often, because the SYN got through before the
    /// handover and nothing after it did.
    ProxyDial,
    /// One client's TLS handshake against this proxy's own listener. Envoy
    /// leaves the equivalent (`transport_socket_connect_timeout`) unset by
    /// default and documents that unset means unlimited, which is a slowloris
    /// surface; naming it here means it cannot be left unset.
    ClientHandshake,
}

impl Wait {
    /// The budget, in the same shape [`crate::Demotion::ttl`] uses: a `match`
    /// in a `const fn`, so the table is one expression and a new variant
    /// without a number does not compile.
    pub const fn budget(self) -> Duration {
        Duration::from_secs(match self {
            Self::TcpConnect => 5,
            Self::TlsHandshake | Self::ClientHandshake => 10,
            Self::ProxyDial => 15,
        })
    }

    /// What an expiry looks like to a caller.
    fn expired(self) -> io::Error {
        io::Error::new(io::ErrorKind::TimedOut, self.describe())
    }

    const fn describe(self) -> &'static str {
        match self {
            Self::TcpConnect => "TCP connect timed out",
            Self::TlsHandshake => "TLS handshake timed out",
            Self::ProxyDial => "dial through the egress timed out",
            Self::ClientHandshake => "the client's TLS handshake timed out",
        }
    }
}

/// Runs `work` under `wait`'s budget.
///
/// Expiry arrives as an `io::Error` of kind `TimedOut` rather than as a new
/// error type, because every seam this wraps already carries one: `E: From<
/// io::Error>` is satisfied by `io::Error` itself and by [`crate::EgressError`],
/// so a bound can be added to a dial path without threading a conversion
/// through it. The alternative — an `Expired` of its own — would be a second
/// `?` at every call site to say something the existing kind already says.
///
/// Cancellation-safe exactly as far as `work` is: the timer holds no state, so
/// dropping this drops `work` and nothing else.
pub async fn within<T, E, F>(wait: Wait, work: F) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
    E: From<io::Error>,
{
    match tokio::time::timeout(wait.budget(), work).await {
        Ok(finished) => finished,
        Err(_elapsed) => Err(wait.expired().into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The budgets nest: a dial contains a connect and a handshake, so a total
    /// smaller than its parts would make the outer bound the only one that ever
    /// fires and the inner names meaningless.
    #[test]
    fn a_whole_dial_allows_at_least_its_parts() {
        assert!(
            Wait::ProxyDial.budget() >= Wait::TcpConnect.budget() + Wait::TlsHandshake.budget()
        );
    }

    /// Aggressive is the point, but a budget under a second would fail a
    /// handshake on any path with a real round trip. RFC 9002's `kInitialRtt`
    /// is 333 ms and a cold PTO about three times that, so a second is the
    /// floor at which a first attempt is even possible.
    #[test]
    fn no_budget_is_shorter_than_one_round_trips_worth_of_retries() {
        for wait in [
            Wait::TcpConnect,
            Wait::TlsHandshake,
            Wait::ProxyDial,
            Wait::ClientHandshake,
        ] {
            assert!(wait.budget() >= Duration::from_secs(1), "{wait:?}");
            assert!(wait.budget() <= Duration::from_secs(30), "{wait:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_wait_that_never_finishes_becomes_a_timed_out_io_error() {
        let error: io::Error = within(Wait::TcpConnect, async {
            std::future::pending::<Result<(), io::Error>>().await
        })
        .await
        .expect_err("a pending future cannot succeed");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("TCP connect"));
    }

    #[tokio::test(start_paused = true)]
    async fn work_that_finishes_inside_its_budget_is_untouched() {
        let value: Result<u8, io::Error> = within(Wait::ProxyDial, async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(7)
        })
        .await;
        assert_eq!(value.unwrap(), 7);
    }
}
