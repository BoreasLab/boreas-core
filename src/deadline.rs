//! Named, bounded waits for network operations.
//!
//! A mobile path can disappear without RST, ICMP, or FIN. A deadline is what
//! releases the task, socket, and buffers left waiting on that path.
//!
//! The budgets are shorter than browser defaults because this service has no
//! tab to close a stalled operation. They bound proxy connection, TLS, and
//! client-handshake work on mobile paths.
//!
//! UDP idle timeouts belong to [`crate::UdpFlowTable`], which enforces RFC 4787
//! REQ-5's two-minute minimum. They are state-expiry rules, not operation waits.

use std::{io, time::Duration};

/// Operation kind with a fixed timeout budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wait {
    /// One TCP connection attempt.
    TcpConnect,
    /// One TLS handshake over an established connection.
    TlsHandshake,
    /// A complete egress dial, including connection, TLS, upgrade, and proxy
    /// negotiation.
    ProxyDial,
    /// One client's TLS handshake with this proxy's listener.
    ClientHandshake,
}

impl Wait {
    /// Returns the fixed budget for this operation kind.
    pub const fn budget(self) -> Duration {
        Duration::from_secs(match self {
            Self::TcpConnect => 5,
            Self::TlsHandshake | Self::ClientHandshake => 10,
            Self::ProxyDial => 15,
        })
    }

    /// Converts expiry into the error type used by callers.
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

/// Runs `work` under the timeout selected by `wait`.
///
/// Expiry is reported as an `io::Error` of kind `TimedOut`, which existing
/// callers already convert through `From<io::Error>`. Dropping the wrapper
/// cancels `work` and retains no timer state.
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

    /// A complete dial budget must cover its connection and handshake parts.
    #[test]
    fn a_whole_dial_allows_at_least_its_parts() {
        assert!(
            Wait::ProxyDial.budget() >= Wait::TcpConnect.budget() + Wait::TlsHandshake.budget()
        );
    }

    /// Every budget is long enough for at least one round trip and bounded by
    /// the service's 30-second upper limit.
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
