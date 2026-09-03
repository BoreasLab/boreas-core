//! A connection shared between callers and opened by its own task.
//!
//! Opening runs on a spawned task under one dial budget, so a caller that
//! stops waiting cancels only its wait: the handshake completes and serves
//! the next caller. Concurrent callers share one attempt. A failed attempt
//! fails the callers waiting on it and leaves nothing behind, so the next
//! caller dials again.

use std::{
    io,
    sync::{Arc, Mutex},
};

use tokio::sync::watch;

/// Outcome of one dial, as callers waiting on it receive it.
type Outcome<C> = Option<Result<C, io::ErrorKind>>;

enum State<C> {
    Down,
    Opening(watch::Receiver<Outcome<C>>),
    Up(C),
}

pub(crate) struct Live<C> {
    state: Arc<Mutex<State<C>>>,
}

impl<C: Clone + Send + Sync + 'static> Live<C> {
    pub(crate) fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(State::Down)),
        }
    }

    /// The connection that is up right now, if one is; never dials.
    pub(crate) fn peek(&self) -> Option<C> {
        match &*crate::locked(&self.state) {
            State::Up(connection) => Some(connection.clone()),
            State::Opening(_) | State::Down => None,
        }
    }

    /// The live connection, or the one `open` yields. `alive` tells a
    /// connection still worth handing out from one to replace.
    pub(crate) async fn get<F>(&self, alive: impl Fn(&C) -> bool, open: F) -> io::Result<C>
    where
        F: Future<Output = io::Result<C>> + Send + 'static,
    {
        let mut waiting = {
            let mut state = crate::locked(&self.state);
            match &*state {
                State::Up(connection) if alive(connection) => return Ok(connection.clone()),
                State::Opening(waiting) => waiting.clone(),
                State::Up(_) | State::Down => {
                    let (report, waiting) = watch::channel(None);
                    *state = State::Opening(waiting.clone());
                    tokio::spawn(dial(Arc::clone(&self.state), open, report));
                    waiting
                }
            }
        };
        let outcome = waiting
            .wait_for(Option::is_some)
            .await
            .map_err(|_| failed(io::ErrorKind::ConnectionAborted))?;
        match outcome.as_ref().expect("waited for a value") {
            Ok(connection) => Ok(connection.clone()),
            Err(kind) => Err(failed(*kind)),
        }
    }
}

async fn dial<C: Clone + Send + Sync + 'static, F>(
    state: Arc<Mutex<State<C>>>,
    open: F,
    report: watch::Sender<Outcome<C>>,
) where
    F: Future<Output = io::Result<C>> + Send + 'static,
{
    let outcome = crate::within(crate::Wait::ProxyDial, open).await;
    *crate::locked(&state) = match &outcome {
        Ok(connection) => State::Up(connection.clone()),
        Err(_) => State::Down,
    };
    let _ = report.send(Some(outcome.map_err(|error| error.kind())));
}

fn failed(kind: io::ErrorKind) -> io::Error {
    io::Error::new(kind, "the upstream connection failed to open")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    /// A caller's deadline cancels its wait, not the dial: the connection
    /// still comes up and the next caller gets it without a second dial.
    #[tokio::test(start_paused = true)]
    async fn a_caller_that_gives_up_does_not_cancel_the_handshake() {
        let live = Arc::new(Live::<u32>::new());
        let dials = Arc::new(AtomicUsize::new(0));
        let open = {
            let dials = Arc::clone(&dials);
            move || {
                let dials = Arc::clone(&dials);
                async move {
                    dials.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    Ok(7)
                }
            }
        };

        let impatient =
            tokio::time::timeout(Duration::from_secs(1), live.get(|_| true, open())).await;
        assert!(impatient.is_err(), "the caller timed out");

        let patient = live.get(|_| true, open()).await.unwrap();
        assert_eq!(patient, 7);
        assert_eq!(dials.load(Ordering::Relaxed), 1, "one dial served both");
    }

    #[tokio::test]
    async fn concurrent_callers_share_one_dial_and_a_dead_connection_is_replaced() {
        let live = Arc::new(Live::<u32>::new());
        let dials = Arc::new(AtomicUsize::new(0));
        let open = {
            let dials = Arc::clone(&dials);
            move || {
                let dials = Arc::clone(&dials);
                async move {
                    let n = dials.fetch_add(1, Ordering::Relaxed) as u32;
                    tokio::task::yield_now().await;
                    Ok(n)
                }
            }
        };
        let first = tokio::spawn({
            let (live, open) = (Arc::clone(&live), open.clone());
            async move { live.get(|_| true, open()).await.unwrap() }
        });
        let second = tokio::spawn({
            let (live, open) = (Arc::clone(&live), open.clone());
            async move { live.get(|_| true, open()).await.unwrap() }
        });
        assert_eq!(first.await.unwrap(), second.await.unwrap());
        assert_eq!(dials.load(Ordering::Relaxed), 1);

        // Declared dead: the next get dials again.
        assert_eq!(live.get(|_| false, open()).await.unwrap(), 1);
        assert_eq!(live.get(|_| true, open()).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn a_failed_dial_fails_its_waiters_and_leaves_nothing_behind() {
        let live = Live::<u32>::new();
        let refused = live
            .get(|_| true, async {
                Err::<u32, _>(io::Error::from(io::ErrorKind::ConnectionRefused))
            })
            .await;
        assert_eq!(
            refused.unwrap_err().kind(),
            io::ErrorKind::ConnectionRefused
        );
        assert_eq!(live.get(|_| true, async { Ok(9) }).await.unwrap(), 9);
    }
}
