//! Operating-system signals, turned into something the shutdown state machine
//! can wait on.
//!
//! This module owns *when* a shutdown starts and nothing about what happens
//! next. In particular it never touches a caller's [`tokio_util::sync::
//! CancellationToken`]: being handed the server's own token was VEGA-046 — a
//! `SIGTERM` then cancelled the DNS accept loops directly, the sockets were gone
//! 1.3 ms later, and no readiness probe could ever be told to stop sending us
//! traffic. [`watch()`] therefore takes no arguments; the ordering of the three
//! tokens lives in `main::serve`, where it can be read in one place.
//!
//! `SIGTERM` is what Docker, Kubernetes and systemd send first. `SIGINT` comes
//! from a terminal and a human, so it runs the same machine with a zero-length
//! drain window (§2.5). `SIGHUP` is caught and ignored: unhandled, its default
//! disposition terminates the process outright, which is a strictly worse outage
//! than the one this module exists to prevent.

use std::sync::{Arc, OnceLock};

use tokio::sync::watch;
use tracing::{info, warn};

/// What started the shutdown. The only thing that varies between them is the
/// length of the drain window.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Cause {
    /// `SIGTERM`: an orchestrator or supervisor. Honours the drain window.
    Term,
    /// `SIGINT`: a human at a terminal. Zero-length window.
    Int,
    /// An internal fatal error, injected by [`Signals::abort`]. Zero-length
    /// window, because draining is pointless when nothing can observe the 503.
    Abort,
}

impl Cause {
    /// The name an operator greps for.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Term => "SIGTERM",
            Self::Int => "SIGINT",
            Self::Abort => "internal abort",
        }
    }

    /// How long to keep answering DNS while `/readyz` reports 503.
    ///
    /// `SIGINT` skips the window because no orchestrator sends it: Kubernetes,
    /// systemd and Docker all send `SIGTERM`, so making Ctrl-C block a developer
    /// for fifteen seconds is a pure usability tax. An internal abort skips it
    /// because the admin listener — the only thing that could serve the 503 — is
    /// what just died.
    pub fn drain_window(self, configured: std::time::Duration) -> std::time::Duration {
        match self {
            Self::Term => configured,
            Self::Int | Self::Abort => std::time::Duration::ZERO,
        }
    }
}

/// A handle on the process's termination signals.
///
/// Cheap to clone; every clone observes the same signals. Cloning is how the
/// admin task reaches [`Signals::abort`] without being given a token it could
/// cancel.
#[derive(Clone, Debug)]
pub struct Signals {
    /// Count of shutdown-worthy signals delivered so far. A counter rather than
    /// a flag so the n-th signal is distinguishable from the first, which is
    /// what lets [`Signals::again`] collapse a window that is already open.
    count: Arc<watch::Sender<u32>>,
    /// What the *first* signal was. Written before the count is bumped, so a
    /// reader that has seen the count has seen the cause.
    cause: Arc<OnceLock<Cause>>,
}

/// Start listening for termination signals.
///
/// Returns immediately. Takes no token, and must keep taking none: see the
/// module documentation.
pub fn watch() -> Signals {
    let (count, _) = watch::channel(0u32);
    let signals = Signals {
        count: Arc::new(count),
        cause: Arc::new(OnceLock::new()),
    };

    tokio::spawn(listen(signals.clone()));

    signals
}

impl Signals {
    /// Resolve on the first `SIGTERM`/`SIGINT`, or on an injected abort.
    ///
    /// Reports which one, because that decides the drain window. If a signal
    /// arrived before this is first awaited it resolves immediately — the
    /// machine must not be able to miss a signal it has already been sent.
    pub async fn first(&self) -> Cause {
        let mut rx = self.count.subscribe();
        while *rx.borrow_and_update() == 0 {
            if rx.changed().await.is_err() {
                // Unreachable while the process lives: the sender is owned by a
                // task that never returns. Never resolving is the safe answer —
                // a spurious "signal" would start a shutdown nobody asked for.
                std::future::pending::<()>().await;
            }
        }
        // Set before the count was bumped, so this is populated. `Term` is the
        // conservative fallback: a full drain, never a shortened one.
        self.cause.get().copied().unwrap_or(Cause::Term)
    }

    /// Resolve on the next signal *after* this call.
    ///
    /// Used to collapse whatever the machine is currently waiting on. A second
    /// signal means "hurry up", not "corrupt yourself": it never exits the
    /// process and never skips a phase. `SIGKILL` is the immediate-exit
    /// mechanism and every supervisor already has it wired to a timeout.
    pub async fn again(&self) {
        let mut rx = self.count.subscribe();
        let baseline = *rx.borrow_and_update();
        loop {
            if rx.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
            if *rx.borrow_and_update() > baseline {
                return;
            }
        }
    }

    /// Start the shutdown machine from inside the process.
    ///
    /// The fatal-admin-error path calls this instead of cancelling the DNS
    /// token. Cancelling it directly is what made a mid-life admin failure kill
    /// DNS instantly with no drain at all (failure mode 3).
    pub fn abort(&self) {
        let _ = self.cause.set(Cause::Abort);
        self.bump();
    }

    /// Publish one more signal.
    fn bump(&self) {
        self.count
            .send_modify(|count| *count = count.saturating_add(1));
    }

    /// Record the first cause, then publish the signal. Order matters: a reader
    /// that observes the count must be able to read the cause.
    fn deliver(&self, cause: Cause) {
        let first = self.cause.set(cause).is_ok();
        self.bump();
        if first {
            info!(signal = cause.as_str(), "shutdown signal received");
        } else {
            info!(
                signal = cause.as_str(),
                "another shutdown signal; collapsing the remaining window"
            );
        }
    }
}

/// Wait for signals forever, feeding them to `signals`.
///
/// Never returns: after the first signal the machine still wants the second, and
/// after the second it still wants to log the tenth rather than let its default
/// disposition apply.
#[cfg(unix)]
async fn listen(signals: Signals) {
    use tokio::signal::unix::{signal, SignalKind};

    // If a handler cannot be installed there is nothing sensible left to do but
    // fall back to what we can hear. Losing SIGTERM handling entirely would mean
    // the default disposition kills us with no drain, so it is logged loudly.
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(stream) => Some(stream),
        Err(error) => {
            warn!(%error, "could not listen for SIGTERM; it will terminate the process undrained");
            None
        }
    };
    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(stream) => Some(stream),
        Err(error) => {
            warn!(%error, "could not listen for SIGINT");
            None
        }
    };
    // Ignoring SIGHUP is a two-line fix for an undrained kill. Mapping it to a
    // reload is the conventional name-server behaviour and may well be right,
    // but that is a reload-semantics decision and belongs to VEGA-005.
    let mut sighup = match signal(SignalKind::hangup()) {
        Ok(stream) => Some(stream),
        Err(error) => {
            warn!(%error, "could not listen for SIGHUP; a terminal hangup will kill the process");
            None
        }
    };

    loop {
        let cause = tokio::select! {
            Some(()) = recv(sigterm.as_mut()) => Cause::Term,
            Some(()) = recv(sigint.as_mut()) => Cause::Int,
            Some(()) = recv(sighup.as_mut()) => {
                warn!("SIGHUP ignored; use POST /reload to reload the zone");
                continue;
            }
            else => break,
        };
        signals.deliver(cause);
    }

    // Reached only if every stream has ended, which in practice means the signal
    // driver is going away with the runtime. Waiting forever beats returning:
    // a `Signals` whose sender has been dropped would resolve `first()` for
    // every waiter at once, i.e. announce a shutdown nobody asked for.
    warn!("signal handling has stopped; shutdown must now come from SIGKILL");
    std::future::pending::<()>().await;
}

/// `recv` on an optional stream, resolving to `None` when there is none.
///
/// `select!` disables a branch whose pattern does not match, so a `None` here
/// takes that signal out of the loop instead of spinning on it.
#[cfg(unix)]
async fn recv(stream: Option<&mut tokio::signal::unix::Signal>) -> Option<()> {
    match stream {
        Some(stream) => stream.recv().await,
        None => std::future::pending().await,
    }
}

/// Ctrl-C is the only portable signal, and it means the same thing as `SIGINT`.
#[cfg(not(unix))]
async fn listen(signals: Signals) {
    loop {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
        signals.deliver(Cause::Int);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn nothing_resolves_without_a_signal() {
        let signals = watch();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), signals.first())
                .await
                .is_err(),
            "a shutdown must not start on its own"
        );
    }

    #[tokio::test]
    async fn an_abort_starts_the_machine_with_a_zero_window() {
        let signals = watch();
        signals.abort();
        assert_eq!(signals.first().await, Cause::Abort);
        assert_eq!(
            Cause::Abort.drain_window(Duration::from_secs(15)),
            Duration::ZERO
        );
    }

    #[tokio::test]
    async fn a_signal_delivered_before_the_machine_waits_is_not_missed() {
        // The race this pins: `first()` awaited only after the process is fully
        // up, while the signal arrived during startup.
        let signals = watch();
        signals.deliver(Cause::Term);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(50), signals.first())
                .await
                .ok(),
            Some(Cause::Term)
        );
    }

    #[tokio::test]
    async fn again_waits_for_a_signal_later_than_the_one_that_started_us() {
        let signals = watch();
        signals.deliver(Cause::Term);
        assert_eq!(signals.first().await, Cause::Term);

        assert!(
            tokio::time::timeout(Duration::from_millis(50), signals.again())
                .await
                .is_err(),
            "the signal that started the shutdown must not also collapse the window"
        );

        let waiting = signals.clone();
        let collapse = tokio::spawn(async move { waiting.again().await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        signals.deliver(Cause::Term);
        tokio::time::timeout(Duration::from_millis(200), collapse)
            .await
            .expect("a second signal collapses the window")
            .expect("the waiter does not panic");
    }

    #[tokio::test]
    async fn the_cause_is_whatever_arrived_first_however_many_follow() {
        let signals = watch();
        signals.deliver(Cause::Int);
        signals.deliver(Cause::Term);
        signals.abort();
        assert_eq!(signals.first().await, Cause::Int);
    }

    #[test]
    fn only_sigterm_honours_the_drain_window() {
        let configured = Duration::from_secs(15);
        assert_eq!(Cause::Term.drain_window(configured), configured);
        assert_eq!(Cause::Int.drain_window(configured), Duration::ZERO);
        assert_eq!(Cause::Abort.drain_window(configured), Duration::ZERO);

        assert_eq!(Cause::Term.as_str(), "SIGTERM");
        assert_eq!(Cause::Int.as_str(), "SIGINT");
        assert_eq!(Cause::Abort.as_str(), "internal abort");
    }
}
