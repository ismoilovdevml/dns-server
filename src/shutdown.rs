//! Turns operating-system termination signals into a [`CancellationToken`].
//!
//! `SIGTERM` is what Docker, Kubernetes and systemd send first, so handling it is
//! the difference between a clean drain and a container that gets `SIGKILL`ed
//! ten seconds later.

use tokio_util::sync::CancellationToken;
use tracing::info;

/// Spawn a task that cancels `token` on the first termination signal.
///
/// Returns immediately; the returned [`tokio::task::JoinHandle`] can be ignored.
pub fn watch(token: CancellationToken) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let signal = wait_for_signal().await;
        info!(signal, "shutdown signal received, draining");
        token.cancel();
    })
}

/// Wait for `SIGINT`/`SIGTERM` (Unix) or Ctrl-C (elsewhere).
///
/// Returns the name of the signal that fired, for logging.
#[cfg(unix)]
async fn wait_for_signal() -> &'static str {
    use tokio::signal::unix::{signal, SignalKind};

    // If we cannot install a handler there is nothing sensible left to do but
    // fall back to Ctrl-C only.
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(error) => {
            tracing::warn!(%error, "could not listen for SIGTERM");
            let _ = tokio::signal::ctrl_c().await;
            return "SIGINT";
        }
    };
    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(error) => {
            tracing::warn!(%error, "could not listen for SIGINT");
            sigterm.recv().await;
            return "SIGTERM";
        }
    };

    tokio::select! {
        _ = sigterm.recv() => "SIGTERM",
        _ = sigint.recv() => "SIGINT",
    }
}

#[cfg(not(unix))]
async fn wait_for_signal() -> &'static str {
    let _ = tokio::signal::ctrl_c().await;
    "CTRL_C"
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn token_is_not_cancelled_without_a_signal() {
        let token = CancellationToken::new();
        let _handle = watch(token.clone());
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!token.is_cancelled());
    }

    #[tokio::test]
    async fn cancelling_the_token_directly_still_works() {
        // The server wiring cancels the same token on fatal errors, so make sure
        // an external cancel is observable by everything waiting on it.
        let token = CancellationToken::new();
        let child = token.clone();
        token.cancel();
        assert!(child.is_cancelled());
        child.cancelled().await;
    }
}
