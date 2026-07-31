//! The process lifecycle phase, shared between the signal handler, the admin
//! endpoints and the metrics exporter.
//!
//! One `AtomicU8`, monotonic by construction: a phase never goes backwards, and
//! [`Lifecycle::enter`] is a compare-and-swap that refuses a backward
//! transition. That is what lets `/readyz`, `/version`, `/metrics` and `/reload`
//! each take a single `Acquire` load and know that every other endpoint answering
//! concurrently agrees with them about which way the process is going.
//!
//! The DNS query hot path never reads any of this — no branch, no atomic, no
//! cost. `Zone::lookup` and `DnsHandler::handle_request` are untouched by
//! shutdown; the ordering is delivered by *when* the listeners are cancelled, not
//! by a per-query check.
//!
//! Design: `.claude/backlog/decisions/VEGA-046-shutdown-drain.md` §1.1 and §11.

use std::{
    fmt,
    sync::{
        atomic::{AtomicU8, Ordering},
        OnceLock,
    },
    time::{Duration, Instant},
};

/// Where the process is in its life.
///
/// Ordered, and the discriminants are the values exported as
/// `dns_shutdown_phase`, so a dashboard built against them keeps working: a new
/// phase has to be appended, never inserted.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Phase {
    /// Binding listeners. `/readyz` is 503 because nothing is serving yet.
    Starting = 0,
    /// Steady state: listeners bound, `/readyz` is 200.
    Serving = 1,
    /// A shutdown has begun. `/readyz` is 503 **and DNS still answers** — the
    /// whole point of VEGA-046 is that these two overlap for the drain window.
    Draining = 2,
    /// The drain window has elapsed; waiting for in-flight requests to finish
    /// before the DNS listeners are cancelled. They are still bound.
    Stopping = 3,
    /// The DNS listeners are closed. The admin listener is still up so a probe
    /// keeps getting an answer until the last moment.
    Closing = 4,
}

impl Phase {
    /// The wire form, used in `X-Vega-Phase`, `/version` and log lines.
    ///
    /// Lowercase ASCII, which is what makes it safe to put in a header value
    /// without a fallible conversion at every call site.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Serving => "serving",
            Self::Draining => "draining",
            Self::Stopping => "stopping",
            Self::Closing => "closing",
        }
    }

    /// Rebuild a phase from the atomic.
    ///
    /// Total on purpose: only [`Lifecycle::enter`] ever writes the atomic and it
    /// only ever writes a discriminant, so the fallback is unreachable — but this
    /// is read from `/metrics` and `/readyz`, which are reachable from the
    /// network, and a `panic!` there is an outage under `panic = "abort"`.
    fn from_bits(bits: u8) -> Self {
        match bits {
            0 => Self::Starting,
            1 => Self::Serving,
            2 => Self::Draining,
            3 => Self::Stopping,
            _ => Self::Closing,
        }
    }
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The published phase, plus the shutdown deadline once one is armed.
///
/// Cheap to share: every reader is one atomic load, so the admin endpoints can
/// each answer from it without a lock and without agreeing on an order.
#[derive(Debug)]
pub struct Lifecycle {
    phase: AtomicU8,
    /// When the hard deadline expires. Set once, at the first signal, so
    /// `/metrics` can count it down for an operator watching a rollout.
    deadline: OnceLock<Instant>,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl Lifecycle {
    /// A process that has not finished binding its listeners.
    pub fn new() -> Self {
        Self {
            phase: AtomicU8::new(Phase::Starting as u8),
            deadline: OnceLock::new(),
        }
    }

    /// The current phase. One `Acquire` load, no lock, no allocation.
    pub fn phase(&self) -> Phase {
        Phase::from_bits(self.phase.load(Ordering::Acquire))
    }

    /// Advance to `next`, returning whether this call was the one that did it.
    ///
    /// Refuses to go backwards. That refusal is load-bearing rather than
    /// defensive: the admin task, the signal task and the main task all publish
    /// phases, and a `Serving` arriving late — a slow startup racing a fast
    /// `SIGTERM` — would otherwise re-advertise a draining process as ready.
    pub fn enter(&self, next: Phase) -> bool {
        let target = next as u8;
        let mut current = self.phase.load(Ordering::Acquire);
        loop {
            if current >= target {
                return false;
            }
            match self.phase.compare_exchange_weak(
                current,
                target,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    /// Whether `/readyz` should answer 200. Only ever true in [`Phase::Serving`].
    pub fn is_ready(&self) -> bool {
        self.phase() == Phase::Serving
    }

    /// Whether the process is on its way out, i.e. `Draining` or later.
    ///
    /// This is the gate `/reload` uses: swapping the zone into a process that is
    /// seconds from exiting cannot help anything, and is the exact window in
    /// which a reload can wedge the drain.
    pub fn is_draining(&self) -> bool {
        self.phase() >= Phase::Draining
    }

    /// Record when the shutdown must be over. First caller wins; later calls are
    /// ignored, so a second signal cannot move the deadline out.
    pub fn arm_deadline(&self, at: Instant) {
        let _ = self.deadline.set(at);
    }

    /// How long is left before the hard deadline, or `None` until it is armed.
    ///
    /// Saturates at zero rather than going negative: the value is exported as a
    /// gauge, and a negative "seconds remaining" is not something an operator
    /// should have to interpret at 3am.
    pub fn deadline_in(&self) -> Option<Duration> {
        self.deadline
            .get()
            .map(|at| at.saturating_duration_since(Instant::now()))
    }

    /// Append the two shutdown series to a Prometheus exposition body.
    ///
    /// A scrape that catches the drain is the only record we will ever have of
    /// it, so the phase is exported unconditionally. The deadline appears only
    /// once armed: an absent series says "no shutdown in progress" far more
    /// clearly than a sentinel value would.
    pub fn render_prometheus(&self, out: &mut String) {
        use fmt::Write as _;

        writeln!(
            out,
            "# HELP dns_shutdown_phase Lifecycle phase: 0 starting, 1 serving, 2 draining, 3 stopping, 4 closing."
        )
        .ok();
        writeln!(out, "# TYPE dns_shutdown_phase gauge").ok();
        writeln!(out, "dns_shutdown_phase {}", self.phase() as u8).ok();

        if let Some(remaining) = self.deadline_in() {
            writeln!(
                out,
                "# HELP dns_shutdown_deadline_seconds Seconds until the shutdown hard deadline."
            )
            .ok();
            writeln!(out, "# TYPE dns_shutdown_deadline_seconds gauge").ok();
            writeln!(
                out,
                "dns_shutdown_deadline_seconds {}",
                remaining.as_secs_f64()
            )
            .ok();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_lifecycle_is_starting_and_not_ready() {
        let lifecycle = Lifecycle::new();
        assert_eq!(lifecycle.phase(), Phase::Starting);
        assert!(!lifecycle.is_ready());
        assert!(!lifecycle.is_draining());
    }

    #[test]
    fn entering_a_later_phase_succeeds_once() {
        let lifecycle = Lifecycle::new();
        assert!(lifecycle.enter(Phase::Serving));
        assert!(lifecycle.is_ready());
        assert!(
            !lifecycle.enter(Phase::Serving),
            "the second caller must be told it did not make the transition"
        );
    }

    #[test]
    fn a_phase_never_goes_backwards() {
        // The mutation this kills: `enter` without the ordering check. A late
        // `Serving` from a slow startup would then re-advertise a draining
        // process as ready, which is the outage this issue is about.
        let lifecycle = Lifecycle::new();
        assert!(lifecycle.enter(Phase::Draining));
        assert!(!lifecycle.enter(Phase::Serving));
        assert_eq!(lifecycle.phase(), Phase::Draining);
        assert!(!lifecycle.is_ready());
        assert!(lifecycle.is_draining());
    }

    #[test]
    fn draining_covers_every_phase_from_draining_onwards() {
        for phase in [Phase::Draining, Phase::Stopping, Phase::Closing] {
            let lifecycle = Lifecycle::new();
            assert!(lifecycle.enter(phase));
            assert!(lifecycle.is_draining(), "{phase} must count as draining");
            assert!(!lifecycle.is_ready(), "{phase} must never be ready");
        }
    }

    #[test]
    fn phases_are_ordered_and_named() {
        assert!(Phase::Starting < Phase::Serving);
        assert!(Phase::Serving < Phase::Draining);
        assert!(Phase::Draining < Phase::Stopping);
        assert!(Phase::Stopping < Phase::Closing);

        // The discriminants are an exported metric; a reordering is an API break.
        for (phase, bits, name) in [
            (Phase::Starting, 0u8, "starting"),
            (Phase::Serving, 1, "serving"),
            (Phase::Draining, 2, "draining"),
            (Phase::Stopping, 3, "stopping"),
            (Phase::Closing, 4, "closing"),
        ] {
            assert_eq!(phase as u8, bits);
            assert_eq!(phase.as_str(), name);
            assert_eq!(phase.to_string(), name);
            assert_eq!(Phase::from_bits(bits), phase);
        }
    }

    #[test]
    fn an_unknown_bit_pattern_reads_as_closing_rather_than_panicking() {
        // Unreachable through `enter`, but `/metrics` and `/readyz` are reachable
        // from the network and `panic = "abort"` makes one panic a full outage.
        assert_eq!(Phase::from_bits(200), Phase::Closing);
    }

    #[test]
    fn the_deadline_is_absent_until_armed_and_then_counts_down() {
        let lifecycle = Lifecycle::new();
        assert!(lifecycle.deadline_in().is_none());

        lifecycle.arm_deadline(Instant::now() + Duration::from_secs(20));
        let first = lifecycle.deadline_in().expect("armed");
        assert!(first <= Duration::from_secs(20));

        std::thread::sleep(Duration::from_millis(20));
        let later = lifecycle.deadline_in().expect("still armed");
        assert!(
            later < first,
            "the deadline must count down: {first:?} then {later:?}"
        );
    }

    #[test]
    fn a_second_arming_cannot_move_the_deadline_out() {
        let lifecycle = Lifecycle::new();
        lifecycle.arm_deadline(Instant::now() + Duration::from_secs(1));
        lifecycle.arm_deadline(Instant::now() + Duration::from_secs(600));
        assert!(
            lifecycle
                .deadline_in()
                .is_some_and(|left| left <= Duration::from_secs(1)),
            "a second signal must never lengthen the wall clock"
        );
    }

    #[test]
    fn an_elapsed_deadline_reports_zero_rather_than_going_negative() {
        let lifecycle = Lifecycle::new();
        let past = Instant::now()
            .checked_sub(Duration::from_secs(5))
            .expect("the monotonic clock is more than five seconds old");
        lifecycle.arm_deadline(past);
        assert_eq!(lifecycle.deadline_in(), Some(Duration::ZERO));
    }

    #[test]
    fn the_exporter_publishes_the_phase_and_only_an_armed_deadline() {
        let lifecycle = Lifecycle::new();
        let mut out = String::new();
        lifecycle.render_prometheus(&mut out);
        assert!(out.contains("dns_shutdown_phase 0"), "{out}");
        assert!(
            !out.contains("dns_shutdown_deadline_seconds "),
            "the deadline gauge must not exist before a signal arms it: {out}"
        );
        assert!(out.contains("# TYPE dns_shutdown_phase gauge"), "{out}");

        lifecycle.enter(Phase::Draining);
        lifecycle.arm_deadline(Instant::now() + Duration::from_secs(20));
        let mut out = String::new();
        lifecycle.render_prometheus(&mut out);
        assert!(out.contains("dns_shutdown_phase 2"), "{out}");
        assert!(out.contains("dns_shutdown_deadline_seconds 1"), "{out}");
    }

    #[test]
    fn concurrent_transitions_settle_on_the_furthest_phase() {
        use std::sync::{Arc, Barrier};

        // `enter` is a CAS retry loop, so the failure mode of losing its exit
        // condition is four threads spinning and this `join` never returning —
        // a hang, not a failure. Bounded by the process, not by a channel; see
        // `src/testutil.rs`.
        let _watchdog = crate::testutil::arm(Duration::from_secs(30));
        let lifecycle = Arc::new(Lifecycle::new());
        let barrier = Arc::new(Barrier::new(4));
        let mut handles = Vec::new();
        for phase in [
            Phase::Serving,
            Phase::Draining,
            Phase::Stopping,
            Phase::Closing,
        ] {
            let lifecycle = Arc::clone(&lifecycle);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                lifecycle.enter(phase);
            }));
        }
        for handle in handles {
            handle.join().expect("worker finishes");
        }
        assert_eq!(lifecycle.phase(), Phase::Closing);
    }

    #[test]
    fn a_storm_of_transitions_terminates_and_never_loses_the_furthest_phase() {
        // `Err(actual) => current = actual` -> `Err(_) => {}` SURVIVED the whole
        // suite. Without the write-back `current` is stale for ever, so every
        // subsequent compare-exchange fails and `enter` spins — a wedged
        // shutdown, on the path that publishes `draining` to `/readyz`. The test
        // above cannot catch it: four threads racing one atomic once each almost
        // never produce a failed exchange, and `compare_exchange_weak` may fail
        // spuriously even when nobody else is writing.
        //
        // Contention here is structural rather than hoped for: every thread
        // walks the *same* array of lifecycles in the same order, so they stay
        // in step and collide on each one, and each of the four is trying to
        // write a different phase so none of them can take the `current >=
        // target` early return. 20,000 transitions across 5,000 cells.
        //
        // The bound is the process watchdog, not a channel: a spin has to fail
        // this test, not leak four threads and report anyway. See
        // `src/testutil.rs`.
        use std::sync::{Arc, Barrier};

        const CELLS: usize = 5_000;
        const PHASES: [Phase; 4] = [
            Phase::Serving,
            Phase::Draining,
            Phase::Stopping,
            Phase::Closing,
        ];

        let _watchdog = crate::testutil::arm(Duration::from_secs(30));
        let cells: Arc<Vec<Lifecycle>> = Arc::new((0..CELLS).map(|_| Lifecycle::new()).collect());
        let barrier = Arc::new(Barrier::new(PHASES.len()));

        let mut handles = Vec::new();
        for phase in PHASES {
            let cells = Arc::clone(&cells);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                let mut won = 0usize;
                for cell in cells.iter() {
                    if cell.enter(phase) {
                        won += 1;
                    }
                }
                won
            }));
        }
        let won: usize = handles
            .into_iter()
            .map(|h| h.join().expect("worker finishes"))
            .sum();

        for (i, cell) in cells.iter().enumerate() {
            assert_eq!(
                cell.phase(),
                Phase::Closing,
                "lifecycle {i} settled on {} rather than the furthest phase any \
                 thread published: a compare-exchange result was dropped",
                cell.phase()
            );
        }
        assert!(
            won >= CELLS,
            "only {won} of {} transitions reported that they made the move; \
             every cell must be advanced at least once",
            CELLS * PHASES.len()
        );
    }
}
