//! Test-only harness support: a watchdog that bounds the **process**, not a
//! channel.
//!
//! # Why this exists
//!
//! Several tests in this tree assert that a bounded loop terminates —
//! `Zone::resolve`'s wildcard-depth walk, `RateLimiter::check_at`'s CAS retry.
//! The failure mode they guard against is not a wrong answer, it is a spin, and
//! a spin cannot be observed by returning from the thing that is spinning.
//!
//! The obvious guard is to run the work on a detached thread and bound the
//! *channel* with `recv_timeout`. That is what this tree did, and it is worse
//! than no guard at all. The test returns and reports, but the walk thread is
//! still spinning inside a process nobody reaps: `cargo test` reports a failure
//! while the binary keeps burning a core, and a mutation harness scores the
//! mutant as a **timeout rather than as caught** — so the mutants that produce
//! the most dangerous defect are exactly the ones scored wrong. On this machine
//! that reached load average 131 with five orphaned mutant binaries at PPID 1.
//!
//! # What this does instead
//!
//! [`arm`] registers a deadline with a single background watchdog thread and
//! returns a guard. Dropping the guard disarms it, including when the test
//! unwinds. If the deadline passes while the guard is still alive, the watchdog
//! prints what tripped and calls [`std::process::exit`].
//!
//! Killing the whole test binary is the point, not a regrettable side effect.
//! The only way a deadline six orders of magnitude above a test's normal runtime
//! expires is that something is not terminating, and there is no way to stop a
//! `loop {}` in another thread from inside the process. Exiting turns the hang
//! into a fast, loud, non-zero exit: no orphan, no core burned for eleven
//! minutes, and a harness reading the exit status sees "the tests failed".
//!
//! # Using it
//!
//! ```ignore
//! #[test]
//! fn a_walk_that_matches_nothing_terminates() {
//!     let _watchdog = crate::testutil::arm(Duration::from_secs(30));
//!     // ... the ordinary test body, on this thread, no channel ...
//! }
//! ```
//!
//! Integration tests under `tests/` pull the same file in with
//! `#[path = "../src/testutil.rs"] mod testutil;` rather than keeping a copy,
//! so there is one implementation of the containment rule and not five.

use std::{
    io::Write as _,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex, MutexGuard, Once, PoisonError,
    },
    time::{Duration, Instant},
};

/// Exit status the watchdog kills the process with.
///
/// 101 is what libtest already exits with for an ordinary test failure, so
/// `cargo test`, CI and any mutation harness reading the status see "the tests
/// failed" — which is the truth — rather than a signal or a timeout, which they
/// classify differently and, in cargo-mutants' case, do not score as caught.
/// Deliberately not `std::process::abort`: SIGABRT on macOS summons the crash
/// reporter, which is another process to reap on a machine already in trouble.
const WATCHDOG_EXIT: i32 = 101;

/// How often the watchdog looks at the armed deadlines.
///
/// The guard is measured in tens of seconds, so 25 ms of slack is noise, and a
/// sleeping thread that wakes 40 times a second costs nothing next to a test
/// suite.
const TICK: Duration = Duration::from_millis(25);

/// One armed deadline.
struct Armed {
    /// Test thread name plus the `file:line` the guard was armed at. Derived,
    /// never hand-written, so it cannot drift out of step with the test it
    /// names.
    label: String,
    deadline: Instant,
    timeout: Duration,
    /// Distinguishes this arming from every other one that has used, or will
    /// use, the same slot index. Without it a `Guard` whose slot has already
    /// been freed and re-armed by another thread would clear somebody else's
    /// deadline on drop — silently disarming a live guard, which is the one
    /// failure this module cannot be allowed to have.
    token: u64,
}

/// Source of [`Armed::token`]. Monotonic for the process; wrapping it would
/// take 2^64 armings.
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(0);

/// Armed deadlines by slot. `None` is a free slot, reused by the next [`arm`],
/// so a suite of ten thousand tests does not grow the vector without bound.
///
/// A plain `static` rather than a `OnceLock`: `Mutex::new` and `Vec::new` are
/// both `const`, and the watchdog thread must be able to read this while the
/// thread that spawned it is still inside its own initialisation.
static REGISTRY: Mutex<Vec<Option<Armed>>> = Mutex::new(Vec::new());

/// Starts the watchdog thread on the first [`arm`] of the process.
static WATCHDOG: Once = Once::new();

/// Take the registry lock, ignoring poisoning.
///
/// Nothing under this lock can panic, so a poisoned mutex means a *different*
/// thread died holding it — which is precisely the situation where the watchdog
/// still has to work. Refusing to look would turn a bug into a hang.
fn registry() -> MutexGuard<'static, Vec<Option<Armed>>> {
    REGISTRY.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A live deadline. Dropping it disarms the watchdog.
///
/// Bind it to a named local (`let _watchdog = ...`). A bare `let _ = arm(..)`
/// drops it on the spot and guards nothing, which is why [`arm`] is
/// `#[must_use]`.
pub(crate) struct Guard {
    idx: usize,
    token: u64,
}

impl Drop for Guard {
    fn drop(&mut self) {
        // Runs on the unwind path too, so a test that fails an assertion
        // disarms just as reliably as one that passes.
        let mut slots = registry();
        if slots[self.idx]
            .as_ref()
            .is_some_and(|armed| armed.token == self.token)
        {
            slots[self.idx] = None;
        }
    }
}

/// Bound the rest of the current test by `timeout`, at the cost of the process
/// if it is exceeded.
///
/// `#[track_caller]`, so the diagnostic names the exact `file:line` that armed
/// the guard without anyone having to repeat the test's name in a string
/// literal and keep it up to date.
#[track_caller]
#[must_use = "the watchdog is disarmed the instant the guard is dropped; bind it, e.g. `let _watchdog = arm(..)`"]
pub(crate) fn arm(timeout: Duration) -> Guard {
    WATCHDOG.call_once(|| {
        std::thread::Builder::new()
            .name("vega-test-watchdog".to_owned())
            .spawn(watch)
            .expect("the test watchdog thread must start; without it a hang is unbounded");
    });

    let caller = std::panic::Location::caller();
    let token = NEXT_TOKEN.fetch_add(1, Ordering::Relaxed);
    let armed = Armed {
        // libtest names each test thread after its test, which is the name a
        // reader wants first. It is `main` under `--test-threads=1`, hence the
        // `file:line` as well.
        label: format!(
            "{} armed at {}:{}",
            std::thread::current().name().unwrap_or("<test>"),
            caller.file(),
            caller.line()
        ),
        deadline: Instant::now() + timeout,
        timeout,
        token,
    };

    let mut slots = registry();
    if let Some(idx) = slots.iter().position(Option::is_none) {
        slots[idx] = Some(armed);
        Guard { idx, token }
    } else {
        slots.push(Some(armed));
        Guard {
            idx: slots.len() - 1,
            token,
        }
    }
}

/// The watchdog thread: wake, look, and kill the process if anything is overdue.
fn watch() -> ! {
    loop {
        std::thread::sleep(TICK);
        let now = Instant::now();
        // Clone out and release the lock before doing anything else, so the
        // watchdog can never be the reason a test thread blocks.
        let overdue = registry()
            .iter()
            .flatten()
            .find(|armed| now >= armed.deadline)
            .map(|armed| (armed.label.clone(), armed.timeout));
        if let Some((label, timeout)) = overdue {
            trip(&label, timeout);
        }
    }
}

/// Report and kill. Never returns.
fn trip(label: &str, timeout: Duration) -> ! {
    // Straight at the process's stderr rather than through `eprintln!`.
    // libtest captures the print macros per test thread and only replays the
    // capture buffer when a test *finishes*; a test that never returns has its
    // output swallowed, which is exactly the case being reported here.
    let mut err = std::io::stderr();
    let _ = writeln!(
        err,
        "\n\
         ============================ vega test watchdog ============================\n\
         {label}\n\
         did not finish within {timeout:?}.\n\
         \n\
         Something it called is not terminating. Killing the whole test process with\n\
         status {WATCHDOG_EXIT} so this is a FAILURE and not a spinning thread inside a binary\n\
         nobody reaps. If you are mutation testing, this mutant is CAUGHT.\n\
         ============================================================================"
    );
    let _ = err.flush();
    std::process::exit(WATCHDOG_EXIT);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The deadline this guard was armed with, or `None` once it is disarmed.
    ///
    /// Looked up by token rather than by slot index, and asserted against a
    /// *chosen* `now` rather than by sleeping. Both are deliberate: these tests
    /// run beside every other test in the binary, so a sibling can reuse a freed
    /// slot between two statements here, and a wall-clock assertion of the shape
    /// "arm 50 ms, drop, sleep 150 ms, expect to still be alive" is a scheduler
    /// race. That exact shape produced a false kill on a loaded machine during
    /// this module's own adversarial pass, which is how these came to be written
    /// this way. Do not put the sleeps back.
    fn deadline_of(token: u64) -> Option<Instant> {
        registry()
            .iter()
            .flatten()
            .find(|armed| armed.token == token)
            .map(|armed| armed.deadline)
    }

    #[test]
    fn a_guard_is_overdue_only_while_it_is_armed() {
        const HOUR: Duration = Duration::from_secs(3600);

        let guard = arm(HOUR);
        let token = guard.token;
        let deadline = deadline_of(token).expect("an armed guard is in the registry");

        // The exact predicate `watch` applies, evaluated at two chosen instants
        // instead of waited for.
        assert!(
            Instant::now() < deadline,
            "a freshly armed guard must not already be overdue"
        );
        assert!(
            Instant::now() + HOUR + Duration::from_secs(1) >= deadline,
            "a guard an hour and a second past its arming must be overdue, or \
             the watchdog can never fire"
        );

        drop(guard);
        assert!(
            deadline_of(token).is_none(),
            "dropping a guard left it in the registry: it will kill the process \
             when its deadline passes, however long ago the test that armed it \
             finished"
        );
    }

    #[test]
    fn a_disarmed_slot_is_reused_rather_than_appended() {
        // Bounds the registry: a suite with thousands of guarded tests must not
        // grow a vector entry per test.
        //
        // Stated as a strict inequality against the number of cycles rather
        // than as "grew by at most one", because other tests in this binary run
        // concurrently and each of them legitimately occupies a slot for its
        // duration. An implementation that appends per `arm` grows by exactly
        // 64 and still fails; one that reuses grows by at most the concurrency.
        let before = registry().len();
        for _ in 0..64 {
            let _watchdog = arm(Duration::from_secs(60));
        }
        let after = registry().len();
        assert!(
            after < before + 64,
            "64 armed-and-dropped guards grew the registry from {before} to \
             {after}: disarmed slots are not being reused"
        );
    }

    #[test]
    fn a_guard_disarms_even_when_the_test_body_panics() {
        // A guard that only disarms on the happy path would mean every failing
        // test leaves a live deadline behind and kills the binary thirty
        // seconds later, hiding the real failure behind the watchdog's.
        let outcome = std::panic::catch_unwind(|| {
            let watchdog = arm(Duration::from_secs(3600));
            let token = watchdog.token;
            std::panic::panic_any(token);
        });
        let token = *outcome
            .expect_err("the closure panicked")
            .downcast::<u64>()
            .expect("the panic payload is the guard's token");
        assert!(
            deadline_of(token).is_none(),
            "a guard that was alive when its test panicked is still armed"
        );
    }
}
