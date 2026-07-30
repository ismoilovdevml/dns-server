//! Structural guards for VEGA-003's bounded rate limiter.
//!
//! Everything in this file is a guard on the *shape* of `src/ratelimit.rs`
//! rather than on its behaviour, and each one says why the behavioural form
//! cannot be written yet. Two reasons recur:
//!
//! 1. **The accessor does not exist.** A test that names an API before
//!    `rust-dev` writes it does not fail — it fails to *compile*, and a test
//!    target that does not compile reports nothing about any other scenario in
//!    the suite. The repository already prefers a source-text guard in this
//!    situation (`tests/shutdown.rs`, "a structural guard, because the
//!    type-level form cannot compile until the API exists"). Each guard below
//!    carries the exact behavioural assertion that must replace it in the same
//!    commit that lands the accessor.
//! 2. **The lint forbids the instrument.** Counting allocations needs a
//!    `#[global_allocator]` implementing `GlobalAlloc`, which is an `unsafe
//!    impl`. `unsafe_code = "forbid"` in `Cargo.toml` applies to every target in
//!    this package and cannot be lifted from inside a file, so the counting
//!    allocator has to come from a dev-dependency. That is a `Cargo.toml` and
//!    `cargo deny` change; it is recorded on VEGA-003 rather than smuggled in.
//!
//! A structural guard is weaker than a behavioural one and is reported as a
//! partial, never as coverage.

use std::path::PathBuf;

/// Read a source file of the crate under test.
fn source(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {relative}: {e}"))
}

/// The body of a method, from its signature to the first closing brace at
/// method indentation. Good enough to isolate one function inside one `impl`.
fn method_body(src: &str, signature: &str) -> String {
    let (_, after) = src
        .split_once(signature)
        .unwrap_or_else(|| panic!("src/ratelimit.rs no longer defines `{signature}`"));
    after
        .split_once("\n    }")
        .unwrap_or_else(|| panic!("`{signature}` has no method-level closing brace"))
        .0
        .to_owned()
}

/// Scenario: The table size is a compile-time constant, not a function of traffic
/// features/rate-limiting.feature:140
///
/// Ruling §3.3: 2^18 slots of 8 bytes = 2,097,152 bytes, allocated once, never
/// grown, never shrunk, never pruned, identical after one query and after 2^64.
///
/// STRUCTURAL PLACEHOLDER. `rust-dev` must delete this and put the behavioural
/// form in `src/ratelimit.rs`'s test module in the same commit:
///
/// ```ignore
/// let rl = RateLimiter::new(1, 1);
/// let before = rl.memory_bytes();
/// for i in 0..2_000_000 { rl.check_at(v4_prefix(i), now); }
/// assert_eq!(rl.memory_bytes(), before);           // equality, not a threshold
/// assert_eq!(rl.memory_bytes(), SLOTS * 8);
/// assert_eq!(RateLimiter::new(1_000_000, 1_000_000).memory_bytes(), before);
/// ```
#[test]
fn the_slot_table_is_sized_by_a_constant_and_reports_its_own_footprint() {
    let src = source("src/ratelimit.rs");

    assert!(
        src.contains("const SLOTS"),
        "src/ratelimit.rs must declare the slot count as a constant. The memory \
         ceiling has to be a property of the binary, not the outcome of a race \
         between a janitor and an attacker (ruling §3.1)."
    );
    assert!(
        src.contains("fn memory_bytes"),
        "src/ratelimit.rs must expose `memory_bytes()` so the ceiling can be \
         asserted by equality before and after a 2,000,000-source flood \
         (ruling §13 B1, B5). Without an accessor the bound is a claim in a \
         comment."
    );
    assert!(
        !src.contains("HashMap"),
        "the limiter must not hold a map at all: every distinct key an attacker \
         forges is 186 measured bytes, and `HashMap::retain` never returns the \
         high-water mark (ruling §1.2, §1.3)."
    );
}

/// Scenario: The check path allocates nothing
/// features/rate-limiting.feature:151
///
/// Ruling §13 B3 asks for a counting global allocator around 100,000 checks
/// asserting **0** allocations. That instrument cannot be built inside this
/// package: `#[global_allocator]` needs an `unsafe impl GlobalAlloc`, and
/// `unsafe_code = "forbid"` applies to every target here and cannot be
/// overridden from inside a file. Doing it properly needs a dev-dependency
/// (`stats_alloc` or `cap`) plus a `cargo deny` review — a `Cargo.toml` change,
/// which is not this agent's to make.
///
/// PARTIAL, and reported as one. What survives is the mutant this criterion
/// actually exists to kill: somebody puts a map, a `Vec` or a lock back on the
/// query path. That is visible in the source and is worth pinning now.
#[test]
fn the_check_path_contains_no_allocating_or_locking_construct() {
    let src = source("src/ratelimit.rs");
    let body = method_body(&src, "pub fn check_at(");

    for forbidden in [
        "insert", "HashMap", "Vec", "String", "format!", "to_owned", "collect(", "Box::new",
        "lock()", "to_vec",
    ] {
        assert!(
            !body.contains(forbidden),
            "`check_at` contains `{forbidden}`. The check runs before message-type, \
             opcode, EDNS, QDCOUNT, QCLASS and QTYPE validation, so a 29-byte garbage \
             datagram reaches it: anything it allocates or locks is a cost the \
             attacker sets. Body was:\n{body}"
        );
    }
}

/// Scenario: A denied query does not write to its slot
/// features/rate-limiting.feature:266
///
/// Under a flood the denial path IS the hot path, so a write-back per dropped
/// packet is a cache line bounced between every core for no semantic gain — and
/// a token bucket that refuses a query has not consumed anything (ruling §5.3
/// step 6). No timing test catches this reliably.
///
/// STRUCTURAL PLACEHOLDER. It cannot be asserted behaviourally at all: a store
/// on the denied path would write back the same refilled deficit and a later
/// timestamp, which is semantically identical, so only the raw word tells the
/// two apart. `rust-dev` must add a `#[cfg(test)]` accessor for the raw slot and
/// replace this with:
///
/// ```ignore
/// let idx = rl.slot_of(prefix);
/// drain(&rl, prefix, now);
/// let before = rl.slot_word(idx);
/// assert!(!rl.check_at(prefix, now));
/// assert_eq!(rl.slot_word(idx), before, "the denied path wrote to its slot");
/// ```
#[test]
fn the_denied_path_has_no_way_to_write_to_its_slot() {
    let src = source("src/ratelimit.rs");
    let body = method_body(&src, "pub fn check_at(");

    assert!(
        !body.contains(".store("),
        "`check_at` performs a plain store. The only write on the query path may \
         be the compare-exchange on the ALLOWED path; a denied query must return \
         without touching the cache line (ruling §5.3 step 6)."
    );
    assert!(
        body.matches("compare_exchange").count() <= 1,
        "`check_at` has more than one compare-exchange site. The denied path must \
         have no write at all, and a second CAS is where one creeps back in."
    );
    assert!(
        body.contains("compare_exchange"),
        "`check_at` must claim its token with a bounded compare-exchange loop \
         failing closed at 8 attempts (ruling §5.3 steps 7-9), not with a lock \
         and not with an unconditional store."
    );
}

/// Scenario: Pruning and the janitor cannot come back
/// features/rate-limiting.feature:372
///
/// The janitor was not merely useless, it was a second defect: `prune_at` walks
/// every entry of a shard while holding that shard's mutex, and with VEGA-020's
/// fixed-seed hasher an attacker concentrates the map into one shard and turns
/// the minute-ly sweep into a synchronised p99 cliff for all traffic (ruling
/// §1.4). It also could not win its race — a 600 s idle TTL against a map that
/// reaches the 128 MiB k8s limit in 7.2 s (§1.5).
///
/// A fixed table has nothing to reclaim, so a revert that "restores" pruning has
/// to fail a test rather than merely a review. Ruling §13 E1.
#[test]
fn pruning_and_the_janitor_do_not_exist_anywhere_in_the_tree() {
    for (file, banned) in [
        (
            "src/ratelimit.rs",
            ["fn prune", "fn tracked", "IDLE_TTL", "janitor"].as_slice(),
        ),
        (
            "src/main.rs",
            ["spawn_janitor", "JANITOR_INTERVAL", "IDLE_TTL", "prune("].as_slice(),
        ),
    ] {
        let src = source(file);
        for needle in banned {
            assert!(
                !src.contains(needle),
                "{file} still mentions `{needle}`. VEGA-003 deletes pruning \
                 outright: with no per-key allocation there is nothing to \
                 reclaim, the old sweep was semantically a no-op for every entry \
                 it was allowed to touch (ruling §4.2), and the task it ran in \
                 was a query-path stall an attacker could aim (§1.4)."
            );
        }
    }
}

/// Scenario: The limiter exposes a constant slot count and a live occupancy gauge
/// features/rate-limiting.feature:450
///
/// `dns_ratelimit_tracked`, as asked for by VEGA-043 and by this issue's own
/// acceptance text, is UNIMPLEMENTABLE after this change: nothing is tracked and
/// source cardinality is deliberately not retained. Shipping a plausible number
/// that does not mean what its name says is worse than renaming it, so it
/// becomes two gauges computed on scrape with relaxed loads — no task, no lock
/// (ruling §8).
///
/// STRUCTURAL PLACEHOLDER. The behavioural form needs both the accessor and the
/// render path, and belongs with whoever wires the gauge into `src/metrics.rs`:
///
/// ```ignore
/// let rl = RateLimiter::new(1, 1);
/// assert_eq!(rl.active_at(now), 0);              // fresh limiter, zero deficit
/// assert!(rl.check_at(prefix, now));
/// assert!(rl.active_at(now) >= 1);
/// assert!(rl.active_at(now) <= rl.slots());
/// assert_eq!(rl.active_at(now + refill_window), 0);   // returns to zero
/// ```
#[test]
fn the_limiter_gauges_are_named_for_what_they_actually_measure() {
    let metrics = source("src/metrics.rs");

    assert!(
        !metrics.contains("dns_ratelimit_tracked"),
        "`dns_ratelimit_tracked` cannot exist after VEGA-003 — nothing is \
         tracked. A gauge whose name promises source cardinality and reports \
         something else is worse than no gauge (ruling §8)."
    );
    for gauge in ["dns_ratelimit_slots", "dns_ratelimit_active"] {
        assert!(
            metrics.contains(gauge),
            "src/metrics.rs must expose `{gauge}`. The pair is what tells an \
             operator whether they are seeing a concentrated attack (rate-limited \
             total rising, active low) or a maximal-diversity flood that has \
             collapsed the table into a near-global limiter (active approaching \
             slots) — which is the alert that says the deployment needs VEGA-041."
        );
    }
}
