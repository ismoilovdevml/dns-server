//! Cross-module guards for VEGA-003's bounded rate limiter.
//!
//! Most of the limiter's behaviour is pinned by the unit tests at the bottom of
//! `src/ratelimit.rs`, next to the arithmetic they describe. Two kinds of claim
//! cannot live there and are made here instead:
//!
//! 1. **The gauges**, which span `src/ratelimit.rs` and `src/metrics.rs`.
//! 2. **The absence of pruning**, which is a claim about the *shape* of the tree
//!    rather than about any value a program can compute. Ruling §13 E1 asks for
//!    it in that form deliberately: a revert that "restores" the janitor has to
//!    fail a test, not merely a review, and there is no runtime observation that
//!    distinguishes a tree with a dead janitor from one without it.
//!
//! Three guards that stood here while the API was being designed have been
//! replaced by the behavioural assertions their doc comments specified, now that
//! the accessors exist:
//!
//! | scenario | now asserted by |
//! |---|---|
//! | the table is a compile-time constant | `src/ratelimit.rs`, `the_slot_table_is_the_same_size_before_and_after_a_two_million_source_flood` |
//! | a denied query does not write to its slot | `src/ratelimit.rs`, `a_denied_query_leaves_its_slot_word_byte_identical` (needs the `#[cfg(test)]` raw-word accessor, so it cannot live in this file) |
//! | the gauges are named for what they measure | below, on `active_at`/`slots` and the rendered exposition |
//!
//! The zero-allocation guard below is **still a partial and is reported as one**,
//! but it is no longer all there is. Ruling §13 B3 asks for 0 allocations across
//! 100,000 checks under a counting global allocator, and the architect ruled on
//! 2026-07-31 that the dev-dependency is worth taking: that test now lives in
//! `tests/ratelimit_alloc.rs`, in its own binary. This one stays as a tripwire,
//! because it fails fast and without an allocator, and it stays classified as a
//! partial because it asserts about *text*: it cannot see through a helper and
//! misses `format!`, `to_owned`, `Box::new`, `collect`, and anything allocating
//! inside `hash_one`.

use std::{
    net::IpAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use vega::{metrics::Metrics, ratelimit::RateLimiter};

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

/// Scenario: The check path allocates nothing
/// features/rate-limiting.feature:165
///
/// PARTIAL, and reported as one. The behavioural form of this criterion — zero
/// allocations under a counting allocator — is `tests/ratelimit_alloc.rs`; this
/// is the tripwire that fails first and without an instrument.
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

/// Scenario: Pruning and the janitor cannot come back
/// features/rate-limiting.feature:456
///
/// The janitor was not merely useless, it was a second defect: `prune_at` walked
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
/// features/rate-limiting.feature:534
///
/// `dns_ratelimit_tracked`, as asked for by VEGA-043 and by VEGA-003's own
/// acceptance text, is UNIMPLEMENTABLE after this change: nothing is tracked and
/// source cardinality is deliberately not retained. Shipping a plausible number
/// that does not mean what its name says is worse than renaming it, so it became
/// two gauges computed on scrape with relaxed loads — no task, no lock (ruling
/// §8). The pair is what tells an operator whether they are seeing a
/// concentrated attack (rate-limited total rising, active low) or a
/// maximal-diversity flood that has collapsed the table into a near-global
/// limiter (active approaching slots), which is the alert that says the
/// deployment needs VEGA-041.
///
/// REPLACES the structural guard that could only grep `src/metrics.rs` for the
/// two names while the accessors did not exist. Ruling §13 F1, F2.
#[test]
fn the_limiter_gauges_report_a_constant_slot_count_and_live_occupancy() {
    // One qps means one milli-token per millisecond, so a spent token takes a
    // full second to come back and the occupancy window is not a race with the
    // test's own runtime.
    let limiter = Arc::new(RateLimiter::new(1, 1));
    let now = Instant::now();
    let source: IpAddr = "198.51.100.1".parse().expect("literal address parses");

    assert_eq!(
        limiter.active_at(now),
        0,
        "a fresh table has no deficit anywhere: the zero word means a full \
         bucket, never touched"
    );

    assert!(limiter.check_at(source, now));
    assert_eq!(
        limiter.active_at(now),
        1,
        "one prefix spent its token, so exactly one slot is below full"
    );
    assert!(
        limiter.active_at(now) <= limiter.slots(),
        "occupancy can never exceed the table"
    );
    assert_eq!(
        limiter.active_at(now + Duration::from_secs(1)),
        0,
        "one second at 1 qps refills the token, and a refilled slot is not \
         active: the gauge is computed against scrape time, not left as a \
         high-water mark"
    );

    let metrics = Metrics::new().with_rate_limiter(Some(Arc::clone(&limiter)));
    let text = metrics.render_prometheus();

    assert!(
        !text.contains("dns_ratelimit_tracked"),
        "`dns_ratelimit_tracked` cannot exist after VEGA-003 — nothing is \
         tracked. A gauge whose name promises source cardinality and reports \
         something else is worse than no gauge (ruling §8):\n{text}"
    );
    assert!(
        text.contains(&format!("dns_ratelimit_slots {}", limiter.slots())),
        "the slot gauge must report the constant table size:\n{text}"
    );
    assert!(
        text.contains("dns_ratelimit_slots 262144"),
        "2^18 slots, so an alert can compute saturation against a known \
         denominator:\n{text}"
    );
    assert!(
        text.contains("dns_ratelimit_active 1"),
        "the occupancy gauge must report the one slot that is below full:\n{text}"
    );
    for gauge in ["dns_ratelimit_slots", "dns_ratelimit_active"] {
        assert!(
            text.contains(&format!("# TYPE {gauge} gauge")),
            "{gauge} must declare its type:\n{text}"
        );
    }
}

/// Scenario: The limiter gauges are absent when rate limiting is off
/// features/rate-limiting.feature:549
///
/// The other side of the gauges: with rate limiting off there is no table, and a
/// series reporting 262,144 slots of a limiter that does not exist would have an
/// operator alerting on saturation that cannot happen.
#[test]
fn the_limiter_gauges_are_absent_when_rate_limiting_is_off() {
    let text = Metrics::new().render_prometheus();
    assert!(
        !text.contains("dns_ratelimit"),
        "a server with no rate limiter must expose no limiter gauges:\n{text}"
    );
}
