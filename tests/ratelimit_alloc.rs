//! Criterion B3: the rate limiter's check path allocates nothing.
//!
//! **This binary contains exactly one test, on purpose.** A `#[global_allocator]`
//! counts allocations for the whole process, so any other test running
//! concurrently in the same binary would be counted too and the assertion would
//! flake — and a flaky test asserting zero is `#[ignore]`d within a month, which
//! is worse than not having it. One test in its own binary is single-threaded by
//! construction, with no `--test-threads` flag for anyone to forget.
//!
//! The instrument is a dev-dependency rather than a local `impl GlobalAlloc`
//! because `[lints.rust] unsafe_code = "forbid"` applies to every target in this
//! package, `forbid` cannot be lifted by an `#[allow]` from inside a file, and
//! that is the lint working as intended. `stats_alloc` puts the `unsafe impl`
//! behind a crate boundary; nothing in this file is unsafe. It clears
//! `cargo deny check` (advisories, bans, licenses, sources).
//!
//! Why this is worth a dependency when `tests/ratelimit.rs` already greps
//! `check_at` for `Vec` and `HashMap`: the source-text guard asserts about text,
//! cannot see through a helper, and misses `format!`, `to_owned`, `Box::new`,
//! `collect` and anything allocating inside `hash_one`. This one observes
//! behaviour, and it is what kills a mutant that reintroduces per-source state
//! too small to show up in RSS.

use std::{
    alloc::System,
    hint::black_box,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Instant,
};

use stats_alloc::{Region, StatsAlloc, INSTRUMENTED_SYSTEM};
use vega::ratelimit::RateLimiter;

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

/// Scenario: The check path allocates nothing
/// features/rate-limiting.feature:165
///
/// Ruling §13 B3. The check runs before message-type, opcode, EDNS, QDCOUNT,
/// QCLASS and QTYPE validation, so a 29-byte garbage datagram reaches it: any
/// allocation here is a cost the attacker sets, at whatever rate they can send.
/// Keying on the full source address allocated a map entry per forged packet,
/// which is the whole of VEGA-003 — 186 measured bytes each, 356 MiB at two
/// million sources, OOM under a 128 MiB limit in 7.2 seconds.
///
/// The assertion is on **zero**, not on a threshold. A threshold would let the
/// per-packet allocation back in at a smaller size.
#[test]
fn one_hundred_thousand_checks_allocate_nothing_at_all() {
    const CHECKS: u32 = 100_000;

    // Everything that legitimately allocates happens before the region opens:
    // the 2 MiB slot table is built once, at startup, off the query path.
    let limiter = RateLimiter::new(50, 100);
    let now = Instant::now();
    let one_source: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));

    let region = Region::new(GLOBAL);

    // A single hammered prefix: the contended-slot path, allowed then denied.
    for _ in 0..CHECKS {
        black_box(limiter.check_at(black_box(one_source), black_box(now)));
    }
    // Maximal diversity across both families: the path an attacker actually
    // walks, and the one that used to mint an entry per packet.
    for i in 0..CHECKS {
        let v4 = IpAddr::V4(Ipv4Addr::from((i << 8) | 1));
        let v6 = IpAddr::V6(Ipv6Addr::from((u128::from(i) << 72) | 1));
        black_box(limiter.check_at(black_box(v4), black_box(now)));
        black_box(limiter.check_at(black_box(v6), black_box(now)));
    }

    let stats = region.change();

    assert_eq!(
        stats.allocations,
        0,
        "{} checks performed {} allocations. The query path must not allocate at \
         all: the source address is chosen by an attacker one packet at a time, so \
         anything allocated per check is memory they mint for free. Full stats: \
         {stats:?}",
        CHECKS * 3,
        stats.allocations
    );
    assert_eq!(
        stats.reallocations, 0,
        "the query path grew an existing allocation, which is a buffer being \
         filled per query: {stats:?}"
    );
    assert_eq!(
        stats.deallocations, 0,
        "the query path freed something, so it had allocated something the \
         counter missed or the region straddles: {stats:?}"
    );
}
