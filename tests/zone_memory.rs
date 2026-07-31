//! VEGA-032 **S1** — what the zone costs to hold, and what a query costs to
//! answer.
//!
//! Spec: `features/zone-data-model.feature`, section "S1 — MEMORY".
//! Ruling: `.claude/backlog/decisions/VEGA-032-zone-data-model.md` §5.2, §7.1,
//! §13 AC-1.6 and AC-1.8. Closes VEGA-066.
//!
//! **This binary contains one test, on purpose.** A `#[global_allocator]` counts
//! allocations for the whole process, so any other test running concurrently
//! would be counted too and the assertions would flake — and a flaky test
//! asserting a byte count is `#[ignore]`d within a month, which is worse than
//! not having it. One test in one binary is single-threaded by construction,
//! with no `--test-threads` flag for anyone to forget. `tests/ratelimit_alloc.rs`
//! is the same shape for the same reason.
//!
//! The instrument is a dev-dependency rather than a local `impl GlobalAlloc`
//! because `[lints.rust] unsafe_code = "forbid"` applies to every target in this
//! package and `forbid` cannot be lifted from inside a file. `stats_alloc` puts
//! the `unsafe impl` behind a crate boundary; nothing here is unsafe.
//!
//! # STATUS: FAILS TODAY. Every number below is measured, not projected.
//!
//! Release build, this machine, `ebe1fbf`:
//!
//! ```text
//! zone heap, 100,000 A records   134,227,984 B live   128.0 MiB   1,342 B/record
//!                                600,035 allocations, ~100,000 reallocations
//! size_of::<Record>()  272        size_of::<Name>()  80       size_of::<RData>()  184
//! answer vector, 1 record        len 1, capacity 4          816 wasted bytes
//! allocations per query, 100k zone with a wildcard:
//!   uncovered NXDOMAIN     1     covered type-miss   1
//!   wildcard hit           2     123-label miss      5
//! ```
//!
//! The gates are the ruling's: **≤ 40 MiB**, capacity == length, and **zero**
//! allocations on the negative paths.
//!
//! # Correction to the ruling's §7.1 inputs, measured here
//!
//! §7.1 *computes* `size_of::<Name>() ≈ 96` and `size_of::<RData>() ≈ 272 − 96 −
//! 8 = 168` from hickory-proto 0.26.1's tinyvec layout, and says explicitly that
//! perf-engineer must confirm both with `size_of` before the S1 numbers are
//! accepted. Measured on this machine they are **80** and **184**. The two
//! errors cancel: `Node` becomes 96 B rather than 112 B and the RDATA array
//! 18.4 MB rather than 16.8 MB, so the per-record total lands within a byte or
//! two of §7.1's ~303 B and the 40 MiB gate stands unchanged. The sizes are
//! printed on every run so a hickory upgrade that moves them is visible rather
//! than inferred.
//!
//! # Why each number is a correctness problem and not a vanity metric
//!
//! *Zone heap.* The owner `Name` is stored once per **record**; the arena stores
//! it once per **node**. The TTL moves to the RRset (RFC 2181 §5 — one TTL per
//! RRset is what the RFC actually requires) and the class to the zone. VEGA-069
//! measured RSS ratcheting 1,736 → 2,676 → 3,095 MiB across three reloads of a
//! 1M-record zone, attributed to freeing and re-allocating a million small
//! blocks; three allocations instead of 300,000 is what removes that mechanism,
//! and a reload that ratchets is an OOM on a schedule.
//!
//! *Answer vector.* 816 bytes of slack on every single-record answer, on the hot
//! path, because the answer is collected with no size hint. The arena knows the
//! rdata range's length before it copies anything.
//!
//! *Negative-path allocations.* Every one of them is `trim_to` materialising a
//! parent name the probe throws away. The negative path is the path an attacker
//! picks — it is the only shape they can generate without knowing the zone — so
//! its allocation count is a cost the attacker sets. The assertion is on
//! **zero**, not on a threshold; a threshold lets a smaller allocation back in.
//!
//! Run: `cargo test --release --test zone_memory -- --nocapture`

use std::alloc::System;
use std::hint::black_box;
use std::time::Duration;

use hickory_proto::rr::{LowerName, Name, RecordType};
use stats_alloc::{Region, StatsAlloc, INSTRUMENTED_SYSTEM};
use vega::{
    config::{RecordSpec, SoaSpec, ZoneConfig},
    zone::{Answer, Zone},
};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

/// The process watchdog, shared by path rather than copied.
#[path = "../src/testutil.rs"]
mod testutil;

/// Building a 100,000-record zone and running a few thousand lookups is seconds
/// under `--release` and under a minute in a debug build. Three minutes is only
/// reachable by something that is not terminating.
const WATCHDOG: Duration = Duration::from_secs(180);

/// VEGA-066's shape: 100,000 owner names, one RRset each, one RDATA each. The
/// size the ruling's §7.1 arithmetic is stated at, so the measurement and the
/// design can be compared directly.
const ZONE_SIZE: usize = 100_000;

/// §5.2's gate. Today's 128.0 MiB against a computed ~30.3 MB for the arena,
/// with the margin left for allocator overhead and for the index's load factor.
const HEAP_BUDGET_BYTES: i64 = 40 * 1024 * 1024;

/// The most labels a name can carry under `example.com.` inside RFC 1035
/// §2.3.4's 255 octets. **Not** the protocol ceiling, which is 127 — see
/// `features/zone-data-model.feature` and
/// `src/zone.rs::the_true_deepest_name_the_wire_can_carry_is_127_labels_and_is_answered`.
const DEEP_QUERY_LABELS: usize = 123;

fn spec(name: &str, ty: &str, value: &str) -> RecordSpec {
    RecordSpec {
        name: name.to_owned(),
        record_type: ty.to_owned(),
        ttl: None,
        values: vec![value.to_owned()],
    }
}

fn lower(name: &str) -> LowerName {
    let mut n: Name = name.parse().expect("fixture name parses");
    n.set_fqdn(true);
    LowerName::from(n)
}

fn config(with_wildcard: bool) -> ZoneConfig {
    let mut records = Vec::with_capacity(ZONE_SIZE + 2);
    if with_wildcard {
        records.push(spec("*.dev", "A", "203.0.113.50"));
    }
    for i in 0..ZONE_SIZE {
        records.push(spec(
            &format!("h{i}"),
            "A",
            &format!("10.{}.{}.{}", (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff),
        ));
    }
    ZoneConfig {
        origin: "example.com".to_owned(),
        default_ttl: 300,
        builtins: false,
        soa: Some(SoaSpec {
            mname: "ns1.example.com.".to_owned(),
            rname: "hostmaster.example.com.".to_owned(),
            serial: 1,
            refresh: 3600,
            retry: 900,
            expire: 604_800,
            minimum: 60,
        }),
        records,
    }
}

/// How many times each negative shape is looked up while the allocation region
/// is open. Large enough that a per-query allocation cannot hide inside the
/// rounding of one call, small enough to be instant.
const LOOKUPS: usize = 1_000;

/// Bytes rendered as MiB to one decimal place, in integer arithmetic.
///
/// `as f64` on a byte count is a clippy `cast_precision_loss` denial and the
/// lint is right to ask: this number appears in a failure message an operator
/// reads, and a silently rounded one is worse than an exact integer.
fn mib(bytes: i64) -> String {
    let tenths = bytes * 10 / (1024 * 1024);
    format!("{}.{}", tenths / 10, tenths % 10)
}

/// The live heap a freshly built zone holds, and the budget verdict.
fn heap_budget(unmet: &mut Vec<String>) -> Zone {
    // The config is built before the region opens: it is the operator's input,
    // not the zone's representation, and counting it would measure the fixture.
    let cfg = config(false);
    let region = Region::new(GLOBAL);
    let zone = Zone::from_config(&cfg).expect("zone builds");
    let stats = region.change();
    let live = i64::try_from(stats.bytes_allocated).expect("byte count fits")
        - i64::try_from(stats.bytes_deallocated).expect("byte count fits");
    let per_record = live / i64::try_from(ZONE_SIZE).expect("zone size fits");

    println!(
        "zone heap: {live} B live ({} MiB, {per_record} B/record) in {} \
         allocations, {} reallocations",
        mib(live),
        stats.allocations,
        stats.reallocations,
    );
    println!(
        "size_of: Record {} Name {} RData {}",
        std::mem::size_of::<hickory_proto::rr::Record>(),
        std::mem::size_of::<Name>(),
        std::mem::size_of::<hickory_proto::rr::RData>(),
    );

    if live > HEAP_BUDGET_BYTES {
        unmet.push(format!(
            "\"A 100,000-record zone costs at most 40 MiB of live heap\": holds \
             {live} bytes ({} MiB, {per_record} B/record) against {} MiB. The \
             owner name is stored once per record instead of once per node, the \
             TTL once per record instead of once per RRset (RFC 2181 §5), and \
             every one-record RRset carries a Vec over-allocated to its minimum \
             capacity",
            mib(live),
            HEAP_BUDGET_BYTES / (1024 * 1024),
        ));
    }
    zone
}

/// The answer vector for a single-record RRset.
fn answer_vector_budget(zone: &Zone, unmet: &mut Vec<String>) {
    let existing = lower("h1234.example.com.");
    let Answer::Records(records) = zone.lookup(&existing, RecordType::A) else {
        panic!("a configured record must answer, or this measures nothing");
    };
    let wasted =
        (records.capacity() - records.len()) * std::mem::size_of::<hickory_proto::rr::Record>();
    println!(
        "answer vector: len {} capacity {} ({wasted} wasted bytes)",
        records.len(),
        records.capacity(),
    );
    if records.capacity() != records.len() {
        unmet.push(format!(
            "\"An answer vector is not over-allocated\": a {}-record answer came \
             back in a Vec of capacity {} — {wasted} wasted bytes per query, on \
             the hot path, because the answer is collected with no size hint. The \
             arena knows the rdata range's length before it copies anything",
            records.len(),
            records.capacity(),
        ));
    }
}

/// Allocations per query on the three negative shapes, in a zone that holds a
/// wildcard — the probe only runs when one exists, and it is the probe that
/// allocates. Measuring this on a wildcard-free zone reports a clean zero and
/// proves nothing.
fn negative_path_budget(unmet: &mut Vec<String>) {
    let zone = Zone::from_config(&config(true)).expect("wildcard zone builds");
    let deep = {
        let mut s = String::with_capacity(DEEP_QUERY_LABELS * 2 + 16);
        for _ in 0..DEEP_QUERY_LABELS - 2 {
            s.push_str("a.");
        }
        s.push_str("example.com.");
        lower(&s)
    };

    let shapes: [(&str, LowerName, RecordType, Answer); 3] = [
        // Uncovered: the shape an attacker generates without knowing the zone.
        (
            "an uncovered name (NXDOMAIN)",
            lower("q.w.e.example.com."),
            RecordType::A,
            Answer::NxDomain,
        ),
        // Covered but the wrong type: RFC 2308 §2.2 NODATA (VEGA-083).
        (
            "a covered name of a type the wildcard lacks (NODATA)",
            lower("x.dev.example.com."),
            RecordType::AAAA,
            Answer::NoData,
        ),
        // The deep miss, where the per-probe cost is multiplied by the depth.
        (
            "a 123-label miss (NXDOMAIN)",
            deep,
            RecordType::A,
            Answer::NxDomain,
        ),
    ];

    for (label, name, qtype, expected) in shapes {
        // The answer is asserted first: an allocation count is meaningless if
        // the query is taking a different branch than the one named.
        assert_eq!(
            zone.lookup(&name, qtype),
            expected,
            "{label} did not answer as expected, so its allocation count would \
             be measuring some other branch"
        );

        let region = Region::new(GLOBAL);
        for _ in 0..LOOKUPS {
            black_box(zone.lookup(black_box(&name), qtype));
        }
        let stats = region.change();
        println!(
            "{label}: {} allocations / {LOOKUPS} lookups ({} bytes)",
            stats.allocations, stats.bytes_allocated,
        );
        if stats.allocations != 0 {
            unmet.push(format!(
                "\"A negative answer in a wildcard zone allocates nothing at \
                 all\": {label} performed {} allocations ({} bytes) over \
                 {LOOKUPS} lookups. Each one is a parent name materialised \
                 through trim_to and thrown away. The negative path is the only \
                 query shape an attacker can drive without knowing the zone, so \
                 its allocation count is a cost they set — and the budget is \
                 zero rather than a threshold, because a threshold lets a \
                 smaller allocation back in",
                stats.allocations, stats.bytes_allocated,
            ));
        }
    }
}

/// Scenario: A 100,000-record zone costs at most 40 MiB of live heap
/// features/zone-data-model.feature:337
///
/// Scenario: An answer vector is not over-allocated
/// features/zone-data-model.feature:352
///
/// Scenario: A negative answer in a wildcard zone allocates nothing at all
/// features/zone-data-model.feature:362
///
/// Three scenarios in one test because they share a 100,000-record zone that
/// costs seconds to build, and because a `#[global_allocator]` makes a second
/// test in this binary a second source of counts.
///
/// Every budget is collected and reported together at the end. Failing at the
/// first would hide the other two behind it, and a reader given one number
/// cannot tell whether the rest are met.
#[test]
fn the_zone_and_its_answers_cost_what_the_ruling_budgets() {
    let _watchdog = testutil::arm(WATCHDOG);

    let mut unmet: Vec<String> = Vec::new();
    let zone = heap_budget(&mut unmet);
    answer_vector_budget(&zone, &mut unmet);
    drop(zone);
    negative_path_budget(&mut unmet);

    assert!(
        unmet.is_empty(),
        "{} of the S1 memory budgets are not met:\n  - {}",
        unmet.len(),
        unmet.join("\n  - "),
    );
}
