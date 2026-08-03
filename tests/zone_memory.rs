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
    let mut records = Vec::with_capacity(ZONE_SIZE + 4);
    // Mandatory since VEGA-032 S5 (RFC 1034 §4.2.1). It costs one `Rrset` and
    // one `RData` at the apex node, which already exists — no new node, and no
    // referral, because the apex is never a zone cut. That fixed cost is why the
    // flat-fixture byte count below moved at S5 and the per-record cost did not.
    records.push(spec("@", "NS", "ns1.example.com."));
    if with_wildcard {
        records.push(spec("*.dev", "A", "203.0.113.50"));
        // An empty non-terminal in the zone the negative paths are measured
        // against (VEGA-032 S2). The zero-allocation guarantee is a property of
        // the probe rather than of the node set, and this is what holds it to
        // that claim rather than to a zone shape.
        records.push(spec("a.b.ent", "A", "203.0.113.41"));
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
fn heap_budget(unmet: &mut Vec<String>) -> (Zone, i64) {
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
    (zone, live)
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

/// How many empty non-terminals the deep fixture implies: `_tcp.hN` and `hN`
/// for each of the [`ZONE_SIZE`] owners. Exact, not estimated — it is what makes
/// the per-node figure below a measurement rather than a ratio of two totals.
const ENTS_IN_THE_DEEP_FIXTURE: i64 = 2 * ZONE_SIZE_I64;

/// [`ZONE_SIZE`] as the signed type the byte arithmetic uses. `as` on a byte
/// count is a clippy denial and the lint is right to ask: these numbers appear
/// in a failure message an operator reads.
const ZONE_SIZE_I64: i64 = 100_000;

/// What one empty non-terminal may cost, in bytes of live heap.
///
/// MEASURED at `e7b8dba`, by solving for the marginal cost of one node over
/// zones that differ in exactly one of {nodes, RRsets, RDATA}: **102 B** — 96 for
/// the `Node` itself (an 80-byte `Name`, an 8-byte range, a flag byte, padded)
/// plus ~6 amortised for its `HashTable` slot. The budget is 110 rather than 102
/// because the index's bucket count is a power of two, so the amortised slot
/// cost swings between ~5 B and ~11 B depending on where the node count falls
/// against the next doubling.
///
/// It is stated **per empty non-terminal** rather than as a total, because that
/// is where the cost actually lives: the same 100,000 records cost 28.8 MiB in a
/// flat zone and ~48 MiB in a zone of `_sip._tcp.host` names. A single global
/// MiB ceiling would either fail the second shape or stop constraining the
/// first. The ruling's §7.1 estimate was 112 B; it is 10 B high here and 62 B
/// LOW for an owner name whose labels exceed hickory's 32-octet inline buffer,
/// where a node costs 174 B — worth knowing before someone materialises
/// ancestors for a zone of long names.
const BYTES_PER_EMPTY_NON_TERMINAL: i64 = 110;

/// The deep fixture: the same records at the same count, at names that imply two
/// empty non-terminals each. Same record type and same rdata as [`config`], so
/// the only thing that differs is the shape of the owner name.
fn deep_config() -> ZoneConfig {
    let mut cfg = config(false);
    // The mandatory apex NS is kept, and kept identical to the flat fixture's,
    // so it cancels exactly in the subtraction below and the difference between
    // the two zones is still only the shape of the owner names.
    cfg.records = std::iter::once(spec("@", "NS", "ns1.example.com."))
        .chain((0..ZONE_SIZE).map(|i| {
            spec(
                &format!("_sip._tcp.h{i}"),
                "A",
                &format!("10.{}.{}.{}", (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff),
            )
        }))
        .collect();
    cfg
}

/// Scenario: An empty non-terminal costs one node and nothing else
/// features/empty-non-terminals.feature:421
///
/// AC-2.6's memory half, and the number the release note owes an operator: RSS
/// grows on upgrade with no config change at all, and "roughly" is not good
/// enough when the deployment is sized.
///
/// Two zones, same record count, same type, same rdata, differing only in the
/// shape of the owner name — so the difference between them **is** the cost of
/// the empty non-terminals, with nothing else varying to explain it away.
fn empty_non_terminal_budget(flat_live: i64, unmet: &mut Vec<String>) {
    let cfg = deep_config();
    let region = Region::new(GLOBAL);
    let zone = Zone::from_config(&cfg).expect("deep zone builds");
    let stats = region.change();
    let live = i64::try_from(stats.bytes_allocated).expect("byte count fits")
        - i64::try_from(stats.bytes_deallocated).expect("byte count fits");

    let delta = live - flat_live;
    let per_ent = delta / ENTS_IN_THE_DEEP_FIXTURE;
    println!(
        "deep zone heap: {live} B live ({} MiB) against {flat_live} B flat; \
         {delta} B for {ENTS_IN_THE_DEEP_FIXTURE} empty non-terminals \
         ({per_ent} B each)",
        mib(live),
    );

    // The gate is meaningless unless the empty non-terminals are actually there.
    // Asserted first and for a name in the middle of the arena, not the first or
    // last, so an off-by-one at either end of the build is still caught.
    for ent in ["_tcp.h50000.example.com.", "h50000.example.com."] {
        if !zone.exists(&lower(ent)) {
            unmet.push(format!(
                "\"An empty non-terminal costs one node and nothing else\": \
                 {ent} does not exist, so this measured the cost of NOT \
                 materialising ancestors. The record beneath it is configured \
                 and, under RFC 8020 §2, one cached NXDOMAIN here takes it out \
                 of service"
            ));
        }
    }

    if per_ent > BYTES_PER_EMPTY_NON_TERMINAL {
        unmet.push(format!(
            "\"An empty non-terminal costs one node and nothing else\": \
             {ENTS_IN_THE_DEEP_FIXTURE} of them cost {delta} bytes, {per_ent} B \
             each, against a budget of {BYTES_PER_EMPTY_NON_TERMINAL} B. A node \
             is 96 B plus its index slot; anything above that is an RRset, an \
             RDATA entry or a second copy of the owner name that an empty \
             non-terminal has no business holding"
        ));
    }
}

/// The flat fixture's live heap, to the byte.
///
/// 30,255,464 B — 28.8 MiB, 302 B per record — from S1 through **S4**. The
/// fixture is FLAT (`h{i}`), so it materialises zero empty non-terminals and S2
/// could not touch it; S3 deleted one `u128` per zone; S4's `cut: NodeIdx` per
/// node landed in padding the S1 `Node` layout was already spending, so the
/// count did not move by a byte across any of the three.
///
/// **Re-baselined once, at S5, by +200 B exactly.** S5 makes an apex NS RRset
/// mandatory (RFC 1034 §4.2.1), so the fixture now declares one, and the
/// measured delta is `size_of::<Rrset>()` (16) + `size_of::<RData>()` (184) at
/// a node that already existed. That is a **fixture** cost, once per zone: the
/// per-record figure is unchanged at 302 B, the node count is unchanged at
/// 100,001, and the window below is unchanged at ±64 B, so the gate is exactly
/// as able to see a per-node field as it was before.
const FLAT_FIXTURE_BYTES: i64 = 30_255_664;

/// How far the flat fixture may drift and still count as unmoved.
///
/// S3's only structural change to a zone's footprint is deleting
/// `wildcard_depths: u128` and replacing it with a `u8` pair, so the arithmetic
/// says 15 bytes smaller. 64 rather than 16, because the arena is three `Box<[T]>`
/// whose element counts are unchanged but whose allocator padding is not
/// something a test should assert to the byte — and because a gate that flaps on
/// an allocator's rounding is a gate that gets deleted.
///
/// It is stated as a WINDOW and not a ceiling on purpose: a zone that got
/// dramatically *smaller* is as much a signal as one that grew. The most likely
/// way for it to shrink by megabytes is that the build started dropping records.
const FLAT_FIXTURE_DRIFT_BYTES: i64 = 64;

/// Scenario: The flat 100,000-record fixture does not grow
/// features/closest-encloser.feature:629
///
/// The S3 half of the memory gate, and the reason it is separate from the 40 MiB
/// ceiling above it: 40 MiB has 11 MiB of headroom, so it would not notice a
/// per-node field being added to pay for a closest-encloser search. This would.
///
/// The obvious wrong way to make a depth search cheap is to memoise something on
/// each node — a parent index, a cached encloser, a depth. On this fixture that
/// is 100,001 nodes, so four bytes each is 400 KB and this fails; the 40 MiB
/// ceiling would not move.
///
/// # Release only, and stated rather than silently skipped
///
/// A byte-exact figure is a claim about the **release** binary. A debug build of
/// the same zone measures 33,863,698 B — 3.4 MB more, ~36 B per node — because
/// `debug_assert_invariants` allocates a `HashSet` of every owner name for the
/// ancestor-closure check (I-3) and the allocator sees larger, differently laid
/// out structures throughout. Comparing that against a release baseline would
/// fail every `cargo test` run for a reason that has nothing to do with the
/// zone model, and a gate that is red by default is a gate somebody deletes.
///
/// The other budgets in this file survive a debug build because they carry
/// headroom: 40 MiB against 28.8, 110 B per empty non-terminal against 105. This
/// one deliberately has none, which is what makes it able to see a per-node
/// field, so it is the one that has to say which build it is talking about.
/// Skipping is announced on stdout rather than done quietly.
fn flat_fixture_does_not_grow(flat_live: i64, unmet: &mut Vec<String>) {
    let drift = flat_live - FLAT_FIXTURE_BYTES;
    println!(
        "flat fixture heap: {flat_live} B against {FLAT_FIXTURE_BYTES} B \
         (S1-S4 baseline + S5's mandatory apex NS), drift {drift:+} B"
    );
    if cfg!(debug_assertions) {
        println!(
            "  (byte-exact drift not checked: debug build. This budget has no \
             headroom by design, and a debug build costs ~36 B per node more \
             than the release baseline it is stated against. Run \
             `cargo test --release --test zone_memory`.)"
        );
        return;
    }
    if drift.abs() > FLAT_FIXTURE_DRIFT_BYTES {
        unmet.push(format!(
            "\"The flat 100,000-record fixture does not grow\": it is now \
             {flat_live} B against {FLAT_FIXTURE_BYTES} B, a drift of \
             {drift:+} B against a window of \
             ±{FLAT_FIXTURE_DRIFT_BYTES} B. This fixture materialises no empty \
             non-terminals and holds one wildcard, so the only thing S3 may \
             change here is one `u128` per ZONE. A drift of this size is \
             per-NODE, which on 100,001 nodes is how a closest-encloser search \
             gets made cheap by memoising something the model does not need"
        ));
    }
}

/// Scenario: A 100,000-record zone costs at most 40 MiB of live heap
/// features/zone-data-model.feature:345
///
/// Scenario: An answer vector is not over-allocated
/// features/zone-data-model.feature:360
///
/// Scenario: A negative answer in a wildcard zone allocates nothing at all
/// features/zone-data-model.feature:370
///
/// Scenario: An empty non-terminal costs one node and nothing else
/// features/empty-non-terminals.feature:421
///
/// Scenario: A negative answer still allocates nothing after ancestors are
/// materialised
/// features/empty-non-terminals.feature:459
///
/// Scenario: The flat 100,000-record fixture does not grow
/// features/closest-encloser.feature:629
///
/// Scenario: The negative paths still allocate nothing
/// features/closest-encloser.feature:648
///
/// Several scenarios in one test because they share a 100,000-record zone that
/// costs seconds to build, and because a `#[global_allocator]` makes a second
/// test in this binary a second source of counts.
///
/// Every budget is collected and reported together at the end. Failing at the
/// first would hide the others behind it, and a reader given one number cannot
/// tell whether the rest are met.
#[test]
fn the_zone_and_its_answers_cost_what_the_ruling_budgets() {
    let _watchdog = testutil::arm(WATCHDOG);

    let mut unmet: Vec<String> = Vec::new();
    let (zone, flat_live) = heap_budget(&mut unmet);
    flat_fixture_does_not_grow(flat_live, &mut unmet);
    answer_vector_budget(&zone, &mut unmet);
    drop(zone);
    empty_non_terminal_budget(flat_live, &mut unmet);
    negative_path_budget(&mut unmet);

    assert!(
        unmet.is_empty(),
        "{} of the S1 memory budgets are not met:\n  - {}",
        unmet.len(),
        unmet.join("\n  - "),
    );
}
