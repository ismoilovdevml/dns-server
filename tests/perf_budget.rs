//! The performance budget for the wildcard parent walk (VEGA-065), expressed
//! as an assertion a CI runner can hold.
//!
//! Wall-clock thresholds do not survive a shared runner, so the budget is a
//! *ratio* between two query shapes measured back to back in the same process.
//! A ratio is immune to a slow machine: if the box is 5x slower both halves are
//! 5x slower and the ratio holds. What a ratio is not immune to is an algorithm
//! that changed complexity class — which is exactly what this guards.
//!
//! Scope, per the VEGA-065 ruling
//! (`.claude/backlog/decisions/VEGA-065-bounded-wildcard-walk.md`, §D): this
//! file holds **one** budget. The other five in perf-engineer's
//! `test-perf_budget.rs` belong to VEGA-002 (the record-map re-key, which the
//! ruling explicitly excludes from VEGA-065 — three of them cannot pass without
//! it) and to VEGA-070 (which owns landing the file as a CI gate). Pulling them
//! in here would hand VEGA-065 a red suite it has no mandate to fix.
//!
//! Run: `cargo test --release --test perf_budget -- --ignored --nocapture`

use std::time::{Duration, Instant};

use hickory_proto::rr::{LowerName, Name, RecordType};
use vega::{
    config::{RecordSpec, SoaSpec, ZoneConfig},
    zone::{Answer, Zone},
};

/// The process watchdog, shared by path rather than copied, so there is one
/// implementation of "a test that hangs must fail" in the tree.
#[path = "../src/testutil.rs"]
mod testutil;

/// This binary builds a 100,000-record zone and then runs 50,000 lookups of a
/// 123-label name, so it is the slowest guarded test in the tree — but it is
/// still seconds, and a deep-name lookup is exactly the shape an unbounded
/// wildcard walk spins on. Three minutes is generous enough that a loaded CI
/// runner cannot trip it and tight enough that a spin is not an orphan.
const WATCHDOG: Duration = Duration::from_secs(180);

/// Big enough that a per-query cost buried in zone-wide work would show, small
/// enough that the zone builds in a couple of seconds under `--release`.
const ZONE_SIZE: usize = 100_000;

/// The most labels a name can carry under `example.com.` inside RFC 1035
/// §2.3.4's 255 octets: `121 * 2 + 8 + 4 + 1 = 255`. The attack packet in
/// VEGA-065's evidence used 100 labels; the true worst case is this.
///
/// **Under this origin only.** The protocol ceiling is [`PROTOCOL_MAX_LABELS`];
/// treating 123 as the limit is the mistake VEGA-032 §5.2 corrects, and it is
/// wrong wherever it appears as a protocol bound rather than as this zone's.
const MAX_QUERY_LABELS: usize = 123;

/// The deepest name the wire can carry at all: RFC 1035 §3.1 encodes a
/// single-octet label in two octets and terminates the name with one, so
/// `127 * 2 + 1 = 255` exactly. Reachable only by a name with no zone suffix to
/// pay for, i.e. under `origin = "."`.
///
/// This is the deepest index every label-keyed structure in the zone model will
/// ever see: VEGA-065's `u128` bit 127 today, and VEGA-032 S0's `[u64; 128]`
/// suffix-hash array from S0 onwards. Measured against hickory-proto 0.26.1 —
/// 127 labels parse, 128 are rejected with `DomainNameTooLong(257)`, pinned by
/// `tests/canonical_order.rs::a_name_one_label_past_the_ceiling_is_rejected_before_it_reaches_the_zone`.
const PROTOCOL_MAX_LABELS: usize = 127;

fn spec(name: &str, ty: &str, values: &[&str]) -> RecordSpec {
    RecordSpec {
        name: name.to_owned(),
        record_type: ty.to_owned(),
        ttl: None,
        values: values.iter().map(|v| (*v).to_owned()).collect(),
    }
}

/// The apex NS RRset every fixture here carries.
///
/// RFC 1034 §4.2.1 requires one and VEGA-032 S5 refuses a zone without one. One
/// record in a hundred thousand; it is in the arena and the index like any
/// other, and every figure below is measured with it present.
fn apex_ns() -> RecordSpec {
    spec("@", "NS", &["ns1.example.com."])
}

fn lower(name: &str) -> LowerName {
    let mut n: Name = name.parse().expect("fixture name parses");
    n.set_fqdn(true);
    LowerName::from(n)
}

/// A zone that holds at least one wildcard — the only zones VEGA-065 exposes.
fn wildcard_zone() -> Zone {
    let mut records = vec![
        apex_ns(),
        spec("@", "A", &["203.0.113.10", "203.0.113.11"]),
        spec("*.apps", "A", &["203.0.113.30"]),
    ];
    records.reserve(ZONE_SIZE);
    for i in 0..ZONE_SIZE {
        records.push(spec(
            &format!("h{i}"),
            "A",
            &[&format!(
                "10.{}.{}.{}",
                (i >> 16) & 0xff,
                (i >> 8) & 0xff,
                i & 0xff
            )],
        ));
    }
    Zone::from_config(&ZoneConfig {
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
    })
    .expect("zone builds")
}

/// Best-of-N timing: the minimum over `rounds`, which discards scheduler
/// interference instead of averaging it in.
fn best_of(rounds: usize, iters: usize, mut f: impl FnMut()) -> Duration {
    let mut best = Duration::MAX;
    for _ in 0..rounds {
        let t = Instant::now();
        for _ in 0..iters {
            f();
        }
        best = best.min(t.elapsed() / u32::try_from(iters).expect("iters fits in u32"));
    }
    best
}

/// BUDGET (VEGA-065): the wildcard parent walk costs what the *zone* contains,
/// never what the *query name* contains.
///
/// Scenario: features/wildcards.feature — "A maximum-length attacker-chosen
/// name costs no more than a one-label name".
///
/// The walk calls `LowerName::base_name()` once per label, and `base_name` goes
/// through `Name::from_labels`, which allocates, revalidates every label and
/// re-appends them one at a time — so step k is O(remaining labels) and the walk
/// is quadratic. Measured before the fix: 174.7 µs for one 100-label NXDOMAIN
/// against a 9.1 µs per-query CPU budget, from a 229-byte packet. 5,725 pps
/// (12.4 Mbit/s) occupies a core.
///
/// # Status
///
/// **Live as of the commit that landed the `wildcard_depths` bitmap.** It was
/// `#[ignore]`d while it was VEGA-065's acceptance criterion rather than a
/// regression guard, and un-ignored in the same commit that bounded the walk.
/// Measured `--release` on one machine, either side of that commit:
///
/// ```text
/// before  shallow 235ns  deep(123 labels) 239.631µs  ratio 1019.7x
/// after   shallow  88ns  deep(123 labels)   1.657µs  ratio   18.8x
/// after   shallow  83ns  deep(123 labels)   1.714µs  ratio   20.7x
/// ```
///
/// (qa-spec measured 1142.2x for the before, perf-engineer 766.2x at 100
/// labels; the spread is machine noise around one complexity class. 123 labels
/// is the real worst case an attacker can send.) The number that closes the
/// DoS is the absolute one: **239.631 µs to 1.657 µs**, a 145x cut, taking one
/// attacker-chosen packet from 26x the 9.1 µs per-query CPU budget to well
/// inside it.
///
/// # Why the ratio is still ~19x and not ~1x
///
/// What remains is linear, and none of it is the walk, which is now one probe
/// regardless of depth. A 123-label query still pays `contains` (`zone_of`
/// zips labels), two clones of a 255-octet name into `(LowerName, RecordType)`
/// lookup keys, and four hashes of it. That is O(labels) with a large constant
/// against an 88 ns shallow baseline, so it dominates the ratio while being
/// harmless: linear in the query name is what every DNS server pays.
///
/// Removing it means not materialising a key per lookup, which is the record
/// -map re-key the VEGA-065 ruling assigns to **VEGA-002**. Until that lands
/// the headroom under 25x is thinner than it looks — 19–21x measured — and the
/// margin is bounded below by how *fast* the shallow case is, not by how slow
/// the deep one is. VEGA-070, which owns wiring this into CI, should either
/// take it after VEGA-002 or re-baseline the ratio on the CI runner first.
#[test]
fn a_deep_name_does_not_cost_more_than_a_shallow_one() {
    // A wildcard walk that stops being bounded does not make this budget fail,
    // it makes it never finish: the 50,000 deep lookups below never return.
    // Without the guard that is a hung binary and, under a mutation harness, a
    // mutant scored as a timeout instead of as caught.
    let _watchdog = testutil::arm(WATCHDOG);
    let z = wildcard_zone();
    let shallow = lower("nope.example.com.");
    let deep = {
        let mut s = String::with_capacity(MAX_QUERY_LABELS * 2 + 16);
        for _ in 0..MAX_QUERY_LABELS - 2 {
            s.push_str("a.");
        }
        s.push_str("example.com.");
        lower(&s)
    };

    // Both must actually be NXDOMAIN, or the comparison measures two different
    // code paths rather than the same path at two depths.
    assert_eq!(z.lookup(&shallow, RecordType::A), Answer::NxDomain);
    assert_eq!(z.lookup(&deep, RecordType::A), Answer::NxDomain);

    // 5,000 iterations keeps the unbounded case (~260 µs a query at this depth)
    // to a few seconds while still averaging out timer noise; best-of-5 does the
    // rest.
    let s = best_of(5, 5_000, || {
        std::hint::black_box(z.lookup(std::hint::black_box(&shallow), RecordType::A));
    });
    let d = best_of(5, 5_000, || {
        std::hint::black_box(z.lookup(std::hint::black_box(&deep), RecordType::A));
    });

    let r = d.as_secs_f64() / s.as_secs_f64();
    println!("shallow {s:?}  deep({MAX_QUERY_LABELS} labels) {d:?}  ratio {r:.1}x");
    assert!(
        r < 25.0,
        "a {MAX_QUERY_LABELS}-label NXDOMAIN costs {r:.1}x a 1-label one \
         (budget 25x, measured {d:?} vs {s:?}); the wildcard walk is unbounded again"
    );
}

/// BUDGET (CLAUDE.md, "Performance budget"): **no `O(n)` scan over the record
/// map per query, for any query type.**
///
/// Scenario: An ANY lookup costs the same on a 100,000-record zone as on a small one
/// features/zone-lookup.feature:390
///
/// `Zone::resolve`'s ANY branch is
/// `for ((owner, _), records) in &self.exact { if owner == name { … } }` — a
/// linear walk of every record set in the zone, with a `LowerName` comparison
/// each time, for one query. It is the only lookup path in the tree that is not
/// keyed.
///
/// # Status: FAILS TODAY, and is `#[ignore]`d for that reason
///
/// This is a live budget violation, not an acceptance criterion waiting on a
/// feature. Measured `--release` on this machine, `h1.example.com` against zones
/// of three sizes, best-of-3 over 200 iterations each:
///
/// ```text
///   zone   1,000 records:  A 219.6 ns   ANY    31.5 µs   ratio     143.5x
///   zone  10,000 records:  A 134.2 ns   ANY   176.0 µs   ratio   1,311.8x
///   zone 100,000 records:  A 100.4 ns   ANY 1,831.4 µs   ratio  18,238.7x
/// ```
///
/// Ten times the records is ten times the cost, which is the definition of the
/// thing the budget forbids. At 100,000 records one ANY lookup is **1.83 ms**,
/// 201x VEGA-065's 9.1 µs per-query CPU budget — an order of magnitude worse
/// than the 174.7 µs wildcard walk that VEGA-065 was raised to fix.
///
/// # What keeps this off the packet path today, and why that is not enough
///
/// `DnsHandler::resolve` never calls `Zone::lookup(_, ANY)`: RFC 8482 minimal
/// -ANY intercepts first (`handler.rs`, `if qtype.is_any()`), answering from
/// `Zone::exists` plus a CNAME lookup. So this was **not** a live remote DoS — it was
/// a 1.8 ms landmine in a `pub fn` with no guard and no test, one routing change
/// away from being one. VEGA-041's SLIP, an AXFR path, or anything that decides
/// to consult the zone for ANY re-arms it.
///
/// The re-key that VEGA-002 deferred and VEGA-032 owns would have made "every
/// RRset at this name" a map hit rather than a scan. VEGA-083 got there first
/// and by a shorter route — see below — so this budget is now live rather than
/// aspirational, and guards against the scan being reintroduced.
///
/// # VEGA-083 (AC-7): the arm is deleted rather than re-keyed
///
/// The scan carried the existence defect under that issue's ruling at a third
/// `pub`-reachable site — `else if self.names.contains(name)` decided NODATA vs
/// NXDOMAIN from the node set, so a wildcard-covered name got a name error here
/// too. Fixing it in place means either a slower scan or VEGA-032's re-key, so
/// it goes: RFC 1035 §3.2.3 makes ANY a QTYPE that can never key the record map,
/// and RFC 8482 makes the response policy the *responder's* business, so the
/// zone layer has nothing to say about ANY beyond whether the name exists.
///
/// `Zone::lookup(_, ANY)` therefore returns `NoData` for every existing name and
/// `NxDomain` otherwise — hence the assertions below, which were
/// `Answer::Records(_)`. Flat cost across zone sizes follows by construction.
/// Un-`#[ignore]`d in the commit that landed the fix, which is AC-7 of that
/// ruling and not a bonus.
#[test]
fn an_any_lookup_does_not_scan_the_whole_record_map() {
    let _watchdog = testutil::arm(WATCHDOG);
    let z = wildcard_zone();
    let name = lower("h1.example.com.");

    // The same existing name either way, so the only difference measured is how
    // the lookup gets there.
    assert!(matches!(z.lookup(&name, RecordType::A), Answer::Records(_)));
    assert_eq!(
        z.lookup(&name, RecordType::ANY),
        Answer::NoData,
        "the zone layer reports existence for ANY and never enumerates the node"
    );

    let a = best_of(3, 200, || {
        std::hint::black_box(z.lookup(std::hint::black_box(&name), RecordType::A));
    });
    let any = best_of(3, 200, || {
        std::hint::black_box(z.lookup(std::hint::black_box(&name), RecordType::ANY));
    });

    let r = any.as_secs_f64() / a.as_secs_f64();
    println!("zone {ZONE_SIZE} records:  A {a:?}  ANY {any:?}  ratio {r:.1}x");
    assert!(
        r < 25.0,
        "ANY costs {r:.1}x A at {ZONE_SIZE} records ({any:?} vs {a:?}). A ratio \
         that grows with the zone is an O(n) scan over the record map, which the \
         performance budget forbids for every query type"
    );
}

/// BUDGET (VEGA-032 §13, AC-2.6): an empty non-terminal is found by the same
/// single probe as any other node.
///
/// Scenario: An empty non-terminal is answered as cheaply as any other existing
/// name
/// features/empty-non-terminals.feature:448
///
/// An empty non-terminal is "a node with no RRsets" (RFC 4592 §2.2.2), so
/// answering one is a hash probe, a hit, and an empty RRset range — strictly
/// *less* work than an exact hit, which additionally binary-searches the type
/// and copies rdata into a `Vec`. If it costs more, the node is not being found
/// and the lookup is falling through to the wildcard walk before it answers,
/// which is a different bug wearing the right rcode.
///
/// Ratio-budgeted like every other case in this file so that a shared or slow
/// runner cannot make it flap. 2x rather than 1x because the exact hit is the
/// *faster* of the two operations to mis-measure: it allocates, so it is the
/// side with the larger constant, and a budget of 1.0 would be measuring
/// `malloc` rather than the probe.
///
/// # Status: FAILS TODAY, and for the right reason
///
/// `_tcp.h1.example.com.` is NXDOMAIN before S2, so the assertion that it is
/// NODATA fails before any timing is taken. That is deliberate: a timing
/// comparison between an exact hit and a name error is a comparison of two
/// different code paths, and it would report a perfectly healthy ratio while
/// measuring nothing at all.
#[test]
fn an_empty_non_terminal_costs_no_more_than_an_exact_hit() {
    let _watchdog = testutil::arm(WATCHDOG);

    let mut records = vec![apex_ns()];
    records.reserve(ZONE_SIZE);
    for i in 0..ZONE_SIZE {
        records.push(spec(
            &format!("_sip._tcp.h{i}"),
            "A",
            &[&format!(
                "10.{}.{}.{}",
                (i >> 16) & 0xff,
                (i >> 8) & 0xff,
                i & 0xff
            )],
        ));
    }
    let z = Zone::from_config(&ZoneConfig {
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
    })
    .expect("zone builds");

    let owner = lower("_sip._tcp.h1.example.com.");
    let ent = lower("_tcp.h1.example.com.");

    assert!(
        matches!(z.lookup(&owner, RecordType::A), Answer::Records(_)),
        "the exact owner must answer, or the baseline is not an exact hit"
    );
    assert_eq!(
        z.lookup(&ent, RecordType::A),
        Answer::NoData,
        "the empty non-terminal must be NODATA before its cost means anything: \
         timing an NXDOMAIN against an exact hit compares two different paths"
    );

    let hit = best_of(5, 5_000, || {
        std::hint::black_box(z.lookup(std::hint::black_box(&owner), RecordType::A));
    });
    let empty = best_of(5, 5_000, || {
        std::hint::black_box(z.lookup(std::hint::black_box(&ent), RecordType::A));
    });

    let r = empty.as_secs_f64() / hit.as_secs_f64();
    println!("exact hit {hit:?}  empty non-terminal {empty:?}  ratio {r:.2}x");
    assert!(
        r < 2.0,
        "an empty non-terminal costs {r:.2}x an exact hit ({empty:?} vs \
         {hit:?}). It is one probe into an empty RRset range and must be the \
         cheaper of the two; a higher cost means the node is not found and the \
         answer is coming out of the wildcard walk"
    );
}

/// BUDGET (VEGA-032 §5.2, AC-1.7): the same claim at the **protocol** ceiling
/// rather than at this zone's.
///
/// Scenario: The true 127-label ceiling is measured and budgeted, not just the
/// 123-label one
/// features/zone-data-model.feature:514
///
/// # Why 123 is not enough
///
/// Every other depth budget in this tree is written at 123 labels, which is the
/// most that fits under `example.com.` inside RFC 1035 §2.3.4's 255 octets. The
/// decoder's ceiling is **127** — `127 * 2 + 1 = 255` — reachable by a bare name
/// with no zone suffix to pay for, and that is the input an attacker sends. It
/// is also the deepest index any label-keyed structure in the zone model will
/// see: bit 127 of VEGA-065's `u128` today, and entry 127 of VEGA-032 S0's
/// `[u64; MAX_LABELS + 1]` suffix-hash array afterwards. With
/// `panic = "abort"`, one index past that is a full outage from one packet.
///
/// The ruling asks for this as a **new baseline at S1**, because the current
/// arithmetic has never been measured at the real boundary. Ratio-budgeted like
/// its sibling above, so a slow or shared runner cannot make it flap: what a
/// ratio cannot survive is a change of complexity class, which is the whole
/// point.
///
/// # The baseline, measured before S1
///
/// ```text
/// shallow 124ns  deep(127 labels) 1.666µs  ratio 13.4x     (this test)
/// shallow  81ns  deep(123 labels) 1.717µs  ratio 21.2x     (its sibling, same run)
/// ```
///
/// The 127-label ratio is *lower* than the 123-label one only because the
/// root-origin shallow control is slower, not because the deep case is cheaper:
/// the absolute deep figures agree to within noise, which is the evidence that
/// the walk is already independent of depth and that 123 was never measuring
/// anything 127 does not. S1 must hold the ratio and is expected to improve
/// both absolutes, because the tuple-key `LowerName` clone disappears.
///
/// Root origin, because that is the only way a 127-label name is in zone.
#[test]
fn the_protocol_ceiling_name_does_not_cost_more_than_a_shallow_one() {
    let _watchdog = testutil::arm(WATCHDOG);

    // A root-origin zone: `origin = "."` is accepted, drives the probe window's
    // floor to zero, and is the only origin under which a 127-label name is
    // inside the zone at all.
    // The apex NS is spelled for the root here, not with `apex_ns()`: this
    // fixture's origin is `.`, and a target under `example.com.` would be an
    // out-of-bailiwick name server, which is legal but is not what the other
    // fixtures carry.
    let mut records = vec![spec("@", "NS", &["ns1."]), spec("*", "A", &["203.0.113.1"])];
    records.reserve(ZONE_SIZE);
    for i in 0..ZONE_SIZE {
        records.push(spec(
            &format!("h{i}.example.com."),
            "A",
            &[&format!(
                "10.{}.{}.{}",
                (i >> 16) & 0xff,
                (i >> 8) & 0xff,
                i & 0xff
            )],
        ));
    }
    let z = Zone::from_config(&ZoneConfig {
        origin: ".".to_owned(),
        default_ttl: 300,
        builtins: false,
        soa: Some(SoaSpec {
            mname: "ns1.".to_owned(),
            rname: "hostmaster.".to_owned(),
            serial: 1,
            refresh: 3600,
            retry: 900,
            expire: 604_800,
            minimum: 60,
        }),
        records,
    })
    .expect("root-origin zone builds");

    let shallow = lower("nope.");
    let deep = lower(&"a.".repeat(PROTOCOL_MAX_LABELS));
    assert_eq!(
        Name::from(deep.clone()).iter().len(),
        PROTOCOL_MAX_LABELS,
        "the fixture must sit exactly at the decoder's ceiling, not near it: \
         this is the input that drives every label-keyed index in the model to \
         its largest reachable value"
    );

    // Both are answered by the apex wildcard, so the two measurements are the
    // same code path at two depths rather than two different paths.
    assert!(matches!(
        z.lookup(&shallow, RecordType::A),
        Answer::Records(_)
    ));
    assert!(matches!(z.lookup(&deep, RecordType::A), Answer::Records(_)));

    let s = best_of(5, 5_000, || {
        std::hint::black_box(z.lookup(std::hint::black_box(&shallow), RecordType::A));
    });
    let d = best_of(5, 5_000, || {
        std::hint::black_box(z.lookup(std::hint::black_box(&deep), RecordType::A));
    });

    let r = d.as_secs_f64() / s.as_secs_f64();
    println!("shallow {s:?}  deep({PROTOCOL_MAX_LABELS} labels) {d:?}  ratio {r:.1}x");
    assert!(
        r < 25.0,
        "a {PROTOCOL_MAX_LABELS}-label lookup costs {r:.1}x a 1-label one \
         (budget 25x, measured {d:?} vs {s:?}). The depth walk is a function of \
         the query name again, at the deepest name the wire can carry"
    );
}

/// How many distinct label depths the hostile zone declares a wildcard at.
///
/// VEGA-078's own evidence used 120, measured on a running server: one 276-byte
/// packet bought ~222 µs of server work (~229 µs measured in-process by
/// perf-engineer), against a 9.1 µs per-query CPU budget. Kept at 120 so the
/// number this test prints can be compared with that issue's directly.
const HOSTILE_WILDCARD_DEPTHS: usize = 120;

/// A zone declaring a wildcard at each of `depths` distinct label depths.
///
/// `*.a`, `*.a.a`, `*.a.a.a`, … — VEGA-078's shape exactly. Deliberately **no
/// bare `*` at the apex**: an apex wildcard is the closest encloser of every
/// name in the zone, so it answers the query and the miss path — the one that
/// pays for every probe — is never reached. That is the difference between
/// measuring the attack and measuring a cache hit.
fn multi_depth_wildcard_zone(depths: usize) -> Zone {
    let mut records = Vec::with_capacity(depths + 2);
    records.push(apex_ns());
    records.push(spec("www", "A", &["203.0.113.20"]));
    for d in 1..=depths {
        let parent = std::iter::repeat_n("a", d).collect::<Vec<_>>().join(".");
        records.push(spec(&format!("*.{parent}"), "A", &["203.0.113.1"]));
    }
    Zone::from_config(&ZoneConfig {
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
    })
    .expect("multi-depth wildcard zone builds")
}

/// BUDGET (VEGA-078; VEGA-032 §5.2 and §13 AC-3.6): the cost of answering a
/// query does not depend on how many distinct label depths the zone declares a
/// wildcard at.
///
/// Scenario: A zone with wildcards at 120 depths costs no more than one with a
/// single depth
/// features/closest-encloser.feature:443
///
/// # The issue, in one paragraph
///
/// VEGA-065 replaced the `base_name()` climb with a descending probe over a
/// `u128` of wildcard depths. The loop runs once per **set bit inside the
/// window** — once per distinct depth at which the zone holds a wildcard — so
/// the per-query cost stopped being a function of the client's name and became a
/// function of the operator's zone. Nothing bounds the operator's side, nothing
/// warns about it, and `wildcard_zone()` above holds exactly one wildcard, so
/// the existing budget measures the single-probe case and stays green at any
/// count. Measured on a running server: 1 depth 33.6 µs RTT, 8 depths 35.9 µs,
/// **120 depths 251.3 µs** against a ~29 µs loopback floor — ~222 µs of server
/// work, slightly worse than the 174.7 µs that opened VEGA-065, and 24x the
/// 9.1 µs per-query budget. ~4,500 pps occupies a core.
///
/// It carries `security: true` for a reason worth restating: the operator
/// supplies the wildcard count, but the **query name is attacker-chosen** and it
/// is what decides that every probe misses. Operator-enabled, attacker-triggered.
///
/// # MEASURED AT `bd4b397`, AND THE NUMBER IS NOT THE ONE THE ISSUE PREDICTED
///
/// ```text
///   1 depth    307 ns
///   8 depths   304 ns
///   32 depths  390 ns
///   120 depths 546 ns        ratio 1.9x
/// ```
///
/// VEGA-078 was filed at ~229 µs for the 120-depth case and the ruling promised
/// ≤ 2 µs at S3. **S1 already delivered 99.7% of that**, and nobody noticed,
/// because this case did not exist to notice it with. The reason is in that
/// issue's own analysis: its cost was dominated by `name.trim_to(depth)` —
/// `Name::from_labels`, an allocation plus a revalidation of `depth` labels —
/// and by a `LowerName` clone into a tuple key, per probe. The arena replaced
/// both with a hash comparison against a precomputed suffix hash, so the probe
/// stopped allocating and the walk collapsed to ~2 ns per depth.
///
/// So the honest statement of what each step buys, and both gates are written to
/// say exactly that:
///
///   * the **absolute** (≤ 2 µs) is the ruling's committed number, it is
///     **already met at `bd4b397`**, and it is here as a RATCHET rather than as
///     an acceptance criterion. It fails the moment anyone reintroduces a
///     per-probe allocation or a materialised lookup key — which is precisely
///     the change that made this a security issue in the first place, and which
///     nothing else in the tree would catch;
///   * the **ratio** (≤ 1.5x) is **S3's own claim, and it is red today at 1.9x**.
///     The probe count is still `popcount(wildcard_depths ∩ window)`; only its
///     constant got smaller. The closest-encloser rule makes it a constant
///     outright, so 120 depths must cost what 1 depth costs.
///
/// A ratio is the right shape for the structural claim because it survives a
/// shared runner: if the box is 5x slower both halves are 5x slower. What a
/// ratio cannot survive is a change of complexity class. The spread above is
/// printed on every run so that a future failure can be read as "constant factor"
/// or "the walk came back" without anyone re-deriving it.
///
/// perf-engineer's ruling on this issue asked for a ratio case to land
/// immediately and for the absolute to be "a tightening of the same case ...
/// measured, in the commit that implements it — not written down in advance as a
/// number nobody has run". Both land here, measured, in that commit.
///
/// # Status: FAILS TODAY on the ratio, and for the right reason
#[test]
fn a_zone_with_many_wildcard_depths_costs_no_more_than_one_with_a_single_depth() {
    let _watchdog = testutil::arm(WATCHDOG);

    let one = multi_depth_wildcard_zone(1);
    let many = multi_depth_wildcard_zone(HOSTILE_WILDCARD_DEPTHS);
    let spread = [1usize, 8, 32, 120];

    // The attack shape: a 123-label name of `b` labels, which is the deepest a
    // name can be under `example.com.` and matches no wildcard parent in either
    // zone, so every probe misses and `trim_to` pays its worst case.
    let hostile = lower(&format!(
        "{}example.com.",
        "b.".repeat(MAX_QUERY_LABELS - 2)
    ));
    assert_eq!(
        Name::from(hostile.clone()).iter().len(),
        MAX_QUERY_LABELS,
        "the query must sit at this zone's depth ceiling, which is where the \
         probe window is widest"
    );

    // Both must reach the SAME answer through the same arm, or the two timings
    // are of two different code paths and the ratio means nothing. NXDOMAIN:
    // nothing encloses this name but the apex, and the apex holds no wildcard.
    for (label, z) in [("1-depth", &one), ("120-depth", &many)] {
        assert_eq!(
            z.lookup(&hostile, RecordType::A),
            Answer::NxDomain,
            "the {label} zone must answer the hostile name with a name error, or \
             the measurement below is of a wildcard hit rather than of the miss \
             path that pays for every probe"
        );
    }

    let single = best_of(5, 2_000, || {
        std::hint::black_box(one.lookup(std::hint::black_box(&hostile), RecordType::A));
    });
    let hostile_cost = best_of(5, 2_000, || {
        std::hint::black_box(many.lookup(std::hint::black_box(&hostile), RecordType::A));
    });

    // The curve, printed rather than asserted. A single ratio says "this got
    // worse"; the curve says whether it got worse by a constant or by a
    // complexity class, which is the difference between a slow machine and the
    // walk coming back.
    for d in spread {
        let z = multi_depth_wildcard_zone(d);
        let t = best_of(5, 2_000, || {
            std::hint::black_box(z.lookup(std::hint::black_box(&hostile), RecordType::A));
        });
        println!("  spread: {d} depths {t:?}");
    }

    let r = hostile_cost.as_secs_f64() / single.as_secs_f64();
    println!(
        "wildcard depths 1 {single:?}   {HOSTILE_WILDCARD_DEPTHS} {hostile_cost:?}   ratio {r:.1}x"
    );

    assert!(
        r < 1.5,
        "a zone declaring wildcards at {HOSTILE_WILDCARD_DEPTHS} distinct depths \
         costs {r:.1}x one declaring a single depth ({hostile_cost:?} vs \
         {single:?}). The probe count is a function of the zone again, which is \
         VEGA-078: the operator supplies the depth count, the attacker supplies \
         the query name that makes every probe miss, and one 276-byte packet \
         buys the difference"
    );
    // RELEASE ONLY, and announced rather than skipped quietly.
    //
    // The ratio above is the structural claim and it holds in either build — a
    // debug build is uniformly slower, so both halves move together and it
    // measures 1.1x there too. The 2 µs is a *wall clock* number, and every
    // figure it was derived from was measured `--release`: the same query costs
    // ~5 µs in a debug build, entirely because of `debug_assert`s and unelided
    // abstraction, and nothing about that says anything about VEGA-078.
    //
    // Asserting it unconditionally would leave `cargo test` red by default, and
    // a gate that is red by default is a gate somebody deletes — the same
    // reasoning `tests/zone_memory.rs::flat_fixture_does_not_grow` is written
    // with, and it is the only other absolute figure in this tree.
    if cfg!(debug_assertions) {
        println!(
            "  (2 µs ceiling not checked: debug build. The ratio above is, and it \
             is the half that carries the structural claim. Run \
             `cargo test --release --test perf_budget`.)"
        );
        return;
    }
    assert!(
        hostile_cost < Duration::from_micros(2),
        "one query against a {HOSTILE_WILDCARD_DEPTHS}-depth wildcard zone costs \
         {hostile_cost:?}, against the ruling's 2 µs (§5.2) and a 9.1 µs \
         per-query CPU budget. This gate was already GREEN at `bd4b397` (546 ns) \
         because the arena removed the per-probe allocation, so a failure here \
         is a regression rather than an unmet criterion: something on the miss \
         path is materialising a name or a lookup key again, which is exactly \
         what made VEGA-078 a security issue"
    );
}

/// BUDGET (VEGA-032 §5.2, AC-4.10): a referral costs no more than **2x** a
/// shallow exact hit.
///
/// Scenario: A referral is assembled from precomputed sections, not searched for
/// features/zone-lookup.feature — AC-4.10
///
/// A referral is the one answer with two record sections, so it is the one an
/// attacker would pick if assembling it cost anything per query. The budget is
/// what makes "precomputed at build time" a checked claim rather than a comment:
/// if the NS RRset were looked up and its glue resolved per query, this would be
/// an extra probe per name server plus their rdata copies, on top of the same
/// hash probe the exact hit pays for.
///
/// 2x rather than 1x because the referral really does copy more records — one NS
/// plus one glue A against one A — and that copy is the answer, not overhead.
/// What the budget excludes is *searching* for them.
///
/// Both sides of the ratio run against the same 100,000-record zone, so the
/// index, the arena and the cache state are shared and the only difference is
/// which branch of `Zone::resolve` runs.
#[test]
fn a_referral_costs_no_more_than_twice_a_shallow_exact_hit() {
    let _watchdog = testutil::arm(WATCHDOG);

    let mut records = vec![
        spec("@", "NS", &["ns1.example.com."]),
        spec("sub", "NS", &["ns1.sub.example.com."]),
        spec("ns1.sub", "A", &["203.0.113.53"]),
    ];
    records.reserve(ZONE_SIZE);
    for i in 0..ZONE_SIZE {
        records.push(spec(
            &format!("h{i}"),
            "A",
            &[&format!(
                "10.{}.{}.{}",
                (i >> 16) & 0xff,
                (i >> 8) & 0xff,
                i & 0xff
            )],
        ));
    }
    let z = Zone::from_config(&ZoneConfig {
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
    })
    .expect("zone builds");

    let hit = lower("h1.example.com.");
    let below_cut = lower("host.sub.example.com.");

    assert!(
        matches!(z.lookup(&hit, RecordType::A), Answer::Records(_)),
        "the baseline must be an exact hit"
    );
    assert!(
        matches!(z.lookup(&below_cut, RecordType::A), Answer::Referral { .. }),
        "the measured case must be a referral, or this times a name error"
    );

    let exact = best_of(5, 5_000, || {
        std::hint::black_box(z.lookup(std::hint::black_box(&hit), RecordType::A));
    });
    let referral = best_of(5, 5_000, || {
        std::hint::black_box(z.lookup(std::hint::black_box(&below_cut), RecordType::A));
    });

    let r = referral.as_secs_f64() / exact.as_secs_f64();
    println!("shallow exact hit {exact:?}  referral {referral:?}  ratio {r:.2}x");
    assert!(
        r < 2.0,
        "a referral costs {r:.2}x a shallow exact hit ({referral:?} vs \
         {exact:?}). The NS RRset and its glue are assembled once per build and \
         answered as two slice clones; a higher cost means they are being \
         searched for per query"
    );
}
