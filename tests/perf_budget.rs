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
const MAX_QUERY_LABELS: usize = 123;

fn spec(name: &str, ty: &str, values: &[&str]) -> RecordSpec {
    RecordSpec {
        name: name.to_owned(),
        record_type: ty.to_owned(),
        ttl: None,
        values: values.iter().map(|v| (*v).to_owned()).collect(),
    }
}

fn lower(name: &str) -> LowerName {
    let mut n: Name = name.parse().expect("fixture name parses");
    n.set_fqdn(true);
    LowerName::from(n)
}

/// A zone that holds at least one wildcard — the only zones VEGA-065 exposes.
fn wildcard_zone() -> Zone {
    let mut records = vec![
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
/// features/zone-lookup.feature:375
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
