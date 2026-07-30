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
