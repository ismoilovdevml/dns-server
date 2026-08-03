//! Property-based tests: invariants that must hold for *every* zone, not just
//! the handful of shapes the example-based tests happen to use.
//!
//! Each test states its invariant in prose first. When one of these fails,
//! proptest prints the smallest zone that breaks it, which is usually the whole
//! bug report.

use std::collections::BTreeSet;
use std::time::Duration;

use hickory_proto::rr::{LowerName, Name, RData, Record, RecordType};
use proptest::prelude::*;
use vega::{
    config::{RecordSpec, SoaSpec, ZoneConfig},
    editor::{Change, ConfigEditor},
    zone::{Answer, Zone},
};

/// The process watchdog, shared by path rather than copied.
///
/// Proptest is the worst possible place to leave a spin unguarded: it drives
/// hundreds of generated zones and query names through `Zone::lookup`, so it is
/// far more likely than any example-based test to *find* the input that does not
/// terminate — and without a guard it finds it by hanging.
#[path = "../src/testutil.rs"]
mod testutil;

/// Per-property budget. 512 cases of zone construction and lookup take single
/// -digit seconds; two minutes is only reachable by a case that never returns.
const WATCHDOG: Duration = Duration::from_secs(120);

const ORIGIN: &str = "example.test";

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

/// A small alphabet, so that generated zones actually collide with each other:
/// wildcards, exact names and their parents keep landing on the same labels.
fn label() -> impl Strategy<Value = String> {
    prop::sample::select(vec!["a", "b", "c", "dev", "www", "apps"]).prop_map(str::to_owned)
}

/// A relative owner name: the apex, one to three labels, or a wildcard.
fn owner_name() -> impl Strategy<Value = String> {
    prop_oneof![
        1 => Just("@".to_owned()),
        4 => prop::collection::vec(label(), 1..4).prop_map(|ls| ls.join(".")),
        2 => prop::collection::vec(label(), 0..3)
            .prop_map(|ls| if ls.is_empty() { "*".to_owned() } else { format!("*.{}", ls.join(".")) }),
    ]
}

/// A record type paired with a presentation-format value that parses for it.
fn typed_value() -> impl Strategy<Value = (String, String)> {
    prop_oneof![
        (0u8..=255, 0u8..=255).prop_map(|(a, b)| ("A".to_owned(), format!("203.0.{a}.{b}"))),
        (0u16..=0xffff).prop_map(|a| ("AAAA".to_owned(), format!("2001:db8::{a:x}"))),
        prop::sample::select(vec!["hello", "v=spf1 -all", "x"])
            .prop_map(|t| ("TXT".to_owned(), format!("\"{t}\""))),
        (1u16..100).prop_map(|p| ("MX".to_owned(), format!("{p} mail.{ORIGIN}."))),
        label().prop_map(|l| ("CNAME".to_owned(), format!("{l}.{ORIGIN}."))),
    ]
}

fn record_spec() -> impl Strategy<Value = RecordSpec> {
    (owner_name(), typed_value(), prop::option::of(1u32..7200)).prop_map(
        |(name, (record_type, value), ttl)| RecordSpec {
            name,
            record_type,
            ttl,
            values: vec![value],
        },
    )
}

fn zone_config() -> impl Strategy<Value = ZoneConfig> {
    prop::collection::vec(record_spec(), 0..12).prop_map(|records| ZoneConfig {
        origin: ORIGIN.to_owned(),
        default_ttl: 300,
        builtins: false,
        soa: Some(SoaSpec {
            mname: format!("ns1.{ORIGIN}."),
            rname: format!("hostmaster.{ORIGIN}."),
            serial: 1,
            refresh: 3600,
            retry: 900,
            expire: 604_800,
            minimum: 60,
        }),
        records,
    })
}

/// A zone holding at least one wildcard, paired with a name that wildcard
/// covers **by construction**.
///
/// Generating the zone and the name independently and filtering the pair with
/// `prop_assume!` is what made `a_wildcard_covered_name_exists_for_every_type`
/// flaky: most pairs are not covered, so proptest hit its global reject limit
/// on CI (247 successes against 1024 rejects) while passing locally on a
/// luckier seed. A test that depends on the generator being lucky is not a
/// test. Building the pair means every generated case exercises the property.
///
/// The caller keeps a `prop_assume!` as a narrow safety net, because a record
/// generated into the zone can still place an exact set at the chosen name —
/// but that is rare, rather than the common case it used to be.
///
/// # AMENDED AT VEGA-032 S3 (ruling §13, AC-3.5)
///
/// Under the closest-encloser rule a name is only covered by `*.<p>` while
/// **nothing between `p` and the name exists**. `zone_config()` generates owners
/// from the same small alphabet as `parent` and `below`, so it can and does
/// declare a name in that gap — and such a name is now correctly NXDOMAIN,
/// which would make this property fail for a reason that has nothing to do with
/// what it tests.
///
/// The ruling asks for the generator to be "constrained". It is constrained **by
/// construction, not by filtering**: every spec whose node name is a strict
/// descendant of the wildcard's parent is dropped before the wildcard is
/// pushed, so the closest encloser of the chosen name is `p` by definition.
/// Adding a `prop_assume!` instead is what took this very property to 1,024
/// global rejects on CI, and doing it again for the same reason would be a
/// choice rather than an accident.
///
/// Note this narrows the ZONE, never the assertion. The property still says
/// what it said: a name a wildcard covers exists for every type.
fn covered_case() -> impl Strategy<Value = (ZoneConfig, String)> {
    (
        zone_config(),
        prop::collection::vec(label(), 0..3),
        prop::collection::vec(label(), 1..3),
        typed_value(),
    )
        .prop_map(|(mut cfg, parent, below, (record_type, value))| {
            let owner = if parent.is_empty() {
                "*".to_owned()
            } else {
                format!("*.{}", parent.join("."))
            };
            // Clear the gap between the wildcard's parent and the covered name,
            // so `p` really is the closest encloser. A strict descendant of `p`
            // would enclose more tightly and, at S3, correctly block synthesis.
            let parent_name = lower(&qualify(if parent.is_empty() { "@" } else { &owner[2..] }));
            cfg.records.retain(|s| {
                let node = lower(&qualify(s.name.trim()));
                !(parent_name.zone_of(&node) && label_count(&parent_name) < label_count(&node))
            });
            cfg.records.push(RecordSpec {
                name: owner,
                record_type,
                ttl: None,
                values: vec![value],
            });
            let suffix = if parent.is_empty() {
                String::new()
            } else {
                format!("{}.", parent.join("."))
            };
            let name = format!("{}.{suffix}{ORIGIN}.", below.join("."));
            (cfg, name)
        })
}

/// A query name: sometimes in the zone, sometimes deliberately outside it.
fn query_name() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => prop::collection::vec(label(), 0..4)
            .prop_map(|ls| if ls.is_empty() { format!("{ORIGIN}.") } else { format!("{}.{ORIGIN}.", ls.join(".")) }),
        1 => prop::collection::vec(label(), 1..3)
            .prop_map(|ls| format!("{}.example.invalid.", ls.join("."))),
        1 => Just(".".to_owned()),
        1 => Just(format!("{ORIGIN}.{ORIGIN}.")),
    ]
}

fn query_type() -> impl Strategy<Value = RecordType> {
    prop::sample::select(vec![
        RecordType::A,
        RecordType::AAAA,
        RecordType::TXT,
        RecordType::MX,
        RecordType::CNAME,
        RecordType::NS,
        RecordType::SRV,
        RecordType::ANY,
        RecordType::SOA,
    ])
}

fn lower(name: &str) -> LowerName {
    let mut n: Name = name.parse().expect("generated name parses");
    n.set_fqdn(true);
    LowerName::from(n)
}

/// The absolute form of a relative owner name from a `RecordSpec`.
fn qualify(relative: &str) -> String {
    if relative == "@" || relative.is_empty() {
        format!("{ORIGIN}.")
    } else {
        format!("{relative}.{ORIGIN}.")
    }
}

fn is_wildcard(name: &str) -> bool {
    name == "*" || name.starts_with("*.")
}

/// Raw label count, asterisks included — the index space `Name::trim_to` uses,
/// and deliberately not `num_labels()`. See
/// `hickorys_num_labels_discounts_a_leading_asterisk_but_trim_to_does_not`.
fn label_count(name: &LowerName) -> usize {
    name.iter().len()
}

// ---------------------------------------------------------------------------
// RETIRED AT VEGA-032 S3, with the oracle they served.
//
// `has_a_source_of_synthesis`, `is_an_empty_non_terminal` and
// `is_covered_by_a_wildcard_empty_non_terminal` existed for exactly one purpose:
// to decide which of `the_wildcard_walk_agrees_with_a_naive_base_name_walk`'s
// disagreements were the permitted ones. One predicate per behaviour change —
// VEGA-083's, then two for VEGA-032 S2 — which is the whitelist growing once per
// issue, made visible as three functions.
//
// `Rfc4592Zone` permits no transitions, so there is nothing left for them to
// decide, and deleting them is part of the retirement rather than tidying that
// happened to accompany it. Their disappearance is the evidence that the
// whitelist is gone rather than merely unused: a dead predicate is an invitation
// to add a fourth.
// ---------------------------------------------------------------------------

/// Every node name the config declares: the owner of each record set, with a
/// wildcard keyed at its own name (`*.dev.example.test.`, RFC 4592 §2.1.1), plus
/// the apex.
///
/// Derived from the configuration, like every other oracle in this file.
fn declared_node_names(cfg: &ZoneConfig) -> BTreeSet<LowerName> {
    let mut out = BTreeSet::new();
    out.insert(lower(&qualify("@")));
    for spec in &cfg.records {
        let name = spec.name.trim();
        out.insert(lower(&qualify(name)));
    }
    out
}

/// The deepest of the `extra` names stacked above `base` that **exists in the
/// zone**, if any, and therefore encloses everything above it.
///
/// `deeper` is built as `<stack_label>.` repeated `extra` times in front of
/// `base`, so the names it introduces are `l.<base>`, `l.l.<base>`, … up to
/// `deeper` itself.
/// If one of them is a node — declared or an empty non-terminal — then RFC 4592
/// §3.3.1 makes it, not the wildcard's parent, the closest encloser of `deeper`
/// and the wildcard correctly stops.
///
/// Returns the SHALLOWEST such name rather than the deepest, because that is the
/// one whose existence first breaks the chain, and naming it is what makes the
/// failure message point at the record responsible.
///
/// Derived from the configuration, like every other oracle in this file. Note
/// that `deeper` itself is excluded: a name that exists is answered by the exact
/// arm and is not a synthesis question at all.
fn stacked_name_that_exists(
    cfg: &ZoneConfig,
    base: &str,
    stack_label: &str,
    extra: usize,
) -> Option<String> {
    let nodes = node_names(cfg);
    (1..extra).find_map(|n| {
        let candidate = format!("{}{base}", format!("{stack_label}.").repeat(n));
        nodes.contains(&lower(&candidate)).then_some(candidate)
    })
}

/// Every name that is a **node** in the zone this config describes: the declared
/// owners — a wildcard under its own name, RFC 4592 §2.1.1 — plus the apex, plus
/// every strict ancestor of both (RFC 4592 §2.2.2).
///
/// Factored out of [`stacked_name_that_exists`] at S3 because the property that
/// calls it needs the same set for a second question, and the two answers have to
/// come from one definition: whether a name is a node decides both whether it
/// encloses what is above it and whether it can have been synthesised at all.
fn node_names(cfg: &ZoneConfig) -> BTreeSet<LowerName> {
    let mut nodes = declared_node_names(cfg);
    let origin_depth = label_count(&lower(&qualify("@")));
    let declared: Vec<LowerName> = nodes.iter().cloned().collect();
    for name in declared {
        let full = Name::from(name);
        for d in origin_depth..full.iter().len() {
            nodes.insert(LowerName::from(full.trim_to(d)));
        }
    }
    nodes
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// INVARIANT (RFC 4592 s2.2.1): a wildcard never shadows a name that
    /// exists. If the zone declares an exact record set at `name`/`type`, a
    /// query for exactly that name and type must return exactly that set —
    /// never a synthesised wildcard answer, and never a mixture.
    #[test]
    fn a_wildcard_never_shadows_an_exact_name(cfg in zone_config()) {
        let _watchdog = testutil::arm(WATCHDOG);
        let Ok(zone) = Zone::from_config(&cfg) else { return Ok(()); };

        for spec in &cfg.records {
            if is_wildcard(&spec.name) {
                continue;
            }
            let owner = qualify(&spec.name);
            let rtype: RecordType = spec.record_type.parse().expect("known type");
            let name = lower(&owner);

            let Answer::Records(records) = zone.lookup(&name, rtype) else {
                prop_assert!(
                    false,
                    "{owner} {rtype} is configured but did not resolve"
                );
                unreachable!()
            };
            prop_assert!(!records.is_empty());

            // Every returned record must be owned by the queried name, and the
            // configured value must be among them. A wildcard answer would be
            // rewritten to the query name too, so also check the value.
            for record in &records {
                prop_assert_eq!(
                    record.name.to_string().to_lowercase(),
                    owner.to_lowercase(),
                    "answer for {} carried the wrong owner name",
                    owner
                );
            }
            let wanted = RData::try_from_str(rtype, &spec.values[0]).expect("value parses");
            prop_assert!(
                records.iter().any(|r| r.data == wanted),
                "{} {} lost its configured value {:?}; got {:?}",
                owner,
                rtype,
                spec.values[0],
                records.iter().map(|r| r.data.to_string()).collect::<Vec<_>>()
            );
        }
    }

    /// INVARIANT: we are authoritative for one zone, so every owner name we put
    /// in an answer must be inside it. Handing back a record for a name outside
    /// the zone is how an authoritative server poisons a resolver's cache.
    #[test]
    fn no_answer_contains_a_name_outside_the_zone(
        cfg in zone_config(),
        name in query_name(),
        qtype in query_type(),
    ) {
        let _watchdog = testutil::arm(WATCHDOG);
        let Ok(zone) = Zone::from_config(&cfg) else { return Ok(()); };
        let queried = lower(&name);

        if let Answer::Records(records) = zone.lookup(&queried, qtype) {
            for record in &records {
                let owner = LowerName::from(record.name.clone());
                prop_assert!(
                    zone.contains(&owner),
                    "answer for {} {} contained out-of-zone owner {}",
                    name,
                    qtype,
                    record.name
                );
            }
        }
    }

    /// INVARIANT: an answer's owner name is always the name that was asked for,
    /// except for the CNAME chase, which is allowed to append records for the
    /// targets it followed. Nothing else may appear.
    #[test]
    fn answers_are_owned_by_the_query_name_or_a_cname_target(
        cfg in zone_config(),
        name in query_name(),
        qtype in query_type(),
    ) {
        let _watchdog = testutil::arm(WATCHDOG);
        let Ok(zone) = Zone::from_config(&cfg) else { return Ok(()); };
        let queried = lower(&name);

        if let Answer::Records(records) = zone.lookup(&queried, qtype) {
            // Names reachable by following the CNAMEs we actually returned.
            let mut reachable = BTreeSet::new();
            reachable.insert(queried.to_string().to_lowercase());
            for record in &records {
                if let RData::CNAME(target) = &record.data {
                    reachable.insert(target.0.to_string().to_lowercase());
                }
            }

            for record in &records {
                prop_assert!(
                    reachable.contains(&record.name.to_string().to_lowercase()),
                    "answer for {} {} contained unrelated owner {} (reachable: {:?})",
                    name, qtype, record.name, reachable
                );
            }
        }
    }

    /// INVARIANT (RFC 2308): NODATA means "this name exists but has no records
    /// of that type". A NODATA answer therefore implies the name is inside the
    /// zone, and an out-of-zone name is always NXDOMAIN.
    #[test]
    fn nodata_implies_the_name_is_in_the_zone(
        cfg in zone_config(),
        name in query_name(),
        qtype in query_type(),
    ) {
        let _watchdog = testutil::arm(WATCHDOG);
        let Ok(zone) = Zone::from_config(&cfg) else { return Ok(()); };
        let queried = lower(&name);
        let answer = zone.lookup(&queried, qtype);

        if !zone.contains(&queried) {
            prop_assert_eq!(
                answer, Answer::NxDomain,
                "{} is outside the zone and must be NXDOMAIN", name
            );
        } else if answer == Answer::NoData {
            prop_assert!(zone.contains(&queried));
        }
    }

    /// INVARIANT: lookup is a pure function of the zone. Two identical queries
    /// must produce identical answers, and neither may panic. `HashMap`
    /// iteration order is randomised per process, so an ANY answer that depends
    /// on it would show up here.
    #[test]
    fn lookup_is_deterministic_and_total(
        cfg in zone_config(),
        name in query_name(),
        qtype in query_type(),
    ) {
        let _watchdog = testutil::arm(WATCHDOG);
        let Ok(zone) = Zone::from_config(&cfg) else { return Ok(()); };
        let queried = lower(&name);

        let first = zone.lookup(&queried, qtype);
        let second = zone.lookup(&queried, qtype);
        if let (Answer::Records(a), Answer::Records(b)) = (&first, &second) {
            // ANY walks a HashMap, so compare as multisets rather than
            // sequences.
            let mut a: Vec<String> = a.iter().map(|r| format!("{r:?}")).collect();
            let mut b: Vec<String> = b.iter().map(|r| format!("{r:?}")).collect();
            a.sort();
            b.sort();
            prop_assert_eq!(a, b);
        } else {
            prop_assert_eq!(&first, &second);
        }
    }

    /// INVARIANT: the TTL on the wire is the one the operator configured — the
    /// per-record TTL if there is one, otherwise the zone default. A wildcard
    /// answer is rewritten to the query name but keeps the configured TTL.
    ///
    /// Restricted to owner/type pairs the config mentions exactly once: when it
    /// mentions the same pair twice the two specs are merged into one RRset and
    /// there is no single "the" configured TTL. That merge is itself a bug —
    /// see `an_rrset_never_mixes_ttls` below.
    #[test]
    fn answers_carry_the_configured_ttl(cfg in zone_config()) {
        let _watchdog = testutil::arm(WATCHDOG);
        let Ok(zone) = Zone::from_config(&cfg) else { return Ok(()); };

        for spec in &cfg.records {
            if is_wildcard(&spec.name) {
                continue;
            }
            let duplicated = cfg
                .records
                .iter()
                .filter(|r| r.name == spec.name && r.record_type == spec.record_type)
                .count()
                > 1;
            if duplicated {
                continue;
            }

            let expected = spec.ttl.unwrap_or(cfg.default_ttl);
            let rtype: RecordType = spec.record_type.parse().expect("known type");
            let wanted = RData::try_from_str(rtype, &spec.values[0]).expect("value parses");

            if let Answer::Records(records) = zone.lookup(&lower(&qualify(&spec.name)), rtype) {
                for record in records.iter().filter(|r| r.data == wanted) {
                    prop_assert_eq!(record.ttl, expected);
                }
            }
        }
    }

    /// INVARIANT: record values that carry no whitespace round-trip through
    /// presentation format. `RData::try_from_str` reads the config and
    /// `Display` is how the tooling shows a value back to the operator, so a
    /// value that does not survive the trip is one the tool cannot re-read.
    ///
    /// TXT is excluded here and covered by its own (failing) test below.
    #[test]
    fn non_txt_record_values_round_trip_through_presentation_format(
        (ty, value) in typed_value().prop_filter("TXT handled separately", |(t, _)| t != "TXT")
    ) {
        let rtype: RecordType = ty.parse().expect("known type");
        let parsed = RData::try_from_str(rtype, &value).expect("fixture parses");
        let rendered = parsed.to_string();
        let reparsed = RData::try_from_str(rtype, &rendered)
            .unwrap_or_else(|e| panic!("{rtype} value {rendered:?} did not re-parse: {e}"));
        prop_assert_eq!(parsed, reparsed, "{} {:?} -> {:?}", rtype, value, rendered);
    }

    /// INVARIANT: `record_count` is what the `dns_zone_records` gauge reports,
    /// so it must equal the number of values the operator wrote.
    #[test]
    fn record_count_equals_the_number_of_configured_values(cfg in zone_config()) {
        let Ok(zone) = Zone::from_config(&cfg) else { return Ok(()); };
        let expected: usize = cfg.records.iter().map(|r| r.values.len()).sum();
        prop_assert_eq!(zone.record_count(), expected);
    }

}

// ---------------------------------------------------------------------------
// VEGA-065 — the wildcard parent walk, differentially.
//
// Spec: features/wildcards.feature, "The bounded walk agrees with the naive
// walk on every zone and every name".
// Ruling: .claude/backlog/decisions/VEGA-065-bounded-wildcard-walk.md, §B.
//
// VEGA-065 replaces an O(labels²) `base_name()` walk with a bounded probe over
// a `u128` bitmap of wildcard depths. The ruling's acceptance criterion is that
// the replacement is *strictly behaviour-preserving*: same `Answer`, same
// records, for every input — including the three ways today's walk violates
// RFC 4592, which are VEGA-006/009/010's to fix and not this issue's.
//
// "Behaviour-preserving" is not something example tests can establish, so the
// naive walk is transcribed below as a reference implementation and the real
// `Zone::lookup` is diffed against it over generated zones and names. A
// hand-built 22-case version of this harness is what caught the rejected
// patch's `num_labels()` bug; this one generalises it.
// ---------------------------------------------------------------------------

/// Labels that generated wildcard parents and generated query names both draw
/// from, so a random query actually lands on a random wildcard.
///
/// `*` is deliberately in the alphabet. RFC 4592 §2.1.3 removed RFC 1035
/// §4.3.3's ban on further asterisks inside a wildcard's owner name, and an
/// asterisk that is not leftmost is an ordinary literal label. Names shaped
/// like `*.dev.example.test.` and `x.*.dev.example.test.` are exactly the ones
/// `LowerName::num_labels()` miscounts, so leaving them out would make this
/// property blind to the bug it exists to catch.
fn walk_label() -> impl Strategy<Value = String> {
    prop::sample::select(vec!["a", "b", "dev", "*"]).prop_map(str::to_owned)
}

/// A record type/value pair, minus CNAME.
///
/// The CNAME chase is a different branch of `Zone::resolve` and VEGA-065 does
/// not touch it; modelling it here would put a second, unrelated
/// transcription in the reference and blur what a disagreement means.
fn walk_typed_value() -> impl Strategy<Value = (String, String)> {
    prop_oneof![
        (0u8..=255, 0u8..=255).prop_map(|(a, b)| ("A".to_owned(), format!("203.0.{a}.{b}"))),
        (0u16..=0xffff).prop_map(|a| ("AAAA".to_owned(), format!("2001:db8::{a:x}"))),
        prop::sample::select(vec!["hello", "x"])
            .prop_map(|t| ("TXT".to_owned(), format!("\"{t}\""))),
        (1u16..100).prop_map(|p| ("MX".to_owned(), format!("{p} mail.{ORIGIN}."))),
    ]
}

/// A wildcard entry whose parent lands somewhere in `[ℓ(O), ℓ(O) + 6]`.
fn walk_wildcard_spec() -> impl Strategy<Value = RecordSpec> {
    (
        prop::collection::vec(walk_label(), 0..7),
        walk_typed_value(),
        prop::option::of(1u32..7200),
    )
        .prop_map(|(labels, (record_type, value), ttl)| RecordSpec {
            name: if labels.is_empty() {
                "*".to_owned()
            } else {
                format!("*.{}", labels.join("."))
            },
            record_type,
            ttl,
            values: vec![value],
        })
}

/// An ordinary entry, so `names.contains` — the check that stops the walk from
/// running at all — is exercised alongside the wildcards.
fn walk_exact_spec() -> impl Strategy<Value = RecordSpec> {
    (
        prop::collection::vec(walk_label(), 0..4),
        walk_typed_value(),
        prop::option::of(1u32..7200),
    )
        .prop_map(|(labels, (record_type, value), ttl)| RecordSpec {
            name: if labels.is_empty() {
                "@".to_owned()
            } else {
                labels.join(".")
            },
            record_type,
            ttl,
            values: vec![value],
        })
}

fn walk_zone_config() -> impl Strategy<Value = ZoneConfig> {
    (
        prop::collection::vec(walk_wildcard_spec(), 0..5),
        prop::collection::vec(walk_exact_spec(), 0..4),
    )
        .prop_map(|(wildcards, exacts)| {
            let mut records = wildcards;
            records.extend(exacts);
            ZoneConfig {
                origin: ORIGIN.to_owned(),
                default_ttl: 300,
                builtins: false,
                soa: None,
                records,
            }
        })
}

/// A query name, in the six shapes the ruling calls out.
///
/// The deep arms are sized against RFC 1035 §2.3.4's 255 octets: under
/// `example.test.` (14 octets) a single-character label costs 2, so 120 of them
/// give a 254-octet, 122-label name — the longest that can reach `Zone::resolve`
/// in this zone.
fn walk_query_name() -> impl Strategy<Value = String> {
    prop_oneof![
        // In-zone, short, from the shared alphabet: lands on wildcards often.
        4 => prop::collection::vec(walk_label(), 0..7).prop_map(|ls| if ls.is_empty() {
            format!("{ORIGIN}.")
        } else {
            format!("{}.{ORIGIN}.", ls.join("."))
        }),
        // Leftmost label is an asterisk: the shape num_labels() undercounts.
        3 => prop::collection::vec(walk_label(), 0..6).prop_map(|ls| if ls.is_empty() {
            format!("*.{ORIGIN}.")
        } else {
            format!("*.{}.{ORIGIN}.", ls.join("."))
        }),
        // Deep, up to the octet limit.
        2 => (0usize..=120).prop_map(|n| {
            let mut s = String::with_capacity(n * 2 + 14);
            for _ in 0..n {
                s.push_str("a.");
            }
            s.push_str(ORIGIN);
            s.push('.');
            s
        }),
        // Deep, but ending on labels a wildcard parent could match.
        2 => (0usize..=100, prop::collection::vec(walk_label(), 1..4)).prop_map(|(n, tail)| {
            let mut s = String::with_capacity(n * 2 + 32);
            for _ in 0..n {
                s.push_str("a.");
            }
            s.push_str(&tail.join("."));
            s.push('.');
            s.push_str(ORIGIN);
            s.push('.');
            s
        }),
        1 => Just(format!("{ORIGIN}.")),
        1 => Just(".".to_owned()),
        1 => prop::collection::vec(walk_label(), 1..3)
            .prop_map(|ls| format!("{}.example.invalid.", ls.join("."))),
    ]
}

fn walk_query_type() -> impl Strategy<Value = RecordType> {
    prop::sample::select(vec![
        RecordType::A,
        RecordType::AAAA,
        RecordType::TXT,
        RecordType::MX,
        RecordType::NS,
    ])
}

/// A brute-force transcription of **RFC 4592 §3.3.1**, replacing VEGA-065's
/// `NaiveZone` at VEGA-032 S3.
///
/// # What was retired here, and why it had to be
///
/// `NaiveZone` transcribed the pre-VEGA-065 `base_name()` climb: walk up from
/// the query name and answer from the first wildcard found. That is the
/// **deliberately non-conformant** rule — it is VEGA-009 itself — and it was the
/// right oracle for VEGA-065, which changed the walk's cost and nothing else.
///
/// It stopped being the right oracle the moment the answers started changing,
/// and it did not fail loudly when that happened: it grew a list of permitted
/// transitions instead. One for VEGA-083 (a covered name is NODATA, not
/// NXDOMAIN), two more for VEGA-032 S2 (an empty non-terminal exists; a wildcard
/// can be one). S3 would have needed three more. A differential whose whitelist
/// grows once per issue is not a gate — it is a record of which bugs were
/// noticed, and the ruling (§5.4, AC-3.4) retires it here rather than let it
/// accumulate a fourth entry.
///
/// # What replaces it
///
/// The RFC, transcribed directly, with **zero permitted transitions**:
///
/// ```text
///   1. exact match at the name        -> those records      RFC 1034 §4.3.2 3.a
///   2. the name exists, no such type  -> NODATA             RFC 2308 §2.2
///   3. closest encloser = the deepest PROPER ancestor that exists
///   4. source of synthesis = `*.<closest encloser>`, and that name only
///   5. no source of synthesis         -> NXDOMAIN           RFC 1034 §4.3.2 3.c
///   6. source of synthesis, no such type -> NODATA          RFC 4592 §3.3.1
///   7. otherwise -> its records, owned by the QUERY name
/// ```
///
/// Step 3 enumerates ancestors one label at a time. The arena finds the same
/// name by binary search over label depth, which is correct only because
/// ancestor closure makes "a node exists at this depth" monotone; enumerating
/// instead is what makes this an independent check of that reasoning rather than
/// a second copy of it.
///
/// **It must not be updated to match a new implementation.** If the real `Zone`
/// and this disagree, the real one is wrong — and unlike its predecessor, this
/// one has no transition list to grow, because it is not a transcription of any
/// Vega commit. There is nothing here for a behaviour change to make stale.
///
/// Restricted to the non-CNAME path, like the oracle it replaces: the chase is a
/// different branch of `Zone::resolve` and modelling it here would put a second,
/// unrelated transcription in the reference and blur what a disagreement means.
/// `tests/arena_differential.rs` covers the chase, against the same rule.
struct Rfc4592Zone {
    origin: LowerName,
    exact: std::collections::HashMap<(LowerName, RecordType), Vec<Record>>,
    wildcard: std::collections::HashMap<(LowerName, RecordType), Vec<Record>>,
    /// Every name that is a node, ancestor closure included. A wildcard is a
    /// node named `*.x` (RFC 4592 §2.1.1) and appears here under that name.
    nodes: BTreeSet<LowerName>,
}

impl Rfc4592Zone {
    /// `None` when the config would not build; the real `Zone` is skipped too.
    fn build(cfg: &ZoneConfig) -> Option<Self> {
        let mut origin: Name = cfg.origin.parse().ok()?;
        origin.set_fqdn(true);
        let lower_origin = LowerName::from(origin.clone());

        let mut zone = Self {
            origin: lower_origin.clone(),
            exact: std::collections::HashMap::new(),
            wildcard: std::collections::HashMap::new(),
            nodes: BTreeSet::new(),
        };

        for spec in &cfg.records {
            let record_type: RecordType = spec.record_type.to_uppercase().parse().ok()?;
            let label = spec.name.trim();
            let is_wildcard_spec = label == "*" || label.starts_with("*.");
            let owner_label = if is_wildcard_spec {
                label
                    .strip_prefix('*')
                    .unwrap_or("")
                    .trim_start_matches('.')
            } else {
                label
            };
            let owner = if owner_label.is_empty() || owner_label == "@" {
                origin.clone()
            } else {
                Name::parse(owner_label, Some(&origin)).ok()?
            };

            let ttl = spec.ttl.unwrap_or(cfg.default_ttl);
            let mut records = Vec::with_capacity(spec.values.len());
            for value in &spec.values {
                let rdata = RData::try_from_str(record_type, value).ok()?;
                records.push(Record::from_rdata(owner.clone(), ttl, rdata));
            }

            let lower = LowerName::from(owner.clone());
            let key = (lower.clone(), record_type);
            if is_wildcard_spec {
                // The wildcard's own node name is `*.<owner>`; the records are
                // keyed at the parent, which is how the source of synthesis is
                // looked up once the closest encloser is known.
                if let Ok(star) = owner.prepend_label("*") {
                    zone.nodes.insert(LowerName::from(star));
                }
                zone.wildcard.entry(key).or_default().extend(records);
            } else {
                zone.nodes.insert(lower);
                zone.exact.entry(key).or_default().extend(records);
            }
        }

        zone.nodes.insert(lower_origin);
        zone.close_under_ancestry();
        Some(zone)
    }

    /// RFC 4592 §2.2.2: every strict ancestor of a node is a node. Computed here
    /// rather than read off the implementation, because the closest encloser is
    /// only well defined over a node set that is closed.
    fn close_under_ancestry(&mut self) {
        let floor = label_count(&self.origin);
        let declared: Vec<LowerName> = self.nodes.iter().cloned().collect();
        for name in declared {
            let full = Name::from(name);
            for d in floor..full.iter().len() {
                self.nodes.insert(LowerName::from(full.trim_to(d)));
            }
        }
    }

    /// Step 3: the deepest **proper** ancestor of `name` that exists.
    ///
    /// A wildcard's parent is a proper ancestor of every name it covers (RFC
    /// 4592 §3.3.1), which is why `*.apps` never covers `apps` itself, and why
    /// the range stops one short of the name's own depth.
    fn closest_encloser(&self, name: &LowerName) -> Option<LowerName> {
        let full = Name::from(name.clone());
        let depth = full.iter().len();
        let floor = label_count(&self.origin);
        if depth <= floor {
            return None;
        }
        (floor..depth).rev().find_map(|d| {
            let ancestor = LowerName::from(full.trim_to(d));
            self.nodes.contains(&ancestor).then_some(ancestor)
        })
    }

    fn lookup(&self, name: &LowerName, record_type: RecordType) -> Answer {
        if !self.origin.zone_of(name) {
            return Answer::NxDomain;
        }
        if let Some(records) = self.exact.get(&(name.clone(), record_type)) {
            return Answer::Records(records.clone());
        }
        // RFC 4592 §2.3: an asterisk in a QNAME gets NO SPECIAL PROCESSING. A
        // wildcard is an ordinary node named `*.x` (§2.1.1), so a query for that
        // literal name is an exact match under RFC 1034 §4.3.2 step 3.a and is
        // answered from the node itself — not synthesised, and not enclosed.
        // The records are keyed at the parent in this model, which is the only
        // reason this is a separate arm rather than part of the one above.
        if is_wildcard(&name.to_string()) {
            if let Some(records) = self.wildcard.get(&(name.base_name(), record_type)) {
                let qname = Name::from(name.clone());
                return Answer::Records(
                    records
                        .iter()
                        .map(|r| Record::from_rdata(qname.clone(), r.ttl, r.data.clone()))
                        .collect(),
                );
            }
        }
        if self.nodes.contains(name) {
            // The name exists and holds nothing of this type. RFC 2308 §2.2, and
            // NO WILDCARD MAY SYNTHESISE HERE: RFC 4592 §2.2.2 forbids synthesis
            // at a name that exists, whatever that name looks like.
            //
            // VEGA-098 is exactly this line. `["* TXT", "*.*.dev A"]` makes
            // `*.dev` an empty non-terminal, and `*.dev.example.test./TXT` must
            // be NODATA — the implementation applies the apex `* TXT` to it,
            // because a wildcard node is deliberately excluded from its
            // exact-match probe (an S1 fidelity decision that S3 is the ruling
            // authorised to remove).
            return Answer::NoData;
        }

        let Some(ce) = self.closest_encloser(name) else {
            return Answer::NxDomain;
        };
        // The source of synthesis is `*.<ce>` AND NOTHING ELSE. "If the source
        // of synthesis does not exist ... there is no wildcard match. There is
        // no search for an alternate."
        let Ok(sos) = Name::from(ce.clone()).prepend_label("*") else {
            return Answer::NxDomain;
        };
        if !self.nodes.contains(&LowerName::from(sos)) {
            return Answer::NxDomain;
        }
        match self.wildcard.get(&(ce, record_type)) {
            Some(records) => {
                let qname = Name::from(name.clone());
                Answer::Records(
                    records
                        .iter()
                        .map(|r| Record::from_rdata(qname.clone(), r.ttl, r.data.clone()))
                        .collect(),
                )
            }
            // The `*` node exists and carries no RRset of this type, so RFC 1034
            // §4.3.2 step 3(c) does not set the name error (VEGA-083).
            None => Answer::NoData,
        }
    }
}

/// Canonical form of an answer, for comparison. Records are compared as a
/// multiset of (owner, type, ttl, rdata) so `HashMap` iteration order cannot
/// make this flap.
fn canonical(answer: &Answer) -> (u8, Vec<String>) {
    match answer {
        Answer::NxDomain => (0, Vec::new()),
        Answer::NoData => (1, Vec::new()),
        Answer::Records(records) => {
            let mut rendered: Vec<String> = records
                .iter()
                .map(|r| {
                    format!(
                        "{} {} {} {}",
                        r.name.to_string().to_lowercase(),
                        r.record_type(),
                        r.ttl,
                        r.data
                    )
                })
                .collect();
            rendered.sort();
            (2, rendered)
        }
    }
}

/// The upstream fact the VEGA-065 ruling rests on, pinned so a hickory upgrade
/// cannot quietly invalidate it.
///
/// `Name::num_labels()` is documented as returning the label count *discounting
/// `*`*, while `Name::trim_to` indexes by the raw `label_ends` count. Mixing the
/// two shifts a wildcard probe one label off for every name whose leftmost label
/// is an asterisk. That is why `num_labels` is banned in `src/zone.rs` and label
/// counts come from `name.iter().len()` instead — `LabelIter` is an
/// `ExactSizeIterator`, so the raw count is a field read.
///
/// This test lives here rather than in `src/zone.rs` precisely so that
/// `grep num_labels src/zone.rs` stays empty and the ban is greppable.
#[test]
fn hickorys_num_labels_discounts_a_leading_asterisk_but_trim_to_does_not() {
    for (name, num_labels, raw) in [
        ("example.test.", 2u8, 2usize),
        ("*.example.test.", 2, 3),
        ("*.dev.example.test.", 3, 4),
        ("*.*.dev.example.test.", 4, 5),
        ("a.*.dev.example.test.", 5, 5),
    ] {
        let n = lower(name);
        assert_eq!(
            n.num_labels(),
            num_labels,
            "{name}: num_labels() changed; the VEGA-065 ruling's arithmetic must be rechecked"
        );
        assert_eq!(
            n.iter().len(),
            raw,
            "{name}: raw label count changed; the wildcard depth bitmap indexes by this"
        );
    }

    // And the index space `trim_to` uses is the raw one: the last `k` raw
    // labels, asterisks counted like any other label.
    let deep = Name::from(lower("*.*.dev.example.test."));
    assert_eq!(
        deep.trim_to(4).to_string(),
        "*.dev.example.test.",
        "trim_to indexes raw labels; a wildcard key at raw depth 4 is only \
         reachable by probing 4, never by probing num_labels() == 3"
    );
    assert_eq!(deep.trim_to(2).to_string(), "example.test.");
}

/// Scenario: A wildcard does not synthesise at a wildcard name that exists
/// features/closest-encloser.feature:193
///
/// **VEGA-098, and the acceptance test for retiring VEGA-065's oracle.**
///
/// The rule for replacing a differential reference is that the replacement must
/// not lose coverage the original had. `the_wildcard_walk_agrees_with_a_naive_
/// base_name_walk` found this case on `main` at `bd4b397` — freshly, from a seed
/// in neither regressions file, which is why CI had been green on luck — and if
/// `Rfc4592Zone` did not also catch it, S3 would ship with strictly less
/// coverage than S2 had while looking like an improvement.
///
/// So it is checked here **deterministically**, not left to a generator:
///
///   1. the replacement oracle answers NODATA for the case (green today — this
///      is a statement about the oracle, and it is what makes the claim
///      "the replacement still catches it" a fact rather than a hope);
///   2. `Zone::lookup` agrees with it (red today; this is VEGA-009 through the
///      shape S2 made reachable, and it goes green at S3).
///
/// Assertion 1 is the load-bearing one for the retirement. If someone later
/// "simplifies" `Rfc4592Zone` in a way that loses the "a name that exists stops
/// synthesis" arm, assertion 1 fails immediately instead of the property quietly
/// becoming weaker than the thing it replaced.
#[test]
fn the_replacement_oracle_catches_the_case_the_retired_one_found() {
    let _watchdog = testutil::arm(WATCHDOG);

    let cfg = ZoneConfig {
        origin: ORIGIN.to_owned(),
        default_ttl: 300,
        builtins: false,
        soa: None,
        records: vec![
            RecordSpec {
                name: "*".to_owned(),
                record_type: "TXT".to_owned(),
                ttl: None,
                values: vec!["\"hello\"".to_owned()],
            },
            RecordSpec {
                name: "*.*.dev".to_owned(),
                record_type: "A".to_owned(),
                ttl: None,
                values: vec!["203.0.113.60".to_owned()],
            },
        ],
    };

    let rfc = Rfc4592Zone::build(&cfg).expect("the VEGA-098 config builds");
    let queried = lower(&format!("*.dev.{ORIGIN}."));

    assert_eq!(
        canonical(&rfc.lookup(&queried, RecordType::TXT)),
        canonical(&Answer::NoData),
        "the replacement oracle must answer NODATA for VEGA-098's case. \
         `*.dev.{ORIGIN}.` exists because `*.*.dev` is configured beneath it \
         (RFC 4592 §2.1.1, §2.2.2), and a name that exists stops synthesis. An \
         oracle that misses this is weaker than the one it replaced, and \
         retiring the old one would then be a loss of coverage dressed up as an \
         improvement"
    );

    // The other half of the same rule, so the oracle cannot satisfy the above by
    // answering NODATA for every wildcard-shaped name: the node that carries
    // records still answers at its own literal name (RFC 4592 §2.3).
    let literal = lower(&format!("*.*.dev.{ORIGIN}."));
    assert!(
        matches!(rfc.lookup(&literal, RecordType::A), Answer::Records(r) if r.len() == 1),
        "an asterisk in a QNAME gets no special processing; the configured \
         wildcard answers a query for its own name"
    );

    // And the implementation, held to it. RED until S3.
    let zone = Zone::from_config(&cfg).expect("the VEGA-098 config builds");
    assert_eq!(
        canonical(&zone.lookup(&queried, RecordType::TXT)),
        canonical(&rfc.lookup(&queried, RecordType::TXT)),
        "VEGA-098: the apex `* TXT` is applied at `*.dev.{ORIGIN}.`, a name that \
         exists. The exact-match probe excludes wildcard nodes — an S1 fidelity \
         decision carrying the note that S2 and S3 remove it with a ruling — so \
         the lookup falls through to the wildcard arm at a name it must never \
         reach"
    );
}

/// Scenario: VEGA-065's label index space stays banned where it is dangerous
/// features/closest-encloser.feature:593
///
/// VEGA-065's ban, **restated as a rule over the whole crate** at VEGA-032 S3.
///
/// The ban itself is unchanged and its reasoning is unchanged: `Name::trim_to`
/// and `SuffixHashes` index RAW labels, `LowerName::num_labels()` is documented
/// as counting them *discounting a leading `*`*, and mixing the two shifts every
/// probe one label off for any name whose leftmost label is an asterisk — four
/// silent wrong answers on the authoritative path. What changes is the shape of
/// the guard.
///
/// # Why the shape had to change
///
/// `src/zone.rs::the_banned_label_counting_function_is_not_used_in_this_module`
/// scans **one named file**. That was right while there was one module working
/// in the raw index space, and it is a fence around a filename rather than
/// around a hazard: it says nothing at all the day the arena's depth arithmetic
/// moves, or is copied, into a second module.
///
/// So this one is written against the RULE: *any* module that works in the raw
/// label index space — one that names `trim_to(`, `label_count`, `MAX_LABELS` or
/// `SuffixHashes` — must not also name the asterisk-discounting count. A new
/// module inherits the ban by doing the thing the ban is about, without anyone
/// remembering to add it to a list.
///
/// # The non-vacuity assertion, and why S3 specifically needs it
///
/// A guard whose scope has quietly emptied passes forever, and S3 is the commit
/// most likely to empty this one: it **deletes** `wildcard_depths`, the u128
/// whose bit indices were the original reason the raw index space mattered. If
/// deleting the bitmap had also removed the last mention of `MAX_LABELS` and
/// `SuffixHashes` from the crate, this test would go green by having nothing
/// left to check — which is the failure mode that makes source-level guards
/// worth so little when they are written carelessly.
///
/// It therefore asserts that the scope is non-empty **and** that `src/zone.rs` is
/// in it. The closest-encloser search reads the suffix hash array on every
/// negative query, so if the arena ever stops being in scope, either the search
/// moved somewhere else or the hazard stopped being checked.
#[test]
fn no_module_working_in_the_raw_label_index_space_uses_the_asterisk_discounting_count() {
    /// Naming any of these means the module indexes raw labels.
    const RAW_INDEX_SPACE: &[&str] = &["trim_to(", "label_count", "MAX_LABELS", "SuffixHashes"];

    // Spliced so the needle cannot match this file, which discusses it.
    let banned = concat!("num_", "labels");

    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rust_files(&src, 0, &mut files);
    assert!(
        !files.is_empty(),
        "no Rust sources found under {}; the guard cannot bite on nothing",
        src.display()
    );

    let mut in_scope: Vec<String> = Vec::new();
    let mut offenders: Vec<String> = Vec::new();

    for path in &files {
        let source = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        // Comments explaining the ban are the point; code is not.
        let code: String = source
            .lines()
            .filter(|line| {
                let t = line.trim_start();
                !(t.starts_with("//") || t.starts_with('*'))
            })
            .collect::<Vec<_>>()
            .join("\n");

        if !RAW_INDEX_SPACE.iter().any(|idiom| code.contains(idiom)) {
            continue;
        }
        let name = path
            .strip_prefix(env!("CARGO_MANIFEST_DIR"))
            .unwrap_or(path)
            .display()
            .to_string();
        in_scope.push(name.clone());
        if code.contains(banned) {
            offenders.push(name);
        }
    }

    assert!(
        offenders.is_empty(),
        "`{banned}` is used in a module that also indexes raw labels. It counts \
         a leading asterisk differently from `trim_to` and from the suffix \
         hashes, so mixing them shifts every wildcard probe one label off for \
         any name whose leftmost label is an asterisk — four silent wrong \
         answers on the authoritative path (VEGA-065). Use a raw count. \
         Offending modules: {offenders:?}"
    );

    // NON-VACUITY. Without this the guard passes by having nothing in scope,
    // and S3 — which deletes the depth bitmap — is exactly the commit that could
    // empty it.
    assert!(
        in_scope.iter().any(|f| f.ends_with("zone.rs")),
        "src/zone.rs is no longer in scope for the raw-label-index ban: it names \
         none of {RAW_INDEX_SPACE:?}. Either the closest-encloser search moved \
         out of the zone module — in which case this guard must follow it — or \
         deleting `wildcard_depths` took the last of the raw index arithmetic \
         with it and this test now checks nothing at all. In scope: {in_scope:?}"
    );
}

/// Every `.rs` file under `dir`, depth-bounded.
///
/// The bound is here because an unbounded recursive walk over a symlinked tree
/// is a hang, and a hung test is a test nobody runs.
fn collect_rust_files(dir: &std::path::Path, depth: usize, found: &mut Vec<std::path::PathBuf>) {
    assert!(depth <= 8, "src/ is nested deeper than expected");
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("a readable directory entry").path();
        if path.is_dir() {
            collect_rust_files(&path, depth + 1, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// INVARIANT (RFC 4592 §3.3.1): for every zone and every query name,
    /// `Zone::lookup` returns exactly what a brute-force transcription of the
    /// closest-encloser rule returns — same variant, same owner names, same
    /// TTLs, same rdata.
    ///
    /// Scenario: The answer agrees with a brute-force transcription of RFC 4592
    /// 3.3.1
    /// features/closest-encloser.feature:548
    ///
    /// # THIS REPLACES `the_wildcard_walk_agrees_with_a_naive_base_name_walk`
    ///
    /// Retired at VEGA-032 S3, in the commit that makes it wrong, which is the
    /// design (ruling §5.4, AC-3.4). Retiring it silently would have been the
    /// failure mode; leaving it in place would have been worse, because its
    /// oracle *is* the defect: it walked up from the query name and answered
    /// from the first wildcard it found, which is VEGA-009 written down as a
    /// reference implementation.
    ///
    /// It survived three behaviour changes by growing a whitelist — one
    /// permitted transition for VEGA-083, two more for VEGA-032 S2 — and S3
    /// would have made that four. A differential whose exception list grows once
    /// per issue has stopped being a gate and become a record of which bugs
    /// somebody noticed.
    ///
    /// The replacement permits **zero** transitions. Every one of the four
    /// exceptions the old oracle carried is now a consequence of the rule rather
    /// than a hole in it:
    ///
    ///   * VEGA-083's `NxDomain -> NoData` for a covered name falls out of "the
    ///     `*` node exists and holds no RRset of this type";
    ///   * S2's "an empty non-terminal is NODATA" falls out of "the name exists"
    ///     over an ancestor-closed node set;
    ///   * S2's "a wildcard can be an empty non-terminal" falls out of a
    ///     wildcard being an ordinary node named `*.x`;
    ///   * S3's own change falls out of the closest encloser being the deepest
    ///     ancestor that exists.
    ///
    /// # What is NOT lost in the swap
    ///
    /// The generators are kept exactly as VEGA-065 wrote them, and they are the
    /// half that found the rejected patch: zones carry up to four wildcards at
    /// random depths *including parents that contain asterisks*, and query names
    /// run from 1 to 122 labels with an asterisk-leading arm. Those are the
    /// shapes `LowerName::num_labels()` miscounts, and a property that dropped
    /// them would be blind to the bug the ban exists to prevent — deleting the
    /// depth bitmap does not delete that hazard, because the closest-encloser
    /// search indexes the same raw label space.
    ///
    /// # Status: FAILS TODAY, and for the right reason
    ///
    /// Any generated zone with a wildcard and an ordinary name beneath it, plus
    /// a query below that name, disagrees: the implementation synthesises and
    /// the RFC does not.
    #[test]
    fn the_wildcard_answer_agrees_with_a_brute_force_rfc_4592_closest_encloser(
        cfg in walk_zone_config(),
        name in walk_query_name(),
        qtype in walk_query_type(),
    ) {
        let _watchdog = testutil::arm(WATCHDOG);
        let Ok(zone) = Zone::from_config(&cfg) else { return Ok(()); };
        let Some(rfc) = Rfc4592Zone::build(&cfg) else { return Ok(()); };
        let queried = lower(&name);

        let actual = zone.lookup(&queried, qtype);
        let expected = rfc.lookup(&queried, qtype);
        let zone_shape = cfg.records.iter()
            .map(|r| format!("{} {}", r.name, r.record_type))
            .collect::<Vec<_>>();

        prop_assert_eq!(
            canonical(&actual),
            canonical(&expected),
            "{} {} disagreed with RFC 4592 §3.3.1, transcribed by brute force. \
             The closest encloser is the deepest PROPER ancestor that exists; \
             the source of synthesis is `*.<it>` and no other name; and if that \
             does not exist there is no wildcard match and no search for an \
             alternate. There is no permitted transition here — this oracle is \
             the RFC, not a previous implementation\n  zone: {:?}\n  got:      \
             {:?}\n  expected: {:?}",
            name,
            qtype,
            zone_shape,
            actual,
            expected
        );
    }

    /// INVARIANT (VEGA-065, **amended at VEGA-032 S3**): the search's cost is a
    /// property of the zone, not of the query. Two query names that differ only
    /// in how many labels are stacked above the wildcard's parent get the same
    /// answer, modulo the owner-name rewrite — **unless one of the stacked names
    /// exists**, in which case that name is the closest encloser and the
    /// wildcard correctly stops reaching.
    ///
    /// Stated separately from the differential because it is the specific thing
    /// a `deepest = num_labels(qname) - 1` clamp gets wrong: it silently drops
    /// the probe entirely once the query is shallow enough.
    ///
    /// # The amendment, and why it is a strengthening
    ///
    /// **This property is a gap in the ruling's AC list.** §13 names AC-3.3
    /// (`the_deepest_wildcard_wins_when_several_could_match` and
    /// `wildcards_at_non_adjacent_depths_are_both_reachable` stay green) and
    /// AC-3.5 (`a_wildcard_covered_name_exists_for_every_type` needs its
    /// generator constrained), but not this one — and its old form is **false**
    /// under the closest-encloser rule. If the zone declares `z.a.b` and the
    /// wildcard is `*.b`, then `a.b` is covered and `z.a.b`'s child is not,
    /// because `z.a.b` exists and encloses it. Flagged to the architect.
    ///
    /// It is amended in both directions rather than narrowed to the cases where
    /// it still holds, because "covered names stay covered when the path is
    /// clear" alone would be satisfied by a build that never stopped reaching:
    ///
    ///   * no stacked name exists  => still covered, exactly as VEGA-065 said;
    ///   * some stacked name exists => a **name error**, unless that name's own
    ///     `*` exists.
    ///
    /// Which of the two applies is decided from the CONFIG, by
    /// `a_stacked_name_exists`, so the implementation gets no vote in it.
    #[test]
    fn adding_labels_above_a_covered_name_does_not_change_whether_it_is_covered(
        cfg in walk_zone_config(),
        tail in prop::collection::vec(walk_label(), 0..5),
        // The label that gets stacked on. Drawn from the SHARED alphabet, not
        // hard-coded: it used to be a literal "z", which no generated owner name
        // can contain, so no stacked name could ever exist in the zone and the
        // "a name in between blocks the wildcard" half of this property would be
        // unreachable — a decorative assertion that can never fail.
        stack_label in walk_label(),
        extra in 0usize..40,
        qtype in walk_query_type(),
    ) {
        let _watchdog = testutil::arm(WATCHDOG);
        let Ok(zone) = Zone::from_config(&cfg) else { return Ok(()); };

        let base = if tail.is_empty() {
            format!("{ORIGIN}.")
        } else {
            format!("{}.{ORIGIN}.", tail.join("."))
        };
        let mut deeper = String::new();
        for _ in 0..extra {
            deeper.push_str(&stack_label);
            deeper.push('.');
        }
        deeper.push_str(&base);

        let shallow = zone.lookup(&lower(&base), qtype);
        let deep = zone.lookup(&lower(&deeper), qtype);

        // A name that exists exactly, or is the apex, is answered without the
        // walk; only the synthesised case is comparable.
        prop_assume!(extra > 0);
        if let Answer::Records(records) = &shallow {
            // The shallow name was synthesised from a wildcard iff its answer is
            // rewritten to it and the name is NOT A NODE.
            //
            // "Not a node", not "no exact record set here", and the difference is
            // S3's. A wildcard's own literal name is a node (RFC 4592 §2.1.1),
            // answered by the exact-match arm under RFC 4592 §2.3 — and its
            // answer is owned by itself, so it is indistinguishable from a
            // synthesis by shape alone. Before S3 it genuinely was one, because
            // the exact probe skipped wildcard nodes; now it is not, and reading
            // it as one asks this property to hold `a.*.example.test.` covered
            // when `*.example.test.` exists and encloses it. Decided from the
            // config, so the implementation gets no vote.
            let synthesised = records
                .iter()
                .all(|r| r.name.to_string().to_lowercase() == base.to_lowercase())
                && !node_names(&cfg).contains(&lower(&base));
            if synthesised {
                // Does any of the names we stacked on exist in the zone? If one
                // does, it is the closest encloser of everything above it and
                // RFC 4592 §3.3.1 stops the wildcard there — correctly. Decided
                // from the config, never from the zone under test.
                let blocked = stacked_name_that_exists(&cfg, &base, &stack_label, extra);

                match &blocked {
                    None => prop_assert!(
                        matches!(deep, Answer::Records(_)),
                        "{} is covered and nothing exists between the wildcard's \
                         parent and {} ({} labels deeper), so it is covered too: \
                         the search is bounded by the query name instead of by \
                         the zone\n  zone: {:?}",
                        base,
                        deeper,
                        extra,
                        cfg.records.iter().map(|r| format!("{} {}", r.name, r.record_type)).collect::<Vec<_>>()
                    ),
                    Some(encloser) => prop_assert!(
                        !matches!(deep, Answer::Records(_)),
                        "{} exists, so it is the closest encloser of {} and the \
                         only source of synthesis is `*.{}` — which the zone \
                         does not hold. A synthesised answer here is a wildcard \
                         reaching into a subtree an operator carved out (RFC \
                         4592 §3.3.1, VEGA-009)\n  zone: {:?}\n  got: {:?}",
                        encloser,
                        deeper,
                        encloser,
                        cfg.records.iter().map(|r| format!("{} {}", r.name, r.record_type)).collect::<Vec<_>>(),
                        deep
                    ),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// VEGA-083 — the name-error determination, as an executable law.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// INVARIANT (RFC 1034 §4.3.2 step 3(c)): for a name with no CNAME at it and
    /// none synthesised for it, whether the answer is a name error is a function
    /// of **the name alone** and never of the QTYPE.
    ///
    /// Scenario: For a name with no CNAME, the rcode is a function of the name alone
    /// features/zone-lookup.feature:286
    ///
    /// This is the strongest single conformance statement in the suite, and it
    /// is the one VEGA-032 must not break when it throws the data model away.
    /// Step 3(c) is unusually explicit about which branch sets the error:
    ///
    /// > If the "*" label does not exist, check whether the name we are looking
    /// > for is the original QNAME … set an authoritative name error in the
    /// > response and exit. … If the "*" label does exist, match RRs at that
    /// > node against QTYPE. If any match, copy them into the answer section …
    /// > Go to step 6.
    ///
    /// The error is set only when the node does not exist. Nothing in that
    /// branch mentions QTYPE, and step 6 is an exit with an empty answer section
    /// and no error. So a server in which QTYPE reaches the rcode — as Vega's
    /// did for AAAA and again, through entirely different code, for ANY — is
    /// wrong by construction rather than by accident, and the two halves cannot
    /// be fixed independently.
    ///
    /// SCOPE. CNAME-free only, by RFC 1034 §3.6.2: chasing an alias legitimately
    /// lets the *target's* status reach the rcode, so a name with a CNAME at it
    /// can answer differently for different types without any of it being a
    /// defect. The scope is taken through `Zone::lookup(_, CNAME)`, which is
    /// wildcard-aware, so it excludes a CNAME synthesised at a covered name as
    /// well as one written there.
    ///
    /// ANY is in the list on purpose. RFC 8482 §4.1/§4.2 change what goes in the
    /// answer section and license no rcode change, so an implementation in which
    /// the existence determination for ANY is *different code* from the one for
    /// AAAA cannot satisfy this property except by coincidence.
    #[test]
    fn the_rcode_of_a_cname_free_name_does_not_depend_on_the_qtype(
        cfg in zone_config(),
        name in query_name(),
    ) {
        let _watchdog = testutil::arm(WATCHDOG);
        let Ok(zone) = Zone::from_config(&cfg) else { return Ok(()); };
        let queried = lower(&name);

        prop_assume!(!matches!(zone.lookup(&queried, RecordType::CNAME), Answer::Records(_)));

        let types = [
            RecordType::A, RecordType::AAAA, RecordType::TXT, RecordType::MX,
            RecordType::SRV, RecordType::NS, RecordType::SOA, RecordType::ANY,
        ];
        let (denied, existed): (Vec<RecordType>, Vec<RecordType>) = types
            .into_iter()
            .partition(|t| matches!(zone.lookup(&queried, *t), Answer::NxDomain));

        prop_assert!(
            denied.is_empty() || existed.is_empty(),
            "{} is a name error for {:?} and exists for {:?}. RFC 1034 §4.3.2 \
             step 3(c) conditions the name error on the `*` node's existence and \
             on nothing else, so one query cannot deny a name that another \
             answers\n  zone: {:?}",
            name,
            denied,
            existed,
            cfg.records.iter().map(|r| format!("{} {}", r.name, r.record_type)).collect::<Vec<_>>()
        );
    }
}

// ---------------------------------------------------------------------------
// Properties that fail today. Each is a bug, stated as an invariant.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// INVARIANT (RFC 2181 s5.2): every record in an RRset carries the same
    /// TTL, and a server must not send one that does not.
    ///
    /// BUG: two `[[zone.records]]` entries with the same owner and type are
    /// merged by `Zone::insert_spec` (`self.exact.entry(key).or_default()
    /// .extend(records)`) while each keeps its own TTL, so the resulting RRset
    /// goes out with mixed TTLs. Nothing warns the operator, and a resolver
    /// caches whichever TTL it feels like.
    ///
    /// Minimal case found by proptest:
    ///   [[zone.records]] name="@" type="CNAME" ttl=1   values=["dev.example.test."]
    ///   [[zone.records]] name="@" type="CNAME"         values=["dev.example.test."]
    #[test]
    #[ignore = "BUG: duplicate record sets are merged into one RRset with mixed TTLs (RFC 2181 s5.2)"]
    fn an_rrset_never_mixes_ttls(
        cfg in zone_config(),
        name in query_name(),
        qtype in query_type(),
    ) {
        let _watchdog = testutil::arm(WATCHDOG);
        let Ok(zone) = Zone::from_config(&cfg) else { return Ok(()); };

        if let Answer::Records(records) = zone.lookup(&lower(&name), qtype) {
            // Group by (owner, type) — that is what an RRset is.
            let mut groups: std::collections::BTreeMap<(String, String), BTreeSet<u32>> =
                std::collections::BTreeMap::new();
            for record in &records {
                groups
                    .entry((
                        record.name.to_string().to_lowercase(),
                        record.record_type().to_string(),
                    ))
                    .or_default()
                    .insert(record.ttl);
            }
            for ((owner, ty), ttls) in groups {
                prop_assert_eq!(
                    ttls.len(), 1,
                    "the {} {} RRset went out with mixed TTLs {:?}",
                    owner, ty, ttls
                );
            }
        }
    }

    /// INVARIANT: a TXT value round-trips through presentation format.
    ///
    /// BUG: it does not, and the failure is silent and lossy.
    ///   `"v=spf1 -all"` parses to one character-string, renders as
    ///   `v=spf1 -all` with the quotes stripped, and re-parses as *two*
    ///   character-strings, which a resolver concatenates to `v=spf1-all`.
    ///   `"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"` comes back as
    ///   just `v=DMARC1` — everything after the first space is dropped.
    ///
    /// The same whitespace splitting is why `vega record add @ TXT
    /// 'v=spf1 include:_spf.google.com -all'` (no inner quotes) reports
    /// `OK created` and then serves three separate character-strings, which
    /// resolvers join into `v=spf1include:_spf.google.com-all`. Verified on the
    /// wire against a running server.
    #[test]
    #[ignore = "BUG: TXT values do not survive a presentation-format round trip; whitespace is silently lost"]
    fn txt_record_values_round_trip_through_presentation_format(
        text in prop::sample::select(vec![
            "v=spf1 -all",
            "hello world",
            "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        ])
    ) {
        let value = format!("\"{text}\"");
        let parsed = RData::try_from_str(RecordType::TXT, &value).expect("fixture parses");
        let rendered = parsed.to_string();
        let reparsed = RData::try_from_str(RecordType::TXT, &rendered)
            .unwrap_or_else(|e| panic!("TXT value {rendered:?} did not re-parse: {e}"));
        prop_assert_eq!(parsed, reparsed, "TXT {:?} -> {:?}", value, rendered);
    }

    /// INVARIANT (RFC 1034 s3.6.2, RFC 2181 s10.1): a CNAME is the only record
    /// allowed at its owner name, and there may be exactly one of it.
    ///
    /// BUG: the zone accepts a CNAME alongside other types at the same name,
    /// and accepts several CNAMEs at one name, with no validation at build time
    /// and no warning. The resulting answers are ones no resolver expects.
    #[test]
    #[ignore = "BUG: a CNAME may coexist with other types, and be duplicated, at one owner name (RFC 1034 s3.6.2)"]
    fn a_cname_is_alone_at_its_owner_name(cfg in zone_config()) {
        let mut cname_owners = BTreeSet::new();
        let mut other_owners = BTreeSet::new();
        for spec in &cfg.records {
            let owner = qualify(&spec.name).to_lowercase();
            if spec.record_type == "CNAME" {
                cname_owners.insert(owner);
            } else {
                other_owners.insert(owner);
            }
        }
        let clash: Vec<_> = cname_owners.intersection(&other_owners).collect();
        prop_assume!(!clash.is_empty());

        prop_assert!(
            Zone::from_config(&cfg).is_err(),
            "a CNAME sharing {clash:?} with another type must be rejected at build time"
        );
    }

    /// INVARIANT (RFC 4592 §2.2, RFC 2308 §2.2.1, RFC 8020 §2): if the zone
    /// synthesises an answer for a name from a wildcard, then **that name
    /// exists**, and every other query at it is NODATA — never NXDOMAIN.
    ///
    /// BUG — VEGA-083, corroborated on the wire and WIDER THAN FILED. The issue
    /// reports the asymmetry for QTYPE=ANY. It is not confined to ANY: it is
    /// every qtype the wildcard does not carry. Against a server holding
    /// `*.dev A 203.0.113.50` and `*.dev TXT "hello"`, over UDP on
    /// 127.0.0.1, hickory 0.26.1 client, one process:
    ///
    /// ```text
    ///   a.dev.example.com A     -> rcode=NOERROR  aa=1 an=1 ns=0   A 203.0.113.50
    ///   a.dev.example.com TXT   -> rcode=NOERROR  aa=1 an=1 ns=0   TXT "hello"
    ///   a.dev.example.com AAAA  -> rcode=NXDOMAIN aa=1 an=0 ns=1   SOA (minimum 60)
    ///   a.dev.example.com ANY   -> rcode=NXDOMAIN aa=1 an=0 ns=1   SOA (minimum 60)
    /// ```
    ///
    /// AAAA is the one that matters operationally. ANY is rare and increasingly
    /// refused outright (RFC 8482); AAAA is sent by every dual-stack client
    /// alongside every A. So the *ordinary* resolution of a wildcard-covered
    /// name emits an authoritative NXDOMAIN as a matter of course, and RFC 2308
    /// §5 says that answer is cached for the SOA MINIMUM — 60 s here, commonly
    /// 3600 in the wild. Under RFC 8020 a resolver may then answer NXDOMAIN for
    /// the whole subtree beneath it. The wildcard's own A record goes out of
    /// service at any resolver that happened to ask for AAAA first.
    ///
    /// Two different code paths, one root cause — a wildcard-covered name is
    /// absent from `Zone::names`:
    ///   * ANY is answered in `handler.rs` from `Zone::has_name`, which is
    ///     `self.names.contains(name)` and knows nothing about synthesis;
    ///   * every other type falls out of `Zone::resolve`'s wildcard walk with
    ///     `Resolution::NxDomain` when no wildcard of that type matches.
    ///
    /// `features/zone-lookup.feature:174` ("An ANY query does not synthesise a
    /// wildcard answer") wrote this down as intended behaviour, with the code as
    /// its justification. It was a bug, not a contract; the scenario has been
    /// inverted and split (features/zone-lookup.feature:230-286) and this test is
    /// no longer `#[ignore]`d — it is the filed regression test for VEGA-083 and
    /// it must be green when the fix lands.
    ///
    /// Scenario: A wildcard-covered name exists for every type, not only the one
    /// the wildcard carries
    /// features/zone-lookup.feature:240
    #[test]
    fn a_wildcard_covered_name_exists_for_every_type(
        (cfg, name) in covered_case(),
        qtype in query_type(),
    ) {
        let _watchdog = testutil::arm(WATCHDOG);
        let Ok(zone) = Zone::from_config(&cfg) else { return Ok(()); };
        let queried = lower(&name);

        // Only names the zone actually synthesises for are in scope: the name
        // must be answered from a wildcard for at least one type, and must not
        // have an exact record set of its own.
        let covered = [
            RecordType::A, RecordType::AAAA, RecordType::TXT,
            RecordType::MX, RecordType::CNAME, RecordType::NS,
        ]
        .into_iter()
        .any(|t| {
            matches!(zone.lookup(&queried, t), Answer::Records(records)
                if !records.is_empty()
                    && !cfg.records.iter().any(|s| {
                        !is_wildcard(&s.name)
                            && qualify(&s.name).to_lowercase() == name.to_lowercase()
                    }))
        });
        prop_assume!(covered);

        // AC-2. `Zone::has_name` is gone: a `pub` predicate meaning "is there a
        // node here" sitting next to one meaning "must this be answered NOERROR"
        // is the footgun that produced this bug, so the narrow one did not
        // survive as public API (ruling §5.5). The message is unchanged from
        // when this read `has_name`, because what it describes is unchanged.
        prop_assert!(
            zone.exists(&queried),
            "{name} is synthesised from a wildcard, so it exists (RFC 4592 §2.2); \
             `has_name` says otherwise, which is what makes QTYPE=ANY there an \
             authoritative NXDOMAIN"
        );
        prop_assert_ne!(
            zone.lookup(&queried, qtype),
            Answer::NxDomain,
            "{} at {} is NXDOMAIN even though the name has a source of synthesis. \
             RFC 2308 §2.2.1 makes this NODATA; as NXDOMAIN it is cached for the \
             SOA MINIMUM and, under RFC 8020, poisons the whole subtree",
            qtype,
            name
        );
    }
}

// ---------------------------------------------------------------------------
// Editor round-trip
// ---------------------------------------------------------------------------

/// One edit against the config file.
#[derive(Clone, Debug)]
enum Edit {
    Add {
        name: String,
        value: String,
        ttl: Option<u32>,
        replace: bool,
    },
    Remove {
        name: String,
        value: Option<String>,
    },
}

fn edit() -> impl Strategy<Value = Edit> {
    prop_oneof![
        (
            label(),
            (0u8..=8, 0u8..=8),
            prop::option::of(1u32..7200),
            any::<bool>()
        )
            .prop_map(|(name, (a, b), ttl, replace)| Edit::Add {
                name,
                value: format!("203.0.{a}.{b}"),
                ttl,
                replace,
            }),
        (label(), prop::option::of((0u8..=8, 0u8..=8))).prop_map(|(name, v)| Edit::Remove {
            name,
            value: v.map(|(a, b)| format!("203.0.{a}.{b}")),
        }),
    ]
}

const COMMENTED: &str = r#"# Top-of-file comment that must survive every edit.
[server]
udp = ["0.0.0.0:53"]   # inline comment on the listener

[zone]
origin = "example.test"
default_ttl = 300

# A comment introducing the SOA.
[zone.soa]
mname = "ns1.example.test."
rname = "hostmaster.example.test."
serial = 7

# A comment introducing the records.
[[zone.records]]
name = "keep"
type = "A"
values = ["203.0.113.1"]
"#;

const COMMENTS: [&str; 4] = [
    "# Top-of-file comment that must survive every edit.",
    "# inline comment on the listener",
    "# A comment introducing the SOA.",
    "# A comment introducing the records.",
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// INVARIANT: `ConfigEditor` is format-preserving. Any sequence of edits,
    /// saved and reopened, must leave every comment intact, keep the file
    /// parseable, and leave the records exactly where a straightforward model
    /// of the same edits says they should be.
    #[test]
    fn the_editor_preserves_comments_and_records_across_any_edit_sequence(
        edits in prop::collection::vec(edit(), 1..12)
    ) {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let path = dir.path().join("vega.toml");
        std::fs::write(&path, COMMENTED).expect("fixture written");

        // A model of the file: name -> (ttl, values in order).
        let mut model: Vec<(String, Option<u32>, Vec<String>)> =
            vec![("keep".to_owned(), None, vec!["203.0.113.1".to_owned()])];

        for e in &edits {
            let mut editor = ConfigEditor::open(&path).expect("reopen");
            match e {
                Edit::Add { name, value, ttl, replace } => {
                    let change = editor
                        .add(name, "A", std::slice::from_ref(value), *ttl, *replace)
                        .expect("a well-formed A record is always addable");

                    if let Some(entry) = model.iter_mut().find(|(n, _, _)| n == name) {
                        if *replace {
                            entry.1 = *ttl;
                            entry.2 = vec![value.clone()];
                        } else {
                            if !entry.2.contains(value) {
                                entry.2.push(value.clone());
                            }
                            if ttl.is_some() && entry.1 != *ttl {
                                entry.1 = *ttl;
                            }
                        }
                    } else {
                        model.push((name.clone(), *ttl, vec![value.clone()]));
                        prop_assert_eq!(change, Change::Created);
                    }
                }
                Edit::Remove { name, value } => {
                    let values: Vec<String> = value.clone().into_iter().collect();
                    editor.remove(name, Some("A"), &values).expect("remove");

                    if let Some(idx) = model.iter().position(|(n, _, _)| n == name) {
                        if values.is_empty() {
                            model.remove(idx);
                        } else {
                            model[idx].2.retain(|v| !values.contains(v));
                            if model[idx].2.is_empty() {
                                model.remove(idx);
                            }
                        }
                    }
                }
            }
            editor.save().expect("save");
        }

        let raw = std::fs::read_to_string(&path).expect("read back");
        for comment in COMMENTS {
            prop_assert!(
                raw.contains(comment),
                "edits {:?} lost the comment {:?}\n{}",
                edits, comment, raw
            );
        }

        let reopened = ConfigEditor::open(&path).expect("the saved file must still parse");
        prop_assert_eq!(reopened.origin(), Some("example.test"));
        prop_assert_eq!(reopened.serial(), Some(7));

        let actual: Vec<(String, Option<u32>, Vec<String>)> = reopened
            .records()
            .into_iter()
            .map(|r| (r.name, r.ttl, r.values))
            .collect();
        prop_assert_eq!(&actual, &model, "edits {:?}\n{}", edits, raw);

        // And the whole thing must still build a servable zone.
        let cfg = ZoneConfig {
            origin: "example.test".to_owned(),
            default_ttl: 300,
            builtins: false,
            soa: None,
            records: reopened
                .records()
                .into_iter()
                .map(|r| RecordSpec {
                    name: r.name,
                    record_type: r.record_type,
                    ttl: r.ttl,
                    values: r.values,
                })
                .collect(),
        };
        prop_assert!(Zone::from_config(&cfg).is_ok(), "{}", raw);
    }
}

// ---------------------------------------------------------------------------
// VEGA-032 S2 — empty non-terminals (closes VEGA-006)
//
// Spec: features/empty-non-terminals.feature
//
// CASES ARE CONSTRUCTED, NOT FILTERED. The deep owner name is generated first
// and the queried ancestor is DERIVED from it by dropping labels, so every case
// is a real empty non-terminal. Generating a zone and a name independently and
// discarding the pairs that do not interact is what took
// `a_wildcard_covered_name_exists_for_every_type` to 247 successes and 1,024
// global rejects on CI while it passed locally on a luckier seed — and empty
// non-terminals are rarer than wildcard-covered names, so the same mistake here
// would bite harder. There is no `prop_assume!` below.
// ---------------------------------------------------------------------------

/// An owner name deep enough to have at least one strict ancestor inside the
/// zone, wildcards included — `*.a.b` implies `a.b` and `b` exactly as `x.a.b`
/// does, because a wildcard is a node named `*.a.b` (RFC 4592 §2.1.1).
fn deep_owner_name() -> impl Strategy<Value = String> {
    prop_oneof![
        4 => prop::collection::vec(label(), 2..5).prop_map(|ls| ls.join(".")),
        2 => prop::collection::vec(label(), 1..4)
            .prop_map(|ls| format!("*.{}", ls.join("."))),
        1 => prop::collection::vec(label(), 1..3)
            .prop_map(|ls| format!("{}.*.{}", ls[0], ls.join("."))),
    ]
}

/// A zone whose every record set sits at a name with ancestors, plus the two
/// indices that pick which owner and which of its ancestors to query.
fn ancestor_case() -> impl Strategy<Value = (ZoneConfig, usize, usize)> {
    (
        prop::collection::vec(
            (
                deep_owner_name(),
                typed_value(),
                prop::option::of(1u32..7200),
            ),
            1..5,
        ),
        0usize..64,
        0usize..64,
    )
        .prop_map(|(owners, which, depth)| {
            let records = owners
                .into_iter()
                .map(|(name, (record_type, value), ttl)| RecordSpec {
                    name,
                    record_type,
                    ttl,
                    values: vec![value],
                })
                .collect();
            (
                ZoneConfig {
                    origin: ORIGIN.to_owned(),
                    default_ttl: 300,
                    builtins: false,
                    soa: None,
                    records,
                },
                which,
                depth,
            )
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// INVARIANT (RFC 4592 §2.2.2, RFC 8020 §2): no strict ancestor of a
    /// configured owner name is ever a name error.
    ///
    /// Scenario: No strict ancestor of any configured owner is ever NXDOMAIN
    /// features/empty-non-terminals.feature:366
    ///
    /// This is VEGA-006 stated as a property rather than as the four example
    /// zones anyone would think to write. The blocker is not that one rcode is
    /// wrong: it is that RFC 8020 §2 lets a resolver turn one wrong NXDOMAIN
    /// into a denial of every name beneath it for the SOA MINIMUM, so the
    /// records that DO exist go out of service. The property therefore asserts
    /// the negative for every type, including the ones no wildcard in the zone
    /// carries, because a dual-stack client asking AAAA is enough to trigger it.
    #[test]
    fn no_strict_ancestor_of_a_configured_owner_is_ever_nxdomain(
        (cfg, which, depth) in ancestor_case(),
        qtype in query_type(),
    ) {
        let _watchdog = testutil::arm(WATCHDOG);
        let Ok(zone) = Zone::from_config(&cfg) else { return Ok(()); };

        let owners: Vec<LowerName> = declared_node_names(&cfg).into_iter().collect();
        let owner = owners[which % owners.len()].clone();
        let full = Name::from(owner.clone());
        let origin_depth = label_count(&lower(&qualify("@")));
        let labels = full.iter().len();

        // Every case is a real ancestor: the owner came first and the depth is
        // taken modulo the range that exists for it. When the owner is the apex
        // the range is empty and the apex itself is the case — which is also a
        // name that must never be NXDOMAIN.
        let span = labels.saturating_sub(origin_depth);
        let d = if span == 0 { origin_depth } else { origin_depth + depth % span };
        let ancestor = LowerName::from(full.trim_to(d));

        let answer = zone.lookup(&ancestor, qtype);
        prop_assert!(
            !matches!(answer, Answer::NxDomain),
            "{} {} is NXDOMAIN, but {} is configured beneath it so it exists \
             (RFC 4592 §2.2.2). Under RFC 8020 §2 a resolver may cache that \
             denial and apply it to the whole subtree, taking the configured \
             record out of service for the SOA MINIMUM\n  zone: {:?}",
            ancestor,
            qtype,
            owner,
            cfg.records.iter().map(|r| format!("{} {}", r.name, r.record_type)).collect::<Vec<_>>()
        );
        prop_assert!(
            zone.exists(&ancestor),
            "Zone::exists says {} does not exist, while {} is configured \
             beneath it. That predicate is the RFC 1034 §4.3.2 step 3(c) \
             name-error determination and the one the DNSSEC closest-encloser \
             proof will read\n  zone: {:?}",
            ancestor,
            owner,
            cfg.records.iter().map(|r| format!("{} {}", r.name, r.record_type)).collect::<Vec<_>>()
        );
    }

    /// INVARIANT (AC-2.4): empty non-terminals are nodes, not records.
    ///
    /// Scenario: An empty non-terminal is not counted as a record
    /// features/empty-non-terminals.feature:195
    ///
    /// `record_count` is the `dns_zone_records` gauge. Materialising ancestors
    /// is the one change in this sequence that could plausibly move it without
    /// any config change at all, and an operator whose alert fires on a gauge
    /// that moved for no reason stops trusting the gauge.
    #[test]
    fn materialising_ancestors_does_not_move_the_record_count(
        (cfg, _, _) in ancestor_case(),
    ) {
        let _watchdog = testutil::arm(WATCHDOG);
        let Ok(zone) = Zone::from_config(&cfg) else { return Ok(()); };

        let configured: usize = cfg.records.iter().map(|r| r.values.len()).sum();
        prop_assert_eq!(
            zone.record_count(),
            configured,
            "the zone counts {} records for {} configured values; an empty \
             non-terminal is a node with no RRsets and contributes nothing to \
             this gauge\n  zone: {:?}",
            zone.record_count(),
            configured,
            cfg.records.iter().map(|r| format!("{} {}", r.name, r.record_type)).collect::<Vec<_>>()
        );
    }
}
