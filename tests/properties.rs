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

/// Does a *source of synthesis* (RFC 4592 §3.3.1) exist for `name` in `cfg`?
///
/// Derived from the configuration, never from the `Zone` under test: this is the
/// oracle that decides which of the differential's disagreements are the one
/// permitted transition, so an implementation is not allowed a vote in it.
///
/// A source of synthesis for `name` is `*.<encloser>` for some proper ancestor
/// `<encloser>` of `name`. Vega stores such an entry under the encloser itself,
/// so the test is: the wildcard's parent is an ancestor of `name`, and a
/// *proper* one — RFC 4592 §3.3.1 makes a wildcard's parent a proper ancestor of
/// every name it covers, which is why `*.apps` never covers `apps` itself.
fn has_a_source_of_synthesis(cfg: &ZoneConfig, name: &LowerName) -> bool {
    cfg.records
        .iter()
        .filter(|spec| is_wildcard(&spec.name))
        .any(|spec| {
            let encloser = spec
                .name
                .trim()
                .strip_prefix('*')
                .unwrap_or("")
                .trim_start_matches('.');
            let parent = lower(&qualify(encloser));
            parent.zone_of(name) && label_count(&parent) < label_count(name)
        })
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

/// A transcription of `Zone`'s build and lookup as they stand *before*
/// VEGA-065, restricted to the non-CNAME, non-ANY path.
///
/// This is the "before" side of the differential. It must not be updated to
/// match a new implementation: the moment it is, the property stops testing
/// anything. If the real `Zone` and this disagree, one of them is wrong and the
/// ruling says it is the real one.
struct NaiveZone {
    origin: LowerName,
    exact: std::collections::HashMap<(LowerName, RecordType), Vec<Record>>,
    wildcard: std::collections::HashMap<(LowerName, RecordType), Vec<Record>>,
    names: std::collections::HashSet<LowerName>,
}

impl NaiveZone {
    /// `None` when the config would not build; the real `Zone` is skipped too.
    fn build(cfg: &ZoneConfig) -> Option<Self> {
        let mut origin: Name = cfg.origin.parse().ok()?;
        origin.set_fqdn(true);
        let lower_origin = LowerName::from(origin.clone());

        let mut zone = Self {
            origin: lower_origin.clone(),
            exact: std::collections::HashMap::new(),
            wildcard: std::collections::HashMap::new(),
            names: std::collections::HashSet::new(),
        };

        for spec in &cfg.records {
            let record_type: RecordType = spec.record_type.to_uppercase().parse().ok()?;
            let label = spec.name.trim();
            let is_wildcard = label == "*" || label.starts_with("*.");
            let owner_label = if is_wildcard {
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

            let lower = LowerName::from(owner);
            let key = (lower.clone(), record_type);
            if is_wildcard {
                zone.wildcard.entry(key).or_default().extend(records);
            } else {
                zone.names.insert(lower);
                zone.exact.entry(key).or_default().extend(records);
            }
        }

        zone.names.insert(lower_origin);
        Some(zone)
    }

    fn lookup(&self, name: &LowerName, record_type: RecordType) -> Answer {
        if !self.origin.zone_of(name) {
            return Answer::NxDomain;
        }
        if let Some(records) = self.exact.get(&(name.clone(), record_type)) {
            return Answer::Records(records.clone());
        }
        if self.names.contains(name) {
            return Answer::NoData;
        }
        if !self.wildcard.is_empty() {
            // Verbatim src/zone.rs:294-312 as of the VEGA-065 ruling.
            let mut parent = name.base_name();
            loop {
                if let Some(records) = self.wildcard.get(&(parent.clone(), record_type)) {
                    let qname = Name::from(name.clone());
                    return Answer::Records(
                        records
                            .iter()
                            .map(|r| Record::from_rdata(qname.clone(), r.ttl, r.data.clone()))
                            .collect(),
                    );
                }
                if parent == self.origin || parent.is_root() {
                    break;
                }
                parent = parent.base_name();
            }
        }
        Answer::NxDomain
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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// INVARIANT (VEGA-065): bounding the wildcard parent walk changes its cost,
    /// never its answer. For every zone and every query name, `Zone::lookup`
    /// must return the same `Answer` — same variant, same owner names, same
    /// TTLs, same rdata — as a naive `base_name()` walk over the same zone.
    ///
    /// Scenario: The bounded walk agrees with the naive walk on every zone and
    /// every name
    /// features/wildcards.feature:477
    ///
    /// This is the property that would have rejected the proposed patch: it
    /// derived probe depths from `LowerName::num_labels()`, which discounts a
    /// leading asterisk, while probing with `Name::trim_to`, which does not, so
    /// it answered NXDOMAIN for four shapes the naive walk answers. The
    /// generators put asterisks in both the zone and the query on purpose.
    ///
    /// VEGA-083 (AC-8) — MONOTONICITY, PROVED RATHER THAN ASSERTED. That issue
    /// is the first change to this walk that is *not* behaviour-preserving: a
    /// name with a source of synthesis but no RRset of the queried type moves
    /// from NXDOMAIN to NODATA (RFC 1034 §4.3.2 step 3(c), RFC 2308 §2.2). The
    /// naive reference is still the pre-VEGA-065 walk and must never be updated;
    /// instead the oracle permits **exactly one** transition and nothing else:
    ///
    ///   * `NxDomain` -> `NoData`, and only where a source of synthesis exists
    ///     for the queried name, decided from the config by
    ///     `has_a_source_of_synthesis` rather than by the code under test;
    ///   * every other difference fails, including any change to a `Found`
    ///     answer's owner name, TTL or rdata, and including a `NoData` that
    ///     appears where nothing covers the name — which is the depths-alone
    ///     shortcut (AC-5) caught mechanically, over generated zones, rather
    ///     than by the handful of names an example test can name.
    ///
    /// The transition is also *required* where it applies, so this direction of
    /// the property is the fix itself and not merely permission for it. That is
    /// what lets a reviewer trust the diff without re-deriving §6.2 by hand.
    #[test]
    fn the_wildcard_walk_agrees_with_a_naive_base_name_walk(
        cfg in walk_zone_config(),
        name in walk_query_name(),
        qtype in walk_query_type(),
    ) {
        let _watchdog = testutil::arm(WATCHDOG);
        let Ok(zone) = Zone::from_config(&cfg) else { return Ok(()); };
        let Some(naive) = NaiveZone::build(&cfg) else { return Ok(()); };
        let queried = lower(&name);

        let actual = zone.lookup(&queried, qtype);
        let expected = naive.lookup(&queried, qtype);
        let zone_shape = cfg.records.iter()
            .map(|r| format!("{} {}", r.name, r.record_type))
            .collect::<Vec<_>>();

        if matches!(expected, Answer::NxDomain) && has_a_source_of_synthesis(&cfg, &queried) {
            // The one permitted transition, and here it is mandatory.
            prop_assert_eq!(
                canonical(&actual),
                canonical(&Answer::NoData),
                "{} {} has a source of synthesis, so RFC 1034 §4.3.2 step 3(c) \
                 forbids the name error: the answer must be NODATA\n  zone: {:?}\n  got: {:?}",
                name,
                qtype,
                zone_shape,
                actual
            );
        } else {
            prop_assert_eq!(
                canonical(&actual),
                canonical(&expected),
                "{} {} disagreed with the naive walk, and not by the one \
                 transition VEGA-083 permits (NXDOMAIN -> NODATA for a name a \
                 wildcard covers)\n  zone: {:?}\n  got:      {:?}\n  expected: {:?}",
                name,
                qtype,
                zone_shape,
                actual,
                expected
            );
        }
    }

    /// INVARIANT (VEGA-065): the walk's cost is a property of the zone, not of
    /// the query. Two query names that differ only in how many labels are
    /// stacked above the wildcard's parent must get the same answer, modulo the
    /// owner-name rewrite — so no bound on the walk may be derived from the
    /// query name's depth.
    ///
    /// Stated separately from the differential because it is the specific thing
    /// a `deepest = num_labels(qname) - 1` clamp gets wrong: it silently drops
    /// the probe entirely once the query is shallow enough.
    #[test]
    fn adding_labels_above_a_covered_name_does_not_change_whether_it_is_covered(
        cfg in walk_zone_config(),
        tail in prop::collection::vec(walk_label(), 0..5),
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
            deeper.push_str("z.");
        }
        deeper.push_str(&base);

        let shallow = zone.lookup(&lower(&base), qtype);
        let deep = zone.lookup(&lower(&deeper), qtype);

        // A name that exists exactly, or is the apex, is answered without the
        // walk; only the synthesised case is comparable.
        prop_assume!(extra > 0);
        if let Answer::Records(records) = &shallow {
            // The shallow name was synthesised from a wildcard iff its answer
            // is rewritten to it and the zone holds no exact set there.
            let synthesised = records
                .iter()
                .all(|r| r.name.to_string().to_lowercase() == base.to_lowercase())
                && !cfg.records.iter().any(|s| {
                    !is_wildcard(&s.name) && qualify(&s.name).to_lowercase() == base.to_lowercase()
                });
            if synthesised {
                prop_assert!(
                    matches!(deep, Answer::Records(_)),
                    "{} is covered but {} ({} labels deeper) is not: the walk is \
                     bounded by the query name instead of by the zone\n  zone: {:?}",
                    base,
                    deeper,
                    extra,
                    cfg.records.iter().map(|r| format!("{} {}", r.name, r.record_type)).collect::<Vec<_>>()
                );
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
