//! VEGA-032 **S1** — the node arena, differentially.
//!
//! Spec: `features/zone-data-model.feature`, section "S1 — THE ARENA,
//! BEHAVIOUR-PRESERVING".
//! Ruling: `.claude/backlog/decisions/VEGA-032-zone-data-model.md` §10.2, §13 AC-1.1.
//!
//! # The only claim S1 makes
//!
//! S1 replaces `exact`, `names`, `wildcard`, `wildcard_depths` and
//! `wildcard_parents` with three flat arrays and a hash index. It fixes nothing:
//! no empty non-terminals (S2), no closest encloser (S3), no delegation (S4), no
//! mandatory SOA (S5). Its acceptance criterion is a **negative** — *no input
//! produces a different answer* — and a negative is not something a reviewer can
//! establish by reading seven hundred lines of arena construction.
//!
//! So today's implementation is transcribed here, **now, while it is still the
//! thing being served**, and every generated zone and query goes through both.
//! Zero permitted transitions: same `Answer` variant, same records, same owner
//! names, same TTLs, same rdata, **in the same order**, plus the same
//! `Zone::exists`, the same `record_count` and the same build outcome.
//!
//! # This file passes today, and that is the point
//!
//! A behaviour-preservation gate that failed today would be a gate on something
//! other than behaviour preservation. What this file is for is the moment it
//! goes **red**, which is the moment S1 changes an answer. Its discrimination
//! was demonstrated by hand-applying mutants to the current `Zone` before it was
//! handed over; see the pass notes on VEGA-032.
//!
//! # The oracle must never be updated
//!
//! [`FrozenZone`] is a transcription of `src/zone.rs` as of `ebe1fbf`. If it and
//! the real `Zone` disagree, **the real one is wrong** — that is the whole
//! contract of S1. Editing this transcription to make a failure go away deletes
//! the only mechanised check on the largest diff in the sequence. It is retired
//! only when a ruling says a behaviour changes, and then in that ruling's own
//! commit, the way VEGA-065's oracle is retired at S3.
//!
//! # Cases are constructed, never filtered
//!
//! Every query name is derived from the zone that was just generated — one of
//! its owners, one of its wildcard parents, that parent with labels stacked on,
//! an ancestor of an owner, a CNAME target. Generating a zone and a name
//! independently and throwing away the pairs that do not interact is what took
//! `a_wildcard_covered_name_exists_for_every_type` to 1,024 global rejects on CI
//! while it passed locally on a luckier seed. There is not one `prop_assume!` in
//! this file, on purpose.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use hickory_proto::rr::{LowerName, Name, RData, Record, RecordType};
use proptest::prelude::*;
use vega::{
    config::{RecordSpec, SoaSpec, ZoneConfig},
    rdata,
    zone::{Answer, Zone},
};

/// The process watchdog, shared by path rather than copied.
#[path = "../src/testutil.rs"]
mod testutil;

/// Per-property budget. A few hundred zone builds and lookups are seconds; two
/// minutes is only reachable by a case that never returns — which is exactly
/// what a bounded-loop mistake in the arena build or the depth walk looks like.
const WATCHDOG: Duration = Duration::from_secs(120);

const ORIGIN: &str = "example.test";

/// Inherited verbatim from `src/zone.rs`. RFC 1034 sets no limit; this stops a
/// misconfigured loop from spinning.
const MAX_CNAME_DEPTH: usize = 8;

/// Inherited verbatim from `src/zone.rs`: RFC 1035 §2.3.4's 255 octets and
/// §3.1's `2n + 1 <= 255`.
const MAX_LABELS: usize = 127;

// ===========================================================================
// The oracle: `src/zone.rs` as of ebe1fbf, transcribed. DO NOT UPDATE.
// ===========================================================================

/// A transcription of `Zone`'s build and lookup as they stand **before** S1.
///
/// Covers every branch, unlike VEGA-065's older oracle in `tests/properties.rs`
/// which deliberately excludes CNAME and ANY: that issue did not touch them, and
/// S1 touches all of them.
struct FrozenZone {
    origin: Name,
    lower_origin: LowerName,
    soa: Option<Record>,
    exact: HashMap<(LowerName, RecordType), Vec<Record>>,
    wildcard: HashMap<(LowerName, RecordType), Vec<Record>>,
    wildcard_depths: u128,
    wildcard_parents: HashSet<LowerName>,
    names: HashSet<LowerName>,
    record_count: usize,
}

/// Three-way result, mirroring the private `Resolution`.
#[derive(Copy, Clone, PartialEq, Eq)]
enum Resolution {
    Found,
    NoData,
    NxDomain,
}

fn label_count(name: &LowerName) -> usize {
    name.iter().len()
}

impl FrozenZone {
    /// `Err` where `Zone::from_config` returns `Err`. The reasons are
    /// transcribed, the wording is not: S1 may reword an error, but it may not
    /// change which configs load.
    fn build(cfg: &ZoneConfig) -> Result<Self, ()> {
        let mut origin: Name = cfg.origin.parse().map_err(|_| ())?;
        origin.set_fqdn(true);
        let lower_origin = LowerName::from(origin.clone());

        let mut zone = Self {
            origin: origin.clone(),
            lower_origin: lower_origin.clone(),
            soa: None,
            exact: HashMap::new(),
            wildcard: HashMap::new(),
            wildcard_depths: 0,
            wildcard_parents: HashSet::new(),
            names: HashSet::new(),
            record_count: 0,
        };

        if let Some(spec) = &cfg.soa {
            let mut mname: Name = spec.mname.parse().map_err(|_| ())?;
            mname.set_fqdn(true);
            let mut rname: Name = spec.rname.parse().map_err(|_| ())?;
            rname.set_fqdn(true);
            zone.soa = Some(Record::from_rdata(
                origin.clone(),
                spec.minimum,
                RData::SOA(hickory_proto::rr::rdata::SOA::new(
                    mname,
                    rname,
                    spec.serial,
                    spec.refresh,
                    spec.retry,
                    spec.expire,
                    spec.minimum,
                )),
            ));
        }

        for spec in &cfg.records {
            zone.insert_spec(spec, cfg.default_ttl)?;
        }

        if zone.soa.is_none() {
            let key = (lower_origin.clone(), RecordType::SOA);
            zone.soa = zone.exact.get(&key).and_then(|rs| rs.first()).cloned();
        }

        zone.names.insert(lower_origin);
        Ok(zone)
    }

    fn insert_spec(&mut self, spec: &RecordSpec, default_ttl: u32) -> Result<(), ()> {
        let record_type: RecordType = spec.record_type.to_uppercase().parse().or(Err(()))?;

        if spec.values.is_empty() {
            return Err(());
        }

        let ttl = spec.ttl.unwrap_or(default_ttl);
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
        let owner = self.qualify(owner_label)?;

        let mut records = Vec::with_capacity(spec.values.len());
        for value in &spec.values {
            // Through the same gate the real build uses, so a value that fails
            // one fails the other.
            let rdata = rdata::parse_value(record_type, &spec.name, value).map_err(|_| ())?;
            records.push(Record::from_rdata(owner.clone(), ttl, rdata));
        }

        self.record_count += records.len();
        let lower = LowerName::from(owner);
        let key = (lower.clone(), record_type);

        if is_wildcard {
            let depth = label_count(&lower);
            if depth <= MAX_LABELS {
                self.wildcard_depths |= 1u128 << depth;
                self.wildcard_parents.insert(lower.clone());
            }
            self.wildcard.entry(key).or_default().extend(records);
        } else {
            self.names.insert(lower);
            self.exact.entry(key).or_default().extend(records);
        }
        Ok(())
    }

    fn qualify(&self, label: &str) -> Result<Name, ()> {
        let label = label.trim();
        if label.is_empty() || label == "@" {
            return Ok(self.origin.clone());
        }
        if label.ends_with('.') {
            let mut name: Name = label.parse().map_err(|_| ())?;
            name.set_fqdn(true);
            if !self.lower_origin.zone_of(&LowerName::from(name.clone())) {
                return Err(());
            }
            return Ok(name);
        }
        Name::parse(label, Some(&self.origin)).map_err(|_| ())
    }

    fn contains(&self, name: &LowerName) -> bool {
        self.lower_origin.zone_of(name)
    }

    fn exists(&self, name: &LowerName) -> bool {
        self.names.contains(name) || self.wildcard_probe(name, RecordType::ANY).1
    }

    fn lookup(&self, name: &LowerName, record_type: RecordType) -> Answer {
        let mut out = Vec::new();
        match self.resolve(name, record_type, 0, &mut out) {
            Resolution::Found => Answer::Records(out),
            Resolution::NoData => Answer::NoData,
            Resolution::NxDomain => Answer::NxDomain,
        }
    }

    fn resolve(
        &self,
        name: &LowerName,
        record_type: RecordType,
        depth: usize,
        out: &mut Vec<Record>,
    ) -> Resolution {
        if !self.contains(name) {
            return Resolution::NxDomain;
        }

        if record_type.is_any() {
            return if self.exists(name) {
                Resolution::NoData
            } else {
                Resolution::NxDomain
            };
        }

        if let Some(records) = self.exact.get(&(name.clone(), record_type)) {
            out.extend(records.iter().cloned());
            return Resolution::Found;
        }

        if record_type != RecordType::CNAME {
            if let Some(cnames) = self.exact.get(&(name.clone(), RecordType::CNAME)) {
                out.extend(cnames.iter().cloned());
                if depth >= MAX_CNAME_DEPTH {
                    return Resolution::Found;
                }
                if let Some(RData::CNAME(target)) = cnames.first().map(|r| &r.data) {
                    let target = LowerName::from(target.0.clone());
                    if self.contains(&target) {
                        let _ = self.resolve(&target, record_type, depth + 1, out);
                    }
                }
                return Resolution::Found;
            }
        }

        if self.names.contains(name) {
            return Resolution::NoData;
        }

        let (records, covered) = self.wildcard_probe(name, record_type);
        if let Some(records) = records {
            let qname = Name::from(name.clone());
            out.extend(
                records
                    .iter()
                    .map(|r| Record::from_rdata(qname.clone(), r.ttl, r.data.clone())),
            );
            return Resolution::Found;
        }

        if covered {
            Resolution::NoData
        } else {
            Resolution::NxDomain
        }
    }

    fn wildcard_probe(
        &self,
        name: &LowerName,
        record_type: RecordType,
    ) -> (Option<&[Record]>, bool) {
        let mut mask = self.wildcard_depths & self.wildcard_window(name);
        let mut covered = false;
        while mask != 0 {
            let depth = (u128::BITS - 1 - mask.leading_zeros()) as usize;
            mask &= !(1u128 << depth);

            let parent = LowerName::from(name.trim_to(depth));
            if self.wildcard_parents.contains(&parent) {
                covered = true;
                if let Some(records) = self.wildcard.get(&(parent, record_type)) {
                    return (Some(records), true);
                }
            }
        }
        (None, covered)
    }

    fn wildcard_window(&self, name: &LowerName) -> u128 {
        let start = label_count(name).saturating_sub(1).min(MAX_LABELS);
        let floor = label_count(&self.lower_origin);
        if start < floor || floor > MAX_LABELS {
            return 0;
        }
        let hi = if start == MAX_LABELS {
            u128::MAX
        } else {
            (1u128 << (start + 1)) - 1
        };
        hi & !((1u128 << floor) - 1)
    }
}

// ===========================================================================
// Comparison
// ===========================================================================

/// An answer rendered for comparison, **order preserved**.
///
/// The older oracle in `tests/properties.rs` sorts the records, because
/// `HashMap` iteration order could otherwise make it flap. Here order is part
/// of the contract: the ruling says config order is preserved into the rdata
/// arena so that answers are deterministic across builds and reloads, and an
/// arena that reordered an RRset would be invisible to a sorted comparison.
fn rendered(answer: &Answer) -> (&'static str, Vec<String>) {
    match answer {
        Answer::NxDomain => ("NXDOMAIN", Vec::new()),
        Answer::NoData => ("NODATA", Vec::new()),
        Answer::Records(records) => (
            "RECORDS",
            records
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
                .collect(),
        ),
    }
}

fn render_soa(soa: Option<&Record>) -> String {
    soa.map_or_else(
        || "<none>".to_owned(),
        |r| format!("{} {} {}", r.name.to_string().to_lowercase(), r.ttl, r.data),
    )
}

fn lower(name: &str) -> LowerName {
    let mut n: Name = name.parse().expect("generated name parses");
    n.set_fqdn(true);
    LowerName::from(n)
}

// ===========================================================================
// Generators — the zone
// ===========================================================================

/// A small alphabet so that generated owners, wildcard parents and query names
/// keep landing on each other. `*` is in it because RFC 4592 §2.1.3 permits a
/// further asterisk inside a wildcard's owner name, and those are the names a
/// label-count mistake breaks.
fn label() -> impl Strategy<Value = String> {
    prop::sample::select(vec!["a", "b", "dev", "apps", "*"]).prop_map(str::to_owned)
}

fn typed_value() -> impl Strategy<Value = (String, String)> {
    prop_oneof![
        (0u8..=255, 0u8..=255).prop_map(|(a, b)| ("A".to_owned(), format!("203.0.{a}.{b}"))),
        (0u16..=0xffff).prop_map(|a| ("AAAA".to_owned(), format!("2001:db8::{a:x}"))),
        prop::sample::select(vec!["hello", "x"])
            .prop_map(|t| ("TXT".to_owned(), format!("\"{t}\""))),
        (1u16..100).prop_map(|p| ("MX".to_owned(), format!("{p} mail.{ORIGIN}."))),
        // CNAME targets are drawn from the same alphabet, so a chase actually
        // lands on something the zone holds often enough to matter.
        prop::collection::vec(prop::sample::select(vec!["a", "b", "dev"]), 1..3)
            .prop_map(|ls| ("CNAME".to_owned(), format!("{}.{ORIGIN}.", ls.join(".")))),
    ]
}

fn exact_spec() -> impl Strategy<Value = RecordSpec> {
    (
        prop::collection::vec(prop::sample::select(vec!["a", "b", "dev", "apps"]), 0..4),
        typed_value(),
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

fn wildcard_spec() -> impl Strategy<Value = RecordSpec> {
    (
        prop::collection::vec(label(), 0..4),
        typed_value(),
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

/// A spec that does **not** build. Present so that "the two agree on whether the
/// build succeeds" is a claim with teeth rather than a claim about a generator
/// that only ever produces valid input.
fn broken_spec() -> impl Strategy<Value = RecordSpec> {
    prop_oneof![
        Just(RecordSpec {
            name: "www.evil.invalid.".to_owned(),
            record_type: "A".to_owned(),
            ttl: None,
            values: vec!["203.0.113.99".to_owned()],
        }),
        Just(RecordSpec {
            name: "www".to_owned(),
            record_type: "NOPE".to_owned(),
            ttl: None,
            values: vec!["x".to_owned()],
        }),
        Just(RecordSpec {
            name: "www".to_owned(),
            record_type: "A".to_owned(),
            ttl: None,
            values: Vec::new(),
        }),
        Just(RecordSpec {
            name: "www".to_owned(),
            record_type: "A".to_owned(),
            ttl: None,
            values: vec!["not-an-ip".to_owned()],
        }),
    ]
}

fn zone_config() -> impl Strategy<Value = ZoneConfig> {
    (
        prop::collection::vec(exact_spec(), 0..6),
        prop::collection::vec(wildcard_spec(), 0..4),
        // Mostly absent: a broken spec makes the whole build fail, so a high
        // rate would starve the lookup half of the property.
        prop::option::weighted(0.08, broken_spec()),
        prop::option::weighted(0.85, Just(())),
    )
        .prop_map(|(exacts, wildcards, broken, with_soa)| {
            let mut records = exacts;
            records.extend(wildcards);
            records.extend(broken);
            ZoneConfig {
                origin: ORIGIN.to_owned(),
                default_ttl: 300,
                builtins: false,
                soa: with_soa.map(|()| SoaSpec {
                    mname: format!("ns1.{ORIGIN}."),
                    rname: format!("hostmaster.{ORIGIN}."),
                    serial: 1,
                    refresh: 3600,
                    retry: 900,
                    expire: 604_800,
                    minimum: 60,
                }),
                records,
            }
        })
}

// ===========================================================================
// Generators — the query, CONSTRUCTED from the zone
// ===========================================================================

/// The absolute name a spec declares, as the zone will key it.
///
/// For a wildcard this is the wildcard's own literal name (`*.dev.example.test.`),
/// not its parent — RFC 4592 §2.1.1 says a wildcard *is* a name with a leftmost
/// asterisk, and at S1 it becomes a node with exactly that name.
fn declared_name(spec: &RecordSpec) -> String {
    let label = spec.name.trim();
    if label == "@" || label.is_empty() {
        format!("{ORIGIN}.")
    } else {
        format!("{label}.{ORIGIN}.")
    }
}

/// The parent a wildcard is indexed under today: `*.dev` -> `dev.example.test.`.
fn wildcard_parent(spec: &RecordSpec) -> Option<String> {
    let label = spec.name.trim();
    if label != "*" && !label.starts_with("*.") {
        return None;
    }
    let rest = label
        .strip_prefix('*')
        .unwrap_or("")
        .trim_start_matches('.');
    Some(if rest.is_empty() {
        format!("{ORIGIN}.")
    } else {
        format!("{rest}.{ORIGIN}.")
    })
}

/// Everything the query generator needs, chosen independently of the zone and
/// then **applied** to it. Nothing is rejected: every combination produces a
/// name, falling back to the origin when the zone has nothing of that kind.
#[derive(Clone, Debug)]
struct QueryPlan {
    shape: u8,
    pick: usize,
    prefix: Vec<String>,
    depth: usize,
}

fn query_plan() -> impl Strategy<Value = QueryPlan> {
    (
        0u8..12,
        0usize..64,
        prop::collection::vec(label(), 1..4),
        0usize..=120,
    )
        .prop_map(|(shape, pick, prefix, depth)| QueryPlan {
            shape,
            pick,
            prefix,
            depth,
        })
}

/// Turn a plan plus a zone into a query name.
///
/// Each shape is a branch of the lookup the arena has to reproduce. They are
/// listed with the branch they reach on today's implementation.
fn query_name(cfg: &ZoneConfig, plan: &QueryPlan) -> String {
    let owners: Vec<String> = cfg.records.iter().map(declared_name).collect();
    let parents: Vec<String> = cfg.records.iter().filter_map(wildcard_parent).collect();
    let cname_targets: Vec<String> = cfg
        .records
        .iter()
        .filter(|s| s.record_type.eq_ignore_ascii_case("CNAME"))
        .filter_map(|s| s.values.first().cloned())
        .collect();

    let pick = |v: &[String]| -> Option<String> {
        if v.is_empty() {
            None
        } else {
            Some(v[plan.pick % v.len()].clone())
        }
    };
    let stack = |base: &str| format!("{}.{base}", plan.prefix.join("."));
    let strip_one = |base: &str| -> String {
        let mut parts = base.splitn(2, '.');
        parts.next();
        parts.next().map_or_else(|| ".".to_owned(), str::to_owned)
    };

    let origin_dot = format!("{ORIGIN}.");
    match plan.shape {
        // Exact owner, verbatim: the RFC 1034 §4.3.2 step 3.a hit, and for a
        // wildcard spec the RFC 4592 §2.3 "asterisk in the QNAME" case.
        0 => pick(&owners).unwrap_or(origin_dot),
        // A wildcard's parent: NXDOMAIN today, an empty non-terminal at S2.
        1 => pick(&parents).unwrap_or(origin_dot),
        // Under a wildcard's parent: the synthesis case.
        2 => pick(&parents).map_or(origin_dot, |p| stack(&p)),
        // Under an existing owner: the closest-encloser case (VEGA-009), which
        // S1 must keep answering exactly as wrongly as it does today.
        3 => pick(&owners).map_or(origin_dot, |o| stack(&o)),
        // A strict ancestor of an owner: the other empty-non-terminal shape.
        4 => pick(&owners).map_or(origin_dot, |o| strip_one(&o)),
        5 => origin_dot,
        6 => ".".to_owned(),
        7 => format!("{}.example.invalid.", plan.prefix.join(".")),
        // A CNAME target, so the chase lands somewhere real.
        8 => pick(&cname_targets).unwrap_or(origin_dot),
        // Deep, up to the octet limit under this origin.
        9 => {
            let mut s = String::with_capacity(plan.depth * 2 + 16);
            for _ in 0..plan.depth {
                s.push_str("a.");
            }
            s.push_str(&origin_dot);
            s
        }
        // Asterisk-leading, the shape a label count that discounts `*` breaks.
        10 => format!("*.{}.{origin_dot}", plan.prefix.join(".")),
        // A name the zone does not hold in any form. Labels are joined with a
        // dot, never fused: hickory rejects a label that mixes an asterisk with
        // other octets, and the alphabet contains one.
        _ => format!("nx.{}.{origin_dot}", plan.prefix.join(".")),
    }
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
        RecordType::SOA,
        RecordType::ANY,
    ])
}

// ===========================================================================
// The property
// ===========================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// INVARIANT (AC-1.1): S1 changes the data structure and nothing else.
    ///
    /// Scenario: The arena answers exactly what today's implementation answers,
    /// for every zone and every query
    /// features/zone-data-model.feature:255
    ///
    /// Also carries, in the same pass:
    ///
    ///   * Scenario: A config the transcription refuses is a config the arena
    ///     refuses — features/zone-data-model.feature:444
    ///   * Scenario: A zone whose config declares no records at all still agrees
    ///     with the transcription — features/zone-data-model.feature:423
    ///
    /// Kept in one property rather than three because they share a generated
    /// zone, and because a build outcome that disagreed while every answer
    /// agreed is not a case anyone would think to write separately.
    ///
    /// `Zone::exists` is compared alongside the answer. It is VEGA-083's public
    /// contract and the ruling's §10.1 keeps its signature and its meaning
    /// through the rewrite; it is also the one predicate the DNSSEC proof
    /// machinery will read, so it must not quietly widen when node existence
    /// stops meaning what it means today.
    #[test]
    fn the_arena_agrees_with_the_pre_s1_implementation_on_every_zone_and_every_query(
        cfg in zone_config(),
        plan in query_plan(),
        qtype in query_type(),
    ) {
        let _watchdog = testutil::arm(WATCHDOG);

        let real = Zone::from_config(&cfg);
        let frozen = FrozenZone::build(&cfg);

        let shape: Vec<String> = cfg.records.iter()
            .map(|r| format!("{} {}", r.name, r.record_type))
            .collect();

        prop_assert_eq!(
            real.is_ok(),
            frozen.is_ok(),
            "the two implementations disagree on whether this config builds \
             (arena: {}, frozen: {}). A rewrite may reword an error; it may not \
             change which configs load, because that is a reload that starts \
             failing or a config that starts smuggling records for someone \
             else's namespace\n  zone: {:?}",
            real.is_ok(),
            frozen.is_ok(),
            shape
        );

        let (Ok(real), Ok(frozen)) = (real, frozen) else { return Ok(()); };

        prop_assert_eq!(
            real.record_count(),
            frozen.record_count,
            "record_count moved; it is the dns_zone_records metric and an \
             operator's only view of whether a reload truncated the zone\n  zone: {:?}",
            shape
        );
        prop_assert_eq!(
            render_soa(real.soa()),
            render_soa(frozen.soa.as_ref()),
            "the SOA moved. Every negative answer carries it (RFC 2308 §3) and \
             its MINIMUM sets the negative cache lifetime (§5)\n  zone: {:?}",
            shape
        );

        let name = query_name(&cfg, &plan);
        let queried = lower(&name);

        prop_assert_eq!(
            real.exists(&queried),
            frozen.exists(&queried),
            "Zone::exists disagreed for {}. It is the RFC 1034 §4.3.2 step 3(c) \
             name-error determination (VEGA-083) and the ruling keeps its \
             contract through the rewrite\n  zone: {:?}",
            name,
            shape
        );

        let actual = real.lookup(&queried, qtype);
        let expected = frozen.lookup(&queried, qtype);
        prop_assert_eq!(
            rendered(&actual),
            rendered(&expected),
            "{} {} (shape {}) disagreed with the pre-S1 implementation. S1 \
             permits ZERO transitions: same variant, same records, same owner \
             names, same TTLs, same rdata, same order\n  zone: {:?}\n  got:      \
             {:?}\n  expected: {:?}",
            name,
            qtype,
            plan.shape,
            shape,
            actual,
            expected
        );
    }
}

/// Scenario: The differential covers ANY, CNAME chasing and the negative paths,
/// not only wildcards
/// features/zone-data-model.feature:272
///
/// The generated property above will reach these, but it reaches them at a rate
/// the generator decides. This walks them deterministically, so a regression in
/// the CNAME chase cannot be hidden by a seed that happened not to build a
/// chain, and so a reader can see the branch list without running proptest.
///
/// Each name/type pair below lands on a different arm of `Zone::resolve`:
/// exact hit, CNAME substitution, CNAME chase into a second name, chase to an
/// out-of-zone target, chase to a dangling target, NODATA at an existing name,
/// wildcard synthesis, wildcard type-miss (NODATA, VEGA-083), uncovered
/// NXDOMAIN, ANY at each of those, and the apex.
#[test]
fn every_branch_of_the_lookup_agrees_with_the_pre_s1_implementation() {
    let _watchdog = testutil::arm(WATCHDOG);

    let spec = |name: &str, ty: &str, value: &str| RecordSpec {
        name: name.to_owned(),
        record_type: ty.to_owned(),
        ttl: None,
        values: vec![value.to_owned()],
    };
    let cfg = ZoneConfig {
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
        records: vec![
            spec("@", "A", "203.0.113.10"),
            spec("host", "A", "203.0.113.20"),
            spec("host", "TXT", "\"two rrsets at one name\""),
            spec("alias", "CNAME", &format!("host.{ORIGIN}.")),
            spec("chain", "CNAME", &format!("alias.{ORIGIN}.")),
            spec("dangling", "CNAME", &format!("nowhere.{ORIGIN}.")),
            spec("outside", "CNAME", "elsewhere.example.invalid."),
            spec("*.dev", "A", "203.0.113.50"),
            spec("*", "A", "203.0.113.1"),
            spec("deep.dev", "A", "203.0.113.51"),
        ],
    };

    let real = Zone::from_config(&cfg).expect("fixture zone builds");
    let frozen = FrozenZone::build(&cfg).expect("transcription builds the same fixture");

    assert_eq!(real.record_count(), frozen.record_count);
    assert_eq!(render_soa(real.soa()), render_soa(frozen.soa.as_ref()));

    let names = [
        ORIGIN.to_owned() + ".",
        format!("host.{ORIGIN}."),
        format!("alias.{ORIGIN}."),
        format!("chain.{ORIGIN}."),
        format!("dangling.{ORIGIN}."),
        format!("outside.{ORIGIN}."),
        format!("x.dev.{ORIGIN}."),
        format!("deep.dev.{ORIGIN}."),
        // VEGA-009's shape: a wildcard leaking below a name that exists. S1
        // must keep answering it exactly as non-conformantly as today.
        format!("a.deep.dev.{ORIGIN}."),
        format!("dev.{ORIGIN}."),
        format!("*.dev.{ORIGIN}."),
        format!("nothing.{ORIGIN}."),
        format!("a.b.c.d.{ORIGIN}."),
        "example.invalid.".to_owned(),
        ".".to_owned(),
    ];
    let types = [
        RecordType::A,
        RecordType::AAAA,
        RecordType::TXT,
        RecordType::CNAME,
        RecordType::SOA,
        RecordType::ANY,
    ];

    let mut compared = 0usize;
    for name in &names {
        let queried = lower(name);
        assert_eq!(
            real.exists(&queried),
            frozen.exists(&queried),
            "Zone::exists disagreed for {name}"
        );
        for qtype in types {
            let actual = real.lookup(&queried, qtype);
            let expected = frozen.lookup(&queried, qtype);
            assert_eq!(
                rendered(&actual),
                rendered(&expected),
                "{name} {qtype} disagreed with the pre-S1 implementation"
            );
            compared += 1;
        }
    }

    assert_eq!(
        compared,
        names.len() * types.len(),
        "the branch sweep did not run every pair; a loop that silently skips is \
         a gate that silently passes"
    );
}
