//! Property-based tests: invariants that must hold for *every* zone, not just
//! the handful of shapes the example-based tests happen to use.
//!
//! Each test states its invariant in prose first. When one of these fails,
//! proptest prints the smallest zone that breaks it, which is usually the whole
//! bug report.

use std::collections::BTreeSet;

use hickory_proto::rr::{LowerName, Name, RData, RecordType};
use proptest::prelude::*;
use vega::{
    config::{RecordSpec, SoaSpec, ZoneConfig},
    editor::{Change, ConfigEditor},
    zone::{Answer, Zone},
};

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
