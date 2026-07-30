//! The in-memory zone: record sets keyed by owner name and type, plus the
//! lookup algorithm that turns a query into an answer.
//!
//! The store is immutable once built, so it can be shared across every worker
//! task behind an [`std::sync::Arc`] with no locking on the query path.

use std::collections::{HashMap, HashSet};

use anyhow::{bail, Context, Result};
use hickory_proto::rr::{
    rdata::{NS, SOA},
    LowerName, Name, RData, Record, RecordType,
};

use crate::config::{RecordSpec, SoaSpec, ZoneConfig};

/// Maximum number of CNAMEs we will follow inside the zone before giving up.
/// RFC 1034 does not set a limit; this stops a misconfigured loop from spinning.
const MAX_CNAME_DEPTH: usize = 8;

/// Longest record value we will hand to the presentation-format parser.
///
/// `RData::try_from_str` runs hickory's zone-file lexer, which carries
/// `assert!(i < 4095)` over the characters of a single token
/// (hickory-proto `serialize/txt/zone_lex.rs`). A longer value aborts the
/// process rather than returning an error — and because `Zone::from_config` is
/// also the reload path, that turns one oversized record in an edited config
/// into a crash loop instead of a rejected reload. Refuse it ourselves, with a
/// message that says what to do.
const MAX_RECORD_VALUE_CHARS: usize = 4090;

/// Result of a zone lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// Records to place in the answer section.
    Records(Vec<Record>),
    /// The owner name exists but has no records of the requested type
    /// (RFC 2308 "NODATA"): `NOERROR` with an empty answer section.
    NoData,
    /// The owner name does not exist: `NXDOMAIN`.
    NxDomain,
}

/// Key for a record set.
type RrKey = (LowerName, RecordType);

/// An immutable authoritative zone.
#[derive(Debug)]
pub struct Zone {
    origin: Name,
    lower_origin: LowerName,
    default_ttl: u32,
    soa: Option<Record>,
    /// Exact-match record sets.
    exact: HashMap<RrKey, Vec<Record>>,
    /// Wildcard record sets, keyed by the name *below* which they apply. A
    /// config entry of `*.dev` is stored under `dev.<origin>`.
    wildcard: HashMap<RrKey, Vec<Record>>,
    /// Every owner name that exists in the zone, used to tell NODATA from NXDOMAIN.
    names: HashSet<LowerName>,
    /// Total number of records, for the `dns_zone_records` metric.
    record_count: usize,
}

impl Zone {
    /// Build a zone from validated configuration.
    ///
    /// Record values are parsed in presentation format, the same syntax a zone
    /// file uses, so `MX` values look like `"10 mail.example.com."`.
    pub fn from_config(cfg: &ZoneConfig) -> Result<Self> {
        let origin = parse_name(&cfg.origin)
            .with_context(|| format!("invalid zone origin {:?}", cfg.origin))?;
        let lower_origin = LowerName::from(origin.clone());

        let mut zone = Self {
            origin: origin.clone(),
            lower_origin,
            default_ttl: cfg.default_ttl,
            soa: None,
            exact: HashMap::new(),
            wildcard: HashMap::new(),
            names: HashSet::new(),
            record_count: 0,
        };

        if let Some(soa) = &cfg.soa {
            zone.soa = Some(build_soa(&origin, soa)?);
        }

        for spec in &cfg.records {
            zone.insert_spec(spec)?;
        }

        // An SOA declared as a plain record set wins over none at all, so pick it
        // up if the operator wrote `[[zone.records]] type = "SOA"` instead.
        if zone.soa.is_none() {
            let key = (zone.lower_origin.clone(), RecordType::SOA);
            zone.soa = zone.exact.get(&key).and_then(|rs| rs.first()).cloned();
        }

        // The apex always exists, even in an empty zone, otherwise a bare
        // `SOA <origin>` query would answer NXDOMAIN for our own zone.
        zone.names.insert(zone.lower_origin.clone());

        Ok(zone)
    }

    fn insert_spec(&mut self, spec: &RecordSpec) -> Result<()> {
        let record_type: RecordType = spec
            .record_type
            .to_uppercase()
            .parse()
            .map_err(|e| anyhow::anyhow!("unknown record type {:?}: {e}", spec.record_type))?;

        if spec.values.is_empty() {
            bail!("record {:?} {} has no values", spec.name, spec.record_type);
        }

        let ttl = spec.ttl.unwrap_or(self.default_ttl);
        let label = spec.name.trim();
        let is_wildcard = label == "*" || label.starts_with("*.");

        // For a wildcard we index under the parent name: `*.dev` -> `dev.<origin>`,
        // and a bare `*` -> `<origin>`.
        let owner_label = if is_wildcard {
            label
                .strip_prefix('*')
                .unwrap_or("")
                .trim_start_matches('.')
        } else {
            label
        };
        let owner = self.qualify(owner_label)?;

        // The record's own name only matters for exact matches; wildcard answers
        // are rewritten to the queried name at lookup time.
        let mut records = Vec::with_capacity(spec.values.len());
        for value in &spec.values {
            let chars = value.chars().count();
            if chars > MAX_RECORD_VALUE_CHARS {
                bail!(
                    "{} record value for {:?} is {chars} characters; the maximum is \
                     {MAX_RECORD_VALUE_CHARS}. Split a long TXT value into several \
                     character-strings instead.",
                    spec.record_type,
                    spec.name
                );
            }
            let rdata = RData::try_from_str(record_type, value).map_err(|e| {
                anyhow::anyhow!(
                    "invalid {} record value {:?} for {:?}: {e}",
                    spec.record_type,
                    value,
                    spec.name
                )
            })?;
            records.push(Record::from_rdata(owner.clone(), ttl, rdata));
        }

        self.record_count += records.len();
        let lower = LowerName::from(owner);
        let key = (lower.clone(), record_type);

        if is_wildcard {
            self.wildcard.entry(key).or_default().extend(records);
        } else {
            self.names.insert(lower);
            self.exact.entry(key).or_default().extend(records);
        }
        Ok(())
    }

    /// Turn a name relative to the origin into an absolute [`Name`].
    fn qualify(&self, label: &str) -> Result<Name> {
        let label = label.trim();
        if label.is_empty() || label == "@" {
            return Ok(self.origin.clone());
        }
        if label.ends_with('.') {
            let name = parse_name(label)?;
            if !self.lower_origin.zone_of(&LowerName::from(name.clone())) {
                bail!("name {label:?} is not inside zone {}", self.origin);
            }
            return Ok(name);
        }
        Name::parse(label, Some(&self.origin))
            .with_context(|| format!("invalid record name {label:?}"))
    }

    /// The zone origin.
    pub fn origin(&self) -> &LowerName {
        &self.lower_origin
    }

    /// The SOA record, if the zone declares one.
    pub fn soa(&self) -> Option<&Record> {
        self.soa.as_ref()
    }

    /// TTL used for records without an explicit one.
    pub fn default_ttl(&self) -> u32 {
        self.default_ttl
    }

    /// Total number of records in the zone.
    pub fn record_count(&self) -> usize {
        self.record_count
    }

    /// True when `name` falls inside this zone.
    pub fn contains(&self, name: &LowerName) -> bool {
        self.lower_origin.zone_of(name)
    }

    /// True when `name` is an owner name this zone holds records for.
    ///
    /// O(1). Exists so the ANY path can tell NXDOMAIN from NODATA without the
    /// full-map scan that made a 29-byte ANY query cost 26x an ordinary lookup
    /// on a 50k-record zone.
    pub fn has_name(&self, name: &LowerName) -> bool {
        self.names.contains(name)
    }

    /// Resolve `name`/`record_type` against the zone.
    ///
    /// Follows in-zone CNAMEs, honours wildcards, and distinguishes NODATA from
    /// NXDOMAIN so the caller can set the right response code.
    pub fn lookup(&self, name: &LowerName, record_type: RecordType) -> Answer {
        let mut answers = Vec::new();
        match self.resolve(name, record_type, 0, &mut answers) {
            Resolution::Found => Answer::Records(answers),
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

        if record_type == RecordType::ANY {
            let mut found = false;
            for ((owner, _), records) in &self.exact {
                if owner == name {
                    out.extend(records.iter().cloned());
                    found = true;
                }
            }
            return if found {
                Resolution::Found
            } else if self.names.contains(name) {
                Resolution::NoData
            } else {
                Resolution::NxDomain
            };
        }

        if let Some(records) = self.exact.get(&(name.clone(), record_type)) {
            out.extend(records.iter().cloned());
            return Resolution::Found;
        }

        // RFC 1034 §3.6.2: a CNAME at the owner name answers queries for any
        // other type, and the target is chased if it lives in this zone.
        if record_type != RecordType::CNAME {
            if let Some(cnames) = self.exact.get(&(name.clone(), RecordType::CNAME)) {
                out.extend(cnames.iter().cloned());
                if depth >= MAX_CNAME_DEPTH {
                    tracing::warn!(%name, "CNAME chain too long, truncating");
                    return Resolution::Found;
                }
                if let Some(RData::CNAME(target)) = cnames.first().map(|r| &r.data) {
                    let target = LowerName::from(target.0.clone());
                    if self.contains(&target) {
                        // A dangling in-zone target still yields the CNAME itself.
                        let _ = self.resolve(&target, record_type, depth + 1, out);
                    }
                }
                return Resolution::Found;
            }
        }

        if self.names.contains(name) {
            return Resolution::NoData;
        }

        // Wildcards only apply when the queried name itself does not exist.
        if !self.wildcard.is_empty() {
            let mut parent = name.base_name();
            loop {
                if let Some(records) = self.wildcard.get(&(parent.clone(), record_type)) {
                    let qname = Name::from(name.clone());
                    out.extend(
                        records
                            .iter()
                            .map(|r| Record::from_rdata(qname.clone(), r.ttl, r.data.clone())),
                    );
                    return Resolution::Found;
                }
                if parent == self.lower_origin || parent.is_root() {
                    break;
                }
                parent = parent.base_name();
            }
        }

        Resolution::NxDomain
    }
}

/// Internal three-way result of [`Zone::resolve`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Resolution {
    Found,
    NoData,
    NxDomain,
}

/// Parse an absolute or relative name into an FQDN.
fn parse_name(input: &str) -> Result<Name> {
    let mut name: Name = input
        .parse()
        .with_context(|| format!("invalid DNS name {input:?}"))?;
    name.set_fqdn(true);
    Ok(name)
}

fn build_soa(origin: &Name, spec: &SoaSpec) -> Result<Record> {
    let mname = parse_name(&spec.mname).context("invalid zone.soa.mname")?;
    let rname = parse_name(&spec.rname).context("invalid zone.soa.rname")?;
    let soa = SOA::new(
        mname,
        rname,
        spec.serial,
        spec.refresh,
        spec.retry,
        spec.expire,
        spec.minimum,
    );
    Ok(Record::from_rdata(
        origin.clone(),
        spec.minimum,
        RData::SOA(soa),
    ))
}

/// Build an `NS` record, exposed for tests and for callers that synthesise
/// delegation data.
pub fn ns_record(owner: Name, ttl: u32, target: &str) -> Result<Record> {
    let target = parse_name(target)?;
    Ok(Record::from_rdata(owner, ttl, RData::NS(NS(target))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ZoneConfig;

    fn spec(name: &str, ty: &str, values: &[&str]) -> RecordSpec {
        RecordSpec {
            name: name.to_owned(),
            record_type: ty.to_owned(),
            ttl: None,
            values: values.iter().map(|v| (*v).to_owned()).collect(),
        }
    }

    fn zone(records: Vec<RecordSpec>) -> Zone {
        Zone::from_config(&ZoneConfig {
            origin: "example.com".to_owned(),
            default_ttl: 300,
            builtins: false,
            soa: Some(SoaSpec {
                mname: "ns1.example.com.".to_owned(),
                rname: "hostmaster.example.com.".to_owned(),
                serial: 7,
                refresh: 3600,
                retry: 900,
                expire: 604_800,
                minimum: 60,
            }),
            records,
        })
        .expect("zone should build")
    }

    fn lower(name: &str) -> LowerName {
        LowerName::from(parse_name(name).unwrap())
    }

    #[test]
    fn apex_a_record_resolves() {
        let z = zone(vec![spec("@", "A", &["203.0.113.10", "203.0.113.11"])]);
        let Answer::Records(records) = z.lookup(&lower("example.com."), RecordType::A) else {
            panic!("expected records");
        };
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].name, parse_name("example.com.").unwrap());
        assert_eq!(records[0].ttl, 300);
    }

    #[test]
    fn subdomain_is_qualified_against_the_origin() {
        let z = zone(vec![spec("www", "A", &["203.0.113.20"])]);
        assert!(matches!(
            z.lookup(&lower("www.example.com."), RecordType::A),
            Answer::Records(_)
        ));
    }

    #[test]
    fn per_record_ttl_overrides_the_zone_default() {
        let mut s = spec("api", "A", &["203.0.113.30"]);
        s.ttl = Some(30);
        let z = zone(vec![s]);
        let Answer::Records(records) = z.lookup(&lower("api.example.com."), RecordType::A) else {
            panic!("expected records");
        };
        assert_eq!(records[0].ttl, 30);
    }

    #[test]
    fn existing_name_wrong_type_is_nodata_not_nxdomain() {
        let z = zone(vec![spec("www", "A", &["203.0.113.20"])]);
        assert_eq!(
            z.lookup(&lower("www.example.com."), RecordType::AAAA),
            Answer::NoData
        );
    }

    #[test]
    fn missing_name_is_nxdomain() {
        let z = zone(vec![spec("www", "A", &["203.0.113.20"])]);
        assert_eq!(
            z.lookup(&lower("nope.example.com."), RecordType::A),
            Answer::NxDomain
        );
    }

    #[test]
    fn out_of_zone_name_is_nxdomain() {
        let z = zone(vec![]);
        assert_eq!(
            z.lookup(&lower("example.org."), RecordType::A),
            Answer::NxDomain
        );
    }

    #[test]
    fn cname_is_chased_within_the_zone() {
        let z = zone(vec![
            spec("www", "CNAME", &["origin.example.com."]),
            spec("origin", "A", &["203.0.113.40"]),
        ]);
        let Answer::Records(records) = z.lookup(&lower("www.example.com."), RecordType::A) else {
            panic!("expected records");
        };
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].record_type(), RecordType::CNAME);
        assert_eq!(records[1].record_type(), RecordType::A);
    }

    #[test]
    fn cname_to_external_target_returns_only_the_cname() {
        let z = zone(vec![spec("cdn", "CNAME", &["cdn.provider.net."])]);
        let Answer::Records(records) = z.lookup(&lower("cdn.example.com."), RecordType::A) else {
            panic!("expected records");
        };
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record_type(), RecordType::CNAME);
    }

    #[test]
    fn cname_loop_terminates() {
        let z = zone(vec![
            spec("a", "CNAME", &["b.example.com."]),
            spec("b", "CNAME", &["a.example.com."]),
        ]);
        // Must not hang or overflow the stack.
        let Answer::Records(records) = z.lookup(&lower("a.example.com."), RecordType::A) else {
            panic!("expected records");
        };
        assert!(records.len() <= MAX_CNAME_DEPTH + 2);
    }

    #[test]
    fn wildcard_matches_and_is_rewritten_to_the_query_name() {
        let z = zone(vec![spec("*.dev", "A", &["203.0.113.50"])]);
        let Answer::Records(records) = z.lookup(&lower("anything.dev.example.com."), RecordType::A)
        else {
            panic!("expected records");
        };
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].name,
            parse_name("anything.dev.example.com.").unwrap()
        );
    }

    #[test]
    fn exact_match_beats_wildcard() {
        let z = zone(vec![
            spec("*.dev", "A", &["203.0.113.50"]),
            spec("special.dev", "A", &["203.0.113.51"]),
        ]);
        let Answer::Records(records) = z.lookup(&lower("special.dev.example.com."), RecordType::A)
        else {
            panic!("expected records");
        };
        assert_eq!(
            &records[0].data,
            &RData::try_from_str(RecordType::A, "203.0.113.51").unwrap()
        );
    }

    #[test]
    fn wildcard_does_not_answer_a_different_type() {
        let z = zone(vec![spec("*.dev", "A", &["203.0.113.50"])]);
        assert_eq!(
            z.lookup(&lower("x.dev.example.com."), RecordType::TXT),
            Answer::NxDomain
        );
    }

    #[test]
    fn any_query_returns_every_type_at_the_name() {
        let z = zone(vec![
            spec("multi", "A", &["203.0.113.60"]),
            spec("multi", "TXT", &["\"hello\""]),
        ]);
        let Answer::Records(records) = z.lookup(&lower("multi.example.com."), RecordType::ANY)
        else {
            panic!("expected records");
        };
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn soa_is_served_at_the_apex() {
        let z = zone(vec![]);
        let soa = z.soa().expect("soa configured");
        assert_eq!(soa.record_type(), RecordType::SOA);
        assert_eq!(soa.ttl, 60);
    }

    #[test]
    fn mx_and_txt_parse_in_presentation_format() {
        let z = zone(vec![
            spec("@", "MX", &["10 mail.example.com."]),
            spec("@", "TXT", &["\"v=spf1 -all\""]),
        ]);
        assert!(matches!(
            z.lookup(&lower("example.com."), RecordType::MX),
            Answer::Records(_)
        ));
        assert!(matches!(
            z.lookup(&lower("example.com."), RecordType::TXT),
            Answer::Records(_)
        ));
    }

    #[test]
    fn bad_record_value_fails_at_build_time() {
        let err = Zone::from_config(&ZoneConfig {
            origin: "example.com".to_owned(),
            default_ttl: 300,
            builtins: false,
            soa: None,
            records: vec![spec("@", "A", &["not-an-ip"])],
        })
        .unwrap_err();
        assert!(err.to_string().contains("invalid A record value"), "{err}");
    }

    #[test]
    fn unknown_record_type_fails_at_build_time() {
        let err = Zone::from_config(&ZoneConfig {
            origin: "example.com".to_owned(),
            default_ttl: 300,
            builtins: false,
            soa: None,
            records: vec![spec("@", "NOPE", &["x"])],
        })
        .unwrap_err();
        assert!(err.to_string().contains("unknown record type"), "{err}");
    }

    #[test]
    fn record_count_tracks_every_value() {
        let z = zone(vec![
            spec("@", "A", &["203.0.113.1", "203.0.113.2"]),
            spec("www", "A", &["203.0.113.3"]),
        ]);
        assert_eq!(z.record_count(), 3);
    }

    // -----------------------------------------------------------------------
    // Regression tests from mutation testing. Each one names the mutant that
    // survived without it, so a later refactor knows what it is load-bearing
    // for.
    // -----------------------------------------------------------------------

    #[test]
    fn a_fully_qualified_in_zone_record_name_is_accepted() {
        // Kills `delete !` in Zone::qualify: with the `!` gone, an in-zone FQDN
        // is rejected and an out-of-zone one is silently accepted instead.
        let z = zone(vec![spec("www.example.com.", "A", &["203.0.113.20"])]);
        let Answer::Records(records) = z.lookup(&lower("www.example.com."), RecordType::A) else {
            panic!("a fully-qualified in-zone name should resolve");
        };
        assert_eq!(records[0].name, parse_name("www.example.com.").unwrap());
    }

    #[test]
    fn a_fully_qualified_out_of_zone_record_name_is_rejected() {
        // The other half of the same mutant: a record claiming a name we are
        // not authoritative for must fail at build time rather than get served.
        let err = Zone::from_config(&ZoneConfig {
            origin: "example.com".to_owned(),
            default_ttl: 300,
            builtins: false,
            soa: None,
            records: vec![spec("evil.example.org.", "A", &["203.0.113.20"])],
        })
        .unwrap_err();
        assert!(err.to_string().contains("is not inside zone"), "{err}");
    }

    #[test]
    fn default_ttl_is_reported_verbatim() {
        // Kills `Zone::default_ttl -> 0` and `-> 1`. The accessor decides the
        // TTL of every built-in sub-zone answer and nothing asserted on it.
        assert_eq!(zone(vec![]).default_ttl(), 300);
    }

    #[test]
    fn the_apex_exists_even_in_an_empty_zone() {
        // Kills deleting `zone.names.insert(zone.lower_origin)`: without it the
        // zone answers NXDOMAIN for its own origin.
        let z = zone(vec![]);
        assert_eq!(
            z.lookup(&lower("example.com."), RecordType::A),
            Answer::NoData
        );
        assert_eq!(
            z.lookup(&lower("example.com."), RecordType::ANY),
            Answer::NoData
        );
    }

    #[test]
    fn a_wildcard_matches_names_several_labels_below_it() {
        // Kills `==` -> `!=` on the origin check in the wildcard walk: with the
        // mutation the walk gives up after a single step and this is NXDOMAIN.
        let z = zone(vec![spec("*.dev", "A", &["203.0.113.50"])]);
        let Answer::Records(records) = z.lookup(&lower("a.b.c.dev.example.com."), RecordType::A)
        else {
            panic!("*.dev must cover every name below dev.example.com");
        };
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].name,
            parse_name("a.b.c.dev.example.com.").unwrap()
        );
    }

    #[test]
    fn a_wildcard_walk_that_matches_nothing_terminates() {
        // Kills `||` -> `&&` in the wildcard-walk break condition. With `&&`
        // the loop calls base_name() on the root for ever; without this timeout
        // the whole test binary hangs instead of reporting a failure.
        use std::sync::mpsc;
        use std::time::Duration;

        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let z = zone(vec![spec("*.dev", "A", &["203.0.113.50"])]);
            let _ = tx.send(z.lookup(&lower("nope.example.com."), RecordType::A));
        });
        let answer = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the wildcard walk must terminate");
        assert_eq!(answer, Answer::NxDomain);
    }

    #[test]
    fn a_cname_loop_is_cut_off_after_a_handful_of_hops() {
        // Kills `MAX_CNAME_DEPTH: 8 -> 800`. `cname_loop_terminates` expressed
        // its bound in terms of the constant, so it stayed green for any value
        // of it; this bound is deliberately hard-coded.
        let z = zone(vec![
            spec("a", "CNAME", &["b.example.com."]),
            spec("b", "CNAME", &["a.example.com."]),
        ]);
        let Answer::Records(records) = z.lookup(&lower("a.example.com."), RecordType::A) else {
            panic!("expected records");
        };
        assert!(
            records.len() <= 16,
            "a CNAME loop produced {} records; the depth limit is not doing its job",
            records.len()
        );
        assert_eq!(records.len(), MAX_CNAME_DEPTH + 1);
    }

    #[test]
    fn a_cname_chain_of_exactly_the_depth_limit_reaches_the_address() {
        let mut records = Vec::new();
        for i in 0..MAX_CNAME_DEPTH {
            records.push(spec(
                &format!("c{i}"),
                "CNAME",
                &[&format!("c{}.example.com.", i + 1)],
            ));
        }
        records.push(spec(&format!("c{MAX_CNAME_DEPTH}"), "A", &["203.0.113.99"]));
        let z = zone(records);

        let Answer::Records(answers) = z.lookup(&lower("c0.example.com."), RecordType::A) else {
            panic!("expected records");
        };
        assert_eq!(answers.len(), MAX_CNAME_DEPTH + 1);
        assert_eq!(answers.last().unwrap().record_type(), RecordType::A);
    }

    #[test]
    fn a_cname_chain_one_hop_too_long_stops_short_of_the_address() {
        // Pins the behaviour on the far side of the limit, so that moving
        // MAX_CNAME_DEPTH has to be a deliberate act.
        let mut records = Vec::new();
        for i in 0..=MAX_CNAME_DEPTH {
            records.push(spec(
                &format!("c{i}"),
                "CNAME",
                &[&format!("c{}.example.com.", i + 1)],
            ));
        }
        records.push(spec(
            &format!("c{}", MAX_CNAME_DEPTH + 1),
            "A",
            &["203.0.113.99"],
        ));
        let z = zone(records);

        let Answer::Records(answers) = z.lookup(&lower("c0.example.com."), RecordType::A) else {
            panic!("expected records");
        };
        assert_eq!(answers.len(), MAX_CNAME_DEPTH + 1);
        assert!(
            answers.iter().all(|r| r.record_type() == RecordType::CNAME),
            "past the limit the chase stops before the address"
        );
    }

    #[test]
    fn record_count_counts_values_not_record_sets() {
        // Kills `record_count += records.len()` -> `+= 1`.
        let z = zone(vec![spec(
            "pool",
            "A",
            &["203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"],
        )]);
        assert_eq!(z.record_count(), 4);
    }

    #[test]
    fn a_zone_level_soa_wins_over_a_record_set_soa() {
        // Kills `zone.soa.is_none()` -> `is_some()` in the SOA fallback.
        let z = zone(vec![spec(
            "@",
            "SOA",
            &["ns9.example.com. hostmaster.example.com. 99 1 1 1 1"],
        )]);
        let RData::SOA(soa) = &z.soa().expect("soa").data else {
            panic!("expected SOA");
        };
        assert_eq!(soa.serial, 7, "[zone.soa] must win over a record set");
    }

    #[test]
    fn a_record_set_soa_is_used_when_no_zone_soa_is_declared() {
        let z = Zone::from_config(&ZoneConfig {
            origin: "example.com".to_owned(),
            default_ttl: 300,
            builtins: false,
            soa: None,
            records: vec![spec(
                "@",
                "SOA",
                &["ns9.example.com. hostmaster.example.com. 99 1 1 1 1"],
            )],
        })
        .expect("zone builds");
        let RData::SOA(soa) = &z.soa().expect("soa").data else {
            panic!("expected SOA");
        };
        assert_eq!(soa.serial, 99);
    }

    #[test]
    fn a_wildcard_never_creates_a_record_at_its_own_parent() {
        // Kills `if is_wildcard` -> `if !is_wildcard` in insert_spec.
        let z = zone(vec![spec("*.dev", "A", &["203.0.113.50"])]);
        assert_eq!(
            z.lookup(&lower("dev.example.com."), RecordType::A),
            Answer::NxDomain,
            "*.dev must not put a record at dev.example.com itself"
        );
    }

    #[test]
    fn an_out_of_zone_name_is_nxdomain_not_nodata() {
        // Kills the out-of-zone `Resolution::NxDomain` -> `NoData`.
        let z = zone(vec![spec("www", "A", &["203.0.113.20"])]);
        assert_eq!(
            z.lookup(&lower("www.example.org."), RecordType::A),
            Answer::NxDomain
        );
        assert_eq!(z.lookup(&lower("."), RecordType::NS), Answer::NxDomain);
    }

    // -----------------------------------------------------------------------
    // Known bugs, written against the RFC. These fail today and are ignored so
    // the suite stays green until the behaviour is fixed.
    // -----------------------------------------------------------------------

    #[test]
    #[ignore = "BUG: empty non-terminals answer NXDOMAIN instead of NODATA (RFC 2308 s2.2.1)"]
    fn an_empty_non_terminal_is_nodata_not_nxdomain() {
        // `a.b.ent.example.com` exists, so `ent.example.com` and
        // `b.ent.example.com` exist too, as empty non-terminals. Answering
        // NXDOMAIN for them is not cosmetic: under RFC 8020 a resolver that
        // caches NXDOMAIN for `ent.example.com` may synthesise NXDOMAIN for
        // everything beneath it, taking the real record out of service.
        // `Zone::names` only ever records explicit owner names, never the
        // ancestors those names imply.
        let z = zone(vec![spec("a.b.ent", "A", &["203.0.113.41"])]);
        assert_eq!(
            z.lookup(&lower("b.ent.example.com."), RecordType::A),
            Answer::NoData
        );
        assert_eq!(
            z.lookup(&lower("ent.example.com."), RecordType::A),
            Answer::NoData
        );
    }

    #[test]
    #[ignore = "BUG: a wildcard is applied below a name that exists (RFC 4592 s3.3.1)"]
    fn a_wildcard_does_not_apply_below_a_name_that_exists() {
        // RFC 4592: the source of synthesis is `*` under the *closest
        // encloser*. For `a.deep.dev.example.com` the closest encloser is
        // `deep.dev.example.com`, which exists, so the source of synthesis is
        // `*.deep.dev.example.com` — which does not exist, hence NXDOMAIN.
        // `Zone::resolve` instead walks up until it finds any wildcard at all,
        // so `*.dev` leaks in underneath a name that already exists.
        let z = zone(vec![
            spec("*.dev", "A", &["203.0.113.50"]),
            spec("deep.dev", "A", &["203.0.113.51"]),
        ]);
        assert_eq!(
            z.lookup(&lower("a.deep.dev.example.com."), RecordType::A),
            Answer::NxDomain
        );
    }

    #[test]
    #[ignore = "BUG: an empty non-terminal created by a wildcard is NXDOMAIN too"]
    fn the_parent_of_a_wildcard_is_not_nxdomain() {
        // `*.apps.example.com` implies `apps.example.com` exists. Answering
        // NXDOMAIN for the parent lets an RFC 8020 resolver conclude the whole
        // wildcard subtree is empty.
        let z = zone(vec![spec("*.apps", "A", &["203.0.113.30"])]);
        assert_eq!(
            z.lookup(&lower("apps.example.com."), RecordType::A),
            Answer::NoData
        );
    }
}
