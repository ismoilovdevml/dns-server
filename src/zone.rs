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

use crate::{
    config::{RecordSpec, SoaSpec, ZoneConfig},
    rdata::{self, ValueError},
};

/// Maximum number of CNAMEs we will follow inside the zone before giving up.
/// RFC 1034 does not set a limit; this stops a misconfigured loop from spinning.
const MAX_CNAME_DEPTH: usize = 8;

/// The most labels any DNS name can carry, and so the highest wildcard depth
/// this zone can ever have to probe.
///
/// RFC 1035 §2.3.4 caps a domain name at 255 octets; §3.1 encodes every label
/// as a length octet followed by at least one content octet and terminates the
/// name with a zero octet, giving `2n + 1 <= 255` and therefore `n <= 127`. Not
/// a tuning knob: a longer name cannot exist on the wire, and hickory's
/// `MAX_LENGTH` check rejects one in `append_label` and in the decoder long
/// before it reaches [`Zone::resolve`]. 127 is also the highest bit of a `u128`,
/// which is what makes one bit per depth fit exactly.
const MAX_LABELS: usize = 127;

/// Raw label count of `name`, asterisk labels included.
///
/// Deliberately **not** `Name::num_labels` / `LowerName::num_labels`, which are
/// documented as counting labels *discounting* a leading `*`, while
/// `Name::trim_to` — how the wildcard walk turns a depth back into a name —
/// indexes by the raw count. The two are different index spaces, and mixing
/// them shifts every probe one label off for any name whose leftmost label is
/// an asterisk: an apex `*` stops answering `*.example.com.` (RFC 4592 §2.3),
/// and a nested `*.*.dev` becomes permanently unreachable (RFC 4592 §2.1.3).
/// That is four silent wrong answers on the authoritative path, so `num_labels`
/// is banned in this module and label counts come from here. The upstream
/// behaviour both halves of that claim rest on is pinned by
/// `tests/properties.rs::hickorys_num_labels_discounts_a_leading_asterisk_but_trim_to_does_not`,
/// so a hickory upgrade cannot quietly invalidate it.
///
/// `LabelIter` is an `ExactSizeIterator`, so this is a field read, not a walk.
#[inline]
fn label_count(name: &LowerName) -> usize {
    name.iter().len()
}

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
    /// Bit `d` is set when the zone holds at least one wildcard whose parent
    /// name has exactly `d` labels.
    ///
    /// The parent walk probes only these depths, so answering a wildcard query
    /// costs what the *operator* configured — one probe, for every zone anyone
    /// actually writes — instead of what the *client* chose. Walking up one
    /// `base_name()` at a time was O(labels²), because `base_name` rebuilds and
    /// revalidates the whole remaining name: 174.7 µs of CPU for one 229-byte
    /// packet, against a 9.1 µs budget (VEGA-065).
    wildcard_depths: u128,
    /// Every name at which the zone holds at least one wildcard, whatever its
    /// type — the *source of synthesis* of RFC 4592 §3.3.1, as a set.
    ///
    /// `wildcard_depths` says a wildcard exists somewhere at depth `d`; this
    /// says one exists at *this* parent. The walk needs both: the bitmap to
    /// decide which depths are worth probing at all, this to decide whether the
    /// probe landed on a source of synthesis. Deriving coverage from the bitmap
    /// alone would make every name whose parent merely shares a depth with some
    /// wildcard exist, which in a zone with an apex wildcard is very nearly
    /// every name there is (VEGA-083, rejected alternative 5).
    wildcard_parents: HashSet<LowerName>,
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
            wildcard_depths: 0,
            wildcard_parents: HashSet::new(),
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

        // Debug-only on purpose: the invariant is maintained structurally by
        // `insert_spec`, and this scan is O(wildcards) on a path an operator
        // pays for on every reload. It is here to fail a future writer who adds
        // a second insertion point, at the moment they add it.
        debug_assert!(
            zone.wildcard.keys().all(|(owner, _)| {
                let depth = label_count(owner);
                depth <= MAX_LABELS
                    && zone.wildcard_depths & (1u128 << depth) != 0
                    && zone.wildcard_parents.contains(owner)
            }),
            "wildcard_depths or wildcard_parents is out of step with the wildcard map; a \
             wildcard is unreachable, or a name it covers answers NXDOMAIN"
        );

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
            // Through `rdata::parse_value` like `vega record add`, and for the
            // same reason: hickory's lexer asserts past 4095 characters, so on
            // this path — startup *and* every reload — an oversized value in an
            // edited config is a crash loop, not a rejected reload. One gate,
            // one bound, one message, whichever end the value came in through
            // (VEGA-071).
            let rdata = rdata::parse_value(record_type, &spec.name, value).map_err(|error| {
                match error {
                    // Reworded, not passed through: an operator reading this is
                    // looking for one record set in a file that may hold
                    // hundreds, so the value and the owner both have to be in
                    // it. The length rule keeps `rdata`'s own wording, which is
                    // what makes it read identically from the CLI.
                    ValueError::Unparsable(e) => anyhow::anyhow!(
                        "invalid {} record value {:?} for {:?}: {e}",
                        spec.record_type,
                        value,
                        spec.name
                    ),
                    too_long @ ValueError::TooLong { .. } => anyhow::Error::new(too_long),
                }
            })?;
            records.push(Record::from_rdata(owner.clone(), ttl, rdata));
        }

        self.record_count += records.len();
        let lower = LowerName::from(owner);
        let key = (lower.clone(), record_type);

        if is_wildcard {
            // Recorded here, in the one place that writes to `wildcard`, so
            // neither index can drift out of step with the map it indexes. A
            // missing bit is a configured wildcard answering NXDOMAIN with
            // nothing in the log; a missing parent is every name that wildcard
            // covers answering NXDOMAIN for the types it does not carry, which
            // is the defect VEGA-083 fixed. Both are silent, so all three writes
            // stay adjacent and `from_config`'s `debug_assert!` fails a future
            // second insertion point at the moment it is added.
            let depth = label_count(&lower);
            // Unreachable — `qualify` builds this name through hickory, which
            // enforces the 255-octet limit MAX_LABELS is derived from. A branch
            // rather than an assumption, because `1u128 << 128` panics and this
            // runs on the reload path. The parent set is written under the same
            // condition as the bit, so a depth the walk can never probe can
            // never claim coverage either.
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

    /// True when a query for `name` must be answered NOERROR rather than
    /// NXDOMAIN.
    ///
    /// Two ways to be true: the zone holds an owner name here, or a source of
    /// synthesis exists for it (RFC 4592 §3.3.1). This is deliberately **not**
    /// "is there a node here" — RFC 4592 §2.2 is explicit that a wildcard-covered
    /// name is not a node in the zone, which is why DNSSEC needs a
    /// closest-encloser proof for it. It is the RFC 1034 §4.3.2 step 3(c)
    /// name-error determination, and it is independent of QTYPE: the name error
    /// is set only when the `*` node does not exist, never because the node
    /// exists and holds nothing of the queried type.
    ///
    /// There is no narrower `pub` predicate on purpose. The one that used to be
    /// here answered "is this in `names`", which reads like existence and is
    /// not; two callers believed the name and a wildcard-covered name answered
    /// NXDOMAIN for every type the wildcard did not carry (VEGA-083).
    ///
    /// O(1) on a zone with no wildcards — `names.contains`, then an empty
    /// probe mask and no probes at all.
    pub fn exists(&self, name: &LowerName) -> bool {
        // RFC 1035 §3.2.3: ANY is a QTYPE and never an RRTYPE, so it can never
        // key `wildcard`. The typed half of the probe therefore always misses
        // and only the coverage bit comes back — which is the half wanted here.
        self.names.contains(name) || self.wildcard_probe(name, RecordType::ANY).1
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

        // RFC 1035 §3.2.3: ANY (255) is a QTYPE, never an RRTYPE, so it can
        // never be a key in `exact` or `wildcard`. RFC 8482 makes *what* to
        // answer for it a responder policy, and that policy lives in
        // `DnsHandler`; the zone layer reports existence and nothing else.
        //
        // This replaced a scan of the whole record map, which cost 1.83 ms on a
        // 100k-record zone — 18,239x an A lookup, and one routing change away
        // from the packet path — and which carried the same existence defect at
        // its NXDOMAIN arm (VEGA-083 §4.4). Reporting existence is the only
        // bounded answer: making the scan wildcard-aware makes it slower still,
        // and making it fast needs the owner-major re-key that is VEGA-032's.
        //
        // A caller that reads `NoData` here as "the node is empty" is wrong.
        // AXFR (VEGA-032) needs ordered node iteration and will not get it from
        // this function, so do not reintroduce the scan to serve a transfer.
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

        // RFC 1034 §4.3.2 step 3(c) sets the authoritative name error *only*
        // when the `*` node does not exist. Here it exists and holds no RRset of
        // this type, so control goes to step 6 — exit with an empty answer
        // section — which is RFC 2308 §2.2 NODATA.
        //
        // Answering NXDOMAIN instead is not cosmetic. It is authoritative and
        // carries the SOA, so RFC 2308 §5 has it cached for the SOA MINIMUM and
        // RFC 8020 §2 then licenses the resolver to deny the entire subtree —
        // including the records the wildcard *does* carry. A dual-stack client's
        // AAAA is enough to trigger it; no attacker is required (VEGA-083).
        if covered {
            Resolution::NoData
        } else {
            Resolution::NxDomain
        }
    }

    /// Walk the wildcard depths for `name`, deepest set bit first.
    ///
    /// Returns the RRset to synthesise from, when the zone holds one of
    /// `record_type` at a source of synthesis for `name`, **and** whether any
    /// source of synthesis for `name` exists at all.
    ///
    /// The two halves answer different questions and only the first depends on
    /// `record_type`: it decides the *answer section*, while coverage decides
    /// NOERROR against NXDOMAIN (RFC 1034 §4.3.2 step 3(c)). Both callers go
    /// through here so the two determinations cannot drift apart and start
    /// returning a QTYPE-dependent rcode again.
    ///
    /// Deepest set bit first, so the closest wildcard answers — the same order
    /// the old `base_name()` climb produced, and what
    /// `the_deepest_wildcard_wins_when_several_could_match` pins. Every depth
    /// skipped is a depth at which no key can exist, because equal names have
    /// equal label counts, so dropping it cannot lose a hit.
    ///
    /// `mask` strictly loses a bit each pass, so termination is structural
    /// rather than a counter that has to be checked against a floor. That
    /// matters for `origin = "."`, where the floor is 0 and a decrementing walk
    /// needs an extra guard to avoid spinning on the root.
    fn wildcard_probe(
        &self,
        name: &LowerName,
        record_type: RecordType,
    ) -> (Option<&[Record]>, bool) {
        let mut mask = self.wildcard_depths & self.wildcard_window(name);
        let mut covered = false;
        while mask != 0 {
            // `mask != 0` bounds `leading_zeros()` at 127, so `depth <= 127`
            // and neither shift below can overflow.
            let depth = (u128::BITS - 1 - mask.leading_zeros()) as usize;
            mask &= !(1u128 << depth);

            let parent = LowerName::from(name.trim_to(depth));
            // Coverage first, and it takes `parent` by reference: where nothing
            // covers the name this skips building and hashing the `(name, type)`
            // tuple key at all. That is the deliberate trade, and it is priced:
            // an uncovered name — the shape an attacker picks, because it is the
            // one they can generate without knowing the zone — measured flat to
            // slightly faster (263 ns -> 253 ns, best of 5x20k, release,
            // 100k-record zone), while a *covered* name pays one extra hash of
            // the parent and measured ~+45 ns. Ordering the tuple probe first
            // would move the cost onto the attacker's path instead, which is the
            // wrong way round. Removing it entirely needs the owner-major re-key
            // that is VEGA-032's (VEGA-083, rejected alternative 6).
            if self.wildcard_parents.contains(&parent) {
                covered = true;
                if let Some(records) = self.wildcard.get(&(parent, record_type)) {
                    return (Some(records), true);
                }
            }
        }
        // Deliberately no early exit on `covered`: which wildcard answers must
        // stay exactly what it is today (deepest type match). Stopping at the
        // deepest wildcard *parent* would be a half-step towards RFC 4592
        // §3.3.1 closest-encloser semantics, which is VEGA-009's, not this.
        (None, covered)
    }

    /// The depths at which a wildcard parent of `name` could possibly sit.
    ///
    /// Bounded above by the depth of `name`'s immediate parent, because a
    /// wildcard's parent is a *proper* ancestor of the names it covers (RFC
    /// 4592 §3.3.1), and below by the origin's depth, because [`Zone::qualify`]
    /// refuses to build a key outside the zone — anything shallower is a
    /// guaranteed miss. Empty when `name` sits at or above the origin.
    fn wildcard_window(&self, name: &LowerName) -> u128 {
        let start = label_count(name).saturating_sub(1).min(MAX_LABELS);
        let floor = label_count(&self.lower_origin);
        if start < floor || floor > MAX_LABELS {
            return 0;
        }
        // `start` is derived from a name the client chose, so the top of the
        // range gets a branch rather than an assumption: `1u128 << 128` is a
        // panic in debug, and with `panic = "abort"` in release one packet
        // would be a full outage.
        let hi = if start == MAX_LABELS {
            u128::MAX
        } else {
            (1u128 << (start + 1)) - 1
        };
        hi & !((1u128 << floor) - 1)
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
    use std::time::Duration;

    use super::*;
    use crate::config::ZoneConfig;

    /// How long any single test in this module may take before the process
    /// watchdog concludes something is spinning and kills the binary.
    ///
    /// The tests here are microseconds of work each — the slowest builds a
    /// thirty-label zone — so thirty seconds is six orders of magnitude of
    /// headroom and can only be reached by a loop that is not terminating.
    /// Generous on purpose: a false trip on a loaded machine costs a re-run,
    /// while a guard set tight enough to flake gets deleted.
    const WALK_WATCHDOG: Duration = Duration::from_secs(30);

    /// Bound the rest of the calling test by the *process* clock.
    ///
    /// Every test below that reaches [`Zone::lookup`] arms this. The failure
    /// mode `Zone::resolve`'s wildcard-depth walk and its CNAME chase guard
    /// against is a **spin**, and a spin cannot be observed by returning from
    /// the thing that is spinning: the guard has to be able to end the process.
    /// Bounding a channel with `recv_timeout` and leaving the walk on a detached
    /// thread — what this module used to do, and only on two of these tests — is
    /// worse than no guard, because the suite reports and moves on while a core
    /// keeps burning and a mutation harness scores the mutant as a timeout
    /// rather than as caught. See `src/testutil.rs`.
    ///
    /// Bind the result: `let _watchdog = watchdog();`. Dropping it disarms.
    #[track_caller]
    #[must_use]
    fn watchdog() -> crate::testutil::Guard {
        crate::testutil::arm(WALK_WATCHDOG)
    }

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

    /// A zone with an arbitrary origin and no SOA, for the cases where the
    /// origin itself is the thing under test (notably `origin = "."`).
    fn zone_with_origin(origin: &str, records: Vec<RecordSpec>) -> Zone {
        Zone::from_config(&ZoneConfig {
            origin: origin.to_owned(),
            default_ttl: 300,
            builtins: false,
            soa: None,
            records,
        })
        .expect("zone should build")
    }

    /// A query name with exactly `labels` labels in total, ending in
    /// `example.com.`.
    ///
    /// Single-character prefix labels keep the wire form inside RFC 1035
    /// §2.3.4's 255-octet limit: at 123 labels the encoding is
    /// `121 * (1 + 1) + (1 + 7) + (1 + 3) + 1 = 255` octets exactly, which is
    /// the longest name that can reach `Zone::resolve` *under this origin*. The
    /// ceiling for the decoder is 127 labels, reached only by a name with no
    /// `example.com.` suffix to pay for; see
    /// `the_true_deepest_name_the_wire_can_carry_is_127_labels_and_is_answered`.
    fn deep_name(labels: usize) -> LowerName {
        let prefix = labels - 2;
        let mut s = String::with_capacity(prefix * 2 + 13);
        for _ in 0..prefix {
            s.push_str("a.");
        }
        s.push_str("example.com.");
        lower(&s)
    }

    /// The A rdata a synthesised answer is expected to carry.
    ///
    /// Through `rdata::parse_value` like everything else, so that hickory's
    /// presentation-format parser is named in exactly one module of this crate
    /// and `tests/single_gate.rs` can hold that claim to the ground.
    fn a(addr: &str) -> RData {
        rdata::parse_value(RecordType::A, "@", addr).expect("fixture address parses")
    }

    #[test]
    fn apex_a_record_resolves() {
        let _watchdog = watchdog();
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
        let _watchdog = watchdog();
        let z = zone(vec![spec("www", "A", &["203.0.113.20"])]);
        assert!(matches!(
            z.lookup(&lower("www.example.com."), RecordType::A),
            Answer::Records(_)
        ));
    }

    #[test]
    fn per_record_ttl_overrides_the_zone_default() {
        let _watchdog = watchdog();
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
        let _watchdog = watchdog();
        let z = zone(vec![spec("www", "A", &["203.0.113.20"])]);
        assert_eq!(
            z.lookup(&lower("www.example.com."), RecordType::AAAA),
            Answer::NoData
        );
    }

    #[test]
    fn missing_name_is_nxdomain() {
        let _watchdog = watchdog();
        let z = zone(vec![spec("www", "A", &["203.0.113.20"])]);
        assert_eq!(
            z.lookup(&lower("nope.example.com."), RecordType::A),
            Answer::NxDomain
        );
    }

    #[test]
    fn out_of_zone_name_is_nxdomain() {
        let _watchdog = watchdog();
        let z = zone(vec![]);
        assert_eq!(
            z.lookup(&lower("example.org."), RecordType::A),
            Answer::NxDomain
        );
    }

    #[test]
    fn cname_is_chased_within_the_zone() {
        let _watchdog = watchdog();
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
        let _watchdog = watchdog();
        let z = zone(vec![spec("cdn", "CNAME", &["cdn.provider.net."])]);
        let Answer::Records(records) = z.lookup(&lower("cdn.example.com."), RecordType::A) else {
            panic!("expected records");
        };
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record_type(), RecordType::CNAME);
    }

    #[test]
    fn cname_loop_terminates() {
        let _watchdog = watchdog();
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
        let _watchdog = watchdog();
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
        let _watchdog = watchdog();
        let z = zone(vec![
            spec("*.dev", "A", &["203.0.113.50"]),
            spec("special.dev", "A", &["203.0.113.51"]),
        ]);
        let Answer::Records(records) = z.lookup(&lower("special.dev.example.com."), RecordType::A)
        else {
            panic!("expected records");
        };
        assert_eq!(&records[0].data, &a("203.0.113.51"));
    }

    /// Scenario: A wildcard does not answer a type it was not configured for,
    /// but the name still exists
    /// features/wildcards.feature:106
    ///
    /// FLIPPED BY VEGA-083, and it was VEGA-010's enshrining test. It asserted
    /// `NxDomain`, which is what the code did, not what RFC 1034 §4.3.2 step
    /// 3(c) says: the authoritative name error is set **only** when the `*` node
    /// does not exist. `*.dev.example.com.` exists and holds no TXT, so control
    /// goes to step 6 — exit with an empty answer section — which is RFC 2308
    /// §2.2 NODATA. As NXDOMAIN the answer is cached for the SOA MINIMUM (RFC
    /// 2308 §5) and RFC 8020 §2 then licenses the resolver to deny the entire
    /// subtree, taking the wildcard's live A record out of service.
    #[test]
    fn wildcard_does_not_answer_a_different_type() {
        let _watchdog = watchdog();
        let z = zone(vec![spec("*.dev", "A", &["203.0.113.50"])]);
        assert_eq!(
            z.lookup(&lower("x.dev.example.com."), RecordType::TXT),
            Answer::NoData
        );
    }

    /// Scenario: An ANY query returns one synthetic HINFO, not the whole node
    /// features/zone-lookup.feature:154
    ///
    /// FLIPPED BY VEGA-083. This was `any_query_returns_every_type_at_the_name`,
    /// asserting that the zone layer enumerates the node for QTYPE=ANY. That arm
    /// is deleted: RFC 1035 §3.2.3 makes ANY a QTYPE and never an RRTYPE, so it
    /// can never key the record map, and RFC 8482 makes *what to answer* for it
    /// a responder policy that lives in `DnsHandler`. The zone layer reports
    /// existence and nothing else, which is also how the `O(zone)` scan behind
    /// it — 1.83 ms on a 100k-record zone — stops being one routing change away
    /// from the packet path.
    ///
    /// AXFR (VEGA-032) will need ordered node iteration. It will not get it from
    /// here; a caller that reads `NoData` as "the node is empty" is wrong.
    #[test]
    fn an_any_lookup_reports_existence_and_never_enumerates_the_node() {
        let _watchdog = watchdog();
        let z = zone(vec![
            spec("multi", "A", &["203.0.113.60"]),
            spec("multi", "TXT", &["\"hello\""]),
        ]);
        assert_eq!(
            z.lookup(&lower("multi.example.com."), RecordType::ANY),
            Answer::NoData,
            "the zone layer must report that the name exists, not enumerate it"
        );
        assert_eq!(
            z.lookup(&lower("nope.example.com."), RecordType::ANY),
            Answer::NxDomain,
            "and it must still distinguish a name that does not exist, or the \
             existence report is worthless"
        );
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
        let _watchdog = watchdog();
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

    /// A TXT value whose *presentation form* is exactly `chars` characters
    /// long, which is what `rdata::MAX_VALUE_CHARS` counts. Quoted, because
    /// hickory otherwise reads whitespace-free runs as separate
    /// character-strings and the length under test would not be one value.
    fn txt_of(chars: usize) -> String {
        let mut value = String::with_capacity(chars);
        value.push('"');
        for _ in 0..chars - 2 {
            value.push('x');
        }
        value.push('"');
        value
    }

    #[test]
    fn a_record_value_at_the_character_limit_is_accepted() {
        let _watchdog = watchdog();
        // Kills `chars > MAX_VALUE_CHARS` -> `>=` in the guard, which now lives
        // in `rdata::parse_value`. Kept here rather than moved there with it:
        // this asserts the *loader* is routed through the gate, which is the
        // half a unit test of `rdata` cannot see. The bound is inclusive — 4090
        // characters is the largest value an operator may write, and moving the
        // comparison one place rejects a config valid since the limit landed.
        let value = txt_of(rdata::MAX_VALUE_CHARS);
        let zone = Zone::from_config(&ZoneConfig {
            origin: "example.com".to_owned(),
            default_ttl: 300,
            builtins: false,
            soa: None,
            records: vec![spec("long", "TXT", &[&value])],
        })
        .expect("a value of exactly rdata::MAX_VALUE_CHARS characters must build");
        assert!(matches!(
            zone.lookup(&lower("long.example.com."), RecordType::TXT),
            Answer::Records(_)
        ));
    }

    #[test]
    fn a_record_value_over_the_character_limit_is_refused_however_far_over() {
        // Kills both `chars > MAX_VALUE_CHARS` -> `>=` (one past the bound must
        // fail) and -> `==` (a value *far* past the bound must fail too — an
        // `==` rejects only the single length 4090 and waves through every
        // larger one), and it kills them through the loader rather than through
        // `rdata` directly, so a zone that stopped calling the gate fails here.
        // Nothing in the suite asserted on this limit at all before mutation
        // testing, so the whole check could have been deleted silently.
        for over in [rdata::MAX_VALUE_CHARS + 1, rdata::MAX_VALUE_CHARS * 4] {
            let value = txt_of(over);
            let err = Zone::from_config(&ZoneConfig {
                origin: "example.com".to_owned(),
                default_ttl: 300,
                builtins: false,
                soa: None,
                records: vec![spec("long", "TXT", &[&value])],
            })
            .unwrap_err();
            let text = err.to_string();
            assert!(
                text.contains("characters; the maximum is"),
                "a {over}-character value must be refused by name, not by accident: {text}"
            );
            assert!(
                text.contains(&over.to_string()),
                "the error must tell the operator how long their value actually is: {text}"
            );
        }
    }

    #[test]
    fn a_fully_qualified_in_zone_record_name_is_accepted() {
        let _watchdog = watchdog();
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
        let _watchdog = watchdog();
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
        let _watchdog = watchdog();
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
        // Kills `mask &= !(1u128 << depth)` -> `|=`, and `||` -> `&&` in the
        // break condition of the `base_name()` climb this replaced. Both spin.
        //
        // This test used to bound a *channel* with `recv_timeout` and leave the
        // walk on a detached thread. That reports a failure and leaves the walk
        // spinning: `cargo test` returns while a core keeps burning, and a
        // mutation harness scores the mutant as a timeout instead of as caught —
        // so the mutants that produce this exact defect were the ones scored
        // wrong. The walk now runs on this thread and the guard is allowed to
        // end the process.
        //
        // THE FIXTURE IS AS LOAD-BEARING AS THE GUARD. This test used to ask a
        // zone holding only `*.dev` about `nope.example.com.`, and that probe
        // window is EMPTY: the query's parent depth is 2, the origin floor is
        // 2, so the window is bit 2 alone while the only wildcard sits at depth
        // 3 — `mask` is zero on entry and the loop body never executes. It
        // would pass with the whole walk deleted, and it did pass, measured,
        // against `mask |= !(1u128 << depth)`. Every name below is chosen to
        // enter the loop and then miss at every depth it probes; do not
        // "simplify" one back to a shallow name.
        let _watchdog = watchdog();
        let z = zone(vec![
            // Parents at depths 3 and 4, so a query can probe more than once.
            spec("*.dev", "A", &["203.0.113.50"]),
            spec("*.dev.ops", "A", &["203.0.113.51"]),
        ]);
        for query in [
            // Window is bits 2..=4, mask is bits 3 and 4: two probes, two
            // misses, then the loop must run out of bits.
            lower("q.w.e.example.com."),
            // One probe, one miss.
            lower("nope.other.example.com."),
            // The longest name that can reach `resolve` at all. This is the
            // shape that turned the old detached-thread guard into an
            // eleven-minute spinning orphan.
            deep_name(123),
        ] {
            assert_eq!(
                z.lookup(&query, RecordType::A),
                Answer::NxDomain,
                "{query} matches no wildcard, so the walk must exhaust its \
                 window and stop rather than spin"
            );
        }
    }

    #[test]
    fn a_cname_loop_is_cut_off_after_a_handful_of_hops() {
        let _watchdog = watchdog();
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
        let _watchdog = watchdog();
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
        let _watchdog = watchdog();
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
        let _watchdog = watchdog();
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
        let _watchdog = watchdog();
        // Kills the out-of-zone `Resolution::NxDomain` -> `NoData`.
        let z = zone(vec![spec("www", "A", &["203.0.113.20"])]);
        assert_eq!(
            z.lookup(&lower("www.example.org."), RecordType::A),
            Answer::NxDomain
        );
        assert_eq!(z.lookup(&lower("."), RecordType::NS), Answer::NxDomain);
    }

    // -----------------------------------------------------------------------
    // VEGA-065 — bounding the wildcard parent walk.
    //
    // Spec: features/wildcards.feature, section "BOUNDED WALK (VEGA-065)".
    // Ruling: .claude/backlog/decisions/VEGA-065-bounded-wildcard-walk.md
    //
    // GROUP A — BEHAVIOUR PRESERVATION. These four pass on today's naive
    // `base_name()` walk and must still pass once that walk is replaced by the
    // mandated `wildcard_depths` bitmap probe. They exist to discriminate
    // against the *rejected* patch, which derived depths from
    // `LowerName::num_labels()` — documented as "discounting `*`" — while
    // indexing with `Name::trim_to`, which counts raw labels. Mixing those two
    // index spaces shifts the probe one label off for every name whose leftmost
    // label is an asterisk, turning four correct answers into NXDOMAIN.
    //
    // Every one of the four therefore involves an asterisk in a position the
    // arithmetic is sensitive to. A test that only queries `x.dev.example.com.`
    // stays green through the regression and is worthless as a guard.
    // -----------------------------------------------------------------------

    #[test]
    fn an_apex_wildcard_answers_a_query_for_the_wildcard_name_itself() {
        let _watchdog = watchdog();
        // RFC 4592 §2.3: "When a wildcard domain name appears in a message's
        // query section, no special processing occurs." The QNAME is an
        // ordinary name that happens to contain an asterisk label, it matches
        // the existing node `*.example.com.`, and it is answered from it.
        //
        // DISCRIMINATES: `*.example.com.` has 3 raw labels but num_labels() == 2.
        // The rejected patch computes deepest = 2 - 1 = 1 and floor = 2, so
        // `while labels >= floor` is false on entry, it makes zero probes and
        // answers NXDOMAIN. `name.iter().len() - 1 == 2 >= floor` probes
        // trim_to(2) == `example.com.`, which is the apex wildcard's key.
        let z = zone(vec![spec("*", "A", &["203.0.113.1"])]);
        let Answer::Records(records) = z.lookup(&lower("*.example.com."), RecordType::A) else {
            panic!("an apex wildcard must answer a query for `*.example.com.` itself");
        };
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, parse_name("*.example.com.").unwrap());
        assert_eq!(records[0].data, a("203.0.113.1"));
    }

    #[test]
    fn a_wildcard_answers_a_query_for_its_own_name() {
        let _watchdog = watchdog();
        // Same rule one level down: `*.dev` is stored under `dev.example.com.`,
        // and a query for the literal name `*.dev.example.com.` walks to that
        // parent and is answered.
        //
        // DISCRIMINATES: the QNAME has 4 raw labels, num_labels() == 3. The
        // rejected patch computes deepest = 2, clamps to max_wildcard_labels = 3,
        // and probes trim_to(2) == `example.com.` — the wrong depth entirely,
        // because the key sits at raw depth 3. floor == 2 then ends the loop and
        // the answer is NXDOMAIN. The raw count probes trim_to(3) ==
        // `dev.example.com.` and hits.
        let z = zone(vec![spec("*.dev", "A", &["203.0.113.50"])]);
        let Answer::Records(records) = z.lookup(&lower("*.dev.example.com."), RecordType::A) else {
            panic!("`*.dev` must answer a query for `*.dev.example.com.` itself");
        };
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, parse_name("*.dev.example.com.").unwrap());
        assert_eq!(records[0].data, a("203.0.113.50"));
    }

    #[test]
    fn a_nested_asterisk_wildcard_still_synthesises() {
        let _watchdog = watchdog();
        // RFC 4592 §2.1.3 deleted RFC 1035 §4.3.3's "<anydomain> should not
        // contain other `*` labels" restriction: "A wildcard domain name can
        // have subdomains." Vega strips only the leftmost asterisk, so `*.*.dev`
        // is stored under the key `*.dev.example.com.`.
        //
        // DISCRIMINATES: that key has 4 raw labels but num_labels() == 3, so the
        // rejected patch records max_wildcard_labels = 3 and never probes depth
        // 4 — the wildcard is permanently unreachable and every query under it
        // is NXDOMAIN. This is a build-side miscount, independent of the
        // query-side one above.
        let z = zone(vec![spec("*.*.dev", "A", &["203.0.113.60"])]);
        let Answer::Records(records) = z.lookup(&lower("x.*.dev.example.com."), RecordType::A)
        else {
            panic!("`*.*.dev` must synthesise for `x.*.dev.example.com.` (RFC 4592 §2.1.3)");
        };
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, parse_name("x.*.dev.example.com.").unwrap());
        assert_eq!(records[0].data, a("203.0.113.60"));
    }

    #[test]
    fn a_query_for_the_nested_wildcard_name_itself_is_answered() {
        let _watchdog = watchdog();
        // The two miscounts compounded: the key `*.dev.example.com.` is one
        // short on the build side *and* the QNAME `*.*.dev.example.com.`
        // (5 raw labels, num_labels() == 4) is one short on the query side.
        //
        // DISCRIMINATES: the rejected patch probes trim_to(3) and trim_to(2) and
        // never trim_to(4) where the key lives, so it answers NXDOMAIN. Kept
        // separate from the test above because it fails through a different
        // pair of arithmetic errors and a fix for one does not fix the other.
        let z = zone(vec![spec("*.*.dev", "A", &["203.0.113.60"])]);
        let Answer::Records(records) = z.lookup(&lower("*.*.dev.example.com."), RecordType::A)
        else {
            panic!("`*.*.dev` must answer a query for `*.*.dev.example.com.` itself");
        };
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, parse_name("*.*.dev.example.com.").unwrap());
        assert_eq!(records[0].data, a("203.0.113.60"));
    }

    // ----------------------------------------- GROUP A2: walk shape and order

    #[test]
    fn an_apex_wildcard_covers_a_name_many_labels_deep() {
        let _watchdog = watchdog();
        // The bitmap probe must still reach the origin depth from a name far
        // below it. Kills a window whose floor is computed from the query name
        // rather than the origin.
        let z = zone(vec![spec("*", "A", &["203.0.113.1"])]);
        let Answer::Records(records) = z.lookup(&lower("a.b.c.d.e.example.com."), RecordType::A)
        else {
            panic!("an apex wildcard covers every name below the origin");
        };
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].name,
            parse_name("a.b.c.d.e.example.com.").unwrap()
        );
    }

    #[test]
    fn the_deepest_wildcard_wins_when_several_could_match() {
        let _watchdog = watchdog();
        // Today's walk starts at the query name's parent and descends, so the
        // closest wildcard answers. The bitmap must be consumed deepest-set-bit
        // first to preserve that. Kills `leading_zeros` -> `trailing_zeros`,
        // which would serve the apex wildcard's address here.
        //
        // (Deepest-wins is not RFC 4592's closest-encloser rule — that defect is
        // VEGA-009. Preserving today's answer is the whole point of VEGA-065.)
        let z = zone(vec![
            spec("*", "A", &["203.0.113.1"]),
            spec("*.dev", "A", &["203.0.113.50"]),
        ]);
        let Answer::Records(records) = z.lookup(&lower("x.dev.example.com."), RecordType::A) else {
            panic!("expected a synthesised answer");
        };
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].data,
            a("203.0.113.50"),
            "the closest wildcard must win; got the apex wildcard's address"
        );
    }

    #[test]
    fn wildcards_at_non_adjacent_depths_are_both_reachable() {
        let _watchdog = watchdog();
        // Depths 2 (the apex `*`) and 8 (`*.a.b.c.d.e.f`), with five empty
        // depths between them. A `max_wildcard_labels` bound handles this by
        // probing the whole range; the bitmap handles it by construction. Both
        // wildcards must answer, and neither may shadow the other.
        let z = zone(vec![
            spec("*", "A", &["203.0.113.1"]),
            spec("*.a.b.c.d.e.f", "A", &["203.0.113.8"]),
        ]);

        let Answer::Records(deep) = z.lookup(&lower("x.a.b.c.d.e.f.example.com."), RecordType::A)
        else {
            panic!("the depth-8 wildcard must answer names below it");
        };
        assert_eq!(deep[0].data, a("203.0.113.8"));

        let Answer::Records(shallow) = z.lookup(&lower("x.example.com."), RecordType::A) else {
            panic!("the apex wildcard must still answer names below the origin");
        };
        assert_eq!(shallow[0].data, a("203.0.113.1"));
    }

    #[test]
    fn wildcards_at_one_two_and_three_levels_are_each_reachable() {
        let _watchdog = watchdog();
        // The failure mode the ruling calls the worst one: `wildcard_depths`
        // silently out of step with the `wildcard` map produces NXDOMAIN for a
        // configured wildcard, with nothing in the logs. Every populated depth
        // gets queried here so a missing `|=` cannot hide.
        let z = zone(vec![
            spec("*", "A", &["203.0.113.1"]),
            spec("*.one", "A", &["203.0.113.2"]),
            spec("*.one.two", "A", &["203.0.113.3"]),
        ]);
        for (query, want) in [
            ("x.example.com.", "203.0.113.1"),
            ("x.one.example.com.", "203.0.113.2"),
            ("x.one.two.example.com.", "203.0.113.3"),
        ] {
            let Answer::Records(records) = z.lookup(&lower(query), RecordType::A) else {
                panic!("{query} must be answered by its configured wildcard");
            };
            assert_eq!(records[0].data, a(want), "wrong wildcard answered {query}");
        }
    }

    #[test]
    fn a_wildcard_thirty_labels_deep_is_still_reachable() {
        // MAX_LABELS is 127 because RFC 1035 §2.3.4 caps a name at 255 octets
        // and §3.1's length-octet encoding gives 2n + 1 <= 255. Nothing else in
        // the suite would notice that constant being shrunk: a wildcard at the
        // apex is reachable under any ceiling above 2, so a `MAX_LABELS = 24`
        // would sail through every other test here while quietly making deep
        // wildcards — legitimate under RFC 4592 — unreachable.
        //
        // 30 labels is comfortably past a plausible wrong value and comfortably
        // inside the octet limit: 28 * 2 + 8 + 4 + 1 = 69.
        const DEPTH: usize = 30;

        let _watchdog = watchdog();
        let parent: String = std::iter::repeat_n("a", DEPTH - 2)
            .collect::<Vec<_>>()
            .join(".");
        let z = zone(vec![spec(&format!("*.{parent}"), "A", &["203.0.113.30"])]);

        let query = lower(&format!("x.{parent}.example.com."));
        let Answer::Records(records) = z.lookup(&query, RecordType::A) else {
            panic!("a wildcard whose parent is {DEPTH} labels deep must still answer");
        };
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].data, a("203.0.113.30"));
        assert_eq!(LowerName::from(records[0].name.clone()), query);
    }

    // ------------------------------------------- GROUP C: boundary and hostile

    #[test]
    fn a_maximum_length_query_name_is_answered() {
        let _watchdog = watchdog();
        // 123 labels is the most a name under `example.com.` can carry inside
        // RFC 1035 §2.3.4's 255 octets, and therefore the most that can ever
        // reach `Zone::resolve`. MAX_LABELS = 127 must leave this in range and
        // `1u128 << depth` must not overflow at it.
        let z = zone(vec![spec("*", "A", &["203.0.113.1"])]);
        let name = deep_name(123);
        let Answer::Records(records) = z.lookup(&name, RecordType::A) else {
            panic!("a maximum-length name under a wildcard must be answered");
        };
        assert_eq!(records.len(), 1);
        assert_eq!(LowerName::from(records[0].name.clone()), name);
    }

    /// Scenario: A maximum-length query name of a type no wildcard holds is NODATA
    /// features/wildcards.feature:402
    ///
    /// FLIPPED BY VEGA-083, and owned by VEGA-065. The type-mismatch path at
    /// maximum depth: the walk runs its full window, hits nothing, and must
    /// return rather than run off the end of the bitmap. That boundary — the
    /// shift at the deepest depth the window can reach — is exactly what this
    /// test is for and is **unchanged**; only the verdict moves, from NXDOMAIN
    /// to NODATA, because the apex `*` is a source of synthesis for this name
    /// (RFC 1034 §4.3.2 step 3(c)). The old comment already said as much: it
    /// called the NXDOMAIN "VEGA-010's defect, pinned as-is".
    #[test]
    fn a_maximum_length_query_name_of_the_wrong_type_is_nodata() {
        let _watchdog = watchdog();
        let z = zone(vec![spec("*", "A", &["203.0.113.1"])]);
        assert_eq!(z.lookup(&deep_name(123), RecordType::TXT), Answer::NoData);
    }

    /// Scenario: A name with the maximum legal number of labels does not panic
    /// the lookup
    /// features/zone-lookup.feature:360
    ///
    /// Scenario: The deepest name the wire can carry is 127 labels, and it is
    /// answered
    /// features/zone-data-model.feature:455
    #[test]
    fn the_true_deepest_name_the_wire_can_carry_is_127_labels_and_is_answered() {
        // CORRECTS a boundary the rest of this module gets wrong. `deep_name`
        // and `tests/perf_budget.rs` both call 123 labels "the most that can
        // ever reach `Zone::resolve`", but 123 is only the ceiling for names
        // under `example.com.`, whose 13-octet suffix eats the budget. The
        // ceiling for the *decoder* is 127: RFC 1035 §3.1 encodes a
        // single-octet label in two octets and terminates with one, so
        // 127 * 2 + 1 = 255 exactly. Measured against hickory 0.26.1 — a
        // hand-built 271-byte query carrying 127 one-octet labels decodes to a
        // 127-label name, and 128 labels is rejected with
        // `name label data exceed 255`.
        //
        // That matters because `wildcard_window` computes `1u128 << (start + 1)`
        // with `start = labels - 1`, so this is the input that drives the shift
        // to its largest reachable value, 127. A shift of 128 aborts the process
        // under `panic = "abort"`. Nothing else in the suite goes past 123.
        let _watchdog = watchdog();
        let z = zone_with_origin(".", vec![spec("*", "A", &["203.0.113.1"])]);
        let name = lower(&("a.".repeat(127)));
        assert_eq!(
            label_count(&name),
            127,
            "the fixture must be at the decoder's ceiling, not near it"
        );

        let Answer::Records(records) = z.lookup(&name, RecordType::A) else {
            panic!("a 127-label name is decodable off the wire and must be answered");
        };
        assert_eq!(records.len(), 1);
        assert_eq!(LowerName::from(records[0].name.clone()), name);
    }

    #[test]
    fn a_wildcard_parent_at_the_label_ceiling_is_registered_not_silently_dropped() {
        // The bit-127 boundary of `wildcard_depths`, which nothing else reaches.
        //
        // `MAX_LABELS: 127 -> 126`, `127 -> 128` and `depth <= MAX_LABELS` ->
        // `<` ALL SURVIVED the whole suite before this test existed. Each drops
        // a wildcard out of the depth bitmap while leaving it in `self.wildcard`
        // — a configured wildcard that is silently unreachable for the life of
        // the process, with nothing in the logs.
        //
        // The ceiling is hard-coded rather than written as `MAX_LABELS`, because
        // a test that builds its fixture from the constant it is checking moves
        // with the mutation and pins nothing. 127 is derived, not tuned: RFC
        // 1035 §2.3.4 caps a name at 255 octets and §3.1 spends two octets on a
        // single-character label plus one terminator, so 2n + 1 <= 255.
        const CEILING: usize = 127;

        let _watchdog = watchdog();
        assert_eq!(
            MAX_LABELS, CEILING,
            "MAX_LABELS is the arithmetic consequence of RFC 1035 §2.3.4 and \
             §3.1, and it is also the highest bit of the u128 the depth bitmap \
             lives in. Moving it is not a tuning decision"
        );

        // 127 single-octet labels in a root-origin zone is 255 octets exactly:
        // the deepest wildcard parent that can be configured at all.
        let parent = std::iter::repeat_n("a", CEILING)
            .collect::<Vec<_>>()
            .join(".");
        let z = zone_with_origin(
            ".",
            vec![spec(&format!("*.{parent}"), "A", &["203.0.113.1"])],
        );

        assert_ne!(
            z.wildcard_depths & (1u128 << CEILING),
            0,
            "a wildcard whose parent sits at exactly {CEILING} labels was left \
             out of the depth bitmap; it is in the wildcard map and the walk \
             will never probe for it"
        );
    }

    #[test]
    fn the_wildcard_probe_window_never_reaches_below_the_origin() {
        // `wildcard_window` documents two bounds. The upper one — the query's
        // parent depth, because RFC 4592 §3.3.1 makes a wildcard's parent a
        // *proper* ancestor — is exercised by every wildcard test here. The
        // lower one is not, and dropping it (`hi & !((1 << floor) - 1)` -> `hi`)
        // SURVIVED the entire suite: no wildcard can be registered above the
        // origin, because `qualify` refuses to build an out-of-zone key, so the
        // extra bits never intersect `wildcard_depths` and no answer changes.
        //
        // The bound is still a contract, and the redundancy that hides it is
        // exactly the kind that stops being true when somebody adds a second
        // insertion point. Asserted on the function rather than through
        // `lookup`, which is the only place it is visible.
        let _watchdog = watchdog();
        let z = zone_with_origin(
            "a.b.c.d.example.com",
            vec![spec("*", "A", &["203.0.113.1"])],
        );

        // Eight labels queried, so the parent depth is 7; the origin is six
        // labels, so the floor is 6. Bits 6 and 7, and nothing else.
        let window = z.wildcard_window(&lower("x.y.a.b.c.d.example.com."));
        assert_eq!(
            window,
            (1u128 << 6) | (1u128 << 7),
            "the probe window must be exactly [origin depth, query parent depth]; \
             got {window:#034x}"
        );
        assert_eq!(
            window & ((1u128 << 6) - 1),
            0,
            "the window reaches below the origin: every one of those depths is a \
             guaranteed miss, and a key there would be outside the zone we are \
             authoritative for"
        );
    }

    #[test]
    fn a_zone_with_no_wildcards_never_probes() {
        let _watchdog = watchdog();
        // `wildcard_depths == 0` replaces `!self.wildcard.is_empty()` as the
        // "are there any wildcards" test. A deep NXDOMAIN in a wildcard-free
        // zone must stay a plain miss — this is the 1.13 µs control against
        // which the 174.7 µs wildcard case in VEGA-065 was measured.
        let z = zone(vec![spec("www", "A", &["203.0.113.20"])]);
        assert_eq!(z.lookup(&deep_name(123), RecordType::A), Answer::NxDomain);
        assert_eq!(
            z.lookup(&lower("nope.example.com."), RecordType::A),
            Answer::NxDomain
        );
    }

    #[test]
    fn a_name_above_the_origin_is_nxdomain_even_with_a_wildcard_present() {
        let _watchdog = watchdog();
        // `com.` is a proper ancestor of the origin, not a descendant, so the
        // probe window is empty: its start (the query's parent depth, 0) is
        // below the floor (the origin depth, 2). Kills a `wildcard_window` that
        // forgets the `start < floor` guard and shifts by a negative width, and
        // kills `start`/`floor` swapped — either would probe outside the zone.
        let z = zone(vec![spec("*", "A", &["203.0.113.1"])]);
        assert_eq!(z.lookup(&lower("com."), RecordType::A), Answer::NxDomain);
        assert_eq!(z.lookup(&lower("."), RecordType::A), Answer::NxDomain);
    }

    /// Scenario: A root-origin zone with a wildcard terminates on a miss
    /// features/wildcards.feature:458
    ///
    /// FLIPPED BY VEGA-083, and owned by VEGA-065. `origin = "."` is accepted by
    /// `parse_name`, and it drives the walk's floor to 0. The rejected patch's
    /// `while labels >= floor { … labels -= 1 }` shape only survives that
    /// because of an extra `if labels == 0 { break }`; a bitmap loop that clears
    /// the bit it just probed terminates structurally. Bounded by the process
    /// watchdog, not by a channel, so a non-terminating walk fails this test
    /// rather than leaking a thread — **that is the property under test and it
    /// is unchanged.**
    ///
    /// The verdict moves from NXDOMAIN to NODATA because with `origin = "."` the
    /// `*` sits at depth 0, which the window includes, so `nope.example.com.`
    /// genuinely has a source of synthesis and RFC 1034 §4.3.2 step 3(c) forbids
    /// the name error. A walk that spun would never reach either answer.
    #[test]
    fn a_root_origin_zone_terminates_on_a_wildcard_miss() {
        let _watchdog = watchdog();
        let z = zone_with_origin(".", vec![spec("*", "A", &["203.0.113.1"])]);
        assert_eq!(
            z.lookup(&lower("nope.example.com."), RecordType::TXT),
            Answer::NoData
        );
    }

    #[test]
    fn a_root_origin_wildcard_answers_a_name_it_covers() {
        // The other half: with floor == 0 the window must still include depth 0,
        // or a root-origin zone's apex wildcard becomes unreachable. Also
        // guarded, because the failure mode of a bad floor is a spin.
        let _watchdog = watchdog();
        let z = zone_with_origin(".", vec![spec("*", "A", &["203.0.113.1"])]);
        let answer = z.lookup(&lower("nope.example.com."), RecordType::A);
        let Answer::Records(records) = answer else {
            panic!("a `*` in a root-origin zone must cover `nope.example.com.`");
        };
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, parse_name("nope.example.com.").unwrap());
    }

    // -----------------------------------------------------------------------
    // VEGA-083 — a wildcard-covered name exists for every QTYPE.
    //
    // Spec: features/zone-lookup.feature, section "WILDCARD-COVERED NAMES";
    //       features/wildcards.feature, section "WRONG TYPE".
    // Ruling: .claude/backlog/decisions/VEGA-083-any-at-a-wildcard-covered-name.md
    //
    // RFC 1034 §4.3.2 step 3(c) sets the authoritative name error *only* when
    // the `*` node does not exist. When it exists and no RR matches QTYPE,
    // control goes to step 6: exit, empty answer section, NOERROR. That branch
    // is not conditioned on QTYPE anywhere, which is why the determination for
    // ANY must be the same computation as the one for AAAA (RFC 8482 §4.1/§4.2
    // change the answer section and license no RCODE change), and why RFC 4035
    // §3.1.3.4 and RFC 5155 §7.2.5 define a whole class of authenticated-denial
    // proof for "wildcard no data" — machinery that would not exist if the
    // answer were a name error.
    //
    // The operational half: AAAA, not ANY, is what fires. Every dual-stack
    // client sends one alongside every A, so the ordinary resolution of a
    // covered name emitted an authoritative NXDOMAIN carrying the SOA, cached
    // for the SOA MINIMUM (RFC 2308 §5), and RFC 8020 §2 then licensed the
    // resolver to deny the whole subtree. No attacker required.
    // -----------------------------------------------------------------------

    /// Scenario: A wildcard answers the type it carries
    /// features/zone-lookup.feature:230
    ///
    /// The positive control, and it is not decorative: every other test in this
    /// section asserts that something is *not* NXDOMAIN, and a fix that simply
    /// stopped synthesising would satisfy all of them while taking the
    /// wildcard's records out of service.
    #[test]
    fn a_wildcard_still_answers_the_type_it_carries() {
        let _watchdog = watchdog();
        let z = zone(vec![spec("*.dev", "A", &["203.0.113.50"])]);
        let Answer::Records(records) = z.lookup(&lower("x.dev.example.com."), RecordType::A) else {
            panic!("`*.dev A` must still synthesise an A record for a covered name");
        };
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].data, a("203.0.113.50"));
        assert_eq!(records[0].name, parse_name("x.dev.example.com.").unwrap());
    }

    /// Scenario: A wildcard-covered name exists for every type, not only the one
    /// the wildcard carries
    /// features/zone-lookup.feature:240
    ///
    /// AAAA is first on purpose: it is the type ordinary traffic asks for, so it
    /// is the one that must go red first if this regresses. TXT, MX and SRV are
    /// there because the defect was in the *walk*, not in any per-type branch,
    /// and a single-type test cannot tell those apart.
    #[test]
    fn a_wildcard_covered_name_is_nodata_for_every_type_the_wildcard_does_not_carry() {
        let _watchdog = watchdog();
        let z = zone(vec![spec("*.dev", "A", &["203.0.113.50"])]);
        for qtype in [
            RecordType::AAAA,
            RecordType::TXT,
            RecordType::MX,
            RecordType::SRV,
        ] {
            assert_eq!(
                z.lookup(&lower("x.dev.example.com."), qtype),
                Answer::NoData,
                "{qtype} at a name covered by `*.dev` must be RFC 2308 §2.2 \
                 NODATA; as NXDOMAIN it is cached for the SOA MINIMUM and, under \
                 RFC 8020 §2, denies the whole subtree including the wildcard's \
                 own A record"
            );
        }
    }

    /// Scenario: An ANY query at a wildcard-covered name is NOERROR with the RFC
    /// 8482 HINFO
    /// features/zone-lookup.feature:257
    ///
    /// The zone-layer half of that scenario: the handler decides what goes in
    /// the answer section, but it can only do so for a name the zone says
    /// exists. This is the third of the three sites that used `names` as the
    /// existence oracle — the `pub`-reachable `Zone::lookup(_, ANY)` arm — and
    /// it is the one no packet reached, which is exactly why it went unnoticed.
    #[test]
    fn an_any_lookup_at_a_wildcard_covered_name_is_nodata_not_nxdomain() {
        let _watchdog = watchdog();
        let z = zone(vec![spec("*.dev", "A", &["203.0.113.50"])]);
        assert_eq!(
            z.lookup(&lower("x.dev.example.com."), RecordType::ANY),
            Answer::NoData,
            "RFC 8482 changes the answer section, not the existence \
             determination, so ANY here must agree with AAAA"
        );
    }

    /// Scenario: A name with no source of synthesis is still NXDOMAIN
    /// features/zone-lookup.feature:268
    ///
    /// The negative control. Without it, "never answer NXDOMAIN" passes every
    /// other test in this section — and a server that never denies a name is
    /// authoritative for every label an attacker can invent.
    #[test]
    fn a_name_with_no_source_of_synthesis_is_still_nxdomain() {
        let _watchdog = watchdog();
        let z = zone(vec![spec("*.dev", "A", &["203.0.113.50"])]);
        for qtype in [RecordType::A, RecordType::AAAA, RecordType::ANY] {
            assert_eq!(
                z.lookup(&lower("x.prod.example.com."), qtype),
                Answer::NxDomain,
                "nothing covers `x.prod.example.com.`, so {qtype} there is a real \
                 name error (RFC 1034 §4.3.2 step 3(c))"
            );
        }
    }

    /// Scenario: Coverage is decided by the wildcard's own parent, not by its
    /// depth
    /// features/zone-lookup.feature:276
    ///
    /// THE DISCRIMINATING TEST OF THIS ISSUE. The obvious wrong shortcut is to
    /// read coverage off `wildcard_depths` alone — the bitmap is already loaded,
    /// already masked by the window, and the loop already knows which depths it
    /// probed. But the bitmap says "a wildcard exists *somewhere* at depth d",
    /// not "at *this* parent". Deriving coverage from it makes every name whose
    /// parent happens to sit at a populated depth exist, which in a zone with an
    /// apex wildcard is very nearly every name there is.
    ///
    /// The failure is silent and it is the dangerous direction for a different
    /// reason than the bug: the server stops denying names it is authoritative
    /// for, so typos and probes resolve to empty answers and nothing in the log
    /// says so.
    ///
    /// It fails in BOTH directions, which is what makes it worth its length:
    /// the first half fails against the depths-alone shortcut, the second half
    /// fails against today's code and against any "fix" that simply stops
    /// covering anything.
    #[test]
    fn coverage_is_decided_by_the_wildcard_parent_not_by_its_depth() {
        let _watchdog = watchdog();
        // `dev.example.com.` and `one.two.example.com.` are wildcard parents at
        // depths 3 and 4. `other.example.com.` and `x.y.example.com.` are not
        // wildcard parents, and sit at exactly those same depths.
        let z = zone(vec![
            spec("*.dev", "A", &["203.0.113.50"]),
            spec("*.one.two", "A", &["203.0.113.51"]),
        ]);

        for (name, depth) in [("q.other.example.com.", 3), ("q.x.y.example.com.", 4)] {
            for qtype in [RecordType::A, RecordType::AAAA, RecordType::ANY] {
                assert_eq!(
                    z.lookup(&lower(name), qtype),
                    Answer::NxDomain,
                    "{name}'s parent is at depth {depth}, where this zone does \
                     hold a wildcard — but not at *that* name. Coverage read off \
                     the depth bitmap alone makes it exist, and with it almost \
                     every name in the zone"
                );
            }
        }

        // The other direction, so this cannot be satisfied by covering nothing.
        for (name, depth) in [("q.dev.example.com.", 3), ("q.one.two.example.com.", 4)] {
            assert_eq!(
                z.lookup(&lower(name), RecordType::AAAA),
                Answer::NoData,
                "{name} IS under the wildcard parent at depth {depth} and must \
                 exist for every type"
            );
        }
    }

    // -----------------------------------------------------------------------
    // VEGA-032 S0/S1 — the boundaries the arena rewrite must not move.
    //
    // Spec: features/zone-data-model.feature, sections "S0 — THE SUFFIX HASH"
    //       and "S1 — THE ARENA, BEHAVIOUR-PRESERVING".
    // Ruling: .claude/backlog/decisions/VEGA-032-zone-data-model.md §13 AC-1.9
    //
    // These pass today. They are here *before* the rewrite, not after it,
    // because each one is an input shape the arena has a new way to get wrong:
    // S0's suffix hash writes into a `[u64; MAX_LABELS + 1]` indexed by a label
    // count taken from a name an attacker chose, and S1 reads every arena range
    // through a slice. Under `panic = "abort"` one out-of-range index is a full
    // outage from one packet, and the shapes below are the ones that reach the
    // largest index and the longest octet run the wire can carry.
    //
    // The rest of the suite works in labels; two of these work in octets, which
    // is a different bound and is where a buffer sized from the wrong one
    // breaks.
    // -----------------------------------------------------------------------

    /// Scenario: A name of maximum-length labels is answered rather than
    /// mis-indexed
    /// features/zone-data-model.feature:215
    ///
    /// Scenario: A query name at exactly 255 octets is answered
    /// features/zone-data-model.feature:465
    ///
    /// RFC 1035 §2.3.4 gives two independent limits — 63 octets per label and
    /// 255 octets per name — and every depth test in this tree exercises only
    /// the second, through names made of single-octet labels. A name can sit at
    /// the octet ceiling with **four** labels, and a hash pass that walked
    /// octets where it meant labels, or sized a buffer from `name.len()` where
    /// it meant `iter().len()`, is wrong here and correct everywhere else the
    /// suite looks.
    ///
    /// Root origin, because 255 octets leaves nothing to pay for a zone suffix.
    #[test]
    fn a_query_name_at_the_octet_ceiling_is_answered_rather_than_mis_indexed() {
        let _watchdog = watchdog();
        let z = zone_with_origin(".", vec![spec("*", "A", &["203.0.113.1"])]);

        // Three labels at the per-label ceiling: 3 * (1 + 63) + 1 = 193 octets.
        let max_label = "a".repeat(63);
        let three = format!("{max_label}.{max_label}.{max_label}.");
        // Four labels landing on the name ceiling exactly:
        // 3 * (1 + 63) + (1 + 61) + 1 = 255.
        let tail = "b".repeat(61);
        let at_limit = format!("{max_label}.{max_label}.{max_label}.{tail}.");

        // `Name::len()` counts the length octet and the content of each label
        // and stops there; the wire form adds one terminating zero, which is
        // what the 255-octet limit counts. Measured against hickory-proto
        // 0.26.1: three 63-octet labels report 192 and four report 256, and the
        // rejection for the latter names 257 — the terminator included.
        for (label, text, wire_octets, labels) in [
            ("three 63-octet labels", three, 193, 3),
            ("exactly 255 octets", at_limit, 255, 4),
        ] {
            let name = lower(&text);
            let parsed = parse_name(&text).expect("fixture parses");
            assert_eq!(
                parsed.len() + 1,
                wire_octets,
                "{label}: the fixture must sit at the boundary it names, or it \
                 tests a shape the wire cannot carry"
            );
            assert_eq!(label_count(&name), labels, "{label}: label count");

            let Answer::Records(records) = z.lookup(&name, RecordType::A) else {
                panic!("{label}: a name the apex wildcard covers must be answered");
            };
            assert_eq!(records.len(), 1, "{label}");
            assert_eq!(
                LowerName::from(records[0].name.clone()),
                name,
                "{label}: the synthesised owner must be the queried name"
            );
        }
    }

    /// Scenario: A zone holding nothing but its apex answers every shape without
    /// panicking
    /// features/zone-data-model.feature:414
    ///
    /// The smallest arena that can exist: one node, no RRsets, no wildcards, and
    /// an empty bucket for every probe. Every branch of the lookup is reachable
    /// on it and each one is an opportunity to index an empty slice or to walk a
    /// zero-length range — the ruling's §6.2 bars `[]` indexing on any
    /// packet-reachable path for exactly this reason.
    ///
    /// It also pins the two answers that must survive an empty zone: the apex
    /// exists (or a bare `SOA example.com.` would be NXDOMAIN about our own
    /// zone), and nothing else does.
    #[test]
    fn a_zone_holding_only_its_apex_answers_every_shape_without_panicking() {
        let _watchdog = watchdog();
        let z = zone(Vec::new());

        assert!(
            z.exists(&lower("example.com.")),
            "the apex must exist even in an empty zone, or a query for our own \
             origin answers NXDOMAIN about a zone we are authoritative for"
        );

        for (label, name, qtype, expected) in [
            ("the apex", "example.com.", RecordType::A, Answer::NoData),
            (
                "the apex, ANY",
                "example.com.",
                RecordType::ANY,
                Answer::NoData,
            ),
            (
                "below it",
                "nope.example.com.",
                RecordType::A,
                Answer::NxDomain,
            ),
            (
                "below it, ANY",
                "nope.example.com.",
                RecordType::ANY,
                Answer::NxDomain,
            ),
            ("above it", "com.", RecordType::A, Answer::NxDomain),
            ("the root", ".", RecordType::A, Answer::NxDomain),
            (
                "an asterisk-leading name",
                "*.example.com.",
                RecordType::A,
                Answer::NxDomain,
            ),
        ] {
            assert_eq!(z.lookup(&lower(name), qtype), expected, "{label}: {name}");
        }

        // The deep shape too: an empty zone is where a walk with nothing to
        // find runs its full window.
        assert_eq!(z.lookup(&deep_name(123), RecordType::A), Answer::NxDomain);
        assert_eq!(z.record_count(), 0);
    }

    // ------------------------------------------------- source-level guards
    //
    // Two contracts of this issue are properties of the *source*, not of any
    // answer, and both are invisible to every behavioural test in the tree. They
    // are checked against `include_str!` of this module, so they cost nothing at
    // runtime and fail at the moment the source stops holding them.

    /// The text of this module, read at compile time.
    const THIS_MODULE: &str = include_str!("zone.rs");

    /// Scenario: not a behaviour — AC-9 of the VEGA-083 ruling.
    ///
    /// Three `#[ignore]`d tests below pin RFC 4592 / RFC 2308 non-conformance
    /// that VEGA-083 must **not** fix: empty non-terminals (VEGA-006), the
    /// closest-encloser rule (VEGA-009), and the empty non-terminal a wildcard
    /// implies at its own parent (VEGA-006 again). The ruling traces by hand
    /// that all three stay red under the mandated diff — the third structurally,
    /// because RFC 4592 §3.3.1 makes a wildcard's parent a proper ancestor of
    /// the names it covers and the probe window is capped at the query's parent
    /// depth, so a wildcard can never declare its own parent covered.
    ///
    /// If one of them turns green, the change went outside its fence and the
    /// change is wrong, not the test. The cheapest way to hide that is to edit
    /// or drop an `ignore` reason while rewriting the tests around it, so the
    /// reasons are pinned verbatim here. The expected text is spliced from
    /// `concat!` fragments on purpose: a literal copy would match itself in
    /// `THIS_MODULE` and the guard would pass against a deleted attribute.
    #[test]
    fn the_three_rfc_bugs_this_fix_must_not_touch_are_still_ignored_with_their_reasons() {
        let expected: [(&str, &str); 3] = [
            (
                "an_empty_non_terminal_is_nodata_not_nxdomain",
                concat!(
                    "BUG: empty non-terminals answer NXDOMAIN instead of NODATA ",
                    "(RFC 2308 s2.2.1)"
                ),
            ),
            (
                "a_wildcard_does_not_apply_below_a_name_that_exists",
                concat!(
                    "BUG: a wildcard is applied below a name that exists ",
                    "(RFC 4592 s3.3.1)"
                ),
            ),
            (
                "the_parent_of_a_wildcard_is_not_nxdomain",
                concat!(
                    "BUG: an empty non-terminal created by a wildcard is ",
                    "NXDOMAIN too"
                ),
            ),
        ];

        let lines: Vec<&str> = THIS_MODULE.lines().collect();
        for (name, reason) in expected {
            let needle = format!("fn {name}(");
            let at = lines
                .iter()
                .position(|line| line.contains(&needle))
                .unwrap_or_else(|| {
                    panic!(
                        "{name} is gone from this module. It pins a known RFC \
                         defect that VEGA-083 is fenced away from; deleting it \
                         is how that fence stops being checked"
                    )
                });
            let attribute = format!("#[ignore = \"{reason}\"]");
            assert!(
                lines[at.saturating_sub(3)..at]
                    .iter()
                    .any(|line| line.trim() == attribute),
                "{name} is no longer `{attribute}`. Either it turned green — in \
                 which case the change went outside VEGA-083's fence and the \
                 change is wrong — or its reason drifted, which is how the next \
                 reader loses the RFC citation"
            );
        }
    }

    /// Scenario: not a behaviour — AC-10 of the VEGA-083 ruling.
    ///
    /// `LowerName::num_labels()` is documented as counting labels *discounting*
    /// a leading `*`, while `Name::trim_to` indexes raw labels. Mixing the two
    /// shifts every wildcard probe one label off for any name whose leftmost
    /// label is an asterisk, which is four silent wrong answers on the
    /// authoritative path (VEGA-065). The ban is stated in the doc comment on
    /// `label_count`; this is what makes it a check rather than a hope.
    ///
    /// The needle is spliced so that the assertion cannot match itself.
    #[test]
    fn the_banned_label_counting_function_is_not_used_in_this_module() {
        let needle = concat!("num_", "labels");
        let offenders: Vec<(usize, &str)> = THIS_MODULE
            .lines()
            .enumerate()
            .filter(|(_, line)| line.contains(needle))
            .filter(|(_, line)| {
                // Comments explaining the ban are the point; code is not.
                let trimmed = line.trim_start();
                !(trimmed.starts_with("//") || trimmed.starts_with('*'))
            })
            .map(|(i, line)| (i + 1, line.trim()))
            .collect();
        assert!(
            offenders.is_empty(),
            "`{needle}` is banned in this module — it counts a leading asterisk \
             differently from `trim_to`, which is the index space the wildcard \
             depth bitmap uses. Use `label_count`. Found at {offenders:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Known bugs, written against the RFC. These fail today and are ignored so
    // the suite stays green until the behaviour is fixed.
    //
    // VEGA-065 NOTE — DO NOT UN-IGNORE THESE. They pin RFC 4592 / RFC 2308
    // non-conformance owned by VEGA-006 and VEGA-009 and fixed by VEGA-032 (the
    // zone data model rewrite), not by bounding the wildcard walk. VEGA-065 is
    // strictly behaviour-preserving, so if one of them turns green the walk
    // changed behaviour and the change is wrong. Fix the walk, not the test.
    //
    // VEGA-083 NOTE — these stay red under it too, and it is NOT
    // behaviour-preserving: it turns NXDOMAIN into NODATA for names a wildcard
    // covers. The empty-non-terminal zone holds no wildcards, so it makes zero
    // probes; the wildcard-below-an-existing-name case is answered from the
    // `Found` path, which VEGA-083 does not touch; and a wildcard can never
    // declare its own parent covered, because RFC 4592 §3.3.1 makes that parent
    // a proper ancestor of the names it covers and `wildcard_window` caps the
    // walk at the query's parent depth. That third one is structural, not luck.
    // The `ignore` reasons are pinned by
    // `the_three_rfc_bugs_this_fix_must_not_touch_are_still_ignored_with_their_reasons`.
    //
    // (VEGA-010 used to be on this list. It was the same defect as VEGA-083 seen
    // through another QTYPE, and closed with it.)
    // -----------------------------------------------------------------------

    #[test]
    #[ignore = "BUG: empty non-terminals answer NXDOMAIN instead of NODATA (RFC 2308 s2.2.1)"]
    fn an_empty_non_terminal_is_nodata_not_nxdomain() {
        let _watchdog = watchdog();
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
        let _watchdog = watchdog();
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
        let _watchdog = watchdog();
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
