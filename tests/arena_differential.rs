//! VEGA-032 **S1 and S2** — the node arena, differentially.
//!
//! Spec: `features/zone-data-model.feature`, section "S1 — THE ARENA,
//! BEHAVIOUR-PRESERVING", and `features/empty-non-terminals.feature` (S2).
//! Ruling: `.claude/backlog/decisions/VEGA-032-zone-data-model.md` §10.2, §13
//! AC-1.1 and AC-2.1 … AC-2.4.
//!
//! # S2 re-arms this file rather than retiring it
//!
//! S1's claim was "zero permitted transitions". S2 deliberately changes answers,
//! so a differential with zero permitted transitions would simply go red and
//! stop being a gate. The oracle is therefore **not** edited: [`FrozenZone`] is
//! still the transcription of `src/zone.rs` at `ebe1fbf`, algorithm untouched.
//! What changes is the **data** it is run over — its node set is closed under
//! ancestry, and the closure is computed **from the config** by
//! [`ancestor_closure`], never from the code under test.
//!
//! That distinction is the whole point. A whitelist of the shape "any NXDOMAIN
//! may become NODATA" would also make this file pass — and would let S3's
//! closest-encloser bug through, because that bug is *also* an NXDOMAIN that
//! ought to be something else. Deriving the closure from the config instead
//! means the permitted transitions are exactly the ones ancestor materialisation
//! can produce, and they are additionally **classified**: every difference
//! between the pre-S2 and post-S2 oracles must fall into one of three named
//! classes ([`Transition`]), and the fixture proves all three are reached.
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
//! S2 does not edit it. `materialise_ancestors` adds **names** to the node set
//! and touches no branch of `resolve`; the pre-S2 oracle is still available and
//! is still compared against, so what S2 changed is visible as a diff between
//! two runs of one algorithm rather than as a diff between two algorithms.
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
    /// Which wildcard rule [`FrozenZone::wildcard_probe`] applies. See
    /// [`WildcardRule`] — this is the S3 amendment, and the only one.
    rule: WildcardRule,
}

/// Which wildcard rule the transcription applies.
///
/// # Why this is an added arm and not an edit
///
/// S1's and S2's contract was that [`FrozenZone`] is never updated. S3 is the
/// commit a ruling authorises to change a *behaviour* (§5.4, AC-3.4), which is
/// the only circumstance under which this file may grow a second rule — and the
/// discipline is that the first one is **kept, reachable and still compared**.
/// [`WildcardRule::DeepestWinsFrozenAtEbe1fbf`]'s body is the pre-S1 walk,
/// moved into its own function without a character changed, and every property
/// below still runs it and still classifies the difference against it. So what
/// S3 changed stays visible as a diff between two rules over one transcription,
/// exactly as S2's change stayed visible as a diff between two node sets.
///
/// The second arm is transcribed from **RFC 4592 §3.3.1 itself**, not from
/// `src/zone.rs`. That is the difference between an oracle and a copy of the
/// answer: a mistake in the arena cannot be reproduced here by construction,
/// because nothing here was read off the implementation.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum WildcardRule {
    /// Deepest set bit of the depth bitmap wins, probing every configured
    /// wildcard depth from the query's parent down to the origin. `src/zone.rs`
    /// at `ebe1fbf`, verbatim. **Never edited.**
    DeepestWinsFrozenAtEbe1fbf,
    /// RFC 4592 §3.3.1: find the closest encloser, form `*.<it>`, probe once.
    /// "If the source of synthesis does not exist ... there is no wildcard
    /// match. There is no search for an alternate."
    ClosestEncloserRfc4592,
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
            rule: WildcardRule::DeepestWinsFrozenAtEbe1fbf,
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

    /// Dispatch on [`Self::rule`]. Added at S3; the arm below it is untouched.
    fn wildcard_probe(
        &self,
        name: &LowerName,
        record_type: RecordType,
    ) -> (Option<&[Record]>, bool) {
        match self.rule {
            WildcardRule::DeepestWinsFrozenAtEbe1fbf => {
                self.wildcard_probe_deepest_wins(name, record_type)
            }
            WildcardRule::ClosestEncloserRfc4592 => {
                self.wildcard_probe_closest_encloser(name, record_type)
            }
        }
    }

    fn wildcard_probe_deepest_wins(
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

    /// Every name that is a **node** in this zone.
    ///
    /// `names` holds ordinary owners and, once the closure has been applied, the
    /// ordinary empty non-terminals. Wildcards are held by their PARENT in this
    /// model, so the wildcard nodes have to be reconstituted: `*.<p>` for each
    /// parent `p` (RFC 4592 §2.1.1 — a wildcard is a name whose leftmost label
    /// is an asterisk, and it is an ordinary node in every other respect).
    ///
    /// This matters for names like `x.*.dev.example.test.`, whose closest
    /// encloser genuinely is `*.dev.example.test.`. Leaving wildcard nodes out
    /// would return a shallower encloser for them and silently reproduce the
    /// defect the whole step exists to fix.
    fn node_names(&self) -> HashSet<LowerName> {
        let mut out = self.names.clone();
        for parent in &self.wildcard_parents {
            if let Ok(star) = Name::from(parent.clone()).prepend_label("*") {
                out.insert(LowerName::from(star));
            }
        }
        out
    }

    /// The closest encloser of `name`: the **deepest proper ancestor that
    /// exists**. RFC 4592 §3.3.1, by brute-force enumeration.
    ///
    /// Deliberately the dumbest possible implementation — count down one label
    /// at a time and stop at the first hit. The arena does this with a binary
    /// search over label depth, which is correct only because ancestor closure
    /// makes "a node exists at this depth" monotone; enumerating instead is what
    /// makes this an independent check of that reasoning rather than a second
    /// copy of it. If the two disagree, the closure has a hole.
    ///
    /// The origin is always a node and every in-zone name descends from it, so
    /// this always succeeds. `None` only for a name that is not strictly below
    /// the origin, which has no proper in-zone ancestor to be enclosed by.
    fn closest_encloser(&self, name: &LowerName, nodes: &HashSet<LowerName>) -> Option<LowerName> {
        let full = Name::from(name.clone());
        let depth = full.iter().len();
        let floor = label_count(&self.lower_origin);
        if depth <= floor {
            return None;
        }
        for d in (floor..depth).rev() {
            let ancestor = LowerName::from(full.trim_to(d));
            if nodes.contains(&ancestor) {
                return Some(ancestor);
            }
        }
        None
    }

    /// RFC 4592 §3.3.1, transcribed clause by clause.
    ///
    /// ```text
    /// "If the 'closest encloser' of the query name is a wildcard domain name
    ///  ... the wildcard record is the source of synthesis ... If the source of
    ///  synthesis does not exist ... there is no wildcard match. There is no
    ///  search for an alternate ... the lookup does not look for other wildcard
    ///  records."
    /// ```
    ///
    /// ONE probe. The absence of a loop here is the whole content of S3.
    fn wildcard_probe_closest_encloser(
        &self,
        name: &LowerName,
        record_type: RecordType,
    ) -> (Option<&[Record]>, bool) {
        let nodes = self.node_names();
        let Some(ce) = self.closest_encloser(name, &nodes) else {
            return (None, false);
        };
        // The source of synthesis is `*.<ce>` and that name only.
        if !self.wildcard_parents.contains(&ce) {
            return (None, false);
        }
        (
            self.wildcard.get(&(ce, record_type)).map(Vec::as_slice),
            true,
        )
    }

    /// The same transcription under the closest-encloser rule.
    fn under_the_rfc_rule(mut self) -> Self {
        self.rule = WildcardRule::ClosestEncloserRfc4592;
        self
    }

    /// Close the node set under ancestry — **the whole of S2**, expressed as
    /// data over the transcription above rather than as a change to it.
    ///
    /// `ents` comes from [`ancestor_closure`], which reads the *config*. A name
    /// whose leftmost label is `*` joins the wildcard side, exactly as a
    /// declared wildcard does, because RFC 4592 §2.1.1 makes a wildcard a name
    /// with a leftmost asterisk and says nothing about how the name came to
    /// exist. Anything else joins `names`, where the pre-existing
    /// `names.contains(name) -> NoData` arm answers it.
    ///
    /// Nothing here touches `exact`, `wildcard` or `record_count`: an empty
    /// non-terminal contributes no records to any answer and does not move the
    /// `dns_zone_records` gauge (AC-2.4).
    fn materialise_ancestors(mut self, ents: &[LowerName]) -> Self {
        for ent in ents {
            if is_wildcard_name(ent) {
                let parent = ent.base_name();
                let depth = label_count(&parent);
                if depth <= MAX_LABELS {
                    self.wildcard_depths |= 1u128 << depth;
                    self.wildcard_parents.insert(parent);
                }
            } else {
                self.names.insert(ent.clone());
            }
        }
        self
    }
}

// ===========================================================================
// S2: the ancestor closure, computed from the CONFIG
// ===========================================================================

/// True when the leftmost label of `name` is exactly `*` (RFC 4592 §2.1.1).
fn is_wildcard_name(name: &LowerName) -> bool {
    Name::from(name.clone())
        .iter()
        .next()
        .is_some_and(|first| first == b"*")
}

/// The node name each record spec declares, as `Zone` keys it.
///
/// Transcribed from `insert_spec`, including the two cases that produce no node
/// at all: a spec that does not qualify (the build fails, and the caller only
/// reaches here when both builds agreed it failed) and a wildcard whose parent
/// sits within two octets of RFC 1035 §2.3.4's 255, so `*.<parent>` has no
/// representable name and S1 warns and serves the zone without it.
fn declared_node_names(cfg: &ZoneConfig) -> Vec<LowerName> {
    let Ok(mut origin) = cfg.origin.parse::<Name>() else {
        return Vec::new();
    };
    origin.set_fqdn(true);
    let lower_origin = LowerName::from(origin.clone());

    let mut out = vec![lower_origin.clone()];
    for spec in &cfg.records {
        if let Some(name) = spec_node_name(&origin, &lower_origin, spec) {
            out.push(name);
        }
    }
    out
}

/// The node name one spec declares, or `None` when it declares none.
///
/// Extracted at S3 so [`declared_node_names`] and [`ConfigModel`] cannot drift:
/// the classifier's whole claim is that it reads the same operator input the
/// build reads, and two copies of this qualification logic is how that stops
/// being true.
///
/// Two cases produce no node at all: a spec that does not qualify (the build
/// fails, and the caller only reaches here when both builds agreed it failed)
/// and a wildcard whose parent sits within two octets of RFC 1035 §2.3.4's 255,
/// so `*.<parent>` has no representable name and S1 warns and serves the zone
/// without it.
fn spec_node_name(origin: &Name, lower_origin: &LowerName, spec: &RecordSpec) -> Option<LowerName> {
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
    } else if owner_label.ends_with('.') {
        let mut name = owner_label.parse::<Name>().ok()?;
        name.set_fqdn(true);
        if !lower_origin.zone_of(&LowerName::from(name.clone())) {
            return None;
        }
        name
    } else {
        Name::parse(owner_label, Some(origin)).ok()?
    };

    if is_wildcard {
        // A wildcard with no representable owner name is not served, so it
        // implies no ancestors either. Pinned by
        // `src/zone.rs::a_wildcard_whose_owner_name_exceeds_the_octet_limit_materialises_no_ancestors`.
        Some(LowerName::from(owner.prepend_label("*").ok()?))
    } else {
        Some(LowerName::from(owner))
    }
}

/// Every name that becomes a node **only** because something exists beneath it:
/// the strict ancestors of every declared node name, up to and including the
/// origin, minus the names the config declares outright.
///
/// This is the closure S2 must materialise, derived from the operator's input
/// alone. It is what makes the permitted transitions below *derived* rather than
/// *whitelisted*.
fn ancestor_closure(cfg: &ZoneConfig) -> HashSet<LowerName> {
    let declared: HashSet<LowerName> = declared_node_names(cfg).into_iter().collect();
    let Ok(mut origin) = cfg.origin.parse::<Name>() else {
        return HashSet::new();
    };
    origin.set_fqdn(true);
    let lower_origin = LowerName::from(origin);
    let origin_depth = label_count(&lower_origin);

    let mut ents = HashSet::new();
    for name in &declared {
        let full = Name::from(name.clone());
        let depth = full.iter().len();
        // Strict ancestors only, down to the origin's own depth. `trim_to`
        // indexes raw labels, asterisks counted — the index space VEGA-065's
        // ban on `num_labels` exists to protect.
        for d in origin_depth..depth {
            let ancestor = LowerName::from(full.trim_to(d));
            if !declared.contains(&ancestor) {
                ents.insert(ancestor);
            }
        }
    }
    ents
}

/// The three ways S2 may change an answer, and the only three.
///
/// Each is decided from the config-derived closure, never from what the
/// implementation returned. A difference that matches none of them fails the
/// property, which is what stops this from degenerating into "NXDOMAIN may
/// become NODATA" — the loose rule that would also let VEGA-009's
/// closest-encloser defect through at S3.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
enum Transition {
    /// **T1** — the queried name is itself an empty non-terminal, so it exists
    /// and the answer is NODATA (RFC 4592 §2.2.2, RFC 2308 §2.2).
    ///
    /// This covers two shapes that look different and are the same rule: a name
    /// that was NXDOMAIN, and a name a wildcard used to synthesise for — RFC
    /// 4592 §2.2.2 is explicit that synthesis does not apply at a name that
    /// exists, so `Records -> NoData` here is required, not tolerated.
    EmptyNonTerminalExists,
    /// **T2** — the queried name is covered by a wildcard that is itself an
    /// empty non-terminal (`x.*.dev` makes `*.dev` exist), so a source of
    /// synthesis exists carrying no RRset and RFC 1034 §4.3.2 step 3(c) forbids
    /// the name error. `NxDomain -> NoData`, and only that.
    CoveredByAWildcardEmptyNonTerminal,
    /// **T3** — a CNAME chase whose target is now an empty non-terminal stops
    /// there, so the answer keeps the CNAME and loses the records that used to
    /// be appended behind it. A strict prefix of the old answer, never a
    /// reordering and never a different record.
    CnameChaseStopsAtAnEmptyNonTerminal,
}

/// Which transition, if any, explains `before -> after`. `None` means "not a
/// transition S2 is allowed to make", and the caller must fail.
fn classify(
    ents: &HashSet<LowerName>,
    origin_depth: usize,
    queried: &LowerName,
    before: &Answer,
    after: &Answer,
) -> Option<Transition> {
    if rendered(before) == rendered(after) {
        return None;
    }

    // T1. The strongest of the three: it does not care what the old answer was,
    // only that the name now exists, and it demands NODATA exactly.
    if ents.contains(queried) {
        return matches!(after, Answer::NoData).then_some(Transition::EmptyNonTerminalExists);
    }

    // T2. A source of synthesis that is an empty non-terminal covers this name.
    // The window is RFC 4592 §3.3.1's: a wildcard's parent is a *proper*
    // ancestor of the names it covers, so depths run from the origin up to the
    // query's own parent.
    if matches!(before, Answer::NxDomain) && matches!(after, Answer::NoData) {
        let full = Name::from(queried.clone());
        let depth = full.iter().len();
        for d in origin_depth..depth {
            let Ok(star) = full.trim_to(d).prepend_label("*") else {
                continue;
            };
            if ents.contains(&LowerName::from(star)) {
                return Some(Transition::CoveredByAWildcardEmptyNonTerminal);
            }
        }
    }

    // T3. The chase stopped at a name that now exists. The surviving answer must
    // be a strict prefix of the old one ending on the CNAME whose target became
    // an empty non-terminal — a truncation, never a reordering or a rewrite.
    if let (Answer::Records(old), Answer::Records(new)) = (before, after) {
        let (_, old_rendered) = rendered(before);
        let (_, new_rendered) = rendered(after);
        if new.len() < old.len() && old_rendered.starts_with(new_rendered.as_slice()) {
            if let Some(RData::CNAME(target)) = new.last().map(|r| &r.data) {
                if ents.contains(&LowerName::from(target.0.clone())) {
                    return Some(Transition::CnameChaseStopsAtAnEmptyNonTerminal);
                }
            }
        }
    }

    None
}

// ===========================================================================
// S3: the closest-encloser rule, computed from the CONFIG
// ===========================================================================

/// The zone as the **operator's config** describes it, for the S3 classifier.
///
/// Everything the classifier needs to decide whether the closest-encloser rule
/// may change an answer, derived from `ZoneConfig` alone. The `Zone` under test
/// contributes nothing to it — which is the entire reason the differential is
/// worth running. An oracle that read the implementation's own node set would
/// agree with any bug that was consistent with itself.
struct ConfigModel {
    origin_depth: usize,
    /// Every name that is a node: the declared owners (a wildcard under its own
    /// `*.x` name, RFC 4592 §2.1.1) plus the ancestor closure S2 materialises.
    nodes: HashSet<LowerName>,
    /// `p` for every wildcard node `*.p`, whether declared or materialised.
    wildcard_parents: HashSet<LowerName>,
    /// `(p, rtype)` for every wildcard `*.p` the config declares with records of
    /// `rtype`. A wildcard that exists only as an empty non-terminal appears in
    /// `wildcard_parents` and in none of these, which is precisely the shape
    /// that separates "covered" from "answered".
    wildcard_types: HashSet<(LowerName, RecordType)>,
}

impl ConfigModel {
    fn build(cfg: &ZoneConfig) -> Self {
        let mut nodes: HashSet<LowerName> = declared_node_names(cfg).into_iter().collect();
        nodes.extend(ancestor_closure(cfg));

        let wildcard_parents: HashSet<LowerName> = nodes
            .iter()
            .filter(|n| is_wildcard_name(n))
            .map(LowerName::base_name)
            .collect();

        let mut wildcard_types = HashSet::new();
        if let Ok(mut origin) = cfg.origin.parse::<Name>() {
            origin.set_fqdn(true);
            let lower_origin = LowerName::from(origin.clone());
            for spec in &cfg.records {
                let Some(node) = spec_node_name(&origin, &lower_origin, spec) else {
                    continue;
                };
                if !is_wildcard_name(&node) {
                    continue;
                }
                let Ok(rtype) = spec.record_type.to_uppercase().parse::<RecordType>() else {
                    continue;
                };
                if spec.values.is_empty() {
                    continue;
                }
                wildcard_types.insert((node.base_name(), rtype));
            }
        }

        let origin_depth = cfg.origin.parse::<Name>().map_or(0, |mut o| {
            o.set_fqdn(true);
            o.iter().len()
        });

        Self {
            origin_depth,
            nodes,
            wildcard_parents,
            wildcard_types,
        }
    }

    /// The closest encloser of `q`: the deepest proper ancestor that is a node.
    ///
    /// `None` for a name that is not strictly below the origin — the apex
    /// itself, the root, an out-of-zone name. Those are answered before any
    /// wildcard rule applies, so "no closest encloser" and "no transition
    /// permitted" are the same statement.
    fn closest_encloser(&self, q: &LowerName) -> Option<LowerName> {
        let full = Name::from(q.clone());
        let depth = full.iter().len();
        if depth <= self.origin_depth {
            return None;
        }
        (self.origin_depth..depth).rev().find_map(|d| {
            let ancestor = LowerName::from(full.trim_to(d));
            self.nodes.contains(&ancestor).then_some(ancestor)
        })
    }

    /// Every proper ancestor of `q` that is a wildcard's parent, deepest first.
    ///
    /// This is the set the pre-S3 walk consulted. The window is RFC 4592
    /// §3.3.1's: a wildcard's parent is a *proper* ancestor of the names it
    /// covers, so `*.apps` never covers `apps` itself.
    fn wildcard_ancestors(&self, q: &LowerName) -> Vec<LowerName> {
        let full = Name::from(q.clone());
        let depth = full.iter().len();
        (self.origin_depth..depth)
            .rev()
            .map(|d| LowerName::from(full.trim_to(d)))
            .filter(|a| self.wildcard_parents.contains(a))
            .collect()
    }

    /// The wildcard the **pre-S3 walk** would have answered `q`/`rtype` from:
    /// the deepest ancestor carrying an RRset of that type.
    fn deepest_typed_wildcard(&self, q: &LowerName, rtype: RecordType) -> Option<LowerName> {
        self.wildcard_ancestors(q)
            .into_iter()
            .find(|p| self.wildcard_types.contains(&(p.clone(), rtype)))
    }

    /// **The predicate the whole classifier rests on.** True when the
    /// closest-encloser rule resolves `q`/`rtype` differently from a
    /// deepest-wins walk over the same node set.
    ///
    /// Derived, not asserted. Under ancestor closure every wildcard parent that
    /// is an ancestor of `q` is itself a node ancestor of `q`, so it can never
    /// be *deeper* than the closest encloser. The two rules can therefore only
    /// diverge in two ways, and this is both of them:
    ///
    ///   * the walk answered from a wildcard that is not `*.<CE>` — either
    ///     because the CE holds no wildcard at all, or because it holds one
    ///     carrying other types and the walk carried on past it;
    ///   * the walk called the name *covered* on the strength of a wildcard
    ///     above the CE, so the name error was suppressed by a wildcard RFC 4592
    ///     §3.3.1 forbids consulting.
    ///
    /// A name that is itself a node is excluded outright: it is answered by the
    /// exact-match arm and no wildcard rule of any kind applies to it. That one
    /// line is what stops S3 being allowed to undo S2 — see
    /// `the_classifier_refuses_transitions_the_closest_encloser_rule_cannot_produce`.
    fn synthesis_moved(&self, q: &LowerName, rtype: RecordType) -> bool {
        if self.nodes.contains(q) {
            return false;
        }
        let Some(ce) = self.closest_encloser(q) else {
            return false;
        };
        let answered_from_the_wrong_name = self
            .deepest_typed_wildcard(q, rtype)
            .is_some_and(|p| p != ce);
        answered_from_the_wrong_name || self.coverage_narrowed_at(q, &ce)
    }

    /// True when `q` was covered by a wildcard above its closest encloser, and
    /// so stops being covered at all.
    fn coverage_narrowed_at(&self, q: &LowerName, ce: &LowerName) -> bool {
        !self.wildcard_parents.contains(ce) && !self.wildcard_ancestors(q).is_empty()
    }

    /// [`Self::coverage_narrowed_at`] without a precomputed closest encloser.
    ///
    /// This is what `Zone::exists` narrows by, and existence narrowing is the
    /// one direction S2's differential explicitly forbade — so at S3 it has to
    /// be permitted, but only exactly here.
    fn coverage_narrowed(&self, q: &LowerName) -> bool {
        if self.nodes.contains(q) {
            return false;
        }
        self.closest_encloser(q)
            .is_some_and(|ce| self.coverage_narrowed_at(q, &ce))
    }

    /// What RFC 4592 §3.3.1 and RFC 1034 §4.3.2 step 3(c) say a name with no
    /// synthesised answer resolves to.
    ///
    /// NXDOMAIN when the source of synthesis does not exist; NODATA when it
    /// exists and carries no RRset of this type, because the authoritative name
    /// error is set *only* when the `*` node is absent (VEGA-083, preserved).
    fn rfc_negative(&self, q: &LowerName, rtype: RecordType) -> Option<Answer> {
        let ce = self.closest_encloser(q)?;
        if !self.wildcard_parents.contains(&ce) {
            return Some(Answer::NxDomain);
        }
        if self.wildcard_types.contains(&(ce, rtype)) {
            // The source of synthesis carries the type, so the RFC answer is a
            // record, not a negative.
            return None;
        }
        Some(Answer::NoData)
    }
}

/// Every name in `cfg` that **carves a subtree out of a wildcard**: a node,
/// itself not a wildcard, with a wildcard's parent as a proper ancestor.
///
/// These are the closest enclosers that change an answer at S3, and the query
/// generator derives its names from them rather than hoping to land on one. The
/// list includes empty non-terminals, because `*.dev` + `a.b.deep.dev` carves
/// out `b.deep.dev` and `deep.dev` — names the operator never wrote — and that
/// is the shape S3 could not have been built without S2 for.
///
/// Sorted, so a `HashSet`'s iteration order cannot make a case a coin flip
/// between two runs of the same seed.
fn carve_out_names(cfg: &ZoneConfig) -> Vec<String> {
    let mut nodes: HashSet<LowerName> = declared_node_names(cfg).into_iter().collect();
    nodes.extend(ancestor_closure(cfg));
    let parents: HashSet<LowerName> = nodes
        .iter()
        .filter(|n| is_wildcard_name(n))
        .map(LowerName::base_name)
        .collect();

    let mut out: Vec<String> = nodes
        .iter()
        .filter(|n| !is_wildcard_name(n))
        .filter(|n| {
            parents
                .iter()
                .any(|p| p.zone_of(n) && label_count(p) < label_count(n))
        })
        .map(std::string::ToString::to_string)
        .collect();
    out.sort();
    out
}

/// The three ways S3 may change an answer, and the only three.
///
/// Each is decided from [`ConfigModel`], never from what the implementation
/// returned. A rule of the shape "a synthesised answer may become NXDOMAIN"
/// would also pass a build that had simply stopped synthesising, which is why
/// the classes are named and their preconditions derived.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
enum S3Transition {
    /// **W1** — a synthesised answer whose source of synthesis was not
    /// `*.<closest encloser>` becomes exactly what RFC 4592 §3.3.1 says:
    /// NXDOMAIN when the closest encloser holds no wildcard, NODATA when it
    /// holds one carrying other types. This is VEGA-009.
    SynthesisRestrictedToTheClosestEncloser,
    /// **W2** — a NODATA that came from coverage *above* the closest encloser
    /// becomes NXDOMAIN. The name error is restored, and this is the arm QTYPE
    /// ANY takes, because ANY is never an RRTYPE and so only ever reads
    /// coverage.
    NameErrorRestoredAboveTheClosestEncloser,
    /// **W3** — a CNAME chase whose target was reached only by a synthesis above
    /// the closest encloser loses its tail. The surviving answer is a strict
    /// prefix of the old one ending on the CNAME, never a reordering and never a
    /// different record.
    CnameChaseLosesAnUnreachableSynthesis,
    /// **W4** — a wildcard is no longer applied AT a wildcard-shaped name that
    /// exists. RFC 4592 §2.2.2: synthesis does not apply at a name that exists,
    /// and RFC 4592 §2.1.1 makes "is a wildcard" a property of the NAME, so
    /// `*.dev` being an empty non-terminal blocks the apex `*` exactly as
    /// `deep.dev` does.
    ///
    /// # This class was not in the ruling, and it was not in the fixture
    ///
    /// **VEGA-098.** The ruling's §13 lists AC-3.1 … AC-3.7 and none of them
    /// covers it, because it is not about the closest encloser at all: the
    /// search never runs for these names, since the name is a node and RFC 1034
    /// §4.3.2 step 3.a answers it. It is the other half of S3 — removing the
    /// exact-match probe's deliberate exclusion of wildcard nodes, which S1
    /// introduced for map-model fidelity with the note that "that exclusion is
    /// what S2 and S3 remove, with a ruling".
    ///
    /// It was found by `the_wildcard_walk_agrees_with_a_naive_base_name_walk` on
    /// `main`, not by anything written for S3, and this file's first S3 fixture
    /// did not contain the shape. That is the argument for keeping the
    /// classification exhaustive and failing on anything unnamed: a class nobody
    /// predicted showed up as an unclassified difference rather than as a silent
    /// pass.
    SynthesisRefusedAtAWildcardNameThatExists,
}

/// Which S3 transition, if any, explains `before -> after`. `None` means "not a
/// transition the closest-encloser rule can produce", and the caller must fail.
fn classify_s3(
    model: &ConfigModel,
    queried: &LowerName,
    qtype: RecordType,
    before: &Answer,
    after: &Answer,
) -> Option<S3Transition> {
    if rendered(before) == rendered(after) {
        return None;
    }

    // A name that EXISTS is answered by the exact-match arm and no wildcard rule
    // of any kind applies to it — including turning an empty non-terminal's
    // NODATA back into a name error, which is S2's gain and not S3's to spend.
    //
    // That guard lives inside `synthesis_moved` and `coverage_narrowed` rather
    // than here, and the difference is load-bearing. W3's queried name is a
    // CNAME owner, so it is ALWAYS a node; the name whose synthesis moved is the
    // chase TARGET. A guard at the top of this function refuses W3 outright and
    // reports the class as unreachable — which is exactly what it did on the
    // first run of `each_permitted_s3_transition_class_is_reached_by_the_fixture`.
    //
    // W1: the answer section loses a synthesis that came from the wrong name.
    if let Answer::Records(old) = before {
        let synthesised_here = !old.is_empty()
            && old
                .iter()
                .all(|r| LowerName::from(r.name.clone()) == *queried);
        if synthesised_here
            && model.synthesis_moved(queried, qtype)
            && model
                .rfc_negative(queried, qtype)
                .is_some_and(|want| rendered(&want) == rendered(after))
        {
            return Some(S3Transition::SynthesisRestrictedToTheClosestEncloser);
        }
    }

    // W2: coverage narrows to the closest encloser and the name error returns.
    if matches!(before, Answer::NoData)
        && matches!(after, Answer::NxDomain)
        && model.coverage_narrowed(queried)
    {
        return Some(S3Transition::NameErrorRestoredAboveTheClosestEncloser);
    }

    // W4: the queried name is a wildcard-shaped node, so it EXISTS and no
    // synthesis may be applied at it (RFC 4592 §2.2.2). The answer must become
    // exactly what that node holds: its own records of this type if it declares
    // any, and NODATA otherwise. VEGA-098.
    if model.nodes.contains(queried) && is_wildcard_name(queried) {
        let declares_the_type = model.wildcard_types.contains(&(queried.base_name(), qtype));
        let correct = if declares_the_type {
            // Its own RRset, owned by its own name — never a synthesis, and
            // never someone else's records.
            matches!(after, Answer::Records(records)
                if !records.is_empty()
                    && records
                        .iter()
                        .all(|r| LowerName::from(r.name.clone()) == *queried))
        } else {
            matches!(after, Answer::NoData)
        };
        if correct {
            return Some(S3Transition::SynthesisRefusedAtAWildcardNameThatExists);
        }
        // A wildcard node whose answer changed to anything else is not a
        // transition this step may make. Returning here rather than falling
        // through keeps W3 from rescuing it on a coincidence of shape.
        return None;
    }

    // W3: the chase stopped at a target the RFC rule no longer synthesises for.
    // A truncation, never a reordering or a rewrite.
    if let (Answer::Records(old), Answer::Records(new)) = (before, after) {
        let (_, old_rendered) = rendered(before);
        let (_, new_rendered) = rendered(after);
        if new.len() < old.len() && old_rendered.starts_with(new_rendered.as_slice()) {
            if let Some(RData::CNAME(target)) = new.last().map(|r| &r.data) {
                let target = LowerName::from(target.0.clone());
                if model.synthesis_moved(&target, qtype) {
                    return Some(S3Transition::CnameChaseLosesAnUnreachableSynthesis);
                }
            }
        }
    }

    None
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
    let render = |records: &[Record]| -> Vec<String> {
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
            .collect()
    };
    match answer {
        Answer::NxDomain => ("NXDOMAIN", Vec::new()),
        Answer::NoData => ("NODATA", Vec::new()),
        Answer::Records(records) => ("RECORDS", render(records)),
        // Unreachable as the generator stands: `typed_value` draws A, AAAA, TXT,
        // MX and CNAME, so no zone it builds carries a non-apex NS RRset and no
        // zone cut exists to refer to. Rendered rather than `unreachable!` so
        // that widening the generator to declare NS fails this comparison with a
        // readable diff instead of aborting the process — the oracles predate
        // S4 and know nothing about delegation, and that is what they should
        // say out loud.
        Answer::Referral {
            answers,
            authority,
            additional,
        } => (
            "REFERRAL",
            render(answers)
                .into_iter()
                .chain(render(authority))
                .chain(render(additional))
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

/// A wildcard **and a name carved out from underneath it**, as one unit.
///
/// S3's interesting case needs three things at once: a wildcard, a name that
/// exists between it and the query, and a query below that name. Left to
/// independent generators that combination is rarer than S2's — S2 needed only a
/// name with an ancestor — and the repository has already paid for the
/// alternative once: `a_wildcard_covered_name_exists_for_every_type` filtered
/// with `prop_assume!` and aborted on CI with "Too many global rejects: 247
/// successes, 1024 rejects" while passing locally on a luckier seed.
///
/// So the pair is CONSTRUCTED. The carve-out name is generated first and the
/// query is derived from it by [`carve_out_names`], which reads the config.
/// Nothing is rejected and every case reaches the branch.
fn carve_out_pair() -> impl Strategy<Value = Vec<RecordSpec>> {
    (
        prop::collection::vec(prop::sample::select(vec!["a", "b", "dev", "apps"]), 0..3),
        typed_value(),
        typed_value(),
    )
        .prop_map(|(tail, (wt, wv), (et, ev))| {
            let parent = if tail.is_empty() {
                "cv".to_owned()
            } else {
                format!("cv.{}", tail.join("."))
            };
            vec![
                RecordSpec {
                    name: format!("*.{parent}"),
                    record_type: wt,
                    ttl: None,
                    values: vec![wv],
                },
                RecordSpec {
                    name: format!("carved.{parent}"),
                    record_type: et,
                    ttl: None,
                    values: vec![ev],
                },
            ]
        })
}

fn zone_config() -> impl Strategy<Value = ZoneConfig> {
    (
        prop::collection::vec(exact_spec(), 0..6),
        prop::collection::vec(wildcard_spec(), 0..4),
        // Mostly absent: a broken spec makes the whole build fail, so a high
        // rate would starve the lookup half of the property.
        prop::option::weighted(0.08, broken_spec()),
        prop::option::weighted(0.85, Just(())),
        // Mostly present, because S3's whole subject is what happens when a
        // name exists between a wildcard and the query. Not ALWAYS present, so
        // the zones with no carve-out at all are still generated and the
        // no-transition path is still exercised.
        prop::option::weighted(0.75, carve_out_pair()),
    )
        .prop_map(|(exacts, wildcards, broken, with_soa, carve)| {
            let mut records = exacts;
            records.extend(wildcards);
            records.extend(broken);
            records.extend(carve.into_iter().flatten());
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
        0u8..17,
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
        // ---------------------------------------------------------------- S2
        // An empty non-terminal, taken straight out of the config-derived
        // closure. CONSTRUCTED, not filtered: empty non-terminals are rarer
        // than wildcards, so generating a name and hoping it is one is how a
        // property reaches 1,024 global rejects on CI. Sorted before picking so
        // that a `HashSet`'s iteration order cannot make the case a coin flip
        // between runs of the same seed.
        12 => {
            let mut ents: Vec<String> = ancestor_closure(cfg)
                .iter()
                .map(std::string::ToString::to_string)
                .collect();
            ents.sort();
            pick(&ents).unwrap_or(origin_dot)
        }
        // A name covered by a wildcard that is itself an empty non-terminal:
        // the T2 shape, which arises from `x.*.dev` and from nothing else the
        // generator produces.
        13 => {
            let mut parents: Vec<String> = ancestor_closure(cfg)
                .iter()
                .filter(|n| is_wildcard_name(n))
                .map(|n| n.base_name().to_string())
                .collect();
            parents.sort();
            pick(&parents).map_or(origin_dot, |p| stack(&p))
        }
        // Under an empty non-terminal: the name whose closest encloser is one.
        14 => {
            let mut ents: Vec<String> = ancestor_closure(cfg)
                .iter()
                .map(std::string::ToString::to_string)
                .collect();
            ents.sort();
            pick(&ents).map_or(origin_dot, |e| stack(&e))
        }
        // ---------------------------------------------------------------- S3
        // BELOW A CARVE-OUT: a wildcard covers this subtree, and a name that
        // EXISTS sits between the wildcard's parent and the query. That name is
        // the closest encloser, so RFC 4592 §3.3.1 allows only `*.<it>` — and
        // this is the shape the pre-S3 walk gets wrong. CONSTRUCTED from the
        // config by `carve_out_names`, never filtered for: the combination is
        // rarer than S2's, and hoping to land on it is how a property reaches
        // 1,024 global rejects on CI.
        15 => {
            let carves = carve_out_names(cfg);
            pick(&carves).map_or(origin_dot, |c| stack(&c))
        }
        // The carve-out name ITSELF, which must keep answering. Without it a
        // build that made the whole subtree disappear would satisfy shape 15.
        16 => {
            let carves = carve_out_names(cfg);
            pick(&carves).unwrap_or(origin_dot)
        }
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

    /// INVARIANT (AC-1.1, AC-2.1 … AC-2.4, AC-3.1 … AC-3.3): the arena answers
    /// what the transcription answers over the **ancestor-closed** node set
    /// under **RFC 4592 §3.3.1**, and every difference from each of the two
    /// earlier models is one of that model's named classes.
    ///
    /// Scenario: The arena answers exactly what today's implementation answers,
    /// for every zone and every query
    /// features/zone-data-model.feature:263
    ///
    /// Scenario: S2 changes the answer at an empty non-terminal and nowhere else
    /// features/empty-non-terminals.feature:381
    ///
    /// Scenario: Every S3 difference is one of four named classes
    /// features/closest-encloser.feature:483
    ///
    /// Also carries, in the same pass:
    ///
    ///   * Scenario: A config the transcription refuses is a config the arena
    ///     refuses — features/zone-data-model.feature:458 and
    ///     features/empty-non-terminals.feature:297
    ///   * Scenario: A zone whose config declares no records at all still agrees
    ///     with the transcription — features/zone-data-model.feature:437
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
    fn the_arena_agrees_with_the_transcription_over_an_ancestor_closed_node_set(
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

        // The S2 oracle: the same algorithm, over a node set closed under
        // ancestry. The closure comes from the config; `frozen` is kept
        // alongside it so that what S2 changed is a diff between two runs of one
        // transcription rather than a diff between two transcriptions.
        let ents = ancestor_closure(&cfg);
        let mut ent_list: Vec<LowerName> = ents.iter().cloned().collect();
        ent_list.sort_by_key(std::string::ToString::to_string);
        let s2 = FrozenZone::build(&cfg)
            .expect("the transcription built once, so it builds twice")
            .materialise_ancestors(&ent_list);
        // S3: the same transcription and the same node set, under RFC 4592
        // §3.3.1 instead of deepest-wins. This is the oracle the implementation
        // is now held to; `s2` stays alongside it so what S3 changed is a diff
        // between two RULES over one transcription, exactly as what S2 changed
        // is a diff between two NODE SETS over the same one.
        let s3 = FrozenZone::build(&cfg)
            .expect("the transcription built once, so it builds three times")
            .materialise_ancestors(&ent_list)
            .under_the_rfc_rule();
        let model = ConfigModel::build(&cfg);
        let origin_depth = label_count(&frozen.lower_origin);

        prop_assert_eq!(
            real.record_count(),
            frozen.record_count,
            "record_count moved; it is the dns_zone_records metric and an \
             operator's only view of whether a reload truncated the zone. S2 \
             permits ZERO transitions here: an empty non-terminal is a node, not \
             a record (AC-2.4)\n  zone: {:?}",
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
            s3.exists(&queried),
            "Zone::exists disagreed for {}. It is the RFC 1034 §4.3.2 step 3(c) \
             name-error determination (VEGA-083), the ruling keeps its contract \
             through the rewrite, and it is the one predicate the DNSSEC proof \
             machinery will read\n  zone: {:?}",
            name,
            shape
        );
        // EXISTENCE NARROWS AT S3, and this assertion is AMENDED rather than
        // deleted. Through S1 and S2 it read "existence may only widen": a name
        // that existed before and does not now is a record taken out of service,
        // and ancestor closure can only add names.
        //
        // The closest-encloser rule genuinely removes some. A name whose only
        // coverage came from a wildcard ABOVE its closest encloser stops being
        // covered, and RFC 4592 §2.2 is explicit that a wildcard-covered name is
        // not a node in the zone — so it stops existing, correctly. The
        // amendment is therefore not "existence may now shrink" but "existence
        // may shrink EXACTLY where `coverage_narrowed` says so, decided from the
        // config". Weakening it to the first form would let a build that had
        // stopped covering anything at all through.
        prop_assert!(
            !s2.exists(&queried) || real.exists(&queried) || model.coverage_narrowed(&queried),
            "{} existed before S3 and does not now, and its coverage did not \
             narrow to the closest encloser. Ancestor closure never removes a \
             name and the closest-encloser rule removes only the names a \
             wildcard above the closest encloser was covering\n  zone: {:?}",
            name,
            shape
        );

        let actual = real.lookup(&queried, qtype);
        let expected = s3.lookup(&queried, qtype);
        prop_assert_eq!(
            rendered(&actual),
            rendered(&expected),
            "{} {} (shape {}) disagreed with the transcription run over the \
             ancestor-closed node set. Same variant, same records, same owner \
             names, same TTLs, same rdata, same order\n  zone: {:?}\n  got:      \
             {:?}\n  expected: {:?}",
            name,
            qtype,
            plan.shape,
            shape,
            actual,
            expected
        );

        // …and the RULE change is held to three named classes of its own,
        // derived from the config by `ConfigModel`. Without this the property
        // above would pass against an oracle that had quietly grown a second
        // behaviour change, which is exactly how a differential stops being a
        // gate.
        let before_s3 = s2.lookup(&queried, qtype);
        if rendered(&before_s3) != rendered(&expected) {
            prop_assert!(
                classify_s3(&model, &queried, qtype, &before_s3, &expected).is_some(),
                "{} {} changed between the deepest-wins rule and the \
                 closest-encloser rule, and the change is not one that rule can \
                 produce (W1 synthesis restricted to `*.<closest encloser>`, W2 \
                 the name error restored above it, W3 a CNAME chase losing an \
                 unreachable synthesis, W4 synthesis refused at a wildcard name \
                 that exists)\n  zone: {:?}\n  before: {:?}\n  after:  \
                 {:?}",
                name,
                qtype,
                shape,
                before_s3,
                expected
            );
        }

        // S2's classification is KEPT and still checked over the same case. S3
        // and S2 are independent claims, and a step that satisfied its own fence
        // by spending the previous step's gains is the one regression a
        // per-step differential would otherwise miss.
        let before = frozen.lookup(&queried, qtype);
        let after_s2 = s2.lookup(&queried, qtype);
        if rendered(&before) != rendered(&after_s2) {
            prop_assert!(
                classify(&ents, origin_depth, &queried, &before, &after_s2).is_some(),
                "{} {} changed between the pre-S2 and post-S2 node sets, and the \
                 change is not one of the three transitions ancestor closure can \
                 produce (T1 the name is an empty non-terminal, T2 it is covered \
                 by a wildcard that is one, T3 a CNAME chase stops at one). An \
                 unclassifiable difference means the closure is doing something \
                 other than closing the node set under ancestry\n  zone: {:?}\n  \
                 before: {:?}\n  after:  {:?}",
                name,
                qtype,
                shape,
                before,
                expected
            );
        }
    }
}

/// The deterministic fixture, shared by the branch sweep and by the
/// transition-class check so that neither can drift from the other.
///
/// Every record here reaches a named branch. The last four are S2's, one per
/// transition class, and they are in the fixture rather than left to the
/// generator because empty non-terminals are rarer than wildcards: a shape the
/// generator reaches at a rate it chooses is a shape that is untested on the run
/// that matters.
fn s2_fixture() -> ZoneConfig {
    let spec = |name: &str, ty: &str, value: &str| RecordSpec {
        name: name.to_owned(),
        record_type: ty.to_owned(),
        ttl: None,
        values: vec![value.to_owned()],
    };
    ZoneConfig {
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
            // S2 shapes, one per transition class.
            // T1: `_tcp.host` and `svc` exist only as ancestors.
            spec("_sip._tcp.host", "SRV", "10 10 5060 host.example.test."),
            spec("a.b.svc", "A", "203.0.113.70"),
            // T2: makes `*.zone.example.test.` an empty non-terminal that is
            // also a wildcard (RFC 4592 §2.1.1, §2.1.3).
            spec("x.*.zone", "A", "203.0.113.71"),
            // T3: a CNAME whose target becomes an empty non-terminal, so the
            // chase that used to append the apex wildcard's synthesised record
            // now stops at the CNAME.
            spec("toent", "CNAME", &format!("b.svc.{ORIGIN}.")),
        ],
    }
}

/// A zone with **no apex wildcard**, which is what T2 needs to be visible at
/// all.
///
/// An apex `*` covers every name in the zone, so nothing under it is ever
/// NXDOMAIN and the "a wildcard that is an empty non-terminal starts covering
/// this name" transition can never be observed there. That is a fact about the
/// shape of the zone rather than about the fix, and it is exactly the kind of
/// masking that makes a one-fixture test report a class as unreachable when it
/// is merely hidden — this file's first run of the class check found it.
fn t2_fixture() -> ZoneConfig {
    let mut cfg = s2_fixture();
    cfg.records.retain(|r| r.name.trim() != "*");
    cfg
}

/// The names swept against [`s2_fixture`], one per branch of the lookup.
fn fixture_names() -> Vec<String> {
    vec![
        ORIGIN.to_owned() + ".",
        format!("host.{ORIGIN}."),
        format!("alias.{ORIGIN}."),
        format!("chain.{ORIGIN}."),
        format!("dangling.{ORIGIN}."),
        format!("outside.{ORIGIN}."),
        format!("x.dev.{ORIGIN}."),
        format!("deep.dev.{ORIGIN}."),
        // VEGA-009's shape: a wildcard leaking below a name that exists. S2 must
        // keep answering it exactly as non-conformantly as today; the fix is
        // S3's.
        format!("a.deep.dev.{ORIGIN}."),
        format!("dev.{ORIGIN}."),
        format!("*.dev.{ORIGIN}."),
        format!("nothing.{ORIGIN}."),
        format!("a.b.c.d.{ORIGIN}."),
        "example.invalid.".to_owned(),
        ".".to_owned(),
        // S2: the empty non-terminals themselves, a name beneath one, the
        // wildcard-shaped one, a name it covers, and the CNAME into one.
        format!("_tcp.host.{ORIGIN}."),
        format!("b.svc.{ORIGIN}."),
        format!("svc.{ORIGIN}."),
        format!("under.b.svc.{ORIGIN}."),
        format!("*.zone.{ORIGIN}."),
        format!("zone.{ORIGIN}."),
        format!("covered.zone.{ORIGIN}."),
        format!("toent.{ORIGIN}."),
    ]
}

/// Scenario: The differential covers ANY, CNAME chasing and the negative paths,
/// not only wildcards
/// features/zone-data-model.feature:280
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
///
/// It also carries the anti-vacuity half of the S2 property above: a
/// classification that nothing exercises permits everything, so the three
/// transition classes are counted here and every one must be observed at least
/// once. The fixture is built to produce them — `_sip._tcp.host` for T1,
/// `x.*.dev` for T2, and a CNAME whose target is an empty non-terminal for T3 —
/// rather than left to a generator that reaches them at a rate it chooses.
///
/// # AMENDED AT S3, in the direction the S3 sweep already ran
///
/// This swept `real` against the **S2** oracle, and S3 changes answers, so
/// `a.deep.dev.example.test.` — VEGA-009's own shape, in this fixture on purpose
/// — went red the moment the closest-encloser search landed. That is the fix
/// arriving, not a regression, and the S2 oracle is simply no longer what the
/// implementation is held to.
///
/// So it now runs the same three oracles its S3 twin does over the S3 fixture:
/// `real == s3` is the claim, `s2 -> s3` classified by `classify_s3` is S3's
/// fence, and `frozen -> s2` classified by S2's `classify` is **kept** with its
/// class counting intact. Nothing was removed: the S2 assertion that used to be
/// `real == s2` is now `s2` sitting between two classified fences, which is
/// strictly more than it checked before.
#[test]
fn every_branch_of_the_lookup_agrees_with_the_transcription_over_an_ancestor_closed_node_set() {
    let _watchdog = testutil::arm(WATCHDOG);

    let cfg = s2_fixture();
    let real = Zone::from_config(&cfg).expect("fixture zone builds");
    let frozen = FrozenZone::build(&cfg).expect("transcription builds the same fixture");
    let model = ConfigModel::build(&cfg);
    let ents = ancestor_closure(&cfg);
    let mut ent_list: Vec<LowerName> = ents.iter().cloned().collect();
    ent_list.sort_by_key(std::string::ToString::to_string);
    let s2 = FrozenZone::build(&cfg)
        .expect("the transcription builds twice")
        .materialise_ancestors(&ent_list);
    let s3 = FrozenZone::build(&cfg)
        .expect("the transcription builds three times")
        .materialise_ancestors(&ent_list)
        .under_the_rfc_rule();
    let origin_depth = label_count(&frozen.lower_origin);

    assert_eq!(real.record_count(), frozen.record_count);
    assert_eq!(render_soa(real.soa()), render_soa(frozen.soa.as_ref()));

    let names = fixture_names();
    let types = [
        RecordType::A,
        RecordType::AAAA,
        RecordType::TXT,
        RecordType::CNAME,
        RecordType::SOA,
        RecordType::ANY,
    ];

    let mut compared = 0usize;
    let mut seen: HashSet<Transition> = HashSet::new();
    for name in &names {
        let queried = lower(name);
        assert_eq!(
            real.exists(&queried),
            s3.exists(&queried),
            "Zone::exists disagreed for {name}"
        );
        for qtype in types {
            let actual = real.lookup(&queried, qtype);
            let expected = s3.lookup(&queried, qtype);
            assert_eq!(
                rendered(&actual),
                rendered(&expected),
                "{name} {qtype} disagreed with a brute-force transcription of RFC \
                 4592 §3.3.1 over the ancestor-closed node set"
            );

            // S3's fence.
            let after_s2 = s2.lookup(&queried, qtype);
            if rendered(&after_s2) != rendered(&expected) {
                assert!(
                    classify_s3(&model, &queried, qtype, &after_s2, &expected).is_some(),
                    "{name} {qtype} changed between the deepest-wins rule and the \
                     closest-encloser rule, and the change is not one that rule \
                     can produce\n  before: {after_s2:?}\n  after:  {expected:?}"
                );
            }

            // S2's fence, KEPT, with its class counting.
            let before = frozen.lookup(&queried, qtype);
            if rendered(&before) != rendered(&after_s2) {
                let class = classify(&ents, origin_depth, &queried, &before, &after_s2)
                    .unwrap_or_else(|| {
                        panic!(
                            "{name} {qtype} changed between the pre-S2 and post-S2 \
                             node sets and the change is not one ancestor closure \
                             can produce\n  before: {before:?}\n  after:  {after_s2:?}"
                        )
                    });
                seen.insert(class);
            }
            compared += 1;
        }
    }

    assert_eq!(
        compared,
        names.len() * types.len(),
        "the branch sweep did not run every pair; a loop that silently skips is \
         a gate that silently passes"
    );
    assert!(
        !seen.is_empty(),
        "the fixture produced no S2 transition at all, so this sweep is \
         measuring S1 and calling it S2"
    );
}

/// Scenario: The wildcard no longer applies below a name that exists — S3
/// discharges the fence
/// features/empty-non-terminals.feature:327
///
/// AMENDED AT S3 only in its citation. The scenario it names inverted when S3
/// landed — it used to assert that `a.deep.dev` was still answered from `*.dev`
/// — but what THIS test does is unchanged and must stay unchanged: it hands S2's
/// classifier the transition S3 makes and requires `None`. The fence is what
/// stopped that fix landing a commit early; keeping the assertion after the fix
/// has landed is what stops S2's classifier being widened later to cover
/// something it never covered.
///
/// **The proof that the permitted transition set is not too loose**, and the
/// reason it is three named classes rather than "NXDOMAIN may become NODATA".
///
/// S3 fixes VEGA-009: `*.dev` stops applying below `deep.dev`, so
/// `a.deep.dev.example.test.` goes from a synthesised A record to NXDOMAIN.
/// S2 must not do that, and a differential that permitted it would let the fix
/// land a step early, un-reviewed, with S3's own differential never written.
/// Here the classifier is handed that exact transition and must refuse it.
///
/// The blanket rule is refused in the same test: an NXDOMAIN that becomes NODATA
/// at a name which is neither an empty non-terminal nor covered by one is *not*
/// a transition ancestor closure can produce, whatever it looks like from the
/// outside. This is the assertion that would have to be deleted, not merely
/// weakened, for a wrong S2 to pass.
#[test]
fn the_classifier_refuses_transitions_ancestor_closure_cannot_produce() {
    let cfg = s2_fixture();
    let ents = ancestor_closure(&cfg);
    let origin_depth = 2; // example.test.

    let synthesised = Answer::Records(vec![Record::from_rdata(
        Name::from(lower(&format!("a.deep.dev.{ORIGIN}."))),
        300,
        rdata::parse_value(RecordType::A, "*.dev", "203.0.113.50").expect("fixture rdata parses"),
    )]);
    assert_eq!(
        classify(
            &ents,
            origin_depth,
            &lower(&format!("a.deep.dev.{ORIGIN}.")),
            &synthesised,
            &Answer::NxDomain,
        ),
        None,
        "the classifier accepted VEGA-009's fix as an S2 transition. \
         `deep.dev` exists, so RFC 4592 §3.3.1 makes `*.deep.dev` the only \
         source of synthesis and this name NXDOMAIN — but that is S3's change, \
         and a differential that permits it here lets the closest-encloser \
         rewrite land a commit early with nothing checking it"
    );

    assert_eq!(
        classify(
            &ents,
            origin_depth,
            &lower(&format!("nothing.{ORIGIN}.")),
            &Answer::NxDomain,
            &Answer::NoData,
        ),
        None,
        "the classifier accepted a blanket NXDOMAIN -> NODATA. Nothing exists \
         at or below `nothing.{ORIGIN}.`, so a name error there is correct; \
         permitting the transition wherever it appears is the loose rule that \
         would also pass a zone which had stopped denying anything at all"
    );

    assert_eq!(
        classify(
            &ents,
            origin_depth,
            &lower(&format!("svc.{ORIGIN}.")),
            &Answer::NxDomain,
            &synthesised,
        ),
        None,
        "the classifier accepted RECORDS at an empty non-terminal. It is a node \
         with no RRsets (RFC 4592 §2.2.2) — NODATA and nothing else. Accepting \
         any answer here would let a build that filed a descendant's records at \
         its ancestor through the differential"
    );

    // …and the control: the transition it must accept, so this test cannot pass
    // by refusing everything.
    let ent = lower(&format!("svc.{ORIGIN}."));
    assert!(
        ents.contains(&ent),
        "the fixture must actually declare something beneath {ent}"
    );
    assert_eq!(
        classify(
            &ents,
            origin_depth,
            &ent,
            &Answer::NxDomain,
            &Answer::NoData
        ),
        Some(Transition::EmptyNonTerminalExists),
    );
}

/// Scenario: All three transition classes are actually reached
/// features/empty-non-terminals.feature:406
///
/// The anti-vacuity half of the differential, and **it does not touch the
/// implementation at all**: it runs the fixture through the transcription twice,
/// once over the declared node set and once over the ancestor-closed one, and
/// requires each of the three permitted transitions to appear.
///
/// Kept separate from the sweep above for one reason: the sweep is RED until S2
/// lands, so an assertion buried at its end would not run until then — and a
/// classification nobody has ever exercised is a whitelist, not a gate. This one
/// is green today. If it goes red, either the fixture stopped producing a shape
/// or `classify` stopped recognising one, and in both cases the property that
/// depends on it has quietly widened.
#[test]
fn each_permitted_transition_class_is_reached_by_the_fixture() {
    let _watchdog = testutil::arm(WATCHDOG);

    let mut seen: HashSet<Transition> = HashSet::new();
    let mut unclassified: Vec<String> = Vec::new();

    for cfg in [s2_fixture(), t2_fixture()] {
        let frozen = FrozenZone::build(&cfg).expect("fixture builds");
        let ents = ancestor_closure(&cfg);
        let mut ent_list: Vec<LowerName> = ents.iter().cloned().collect();
        ent_list.sort_by_key(std::string::ToString::to_string);
        let s2 = FrozenZone::build(&cfg)
            .expect("fixture builds twice")
            .materialise_ancestors(&ent_list);
        let origin_depth = label_count(&frozen.lower_origin);

        assert!(
            !ents.is_empty(),
            "the fixture declares no name with a strict ancestor, so it cannot \
             exercise ancestor closure"
        );
        // The closure's DEPTH, pinned. `a.b.svc` implies `b.svc` *and* `svc`,
        // and a loop that stops one level short still produces all three
        // transition classes below — so without this the class check passes
        // against a closure that leaves every grandparent NXDOMAIN, which is
        // the same RFC 8020 §2 denial one label higher. Found by hand-applying
        // exactly that mutant.
        for required in [
            format!("b.svc.{ORIGIN}."),
            format!("svc.{ORIGIN}."),
            format!("_tcp.host.{ORIGIN}."),
        ] {
            assert!(
                ents.contains(&lower(&required)),
                "{required} is a strict ancestor of a configured owner and is \
                 not in the closure. Every ancestor up to the origin is a node \
                 (RFC 4592 §2.2.2, ruling I-3), not just the immediate parent"
            );
        }

        for name in fixture_names() {
            let queried = lower(&name);
            for qtype in [
                RecordType::A,
                RecordType::AAAA,
                RecordType::TXT,
                RecordType::SRV,
                RecordType::CNAME,
                RecordType::ANY,
            ] {
                let before = frozen.lookup(&queried, qtype);
                let after = s2.lookup(&queried, qtype);
                if rendered(&before) == rendered(&after) {
                    continue;
                }
                match classify(&ents, origin_depth, &queried, &before, &after) {
                    Some(class) => {
                        seen.insert(class);
                    }
                    None => unclassified.push(format!("{name} {qtype}: {before:?} -> {after:?}")),
                }
            }
        }
    }

    assert!(
        unclassified.is_empty(),
        "ancestor closure alone produced a difference that `classify` does not \
         recognise. Either the closure is doing more than closing the node set \
         under ancestry, or there is a fourth transition class that has to be \
         named and specced before S2 can be accepted:\n  - {}",
        unclassified.join("\n  - ")
    );

    for required in [
        Transition::EmptyNonTerminalExists,
        Transition::CoveredByAWildcardEmptyNonTerminal,
        Transition::CnameChaseStopsAtAnEmptyNonTerminal,
    ] {
        assert!(
            seen.contains(&required),
            "{required:?} was never observed on this fixture, so the \
             classification in the property above permits it without ever \
             checking it. A transition class nothing exercises is a whitelist \
             entry, not a gate. Observed: {seen:?}"
        );
    }
}

// ===========================================================================
// S3 — the closest encloser (VEGA-009, VEGA-078)
// ===========================================================================

/// The S3 fixture, built so that a closest-encloser search which is **short by
/// one level** changes an answer in both directions.
///
/// S2's first classifier accepted a mutant whose ancestor closure stopped one
/// level short, because the fixture it was checked against still produced every
/// transition class with the shallower closure. The lesson is that an off-by-one
/// in a depth search is only visible on a LADDER — two wildcards at adjacent
/// depths with an existing name between them — and this fixture carries one:
///
/// ```text
///   *.dev            answers q.dev
///   deep.dev         exists, holds no wildcard
///   x.deep.dev       exists, so it encloses q.x.deep.dev
///   *.x.deep.dev     answers q.x.deep.dev
/// ```
///
/// A search short by one answers `q.x.deep.dev` NXDOMAIN (it looks for
/// `*.deep.dev`) *and* answers `q.deep.dev` from `*.dev` (it looks for `*.dev`).
/// Two failures in opposite directions from one off-by-one; either alone would
/// be invisible without the ladder. `the_fixture_exposes_a_closest_encloser_
/// computed_one_level_short` asserts the ladder is actually there, so it cannot
/// be edited away by a diff that looks like tidying.
///
/// The rest of the records exist one per transition class and per branch:
/// `*.carve` over `sub.carve` over `*.sub.carve TXT` gives W1's NODATA arm (the
/// source of synthesis exists and carries the wrong type); `a.b.svc` gives an
/// empty non-terminal that must NOT move at S3; `toCarve` is a CNAME into a
/// carved-out name for W3.
fn s3_fixture() -> ZoneConfig {
    let spec = |name: &str, ty: &str, value: &str| RecordSpec {
        name: name.to_owned(),
        record_type: ty.to_owned(),
        ttl: None,
        values: vec![value.to_owned()],
    };
    ZoneConfig {
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
            spec("host", "A", "203.0.113.20"),
            // The ladder. Do not flatten it.
            spec("*.dev", "A", "203.0.113.50"),
            spec("deep.dev", "A", "203.0.113.51"),
            spec("x.deep.dev", "A", "203.0.113.52"),
            spec("*.x.deep.dev", "A", "203.0.113.53"),
            // W1's NODATA arm: the source of synthesis exists and carries only
            // TXT, so an A query stops there instead of walking up to `*.carve`.
            spec("*.carve", "A", "203.0.113.60"),
            spec("sub.carve", "A", "203.0.113.61"),
            spec("*.sub.carve", "TXT", "\"only text here\""),
            // An empty non-terminal, which S3 must not touch: `b.svc` and `svc`
            // exist because `a.b.svc` does.
            spec("a.b.svc", "A", "203.0.113.70"),
            // W3: a CNAME whose target is inside the carve-out, so the chase
            // that used to append `*.dev`'s synthesised A now stops at the CNAME.
            spec("tocarve", "CNAME", &format!("q.deep.dev.{ORIGIN}.")),
            // VEGA-098: makes `*.zone.example.test.` an empty non-terminal that
            // is ALSO a wildcard. A name that exists stops synthesis whatever
            // its leftmost label is (RFC 4592 §2.1.1, §2.2.2), so a wildcard
            // above it must not be applied AT it. Paired with the apex wildcard
            // in `s3_apex_wildcard_fixture`, which is what makes the divergence
            // observable — found on `main` by the very oracle S3 retires.
            spec("x.*.zone", "A", "203.0.113.80"),
        ],
    }
}

/// The same fixture **plus an apex wildcard**, which masks W2.
///
/// An apex `*` covers every name in the zone, so no name below it is ever
/// NXDOMAIN under the old rule and "the name error is restored" cannot be
/// observed — except at the apex wildcard's own level, which is exactly what
/// this variant reaches. The mirror image of S2's `t2_fixture`, and here for the
/// same reason: a class reported as unreachable because one fixture happened to
/// hide it is the failure mode this file exists to avoid.
fn s3_apex_wildcard_fixture() -> ZoneConfig {
    let mut cfg = s3_fixture();
    cfg.records.push(RecordSpec {
        name: "*".to_owned(),
        record_type: "A".to_owned(),
        ttl: None,
        values: vec!["203.0.113.1".to_owned()],
    });
    cfg
}

/// The names swept against the S3 fixtures, one per branch of the rule.
fn s3_fixture_names() -> Vec<String> {
    vec![
        ORIGIN.to_owned() + ".",
        format!("host.{ORIGIN}."),
        // The ladder, queried at all three rungs.
        format!("q.dev.{ORIGIN}."),
        format!("q.deep.dev.{ORIGIN}."),
        format!("q.x.deep.dev.{ORIGIN}."),
        format!("q.r.x.deep.dev.{ORIGIN}."),
        format!("deep.dev.{ORIGIN}."),
        format!("x.deep.dev.{ORIGIN}."),
        format!("*.dev.{ORIGIN}."),
        format!("dev.{ORIGIN}."),
        // The type-miss arm.
        format!("q.carve.{ORIGIN}."),
        format!("q.sub.carve.{ORIGIN}."),
        format!("sub.carve.{ORIGIN}."),
        // Empty non-terminals: NODATA, and S3 must leave them alone.
        format!("b.svc.{ORIGIN}."),
        format!("svc.{ORIGIN}."),
        format!("q.b.svc.{ORIGIN}."),
        // The CNAME into the carve-out.
        format!("tocarve.{ORIGIN}."),
        // VEGA-098's shape: a wildcard that is an empty non-terminal, a name it
        // covers, and its parent.
        format!("*.zone.{ORIGIN}."),
        format!("covered.zone.{ORIGIN}."),
        format!("zone.{ORIGIN}."),
        // Names nothing encloses tightly, and names outside the zone.
        format!("nothing.{ORIGIN}."),
        format!("a.b.c.d.{ORIGIN}."),
        "example.invalid.".to_owned(),
        ".".to_owned(),
    ]
}

/// Scenario: A closest encloser computed one level short is visible in an
/// answer
/// features/closest-encloser.feature:265
///
/// The anti-masking check, and it runs against the **config model** rather than
/// against the implementation, so it holds even while the implementation is
/// wrong. S2's warning made concrete: its class check passed against a closure
/// that stopped one level short, because its own fixture still produced all
/// three classes either way. This asserts the ladder rung by rung, so a
/// classifier whose own `closest_encloser` is short by one fails HERE rather
/// than silently agreeing with a short implementation.
#[test]
fn the_fixture_exposes_a_closest_encloser_computed_one_level_short() {
    let _watchdog = testutil::arm(WATCHDOG);
    let model = ConfigModel::build(&s3_fixture());

    for (query, encloser, synthesises) in [
        // Deepest rung: enclosed by a name that DOES hold a wildcard.
        (
            format!("q.x.deep.dev.{ORIGIN}."),
            format!("x.deep.dev.{ORIGIN}."),
            true,
        ),
        // Middle rung: enclosed by a name that does NOT. A search short by one
        // lands on `dev` here and leaks `*.dev` into the carve-out.
        (
            format!("q.deep.dev.{ORIGIN}."),
            format!("deep.dev.{ORIGIN}."),
            false,
        ),
        // Shallowest rung: enclosed by the wildcard's own parent.
        (format!("q.dev.{ORIGIN}."), format!("dev.{ORIGIN}."), true),
    ] {
        let ce = model
            .closest_encloser(&lower(&query))
            .unwrap_or_else(|| panic!("{query} is strictly below the origin, so it has one"));
        assert_eq!(
            ce,
            lower(&encloser),
            "the closest encloser of {query} is {encloser}. A search that is \
             short by one level returns a shallower name here, which is how a \
             wildcard synthesises into a subtree an operator carved out — \
             VEGA-009 reopened, with answers that look correct"
        );
        assert_eq!(
            model.wildcard_parents.contains(&ce),
            synthesises,
            "{encloser} {} hold a wildcard. The ladder only exposes an \
             off-by-one while adjacent rungs disagree about this",
            if synthesises { "must" } else { "must not" }
        );
    }

    // …and the ladder must actually be a ladder: three consecutive depths.
    assert_eq!(
        model
            .closest_encloser(&lower(&format!("q.x.deep.dev.{ORIGIN}.")))
            .map(|n| Name::from(n).iter().len()),
        Some(5),
        "the ladder's rungs must sit at consecutive depths, or a search short \
         by one still lands on a name that agrees with the truth"
    );
}

/// Scenario: The classifier refuses transitions the closest-encloser rule cannot
/// produce
/// features/closest-encloser.feature:514
///
/// **The proof that the permitted transition set is not too loose**, and the
/// reason it is three named classes with derived preconditions rather than
/// "a synthesised answer may become NXDOMAIN".
///
/// Five refusals and two accepts. The accepts are not decoration: without them
/// this test passes against a classifier that returns `None` for everything,
/// which would make the differential vacuous in the one direction nobody checks.
#[test]
// Five refusals and three accepts belong in ONE test. Split them and the refusal
// half keeps passing while somebody deletes the accepts, which is the exact
// failure mode this test exists to prevent: a classifier that returns `None` for
// everything refuses every wrong transition and makes the differential vacuous.
// The lint is measuring length; the property being asserted is that the two
// halves cannot be separated.
#[allow(clippy::too_many_lines)]
fn the_classifier_refuses_transitions_the_closest_encloser_rule_cannot_produce() {
    let cfg = s3_fixture();
    let model = ConfigModel::build(&cfg);

    let synthesised_at = |name: &str, value: &str| {
        Answer::Records(vec![Record::from_rdata(
            Name::from(lower(name)),
            300,
            rdata::parse_value(RecordType::A, "*", value).expect("fixture rdata parses"),
        )])
    };

    // ---------------------------------------------------------------- REFUSE
    // 1. S3 must not undo S2. An empty non-terminal is a name that EXISTS, so
    //    no wildcard rule of any kind applies to it. A classifier that permitted
    //    NODATA -> NXDOMAIN wherever it appeared would let S3 silently reopen
    //    VEGA-006 while closing VEGA-009, and this differential would stay green
    //    the whole time. This is the highest-value assertion in the file.
    let ent = lower(&format!("svc.{ORIGIN}."));
    assert!(
        model.nodes.contains(&ent),
        "the fixture must actually declare something beneath {ent}, or this \
         refusal is about a name that does not exist"
    );
    assert_eq!(
        classify_s3(
            &model,
            &ent,
            RecordType::A,
            &Answer::NoData,
            &Answer::NxDomain
        ),
        None,
        "the classifier accepted an empty non-terminal losing its NODATA. \
         `svc.{ORIGIN}.` exists because `a.b.svc.{ORIGIN}.` does (RFC 4592 \
         §2.2.2); a name error there is cached for the SOA MINIMUM and, under \
         RFC 8020 §2, denies the record beneath it. S3 changes which WILDCARD \
         answers a covered name and nothing about which names exist"
    );

    // 2. Legitimate synthesis must not be droppable. `q.dev` is enclosed by
    //    `dev`, which holds `*.dev` carrying A, so the RFC answer is a record.
    //    A build that simply stopped synthesising produces exactly this
    //    transition, and it must not be classifiable.
    assert_eq!(
        classify_s3(
            &model,
            &lower(&format!("q.dev.{ORIGIN}.")),
            RecordType::A,
            &synthesised_at(&format!("q.dev.{ORIGIN}."), "203.0.113.50"),
            &Answer::NxDomain,
        ),
        None,
        "the classifier accepted a wildcard being switched off. `dev.{ORIGIN}.` \
         IS the closest encloser of `q.dev.{ORIGIN}.` and it holds `*.dev` with \
         an A record, so RFC 4592 §3.3.1 requires the synthesis. Permitting this \
         would let 'delete the wildcard probe' pass the differential"
    );

    // 3. The reverse direction: a wildcard GAINING reach below an existing
    //    name. That is the signature of a closest-encloser search that is short
    //    by one, and it is the mutant the ruling calls the most dangerous in the
    //    model. S3 narrows synthesis; it never widens it.
    assert_eq!(
        classify_s3(
            &model,
            &lower(&format!("q.deep.dev.{ORIGIN}.")),
            RecordType::A,
            &Answer::NxDomain,
            &synthesised_at(&format!("q.deep.dev.{ORIGIN}."), "203.0.113.50"),
        ),
        None,
        "the classifier accepted a wildcard REACHING FURTHER after S3. \
         `deep.dev.{ORIGIN}.` exists, so it encloses `q.deep.dev.{ORIGIN}.` and \
         `*.dev` must not apply. A search that is short by one produces exactly \
         this, and it is VEGA-009 reopened wearing a green differential"
    );

    // 4. The blanket rule, refused. A name whose closest encloser DOES hold the
    //    wildcard that answered it is unaffected by S3, whatever the transition
    //    looks like from outside.
    assert_eq!(
        classify_s3(
            &model,
            &lower(&format!("q.dev.{ORIGIN}.")),
            RecordType::A,
            &synthesised_at(&format!("q.dev.{ORIGIN}."), "203.0.113.50"),
            &Answer::NoData,
        ),
        None,
        "the classifier accepted RECORDS becoming NODATA at a name the closest \
         encloser's own wildcard answers. `*.dev` carries A and `dev` is the \
         closest encloser, so RFC 4592 §3.3.1 requires the record"
    );

    // 5. And a name nothing ever covered: there is no coverage to narrow, so
    //    there is no transition to permit.
    assert_eq!(
        classify_s3(
            &model,
            &lower(&format!("nothing.{ORIGIN}.")),
            RecordType::A,
            &Answer::NoData,
            &Answer::NxDomain,
        ),
        None,
        "the classifier accepted a blanket NODATA -> NXDOMAIN. No wildcard is an \
         ancestor of `nothing.{ORIGIN}.` in this fixture, so nothing covered it \
         before S3 and nothing stopped covering it at S3"
    );

    // ---------------------------------------------------------------- ACCEPT
    // 6. VEGA-009's own transition: the wildcard stops reaching into the
    //    carve-out and the name error appears.
    assert_eq!(
        classify_s3(
            &model,
            &lower(&format!("q.deep.dev.{ORIGIN}.")),
            RecordType::A,
            &synthesised_at(&format!("q.deep.dev.{ORIGIN}."), "203.0.113.50"),
            &Answer::NxDomain,
        ),
        Some(S3Transition::SynthesisRestrictedToTheClosestEncloser),
        "this IS VEGA-009's transition and the classifier must recognise it, or \
         the differential passes by refusing everything"
    );

    // 5b. W4, refused in the direction that would lose a wildcard node's OWN
    //     records. `*.dev` declares an A record, so a query for its literal name
    //     is an exact match under RFC 1034 §4.3.2 step 3.a and must return it —
    //     RFC 4592 §2.3, an asterisk in a QNAME gets no special processing.
    //     Removing the exact probe's wildcard exclusion must make these names
    //     answer MORE precisely, never make them answer nothing.
    let wildcard_node = lower(&format!("*.dev.{ORIGIN}."));
    assert!(
        model.nodes.contains(&wildcard_node),
        "the fixture must declare `*.dev`, or this refusal is about a name that \
         does not exist"
    );
    assert_eq!(
        classify_s3(
            &model,
            &wildcard_node,
            RecordType::A,
            &synthesised_at(&format!("*.dev.{ORIGIN}."), "203.0.113.50"),
            &Answer::NoData,
        ),
        None,
        "the classifier accepted a wildcard node losing its own A record. \
         `*.dev.{ORIGIN}.` declares one, and a query for that literal name is an \
         exact match (RFC 4592 §2.3, RFC 1034 §4.3.2 step 3.a). W4 refuses \
         synthesis AT a name that exists; it does not refuse the name's own \
         RRset"
    );

    // 7. W1's other arm: the source of synthesis exists and carries the wrong
    //    type, so the answer is NODATA rather than a name error, and it must not
    //    fall back to `*.carve`.
    assert_eq!(
        classify_s3(
            &model,
            &lower(&format!("q.sub.carve.{ORIGIN}.")),
            RecordType::A,
            &synthesised_at(&format!("q.sub.carve.{ORIGIN}."), "203.0.113.60"),
            &Answer::NoData,
        ),
        Some(S3Transition::SynthesisRestrictedToTheClosestEncloser),
        "`*.sub.carve` is the source of synthesis and carries only TXT. RFC 1034 \
         §4.3.2 step 3(c) sets the name error only when the `*` node is absent, \
         and it is present, so this is NODATA — and `*.carve`'s A record must \
         not be reached (\"there is no search for an alternate\")"
    );

    // 8. W4's accept: a wildcard-shaped EMPTY NON-TERMINAL stops synthesis at
    //    itself. `*.zone` exists because `x.*.zone` is configured beneath it and
    //    it declares nothing, so the answer is NODATA and no wildcard above it
    //    may be applied. VEGA-098.
    let wildcard_ent = lower(&format!("*.zone.{ORIGIN}."));
    assert!(
        model.nodes.contains(&wildcard_ent)
            && !model
                .wildcard_types
                .iter()
                .any(|(p, _)| { *p == wildcard_ent.base_name() }),
        "the fixture must make `*.zone.{ORIGIN}.` an empty non-terminal — a node \
         that declares no RRset of its own — or this accept is about a different \
         shape entirely"
    );
    assert_eq!(
        classify_s3(
            &model,
            &wildcard_ent,
            RecordType::A,
            &synthesised_at(&format!("*.zone.{ORIGIN}."), "203.0.113.1"),
            &Answer::NoData,
        ),
        Some(S3Transition::SynthesisRefusedAtAWildcardNameThatExists),
        "this IS VEGA-098's transition and the classifier must recognise it. It \
         is the class no ruling predicted and no hand-written S3 fixture \
         contained; it turned up as an unclassified difference, which is the \
         only reason it is specced at all"
    );
}

/// Scenario: All four transition classes are actually reached
/// features/closest-encloser.feature:536
///
/// The anti-vacuity half of the S3 differential, and — like S2's — it **does not
/// touch the implementation at all**. It runs the fixtures through the
/// transcription twice, once under the deepest-wins rule and once under RFC 4592
/// §3.3.1, and requires each of the three permitted transitions to appear.
///
/// Kept separate from the sweep for one reason: the sweep is RED until S3 lands,
/// so an assertion buried at its end would not run until then — and a
/// classification nobody has ever exercised is a whitelist, not a gate. This one
/// is GREEN TODAY. If it goes red, either a fixture stopped producing a shape or
/// `classify_s3` stopped recognising one, and in both cases the property that
/// depends on it has quietly widened.
#[test]
fn each_permitted_s3_transition_class_is_reached_by_the_fixture() {
    let _watchdog = testutil::arm(WATCHDOG);

    let mut seen: HashSet<S3Transition> = HashSet::new();
    let mut unclassified: Vec<String> = Vec::new();

    for cfg in [s3_fixture(), s3_apex_wildcard_fixture()] {
        let model = ConfigModel::build(&cfg);
        let ents = ancestor_closure(&cfg);
        let mut ent_list: Vec<LowerName> = ents.iter().cloned().collect();
        ent_list.sort_by_key(std::string::ToString::to_string);

        let s2 = FrozenZone::build(&cfg)
            .expect("fixture builds")
            .materialise_ancestors(&ent_list);
        let s3 = FrozenZone::build(&cfg)
            .expect("fixture builds twice")
            .materialise_ancestors(&ent_list)
            .under_the_rfc_rule();

        for name in s3_fixture_names() {
            let queried = lower(&name);
            for qtype in [
                RecordType::A,
                RecordType::AAAA,
                RecordType::TXT,
                RecordType::CNAME,
                RecordType::ANY,
            ] {
                let before = s2.lookup(&queried, qtype);
                let after = s3.lookup(&queried, qtype);
                if rendered(&before) == rendered(&after) {
                    continue;
                }
                match classify_s3(&model, &queried, qtype, &before, &after) {
                    Some(class) => {
                        seen.insert(class);
                    }
                    None => unclassified.push(format!("{name} {qtype}: {before:?} -> {after:?}")),
                }
            }
        }
    }

    assert!(
        unclassified.is_empty(),
        "the closest-encloser rule alone produced a difference that \
         `classify_s3` does not recognise. Either the rule is doing more than \
         restricting synthesis to `*.<closest encloser>`, or there is a fourth \
         transition class that has to be named and specced before S3 can be \
         accepted:\n  - {}",
        unclassified.join("\n  - ")
    );

    for required in [
        S3Transition::SynthesisRestrictedToTheClosestEncloser,
        S3Transition::NameErrorRestoredAboveTheClosestEncloser,
        S3Transition::CnameChaseLosesAnUnreachableSynthesis,
        S3Transition::SynthesisRefusedAtAWildcardNameThatExists,
    ] {
        assert!(
            seen.contains(&required),
            "{required:?} was never observed on these fixtures, so the \
             classification in the property permits it without ever checking \
             it. A transition class nothing exercises is a whitelist entry, not \
             a gate. Observed: {seen:?}"
        );
    }
}

/// Scenario: Every S3 difference is one of four named classes
/// features/closest-encloser.feature:483
///
/// The deterministic branch sweep for S3, and the file's load-bearing assertion:
/// the arena answers **what RFC 4592 §3.3.1 answers**, and every difference from
/// the pre-S3 rule is classified.
///
/// Three oracles run over one fixture, and all three comparisons are kept:
///
///   * `frozen` — deepest-wins over the DECLARED node set, i.e. pre-S2;
///   * `s2` — deepest-wins over the ancestor-closed node set, i.e. pre-S3;
///   * `s3` — the RFC rule over the same closed node set.
///
/// `real == s3` is S3's claim. `s2 -> s3` classified by `classify_s3` is S3's
/// fence. `frozen -> s2` classified by S2's `classify` is **kept**, so that S3
/// cannot quietly undo S2's three classes while satisfying its own — which is
/// the one way a step in this sequence could regress the step before it and stay
/// green.
///
/// # Status: FAILS TODAY, and for the right reason
///
/// `q.deep.dev.example.test.` is answered from `*.dev` before S3 and is NXDOMAIN
/// after it.
#[test]
fn every_branch_of_the_lookup_agrees_with_the_rfc_4592_closest_encloser_rule() {
    let _watchdog = testutil::arm(WATCHDOG);

    let cfg = s3_fixture();
    let real = Zone::from_config(&cfg).expect("fixture zone builds");
    let model = ConfigModel::build(&cfg);
    let ents = ancestor_closure(&cfg);
    let mut ent_list: Vec<LowerName> = ents.iter().cloned().collect();
    ent_list.sort_by_key(std::string::ToString::to_string);

    let frozen = FrozenZone::build(&cfg).expect("the transcription builds the fixture");
    let s2 = FrozenZone::build(&cfg)
        .expect("the transcription builds twice")
        .materialise_ancestors(&ent_list);
    let s3 = FrozenZone::build(&cfg)
        .expect("the transcription builds three times")
        .materialise_ancestors(&ent_list)
        .under_the_rfc_rule();
    let origin_depth = label_count(&frozen.lower_origin);

    let types = [
        RecordType::A,
        RecordType::AAAA,
        RecordType::TXT,
        RecordType::CNAME,
        RecordType::SOA,
        RecordType::ANY,
    ];
    let names = s3_fixture_names();
    let mut compared = 0usize;

    for name in &names {
        let queried = lower(name);
        assert_eq!(
            real.exists(&queried),
            s3.exists(&queried),
            "`Zone::exists` disagreed for {name}. It is the RFC 1034 §4.3.2 step \
             3(c) name-error determination and the one predicate the DNSSEC \
             proof machinery will read, so it narrows to the closest encloser \
             with everything else"
        );

        for qtype in types {
            let actual = real.lookup(&queried, qtype);
            let expected = s3.lookup(&queried, qtype);
            assert_eq!(
                rendered(&actual),
                rendered(&expected),
                "{name} {qtype} disagreed with a brute-force transcription of \
                 RFC 4592 §3.3.1 over the ancestor-closed node set. Same \
                 variant, same records, same owner names, same TTLs, same rdata, \
                 same order"
            );

            // S3's fence.
            let before_s3 = s2.lookup(&queried, qtype);
            if rendered(&before_s3) != rendered(&expected) {
                assert!(
                    classify_s3(&model, &queried, qtype, &before_s3, &expected).is_some(),
                    "{name} {qtype} changed between the deepest-wins rule and \
                     the closest-encloser rule, and the change is not one the \
                     rule can produce (W1 synthesis restricted to the closest \
                     encloser, W2 the name error restored, W3 a CNAME chase \
                     losing an unreachable synthesis, W4 synthesis refused at a \
                     wildcard name that exists)\n  before: {before_s3:?}\n  \
                     after:  {expected:?}"
                );
            }

            // S2's fence, KEPT. S3 must not spend S2's gains to pay for its own.
            let before_s2 = frozen.lookup(&queried, qtype);
            let after_s2 = s2.lookup(&queried, qtype);
            if rendered(&before_s2) != rendered(&after_s2) {
                assert!(
                    classify(&ents, origin_depth, &queried, &before_s2, &after_s2).is_some(),
                    "{name} {qtype} broke S2's classification while S3 was being \
                     specced. Ancestor closure and the closest-encloser rule are \
                     independent claims and both are still checked here"
                );
            }
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
