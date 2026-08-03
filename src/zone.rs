//! The in-memory zone: a canonically ordered arena of nodes, plus the lookup
//! algorithm that turns a query into an answer.
//!
//! The store is immutable once built, so it can be shared across every worker
//! task behind an [`std::sync::Arc`] with no locking on the query path.
//!
//! # The shape, and why it is this shape
//!
//! Three flat `Box<[T]>` — nodes, RRsets, RDATA — plus a
//! [`hashbrown::HashTable`] of node indices keyed on a per-zone-seeded,
//! label-wise hash of the owner name. Three allocations for a whole zone, where
//! the parallel `HashMap`/`HashSet` model this replaces cost roughly three per
//! record: 128.0 MiB and 600,035 allocations for 100,000 records, because the
//! owner name was stored once per **record** and every single-record set carried
//! a `Vec` over-allocated to `Vec`'s minimum capacity of four.
//!
//! The arena is physically ordered by RFC 4034 §6.1 canonical DNS name order
//! from the first commit, so node index order *is* canonical order and every
//! ancestor precedes its descendants. **Nothing reads that order yet.** It is
//! pinned now because its failure mode is invisible until DNSSEC signs a zone,
//! at which point the NSEC chain does not close and every validating resolver
//! SERVFAILs the whole zone.
//!
//! The node set is **closed under ancestry**, up to but never past the origin:
//! a name that exists only because something exists beneath it is a node with
//! no RRsets, and answers NODATA rather than NXDOMAIN (RFC 4592 §2.2.2). That
//! is not a nicety — RFC 8020 §2 lets a resolver apply one cached NXDOMAIN to
//! the entire subtree below it, so denying an empty non-terminal denies the
//! records that do exist under it (VEGA-006).
//!
//! # What this module does NOT do yet
//!
//! This is S2 of the six commits VEGA-032 sequences. A wildcard still applies
//! below a name that exists rather than only under the closest encloser (S3),
//! there is no delegation, glue or occlusion handling (S4), and SOA and apex NS
//! are still optional (S5). `tests/arena_differential.rs` holds this file to a
//! transcription of the implementation S1 replaced, fed a node set closed under
//! ancestry, and permits exactly three classes of difference — all three
//! consequences of that closure and each derived from the config rather than
//! from what this file returned.
//!
//! Ruling: `.claude/backlog/decisions/VEGA-032-zone-data-model.md`.

use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::hash::BuildHasher;
use std::ops::Range;

use anyhow::{bail, Context, Result};
use hashbrown::HashTable;
use hickory_proto::rr::{
    rdata::{NS, SOA},
    LowerName, Name, RData, Record, RecordType,
};

use crate::{
    canonical::write_canonical_sort_key,
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

// ---------------------------------------------------------------------------
// VEGA-032 S0/S1 — the primitives the node arena is built and probed with.
// ---------------------------------------------------------------------------

/// Index into the node arena.
///
/// A `u32` caps a zone at `u32::MAX - 1` nodes; the build fails with a named
/// error rather than wrapping, because a wrapped index answers the wrong
/// records and says nothing about it.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) struct NodeIdx(u32);

impl NodeIdx {
    /// The apex is always node 0: canonical order puts the shortest name in the
    /// zone first, and every other node in a zone is a descendant of the apex.
    pub(crate) const APEX: Self = Self(0);

    /// "No delegation at or above this node". A sentinel rather than an
    /// `Option<NodeIdx>` so the field stays four bytes instead of eight.
    // Read by `Node::cut`, which arrives with delegation at S4. Kept here rather
    // than added then, because it is the other half of `APEX`'s contract that a
    // `u32` index reserves two values and the build must never hand out either.
    #[allow(dead_code)]
    pub(crate) const NONE: Self = Self(u32::MAX);

    /// The arena position, for slice access. Never `[]`: a range built at build
    /// time "must" be valid is exactly the assumption the next refactor
    /// falsifies, and with `panic = "abort"` one bad index is a full outage.
    pub(crate) fn get(self) -> usize {
        self.0 as usize
    }
}

/// Multiplier of the per-octet fold. FNV-1a's 64-bit prime.
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Multiplier of the per-*label* finalisation. The golden-ratio constant, whose
/// high bits depend on every input bit, which is what turns the running fold
/// into a usable hash at each label boundary.
const GOLDEN: u64 = 0x9e37_79b9_7f4a_7c15;

/// Fold one label into a running suffix hash.
///
/// The per-octet step is FNV-1a; the per-label step is a multiply and an
/// xor-shift. The finalisation is what marks the **boundary** between labels:
/// without it `ab.c` and `a.bc` present the same octets in the same order to
/// the fold and collide by construction, and it is also what makes every
/// intermediate state a finished hash in its own right — which is the whole
/// trick that lets one reverse pass produce a hash for every suffix instead of
/// 127 separate finalisations.
///
/// `SipHash` is rejected here for that reason alone: 127 `finish()` calls is
/// microseconds, and the whole deep-name budget is 9.1 µs.
///
/// Case is not folded. Both sides of every comparison are `LowerName`, which
/// hickory documents as "guaranteed to be in lower case form" and constructs
/// through `Name::to_lowercase`; the name arithmetic that survives a mixed-case
/// input is the label comparison, not the hash.
#[inline]
fn mix_label(state: u64, label: &[u8]) -> u64 {
    let mut hash = state;
    for &octet in label {
        hash = (hash ^ u64::from(octet)).wrapping_mul(FNV_PRIME);
    }
    let hash = hash.wrapping_mul(GOLDEN);
    hash ^ (hash >> 31)
}

/// Hash of a whole name under `seed`, folded right to left.
///
/// The root hashes to the seed itself, which is what makes
/// [`SuffixHashes::at(0)`](SuffixHashes::at) meaningful and what lets a
/// root-origin zone use the same arithmetic as every other.
fn name_hash(seed: u64, name: &LowerName) -> u64 {
    let mut hash = seed;
    for label in name.iter().rev() {
        hash = mix_label(hash, label);
    }
    hash
}

/// The hash of **every suffix** of one query name, indexed by label count.
///
/// `h[d]` is the hash of the `d` rightmost labels, so `h[0]` is the root and
/// `h[label_count]` is the name itself. One reverse pass over the name fills
/// all of them, because [`mix_label`] finalises at every label boundary.
///
/// This is what removes the last allocation from the negative path. Probing a
/// depth used to mean `Name::trim_to` → `Name::from_labels`, which allocates two
/// intermediate `Vec`s and revalidates every label, for a name the probe throws
/// away — measured at one allocation per negative query in a wildcard zone and
/// five for a 123-label miss. VEGA-065 recorded that as its declared residual
/// cost; this is where it is paid off.
///
/// 1,032 bytes of stack, no heap, no `Vec`, nothing dropped. The array is sized
/// from [`MAX_LABELS`], which is not a tuning knob: a longer name cannot exist
/// on the wire and hickory rejects one before it reaches us, pinned by
/// `tests/canonical_order.rs::a_name_one_label_past_the_ceiling_is_rejected_before_it_reaches_the_zone`.
struct SuffixHashes {
    /// `h[d]` hashes the `d` rightmost labels. Filled up to `min(labels,
    /// MAX_LABELS)`; entries past that are never read, because [`Self::at`]
    /// refuses them.
    h: [u64; MAX_LABELS + 1],
    /// The name's **raw** label count, asterisks included — the index space
    /// `label_count` and `trim_to` share, and the one `num_labels` is banned
    /// for not being.
    labels: usize,
}

impl SuffixHashes {
    /// One reverse pass over `name`.
    ///
    /// The loop is bounded by `MAX_LABELS` and not by the name, because the
    /// name is chosen by whoever sent the packet. A name longer than the wire
    /// permits cannot reach here, and if one ever did the pass would stop at the
    /// ceiling and [`Self::at`] would refuse every depth past it — a miss, never
    /// an out-of-range write.
    fn new(seed: u64, name: &LowerName) -> Self {
        let mut h = [seed; MAX_LABELS + 1];
        let mut filled = 0usize;
        for label in name.iter().rev().take(MAX_LABELS) {
            let next = mix_label(h[filled], label);
            filled += 1;
            h[filled] = next;
        }
        Self {
            h,
            labels: label_count(name),
        }
    }

    /// The name's raw label count.
    fn labels(&self) -> usize {
        self.labels
    }

    /// The hash of the `depth` rightmost labels, or `None` when there is no
    /// such suffix.
    ///
    /// `None` past `labels` so that a caller cannot mistake the hash of a
    /// *shorter* name for the hash of the one it asked about; `None` past
    /// `MAX_LABELS` because those entries were never filled.
    fn at(&self, depth: usize) -> Option<u64> {
        if depth > self.labels || depth > MAX_LABELS {
            return None;
        }
        self.h.get(depth).copied()
    }
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

/// The `*` label, RFC 4592 §2.1.1. A wildcard is a node whose leftmost label is
/// this and nothing else; it is not an entry filed under its parent.
const WILDCARD_LABEL: &[u8] = b"*";

/// How much scratch to reserve per name for the build-time sort keys.
///
/// A key is one octet per label octet plus two per label, so a three-label name
/// like `www.example.com.` is 24. Reserving is what keeps the one shared buffer
/// to a handful of growths instead of a `realloc` per name; overshooting costs
/// scratch that is freed before the zone is served.
const TYPICAL_KEY_OCTETS: usize = 32;

/// A half-open `(start, end)` range into one of the three arenas.
///
/// `u32` rather than `usize` because two of them plus a `RecordType` and a TTL
/// is sixteen bytes per RRset, and the arena is the reason a 100,000-record zone
/// fits in tens of megabytes instead of 128 MiB.
type Span = (u32, u32);

/// A [`Span`] as a slice range.
///
/// Never used to index with `[]`. Every caller feeds the result to
/// `slice::get`, so a range the build got wrong is an empty answer rather than
/// an abort — with `panic = "abort"` in release, one out-of-range index on the
/// packet path is a full outage, and "the build made this range so it must be
/// valid" is exactly the assumption the next refactor falsifies.
fn span(range: Span) -> Range<usize> {
    // A widening conversion on every platform this targets. `unwrap_or` rather
    // than `unwrap` because nothing on a packet-reachable path may panic; the
    // saturated values produce an empty range, hence an empty slice.
    let start = usize::try_from(range.0).unwrap_or(usize::MAX);
    let end = usize::try_from(range.1).unwrap_or(0);
    start..end
}

/// What a node is, beyond its records.
///
/// Flags rather than a `NodeKind` enum, because the states are not mutually
/// exclusive — the apex owns an NS RRset and is not a cut, a glue node sits
/// below a cut and is also an ordinary node with an A RRset, and a node can be
/// named `*.something` and hold no records at all. An enum either loses one of
/// those combinations or grows into a bitfield with extra steps
/// (VEGA-032 §3.2).
///
/// Bits 1 and 4 are reserved for `DELEGATION` and `GLUE`, which arrive with S4.
/// They are not declared here: a flag nothing reads is a flag nobody maintains.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct NodeFlags(u8);

impl NodeFlags {
    /// No flags: an ordinary node.
    const NONE: Self = Self(0);

    /// The leftmost label is `*` (RFC 4592 §2.1.1), so this node is a source of
    /// synthesis.
    ///
    /// **Through S2 this also means "not an ordinary node".** The model it
    /// replaces kept wildcards in a separate map, so a query for the literal
    /// name `*.dev.example.com.` never matched an exact key and fell through to
    /// the wildcard walk. [`Zone::exact_node`] therefore skips these, which
    /// reproduces that exactly — including the case that makes the difference
    /// observable, a wildcard holding a CNAME, where treating the node as
    /// ordinary would substitute the CNAME for a query the old model answered
    /// NODATA. S3 is where that changes, deliberately and with a ruling.
    ///
    /// Set from the **name**, never from which loop built the node: `x.*.dev`
    /// materialises `*.dev` as an empty non-terminal, and RFC 4592 §2.1.1 makes
    /// that a wildcard however it came to exist. A node flagged otherwise is one
    /// the exact probe matches and the wildcard probe cannot reach.
    const WILDCARD: Self = Self(1 << 2);

    /// A CNAME RRset is present, so the RFC 1034 §3.6.2 substitution has
    /// something to find. Lets every other node skip a second type search.
    const HAS_CNAME: Self = Self(1 << 3);

    /// True when every bit of `other` is set here.
    const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Set every bit of `other`.
    fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

/// One RRset, or one TTL-homogeneous run of one.
///
/// RFC 2181 §5 says every record in an RRset shares a TTL and that they are
/// atomic, so the TTL belongs here and not once per record — that移 alone is four
/// bytes times every record in the zone.
///
/// **A run, not strictly an RRset, until S5.** Two `[[zone.records]]` blocks for
/// one owner and type with different TTLs are merged today into a single set
/// with mixed TTLs, which is the RFC 2181 §5 violation VEGA-061 pins and S5
/// fixes. Until then the arena keeps them as consecutive runs of one type, in
/// config order, so the answer is byte-identical to what the map model produced.
/// `tests/properties.rs::an_rrset_never_mixes_ttls` stays red on purpose.
#[derive(Debug)]
struct Rrset {
    /// RFC 1035 §3.2.2. Never `ANY`: §3.2.3 makes 255 a QTYPE, so it can never
    /// be the type of a record and never a key here.
    rtype: RecordType,
    ttl: u32,
    /// Half-open range into [`Zone::rdata`]. Config order is preserved, so
    /// answers are deterministic across builds and reloads.
    rdata: Span,
}

/// One name in the zone.
///
/// 96 bytes: an 80-byte `Name`, an 8-byte range, one byte of flags, padded.
/// Measured, not computed — the ruling's §7.1 works from
/// `size_of::<Name>() = 96` and `size_of::<RData>() = 168`, and hickory-proto
/// 0.26.1 on this machine reports **80** and **184**. The two errors cancel and
/// the ~303 B/record total stands; `tests/zone_memory.rs` prints all three on
/// every run so a dependency bump that moves them is visible.
#[derive(Debug)]
struct Node {
    /// The owner name, in the case the config wrote it, because that is the case
    /// the map model echoed into every answer.
    ///
    /// The zone's only copy of it. Storing it once per **record** instead is
    /// where most of the 1,342 bytes per record went.
    name: Name,
    /// Half-open range into [`Zone::rrsets`], ascending by numeric RRTYPE — so a
    /// type lookup is a binary search, and so RFC 4034 §4.1.2's NSEC type bitmap
    /// will want no second sort.
    ///
    /// **Empty** for an empty non-terminal, which is all an empty non-terminal
    /// is: RFC 4592 §2.2.2 defines it as a name with no RRsets that has
    /// descendants, and RFC 4035 §2.3 wants exactly that — an NSEC carrying only
    /// the NSEC and RRSIG bits — rather than a variant to special-case.
    rrsets: Span,
    flags: NodeFlags,
}

/// An immutable authoritative zone.
#[derive(Debug)]
pub struct Zone {
    /// The origin, lowercased. There is no second, case-preserving copy: node 0
    /// **is** the apex, carrying the origin exactly as the config wrote it, so a
    /// separate field would be a second source of truth for one name.
    lower_origin: LowerName,
    default_ttl: u32,
    soa: Option<Record>,

    /// Nodes in RFC 4034 §6.1 canonical order. Node 0 is the apex, and every
    /// ancestor precedes its descendants, because canonical order sorts on the
    /// rightmost label first.
    ///
    /// **Closed under ancestry since S2.** A node exists here for each name the
    /// config declares, plus the apex, plus every strict ancestor of both:
    /// `a.b.ent` alone puts `b.ent` and `ent` here as nodes with no RRsets. That
    /// closure is the property every later step rests on — it is what makes "a
    /// node exists at this depth" monotone, and so what lets S3's
    /// closest-encloser search be a binary search at all.
    nodes: Box<[Node]>,
    rrsets: Box<[Rrset]>,
    rdata: Box<[RData]>,

    /// Owner name to node index, keyed on [`name_hash`] and compared label-wise,
    /// so a probe never materialises a key.
    ///
    /// Seeded per zone from `RandomState`, which the OS seeds once per process.
    /// Mandatory, not decorative: the operator picks the keys in this table and
    /// an attacker picks every probe, so with a fixed multiplier a family of
    /// QNAMEs can be precomputed to land in one group and turn each probe into a
    /// scan of it.
    index: HashTable<u32>,
    hash_seed: u64,

    /// Bit `d` is set when the zone holds at least one wildcard whose parent
    /// name has exactly `d` labels.
    ///
    /// The parent walk probes only these depths, so answering a wildcard query
    /// costs what the *operator* configured — one probe, for every zone anyone
    /// actually writes — instead of what the *client* chose. Walking up one
    /// `base_name()` at a time was O(labels²), because `base_name` rebuilds and
    /// revalidates the whole remaining name: 174.7 µs of CPU for one 229-byte
    /// packet, against a 9.1 µs budget (VEGA-065).
    ///
    /// **Kept at S1, and subsumed at S3, not undone.** Once S2 closes the node
    /// set under ancestry the set of populated depths is contiguous, so this
    /// `u128` carries no information a `u8` pair does not and the bitmap becomes
    /// `((1 << (max_depth + 1)) - 1) & !((1 << origin_depth) - 1)`. That is
    /// VEGA-065's invariant made structural. Until then it is what keeps the
    /// walk bounded, and it is recomputed here over wildcard *nodes*.
    wildcard_depths: u128,

    /// Total number of records, for the `dns_zone_records` metric.
    record_count: usize,
}

impl Zone {
    /// Build a zone from validated configuration.
    ///
    /// Record values are parsed in presentation format, the same syntax a zone
    /// file uses, so `MX` values look like `"10 mail.example.com."`.
    ///
    /// O(R + N log N): the log factor buys canonical order, which is the
    /// prerequisite for DNSSEC's NSEC chain (RFC 4035 §2.3) and AXFR's
    /// deterministic iteration (RFC 5936 §2.2). The sort runs on a precomputed
    /// byte key rather than on `LowerName: Ord`, because each `Ord` comparison
    /// is O(labels × octets) through two iterators and reload wall time is
    /// already seconds on a million-record zone.
    pub fn from_config(cfg: &ZoneConfig) -> Result<Self> {
        let origin = parse_name(&cfg.origin)
            .with_context(|| format!("invalid zone origin {:?}", cfg.origin))?;
        let lower_origin = LowerName::from(origin.clone());

        // Built before the records, so a malformed `[zone.soa]` is reported
        // ahead of a malformed record set — the order the previous model failed
        // in, and an operator reading a reload failure reads the first line.
        let soa = match &cfg.soa {
            Some(spec) => Some(build_soa(&origin, spec)?),
            None => None,
        };

        let mut builder = ZoneBuilder::new(&origin, &lower_origin, cfg.default_ttl);
        for spec in &cfg.records {
            builder.insert_spec(spec)?;
        }

        let mut zone = builder.finish(soa)?;

        // An SOA declared as a plain record set wins over none at all, so pick it
        // up if the operator wrote `[[zone.records]] type = "SOA"` instead.
        if zone.soa.is_none() {
            zone.soa = zone.apex_soa();
        }

        zone.debug_assert_invariants();
        Ok(zone)
    }

    /// The SOA sitting at the apex as an ordinary record set, if there is one.
    ///
    /// The first record of the set, matching what the map model's
    /// `rs.first().cloned()` returned.
    fn apex_soa(&self) -> Option<Record> {
        let hashes = SuffixHashes::new(self.hash_seed, &self.lower_origin);
        let idx = self.exact_node(&self.lower_origin, &hashes)?;
        let node = self.nodes.get(idx.get())?;
        let first = self.rrsets_of(node, RecordType::SOA).first()?;
        let value = self.rdata.get(span(first.rdata))?.first()?;
        Some(Record::from_rdata(
            node.name.clone(),
            first.ttl,
            value.clone(),
        ))
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

    // ----------------------------------------------------------- the probe

    /// The node whose hash is `hash` and which satisfies `matches`.
    ///
    /// One table lookup and, only on a hash hit, one label-wise comparison.
    /// Nothing is built, nothing is cloned, nothing is dropped — which is the
    /// whole point: this replaces a `(LowerName, RecordType)` tuple key that had
    /// to be materialised, hashed and thrown away on every probe.
    fn probe(&self, hash: u64, matches: impl Fn(&Node) -> bool) -> Option<NodeIdx> {
        let found = self.index.find(hash, |&i| {
            usize::try_from(i)
                .ok()
                .and_then(|i| self.nodes.get(i))
                .is_some_and(&matches)
        })?;
        Some(NodeIdx(*found))
    }

    /// The ordinary (non-wildcard) node at `name`, if the zone holds one.
    ///
    /// This is the arena's answer to both `exact.get(...)` and
    /// `names.contains(...)` in the model it replaces: those two structures
    /// agreed by construction, because every insertion wrote to both. Wildcards
    /// were in neither, which is what [`NodeFlags::WILDCARD`] reproduces.
    fn exact_node(&self, name: &LowerName, hashes: &SuffixHashes) -> Option<NodeIdx> {
        let depth = hashes.labels();
        let hash = hashes.at(depth)?;
        self.probe(hash, |node| {
            !node.flags.contains(NodeFlags::WILDCARD)
                && node_name_matches(&node.name, name, depth, false)
        })
    }

    /// The source of synthesis `*.<the `depth` rightmost labels of `name`>`,
    /// if the zone holds one (RFC 4592 §3.3.1).
    ///
    /// One probe, at one hash: `h[depth]` already hashes the parent, and folding
    /// the `*` label into it costs a multiply. No name is materialised, which is
    /// the allocation VEGA-065 declared as its residual cost.
    fn wildcard_node(
        &self,
        name: &LowerName,
        depth: usize,
        hashes: &SuffixHashes,
    ) -> Option<NodeIdx> {
        let hash = mix_label(hashes.at(depth)?, WILDCARD_LABEL);
        self.probe(hash, |node| {
            node.flags.contains(NodeFlags::WILDCARD)
                && node_name_matches(&node.name, name, depth, true)
        })
    }

    /// The RRsets of `rtype` at `node`, as a contiguous slice.
    ///
    /// A slice rather than a single RRset because two config blocks for one
    /// owner and type with different TTLs are still merged into one answer until
    /// S5 (see [`Rrset`]). Two `partition_point`s rather than one
    /// `binary_search`, so the run is found whole and in order however long it
    /// is. Both are O(log T) and bounded by the node's own RRset count.
    fn rrsets_of(&self, node: &Node, rtype: RecordType) -> &[Rrset] {
        let Some(all) = self.rrsets.get(span(node.rrsets)) else {
            return &[];
        };
        let want = u16::from(rtype);
        let lo = all.partition_point(|r| u16::from(r.rtype) < want);
        let hi = all.partition_point(|r| u16::from(r.rtype) <= want);
        all.get(lo..hi).unwrap_or(&[])
    }

    /// Copy every record of `run` into `out`, owned by `owner`.
    ///
    /// `reserve_exact` from a length the arena already knows. The model this
    /// replaces collected with no size hint at all, so a one-record answer came
    /// back in a `Vec` of capacity four — 816 wasted bytes on every query on the
    /// hot path (VEGA-066).
    fn emit(&self, run: &[Rrset], owner: &Name, out: &mut Vec<Record>) {
        out.reserve_exact(run.iter().map(|r| span(r.rdata).len()).sum());
        for rrset in run {
            let Some(values) = self.rdata.get(span(rrset.rdata)) else {
                continue;
            };
            for value in values {
                out.push(Record::from_rdata(owner.clone(), rrset.ttl, value.clone()));
            }
        }
    }

    // ---------------------------------------------------------- the lookup

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
    /// O(1) on a zone with no wildcards — one probe, then an empty probe mask
    /// and no probes at all.
    pub fn exists(&self, name: &LowerName) -> bool {
        let hashes = SuffixHashes::new(self.hash_seed, name);
        self.exists_hashed(name, &hashes)
    }

    /// [`Zone::exists`] against a suffix hash the caller has already paid for.
    fn exists_hashed(&self, name: &LowerName, hashes: &SuffixHashes) -> bool {
        // RFC 1035 §3.2.3: ANY is a QTYPE and never an RRTYPE, so it can never
        // be the type of an RRset. The typed half of the probe therefore always
        // misses and only the coverage bit comes back — which is the half wanted
        // here.
        self.exact_node(name, hashes).is_some()
            || self.wildcard_probe(name, hashes, RecordType::ANY).1
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

        // One reverse pass over the query name, before any probe. Every depth
        // this lookup will ask about is answered out of the stack from here on.
        // Recomputed per CNAME hop because the name changes, and that recursion
        // is bounded by MAX_CNAME_DEPTH.
        let hashes = SuffixHashes::new(self.hash_seed, name);

        // RFC 1035 §3.2.3: ANY (255) is a QTYPE, never an RRTYPE, so it can
        // never be the type of an RRset in the arena. RFC 8482 makes *what* to
        // answer for it a responder policy, and that policy lives in
        // `DnsHandler`; the zone layer reports existence and nothing else.
        //
        // This replaced a scan of the whole record map, which cost 1.83 ms on a
        // 100k-record zone — 18,239x an A lookup, and one routing change away
        // from the packet path — and which carried the same existence defect at
        // its NXDOMAIN arm (VEGA-083 §4.4). Reporting existence is the only
        // bounded answer, and it stays bounded now that a node arena exists:
        // "iterate the nodes" is a very natural thing to reach for and would put
        // the O(zone) scan straight back.
        //
        // A caller that reads `NoData` here as "the node is empty" is wrong.
        // AXFR (VEGA-034) needs ordered node iteration and will not get it from
        // this function, so do not reintroduce the scan to serve a transfer.
        if record_type.is_any() {
            return if self.exists_hashed(name, &hashes) {
                Resolution::NoData
            } else {
                Resolution::NxDomain
            };
        }

        if let Some(idx) = self.exact_node(name, &hashes) {
            if let Some(node) = self.nodes.get(idx.get()) {
                let run = self.rrsets_of(node, record_type);
                if !run.is_empty() {
                    self.emit(run, &node.name, out);
                    return Resolution::Found;
                }

                // RFC 1034 §3.6.2: a CNAME at the owner name answers queries for
                // any other type, and the target is chased if it lives in this
                // zone.
                if record_type != RecordType::CNAME && node.flags.contains(NodeFlags::HAS_CNAME) {
                    let cnames = self.rrsets_of(node, RecordType::CNAME);
                    if !cnames.is_empty() {
                        self.emit(cnames, &node.name, out);
                        if depth >= MAX_CNAME_DEPTH {
                            tracing::warn!(%name, "CNAME chain too long, truncating");
                            return Resolution::Found;
                        }
                        if let Some(RData::CNAME(target)) = self.first_value(cnames) {
                            let target = LowerName::from(target.0.clone());
                            if self.contains(&target) {
                                // A dangling in-zone target still yields the
                                // CNAME itself.
                                let _ = self.resolve(&target, record_type, depth + 1, out);
                            }
                        }
                        return Resolution::Found;
                    }
                }

                return Resolution::NoData;
            }
        }

        // Wildcards only apply when the queried name itself does not exist.
        let (run, covered) = self.wildcard_probe(name, &hashes, record_type);
        if !run.is_empty() {
            let qname = Name::from(name.clone());
            self.emit(run, &qname, out);
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

    /// The first RDATA of `run`, for reading a CNAME's target.
    fn first_value(&self, run: &[Rrset]) -> Option<&RData> {
        self.rdata.get(span(run.first()?.rdata))?.first()
    }

    /// Walk the wildcard depths for `name`, deepest set bit first.
    ///
    /// Returns the RRsets to synthesise from, when the zone holds one of
    /// `record_type` at a source of synthesis for `name`, **and** whether any
    /// source of synthesis for `name` exists at all.
    ///
    /// The two halves answer different questions and only the first depends on
    /// `record_type`: it decides the *answer section*, while coverage decides
    /// NOERROR against NXDOMAIN (RFC 1034 §4.3.2 step 3(c)). Both callers go
    /// through here so the two determinations cannot drift apart and start
    /// returning a QTYPE-dependent rcode again.
    ///
    /// Coverage is decided by finding the `*` node itself, never by the depth
    /// bitmap. The bitmap says a wildcard exists *somewhere* at depth `d`, not
    /// at *this* parent, and deriving coverage from it makes every name whose
    /// parent merely shares a depth with some wildcard exist — which in a zone
    /// with an apex wildcard is very nearly every name there is (VEGA-083,
    /// rejected alternative 5).
    ///
    /// Deepest set bit first, so the closest wildcard answers — the same order
    /// the old `base_name()` climb produced, and what
    /// `the_deepest_wildcard_wins_when_several_could_match` pins. Every depth
    /// skipped is a depth at which no node can exist, because equal names have
    /// equal label counts, so dropping it cannot lose a hit. (Deepest-wins is
    /// **not** RFC 4592 §3.3.1's closest-encloser rule. That is VEGA-009's, and
    /// it is S3's; S1 preserves today's answer byte for byte.)
    ///
    /// `mask` strictly loses a bit each pass, so termination is structural
    /// rather than a counter that has to be checked against a floor. That
    /// matters for `origin = "."`, where the floor is 0 and a decrementing walk
    /// needs an extra guard to avoid spinning on the root.
    fn wildcard_probe(
        &self,
        name: &LowerName,
        hashes: &SuffixHashes,
        record_type: RecordType,
    ) -> (&[Rrset], bool) {
        let mut mask = self.wildcard_depths & self.wildcard_window(name);
        let mut covered = false;
        while mask != 0 {
            // `mask != 0` bounds `leading_zeros()` at 127, so `depth <= 127`
            // and neither shift below can overflow.
            let depth = (u128::BITS - 1 - mask.leading_zeros()) as usize;
            mask &= !(1u128 << depth);

            if let Some(idx) = self.wildcard_node(name, depth, hashes) {
                covered = true;
                if let Some(node) = self.nodes.get(idx.get()) {
                    let run = self.rrsets_of(node, record_type);
                    if !run.is_empty() {
                        return (run, true);
                    }
                }
            }
        }
        // Deliberately no early exit on `covered`: which wildcard answers must
        // stay exactly what it is today (deepest type match). Stopping at the
        // deepest wildcard *parent* would be a half-step towards RFC 4592
        // §3.3.1 closest-encloser semantics, which is VEGA-009's, not this.
        (&[], covered)
    }

    /// The depths at which a wildcard parent of `name` could possibly sit.
    ///
    /// Bounded above by the depth of `name`'s immediate parent, because a
    /// wildcard's parent is a *proper* ancestor of the names it covers (RFC
    /// 4592 §3.3.1), and below by the origin's depth, because [`ZoneBuilder::qualify`]
    /// refuses to build a name outside the zone — anything shallower is a
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

    // ------------------------------------------------------- the invariants

    /// The structural facts the arena is built to hold, checked in debug builds.
    ///
    /// Every one is maintained by construction, which is exactly why they are
    /// asserted: each is here to fail a future writer at the moment they add a
    /// second write site, the discipline VEGA-065 established for
    /// `wildcard_depths` and VEGA-083 extended to wildcard coverage. Debug-only
    /// because this is O(N) on a path an operator pays for on every reload.
    fn debug_assert_invariants(&self) {
        debug_assert!(
            self.nodes
                .get(NodeIdx::APEX.get())
                .is_some_and(|n| LowerName::from(n.name.clone()) == self.lower_origin),
            "node 0 is not the apex; canonical order puts the shortest name in \
             the zone first and NodeIdx::APEX reads that as given"
        );
        debug_assert!(
            self.nodes
                .windows(2)
                .all(|pair| LowerName::from(pair[0].name.clone())
                    < LowerName::from(pair[1].name.clone())),
            "the arena is not in strictly increasing RFC 4034 §6.1 canonical \
             order. Nothing reads that order yet; the first reader is the NSEC \
             chain, and a chain that does not close SERVFAILs the whole zone"
        );
        debug_assert!(
            {
                // Invariant I-3, and the most dangerous coupling in the model:
                // S3's closest-encloser search reads "a node exists at this
                // depth" as a MONOTONE predicate, which it is only while the
                // node set is closed under ancestry. A hole returns a shallower
                // encloser than the truth, so a wildcard synthesises into a
                // subtree an operator carved out — VEGA-009 reopened, silently,
                // with answers that look correct. The set is a debug-only
                // allocation on the reload path, which is what buys the check
                // for every zone an operator ever loads rather than for the
                // zones a test happens to name.
                let names: std::collections::HashSet<LowerName> = self
                    .nodes
                    .iter()
                    .map(|node| LowerName::from(node.name.clone()))
                    .collect();
                names.iter().all(|name| {
                    *name == self.lower_origin
                        || names.contains(&LowerName::from(Name::from(name.clone()).base_name()))
                })
            },
            "a node's parent is not a node. The node set must be closed under \
             ancestry (RFC 4592 §2.2.2): a name that exists only as an ancestor \
             answers NXDOMAIN, and RFC 8020 §2 then denies every record beneath it"
        );
        debug_assert!(
            self.index.len() == self.nodes.len(),
            "the index and the arena hold different numbers of entries; some \
             configured record is unreachable and nothing says so"
        );
        debug_assert!(
            self.nodes.iter().all(|node| {
                let all = self.rrsets.get(span(node.rrsets));
                all.is_some_and(|rrsets| {
                    rrsets
                        .windows(2)
                        .all(|p| u16::from(p[0].rtype) <= u16::from(p[1].rtype))
                        && rrsets
                            .iter()
                            .all(|r| self.rdata.get(span(r.rdata)).is_some_and(|v| !v.is_empty()))
                })
            }),
            "an RRset range is out of bounds, out of type order, or empty; the \
             type search is a binary search and reads the order as given"
        );
        debug_assert!(
            self.nodes.iter().all(|node| {
                !node.flags.contains(NodeFlags::WILDCARD) || {
                    let depth = label_count(&LowerName::from(node.name.clone()));
                    depth >= 1
                        && depth - 1 <= MAX_LABELS
                        && self.wildcard_depths & (1u128 << (depth - 1)) != 0
                }
            }),
            "wildcard_depths is out of step with the wildcard nodes; a wildcard \
             is unreachable, or a name it covers answers NXDOMAIN"
        );
    }
}

/// True when `node_name` is exactly the `depth` rightmost labels of `qname`,
/// with a leading `*` label when `star`.
///
/// The comparison a hash hit is confirmed with. No name is materialised on
/// either side: both are walked label by label from the right, which is also the
/// order RFC 4034 §6.1 compares in.
///
/// Case-insensitive per RFC 4343 §2, even though `LowerName` guarantees its own
/// side is folded — the node's name is stored in the case the config wrote it,
/// because that is the case the model this replaces echoed into every answer.
///
/// Bounded by `depth`, which the caller has already clamped to the query name's
/// own label count.
fn node_name_matches(node_name: &Name, qname: &LowerName, depth: usize, star: bool) -> bool {
    if node_name.iter().len() != depth + usize::from(star) {
        return false;
    }
    let mut node_labels = node_name.iter().rev();
    let mut query_labels = qname.iter().rev();
    for _ in 0..depth {
        match (node_labels.next(), query_labels.next()) {
            (Some(left), Some(right)) if left.eq_ignore_ascii_case(right) => {}
            _ => return false,
        }
    }
    !star || node_labels.next() == Some(WILDCARD_LABEL)
}

// ---------------------------------------------------------------------------
// The build
// ---------------------------------------------------------------------------

/// One node under construction, before the arena is laid out.
struct ScratchNode {
    name: Name,
    wildcard: bool,
    /// RRsets in config order. Sorted by numeric RRTYPE on the way into the
    /// arena, with a **stable** sort, so that the order two blocks of one type
    /// were declared in survives.
    rrsets: Vec<ScratchRrset>,
}

/// One RRset, or one TTL-homogeneous run of one, under construction.
struct ScratchRrset {
    rtype: RecordType,
    ttl: u32,
    rdata: Vec<RData>,
}

/// Turns a validated config into the three arenas.
///
/// A scratch `HashMap` keyed by lowercased owner name, because the config
/// arrives in whatever order the operator wrote it and the arena has to come out
/// canonically sorted. Everything here is dropped once the arenas are built.
struct ZoneBuilder<'a> {
    origin: &'a Name,
    lower_origin: &'a LowerName,
    default_ttl: u32,
    nodes: HashMap<LowerName, ScratchNode>,
    record_count: usize,
    wildcard_depths: u128,
}

impl<'a> ZoneBuilder<'a> {
    fn new(origin: &'a Name, lower_origin: &'a LowerName, default_ttl: u32) -> Self {
        Self {
            origin,
            lower_origin,
            default_ttl,
            nodes: HashMap::new(),
            record_count: 0,
            wildcard_depths: 0,
        }
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

        // A wildcard's name is `*` prepended to whatever follows the asterisk:
        // `*.dev` under `example.com.` is the node `*.dev.example.com.`
        // (RFC 4592 §2.1.1). Only the leftmost asterisk is stripped, because
        // §2.1.3 deleted RFC 1035's "should not contain other `*` labels" and a
        // wildcard may have subdomains.
        let owner_label = if is_wildcard {
            label
                .strip_prefix('*')
                .unwrap_or("")
                .trim_start_matches('.')
        } else {
            label
        };
        let owner = self.qualify(owner_label)?;

        let mut rdata = Vec::with_capacity(spec.values.len());
        for value in &spec.values {
            // Through `rdata::parse_value` like `vega record add`, and for the
            // same reason: hickory's lexer asserts past 4095 characters, so on
            // this path — startup *and* every reload — an oversized value in an
            // edited config is a crash loop, not a rejected reload. One gate,
            // one bound, one message, whichever end the value came in through
            // (VEGA-071).
            let parsed = rdata::parse_value(record_type, &spec.name, value).map_err(|error| {
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
            rdata.push(parsed);
        }

        self.record_count += rdata.len();

        let node_name = if is_wildcard {
            // Recorded from the *parent's* depth, which is the index space the
            // walk probes in, and recorded before the node is built so that the
            // one case below where no node can exist still registers. A missing
            // bit is a configured wildcard answering NXDOMAIN with nothing in
            // the log.
            let depth = label_count(&LowerName::from(owner.clone()));
            // Unreachable — `qualify` builds this name through hickory, which
            // enforces the 255-octet limit MAX_LABELS is derived from. A branch
            // rather than an assumption, because `1u128 << 128` panics and this
            // runs on the reload path.
            if depth <= MAX_LABELS {
                self.wildcard_depths |= 1u128 << depth;
            }
            // A wildcard can fail to have a representable owner name of its
            // own: RFC 1035 §2.3.4 caps a name at 255 octets, and a parent
            // within two of that ceiling leaves no room for the `*`. By the
            // same arithmetic such a wildcard covers no representable name
            // either — every name it could match carries at least one more
            // label, which costs at least two more octets — so there is nothing
            // for a node here to answer, and the model this replaces could not
            // answer from it either: its probe window stops at the query's
            // parent depth, which can never reach this parent's own. The depth
            // bit above is still recorded and the records are still counted,
            // because both are observable and neither needs the node.
            let Ok(name) = owner.prepend_label("*") else {
                tracing::warn!(
                    record = %spec.name,
                    "wildcard owner name exceeds the 255-octet limit of RFC 1035 §2.3.4; \
                     it can match no name the wire can carry and is not served"
                );
                return Ok(());
            };
            name
        } else {
            owner
        };

        let key = LowerName::from(node_name.clone());
        let node = self.nodes.entry(key).or_insert_with(|| ScratchNode {
            name: node_name,
            wildcard: is_wildcard,
            rrsets: Vec::new(),
        });
        debug_assert_eq!(
            node.wildcard, is_wildcard,
            "one owner name reached the arena as both a wildcard and an ordinary \
             node; the two are answered from different branches and only one of \
             them would win"
        );

        // Append to the most recent run of this type when the TTLs agree, and
        // start a new run when they do not. The map model merged every block for
        // one owner and type into a single `Vec` in config order, TTLs and all
        // (RFC 2181 §5 says it should not — that is VEGA-061 and S5's), so runs
        // are what reproduce the answer exactly without storing a TTL per record.
        let mut appended = false;
        if let Some(i) = node.rrsets.iter().rposition(|r| r.rtype == record_type) {
            if let Some(run) = node.rrsets.get_mut(i) {
                if run.ttl == ttl {
                    run.rdata.append(&mut rdata);
                    appended = true;
                }
            }
        }
        if !appended {
            node.rrsets.push(ScratchRrset {
                rtype: record_type,
                ttl,
                rdata,
            });
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
        Name::parse(label, Some(self.origin))
            .with_context(|| format!("invalid record name {label:?}"))
    }

    /// Close the node set under ancestry: every strict ancestor of every node,
    /// down to the origin, becomes a node with no RRsets (RFC 4592 §2.2.2).
    ///
    /// This is the whole of VEGA-032 S2, and it closes VEGA-006. A name that
    /// exists only because something exists beneath it — `_tcp.example.com.`
    /// under `_sip._tcp.example.com. SRV` — used to fall through to NXDOMAIN,
    /// and RFC 8020 §2 lets a resolver cache that denial and apply it to the
    /// **whole subtree**, including the SRV record that does exist. SRV, TLSA,
    /// ACME and DKIM all create such names, so any zone using them was one
    /// cache fill away from losing records.
    ///
    /// An empty non-terminal is not a variant in this model. It is "a node with
    /// no RRsets", which is what §2.2.2 says it is, and what RFC 4035 §2.3 will
    /// need to emit an NSEC carrying only the NSEC and RRSIG bits.
    ///
    /// # Closure over the node set, not over the config
    ///
    /// The walk starts from the nodes the build actually holds, so a wildcard
    /// whose owner name exceeds RFC 1035 §2.3.4's 255 octets — which
    /// [`Self::insert_spec`] warns about and does not materialise — implies no
    /// ancestors either. A name that existed because of a record the zone
    /// refused to hold would be worse than the NXDOMAIN.
    ///
    /// # Three properties this must hold, each with a test that fails without it
    ///
    /// * It never overwrites an existing node. An ancestor is very often also a
    ///   declared owner, and materialisation is a second write site for a node
    ///   the config already wrote; clobbering deletes a configured record inside
    ///   the build, where nothing else in this tree would notice.
    /// * `record_count` does not move. Empty non-terminals are nodes, not
    ///   records, and that gauge is an operator's only view of whether a reload
    ///   truncated the zone (AC-2.4).
    /// * The wildcard flag comes from the **name**. `x.*.dev` materialises
    ///   `*.dev`, and RFC 4592 §2.1.1 makes a leftmost `*` a wildcard however
    ///   the name came to exist. Deriving the flag from which loop created the
    ///   node instead would leave a node that the exact-name probe matches and
    ///   the wildcard probe does not — a source of synthesis nobody can reach.
    ///
    /// O(number of nodes created), not O(nodes × depth): the walk stops at the
    /// first ancestor that already exists, and by induction everything above
    /// that one is the responsibility of whoever inserted it. A flat zone —
    /// 100,000 names one label below the apex — therefore does no work at all
    /// and does not grow by a byte, which is what `tests/zone_memory.rs` holds
    /// this to.
    fn materialise_ancestors(&mut self) {
        let origin_depth = label_count(self.lower_origin);

        // Snapshotted, because the walk inserts into the same map. Only names
        // with a strict ancestor *below* the origin can imply a new node: the
        // ancestor of a name one label down is the origin, which is already
        // there. That filter is what keeps a flat zone free of this allocation
        // entirely rather than paying for a clone of every owner name.
        let pending: Vec<Name> = self
            .nodes
            .values()
            .filter(|node| node.name.iter().len() > origin_depth + 1)
            .map(|node| node.name.clone())
            .collect();

        for name in pending {
            let mut current = name;
            // Terminates twice over: every pass either breaks or strictly
            // reduces the label count, and the count starts at most at
            // MAX_LABELS because hickory refused to build a longer name.
            while current.iter().len() > origin_depth + 1 {
                let key = LowerName::from(current.base_name());
                if self.nodes.contains_key(&key) {
                    // Either declared — in which case it is in `pending` on its
                    // own account — or already materialised by an earlier walk
                    // that carried on upwards from here. Both leave the chain
                    // above this point closed.
                    break;
                }

                // Lowercased, not spelled as the descendant that implied it
                // spells it. Nobody wrote this name, two descendants may
                // disagree about its case, and the scratch map's iteration
                // order would otherwise decide which spelling wins — a build
                // that is not reproducible. RFC 4343 §2 makes case
                // non-semantic and RFC 4034 §6.2's canonical form is lowercase,
                // so this is also the form the NSEC chain will want.
                let parent = Name::from(key.clone());
                let wildcard = parent.iter().next() == Some(WILDCARD_LABEL);
                if wildcard {
                    // The bitmap is indexed by the wildcard's *parent* depth,
                    // the index space the walk probes in. A node exists, so its
                    // name is representable and the depth is within
                    // `MAX_LABELS`; the branch is here because `1u128 << 128`
                    // panics and this runs on the reload path.
                    let depth = label_count(&key).saturating_sub(1);
                    if depth <= MAX_LABELS {
                        self.wildcard_depths |= 1u128 << depth;
                    }
                }

                self.nodes.insert(
                    key,
                    ScratchNode {
                        name: parent.clone(),
                        wildcard,
                        // The definition of an empty non-terminal, and the
                        // reason `record_count` does not move.
                        rrsets: Vec::new(),
                    },
                );
                current = parent;
            }
        }
    }

    /// Lay the scratch map out as three exactly-sized arenas plus an index.
    fn finish(mut self, soa: Option<Record>) -> Result<Zone> {
        let origin = self.origin.clone();
        let lower_origin = self.lower_origin.clone();
        let default_ttl = self.default_ttl;

        // The apex always exists, even in an empty zone, otherwise a bare
        // `SOA <origin>` query would answer NXDOMAIN for our own zone. It is
        // inserted before the ancestor closure below, which reads it as the
        // floor every walk stops at.
        self.nodes
            .entry(lower_origin.clone())
            .or_insert_with(|| ScratchNode {
                name: origin.clone(),
                wildcard: false,
                rrsets: Vec::new(),
            });

        self.materialise_ancestors();

        let entries: Vec<(LowerName, ScratchNode)> = self.nodes.into_iter().collect();

        let rrset_total: usize = entries.iter().map(|(_, n)| n.rrsets.len()).sum();
        let rdata_total: usize = entries
            .iter()
            .flat_map(|(_, n)| n.rrsets.iter())
            .map(|r| r.rdata.len())
            .sum();

        // Sorted by a precomputed byte key, not by `LowerName: Ord`. Each `Ord`
        // comparison is O(labels × octets) through two iterators, which at
        // 100,000 names is hundreds of milliseconds on every reload; the key is
        // a `memcmp`. Correctness still rests on `Ord`, which is what
        // `debug_assert_invariants` and `tests/canonical_order.rs` hold it to.
        //
        // Every key goes into **one** scratch buffer and what gets sorted is a
        // permutation of indices, so the sort costs three allocations rather
        // than one per name. `sort_by_cached_key` would be 100,000 allocations
        // and 100,000 frees on the reload path, and VEGA-069 measured RSS
        // ratcheting 1,736 -> 2,676 -> 3,095 MiB across three reloads on exactly
        // that kind of churn. The buffer is dropped with the permutation.
        let mut keys: Vec<u8> = Vec::with_capacity(entries.len() * TYPICAL_KEY_OCTETS);
        let mut key_spans: Vec<Span> = Vec::with_capacity(entries.len());
        for (lower, _) in &entries {
            let start = arena_offset(keys.len())?;
            write_canonical_sort_key(lower, &mut keys);
            key_spans.push((start, arena_offset(keys.len())?));
        }
        let key_of = |i: usize| -> &[u8] {
            key_spans
                .get(i)
                .and_then(|&s| keys.get(span(s)))
                .unwrap_or_default()
        };
        let mut order: Vec<usize> = (0..entries.len()).collect();
        // Unstable is safe: no two nodes share a key. Equal keys mean equal
        // names under RFC 4034 §6.1, and the scratch map is keyed by exactly
        // that equivalence, so a duplicate cannot have survived to here.
        order.sort_unstable_by(|&a, &b| key_of(a).cmp(key_of(b)));

        let mut slots: Vec<Option<(LowerName, ScratchNode)>> =
            entries.into_iter().map(Some).collect();

        let mut nodes = Vec::with_capacity(slots.len());
        let mut rrsets = Vec::with_capacity(rrset_total);
        let mut rdata = Vec::with_capacity(rdata_total);
        let mut hashes = Vec::with_capacity(slots.len());

        let hash_seed = RandomState::new().hash_one(0u64);

        for position in order {
            let Some((lower, mut scratch)) = slots.get_mut(position).and_then(Option::take) else {
                continue;
            };
            // Stable, so two runs of one type stay in the order the config
            // declared them.
            scratch.rrsets.sort_by_key(|r| u16::from(r.rtype));

            let rrsets_start = arena_offset(rrsets.len())?;
            let mut flags = NodeFlags::NONE;
            if scratch.wildcard {
                flags.insert(NodeFlags::WILDCARD);
            }
            for run in scratch.rrsets {
                if run.rtype == RecordType::CNAME {
                    flags.insert(NodeFlags::HAS_CNAME);
                }
                let rdata_start = arena_offset(rdata.len())?;
                rdata.extend(run.rdata);
                let rdata_end = arena_offset(rdata.len())?;
                rrsets.push(Rrset {
                    rtype: run.rtype,
                    ttl: run.ttl,
                    rdata: (rdata_start, rdata_end),
                });
            }
            let rrsets_end = arena_offset(rrsets.len())?;

            hashes.push(name_hash(hash_seed, &lower));
            nodes.push(Node {
                name: scratch.name,
                rrsets: (rrsets_start, rrsets_end),
                flags,
            });
        }

        // Sized exactly, so no insertion resizes and the hasher below is never
        // called — it is required by the signature, not by the work.
        let mut index = HashTable::with_capacity(nodes.len());
        for (i, &hash) in hashes.iter().enumerate() {
            index.insert_unique(hash, arena_offset(i)?, |&other| {
                usize::try_from(other)
                    .ok()
                    .and_then(|o| hashes.get(o))
                    .copied()
                    .unwrap_or(hash)
            });
        }

        Ok(Zone {
            lower_origin,
            default_ttl,
            soa,
            nodes: nodes.into_boxed_slice(),
            rrsets: rrsets.into_boxed_slice(),
            rdata: rdata.into_boxed_slice(),
            index,
            hash_seed,
            wildcard_depths: self.wildcard_depths,
            record_count: self.record_count,
        })
    }
}

/// An arena offset as a `u32`, or a named build error.
///
/// A `u32` caps each arena at `u32::MAX` entries. A zone that large fails to
/// build rather than wrapping an index, because a wrapped index answers the
/// wrong records and says nothing about it.
fn arena_offset(len: usize) -> Result<u32> {
    u32::try_from(len).with_context(|| {
        format!(
            "zone is too large for this data model: an arena reached {len} \
             entries and indices are 32-bit. Split the zone"
        )
    })
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
    /// features/wildcards.feature:132
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

    /// Scenario: A wildcard's parent holds no record of its own
    /// features/empty-non-terminals.feature:122
    ///
    /// REWRITTEN AT VEGA-032 S2, not deleted (ruling §13 AC-2.3). It asserted
    /// `NxDomain` for `dev.example.com.`, which is the exact opposite of
    /// `the_parent_of_a_wildcard_is_not_nxdomain` and of RFC 4592 §2.2.2 — the
    /// wildcard is a node named `*.dev.example.com.`, so its parent exists for
    /// the same reason any other ancestor does.
    ///
    /// It is rewritten rather than deleted because it is a MUTATION KILL: it
    /// exists to catch `if is_wildcard` -> `if !is_wildcard` in `insert_spec`,
    /// which files a wildcard's records at its parent name. That kill is kept by
    /// asserting the two halves of the contract that are actually true — the
    /// parent exists and holds NO records, and the wildcard still synthesises
    /// below it. The inverted mutant answers `203.0.113.50` at the parent and
    /// fails the first half; a mutant that drops wildcards entirely fails the
    /// second.
    #[test]
    fn a_wildcard_never_creates_a_record_at_its_own_parent() {
        let _watchdog = watchdog();
        let z = zone(vec![spec("*.dev", "A", &["203.0.113.50"])]);
        assert_eq!(
            z.lookup(&lower("dev.example.com."), RecordType::A),
            Answer::NoData,
            "`dev.example.com.` exists as the parent of the wildcard node \
             `*.dev.example.com.` (RFC 4592 §2.2.2), so it is NODATA — but it \
             must hold no record of its own. Records here mean `*.dev` was \
             filed under its parent name instead of at its own"
        );
        let Answer::Records(records) = z.lookup(&lower("x.dev.example.com."), RecordType::A) else {
            panic!(
                "the wildcard must still synthesise below its parent; a parent \
                 that exists is not a parent that swallowed the wildcard"
            );
        };
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].data, a("203.0.113.50"));
        assert_eq!(
            records[0].name,
            parse_name("x.dev.example.com.").unwrap(),
            "a synthesised record is owned by the queried name (RFC 4592 §3.3.1)"
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
    /// features/wildcards.feature:428
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
    /// features/zone-data-model.feature:469
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

    /// Scenario: The closest encloser search costs at most eight probes at the
    /// deepest name the wire can carry
    /// features/closest-encloser.feature:289
    ///
    /// REWRITTEN AT VEGA-032 S3, and strengthened rather than weakened. It
    /// asserted `wildcard_depths & (1 << 127) != 0` — the top bit of VEGA-065's
    /// bitmap, which nothing else reached. That field is deleted at S3, so an
    /// assertion about it would have to go one way or the other, and the two
    /// options are not equal: deleting the test loses the mutation kills
    /// (`MAX_LABELS: 127 -> 126`, `127 -> 128` and `depth <= MAX_LABELS` -> `<`
    /// ALL survived the whole suite before it existed), while restating it as an
    /// ANSWER keeps every one of them and stops depending on a private field.
    ///
    /// So it now asserts what the bit was a proxy for: **the deepest wildcard a
    /// zone can hold still synthesises.** That is a strictly stronger claim — a
    /// bit can be set on a wildcard the search never reaches.
    ///
    /// The arithmetic of "deepest", which is why the parent sits at 126 and not
    /// at 127. RFC 1035 §2.3.4 caps a name at 255 octets and §3.1 spends two
    /// octets on a single-character label plus one terminator, so a name carries
    /// at most 127 of them. A wildcard at parent depth `d` is a node of `d + 1`
    /// labels, and the shallowest name it covers also has `d + 1` — one label
    /// below the parent, RFC 4592 §3.3.1 — so both hit the ceiling together at
    /// `d = 126`. At `d = 127` the wildcard has no representable owner name at
    /// all, which is a different case and is pinned separately by
    /// `a_wildcard_whose_owner_name_exceeds_the_octet_limit_materialises_no_ancestors`.
    ///
    /// Getting this wrong is easy and quiet — the first version of this test
    /// used `d = 125` and asserted a 127-label covered name, which is 126. The
    /// length assertion below is there because a fixture that misses the ceiling
    /// by one measures the ordinary case and reports it as the boundary.
    #[test]
    fn the_deepest_wildcard_a_zone_can_hold_still_synthesises() {
        // Hard-coded rather than written as `MAX_LABELS`, because a test that
        // builds its fixture from the constant it is checking moves with the
        // mutation and pins nothing.
        const CEILING: usize = 127;
        const DEEPEST_USEFUL_PARENT: usize = CEILING - 1;

        let _watchdog = watchdog();
        assert_eq!(
            MAX_LABELS, CEILING,
            "MAX_LABELS is the arithmetic consequence of RFC 1035 §2.3.4 and \
             §3.1. It sizes the suffix hash array the closest-encloser search \
             indexes on every negative query, and moving it is not a tuning \
             decision"
        );

        let parent = std::iter::repeat_n("a", DEEPEST_USEFUL_PARENT)
            .collect::<Vec<_>>()
            .join(".");
        let z = zone_with_origin(
            ".",
            vec![spec(&format!("*.{parent}"), "A", &["203.0.113.1"])],
        );

        // 127 labels exactly: the shallowest name this wildcard can cover, and
        // the deepest name the wire can carry.
        let covered = lower(&format!("q.{parent}."));
        assert_eq!(
            Name::from(covered.clone()).iter().len(),
            CEILING,
            "the covered name must sit exactly at the decoder's ceiling"
        );

        let Answer::Records(records) = z.lookup(&covered, RecordType::A) else {
            panic!(
                "a wildcard whose parent sits at {DEEPEST_USEFUL_PARENT} labels \
                 is the deepest one a zone can usefully hold, and the name it \
                 covers is the deepest the wire can carry. Failing here means \
                 the wildcard is configured, counted and permanently \
                 unreachable, with nothing in the logs to say so"
            );
        };
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].data, a("203.0.113.1"));
        assert_eq!(
            LowerName::from(records[0].name.clone()),
            covered,
            "RFC 4592 §3.3.1: the synthesised record is owned by the query name"
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
    /// features/wildcards.feature:484
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
    /// features/zone-data-model.feature:223
    ///
    /// Scenario: A query name at exactly 255 octets is answered
    /// features/zone-data-model.feature:479
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
    /// features/zone-data-model.feature:428
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

    // -------------------------------------------------- S1: the arena
    //
    // AC-1.4 and AC-1.5. Nothing consumes the arena's ordering at S1, which is
    // precisely why it is asserted at S1: the first consumer is the NSEC chain,
    // and a chain that does not close SERVFAILs the entire zone at every
    // validating resolver — a failure that is invisible until it is total.
    // §10.1 keeps `Node`, `NodeIdx` and the arenas `pub(crate)`, so these
    // cannot be integration tests.

    /// A zone whose owner names are RFC 4034 §6.1's example vector, as far as
    /// the config surface can express it.
    ///
    /// The RFC's `\001.z.example` and `\200.z.example` go in through raw label
    /// octets, which `[[zone.records]]` has no syntax for — hickory's `FromStr`
    /// rejects `\001` as a malformed label. `tests/canonical_order.rs` puts all
    /// nine through the key directly; what is exercised here is that the arena
    /// is physically sorted by it, which the six writable names establish.
    /// `*.z` is among them, so a wildcard node's position is pinned too.
    fn rfc_4034_example_zone() -> Zone {
        zone_with_origin(
            "example",
            vec![
                spec("z", "A", &["203.0.113.6"]),
                spec("yljkjljk.a", "A", &["203.0.113.3"]),
                spec("*.z", "A", &["203.0.113.8"]),
                spec("@", "A", &["203.0.113.1"]),
                spec("zABC.a", "A", &["203.0.113.5"]),
                spec("a", "A", &["203.0.113.2"]),
                spec("Z.a", "A", &["203.0.113.4"]),
            ],
        )
    }

    /// Scenario: The arena is physically in RFC 4034 §6.1 canonical order
    /// features/zone-data-model.feature:387
    ///
    /// Asserted against `LowerName: Ord`, whose `cmp_labels` *is* §6.1, rather
    /// than against the byte key the arena is actually sorted by — the key's
    /// correctness is claimed *from* `Ord`, so checking one against the other is
    /// the only check that is not circular. `tests/canonical_order.rs` holds the
    /// key to the RFC's own printed vector; this holds the arena to the key.
    #[test]
    fn the_arena_is_in_rfc_4034_canonical_order() {
        let z = rfc_4034_example_zone();
        assert!(
            z.nodes.len() >= 7,
            "the fixture must materialise every owner as a node, or the ordering \
             is asserted over a shorter list than it looks"
        );

        for pair in z.nodes.windows(2) {
            let (left, right) = (&pair[0], &pair[1]);
            let (lo, hi) = (
                LowerName::from(left.name.clone()),
                LowerName::from(right.name.clone()),
            );
            assert_eq!(
                lo.cmp(&hi),
                std::cmp::Ordering::Less,
                "the arena is not in RFC 4034 §6.1 canonical order: {} is filed \
                 before {}. Nothing reads this order yet, which is why it is \
                 pinned now — the first reader is the NSEC chain, whose next \
                 owner name is node i+1, and a chain that does not close \
                 SERVFAILs the whole zone at every validating resolver",
                left.name,
                right.name
            );
        }
    }

    /// Scenario: Node 0 is the apex and every node's parent has a lower index
    /// features/zone-data-model.feature:399
    ///
    /// The two structural facts the rest of the design reads as given:
    /// `NodeIdx::APEX` is a constant rather than a search, and S4's `cut`
    /// propagation is one forward pass because a parent has always already been
    /// visited. Both are consequences of canonical order and both stop being
    /// true silently if the sort moves.
    ///
    /// Stated over *ancestors*, not just parents. At S1 there are no empty
    /// non-terminals (that is S2), so a node's immediate parent is frequently
    /// not a node at all — but every ancestor that *is* one must still precede
    /// it, and that is the property the forward pass actually needs.
    #[test]
    fn node_zero_is_the_apex_and_every_ancestor_that_exists_precedes_its_descendant() {
        for z in [
            rfc_4034_example_zone(),
            zone(vec![
                spec("a.b.c.deep", "A", &["203.0.113.1"]),
                spec("*.dev", "A", &["203.0.113.2"]),
                spec("*.*.dev", "A", &["203.0.113.3"]),
                spec("dev", "A", &["203.0.113.4"]),
                spec("www", "CNAME", &["dev.example.com."]),
            ]),
            zone(Vec::new()),
            zone_with_origin(".", vec![spec("*", "A", &["203.0.113.1"])]),
        ] {
            let apex = z
                .nodes
                .get(NodeIdx::APEX.get())
                .expect("every zone has at least its apex");
            assert_eq!(
                LowerName::from(apex.name.clone()),
                z.lower_origin,
                "node 0 is not the apex. Canonical order puts the shortest name \
                 in the zone first and every other node is a descendant of it, \
                 so NodeIdx::APEX is a constant rather than a search — unless \
                 the sort changed"
            );

            for (i, node) in z.nodes.iter().enumerate() {
                let name = LowerName::from(node.name.clone());
                for (j, other) in z.nodes.iter().enumerate() {
                    let ancestor = LowerName::from(other.name.clone());
                    if i == j || !ancestor.zone_of(&name) {
                        continue;
                    }
                    assert!(
                        j < i,
                        "{} is an ancestor of {} but sits at index {j}, after \
                         index {i}. Every forward pass over the arena — `cut` \
                         propagation at S4, the NSEC chain at VEGA-040 — reads \
                         this as given and none of them would notice",
                        other.name,
                        node.name
                    );
                }
            }
        }
    }

    /// Scenario: Every node round-trips through the hash index
    /// features/zone-data-model.feature:416
    ///
    /// The index and the arena are built in one function from one scratch map
    /// and dropped together, so they cannot drift across a reload. What this
    /// guards is the build-time failure: a node the index cannot find is a
    /// configured record answering NXDOMAIN with nothing in the log.
    ///
    /// Probed the way a packet probes — through the suffix hash of the node's
    /// own name — so a seed or a fold that disagreed between build and query
    /// fails here rather than in production.
    #[test]
    fn every_node_round_trips_through_the_hash_index() {
        for z in [
            rfc_4034_example_zone(),
            zone(vec![
                spec("*.dev", "A", &["203.0.113.2"]),
                spec("*.*.dev", "A", &["203.0.113.3"]),
                spec("dev", "A", &["203.0.113.4"]),
                spec("a.b.c.deep", "A", &["203.0.113.1"]),
            ]),
            zone_with_origin(".", vec![spec("*", "A", &["203.0.113.1"])]),
        ] {
            assert_eq!(
                z.index.len(),
                z.nodes.len(),
                "the index holds a different number of entries than the arena \
                 holds nodes"
            );

            for (i, node) in z.nodes.iter().enumerate() {
                let name = LowerName::from(node.name.clone());
                let hashes = SuffixHashes::new(z.hash_seed, &name);
                // A wildcard node is probed as `*` under its parent, which is
                // the shape the lookup uses and the only shape that reaches it.
                let found = if node.flags.contains(NodeFlags::WILDCARD) {
                    z.wildcard_node(&name, hashes.labels().saturating_sub(1), &hashes)
                } else {
                    z.exact_node(&name, &hashes)
                };
                assert_eq!(
                    found.map(NodeIdx::get),
                    Some(i),
                    "{} is node {i} in the arena and the index does not lead \
                     back to it. A record that cannot be found is NXDOMAIN with \
                     nothing in the log",
                    node.name
                );
            }
        }
    }

    /// The order a record set is answered in is the order the config declares
    /// it, across every shape the arena stores one in.
    ///
    /// WRITTEN BECAUSE A MUTANT SURVIVED. Emitting an RRset's records in
    /// reverse — `values.iter().rev()` in `Zone::emit` — passed all 573 tests in
    /// this tree, `tests/arena_differential.rs` included. The differential
    /// compares records in order and would have caught it, but its generator
    /// gives every spec a single value and a random TTL, so a set with two
    /// records in it is a case it reaches only by luck. Order was unpinned
    /// before S1 too (qa-spec recorded it as finding (b)); S1 is where it starts
    /// mattering, because the arena is free to lay records out in any order it
    /// likes and nothing else would notice.
    ///
    /// Order is contract, not taste: the ruling makes config order the reason
    /// answers are deterministic across builds and reloads, and a zone that
    /// permutes an address set between reloads makes a load-balancing
    /// resolver's behaviour unreproducible and a packet capture undiffable.
    ///
    /// The third case is the discriminating one. Two blocks for one owner and
    /// type with **different** TTLs are merged into one answer with mixed TTLs
    /// today — the RFC 2181 §5 violation VEGA-061 pins and S5 fixes — so the
    /// arena keeps them as consecutive runs rather than storing a TTL per
    /// record. Declaring 10, 20, then 10 again is what says the runs are not
    /// regrouped by TTL on the way in, and it is a case that cannot arise at all
    /// once S5 refuses the config.
    #[test]
    fn an_rrset_is_answered_in_the_order_the_config_declares_it() {
        let _watchdog = watchdog();

        let ttl = |name: &str, values: &[&str], ttl: u32| {
            let mut s = spec(name, "A", values);
            s.ttl = Some(ttl);
            s
        };

        let z = zone(vec![
            spec("pool", "A", &["203.0.113.1", "203.0.113.2", "203.0.113.3"]),
            ttl("merged", &["203.0.113.10"], 60),
            ttl("merged", &["203.0.113.11"], 60),
            ttl("runs", &["203.0.113.20"], 10),
            ttl("runs", &["203.0.113.21"], 20),
            ttl("runs", &["203.0.113.22"], 10),
        ]);

        for (label, name, want) in [
            (
                "one block, three values",
                "pool.example.com.",
                vec![
                    ("203.0.113.1", 300),
                    ("203.0.113.2", 300),
                    ("203.0.113.3", 300),
                ],
            ),
            (
                "two blocks at one TTL",
                "merged.example.com.",
                vec![("203.0.113.10", 60), ("203.0.113.11", 60)],
            ),
            (
                "three blocks, TTLs 10, 20, 10",
                "runs.example.com.",
                vec![
                    ("203.0.113.20", 10),
                    ("203.0.113.21", 20),
                    ("203.0.113.22", 10),
                ],
            ),
        ] {
            let Answer::Records(records) = z.lookup(&lower(name), RecordType::A) else {
                panic!("{label}: {name} must be answered");
            };
            let got: Vec<(RData, u32)> = records.iter().map(|r| (r.data.clone(), r.ttl)).collect();
            let expected: Vec<(RData, u32)> =
                want.iter().map(|(addr, ttl)| (a(addr), *ttl)).collect();
            assert_eq!(
                got, expected,
                "{label}: {name} was answered out of the order its config \
                 declares. Config order is what makes an answer reproducible \
                 across a reload"
            );
        }
    }

    // ----------------------------------------------- S0: the suffix hash
    //
    // AC-0.4 of the ruling, and the two scenarios it is written from. Neither is
    // reachable from outside the crate: §10.1 keeps the primitives `pub(crate)`
    // on purpose, because a `pub` API with no caller is its own defect, and
    // there is no answer to attach the claim to. So they are unit tests, here,
    // in the commit that adds the primitive.

    /// Scenario: The suffix hash at every depth equals hashing that suffix
    /// directly
    /// features/zone-data-model.feature:187
    ///
    /// The entire correctness claim of the one-pass hash. `h[d]` is produced by
    /// folding labels right to left and stopping; the oracle materialises the
    /// `d` rightmost labels with `trim_to` — the very allocation S0 exists to
    /// remove from the hot path, which is exactly why it is safe to use as the
    /// reference here — and hashes that name from scratch. If the two ever
    /// disagree, every probe below the deepest label looks in the wrong bucket
    /// and a configured wildcard answers NXDOMAIN with nothing in the log.
    ///
    /// The last assertion is the one that pins the per-label finalisation, and
    /// the pair is not obvious. The fold consumes labels from the **rightmost**,
    /// so `b.ac.` presents `a, c, b` and so does `cb.a.` — the same octets, in
    /// the same order, with the boundary in a different place. Two names that
    /// merely *look* transposed (`ab.c.` against `a.bc.`) present `c, a, b` and
    /// `b, c, a` and are separated by the octet order alone, so a test written
    /// on those passes with the finalisation deleted. Measured: it did.
    #[test]
    fn the_suffix_hash_at_every_depth_equals_hashing_that_suffix_directly() {
        const SEED: u64 = 0x0123_4567_89ab_cdef;

        for text in [
            ".",
            "example.com.",
            "a.b.c.d.e.example.com.",
            "b.ac.example.com.",
            "cb.a.example.com.",
            "*.dev.example.com.",
            "*.*.dev.example.com.",
        ] {
            let name = lower(text);
            let hashes = SuffixHashes::new(SEED, &name);
            assert_eq!(
                hashes.labels(),
                label_count(&name),
                "{text}: the pass must record the raw label count"
            );

            for depth in 0..=label_count(&name) {
                let suffix = LowerName::from(name.trim_to(depth));
                assert_eq!(
                    hashes.at(depth),
                    Some(name_hash(SEED, &suffix)),
                    "{text}: h[{depth}] is not the hash of {suffix}, so every \
                     probe at that depth looks in the wrong bucket"
                );
            }

            assert_eq!(
                hashes.at(label_count(&name) + 1),
                None,
                "{text}: a depth past the name's own label count has no suffix \
                 to hash and must not report one"
            );
        }

        // The boundary case. `b.ac.` and `cb.a.` are the same five octets in
        // the same order under a right-to-left fold; only the finalisation at
        // each label boundary tells them apart. Without it these two names key
        // the same bucket, and a zone holding both answers one of them from the
        // other's records.
        assert_ne!(
            name_hash(SEED, &lower("b.ac.")),
            name_hash(SEED, &lower("cb.a.")),
            "two names differing only in where a label boundary falls hash the \
             same; the fold is not marking boundaries"
        );
    }

    /// Scenario: A 127-label name produces 128 suffix hashes and allocates
    /// nothing
    /// features/zone-data-model.feature:197
    ///
    /// `h[0]` is the root, so the deepest name the wire can carry fills the
    /// array to its last entry and not one past it. That last entry is indexed
    /// by a label count taken from a name an attacker chose, and with
    /// `panic = "abort"` one index past it is a full outage from one packet.
    ///
    /// The allocation half is asserted structurally here — the whole state is a
    /// `[u64; MAX_LABELS + 1]` and a `usize`, with nowhere to keep a heap
    /// pointer — and mechanically in `tests/zone_memory.rs`, whose negative-path
    /// budget is **zero** allocations over a thousand lookups and which drives
    /// this pass on every one of them. A `#[global_allocator]` cannot be
    /// installed here: it counts the whole process, and this binary runs 380
    /// other tests in parallel.
    #[test]
    fn a_name_at_the_label_ceiling_fills_the_suffix_array_and_keeps_it_on_the_stack() {
        const SEED: u64 = 0x0f0f_0f0f_0f0f_0f0f;

        let name = lower(&("a.".repeat(MAX_LABELS)));
        assert_eq!(
            label_count(&name),
            MAX_LABELS,
            "the fixture must sit exactly at the ceiling, not near it"
        );

        let hashes = SuffixHashes::new(SEED, &name);
        let defined = (0..=MAX_LABELS + 1)
            .filter(|d| hashes.at(*d).is_some())
            .count();
        assert_eq!(
            defined,
            MAX_LABELS + 1,
            "a {MAX_LABELS}-label name must produce exactly {} suffix hashes — \
             one per depth including the root",
            MAX_LABELS + 1
        );

        assert_eq!(
            std::mem::size_of::<SuffixHashes>(),
            std::mem::size_of::<[u64; MAX_LABELS + 1]>() + std::mem::size_of::<usize>(),
            "SuffixHashes grew past its stack array and a label count. Anything \
             else in there is a heap pointer, and the negative path — the only \
             query shape an attacker can drive without knowing the zone — is \
             budgeted at zero allocations"
        );
    }

    // ------------------------------------------------- source-level guards
    //
    // Two contracts of this issue are properties of the *source*, not of any
    // answer, and both are invisible to every behavioural test in the tree. They
    // are checked against `include_str!` of this module, so they cost nothing at
    // runtime and fail at the moment the source stops holding them.

    /// The text of this module, read at compile time.
    const THIS_MODULE: &str = include_str!("zone.rs");

    /// The text of `tests/rfc_conformance.rs`, read at compile time.
    ///
    /// The wire-level twin of VEGA-009's unit test lives there, and the fence
    /// has to cover both or it covers neither: a zone layer that answers
    /// NXDOMAIN while the handler renders NOERROR is the same bug wearing a
    /// green unit test. Reading the file rather than calling into it keeps this
    /// a source-level guard with no runtime cost and no dependency on the
    /// integration harness.
    const RFC_CONFORMANCE: &str = include_str!("../tests/rfc_conformance.rs");

    /// Scenario: The pinned VEGA-009 tests are green and no longer ignored
    /// features/closest-encloser.feature:694
    ///
    /// AMENDED AT VEGA-032 S3, in the commit that discharges the last third of
    /// it — which is the only commit in which editing it is legitimate (ruling
    /// §13, the same rule VEGA-005 Amendment 3a set for the reload
    /// classification table).
    ///
    /// It has now inverted completely. It began as VEGA-083's AC-9, asserting
    /// that all **three** `#[ignore]`d tests stayed ignored with their reasons
    /// pinned verbatim. S2 turned two of them green. S3 turns the third green,
    /// so there is no longer any `#[ignore]` for it to pin — and a guard that
    /// still said "one is still ignored" would be drift wearing a passing test.
    ///
    /// What is left is the direction that stays load-bearing forever: **none of
    /// them may be `#[ignore]`d again**, in either file. Re-ignoring a test is
    /// the cheapest way to make a regression disappear, every one of these was
    /// un-ignored by a ruling, and each pins a defect that is silent in
    /// production — a wildcard leaking into a subtree an operator carved out
    /// answers with a correct-looking address, and an empty non-terminal
    /// answering NXDOMAIN takes live records out of service through RFC 8020 §2
    /// rather than through an error anyone sees.
    ///
    /// The needle is spliced from `concat!` fragments on purpose: a literal
    /// copy would match itself in `THIS_MODULE` and the guard would pass against
    /// a re-added attribute.
    ///
    /// AMENDED AT VEGA-032 S2, in the commit that discharged two thirds of it —
    /// which is the only commit in which editing it is legitimate (ruling §13,
    /// the same rule VEGA-005 Amendment 3a set for the reload classification
    /// table). It was AC-9 of the VEGA-083 ruling and it asserted that all
    /// **three** `#[ignore]`d tests below stayed ignored with their reasons
    /// pinned verbatim.
    ///
    /// S2 materialises every strict ancestor, so two of the three are now green
    /// and un-`#[ignore]`d: `an_empty_non_terminal_is_nodata_not_nxdomain` and
    /// `the_parent_of_a_wildcard_is_not_nxdomain`, both VEGA-006's. The third,
    /// `a_wildcard_does_not_apply_below_a_name_that_exists`, is VEGA-009's and
    /// belongs to **S3**: ancestor closure makes the closest-encloser fix
    /// tempting to fold in here, and folding it in would leave S3 with nothing
    /// to prove and no differential to prove it against.
    ///
    /// S3 discharges the last of the three. The guard therefore checks **one**
    /// direction now, in **two** files:
    ///
    ///  * all three are still present — deleting a test is how a fence stops
    ///    being checked without anyone reading a diff that says so;
    ///  * none of them carries an `#[ignore]`, in `src/zone.rs` or in
    ///    `tests/rfc_conformance.rs`.
    ///
    /// And it checks that the *reason strings* are gone from both files as
    /// literals, so an `#[ignore]` cannot come back spelled the way it was.
    #[test]
    fn every_rfc_bug_this_model_fixes_is_green_and_none_of_them_is_ignored_again() {
        let ignored_near = |source: &str, name: &str| -> Option<String> {
            let lines: Vec<&str> = source.lines().collect();
            let needle = format!("fn {name}(");
            let at = lines
                .iter()
                .position(|line| line.contains(&needle))
                .unwrap_or_else(|| {
                    panic!(
                        "{name} is gone. It pins a known RFC defect, or the fix \
                         for one; deleting it is how the fence stops being \
                         checked"
                    )
                });
            lines[at.saturating_sub(4)..at]
                .iter()
                .map(|l| l.trim())
                .find(|l| l.starts_with("#[ignore"))
                .map(str::to_owned)
        };

        // VEGA-006, discharged at S2. VEGA-009, discharged at S3. All three are
        // now green and none may be `#[ignore]`d again.
        for (source, file, name, issue) in [
            (
                THIS_MODULE,
                "src/zone.rs",
                "an_empty_non_terminal_is_nodata_not_nxdomain",
                "VEGA-006",
            ),
            (
                THIS_MODULE,
                "src/zone.rs",
                "the_parent_of_a_wildcard_is_not_nxdomain",
                "VEGA-006",
            ),
            (
                THIS_MODULE,
                "src/zone.rs",
                "a_wildcard_does_not_apply_below_a_name_that_exists",
                "VEGA-009",
            ),
            (
                RFC_CONFORMANCE,
                "tests/rfc_conformance.rs",
                "an_empty_non_terminal_answers_nodata_over_the_wire",
                "VEGA-006",
            ),
            (
                RFC_CONFORMANCE,
                "tests/rfc_conformance.rs",
                "a_wildcard_does_not_reach_below_a_name_that_exists",
                "VEGA-009",
            ),
        ] {
            assert_eq!(
                ignored_near(source, name),
                None,
                "{file}::{name} is `#[ignore]`d again. It pins {issue}, closed by \
                 the VEGA-032 zone data model, and it was un-ignored by a ruling. \
                 Re-ignoring a test is not a way to fix the code it catches: if \
                 it is failing, either a wildcard is leaking into a subtree an \
                 operator carved out (RFC 4592 §3.3.1) or a name that exists only \
                 as an ancestor is answering NXDOMAIN and RFC 8020 §2 is denying \
                 the live records beneath it. Both are silent in production"
            );
        }

        // The reason strings themselves, so the attribute cannot come back
        // wearing its old text. Spliced, or the needles would match here.
        for (source, file, reason) in [
            (
                THIS_MODULE,
                "src/zone.rs",
                concat!(
                    "BUG: a wildcard is applied below a name that exists ",
                    "(RFC 4592 s3.3.1)"
                ),
            ),
            (
                RFC_CONFORMANCE,
                "tests/rfc_conformance.rs",
                concat!(
                    "BUG: a wildcard is applied below an existing closest ",
                    "encloser (RFC 4592 s3.3.1)"
                ),
            ),
        ] {
            assert!(
                !source.contains(&format!("#[ignore = \"{reason}\"]")),
                "{file} still carries `#[ignore = \"{reason}\"]`. VEGA-009 is \
                 closed at VEGA-032 S3; an ignore attribute quoting it is either \
                 a fence that was never taken down or one that was put back"
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
    // Known bugs, written against the RFC. This list is **empty at VEGA-032
    // S3**: all three of its residents are green and none of them carries an
    // `#[ignore]` any more. They are kept here, together, because what they pin
    // is what the model exists to get right, and because a regression test is
    // worth most when the reader can see the defect it was written against.
    //
    // THE ORDER THEY WERE DISCHARGED IN, AND BY WHAT.
    //
    //   * `an_empty_non_terminal_is_nodata_not_nxdomain` — VEGA-006, **S2**.
    //     Every strict ancestor of every owner is a node with an empty RRset
    //     range, so a name that exists only as an ancestor is NODATA (RFC 4592
    //     §2.2.2, RFC 2308 §2.2) and RFC 8020 §2 can no longer be used to deny
    //     the subtree beneath it.
    //   * `the_parent_of_a_wildcard_is_not_nxdomain` — VEGA-006, **S2**. A
    //     wildcard is a node named `*.x`, so `x` exists for exactly the same
    //     reason as any other ancestor.
    //   * `a_wildcard_does_not_apply_below_a_name_that_exists` — VEGA-009,
    //     **S3**. RFC 4592 §3.3.1: the source of synthesis is `*` under the
    //     CLOSEST ENCLOSER and no other name. The walk that climbed to the
    //     first wildcard it could find is deleted; the lookup finds the closest
    //     encloser by binary search over label depth and makes exactly ONE
    //     probe at `*.<CE>`. "There is no search for an alternate" is now a
    //     property of the code rather than a comment above a loop.
    //
    // WHY S3 NEEDED S2 UNDERNEATH IT. The binary search reads "a node exists at
    // this depth" as a MONOTONE predicate, which it is only while the node set
    // is closed under ancestry. And the rule is only *expressible* once empty
    // non-terminals exist: in `*.dev` + `a.b.deep.dev`, the closest encloser of
    // `x.b.deep.dev` is `b.deep.dev`, a name the operator never wrote.
    //
    // VEGA-065 NOTE, kept for the history it records — that issue was strictly
    // behaviour-preserving and all three stayed red under it.
    //
    // VEGA-083 NOTE, likewise: it is NOT behaviour-preserving (it turns NXDOMAIN
    // into NODATA for names a wildcard covers) and all three still stayed red,
    // structurally rather than by luck — a wildcard cannot declare its own
    // parent covered, because RFC 4592 §3.3.1 makes that parent a proper
    // ancestor of the names it covers and `wildcard_window` caps the walk at the
    // query's parent depth.
    //
    // VEGA-032 S3 NOTE — what it cost to close the third. The bounded walk over
    // `wildcard_depths` is gone, and with it the u128: ancestor closure makes
    // the populated depths contiguous, so the bitmap carries no information a
    // `u8` pair does not. VEGA-065's *invariant* is kept verbatim — raw label
    // counting, `MAX_LABELS = 127`, the `num_labels` ban — and only its
    // mechanism is replaced. VEGA-065's differential oracle
    // (`tests/properties.rs::the_wildcard_walk_agrees_with_a_naive_base_name_walk`)
    // is RETIRED here, in the commit that makes it wrong, and replaced by a
    // brute-force transcription of RFC 4592 §3.3.1 that permits no transitions
    // at all. Retiring it silently would have been the failure mode.
    //
    // VEGA-078 closes with it, and not as a patch: the probe count stops being
    // `popcount(wildcard_depths)` and becomes a constant, so the 120-depth zone
    // that bought an attacker ~229 µs of CPU for one 276-byte packet is now the
    // same cost as a one-depth zone.
    //
    // The absence of an `#[ignore]` on all three, in both files, is pinned by
    // `every_rfc_bug_this_model_fixes_is_green_and_none_of_them_is_ignored_again`.
    //
    // (VEGA-010 used to be on this list. It was the same defect as VEGA-083 seen
    // through another QTYPE, and closed with it.)
    // -----------------------------------------------------------------------

    /// Scenario: A name that exists only as an ancestor is NODATA, not NXDOMAIN
    /// features/empty-non-terminals.feature:73
    ///
    /// VEGA-006's headline, un-`#[ignore]`d at VEGA-032 S2.
    #[test]
    fn an_empty_non_terminal_is_nodata_not_nxdomain() {
        let _watchdog = watchdog();
        // `a.b.ent.example.com` exists, so `ent.example.com` and
        // `b.ent.example.com` exist too, as empty non-terminals. Answering
        // NXDOMAIN for them is not cosmetic: under RFC 8020 a resolver that
        // caches NXDOMAIN for `ent.example.com` may synthesise NXDOMAIN for
        // everything beneath it, taking the real record out of service.
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

    /// Scenario: A wildcard does not apply below a name that exists
    /// features/closest-encloser.feature:117
    ///
    /// VEGA-009's headline, un-`#[ignore]`d at VEGA-032 S3.
    #[test]
    fn a_wildcard_does_not_apply_below_a_name_that_exists() {
        let _watchdog = watchdog();
        // RFC 4592: the source of synthesis is `*` under the *closest
        // encloser*. For `a.deep.dev.example.com` the closest encloser is
        // `deep.dev.example.com`, which exists, so the source of synthesis is
        // `*.deep.dev.example.com` — which does not exist, hence NXDOMAIN.
        // `Zone::resolve` used to walk up until it found any wildcard at all,
        // so `*.dev` leaked in underneath a name that already existed.
        let z = zone(vec![
            spec("*.dev", "A", &["203.0.113.50"]),
            spec("deep.dev", "A", &["203.0.113.51"]),
        ]);
        assert_eq!(
            z.lookup(&lower("a.deep.dev.example.com."), RecordType::A),
            Answer::NxDomain
        );
    }

    /// Scenario: The parent of a wildcard exists
    /// features/empty-non-terminals.feature:112
    ///
    /// VEGA-006 through the wildcard shape, un-`#[ignore]`d at VEGA-032 S2.
    #[test]
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

    // =======================================================================
    // VEGA-032 S2 — EMPTY NON-TERMINALS (closes VEGA-006)
    //
    // Spec: features/empty-non-terminals.feature
    // Ruling: .claude/backlog/decisions/VEGA-032-zone-data-model.md §3.1, §4.3,
    //         §6.1 I-3, §10.2 (S2), §13 AC-2.1 … AC-2.6
    //
    // Every strict ancestor of every owner name, up to the origin, is a node
    // with an empty RRset range. An empty non-terminal is not a variant in the
    // model — it is "a node with no RRsets", which is what RFC 4592 §2.2.2 says
    // it is and what RFC 4035 §2.3 will need to emit an NSEC carrying only the
    // NSEC and RRSIG bits.
    //
    // Two of these are about answers and one is about structure. The structural
    // one (`every_node_has_its_parent_in_the_arena`) is the most valuable test
    // in this group even though it asserts no answer at all: S3's
    // closest-encloser BINARY SEARCH needs "a node exists at this depth" to be
    // monotone, and it is monotone only under ancestor closure. A hole in the
    // chain returns a shallower encloser than the truth, synthesises a wildcard
    // into a subtree an operator carved out, and reopens VEGA-009 with answers
    // that look correct.
    // =======================================================================

    /// Every owner name a zone holds a node for, as the arena holds them.
    ///
    /// Reaches into the arena rather than going through [`Zone::exists`],
    /// because `exists` deliberately answers "would this name be a name error"
    /// — it is true for wildcard-covered names that are not nodes and false for
    /// wildcard nodes themselves (RFC 4592 §2.2). Ancestor closure is a claim
    /// about the NODE SET, so it has to be read off the node set.
    fn node_names(z: &Zone) -> std::collections::HashSet<LowerName> {
        z.nodes
            .iter()
            .map(|n| LowerName::from(n.name.clone()))
            .collect()
    }

    /// Scenario: Every strict ancestor of an owner exists, not just the
    /// immediate parent
    /// features/empty-non-terminals.feature:82
    ///
    /// A materialisation loop that stops after one level passes
    /// `an_empty_non_terminal_is_nodata_not_nxdomain` and leaves every
    /// grandparent NXDOMAIN — the same RFC 8020 §2 denial, one label higher.
    /// The ruling names "ancestor materialisation loop stopping one level short"
    /// as a mutant that must be killed; this is what kills it.
    #[test]
    fn every_strict_ancestor_of_an_owner_exists_up_to_the_apex() {
        let _watchdog = watchdog();
        let z = zone(vec![spec("a.b.c.d", "A", &["203.0.113.41"])]);
        for ancestor in [
            "b.c.d.example.com.",
            "c.d.example.com.",
            "d.example.com.",
            "example.com.",
        ] {
            assert_eq!(
                z.lookup(&lower(ancestor), RecordType::A),
                Answer::NoData,
                "{ancestor} exists because a.b.c.d.example.com. does \
                 (RFC 4592 §2.2.2); NXDOMAIN here lets an RFC 8020 §2 resolver \
                 deny everything below it, including the configured record"
            );
        }
    }

    /// Scenario: The record beneath an empty non-terminal still answers
    /// features/empty-non-terminals.feature:91
    ///
    /// The half that makes the fix worth having, and the anti-vacuity control
    /// for every negative assertion in this group: a build that materialised
    /// ancestors but shadowed or dropped the leaf would satisfy all of them.
    #[test]
    fn the_record_beneath_an_empty_non_terminal_still_answers() {
        let _watchdog = watchdog();
        let z = zone(vec![spec("a.b.ent", "A", &["203.0.113.41"])]);
        let Answer::Records(records) = z.lookup(&lower("a.b.ent.example.com."), RecordType::A)
        else {
            panic!("the configured record must still answer at its own name");
        };
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].data, a("203.0.113.41"));
        assert_eq!(records[0].name, parse_name("a.b.ent.example.com.").unwrap());
        assert_eq!(records[0].ttl, 300);
    }

    /// Scenario: The service-record shapes that created this bug are all NODATA
    /// features/empty-non-terminals.feature:100
    ///
    /// VEGA-006's own evidence. SRV, TLSA and DKIM each put a record two or
    /// three labels below a name nobody writes, so every zone that uses them
    /// holds empty non-terminals; the issue's acceptance criterion names these
    /// three shapes specifically.
    #[test]
    fn the_service_record_shapes_that_created_this_bug_are_all_nodata() {
        let _watchdog = watchdog();
        let z = zone(vec![
            spec("_sip._tcp", "SRV", &["10 10 5060 sip.example.com."]),
            spec(
                "_443._tcp.www",
                "TLSA",
                &["3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],
            ),
            spec("sel._domainkey", "TXT", &["v=DKIM1; k=rsa; p=MIIB"]),
        ]);

        for ent in [
            "_tcp.example.com.",
            "_tcp.www.example.com.",
            "www.example.com.",
            "_domainkey.example.com.",
        ] {
            assert_eq!(
                z.lookup(&lower(ent), RecordType::A),
                Answer::NoData,
                "{ent} is an empty non-terminal of a service record set"
            );
        }

        // Anti-vacuity: each configured record still answers at its own name, or
        // the NODATA answers above are a zone that lost its records.
        for (name, rtype) in [
            ("_sip._tcp.example.com.", RecordType::SRV),
            ("_443._tcp.www.example.com.", RecordType::TLSA),
            ("sel._domainkey.example.com.", RecordType::TXT),
        ] {
            let Answer::Records(records) = z.lookup(&lower(name), rtype) else {
                panic!("{name} {rtype} must still answer");
            };
            assert_eq!(records.len(), 1, "{name} {rtype}");
        }
    }

    /// Scenario: An owner one label below the apex creates no empty
    /// non-terminal
    /// features/empty-non-terminals.feature:163
    ///
    /// The discriminating negative for the whole feature. Without it, "answer
    /// NODATA for every name in the zone" passes every positive scenario here
    /// and makes the server authoritatively deny nothing — which is the failure
    /// mode VEGA-083 spent an issue bounding.
    #[test]
    fn an_owner_one_label_below_the_apex_creates_no_empty_non_terminal() {
        let _watchdog = watchdog();
        let z = zone(vec![spec("www", "A", &["203.0.113.10"])]);
        assert_eq!(
            z.lookup(&lower("nope.example.com."), RecordType::A),
            Answer::NxDomain,
            "nothing exists at or below nope.example.com., so it is a real name \
             error (RFC 1034 §4.3.2 step 3(c))"
        );
        assert_eq!(
            z.lookup(&lower("x.www.example.com."), RecordType::A),
            Answer::NxDomain,
            "an owner name is not made into a wildcard by having descendants \
             materialised above it"
        );
    }

    /// Scenario: The ancestor walk stops at the origin and never materialises a
    /// name above it
    /// features/empty-non-terminals.feature:174
    ///
    /// The off-by-one in the other direction. A walk that runs past the origin
    /// puts `com.` and the root in the node set; a server that holds a node for
    /// `com.` is one dispatch change away from answering for it. Out-of-zone
    /// names are refused before the zone is consulted, so the claim is asserted
    /// against the node set itself, where it is observable.
    #[test]
    fn the_ancestor_walk_stops_at_the_origin() {
        let _watchdog = watchdog();
        let z = zone(vec![spec("a.b", "A", &["203.0.113.41"])]);
        let names = node_names(&z);
        for above in ["com.", "."] {
            assert!(
                !names.contains(&lower(above)),
                "{above} is above the origin and must never be a node: \
                 materialising it makes the zone claim a name it is not \
                 authoritative for. Nodes: {names:?}"
            );
        }
        assert!(
            names.contains(&lower("b.example.com.")),
            "the walk must reach the ancestor it exists for"
        );
        assert!(names.contains(&lower("example.com.")), "the apex is a node");
    }

    /// Scenario: An empty non-terminal is NODATA for every type, including ANY
    /// features/empty-non-terminals.feature:185
    ///
    /// Existence is a property of the NAME and never of the QTYPE (RFC 1034
    /// §4.3.2 step 3(c)). A fix that materialised ancestors per type — the
    /// obvious shape if the ancestor loop is written inside `insert_spec`'s
    /// RRset handling — would answer NXDOMAIN for AAAA at a name that exists,
    /// which is the same RFC 8020 §2 denial arriving through a dual-stack
    /// client rather than through an attacker.
    #[test]
    fn an_empty_non_terminal_is_nodata_for_every_type_including_any() {
        let _watchdog = watchdog();
        let z = zone(vec![spec("a.b.ent", "A", &["203.0.113.41"])]);
        for rtype in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::TXT,
            RecordType::MX,
            RecordType::SRV,
            RecordType::CNAME,
            RecordType::SOA,
            RecordType::NS,
            RecordType::ANY,
        ] {
            assert_eq!(
                z.lookup(&lower("b.ent.example.com."), rtype),
                Answer::NoData,
                "b.ent.example.com. exists, so {rtype} there is NODATA and never \
                 a name error"
            );
        }
        assert!(
            z.exists(&lower("b.ent.example.com.")),
            "Zone::exists is the RFC 1034 §4.3.2 step 3(c) name-error \
             determination and an empty non-terminal is not a name error"
        );
    }

    /// Scenario: An empty non-terminal is not counted as a record
    /// features/empty-non-terminals.feature:195
    ///
    /// AC-2.4. `record_count` is the `dns_zone_records` gauge and an operator's
    /// only view of whether a reload truncated the zone. Empty non-terminals are
    /// nodes, not records; counting them moves the gauge on upgrade with no
    /// config change and makes any alert on it worthless.
    #[test]
    fn an_empty_non_terminal_is_not_counted_as_a_record() {
        let _watchdog = watchdog();
        let z = zone(vec![spec("a.b.c.d", "A", &["203.0.113.41"])]);
        assert_eq!(
            z.record_count(),
            1,
            "one configured value is one record, however many nodes it implies"
        );
        assert_eq!(
            z.nodes.len(),
            5,
            "a.b.c.d + three empty non-terminals + the apex; if this is 1 the \
             ancestors were never materialised and if it is more they were \
             materialised twice"
        );
    }

    /// Scenario: Every node in the arena has its parent in the arena
    /// features/empty-non-terminals.feature:205
    ///
    /// Invariant I-3, asserted structurally rather than through an answer.
    /// **This is the load-bearing test of S2 and the reason S3 can be a binary
    /// search at all**: the predicate "a node exists at this depth" is monotone
    /// only because the node set is closed under ancestry. A hole in the chain
    /// makes S3's search return a shallower closest encloser than the truth, so
    /// a wildcard synthesises into a subtree an operator carved out — VEGA-009
    /// reopened, silently, with correct-looking answers.
    ///
    /// Asserted in a release build too, not only behind `debug_assert`, because
    /// a release build is where it will run.
    #[test]
    fn every_node_has_its_parent_in_the_arena() {
        let _watchdog = watchdog();
        for z in [
            zone(vec![
                spec("a.b.c.deep", "A", &["203.0.113.1"]),
                spec("*.dev", "A", &["203.0.113.2"]),
                spec("*.*.dev", "A", &["203.0.113.3"]),
                spec("x.*.dev", "A", &["203.0.113.5"]),
                spec("dev", "A", &["203.0.113.4"]),
                spec("_sip._tcp", "SRV", &["10 10 5060 sip.example.com."]),
            ]),
            zone(Vec::new()),
            zone_with_origin(".", vec![spec("a.b.c.", "A", &["203.0.113.1"])]),
        ] {
            let names = node_names(&z);
            let apex = z.lower_origin.clone();
            for name in &names {
                if *name == apex {
                    continue;
                }
                let parent = LowerName::from(Name::from(name.clone()).base_name());
                assert!(
                    names.contains(&parent),
                    "{name} is a node but its parent {parent} is not. The node \
                     set must be closed under ancestry (RFC 4592 §2.2.2, ruling \
                     I-3): S3's closest-encloser binary search reads \"a node \
                     exists at this depth\" as a monotone predicate, and a hole \
                     here makes it return a shallower encloser than the truth"
                );
            }

            // The order half: canonical order is what makes the forward pass
            // that computes `cut` (S4) correct, and ancestor closure is what
            // makes "the parent" a node to find in the first place.
            for (i, node) in z.nodes.iter().enumerate() {
                let name = LowerName::from(node.name.clone());
                for (j, other) in z.nodes.iter().enumerate() {
                    let ancestor = LowerName::from(other.name.clone());
                    if i == j || !ancestor.zone_of(&name) {
                        continue;
                    }
                    assert!(
                        j < i,
                        "{ancestor} is an ancestor of {name} but sits after it"
                    );
                }
            }
        }
    }

    /// Scenario: An ancestor that is also a declared owner keeps its records
    /// features/empty-non-terminals.feature:218
    ///
    /// The collision case. `b.example.com.` is both a configured owner and the
    /// strict ancestor of `a.b.example.com.`, and ancestor materialisation is a
    /// second write site for a node the config already wrote. An insertion that
    /// overwrites rather than merges deletes a configured record in the build,
    /// where nothing else in this tree would notice.
    #[test]
    fn an_ancestor_that_is_also_a_declared_owner_keeps_its_records() {
        let _watchdog = watchdog();
        // Both orders, because whichever of the two write sites runs first must
        // not win: a scratch map that is populated by config order alone would
        // pass one of these and fail the other.
        for records in [
            vec![
                spec("b", "A", &["203.0.113.20"]),
                spec("a.b", "A", &["203.0.113.41"]),
            ],
            vec![
                spec("a.b", "A", &["203.0.113.41"]),
                spec("b", "A", &["203.0.113.20"]),
            ],
        ] {
            let z = zone(records);
            let Answer::Records(records) = z.lookup(&lower("b.example.com."), RecordType::A) else {
                panic!("the declared record at b.example.com. must survive being an ancestor");
            };
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].data, a("203.0.113.20"));
            assert_eq!(z.record_count(), 2);
        }
    }

    /// Scenario: An ancestor that is also a declared wildcard keeps its records
    /// and stays a wildcard
    /// features/empty-non-terminals.feature:229
    ///
    /// The same collision one step nastier: `*.dev.example.com.` is a declared
    /// wildcard **and** the strict ancestor of `x.*.dev.example.com.`, which RFC
    /// 4592 §2.1.3 explicitly permits ("a wildcard domain name can have
    /// subdomains"). The build already carries a `debug_assert` that one name
    /// never arrives as both a wildcard and an ordinary node; ancestor
    /// materialisation is a second write site for exactly that field, so it must
    /// derive the flag from the NAME rather than from which loop inserted it.
    #[test]
    fn an_ancestor_that_is_also_a_declared_wildcard_keeps_its_records_and_stays_a_wildcard() {
        let _watchdog = watchdog();
        for records in [
            vec![
                spec("*.dev", "A", &["203.0.113.50"]),
                spec("x.*.dev", "A", &["203.0.113.60"]),
            ],
            vec![
                spec("x.*.dev", "A", &["203.0.113.60"]),
                spec("*.dev", "A", &["203.0.113.50"]),
            ],
        ] {
            let z = zone(records);

            let Answer::Records(synthesised) =
                z.lookup(&lower("y.dev.example.com."), RecordType::A)
            else {
                panic!("the declared wildcard must still synthesise below its parent");
            };
            assert_eq!(synthesised[0].data, a("203.0.113.50"));

            let Answer::Records(literal) = z.lookup(&lower("x.*.dev.example.com."), RecordType::A)
            else {
                panic!("the literal name below the wildcard must answer its own record");
            };
            assert_eq!(literal[0].data, a("203.0.113.60"));
            assert_eq!(z.record_count(), 2);
        }
    }

    /// Scenario: A zone holding no records materialises no empty non-terminals
    /// features/empty-non-terminals.feature:248
    ///
    /// The empty case for the new loop: it runs over an empty owner set and must
    /// produce an empty result rather than the root, the origin twice, or an
    /// empty name.
    #[test]
    fn a_zone_holding_no_records_materialises_no_empty_non_terminals() {
        let _watchdog = watchdog();
        let z = zone(Vec::new());
        assert_eq!(z.nodes.len(), 1, "the apex, and nothing else");
        assert_eq!(
            z.lookup(&lower("x.example.com."), RecordType::A),
            Answer::NxDomain
        );
        assert_eq!(
            z.lookup(&lower("example.com."), RecordType::A),
            Answer::NoData,
            "the apex exists on its own account even with no records"
        );
    }

    /// Scenario: An apex-only owner adds nothing to the node set
    /// features/empty-non-terminals.feature:258
    ///
    /// `@` qualifies to the origin, whose only strict ancestors are outside the
    /// zone. The walk must yield nothing here rather than one entry for the
    /// origin itself, which would be the apex inserted twice.
    #[test]
    fn an_apex_only_owner_adds_nothing_to_the_node_set() {
        let _watchdog = watchdog();
        let z = zone(vec![spec("@", "A", &["203.0.113.10"])]);
        assert_eq!(z.nodes.len(), 1);
        let Answer::Records(records) = z.lookup(&lower("example.com."), RecordType::A) else {
            panic!("the apex record must answer");
        };
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].data, a("203.0.113.10"));
    }

    /// Scenario: A wildcard whose own owner name exceeds 255 octets
    /// materialises no ancestors
    /// features/empty-non-terminals.feature:281
    ///
    /// RFC 1035 §2.3.4 caps a name at 255 octets, so a wildcard whose parent
    /// sits within two octets of the ceiling has no representable owner name and
    /// no node — S1 warns and serves the zone unchanged, because such a wildcard
    /// covers no representable name either.
    ///
    /// It follows that its parent is **not** an empty non-terminal: ancestor
    /// closure is closure over the NODE set, and no node exists here to imply
    /// one. Pinned because "materialise every strict ancestor of every owner" is
    /// also a defensible reading of the ruling, and under it a name would exist
    /// because of a record the zone refused to hold.
    #[test]
    fn a_wildcard_whose_owner_name_exceeds_the_octet_limit_materialises_no_ancestors() {
        let _watchdog = watchdog();
        // 121 single-octet labels + `example.com.` is 255 octets exactly, so
        // prepending `*.` is 257 and the wildcard has no owner name.
        let parent: String = std::iter::repeat_n("a", 121).collect::<Vec<_>>().join(".");
        let z = zone(vec![spec(&format!("*.{parent}"), "A", &["203.0.113.70"])]);

        let parent_name = lower(&format!("{parent}.example.com."));
        // The condition under test, asserted rather than assumed: the parent is
        // a name hickory will build and `*.<parent>` is not.
        assert!(
            Name::from(parent_name.clone()).prepend_label("*").is_err(),
            "the fixture must sit close enough to RFC 1035 §2.3.4's 255 octets \
             that the wildcard has no owner name, or it tests nothing"
        );
        assert_eq!(
            z.lookup(&parent_name, RecordType::A),
            Answer::NxDomain,
            "no node exists for the wildcard, so nothing implies its parent \
             exists; a name that exists because of a record the zone refused to \
             hold is worse than the NXDOMAIN"
        );
        assert_eq!(
            z.record_count(),
            1,
            "the record is still counted — that is S1's behaviour and S2 changes \
             answers, not the gauge"
        );
        assert_eq!(z.nodes.len(), 1, "the apex, and nothing else");
    }

    /// Scenario: A wildcard that is itself an empty non-terminal covers its
    /// names with NODATA
    /// features/empty-non-terminals.feature:311
    ///
    /// The subtlest behaviour S2 introduces, written down rather than
    /// discovered. `x.*.dev` makes `*.dev.example.com.` exist as an empty
    /// non-terminal — a node whose leftmost label is an asterisk. RFC 4592
    /// §2.1.1 says that **is** a wildcard, so it becomes a source of synthesis
    /// carrying no RRset, and RFC 1034 §4.3.2 step 3(c) then forbids the name
    /// error for the names it covers: `y.dev.example.com.` is NODATA where today
    /// it is NXDOMAIN.
    ///
    /// The flag is a property of the NAME, not of which loop created the node.
    /// Deriving it from the config instead leaves a node that the exact-name
    /// probe matches and the wildcard probe does not — a wildcard nobody can
    /// reach, and a literal query for `*.dev.example.com.` answered from a
    /// branch the pre-S1 model never used.
    #[test]
    fn a_wildcard_that_is_an_empty_non_terminal_covers_its_names_with_nodata() {
        let _watchdog = watchdog();
        let z = zone(vec![spec("x.*.dev", "A", &["203.0.113.60"])]);

        assert_eq!(
            z.lookup(&lower("y.dev.example.com."), RecordType::A),
            Answer::NoData,
            "`*.dev.example.com.` exists as an empty non-terminal, so it is a \
             source of synthesis that carries no RRset: RFC 1034 §4.3.2 step \
             3(c) forbids the name error"
        );
        assert!(
            z.exists(&lower("y.dev.example.com.")),
            "coverage and existence are one determination (VEGA-083)"
        );

        let Answer::Records(records) = z.lookup(&lower("x.*.dev.example.com."), RecordType::A)
        else {
            panic!("the configured record must still answer at its own literal name");
        };
        assert_eq!(records[0].data, a("203.0.113.60"));

        // And the empty non-terminal itself, queried literally: it exists, so it
        // is NODATA rather than a name error (RFC 4592 §2.3 — an asterisk in a
        // QNAME gets no special processing).
        assert_eq!(
            z.lookup(&lower("*.dev.example.com."), RecordType::A),
            Answer::NoData
        );
    }

    /// Scenario: An empty non-terminal chain at the protocol's label ceiling is
    /// answered
    /// features/empty-non-terminals.feature:352
    ///
    /// 127 labels is the deepest name the wire can carry — RFC 1035 §3.1 encodes
    /// a single-octet label in two octets and terminates with one, so
    /// `127 * 2 + 1 = 255` — and it is reachable only under `origin = "."`. One
    /// owner at that depth materialises 126 ancestors, which drives every
    /// label-indexed structure in the model to its largest reachable value: bit
    /// 127 of the `u128` depth bitmap and entry 127 of the `[u64; 128]` suffix
    /// hash. With `panic = "abort"` one index past the end is a full outage from
    /// one packet, so the whole chain is swept, under the process watchdog.
    #[test]
    fn an_empty_non_terminal_chain_at_the_label_ceiling_is_answered() {
        const CEILING: usize = 127;

        let _watchdog = watchdog();

        let owner: String = std::iter::repeat_n("a", CEILING)
            .collect::<Vec<_>>()
            .join(".");
        let z = zone_with_origin(".", vec![spec(&format!("{owner}."), "A", &["203.0.113.1"])]);
        let full = Name::from(lower(&format!("{owner}.")));
        assert_eq!(
            full.iter().len(),
            CEILING,
            "the fixture must sit exactly at the decoder's ceiling"
        );

        let Answer::Records(records) = z.lookup(&LowerName::from(full.clone()), RecordType::A)
        else {
            panic!("the owner at the ceiling must answer");
        };
        assert_eq!(records.len(), 1);

        for depth in 0..CEILING {
            let ancestor = LowerName::from(full.trim_to(depth));
            assert_eq!(
                z.lookup(&ancestor, RecordType::A),
                Answer::NoData,
                "the ancestor at depth {depth} of a 127-label owner exists \
                 (RFC 4592 §2.2.2) and must be answered rather than indexed out \
                 of bounds"
            );
        }
    }

    // =======================================================================
    // VEGA-032 S3 — THE CLOSEST ENCLOSER (closes VEGA-009 and VEGA-078)
    //
    // Spec: features/closest-encloser.feature
    // Ruling: .claude/backlog/decisions/VEGA-032-zone-data-model.md §4.2 step B,
    //         §4.3, §5.4, §10.2 (S3), §13 AC-3.1 … AC-3.7
    //
    // RFC 4592 §3.3.1, in full, because every test below is one clause of it:
    //
    //   "If the 'closest encloser' of the query name is a wildcard domain name
    //    ... the wildcard record is the source of synthesis ... If the source of
    //    synthesis does not exist ... there is no wildcard match. There is no
    //    search for an alternate ... the lookup does not look for other wildcard
    //    records."
    //
    // Two behaviours fall out, and the second is the one Vega got wrong:
    //
    //   1. a name that EXISTS between the wildcard's parent and the query name
    //      makes that name the closest encloser, and the wildcard no longer
    //      reaches past it;
    //   2. when the source of synthesis exists but carries no RRset of the
    //      queried type, the lookup STOPS — it does not fall back to a shallower
    //      wildcard.
    //
    // The second is what distinguishes the closest-encloser rule from
    // "deepest wildcard wins", which is what the bounded walk implemented. A
    // test suite that only tested (1) would pass an implementation that found
    // the closest encloser correctly and then kept walking on a type miss.
    // `there_is_no_search_for_an_alternate_above_the_closest_encloser` is that
    // test, and it is the most load-bearing example in this section.
    // =======================================================================

    /// Scenario: A wildcard synthesises for a name whose closest encloser is its
    /// parent
    /// features/closest-encloser.feature:80
    ///
    /// The control for every negative below. A fix that simply stopped
    /// synthesising would pass `a_wildcard_does_not_apply_below_a_name_that_exists`
    /// and fail here, which is why the two are separate tests rather than two
    /// assertions in one.
    #[test]
    fn a_wildcard_synthesises_when_its_parent_is_the_closest_encloser() {
        let _watchdog = watchdog();
        let z = zone(vec![spec("*.dev", "A", &["203.0.113.50"])]);
        let Answer::Records(records) = z.lookup(&lower("x.dev.example.com."), RecordType::A) else {
            panic!(
                "`dev.example.com.` is the closest encloser of \
                 `x.dev.example.com.` and it holds a wildcard, so \
                 `*.dev.example.com.` is the source of synthesis (RFC 4592 \
                 §3.3.1)"
            );
        };
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].data, a("203.0.113.50"));
        assert_eq!(
            records[0].name,
            Name::from(lower("x.dev.example.com.")),
            "RFC 4592 §3.3.1: the synthesised record is owned by the QUERY name, \
             never by the wildcard's own name"
        );
    }

    /// Scenario: The carved-out name itself still answers
    /// features/closest-encloser.feature:130
    ///
    /// Scenario: The sibling of a carved-out name is still synthesised
    /// features/closest-encloser.feature:140
    ///
    /// The two anti-vacuity halves of VEGA-009's headline, in one fixture
    /// because they are one claim: the carve-out is respected and nothing else
    /// moved. Without the sibling half, "delete the wildcard" passes.
    #[test]
    fn a_carve_out_blocks_the_wildcard_without_disabling_it() {
        let _watchdog = watchdog();
        let z = zone(vec![
            spec("*.dev", "A", &["203.0.113.50"]),
            spec("deep.dev", "A", &["203.0.113.51"]),
        ]);

        let Answer::Records(carved) = z.lookup(&lower("deep.dev.example.com."), RecordType::A)
        else {
            panic!("the carved-out name must still serve its own record");
        };
        assert_eq!(carved[0].data, a("203.0.113.51"));

        let Answer::Records(sibling) = z.lookup(&lower("other.dev.example.com."), RecordType::A)
        else {
            panic!(
                "`other.dev.example.com.` does not exist, so its closest \
                 encloser is still `dev.example.com.` and the catch-all still \
                 applies to it. A fix that switched the wildcard off entirely \
                 would answer NXDOMAIN here"
            );
        };
        assert_eq!(sibling[0].data, a("203.0.113.50"));
    }

    /// Scenario: The nested carve-out holds two levels down
    /// features/closest-encloser.feature:151
    ///
    /// AC-3.2. Three names in a chain, so an implementation that compares only
    /// against the query's IMMEDIATE parent passes
    /// `a_wildcard_does_not_apply_below_a_name_that_exists` and fails here.
    #[test]
    fn the_nested_carve_out_blocks_the_wildcard_two_levels_down() {
        let _watchdog = watchdog();
        let z = zone(vec![
            spec("*.dev", "A", &["203.0.113.50"]),
            spec("b.dev", "A", &["203.0.113.51"]),
            spec("c.b.dev", "A", &["203.0.113.52"]),
        ]);
        assert_eq!(
            z.lookup(&lower("x.c.b.dev.example.com."), RecordType::A),
            Answer::NxDomain,
            "the closest encloser is `c.b.dev.example.com.`, so the only source \
             of synthesis is `*.c.b.dev.example.com.` and it does not exist"
        );
        let Answer::Records(records) = z.lookup(&lower("x.dev.example.com."), RecordType::A) else {
            panic!("the wildcard must still answer where nothing encloses more tightly");
        };
        assert_eq!(records[0].data, a("203.0.113.50"));
    }

    /// Scenario: An empty non-terminal is a closest encloser like any other name
    /// features/closest-encloser.feature:162
    ///
    /// The S2/S3 interaction, and the reason S3 could not have been built first.
    /// `b.deep.dev.example.com.` is configured NOWHERE — it exists only because
    /// `a.b.deep.dev` does (RFC 4592 §2.2.2). It is still a name that exists, so
    /// it is still the closest encloser, and `*.dev` must not reach past it.
    ///
    /// An implementation whose closest-encloser search consulted only DECLARED
    /// owner names answers `203.0.113.50` here, which is VEGA-009 reopened
    /// through the empty non-terminal that VEGA-006 introduced.
    #[test]
    fn an_empty_non_terminal_is_a_closest_encloser_like_any_other_name() {
        let _watchdog = watchdog();
        let z = zone(vec![
            spec("*.dev", "A", &["203.0.113.50"]),
            spec("a.b.deep.dev", "A", &["203.0.113.53"]),
        ]);

        // `deep.dev` and `b.deep.dev` are empty non-terminals, so both enclose.
        for name in ["x.b.deep.dev.example.com.", "x.deep.dev.example.com."] {
            assert_eq!(
                z.lookup(&lower(name), RecordType::A),
                Answer::NxDomain,
                "{name}'s closest encloser exists only as an empty non-terminal, \
                 and RFC 4592 §3.3.1 makes `*.<that name>` the only source of \
                 synthesis. Answering from `*.dev` reaches past a name that \
                 exists"
            );
        }

        // …and the wildcard still applies where nothing encloses more tightly.
        let Answer::Records(records) = z.lookup(&lower("x.dev.example.com."), RecordType::A) else {
            panic!("`dev.example.com.` still encloses `x.dev.example.com.`");
        };
        assert_eq!(records[0].data, a("203.0.113.50"));
    }

    /// Scenario: There is no search for an alternate wildcard above the closest
    /// encloser
    /// features/closest-encloser.feature:176
    ///
    /// RFC 4592 §3.3.1's last sentence, made observable — and the single most
    /// discriminating example in this section.
    ///
    /// The source of synthesis EXISTS here (`*.dev.example.com.`) and simply
    /// carries no A record. The bounded walk continues past it to the apex
    /// wildcard and serves 203.0.113.1. The closest-encloser rule stops, and RFC
    /// 1034 §4.3.2 step 3(c) makes that NODATA rather than a name error, because
    /// the `*` node exists (VEGA-083, preserved exactly).
    ///
    /// Every other test in this section is about WHICH name encloses. This one
    /// is about what happens after the right name has been found, so an
    /// implementation that computes the closest encloser correctly and then
    /// keeps walking on a type miss fails here and nowhere else.
    #[test]
    fn there_is_no_search_for_an_alternate_above_the_closest_encloser() {
        let _watchdog = watchdog();
        let z = zone(vec![
            spec("*", "A", &["203.0.113.1"]),
            spec("*.dev", "TXT", &["\"only text here\""]),
        ]);
        assert_eq!(
            z.lookup(&lower("x.dev.example.com."), RecordType::A),
            Answer::NoData,
            "`*.dev.example.com.` is the source of synthesis and holds no A \
             record. RFC 4592 §3.3.1: \"there is no search for an alternate\" — \
             the apex wildcard's 203.0.113.1 must not appear. RFC 1034 §4.3.2 \
             step 3(c) sets the name error only when the `*` node does not \
             exist, and it does, so this is NODATA and not NXDOMAIN"
        );

        // The type it does carry still answers from the same node, so this is a
        // statement about the search and not about the wildcard being broken.
        let Answer::Records(records) = z.lookup(&lower("x.dev.example.com."), RecordType::TXT)
        else {
            panic!("the source of synthesis still answers the type it carries");
        };
        assert_eq!(records.len(), 1);

        // …and the apex wildcard still answers names it genuinely encloses.
        let Answer::Records(apex) = z.lookup(&lower("elsewhere.example.com."), RecordType::A)
        else {
            panic!("the apex wildcard is the closest encloser of `elsewhere.example.com.`");
        };
        assert_eq!(apex[0].data, a("203.0.113.1"));
    }

    /// Scenario: A closest encloser computed one level short is visible in an
    /// answer
    /// features/closest-encloser.feature:265
    ///
    /// The mutant the ruling calls the most dangerous in the model (§4.3, §8),
    /// given a fixture shaped so it cannot hide.
    ///
    /// S2's first transition classifier accepted an ancestor-closure walk that
    /// stopped one level short, because the fixture it was checked against still
    /// produced every transition class with the shallower closure. The lesson is
    /// that an off-by-one in a depth search is only visible on a LADDER: two
    /// wildcards at adjacent depths with an existing name between them.
    ///
    ///   *.dev          answers x.dev
    ///   deep.dev       exists, holds no wildcard
    ///   x.deep.dev     exists, so it encloses q.x.deep.dev
    ///   *.x.deep.dev   answers q.x.deep.dev
    ///
    /// A search that is short by one answers `q.x.deep.dev` NXDOMAIN (it looks
    /// for `*.deep.dev`) *and* answers `q.deep.dev` from `*.dev` (it looks for
    /// `*.dev`). Two failures in opposite directions from one off-by-one, and
    /// either alone would be invisible without the ladder.
    #[test]
    fn a_closest_encloser_computed_one_level_short_is_visible_in_an_answer() {
        let _watchdog = watchdog();
        let z = zone(vec![
            spec("*.dev", "A", &["203.0.113.50"]),
            spec("deep.dev", "A", &["203.0.113.51"]),
            spec("x.deep.dev", "A", &["203.0.113.52"]),
            spec("*.x.deep.dev", "A", &["203.0.113.53"]),
        ]);

        let Answer::Records(deepest) = z.lookup(&lower("q.x.deep.dev.example.com."), RecordType::A)
        else {
            panic!(
                "the closest encloser of `q.x.deep.dev.example.com.` is \
                 `x.deep.dev.example.com.`, which holds a wildcard. A search \
                 that stopped one level short looked for `*.deep.dev` and found \
                 nothing"
            );
        };
        assert_eq!(deepest[0].data, a("203.0.113.53"));

        assert_eq!(
            z.lookup(&lower("q.deep.dev.example.com."), RecordType::A),
            Answer::NxDomain,
            "the closest encloser is `deep.dev.example.com.`, which holds no \
             wildcard. A search that stopped one level short looked for `*.dev` \
             and leaked 203.0.113.50 into the carve-out"
        );

        let Answer::Records(shallow) = z.lookup(&lower("q.dev.example.com."), RecordType::A) else {
            panic!("`dev.example.com.` still encloses `q.dev.example.com.`");
        };
        assert_eq!(shallow[0].data, a("203.0.113.50"));
    }

    /// Scenario: A name below a carve-out is NXDOMAIN for every type, not just
    /// the configured one
    /// features/closest-encloser.feature:255
    ///
    /// The rcode must not depend on the QTYPE. A dual-stack client asks AAAA
    /// alongside every A and a resolver asks ANY; if any of them answered
    /// NOERROR the zone would be reporting two different existence answers for
    /// one name, which is the shape of the VEGA-083 defect one level along.
    #[test]
    fn a_name_below_a_carve_out_is_nxdomain_for_every_type() {
        let _watchdog = watchdog();
        let z = zone(vec![
            spec("*.dev", "A", &["203.0.113.50"]),
            spec("deep.dev", "A", &["203.0.113.51"]),
        ]);
        for qtype in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::TXT,
            RecordType::MX,
            RecordType::ANY,
        ] {
            assert_eq!(
                z.lookup(&lower("a.deep.dev.example.com."), qtype),
                Answer::NxDomain,
                "{qtype} at `a.deep.dev.example.com.` must be a name error like \
                 every other type: the name does not exist and no source of \
                 synthesis covers it, and existence is a property of the name \
                 rather than of the question"
            );
        }
        assert!(
            !z.exists(&lower("a.deep.dev.example.com.")),
            "`Zone::exists` is the RFC 1034 §4.3.2 step 3(c) name-error \
             determination and it is the predicate the DNSSEC proof machinery \
             will read. A name no source of synthesis covers does not exist"
        );
    }

    /// Scenario: A zone holding only its apex encloses every name at the apex
    /// features/closest-encloser.feature:315
    ///
    /// The degenerate zone, and the floor of the search: every in-zone name
    /// descends from the apex and the apex is always a node, so the search
    /// always succeeds and never has to report "none". That is what lets it
    /// return a `NodeIdx` rather than an `Option`, which is what keeps `unwrap`
    /// off a packet-reachable path.
    #[test]
    fn a_zone_holding_only_its_apex_encloses_every_name_at_the_apex() {
        let _watchdog = watchdog();
        let z = zone(Vec::new());
        for name in [
            "anything.example.com.",
            "anything.deep.example.com.",
            "a.b.c.d.e.f.g.example.com.",
        ] {
            assert_eq!(
                z.lookup(&lower(name), RecordType::A),
                Answer::NxDomain,
                "{name}'s closest encloser is the apex and `*.example.com.` does \
                 not exist"
            );
        }
    }

    /// Scenario: The apex itself is never covered by its own wildcard
    /// features/closest-encloser.feature:351
    ///
    /// RFC 4592 §2.1.2: a wildcard's owner name never matches the name it is
    /// attached to. The apex is a node, so it is answered by the exact arm and
    /// the search never runs — but a search whose upper bound were the query's
    /// OWN depth rather than its parent's would make `*.example.com.` the source
    /// of synthesis for `example.com.` and serve the catch-all at the apex.
    #[test]
    fn the_apex_is_never_covered_by_its_own_wildcard() {
        let _watchdog = watchdog();
        let z = zone(vec![spec("*", "A", &["203.0.113.1"])]);
        assert_eq!(
            z.lookup(&lower("example.com."), RecordType::A),
            Answer::NoData,
            "the apex exists and holds no A record. Synthesising here would mean \
             the search's ceiling came from the query's own depth rather than \
             from its parent's (RFC 4592 §2.1.2)"
        );
    }

    /// Scenario: An asterisk in the query name gets no special processing
    /// features/closest-encloser.feature:372
    ///
    /// RFC 4592 §2.3, on the raw index space VEGA-065's ban exists to protect.
    /// `x.*.dev.example.com.` is an ordinary name whose leftmost labels happen to
    /// include an asterisk. Its closest encloser is `*.dev.example.com.` — which
    /// exists as an empty non-terminal because `*.*.dev` was configured — so the
    /// source of synthesis is `*.*.dev.example.com.` and it answers.
    ///
    /// `LowerName::num_labels()` discounts a leading asterisk while `trim_to` and
    /// the suffix hashes do not, so a depth computed with the wrong one indexes
    /// one label off for exactly these names. Deleting the depth bitmap does not
    /// delete that hazard: the closest-encloser search indexes the same space.
    #[test]
    fn an_asterisk_in_the_query_name_gets_no_special_processing() {
        let _watchdog = watchdog();
        let z = zone(vec![spec("*.*.dev", "A", &["203.0.113.60"])]);

        let Answer::Records(records) = z.lookup(&lower("x.*.dev.example.com."), RecordType::A)
        else {
            panic!(
                "`*.dev.example.com.` exists as an empty non-terminal, so it is \
                 the closest encloser of `x.*.dev.example.com.` and \
                 `*.*.dev.example.com.` is the source of synthesis"
            );
        };
        assert_eq!(records[0].data, a("203.0.113.60"));
        assert_eq!(records[0].name, Name::from(lower("x.*.dev.example.com.")));

        // The wildcard's own literal name is a node, answered by the exact arm.
        let Answer::Records(literal) = z.lookup(&lower("*.*.dev.example.com."), RecordType::A)
        else {
            panic!("a wildcard's own name is an ordinary node (RFC 4592 §2.1.1)");
        };
        assert_eq!(literal[0].data, a("203.0.113.60"));
    }

    /// Scenario: A 127-label attacker-chosen name below a carve-out is answered
    /// without excessive work
    /// features/closest-encloser.feature:414
    ///
    /// The deepest name the wire can carry — RFC 1035 §3.1 encodes a
    /// single-octet label in two octets and terminates with one, so
    /// `127 * 2 + 1 = 255` — aimed at the subtree the operator closed. Root
    /// origin, because that is the only way a 127-label name is in zone at all.
    ///
    /// This is the input that drives the closest-encloser search to its widest
    /// window: floor 0, ceiling 126. With `panic = "abort"` one index past the
    /// end of the suffix hash array is a full outage from one packet, so the
    /// whole thing runs under the process watchdog.
    #[test]
    fn a_query_at_the_protocol_ceiling_below_a_carve_out_is_nxdomain() {
        const CEILING: usize = 127;

        let _watchdog = watchdog();
        // The carve-out is `a.a.` and the query is 127 `a` labels, so every one
        // of the 124 intermediate ancestors is a name that does NOT exist and
        // the two that do sit at the very bottom of the search window. Single
        // -octet labels throughout, because 127 labels only fit inside RFC 1035
        // §2.3.4's 255 octets when every one of them is one octet long.
        let z = zone_with_origin(
            ".",
            vec![
                spec("*", "A", &["203.0.113.1"]),
                spec("a.a.", "A", &["203.0.113.2"]),
            ],
        );

        let deep = "a.".repeat(CEILING);
        let queried = lower(&deep);
        assert_eq!(
            Name::from(queried.clone()).iter().len(),
            CEILING,
            "the fixture must sit exactly at the decoder's ceiling, not near it"
        );

        assert_eq!(
            z.lookup(&queried, RecordType::A),
            Answer::NxDomain,
            "`a.a.` exists, so every name beneath it is enclosed by a name that \
             carries no wildcard. The apex `*` must not reach 127 labels down \
             into it"
        );

        // And the same wildcard still covers a name it genuinely encloses, so
        // this is not a test that passes because the zone answers nothing.
        let Answer::Records(covered) = z.lookup(&lower("nope.example.org."), RecordType::A) else {
            panic!("the root-origin apex wildcard encloses `nope.example.org.`");
        };
        assert_eq!(covered[0].data, a("203.0.113.1"));
    }

    /// Scenario: An attacker cannot reach into a carve-out by inventing labels
    /// beneath it
    /// features/closest-encloser.feature:402
    ///
    /// The security statement of VEGA-009, as a sweep rather than as one name.
    /// The operator carved `deep.dev` out of the catch-all; an attacker who can
    /// pick any name at all must not be able to make the server authoritatively
    /// assert an address inside it. One example name could pass by accident —
    /// forty invented ones at three different depths cannot.
    #[test]
    fn an_invented_name_beneath_a_carve_out_never_reaches_the_catch_all() {
        let _watchdog = watchdog();
        let z = zone(vec![
            spec("*.dev", "A", &["203.0.113.50"]),
            spec("deep.dev", "A", &["203.0.113.51"]),
        ]);
        for i in 0..40 {
            for name in [
                format!("n{i}.deep.dev.example.com."),
                format!("n{i}.x.deep.dev.example.com."),
                format!("x.n{i}.y.deep.dev.example.com."),
            ] {
                assert_eq!(
                    z.lookup(&lower(&name), RecordType::A),
                    Answer::NxDomain,
                    "{name} is inside a subtree the operator carved out of the \
                     catch-all. RFC 4592 §3.3.1 makes `*.<its closest encloser>` \
                     the only source of synthesis, and none of them exists"
                );
            }
        }
    }

    // ------------------------------------------------ the bitmap is subsumed

    /// Scenario: The zone carries no wildcard depth bitmap
    /// features/closest-encloser.feature:582
    ///
    /// Ancestor closure makes the populated node depths contiguous, so
    /// VEGA-065's `u128 wildcard_depths` is exactly
    /// `((1 << (max_depth + 1)) - 1) & !((1 << origin_depth) - 1)` and carries no
    /// information a `u8` pair does not. Sixteen bytes per zone become one.
    ///
    /// The far more important half is the probe count. VEGA-065's was
    /// `popcount(wildcard_depths ∩ window)` — operator-controlled, unbounded in
    /// practice, and the direct cause of VEGA-078's ~229 µs of CPU for one
    /// 276-byte packet. Leaving the field in place while adding the
    /// closest-encloser search would leave the walk one `if` away from coming
    /// back, so the field's absence is asserted rather than assumed.
    ///
    /// A source-level check because there is nothing observable to attach it to:
    /// the field is private, the struct is `pub(crate)` by §10.1, and its
    /// deletion changes no answer. That is precisely why it needs a guard.
    #[test]
    fn the_zone_carries_no_wildcard_depth_bitmap() {
        let needle = concat!("wildcard_", "depths");
        let offenders: Vec<(usize, &str)> = THIS_MODULE
            .lines()
            .enumerate()
            .filter(|(_, line)| line.contains(needle))
            .filter(|(_, line)| {
                // Prose recording why it went is the point; a field, a mask or a
                // walk is not.
                let trimmed = line.trim_start();
                !(trimmed.starts_with("//") || trimmed.starts_with('*'))
            })
            .map(|(i, line)| (i + 1, line.trim()))
            .collect();
        assert!(
            offenders.is_empty(),
            "`{needle}` is back in this module. Ancestor closure makes the \
             populated depths contiguous, so it carries no information the \
             origin/max depth pair does not — and the probe loop it feeds is \
             VEGA-078: one probe per configured wildcard depth, ~229 µs of CPU \
             for one 276-byte packet on a 120-depth zone. Found at {offenders:?}"
        );
    }

    /// Scenario: MAX_LABELS is still the arithmetic consequence of the 255-octet
    /// limit
    /// features/closest-encloser.feature:612
    ///
    /// The bitmap goes; the reasoning that made it correct must not. This is
    /// VEGA-065's constant and its derivation, re-asserted in the commit that
    /// deletes the structure it was originally sized for — because "we removed
    /// the thing that used 127" is exactly the diff in which 127 stops being
    /// checked.
    ///
    /// It is the deepest index the suffix hash array will ever see, and under
    /// `panic = "abort"` one past it is a full outage from one packet.
    #[test]
    fn the_label_ceiling_survives_the_deletion_of_the_depth_bitmap() {
        // RFC 1035 §3.1: a single-octet label costs two octets on the wire and
        // the name is terminated by one more, so 2n + 1 <= 255 gives n = 127.
        // Written out rather than as `MAX_LABELS` so this is a derivation and
        // not a tautology.
        const CEILING: usize = (255 - 1) / 2;
        assert_eq!(
            MAX_LABELS, CEILING,
            "MAX_LABELS is the arithmetic consequence of RFC 1035 §2.3.4 and \
             §3.1, not a tuning knob. It sizes the suffix hash array the \
             closest-encloser search reads on every negative query"
        );

        // And `label_count` still counts a leading asterisk as a label, which is
        // the index space `trim_to` and the suffix hashes share.
        assert_eq!(label_count(&lower("*.dev.example.com.")), 4);
        assert_eq!(label_count(&lower("*.*.dev.example.com.")), 5);
        assert_eq!(label_count(&lower("a.*.dev.example.com.")), 5);
    }

    /// Scenario: A wildcard does not synthesise at a wildcard name that exists
    /// features/closest-encloser.feature:193
    ///
    /// **VEGA-098**, as a named example rather than as a seed.
    ///
    /// Found by `the_wildcard_walk_agrees_with_a_naive_base_name_walk` on `main`
    /// at `bd4b397`, in a clean worktree, with the seed in neither
    /// `proptest-regressions` file — so proptest rediscovers it fresh on some
    /// runs and not on others, and CI had been passing on luck. A minimal
    /// committed example that fails today and passes after S3 is worth more than
    /// a generator that finds it one run in ten.
    ///
    /// ```text
    ///   zone:  ["* TXT", "*.*.dev A"]
    ///   query: *.dev.example.com. TXT
    ///   got    Records([*.dev.example.com. TXT "hello"])
    ///   want   NoData
    /// ```
    ///
    /// # The mechanism, because it is not the obvious one
    ///
    /// S2 made `*.dev.example.com.` an **empty non-terminal**: `*.*.dev` is
    /// configured beneath it, and ancestor closure materialises every strict
    /// ancestor whatever its leftmost label happens to be (RFC 4592 §2.1.1 makes
    /// a wildcard a property of the NAME, never of how the node came to exist).
    ///
    /// A name that exists must stop synthesis outright — RFC 4592 §2.2.2 — so
    /// the answer is NODATA. The apex `* TXT` is applied to it anyway, because
    /// the exact-match probe deliberately **excludes wildcard nodes**: the map
    /// model S1 replaced held wildcards in neither `exact` nor `names`, and
    /// preserving that was an S1 fidelity decision with the note that "that
    /// exclusion is what S2 and S3 remove, with a ruling".
    ///
    /// **This is the ruling, and this is the removal.** It is the one part of S3
    /// that is not about the closest encloser at all: the closest-encloser search
    /// never runs here, because the name is a node and step 3.a answers it. So
    /// an implementation that fixed only the search would still fail this, which
    /// is why it is a named test and not left to the differential.
    ///
    /// S2 did not introduce the defect. It made VEGA-009 reachable in a shape the
    /// oracle can see, and the oracle was right to fail.
    #[test]
    fn a_wildcard_does_not_synthesise_at_a_wildcard_name_that_exists() {
        let _watchdog = watchdog();
        let z = zone(vec![
            spec("*", "TXT", &["\"hello\""]),
            spec("*.*.dev", "A", &["203.0.113.60"]),
        ]);

        assert_eq!(
            z.lookup(&lower("*.dev.example.com."), RecordType::TXT),
            Answer::NoData,
            "`*.dev.example.com.` exists — `*.*.dev.example.com.` is configured \
             beneath it, so ancestor closure materialises it (RFC 4592 §2.1.1, \
             §2.2.2). A name that exists stops synthesis, so the apex `* TXT` \
             must not be applied to it. VEGA-098"
        );

        // The other half of the same contract, and the reason this cannot be
        // fixed by simply refusing to answer wildcard-shaped names: the node
        // that DOES carry records still answers at its own literal name (RFC
        // 4592 §2.3 — an asterisk in a QNAME gets no special processing).
        let Answer::Records(records) = z.lookup(&lower("*.*.dev.example.com."), RecordType::A)
        else {
            panic!(
                "the configured wildcard must still answer a query for its own \
                 literal name; excluding wildcard nodes from the exact probe is \
                 what this test exists to remove, not to widen"
            );
        };
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].data, a("203.0.113.60"));
        assert_eq!(records[0].name, Name::from(lower("*.*.dev.example.com.")));

        // And the empty non-terminal still covers the names below it, because a
        // wildcard that is an empty non-terminal is still a source of synthesis
        // carrying no RRset (RFC 1034 §4.3.2 step 3(c), S2's T2 class).
        assert_eq!(
            z.lookup(&lower("x.dev.example.com."), RecordType::TXT),
            Answer::NoData,
            "`*.dev.example.com.` is the source of synthesis for \
             `x.dev.example.com.` and carries no TXT, so the name error is \
             forbidden — and the apex `* TXT` must not be reached either, \
             because RFC 4592 §3.3.1 permits no search for an alternate"
        );
    }
}
