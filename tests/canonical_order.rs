//! VEGA-032 **S0** — the canonical sort key, and the ban that guards the index
//! space it is computed in.
//!
//! Spec: `features/zone-data-model.feature`, sections "S0 — CANONICAL ORDER"
//! and "S0 — THE SUFFIX HASH".
//! Ruling: `.claude/backlog/decisions/VEGA-032-zone-data-model.md` §7.2, §13 AC-0.
//!
//! # Why this file exists before the code does
//!
//! The arena is physically sorted into RFC 4034 §6.1 canonical DNS name order
//! from the first commit, and **nothing consumes that order yet**. Its failure
//! mode is therefore invisible until DNSSEC lands, at which point a mis-ordered
//! arena means the NSEC chain does not close and every validating resolver
//! SERVFAILs the whole zone. There is no answer to observe, so the ordering is
//! pinned against the two things that cannot be wrong in the same direction as
//! our implementation: the RFC's own printed example vector, and
//! `LowerName: Ord`, whose `cmp_labels` *is* §6.1.
//!
//! # THE ONE LINE S0 CHANGES — and the only one
//!
//! [`key_under_test`] is a transcription of the key the ruling mandates. Until
//! S0 lands there is no `canonical_sort_key` to call, so the transcription is
//! what these assertions run against, and they are already load-bearing: they
//! are what says the *design* is right, and they reject a plain `0x00`
//! terminator today (see
//! `a_nul_octet_in_a_label_inverts_a_plain_terminator_key_and_not_the_escaped_one`).
//!
//! **S0's commit repoints [`key_under_test`] at the real function and changes
//! nothing else in this file.** Rewriting an assertion to match an
//! implementation is how a differential stops testing anything; if the real key
//! disagrees with anything below, the key is wrong.

use std::cmp::Ordering;

use hickory_proto::rr::{LowerName, Name};
use proptest::prelude::*;

/// The real key, pulled in by path rather than through a `pub` export.
///
/// `canonical_sort_key` is `pub(crate)` by the ruling's §10.1 — a `pub` API with
/// no caller outside the crate is the thing §12 fences off — so this test
/// compiles the module's own source, exactly as every test in this tree already
/// does with `src/testutil.rs`. Compiling the source is strictly stronger than
/// calling an export: there is no second copy to drift.
#[path = "../src/canonical.rs"]
mod canonical;

/// Highest label count any DNS name can carry.
///
/// RFC 1035 §2.3.4 caps a name at 255 octets and §3.1 spends a length octet
/// plus at least one content octet per label plus one terminator, so
/// `2n + 1 <= 255`. Measured against hickory-proto 0.26.1: 127 single-octet
/// labels parse, 128 are rejected with `DomainNameTooLong(257)`. Pinned by
/// `src/zone.rs::a_name_one_label_past_the_ceiling_is_rejected_before_it_reaches_the_zone`.
const MAX_LABELS: usize = 127;

// ---------------------------------------------------------------------------
// The key under test, and the variant that must NOT be it
// ---------------------------------------------------------------------------

/// The canonical sort key, as VEGA-032 §7.2 mandates it.
///
/// Per label, from the **rightmost**, lowercased, with `0x00` escaped as
/// `0x00 0x01` and labels separated by `0x00 0x00`.
///
/// Rightmost-first because RFC 4034 §6.1 orders names by comparing labels from
/// the root outwards. The escape because RFC 2181 §11 permits any octet in a
/// label, so a plain terminator is not order-preserving. With the escape, the
/// separator (`00 00`) sorts below every escaped octet (`00 01` for NUL, `>= 01`
/// otherwise), and byte order equals canonical order.
///
/// # S0 replaces this body with a call to the real key. Nothing else.
fn key_under_test(name: &LowerName) -> Vec<u8> {
    let mut key = Vec::new();
    canonical::write_canonical_sort_key(name, &mut key);
    // The transcription below is the ruling's §7.2 encoding, written down before
    // any code existed. Diffing the real key against it here — octet for octet,
    // not merely "sorts the same way" — is the use the transcription was kept
    // for, and it makes every assertion in this file a check on the encoding as
    // well as on the order.
    assert_eq!(
        key,
        escaped_key(name),
        "the real canonical key does not encode {name} the way VEGA-032 §7.2 \
         mandates. Two encodings can agree on every order this file happens to \
         check and still differ on one nobody generated"
    );
    key
}

/// The mandated key, kept separately from [`key_under_test`] so that after S0
/// repoints the latter, this stays as the specification of what was asked for
/// and the two can be diffed against each other.
fn escaped_key(name: &LowerName) -> Vec<u8> {
    let name = Name::from(name.clone());
    let labels: Vec<Vec<u8>> = name.iter().map(<[u8]>::to_vec).collect();
    // Two octets per input octet in the worst case, plus a two-octet separator.
    let mut key = Vec::with_capacity(name.len() * 2 + 2);
    for label in labels.iter().rev() {
        for byte in label {
            let byte = byte.to_ascii_lowercase();
            if byte == 0x00 {
                key.extend_from_slice(&[0x00, 0x01]);
            } else {
                key.push(byte);
            }
        }
        key.extend_from_slice(&[0x00, 0x00]);
    }
    key
}

/// The obvious wrong key: one `0x00` terminator per label, no escape.
///
/// Kept in the tree, and asserted to be **wrong**, because it is what anybody
/// simplifying [`escaped_key`] would arrive at, and because the input that
/// distinguishes them — a label containing a NUL octet — appears in no zone
/// anybody writes by hand and in every zone generated from user input.
fn plain_terminator_key(name: &LowerName) -> Vec<u8> {
    let name = Name::from(name.clone());
    let labels: Vec<Vec<u8>> = name.iter().map(<[u8]>::to_vec).collect();
    let mut key = Vec::with_capacity(name.len() + 1);
    for label in labels.iter().rev() {
        key.extend(label.iter().map(u8::to_ascii_lowercase));
        key.push(0x00);
    }
    key
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Build a name from raw label octets. Panics only on fixtures this file
/// controls, never on anything derived from a packet.
fn name_of(labels: &[&[u8]]) -> LowerName {
    let owned: Vec<Vec<u8>> = labels.iter().map(|l| (*l).to_vec()).collect();
    let mut name = Name::from_labels(owned).expect("fixture labels are within RFC 1035 limits");
    name.set_fqdn(true);
    LowerName::from(name)
}

fn parsed(text: &str) -> LowerName {
    let mut name: Name = text.parse().expect("fixture name parses");
    name.set_fqdn(true);
    LowerName::from(name)
}

/// RFC 4034 §6.1's own example vector, **in the order the RFC prints it**.
///
/// Quoted from the RFC:
///
/// ```text
///     example
///     a.example
///     yljkjljk.a.example
///     Z.a.example
///     zABC.a.EXAMPLE
///     z.example
///     \001.z.example
///     *.z.example
///     \200.z.example
/// ```
///
/// `\001`, `*` (0x2a) and `\200` (0x80) share a parent and are ordered by that
/// one octet, which is what makes the vector a test of the *key* and not of the
/// label splitting. hickory's `FromStr` rejects `\001` as a malformed label, so
/// the octets go in through `Name::from_labels` rather than through a parse.
fn rfc_4034_example_vector() -> Vec<LowerName> {
    vec![
        name_of(&[b"example"]),
        name_of(&[b"a", b"example"]),
        name_of(&[b"yljkjljk", b"a", b"example"]),
        name_of(&[b"Z", b"a", b"example"]),
        name_of(&[b"zABC", b"a", b"EXAMPLE"]),
        name_of(&[b"z", b"example"]),
        name_of(&[&[0x01], b"z", b"example"]),
        name_of(&[b"*", b"z", b"example"]),
        name_of(&[&[0x80], b"z", b"example"]),
    ]
}

fn sorted_by_key(mut names: Vec<LowerName>) -> Vec<LowerName> {
    names.sort_by_cached_key(key_under_test);
    names
}

// ---------------------------------------------------------------------------
// AC-0.2 — the RFC's own answer
// ---------------------------------------------------------------------------

/// Scenario: RFC 4034 §6.1's own nine-name example sorts into the order the RFC prints
/// features/zone-data-model.feature:84
///
/// Shuffled deterministically before sorting — a vector fed in already sorted
/// is passed by a key function that returns a constant.
#[test]
fn the_rfc_4034_example_vector_sorts_into_the_order_the_rfc_prints() {
    let expected = rfc_4034_example_vector();

    // A fixed, non-identity permutation: reversed, then rotated, so no adjacent
    // pair arrives in its final position.
    let mut shuffled: Vec<LowerName> = expected.iter().rev().cloned().collect();
    shuffled.rotate_left(4);
    assert_ne!(
        shuffled, expected,
        "the input must not already be in the answer's order, or a constant key passes"
    );

    let got = sorted_by_key(shuffled);
    let render = |v: &[LowerName]| v.iter().map(ToString::to_string).collect::<Vec<_>>();
    assert_eq!(
        render(&got),
        render(&expected),
        "the canonical sort key does not reproduce RFC 4034 §6.1's printed order. \
         Nothing consumes this ordering yet, which is exactly why it is pinned \
         now: the first consumer is the NSEC chain, and a chain that does not \
         close SERVFAILs the entire zone at every validating resolver"
    );
}

// ---------------------------------------------------------------------------
// AC-0.1 — the key equals LowerName: Ord, for every input
// ---------------------------------------------------------------------------

/// A label of arbitrary octets, including 0x00 and 0xff.
///
/// One to six octets: short enough that any six of them stay inside RFC 1035
/// §2.3.4's 255-octet name, so every generated pair is **constructed** rather
/// than generated-and-filtered. Filtering here would silently stop exercising
/// the deep cases as the generator drifted.
fn octet_label() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(0u8..=255, 1..=6)
}

/// A label from a small alphabet that collides often, so generated names
/// actually share prefixes and the comparison reaches past the first octet.
fn colliding_label() -> impl Strategy<Value = Vec<u8>> {
    prop::sample::select(vec![
        b"a".to_vec(),
        b"A".to_vec(),
        b"ab".to_vec(),
        b"a\x00".to_vec(),
        b"a\xff".to_vec(),
        b"*".to_vec(),
        b"example".to_vec(),
        vec![0x00],
    ])
}

fn generated_name() -> impl Strategy<Value = LowerName> {
    prop_oneof![
        prop::collection::vec(octet_label(), 1..=6),
        prop::collection::vec(colliding_label(), 1..=6),
    ]
    .prop_map(|labels| {
        let mut name = Name::from_labels(labels).expect("bounded labels build a legal name");
        name.set_fqdn(true);
        LowerName::from(name)
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// INVARIANT (AC-0.1): sorting by the byte key is sorting by
    /// `LowerName: Ord`, for every pair of names, including equality.
    ///
    /// Scenario: The canonical sort key orders every name exactly as LowerName Ord does
    /// features/zone-data-model.feature:95
    ///
    /// The key exists only because `LowerName: Ord` is too slow to sort 100,000
    /// names with on every reload — each comparison is O(labels × octets)
    /// through two iterators. Correctness still rests entirely on `Ord`, so the
    /// key has to be *equal* to it and not merely close. The generator supplies
    /// what hand-written cases do not: NUL and 0xff octets, mixed case, names
    /// that are proper suffixes of each other, and labels drawn from an
    /// alphabet that collides.
    #[test]
    fn the_canonical_key_orders_every_name_exactly_as_lowername_ord_does(
        left in generated_name(),
        right in generated_name(),
    ) {
        let by_key = key_under_test(&left).cmp(&key_under_test(&right));
        let by_ord = left.cmp(&right);
        prop_assert_eq!(
            by_key,
            by_ord,
            "canonical key and LowerName: Ord disagree on {:?} vs {:?} \
             (key said {:?}, Ord said {:?}). The arena is sorted by the key and \
             its correctness is claimed from Ord; where they differ, the arena \
             is not in RFC 4034 §6.1 order",
            left.to_string(),
            right.to_string(),
            by_key,
            by_ord
        );
    }
}

// ---------------------------------------------------------------------------
// AC-0.3 — the NUL escape, and the proof that it is load-bearing
// ---------------------------------------------------------------------------

/// Scenario: A label containing a NUL octet sorts by the escaped key, and a plain terminator inverts it
/// features/zone-data-model.feature:107
///
/// The counterexample the ruling names, measured rather than argued. Against
/// hickory-proto 0.26.1:
///
/// ```text
/// LowerName: Ord        p.a.root. vs q.a\000.root.  ->  Less
/// escaped key           [.. 61 00 00 70 00 00] vs [.. 61 00 01 00 00 71 00 00]  ->  Less
/// plain 0x00 terminator [.. 61 00 70 00]      vs [.. 61 00 00 71 00]           ->  Greater
/// ```
///
/// The two halves of this test are not redundant. The first says the escape is
/// **correct**; the second says it is **necessary**, and it is the second that
/// stops the escape being deleted as noise by someone who has never seen a NUL
/// in a label. `Name::from_labels` accepts one, so this is reachable.
#[test]
fn a_nul_octet_in_a_label_inverts_a_plain_terminator_key_and_not_the_escaped_one() {
    let p_a = name_of(&[b"p", b"a", b"root"]);
    let q_a_nul = name_of(&[b"q", b"a\x00", b"root"]);

    assert_eq!(
        p_a.cmp(&q_a_nul),
        Ordering::Less,
        "RFC 4034 §6.1 compares the rightmost labels first: root == root, then \
         \"a\" against \"a\\0\", where \"a\" is the shorter and sorts first"
    );

    assert_eq!(
        key_under_test(&p_a).cmp(&key_under_test(&q_a_nul)),
        Ordering::Less,
        "the canonical key disagrees with LowerName: Ord on a label containing a \
         NUL octet, which RFC 2181 §11 explicitly permits"
    );

    assert_eq!(
        plain_terminator_key(&p_a).cmp(&plain_terminator_key(&q_a_nul)),
        Ordering::Greater,
        "a plain 0x00 terminator was expected to INVERT this pair, and did not. \
         Either the fixture stopped containing a NUL octet or the transcription \
         drifted — and if the plain key is order-preserving after all, the \
         escape in the real key is untested from here on"
    );
}

// ---------------------------------------------------------------------------
// AC-0.1, named cases the generator would reach only by luck
// ---------------------------------------------------------------------------

/// Scenario: Two names differing only in case are equal under the canonical key
/// features/zone-data-model.feature:119
///
/// RFC 4034 §6.1 compares octets case-insensitively and RFC 4343 says the same
/// about matching. Two spellings of one owner name must produce one key, or the
/// build materialises the same node twice and the index round trip stops
/// holding.
#[test]
fn two_names_differing_only_in_case_compare_equal_under_the_canonical_key() {
    let upper = name_of(&[b"Z", b"a", b"EXAMPLE"]);
    let lower = name_of(&[b"z", b"a", b"example"]);

    assert_eq!(upper.cmp(&lower), Ordering::Equal, "LowerName: Ord");
    assert_eq!(
        key_under_test(&upper),
        key_under_test(&lower),
        "the canonical key is case-sensitive. Two spellings of one owner name \
         would become two nodes in the arena, and the deeper one would be \
         unreachable through the index"
    );
}

/// Scenario: A name sorts before every name that has it as a proper suffix
/// features/zone-data-model.feature:128
///
/// Ancestors precede descendants. Everything the arena does with indices reads
/// this as given: node 0 is the apex, `cut` propagates in one forward pass
/// because a parent is always already visited, and the NSEC next owner of node
/// `i` is node `i+1`. A key that got it backwards changes no answer at S1 and
/// breaks all three later.
#[test]
fn a_name_sorts_before_every_name_that_has_it_as_a_proper_suffix() {
    let names = vec![
        name_of(&[b"b", b"a", b"example"]),
        name_of(&[b"example"]),
        name_of(&[b"a", b"example"]),
    ];
    let sorted = sorted_by_key(names);
    let rendered: Vec<String> = sorted.iter().map(ToString::to_string).collect();
    assert_eq!(
        rendered,
        vec!["example.", "a.example.", "b.a.example."],
        "canonical order must put every ancestor before its descendants; the \
         arena's forward passes depend on it and none of them would notice"
    );
}

/// Scenario: The root name is the smallest key there is
/// features/zone-data-model.feature:138
///
/// The empty case, and it is reachable: `origin = "."` is an accepted
/// configuration, so in some zones the root really is node 0.
#[test]
fn the_root_name_is_the_smallest_key_there_is() {
    let root = parsed(".");
    assert!(key_under_test(&root).is_empty(), "the root has no labels");

    for other in [
        name_of(&[b"example"]),
        name_of(&[&[0x00]]),
        name_of(&[b"a", b"example"]),
    ] {
        assert_eq!(
            key_under_test(&root).cmp(&key_under_test(&other)),
            Ordering::Less,
            "the root must sort before {other}, as it does under LowerName: Ord"
        );
        assert_eq!(
            root.cmp(&other),
            Ordering::Less,
            "LowerName: Ord on {other}"
        );
    }
}

/// Scenario: A label made entirely of 0xff octets is ordered as data, not as a delimiter
/// features/zone-data-model.feature:146
///
/// The far end of the octet range from the NUL case. A key that treated any
/// octet as structural rather than as content would misplace it, and RFC 2181
/// §11 permits it.
#[test]
fn a_label_of_high_octets_is_ordered_as_data_not_as_a_delimiter() {
    let high = name_of(&[&[0xff, 0xff, 0xff], b"example"]);
    let ordinary = name_of(&[b"zzz", b"example"]);
    let nul = name_of(&[&[0x00], b"example"]);

    for (left, right) in [(&high, &ordinary), (&nul, &high), (&nul, &ordinary)] {
        assert_eq!(
            key_under_test(left).cmp(&key_under_test(right)),
            left.cmp(right),
            "canonical key and LowerName: Ord disagree on {left} vs {right}"
        );
    }
}

/// Scenario: Names chosen to collide under a naive key still sort correctly
/// features/zone-data-model.feature:155
///
/// An operator picks the names in a zone, but a zone file can be generated from
/// user-supplied input — a hosting control panel, a dynamic-DNS front end. A
/// family of names agreeing on every label but one boundary octet is what
/// breaks a hand-rolled key, and it is the family somebody who wanted to break
/// one would submit.
#[test]
fn names_that_collide_on_every_label_but_one_boundary_octet_still_sort_correctly() {
    let mut family: Vec<LowerName> = Vec::new();
    for boundary in [0x00u8, 0x01, 0x2a, 0x2e, 0x5c, 0x7f, 0x80, 0xfe, 0xff] {
        family.push(name_of(&[&[b'a', boundary], b"a", b"example"]));
        family.push(name_of(&[&[boundary], b"a", b"example"]));
        family.push(name_of(&[b"a", &[boundary], b"example"]));
    }

    let by_key = sorted_by_key(family.clone());
    let by_ord = {
        let mut v = family;
        v.sort();
        v
    };
    assert_eq!(
        by_key.iter().map(ToString::to_string).collect::<Vec<_>>(),
        by_ord.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "sorting a family of near-identical names by the canonical key does not \
         match sorting them by LowerName: Ord"
    );
}

// ---------------------------------------------------------------------------
// AC-0.5 — the ban follows the code, rather than naming one file
// ---------------------------------------------------------------------------

/// Scenario: The banned label-counting function stays out of every module that indexes by depth
/// features/zone-data-model.feature:233
///
/// `LowerName::num_labels()` is documented as counting labels *discounting* a
/// leading `*`; `Name::trim_to` and the suffix hash index the raw count. Mixing
/// the two shifts every probe one label off for any name whose leftmost label is
/// an asterisk — four silent wrong answers on the authoritative path, which is
/// VEGA-065's entire finding. `src/zone.rs` already guards itself with an
/// `include_str!` of its own text.
///
/// This one guards the *rule* rather than the file, because S0 moves the label
/// arithmetic into new code and a guard that names `src/zone.rs` would follow
/// none of it. The scan finds every module that indexes a name by label depth —
/// by the markers below — and holds each of them to the ban.
///
/// `src/handler.rs` uses `num_labels` legitimately, for a greeting string, and
/// indexes nothing by depth; it is out of scope here by construction, not by an
/// exemption list. (It does then `iter().take()` on the same count, which is the
/// same index-space mix one level down. Out of scope for VEGA-032 and worth its
/// own issue.)
#[test]
fn the_banned_label_counting_function_is_not_used_in_any_module_that_indexes_by_depth() {
    // A module "indexes a name by label depth" if it names any of these. The
    // list is deliberately wider than today's code so that S0's new primitives
    // are covered the moment they are written, whatever file they land in.
    const MARKERS: [&str; 5] = [
        "trim_to(",
        "fn label_count",
        "MAX_LABELS",
        "SuffixHashes",
        "suffix_hash",
    ];
    let needle = concat!("num_", "labels");

    let mut scanned: Vec<String> = Vec::new();
    let mut offenders: Vec<String> = Vec::new();

    for path in rust_sources("src") {
        let source = std::fs::read_to_string(&path).expect("source file is readable");
        if !MARKERS.iter().any(|m| source.contains(m)) {
            continue;
        }
        scanned.push(path.display().to_string());
        for (i, line) in source.lines().enumerate() {
            let trimmed = line.trim_start();
            // Comments explaining the ban are the point; code is not.
            if trimmed.starts_with("//") || trimmed.starts_with('*') {
                continue;
            }
            if line.contains(needle) {
                offenders.push(format!("{}:{}: {}", path.display(), i + 1, line.trim()));
            }
        }
    }

    // Without this, deleting `trim_to` at S1 and renaming the constant would
    // make the scan cover no files at all and pass vacuously — which is the
    // failure mode of every source-text guard.
    assert!(
        !scanned.is_empty(),
        "no module in src/ names any of {MARKERS:?}, so this guard scanned \
         nothing and would pass against any code at all. The markers have \
         drifted away from the code that indexes names by label depth"
    );
    assert!(
        offenders.is_empty(),
        "`{needle}` counts a leading asterisk differently from `trim_to` and \
         from the suffix hash, which index the raw label count. Mixing the two \
         index spaces is four silent wrong answers on the authoritative path \
         (VEGA-065). Use `label_count`. Scanned {scanned:?}, found {offenders:?}"
    );
}

/// Every `.rs` file under `dir`, recursively. Small enough to inline rather than
/// share: `tests/single_gate.rs` has its own, and coupling two source-text
/// guards to one walker means a change to either can silently blind the other.
fn rust_sources(dir: &str) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(dir)];
    while let Some(path) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

// ---------------------------------------------------------------------------
// The ceiling every label-indexed array in the model is sized from
// ---------------------------------------------------------------------------

/// Scenario: A name one label past the ceiling never reaches the zone at all
/// features/zone-data-model.feature:214
///
/// `MAX_LABELS` is not a tuning knob and the `[u64; MAX_LABELS + 1]` array the
/// suffix hash writes into is indexed by a label count taken from a name an
/// attacker chose. With `panic = "abort"` one out-of-range index is a full
/// outage from one packet, so the claim "hickory cannot hand us a 128-label
/// name" is pinned here rather than assumed — a dependency bump is exactly how
/// it would stop being true.
///
/// This duplicates no existing test: `src/zone.rs` pins that a 127-label name
/// *is* answered; nothing pinned that 128 is refused.
#[test]
fn a_name_one_label_past_the_ceiling_is_rejected_before_it_reaches_the_zone() {
    let at_ceiling: Result<Name, _> = "a.".repeat(MAX_LABELS).parse();
    let at_ceiling = at_ceiling.expect("127 single-octet labels is 255 octets exactly");
    assert_eq!(
        at_ceiling.iter().len(),
        MAX_LABELS,
        "the fixture must sit exactly at the ceiling, not near it"
    );

    let over: Result<Name, _> = "a.".repeat(MAX_LABELS + 1).parse();
    assert!(
        over.is_err(),
        "hickory accepted a {}-label name. Every label-indexed array in the zone \
         model is sized from {MAX_LABELS}, so this is now an out-of-bounds index \
         reachable from one packet",
        MAX_LABELS + 1
    );
}
