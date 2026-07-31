//! The RFC 4034 §6.1 canonical name order, as a byte key you can `memcmp`.
//!
//! This module owns one thing: turning a domain name into a byte string whose
//! `Ord` **is** canonical DNS name order. Nothing else about names lives here —
//! label counting, the suffix hash and the arena are `zone`'s.
//!
//! # Why a key at all
//!
//! `LowerName: Ord` already implements RFC 4034 §6.1: hickory's `cmp_labels`
//! zips reversed label iterators, compares octets case-insensitively, then
//! compares label lengths, then label counts. Correctness rests entirely on
//! that, and this key is checked against it rather than against a reading of
//! the RFC. What `Ord` cannot do is sort a hundred thousand names on every
//! reload: each comparison is O(labels × octets) through two iterators, and the
//! zone arena is sorted into canonical order from its first commit
//! (VEGA-032 §7.2). Sorting `memcmp`-able keys is what makes that affordable.
//!
//! # The encoding, and why the escape is not decoration
//!
//! One label at a time, **from the rightmost**, lowercased, with `0x00` written
//! as `0x00 0x01` and every label terminated by `0x00 0x00`.
//!
//! Rightmost-first because §6.1 orders names by comparing labels outwards from
//! the root. The escape because RFC 2181 §11 permits *any* octet in a label,
//! including NUL, and a plain `0x00` terminator is then not order-preserving:
//! `p.a.root.` against `q.a\000.root.` sorts `Less` under `Ord` and `Greater`
//! under a plain terminator. With the escape the separator (`00 00`) sorts below
//! every escaped octet (`00 01` for NUL, `>= 01` for everything else), so byte
//! order and canonical order coincide.
//!
//! # Tests
//!
//! Deliberately none in this file. `tests/canonical_order.rs` compiles this
//! module by `#[path]` — the same way every test in this tree shares
//! `src/testutil.rs` — because the key is `pub(crate)` and an integration test
//! cannot otherwise reach it. A `#[cfg(test)] mod tests` here would be compiled
//! and run twice, once in each binary, which is how one of the two copies stops
//! being noticed.

use hickory_proto::rr::LowerName;

/// Ends a label. Two octets, and both zero, so it sorts below every escaped
/// content octet — which is what makes byte order equal canonical order.
const LABEL_END: [u8; 2] = [0x00, 0x00];

/// A NUL octet appearing *inside* a label. `0x00 0x01` sorts above
/// [`LABEL_END`] and below every other octet, which is exactly where a NUL
/// belongs (RFC 2181 §11 permits it; RFC 4034 §6.1 compares it as data).
const ESCAPED_NUL: [u8; 2] = [0x00, 0x01];

/// Append the canonical sort key of `name` to `key`: a byte string whose `Ord`
/// is RFC 4034 §6.1 canonical DNS name order.
///
/// Equal names produce equal keys, so two spellings of one owner name — which
/// §6.1 compares case-insensitively — cannot become two nodes in the arena.
///
/// Appending into a caller-owned buffer rather than returning a `Vec` is the
/// whole point: a build sorting 100,000 names puts every key in **one** scratch
/// buffer and sorts a permutation of indices, so the sort costs three
/// allocations instead of one per name. The buffer is dropped once the
/// permutation has been applied; no key is ever stored.
pub(crate) fn write_canonical_sort_key(name: &LowerName, key: &mut Vec<u8>) {
    // `LowerName` derefs to `Name`, whose `LabelIter` is `DoubleEndedIterator`,
    // so the reverse walk costs no allocation and no intermediate name.
    for label in name.iter().rev() {
        for octet in label {
            let octet = octet.to_ascii_lowercase();
            if octet == 0x00 {
                key.extend_from_slice(&ESCAPED_NUL);
            } else {
                key.push(octet);
            }
        }
        key.extend_from_slice(&LABEL_END);
    }
}
