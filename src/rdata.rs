//! The one gate between operator-supplied presentation-format text and
//! hickory's zone-file lexer.
//!
//! `RData::try_from_str` is not total. Its lexer carries `assert!(i < 4095)`
//! over the characters it consumes for a single token (hickory-proto
//! `serialize/txt/zone_lex.rs`), so a long enough value panics where the
//! signature promises an `Err`. With `panic = "abort"` in the release profile
//! that is not a rejected record but a dead process — and on the reload path, a
//! process that `Restart=always` brings back to the same config and kills again.
//!
//! Two places in this crate hand operator text to that parser: `Zone::insert_spec`
//! (config to zone, so startup *and* every reload) and `editor::validate_value`
//! (`vega record add`). The bound was first fixed in the zone only, and the
//! editor kept aborting — the same bug with a different stack trace. So the
//! bound and the check live here, in one function, and nothing else in the crate
//! calls `try_from_str` at all — not even a test fixture, because a rule with an
//! exception is a rule nobody can check mechanically.
//!
//! That claim is not on trust. `tests/single_gate.rs` reads `src/**/*.rs` and
//! fails if any other module names the parser; it was added when the claim had
//! already gone stale, `zone.rs` having kept its own call behind a duplicate of
//! [`MAX_VALUE_CHARS`] (VEGA-089's review). The `const _` assertion below is the
//! same idea one layer down: a guard above the assertion it guards is checked by
//! the compiler, not by a reader.

use hickory_proto::{
    rr::{RData, RecordType},
    serialize::txt::ParseError,
};

/// Longest record value we will hand to the presentation-format parser.
///
/// The lexer aborts at 4095 characters within a single token; 4090 leaves a
/// small margin so a future change to how a token is counted cannot walk us
/// back over the edge. The bound is inclusive: a value of exactly
/// `MAX_VALUE_CHARS` characters is accepted.
///
/// Measured against the whole value rather than per token, which is stricter
/// than the lexer needs for a multi-chunk TXT. Deliberate: this number decides
/// what `vega record add` writes *and* what a later reload will accept, and a
/// value that passes one and fails the other is how an operator loses a server
/// at 3am.
pub const MAX_VALUE_CHARS: usize = 4090;

/// The count at which hickory's lexer asserts, quoted from its own source
/// (`for i in 0..4_096 { assert!(i < 4095); ... }`). Only here to hold
/// [`MAX_VALUE_CHARS`] below it.
const LEXER_ABORTS_AT: usize = 4095;

/// A guard above the assertion it guards is not a guard. Checked at compile
/// time rather than in a test, so raising [`MAX_VALUE_CHARS`] past hickory's
/// limit cannot build at all.
const _: () = assert!(MAX_VALUE_CHARS < LEXER_ABORTS_AT);

/// Why a record value was refused.
///
/// Split by cause because the callers word their diagnostics differently — the
/// config path names the record, the CLI path names the flag the operator
/// typed — while the length rule itself must read the same everywhere.
#[derive(Debug, thiserror::Error)]
pub enum ValueError {
    /// Long enough to abort hickory's lexer, so refused before it sees it.
    #[error(
        "{record_type} record value for {owner:?} is {chars} characters; the maximum is \
         {MAX_VALUE_CHARS}. Split a long TXT value into several character-strings instead."
    )]
    TooLong {
        /// Type the value was offered for.
        record_type: RecordType,
        /// Owner name the value was offered at, as the operator wrote it.
        owner: String,
        /// Length actually offered, in characters.
        chars: usize,
    },

    /// The parser rejected it, which is the ordinary "you typed it wrong" case.
    #[error(transparent)]
    Unparsable(#[from] ParseError),
}

/// Parse `value` as presentation-format RDATA for `record_type` at `owner`.
///
/// `owner` is only ever used to build the error message, so pass whatever the
/// operator would recognise — the config's `name`, or the CLI argument.
pub fn parse_value(record_type: RecordType, owner: &str, value: &str) -> Result<RData, ValueError> {
    // Counted in `char`s, not bytes: the lexer's loop advances once per
    // character, so a multi-byte value is longer in bytes than the assertion
    // ever sees and a byte count would refuse values that parse perfectly well.
    let chars = value.chars().count();
    if chars > MAX_VALUE_CHARS {
        return Err(ValueError::TooLong {
            record_type,
            owner: owner.to_owned(),
            chars,
        });
    }

    Ok(RData::try_from_str(record_type, value)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A TXT value of exactly `n` characters, quotes included.
    fn txt_of(n: usize) -> String {
        format!("\"{}\"", "a".repeat(n - 2))
    }

    /// Scenario: A record value of exactly the maximum length is accepted
    /// features/cli-record-editing.feature
    #[test]
    fn a_value_of_exactly_the_maximum_length_parses() {
        let value = txt_of(MAX_VALUE_CHARS);
        assert_eq!(value.chars().count(), MAX_VALUE_CHARS);
        parse_value(RecordType::TXT, "@", &value).expect("the bound is inclusive");
    }

    /// Scenario: A record value one character over the maximum is rejected
    /// features/cli-record-editing.feature
    #[test]
    fn a_value_one_character_over_the_maximum_is_too_long_not_a_panic() {
        let value = txt_of(MAX_VALUE_CHARS + 1);
        let error = parse_value(RecordType::TXT, "@", &value).unwrap_err();
        assert!(
            matches!(error, ValueError::TooLong { chars, .. } if chars == MAX_VALUE_CHARS + 1),
            "{error:?}"
        );
    }

    /// The value that actually killed a process: 4200 characters, the length
    /// from the bug report, and far enough past the lexer's own limit that a
    /// guard placed after the parse call would not save us.
    #[test]
    fn the_length_from_the_bug_report_is_an_error_rather_than_an_abort() {
        let error = parse_value(RecordType::TXT, "@", &txt_of(4200)).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("is 4200 characters"), "{message}");
        assert!(
            message.contains(&format!("the maximum is {MAX_VALUE_CHARS}")),
            "{message}"
        );
    }

    /// The value hickory itself aborts on, sent through the guard: proof the
    /// bound is not merely *near* the lexer's limit but below it. Pairs with
    /// the `const _` assertion above, which catches the same mistake at build
    /// time; this one catches it if the guard is bypassed instead of raised.
    #[test]
    fn the_length_the_lexer_asserts_on_never_reaches_the_lexer() {
        let error = parse_value(RecordType::TXT, "@", &txt_of(LEXER_ABORTS_AT)).unwrap_err();
        assert!(matches!(error, ValueError::TooLong { .. }), "{error:?}");
    }

    /// Proof the guard is not just a length check standing in for the parser:
    /// a short but nonsensical value must still come back as `Unparsable`, so
    /// the caller can word it as a typo rather than as a size problem.
    #[test]
    fn a_short_but_invalid_value_is_unparsable_rather_than_too_long() {
        let error = parse_value(RecordType::A, "www", "not-an-ip").unwrap_err();
        assert!(matches!(error, ValueError::Unparsable(_)), "{error:?}");
    }

    /// The owner name is in the message because the operator has to find the
    /// offending record in a file that may hold hundreds.
    #[test]
    fn the_too_long_message_names_the_owner_and_the_type() {
        let error = parse_value(RecordType::TXT, "dkim._domainkey", &txt_of(9000)).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("dkim._domainkey"), "{message}");
        assert!(message.starts_with("TXT "), "{message}");
    }
}
