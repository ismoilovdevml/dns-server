//! The one gate between a config file's bytes and a TOML parser — and the one
//! place a parse failure is turned into text an operator will read.
//!
//! Both TOML crates this project uses print the offending *source line* in their
//! `Display`, with a caret under the column:
//!
//! ```text
//! TOML parse error at line 2, column 36
//!   |
//! 2 | admin_token = "SUPER-SECRET-TOKEN-1
//!   |                                    ^
//! ```
//!
//! That is a fine error for a compiler and a disclosure for a name server: the
//! line that fails to parse is very often the one with the token on it, and this
//! string reaches an operator's terminal, a CI job log, a `/reload` response body
//! and a WARN line on the way to whatever aggregates container stdout.
//!
//! It has been fixed twice. VEGA-082 redacted it inside `Config::read_file`,
//! which covers `serve`, `check` and `/reload`. `editor.rs` then parsed the same
//! file with `toml_edit` — a *different crate*, with its own `Display` — so
//! `vega record add`, `vega record list` and `vega zone show` went on printing
//! the line (VEGA-089). Redacting per call site is what produced the second bug,
//! so the rule here is stronger: **this module is the only one in the crate that
//! may name a TOML parser's entry points, its document type or its error type.**
//! Everything else calls [`deserialize`] or [`document`] and can only ever hold a
//! [`ParseError`], which has no way to render the input because it never keeps
//! it — only a line, a column and the parser's own description of what it wanted.
//!
//! The rule is enforced from two sides, because each has a hole the other
//! covers:
//!
//! * `clippy.toml` lists those paths under `disallowed-types` and
//!   `disallowed-methods`, so a new call site elsewhere fails
//!   `cargo clippy --all-targets --all-features -- -D warnings`. The single
//!   `#[allow]` that opts this module out is directly below. That layer cannot
//!   see a call whose error type is inferred and never written down.
//! * `tests/toml_parse_chokepoint.rs` reads `src/**/*.rs` and fails if any other
//!   module contains those names *or* an `#[allow]` for the two lints. That
//!   layer catches the inference forms, and it is why the `#[allow]` below is
//!   worth grepping for.
//!
//! ## What is kept, and what is dropped
//!
//! Kept: the line, the column, and `Error::message()` — the parser's description
//! of what it expected, assembled from grammar literals. Those are what make the
//! error actionable, and VEGA-082's tests pin them.
//!
//! Dropped: the quoted source line and the caret.
//!
//! One honest limit. For a *syntax* failure the message is grammar text and
//! cannot contain input. For a *deserialisation* failure serde composes the
//! message, and serde quotes key names, unknown enum variants and scalars that
//! are of the wrong type for a typed field. None of those is reachable from a
//! well-formed token sitting where a token belongs — `admin_token` is a `String`,
//! so every TOML string is valid there and the only failures it can produce are
//! positional. `config::tests::no_parse_failure_shape_echoes_the_value_of_admin_token`
//! is what holds that claim to the ground, one input shape at a time.

// `clippy.toml` disallows the parser entry points, the document type and both
// error types crate-wide. This module is the exception those lints exist to
// create, so the allow covers it whole rather than being sprinkled over the four
// items that need it — and `tests/toml_parse_chokepoint.rs` fails if a second
// allow for either lint appears anywhere in `src/`, which is what stops the
// exception from spreading.
#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "the chokepoint the lints exist to funnel every caller into"
)]

use std::{
    fmt,
    ops::{Deref, DerefMut, Range},
};

use serde::de::DeserializeOwned;

/// An editable TOML document, parsed through this module.
///
/// A newtype rather than a re-export, so that `toml_edit::DocumentMut` — which
/// is `FromStr`, i.e. a parser that any module could reach for — appears in
/// exactly one file in the crate and both halves of the guard above can say so
/// mechanically. Callers get every method of the document through [`Deref`];
/// what they do not get is a way to build one without coming through here.
#[derive(Debug, Clone)]
pub struct Document(toml_edit::DocumentMut);

impl Deref for Document {
    type Target = toml_edit::DocumentMut;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Document {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl fmt::Display for Document {
    /// The document as it would be written back to the file, comments and
    /// layout intact. `editor::save` renders through this.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Why a TOML file would not parse, in terms an operator can act on and a log
/// aggregator can keep.
///
/// Deliberately not a wrapper around either crate's error: a wrapper keeps the
/// original reachable, and the first thing that renders a chain — `anyhow`'s
/// `{:#}` and `{:?}` both do — puts the source line back. The fields are a pair
/// of integers and a grammar description; there is nothing here to leak.
#[derive(Clone, PartialEq, Eq)]
pub struct ParseError {
    /// One-based line and column, absent when the parser reported no span.
    position: Option<(usize, usize)>,
    /// The parser's own description of what it found and what it expected.
    message: String,
}

impl ParseError {
    /// Build from the parts every TOML error in either crate exposes.
    ///
    /// Private, and takes `raw` only to turn a byte offset into a position: an
    /// error that could be constructed from outside could be constructed with
    /// the file's text as its message.
    fn new(raw: &str, span: Option<Range<usize>>, message: &str) -> Self {
        Self {
            position: span.map(|span| position(raw, span.start)),
            message: message.to_owned(),
        }
    }

    /// One-based line the parser stopped at, when it reported one.
    ///
    /// Exposed so a caller can put the position in a structured log field
    /// without re-parsing our own prose.
    pub fn line(&self) -> Option<usize> {
        self.position.map(|(line, _)| line)
    }

    /// One-based column the parser stopped at, when it reported one.
    pub fn column(&self) -> Option<usize> {
        self.position.map(|(_, column)| column)
    }
}

impl fmt::Display for ParseError {
    /// Worded exactly as `toml`'s own first line, minus the quoted source: an
    /// operator's runbook, and VEGA-082's tests, both match on this text.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.position {
            Some((line, column)) => {
                write!(
                    f,
                    "TOML parse error at line {line}, column {column}: {}",
                    self.message
                )
            }
            None => f.write_str(&self.message),
        }
    }
}

impl fmt::Debug for ParseError {
    /// The same text as `Display`. A derived `Debug` would read differently in a
    /// `tracing` field than on the terminal for no gain — there is nothing in
    /// this error a reader would want that `Display` withholds.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for ParseError {
    /// No source, on purpose. This is the whole redaction: `anyhow` prints the
    /// entire chain for `{:#}` and `{:?}`, so a surviving parser error anywhere
    /// under here re-introduces the snippet at the first thing that renders it.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// Deserialise a TOML document into `T`.
///
/// The startup and reload path: `Config::read_file` turns the file into a
/// `FileConfig` through here.
pub fn deserialize<T: DeserializeOwned>(raw: &str) -> Result<T, ParseError> {
    toml::from_str(raw).map_err(|error| ParseError::new(raw, error.span(), error.message()))
}

/// Parse a TOML document for editing, preserving comments and layout.
///
/// The `vega record` / `vega zone` path: those commands rewrite one key of a
/// file an operator maintains by hand, so the document model has to survive the
/// round trip.
pub fn document(raw: &str) -> Result<Document, ParseError> {
    raw.parse::<toml_edit::DocumentMut>()
        .map(Document)
        .map_err(|error| ParseError::new(raw, error.span(), error.message()))
}

/// A byte offset into `raw` as the one-based line and column `toml` would report.
///
/// Same arithmetic as `toml`'s own `translate_position`, so the numbers an
/// operator sees do not move: columns count characters, not bytes.
fn position(raw: &str, offset: usize) -> (usize, usize) {
    // The span comes from a parser reading this very string, so it is already a
    // character boundary and in range. Clamped and floored anyway, because
    // `/reload` reaches this from the network and `panic = "abort"` turns one
    // slice panic into a full outage. Both loops below are bounded: the floor
    // steps back at most three bytes (UTF-8's longest encoding) since offset 0 is
    // always a boundary.
    let mut offset = offset.min(raw.len());
    while offset > 0 && !raw.is_char_boundary(offset) {
        offset -= 1;
    }
    let head = &raw[..offset];
    let line_start = head.rfind('\n').map_or(0, |newline| newline + 1);
    let line = head[..line_start].matches('\n').count() + 1;
    let column = head[line_start..].chars().count() + 1;
    (line, column)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    /// The secret every leak test below plants. Distinctive enough that a
    /// substring search cannot match anything the renderer legitimately emits.
    const SECRET: &str = "SUPER-SECRET-TOKEN-1";

    /// A deserialise target that accepts any table of scalars, so these tests
    /// exercise the parser rather than the shape of a config.
    type AnyTable = BTreeMap<String, BTreeMap<String, String>>;

    /// The position we report is the position `toml` would have reported: an
    /// operator comparing our message with their editor's gutter must not find
    /// an off-by-one.
    #[test]
    fn a_byte_offset_becomes_the_same_one_based_line_and_column_toml_uses() {
        let raw = "a\nbcd\nz";
        assert_eq!(position(raw, 0), (1, 1));
        assert_eq!(position(raw, 2), (2, 1));
        assert_eq!(position(raw, 4), (2, 3));
        assert_eq!(position(raw, 6), (3, 1));
        // Past the end (the parser reports EOF this way) and inside a multi-byte
        // character: neither may panic, because /reload reaches this from the
        // network and `panic = "abort"` makes one panic an outage.
        assert_eq!(position(raw, 99), (3, 2));
        assert_eq!(position("héllo", 2), (1, 2));
    }

    /// Scenario: No command echoes the admin_token line from a broken config
    /// features/config-precedence.feature:481
    ///
    /// Both parsers, one assertion: this is the property the whole module
    /// exists for, and the reason it is a `for` loop rather than two tests is
    /// that a future third parser belongs in the same loop.
    #[test]
    fn neither_parser_puts_the_offending_source_line_in_its_error() {
        let raw = format!("[server]\nadmin_token = \"{SECRET}\n");

        let from_document = document(&raw).expect_err("an unterminated string cannot parse");
        let from_deserialize =
            deserialize::<AnyTable>(&raw).expect_err("an unterminated string cannot parse");

        for error in [from_document, from_deserialize] {
            let rendered = error.to_string();
            assert!(!rendered.contains(SECRET), "{rendered}");
            assert!(
                !rendered.contains('^'),
                "the caret line survived: {rendered}"
            );
            assert_eq!(error.line(), Some(2), "{rendered}");
            assert_eq!(error.column(), Some(36), "{rendered}");
            assert!(
                rendered.contains("TOML parse error at line 2, column 36"),
                "the position is what makes it actionable: {rendered}"
            );
        }
    }

    /// `Display` is not the only way out of a process. `anyhow` renders the
    /// chain for `{:#}` and `{:?}`, and a `tracing` field renders `Debug`; the
    /// error must be safe in all of them, which is what having no `source` buys.
    #[test]
    fn no_rendering_of_the_error_reaches_the_input() {
        let raw = format!("[server]\nadmin_token = \"{SECRET}\n");
        let error = document(&raw).expect_err("an unterminated string cannot parse");

        let wrapped = anyhow::Error::new(error).context("parsing vega.toml");
        for rendered in [
            format!("{wrapped}"),
            format!("{wrapped:#}"),
            format!("{wrapped:?}"),
        ] {
            assert!(!rendered.contains(SECRET), "{rendered}");
        }
        assert!(
            format!("{wrapped:#}").contains("line 2, column 36"),
            "the position must survive being wrapped: {wrapped:#}"
        );
    }

    /// A parser can report a failure with no span at all (`toml` does this for
    /// some serde errors). The message still has to come through, because an
    /// error with neither position nor description is unactionable.
    #[test]
    fn a_failure_without_a_span_still_carries_the_parsers_message() {
        let error = ParseError::new("irrelevant", None, "missing field `origin`");
        assert_eq!(error.to_string(), "missing field `origin`");
        assert_eq!(error.line(), None);
        assert_eq!(error.column(), None);
    }

    /// The good path: a document parsed here is fully usable through `Deref`,
    /// so routing a caller through this module costs it nothing.
    #[test]
    fn a_parsed_document_is_readable_and_writable_through_the_newtype() {
        let mut doc = document("# kept\n[zone]\norigin = \"example.com\"\n").expect("valid TOML");
        assert_eq!(
            doc.get("zone")
                .and_then(|zone| zone.get("origin"))
                .and_then(|origin| origin.as_str()),
            Some("example.com")
        );

        doc["zone"]["origin"] = toml_edit::value("other.test");
        let rendered = doc.to_string();
        assert!(rendered.contains("other.test"), "{rendered}");
        assert!(
            rendered.contains("# kept"),
            "the comment-preserving document model is the point of this type: {rendered}"
        );
    }

    /// A valid file deserialises, which is the other half of "this module is
    /// not just an error renderer".
    #[test]
    fn a_valid_document_deserialises() {
        let table: AnyTable =
            deserialize("[zone]\norigin = \"example.com\"\n").expect("valid TOML");
        assert_eq!(table["zone"]["origin"], "example.com");
    }
}
