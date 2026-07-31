//! The crate's single-gate rules, enforced by reading its own source.
//!
//! Two parsers in this codebase are dangerous enough that all of their callers
//! were funnelled into one module, and in both cases the module doc says so.
//! Both claims were false at some point, in the same way: a second call site
//! appeared, nobody noticed the doc no longer described the code, and the bug
//! the gate existed to prevent came back through the new path.
//!
//! * **`src/tomlparse.rs`** owns every TOML parse. Both TOML crates print the
//!   offending *source line* in their `Display`, and on a config file that line
//!   is very often `admin_token = "…`. VEGA-082 redacted it inside
//!   `Config::read_file`; `editor.rs` went on parsing the same file with
//!   `toml_edit` — a different crate, its own `Display` — so `vega record add`,
//!   `vega record list` and `vega zone show` printed the token anyway
//!   (VEGA-089). Fixing that call site the way the first was fixed would only
//!   have waited for a third.
//! * **`src/rdata.rs`** owns every call to `RData::try_from_str`, whose lexer
//!   carries `assert!(i < 4095)`; with `panic = "abort"` a long enough record
//!   value is not a rejected record but a dead process. The bound was first put
//!   in the zone loader only, and `vega record add` kept aborting (VEGA-071).
//!
//! A doc comment cannot enforce either. This can: a new call site fails here,
//! in a test, rather than in an incident. For the TOML gate `clippy.toml` adds a
//! compile-time layer (`disallowed-types` / `disallowed-methods`); it catches
//! the named forms even when this test is not run, and misses the ones where the
//! error type is inferred and never written down, which is exactly what the text
//! scan below is for.

use std::{
    fs,
    path::{Path, PathBuf},
};

/// Deepest directory nesting we will walk under `src/`.
///
/// The tree is two levels (`src/commands/`); the bound is here because an
/// unbounded recursive walk over a symlinked tree is a hang, and a hung test is
/// a test nobody runs.
const MAX_DEPTH: usize = 8;

/// One "everything goes through here" rule.
struct Gate {
    /// The module that owns the rule, relative to `src/`.
    owner: &'static str,
    /// Ways to reach the guarded parser, or to name what it hands back.
    ///
    /// Matched as whole identifier paths, anywhere in the file including
    /// comments — prose that has to discuss the dangerous call belongs in the
    /// owning module, where a reader sees the whole rule at once.
    idioms: &'static [&'static str],
    /// What a caller should do instead, said the way the failure will read.
    instead: &'static str,
}

/// The rules, in the order they were learned the hard way.
const GATES: &[Gate] = &[
    Gate {
        owner: "tomlparse.rs",
        idioms: &[
            // toml_edit: the document types and its error, however spelled. The
            // inference forms are why this is not just the two error types —
            // `raw.parse::<DocumentMut>()?` never names `TomlError` at all, and
            // that is the exact call VEGA-089 was filed for.
            "DocumentMut",
            "ImDocument",
            "TomlError",
            "toml_edit::de",
            // toml: the deserialising entry points and its error.
            "toml::from_str",
            "toml::de::",
            "toml::Deserializer",
            "toml::Value",
            // `Value` in either crate is `FromStr`, so it is a parser with a
            // friendly name; `editor.rs` uses the type freely, so only the
            // parsing forms count.
            "Value::from_str",
            "parse::<Value>",
            // The escape hatch for the clippy layer. One `#[allow]`, in one
            // file, or the compile-time half of this rule can be switched off
            // in a one-line diff that reads like tidying.
            "clippy::disallowed_types",
            "clippy::disallowed_methods",
        ],
        instead: "call tomlparse::deserialize or tomlparse::document, the one place a TOML \
                  parse failure is rendered without quoting the offending source line back \
                  at the operator — that line is very often `admin_token = \"…` \
                  (VEGA-082, then VEGA-089)",
    },
    Gate {
        owner: "rdata.rs",
        idioms: &["try_from_str"],
        instead: "call rdata::parse_value, the one place operator text meets hickory's \
                  zone-file lexer — the lexer asserts past 4095 characters, and under \
                  `panic = \"abort\"` that assert is an outage, not an error (VEGA-071)",
    },
];

/// Every `.rs` file under `dir`, depth-bounded.
fn rust_files(dir: &Path, depth: usize, found: &mut Vec<PathBuf>) {
    assert!(depth <= MAX_DEPTH, "src/ is nested deeper than {MAX_DEPTH}");
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("a readable directory entry").path();
        if path.is_dir() {
            rust_files(&path, depth + 1, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
}

/// `src/`, from the manifest rather than the working directory, so the test
/// finds the crate whether it is run by `cargo test` or by a bare binary.
fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Does `source` contain `idiom` as a whole identifier path?
///
/// Substring alone is too eager: `Value::from_str` is a `toml_edit` parser and
/// also the tail of `HeaderValue::from_str`, which `admin.rs` uses on every
/// response. So a match only counts when it does not continue an identifier to
/// its left — the same rule an editor's "whole word" search applies.
fn names(source: &str, idiom: &str) -> bool {
    source.match_indices(idiom).any(|(at, _)| {
        source[..at]
            .chars()
            .next_back()
            .is_none_or(|before| !before.is_alphanumeric() && before != '_')
    })
}

/// Which of `gate`'s idioms `source` contains.
fn offences(gate: &Gate, source: &str) -> Vec<&'static str> {
    gate.idioms
        .iter()
        .copied()
        .filter(|idiom| names(source, idiom))
        .collect()
}

/// Scenario: A new call site cannot render a raw TOML parse error
/// features/config-precedence.feature:496
#[test]
fn only_the_owning_module_names_the_parser_behind_each_gate() {
    let src = src_dir();
    let mut files = Vec::new();
    rust_files(&src, 0, &mut files);
    assert!(
        files.len() > 10,
        "the walk found only {} files under {}; it is not looking at the crate",
        files.len(),
        src.display()
    );

    for gate in GATES {
        let mut owner_seen = false;
        for file in &files {
            let name = file
                .strip_prefix(&src)
                .expect("every file came from src/")
                .to_string_lossy()
                .into_owned();
            if name == gate.owner {
                owner_seen = true;
                continue;
            }

            let source = fs::read_to_string(file).unwrap_or_else(|e| panic!("reading {name}: {e}"));
            let offences = offences(gate, &source);
            assert!(
                offences.is_empty(),
                "src/{name} names {offences:?}, which belongs to src/{}.\n\
                 Instead, {}.",
                gate.owner,
                gate.instead
            );
        }
        assert!(
            owner_seen,
            "src/{} is gone; the rule it owns has no home",
            gate.owner
        );
    }
}

/// A detector that matches nothing passes this file forever, so prove each
/// idiom is actually detected. Without this the lists could be emptied — or
/// quietly misspelled — in a diff that looks like a tidy-up.
#[test]
fn the_detector_flags_every_idiom_it_claims_to() {
    for gate in GATES {
        assert!(
            !gate.idioms.is_empty(),
            "the {} gate detects nothing",
            gate.owner
        );
        for idiom in gate.idioms {
            let source = format!("fn f() {{ let _ = {idiom}; }}\n");
            assert_eq!(
                offences(gate, &source),
                vec![*idiom],
                "the detector missed {idiom:?}, which it lists as forbidden"
            );
        }
        assert!(
            offences(
                gate,
                "fn f() { tomlparse::deserialize(raw); rdata::parse_value(t, o, v); }"
            )
            .is_empty(),
            "the {} gate flags its own approved call, so every module would fail",
            gate.owner
        );
        // The one near-miss in the tree: a whole-word rule is what keeps the
        // detector from crying wolf on every HTTP header we build, and a
        // detector that cries wolf is one somebody switches off.
        assert!(
            offences(gate, "HeaderValue::from_str(phase.as_str())").is_empty(),
            "an unrelated `from_str` is not a parser this crate gates"
        );
    }
}

/// The rule is worth nothing if the chokepoint itself stops redacting, and a
/// unit test inside `src/tomlparse.rs` cannot show that the module the binary
/// links is the module that redacts. This goes in through the public API, the
/// way `config.rs` and `editor.rs` do.
///
/// Scenario: No command echoes the admin_token line from a broken config
/// features/config-precedence.feature:481
#[test]
fn the_chokepoint_keeps_the_position_and_drops_the_line() {
    const SECRET: &str = "SUPER-SECRET-TOKEN-1";
    /// Any table of string values, which is enough to reach the parser.
    type Table = std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>;

    let raw = format!("[server]\nadmin_token = \"{SECRET}\n");
    let from_document = vega::tomlparse::document(&raw).expect_err("unterminated string");
    let from_deserialize =
        vega::tomlparse::deserialize::<Table>(&raw).expect_err("unterminated string");

    for error in [from_document, from_deserialize] {
        // Display, Debug and the anyhow chain are three separate renderings and
        // three separate ways out; VEGA-082 shipped with `{:#}` in mind, and the
        // editor path reached an operator through a plain `{}` instead.
        let renderings = [
            format!("{error}"),
            format!("{error:?}"),
            format!(
                "{:#}",
                anyhow::Error::new(error).context("parsing vega.toml")
            ),
        ];
        for rendering in renderings {
            assert!(
                !rendering.contains(SECRET),
                "the chokepoint leaked the source line: {rendering}"
            );
            assert!(
                rendering.contains("line 2") && rendering.contains("column"),
                "the position is what makes the error useful: {rendering}"
            );
        }
    }
}
