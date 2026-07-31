//! Length limits on record values, end to end through the real binary.
//!
//! `RData::try_from_str` aborts rather than erroring on a long enough value
//! (hickory-proto `serialize/txt/zone_lex.rs`: `assert!(i < 4095)`), and the
//! release profile sets `panic = "abort"`, so the difference between a guarded
//! and an unguarded path is the difference between exit 1 and SIGABRT. Only a
//! subprocess can tell those apart, which is why these live out here rather than
//! in a unit test: a `#[test]` that aborts takes the test binary with it.
//!
//! The second thing these pin is that `vega record add` and `vega check` agree.
//! The guard was once in the zone loader only, so the editor aborted on a value
//! the loader would have refused politely; anything the CLI is willing to write
//! must be something the server is willing to load.

use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

use tempfile::TempDir;
use vega::rdata::MAX_VALUE_CHARS;

/// Path to the binary under test, as provided by Cargo.
fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_vega"))
}

/// Run the binary with `args`, from `dir`.
fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .current_dir(dir)
        .env("NO_COLOR", "1")
        .env_remove("CLICOLOR_FORCE")
        .env_remove("VEGA_CONFIG")
        .env_remove("RUST_LOG")
        .output()
        .expect("the binary should be runnable")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A workspace with a config already initialised for `example.com`.
fn workspace() -> TempDir {
    let dir = TempDir::new().expect("temp dir");
    let output = run(dir.path(), &["init", "--origin", "example.com"]);
    assert!(output.status.success(), "init failed: {}", stderr(&output));
    dir
}

/// A TXT value of exactly `n` characters, quotes included.
fn txt_of(n: usize) -> String {
    format!("\"{}\"", "a".repeat(n - 2))
}

/// Append a TXT record set carrying `value` to the workspace config.
///
/// Written as a TOML literal string so the embedded presentation-format quotes
/// survive verbatim, exactly as `record add` would have written them.
fn append_txt_record(dir: &Path, value: &str) {
    let path = dir.join("vega.toml");
    let existing = std::fs::read_to_string(&path).expect("config reads");
    let appended = format!(
        "{existing}\n[[zone.records]]\nname = \"big\"\ntype = \"TXT\"\nvalues = ['{value}']\n"
    );
    std::fs::write(&path, appended).expect("config writes");
}

/// Assert the process exited with status `code` — and say so in terms that
/// distinguish a clean failure from a signal, because `None` here means the
/// abort this whole file exists to prevent.
fn assert_exit(output: &Output, code: i32) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "expected exit {code}, got {:?}\nstdout: {}\nstderr: {}",
        output.status,
        stdout(output),
        stderr(output)
    );
}

/// Scenario: An oversized record value exits 1 rather than aborting the process
/// features/cli-record-editing.feature
///
/// The reported bug, verbatim: `vega record add big TXT <4200 chars>` exited
/// 134 (SIGABRT) from inside hickory's lexer. The assertion that matters is the
/// exit *code*: an abort has none at all.
#[test]
fn record_add_with_an_oversized_value_exits_one_rather_than_aborting() {
    let dir = workspace();
    let value = txt_of(4200);

    let output = run(dir.path(), &["record", "add", "big", "TXT", &value]);

    assert_exit(&output, 1);
    let message = stderr(&output);
    assert!(message.contains("is 4200 characters"), "{message}");
    assert!(
        message.contains(&format!("the maximum is {MAX_VALUE_CHARS}")),
        "{message}"
    );
    assert!(
        !message.contains("assertion failed"),
        "the lexer assertion still fired: {message}"
    );

    let config = std::fs::read_to_string(dir.path().join("vega.toml")).expect("config reads");
    assert!(
        !config.contains("aaaa"),
        "the rejected value was written to the config anyway"
    );
}

/// Scenario: A record value of exactly the maximum length is accepted
/// features/cli-record-editing.feature
///
/// And then the server loads it. This is the half that catches divergence: if
/// the editor's bound is ever loosened past the zone loader's, `record add`
/// succeeds here and `check` fails on the next line.
#[test]
fn a_value_at_the_limit_is_written_by_record_add_and_accepted_by_check() {
    let dir = workspace();
    let value = txt_of(MAX_VALUE_CHARS);

    let added = run(dir.path(), &["record", "add", "big", "TXT", &value]);
    assert_exit(&added, 0);

    let checked = run(dir.path(), &["check"]);
    assert_exit(&checked, 0);
}

/// Scenario: A record value one character over the maximum is rejected
/// features/cli-record-editing.feature
///
/// Refused by both paths, with the same message. The two guards were once
/// separate constants in separate modules; this is what says they are one rule.
#[test]
fn one_character_over_the_limit_is_refused_by_both_record_add_and_check() {
    let over = MAX_VALUE_CHARS + 1;
    let value = txt_of(over);

    let edit_dir = workspace();
    let added = run(edit_dir.path(), &["record", "add", "big", "TXT", &value]);
    assert_exit(&added, 1);

    let load_dir = workspace();
    append_txt_record(load_dir.path(), &value);
    let checked = run(load_dir.path(), &["check"]);
    assert_exit(&checked, 1);

    let complaint = format!("is {over} characters; the maximum is {MAX_VALUE_CHARS}");
    let from_add = stderr(&added);
    let from_check = format!("{}{}", stdout(&checked), stderr(&checked));
    assert!(from_add.contains(&complaint), "record add said: {from_add}");
    assert!(from_check.contains(&complaint), "check said: {from_check}");
}
