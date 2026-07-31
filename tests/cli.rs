//! End-to-end tests for the command-line interface.
//!
//! These run the real binary as a subprocess, so they cover argument parsing,
//! exit codes, file writes and JSON shape — the contract that scripts and agents
//! actually depend on, and none of which the library tests can see.
//!
//! The last section extends that contract to the commands we *ship*: the
//! `Exec*=` lines of `deploy/systemd/vega.service` are command lines like any
//! other, and until VEGA-007 nothing ever ran them.

use std::{
    collections::BTreeMap,
    fs,
    iter::Peekable,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    str::Chars,
    time::{Duration, Instant},
};

use clap::Parser as _;
use tempfile::TempDir;
use vega::cli::{Cli, Command as CliCommand};

/// Path to the binary under test, as provided by Cargo.
fn bin() -> PathBuf {
    // CARGO_BIN_EXE_<name> is set for integration tests of a binary target.
    PathBuf::from(env!("CARGO_BIN_EXE_vega"))
}

/// Run the binary with `args`, from `dir`.
fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .current_dir(dir)
        // Keep output deterministic: no colour, no inherited config, no RUST_LOG.
        .env("NO_COLOR", "1")
        .env_remove("CLICOLOR_FORCE")
        .env_remove("VEGA_CONFIG")
        .env_remove("RUST_LOG")
        .output()
        .expect("the binary should be runnable")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Parse stdout as a single JSON value.
fn json(output: &Output) -> serde_json::Value {
    let text = stdout(output);
    serde_json::from_str(text.trim()).unwrap_or_else(|e| {
        panic!(
            "stdout was not JSON ({e}): {text:?}\nstderr: {}",
            stderr(output)
        )
    })
}

/// A workspace with a config already initialised for `example.com`.
fn workspace() -> TempDir {
    let dir = TempDir::new().expect("temp dir");
    let output = run(dir.path(), &["init", "--origin", "example.com", "--json"]);
    assert!(output.status.success(), "init failed: {}", stderr(&output));
    dir
}

#[test]
fn version_and_help_work() {
    let dir = TempDir::new().unwrap();

    let version = run(dir.path(), &["--version"]);
    assert!(version.status.success());
    assert!(stdout(&version).contains(env!("CARGO_PKG_VERSION")));

    let help = run(dir.path(), &["--help"]);
    assert!(help.status.success());
    let text = stdout(&help);
    for expected in [
        "record", "zone", "query", "status", "reload", "check", "init",
    ] {
        assert!(
            text.contains(expected),
            "help should mention {expected}:\n{text}"
        );
    }
}

#[test]
fn init_creates_a_config_and_is_idempotent() {
    let dir = TempDir::new().unwrap();

    let first = run(dir.path(), &["init", "--origin", "example.com", "--json"]);
    assert!(first.status.success());
    assert_eq!(json(&first)["created"], true);
    assert!(dir.path().join("vega.toml").is_file());

    // A second run must not clobber the file.
    let second = run(dir.path(), &["init", "--origin", "other.test", "--json"]);
    assert!(second.status.success());
    assert_eq!(json(&second)["created"], false);

    let show = run(dir.path(), &["zone", "show", "--json"]);
    assert_eq!(json(&show)["origin"], "example.com");
}

#[test]
fn config_is_discovered_in_the_working_directory() {
    let dir = workspace();
    // No --config: the search path should find ./vega.toml.
    let output = run(dir.path(), &["zone", "show", "--json"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(json(&output)["origin"], "example.com");
}

#[test]
fn missing_config_is_an_error_with_a_useful_message() {
    let dir = TempDir::new().unwrap();
    let output = run(dir.path(), &["record", "list"]);
    assert!(!output.status.success());
    let text = stderr(&output);
    assert!(text.contains("no config file found"), "{text}");
    assert!(text.contains("vega init"), "{text}");
}

#[test]
fn record_add_reports_what_changed() {
    let dir = workspace();

    let created = run(
        dir.path(),
        &["record", "add", "www", "A", "203.0.113.10", "--json"],
    );
    assert!(created.status.success(), "{}", stderr(&created));
    assert_eq!(json(&created)["change"], "created");

    let extended = run(
        dir.path(),
        &["record", "add", "www", "A", "203.0.113.11", "--json"],
    );
    assert_eq!(json(&extended)["change"], "extended");

    let unchanged = run(
        dir.path(),
        &["record", "add", "www", "A", "203.0.113.11", "--json"],
    );
    assert!(unchanged.status.success(), "idempotent edits must exit 0");
    assert_eq!(json(&unchanged)["change"], "unchanged");

    let replaced = run(
        dir.path(),
        &[
            "record",
            "add",
            "www",
            "A",
            "198.51.100.1",
            "--replace",
            "--json",
        ],
    );
    assert_eq!(json(&replaced)["change"], "replaced");
    assert_eq!(
        json(&replaced)["record"]["values"],
        serde_json::json!(["198.51.100.1"])
    );
}

#[test]
fn record_add_rejects_bad_input_without_writing() {
    let dir = workspace();
    let before = std::fs::read_to_string(dir.path().join("vega.toml")).unwrap();

    let bad_value = run(dir.path(), &["record", "add", "www", "A", "not-an-ip"]);
    assert!(!bad_value.status.success());
    assert!(
        stderr(&bad_value).contains("invalid A value"),
        "{}",
        stderr(&bad_value)
    );

    let bad_type = run(dir.path(), &["record", "add", "www", "NOPE", "x"]);
    assert!(!bad_type.status.success());
    assert!(stderr(&bad_type).contains("unknown record type"));

    assert_eq!(
        std::fs::read_to_string(dir.path().join("vega.toml")).unwrap(),
        before,
        "a rejected edit must leave the file untouched"
    );
}

#[test]
fn record_list_and_get_filter_correctly() {
    let dir = workspace();
    run(dir.path(), &["record", "add", "www", "A", "203.0.113.10"]);
    run(dir.path(), &["record", "add", "www", "TXT", "\"hello\""]);
    run(dir.path(), &["record", "add", "api", "A", "203.0.113.20"]);

    let all = run(dir.path(), &["record", "list", "--json"]);
    assert_eq!(json(&all)["count"], 3);

    let by_type = run(dir.path(), &["record", "list", "--type", "a", "--json"]);
    assert_eq!(
        json(&by_type)["count"],
        2,
        "type filter is case-insensitive"
    );

    let by_name = run(dir.path(), &["record", "list", "--name", "www", "--json"]);
    assert_eq!(json(&by_name)["count"], 2);

    let found = run(dir.path(), &["record", "get", "www", "A", "--json"]);
    assert!(found.status.success());
    assert_eq!(json(&found)["found"], true);

    // A miss must exit non-zero so shell conditionals work.
    let missing = run(dir.path(), &["record", "get", "ghost", "--json"]);
    assert!(!missing.status.success());
    assert_eq!(json(&missing)["found"], false);
}

#[test]
fn record_delete_removes_values_and_whole_sets() {
    let dir = workspace();
    run(
        dir.path(),
        &["record", "add", "www", "A", "203.0.113.10", "203.0.113.11"],
    );

    let one_value = run(
        dir.path(),
        &[
            "record",
            "delete",
            "www",
            "A",
            "--value",
            "203.0.113.10",
            "--json",
        ],
    );
    assert_eq!(json(&one_value)["change"], "removed");
    assert_eq!(
        json(&one_value)["record"]["values"],
        serde_json::json!(["203.0.113.11"])
    );

    let whole_set = run(dir.path(), &["record", "delete", "www", "A", "--json"]);
    assert_eq!(json(&whole_set)["change"], "removed");

    let list = run(dir.path(), &["record", "list", "--json"]);
    assert_eq!(json(&list)["count"], 0);

    // Deleting something absent is not an error.
    let absent = run(dir.path(), &["record", "delete", "ghost", "A", "--json"]);
    assert!(absent.status.success());
    assert_eq!(json(&absent)["change"], "unchanged");
}

#[test]
fn wildcards_and_apex_names_are_accepted() {
    let dir = workspace();

    let apex = run(
        dir.path(),
        &["record", "add", "@", "A", "203.0.113.1", "--json"],
    );
    assert!(apex.status.success(), "{}", stderr(&apex));
    assert_eq!(json(&apex)["record"]["name"], "@");

    let wildcard = run(
        dir.path(),
        &["record", "add", "*.apps", "A", "203.0.113.30", "--json"],
    );
    assert!(wildcard.status.success());
    assert_eq!(json(&wildcard)["record"]["name"], "*.apps");

    let mx = run(
        dir.path(),
        &["record", "add", "@", "MX", "10 mail.example.com.", "--json"],
    );
    assert!(mx.status.success(), "{}", stderr(&mx));
}

#[test]
fn config_edits_survive_a_round_trip_and_keep_comments() {
    let dir = workspace();
    let path = dir.path().join("vega.toml");

    // The generated config starts with a comment; edits must not eat it.
    let before = std::fs::read_to_string(&path).unwrap();
    let comment = before.lines().next().unwrap().to_owned();
    assert!(
        comment.starts_with('#'),
        "fixture should start with a comment"
    );

    run(dir.path(), &["record", "add", "www", "A", "203.0.113.10"]);
    let after = std::fs::read_to_string(&path).unwrap();
    assert!(after.contains(&comment), "comment was lost:\n{after}");
}

#[test]
fn bump_serial_advances_monotonically() {
    let dir = workspace();

    let first = run(dir.path(), &["zone", "bump-serial", "--json"]);
    assert!(first.status.success(), "{}", stderr(&first));
    let a = json(&first)["serial"].as_u64().expect("serial is a number");

    let second = run(dir.path(), &["zone", "bump-serial", "--json"]);
    let b = json(&second)["serial"].as_u64().unwrap();
    assert!(b >= a, "{b} should be >= {a}");

    // And an edit with --bump-serial moves it again.
    let edit = run(
        dir.path(),
        &[
            "record",
            "add",
            "www",
            "A",
            "203.0.113.10",
            "--bump-serial",
            "--json",
        ],
    );
    let c = json(&edit)["serial"].as_u64().unwrap();
    assert!(c >= b, "{c} should be >= {b}");
}

#[test]
fn check_validates_and_reports_the_zone() {
    let dir = workspace();
    run(dir.path(), &["record", "add", "www", "A", "203.0.113.10"]);

    let output = run(dir.path(), &["check", "--json"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let value = json(&output);
    assert_eq!(value["ok"], true);
    assert_eq!(value["zone"]["origin"], "example.com");
    assert_eq!(value["zone"]["records"], 1);
    assert_eq!(value["zone"]["soa"], true);
}

#[test]
fn check_fails_on_a_broken_config() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join("vega.toml"),
        "[zone]\norigin = \"example.com\"\n\n[[zone.records]]\nname = \"@\"\ntype = \"A\"\nvalues = [\"garbage\"]\n",
    )
    .unwrap();

    let output = run(dir.path(), &["check"]);
    assert!(!output.status.success(), "a bad zone must fail the check");
    assert!(
        stderr(&output).contains("invalid A record value"),
        "{}",
        stderr(&output)
    );
}

/// Scenario: A startup failure does not echo the admin_token line
/// features/config-precedence.feature:462
///
/// The reproduction in VEGA-082 was this path, not `/reload`: an operator types
/// one unterminated quote, and the token is on their terminal and in the
/// journal. `serve` fails before it binds anything, so this stays a pure
/// command-line test.
#[test]
fn a_startup_failure_does_not_echo_the_admin_token_line() {
    const SECRET: &str = "SUPER-SECRET-TOKEN-1";
    let broken = [
        format!("[server]\nadmin_token = \"{SECRET}\n[zone]\norigin = \"example.com\"\n"),
        format!(
            "[server]\nadmin_token = \"{SECRET}\"\nadmin_token = \"{SECRET}\"\n\
             [zone]\norigin = \"example.com\"\n"
        ),
    ];

    for toml in broken {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("vega.toml"), &toml).unwrap();

        // Both renderings: `report` writes prose to stderr and JSON to stdout,
        // and each one is a separate way for the secret to leave the process.
        for args in [vec!["serve"], vec!["serve", "--json"], vec!["check"]] {
            let output = run(dir.path(), &args);
            assert!(!output.status.success(), "{args:?} must fail to start");
            let combined = format!("{}{}", stdout(&output), stderr(&output));
            assert!(
                !combined.contains(SECRET),
                "{args:?} echoed the offending config line back, secret and all: {combined}"
            );
            assert!(
                combined.contains("line 2") || combined.contains("line 3"),
                "{args:?} must still say where the file is broken: {combined}"
            );
        }
    }
}

/// Every subcommand that can reach a TOML parser, as an argv the binary accepts.
///
/// Listed here rather than derived from `Cli`, because the property under test is
/// "an operator ran this and the secret came back", and that is an argv. A
/// command added without a line here is a command this test does not cover — see
/// `tests/toml_parse_chokepoint.rs`, which catches the same omission from the
/// other side, at the call site rather than at the command line.
const COMMANDS_THAT_PARSE_THE_CONFIG: &[&[&str]] = &[
    &["serve"],
    &["check"],
    &["record", "list"],
    &["record", "get", "www"],
    &["record", "add", "www", "A", "203.0.113.10"],
    &["record", "delete", "www", "A"],
    &["zone", "show"],
    &["zone", "export"],
    &["zone", "bump-serial"],
];

/// Scenario: No command echoes the admin_token line from a broken config
/// features/config-precedence.feature:481
///
/// VEGA-082 fixed `serve` and `check`, which parse through `Config::read_file`.
/// The editing commands parse the same file through `toml_edit`, a different
/// crate with its own `Display`, and kept printing the line — VEGA-089. The list
/// is exhaustive on purpose: the defect was never "this one command", it was
/// "the redaction was not at a chokepoint", and only running all of them says
/// otherwise.
#[test]
fn no_command_that_reads_the_config_echoes_the_admin_token_line() {
    const SECRET: &str = "SUPER-SECRET-TOKEN-1";
    let broken = [
        format!("[server]\nadmin_token = \"{SECRET}\n[zone]\norigin = \"example.com\"\n"),
        format!(
            "[server]\nadmin_token = \"{SECRET}\"\nadmin_token = \"{SECRET}\"\n\
             [zone]\norigin = \"example.com\"\n"
        ),
    ];

    for toml in broken {
        for command in COMMANDS_THAT_PARSE_THE_CONFIG {
            // Both renderings, for every command: `report` writes prose to
            // stderr and JSON to stdout, and each is a separate way out.
            for json in [false, true] {
                let dir = TempDir::new().unwrap();
                std::fs::write(dir.path().join("vega.toml"), &toml).unwrap();
                let mut args = command.to_vec();
                if json {
                    args.push("--json");
                }

                let output = run(dir.path(), &args);
                assert!(!output.status.success(), "{args:?} must fail");
                let combined = format!("{}{}", stdout(&output), stderr(&output));
                assert!(
                    !combined.contains(SECRET),
                    "{args:?} echoed the offending config line back, secret and all: {combined}"
                );
                assert!(
                    combined.contains("line 2") || combined.contains("line 3"),
                    "{args:?} must still say where the file is broken: {combined}"
                );
                assert!(
                    combined.contains("column"),
                    "{args:?} must still say which column: {combined}"
                );
            }
        }
    }
}

#[test]
fn zone_export_emits_zone_file_syntax() {
    let dir = workspace();
    run(
        dir.path(),
        &["record", "add", "www", "A", "203.0.113.10", "--ttl", "60"],
    );
    run(
        dir.path(),
        &["record", "add", "@", "MX", "10 mail.example.com."],
    );

    let output = run(dir.path(), &["zone", "export"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("$ORIGIN example.com."), "{text}");
    assert!(text.contains("www\t60\tIN\tA\t203.0.113.10"), "{text}");
    assert!(text.contains("@\tIN\tMX\t10 mail.example.com."), "{text}");
}

#[test]
fn shell_completions_are_generated() {
    let dir = TempDir::new().unwrap();
    for shell in ["bash", "zsh", "fish"] {
        let output = run(dir.path(), &["completions", shell]);
        assert!(output.status.success(), "{shell}: {}", stderr(&output));
        assert!(
            stdout(&output).contains("vega"),
            "{shell} completions look empty"
        );
    }
}

#[test]
fn client_commands_fail_cleanly_when_nothing_is_listening() {
    let dir = workspace();
    // Port 1 is reserved and will refuse the connection.
    let unreachable = ["--admin-listen", "127.0.0.1:1"];

    let health = run(dir.path(), &[&["healthcheck"], &unreachable[..]].concat());
    assert!(!health.status.success());

    let status = run(
        dir.path(),
        &[&["status", "--json"], &unreachable[..]].concat(),
    );
    assert!(!status.status.success());
    assert_eq!(json(&status)["reachable"], false);

    let reload = run(
        dir.path(),
        &[&["reload", "--json"], &unreachable[..]].concat(),
    );
    assert!(!reload.status.success());
    assert_eq!(json(&reload)["ok"], false);
}

#[test]
fn query_reports_an_unreachable_server_as_json() {
    let dir = workspace();
    let output = run(
        dir.path(),
        &[
            "query",
            "www.example.com",
            "A",
            "--server",
            "127.0.0.1:1",
            "--json",
        ],
    );
    assert!(!output.status.success());
    let value = json(&output);
    assert_eq!(value["ok"], false);
    // The message must name the server that failed, whatever the OS called the
    // failure (refused, unreachable, timed out).
    let error = value["error"].as_str().unwrap_or_default();
    assert!(error.contains("127.0.0.1:1"), "unexpected error: {error}");
}

#[test]
fn query_rejects_a_hostname_as_the_server() {
    let dir = workspace();
    let output = run(
        dir.path(),
        &[
            "query",
            "www.example.com",
            "A",
            "--server",
            "ns1.example.com",
        ],
    );
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("not resolved"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn json_output_is_never_coloured() {
    let dir = workspace();
    let output = Command::new(bin())
        .args(["zone", "show", "--json"])
        .current_dir(dir.path())
        // Even with colour forced, JSON must stay clean so it stays parseable.
        .env("CLICOLOR_FORCE", "1")
        .env_remove("NO_COLOR")
        .output()
        .expect("runnable");

    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        !text.contains('\u{1b}'),
        "JSON contained escape codes: {text:?}"
    );
    serde_json::from_str::<serde_json::Value>(text.trim()).expect("valid JSON");
}

#[test]
fn text_output_is_plain_when_no_color_is_set() {
    let dir = workspace();
    let output = run(dir.path(), &["zone", "show"]);
    let text = stdout(&output);
    assert!(!text.contains('\u{1b}'), "NO_COLOR was ignored: {text:?}");
}

#[test]
fn global_flags_are_accepted_on_either_side_of_the_subcommand() {
    let dir = workspace();
    let path = dir.path().join("vega.toml");
    let path = path.to_str().unwrap();

    let before = run(dir.path(), &["--config", path, "zone", "show", "--json"]);
    assert!(before.status.success(), "{}", stderr(&before));

    let after = run(dir.path(), &["zone", "show", "--config", path, "--json"]);
    assert!(after.status.success(), "{}", stderr(&after));

    assert_eq!(json(&before)["origin"], json(&after)["origin"]);
}

// ---------------------------------------------------------------------------
// The shipped systemd unit
// ---------------------------------------------------------------------------
//
// VEGA-007: the unit we publish had `ExecStartPre=... --check`, a flag that does
// not exist — `check` is a subcommand. With `Type=simple`, a failing
// ExecStartPre means ExecStart never runs, so everyone who followed the README
// got a service that could not start. Every gate stayed green through all of it,
// because nothing in CI, the Makefile, the installer or the test suite ever read
// the unit file.
//
// These tests close that hole. They parse the *real* unit — not a copy of the
// commands, which would only test itself — pull its `Exec*=` lines through the
// same unquoting systemd does, and then put them in front of the binary: the
// ones we execute pointed at the binary Cargo just built and a throwaway config,
// the one we cannot execute exactly as written.
//
// Deliberate limits, stated rather than papered over:
//
// * `ExecStartPre` is *executed*. It is a short-lived validation command, so
//   exit 0 is a real assertion, and `..._rejects_a_broken_config` proves it is
//   a gate rather than something that trivially succeeds.
// * `ExecStart` is *not* executed. It starts a name server that binds :53 and
//   by design never exits; running it in a test would hang, need root, and
//   fight whatever else holds :53. Instead its argv goes through
//   `vega::cli::Cli::try_parse_from` — literally the type `src/main.rs` calls
//   `Cli::parse()` on — and we assert the parse succeeds, resolves to `serve`,
//   and points at the config the unit says it does. That catches a removed
//   flag, a renamed subcommand, and an ExecStart that quietly stopped serving.
//   It does not claim to have started the server, and nothing here should be
//   read as claiming that.

/// Override for the unit file under test.
///
/// Only exists so CI can point the guard at a deliberately broken copy and
/// prove it fails; see `deploy/prove-unit-guard-fails.sh`. A guard that has
/// never been observed to fail is decoration.
const UNIT_PATH_ENV: &str = "VEGA_UNIT_FILE";

/// One `Exec*=` directive, after systemd's own prefix stripping and unquoting.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecLine {
    directive: String,
    /// The `-` prefix: systemd ignores a non-zero exit from this command. Such
    /// a line may not be asserted to succeed, only to be well-formed.
    ignore_failure: bool,
    argv: Vec<String>,
}

/// The unit file the guard reads.
fn unit_path() -> PathBuf {
    if let Some(over) = std::env::var_os(UNIT_PATH_ENV) {
        let path = PathBuf::from(over);
        assert!(
            path.is_file(),
            "{UNIT_PATH_ENV} points at {}, which is not a file. Refusing to \
             silently fall back to the repository unit: an override that checks \
             nothing is worse than no override.",
            path.display()
        );
        return path;
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy/systemd/vega.service")
}

/// Read the unit. A missing unit is a failure, never a skip.
fn unit_text() -> String {
    let path = unit_path();
    fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "could not read the systemd unit at {}: {e}. This guard exists \
             because nothing else reads it; skipping when it is absent would \
             put the hole straight back.",
            path.display()
        )
    })
}

/// Expand the systemd specifiers we can expand honestly, and refuse the rest.
///
/// `vega.service` is not a template unit, so `%i` and friends have no value to
/// substitute. Guessing one would test a command systemd would never run.
fn expand_specifiers(value: &str, directive: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('%') => out.push('%'),
            Some(other) => panic!(
                "{directive} uses the systemd specifier %{other}, which this \
                 guard cannot expand. Teach expand_specifiers what it resolves \
                 to, or the guard is checking a command systemd never runs."
            ),
            None => panic!("{directive} ends in a bare '%'"),
        }
    }
    out
}

/// Read a `$VAR` / `${VAR}` reference and append its value.
fn push_variable(
    out: &mut String,
    chars: &mut Peekable<Chars<'_>>,
    env: &BTreeMap<String, String>,
    directive: &str,
) {
    let braced = chars.peek() == Some(&'{');
    if braced {
        chars.next();
    }
    let mut name = String::new();
    let mut closed = !braced;
    while let Some(&c) = chars.peek() {
        if braced && c == '}' {
            chars.next();
            closed = true;
            break;
        }
        if c.is_ascii_alphanumeric() || c == '_' {
            name.push(c);
            chars.next();
        } else {
            break;
        }
    }
    assert!(closed, "{directive} has an unterminated ${{...}} reference");
    assert!(!name.is_empty(), "{directive} has a bare '$'");

    // systemd would substitute an empty string for an unset variable, which
    // means the command silently changes shape. Say so instead.
    let value = env.get(&name).unwrap_or_else(|| {
        panic!(
            "{directive} references ${name}, which no Environment= line in the \
             unit sets. systemd would substitute an empty string; this guard \
             will not guess what command that leaves behind."
        )
    });
    out.push_str(value);
}

/// Split a systemd command line into argv the way systemd does.
///
/// Whitespace separates, `"` and `'` quote, `\` escapes, and `$VAR` outside
/// single quotes comes from the unit's own `Environment=` assignments.
fn split_argv(line: &str, env: &BTreeMap<String, String>, directive: &str) -> Vec<String> {
    let mut argv: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut started = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' => {
                if started {
                    argv.push(std::mem::take(&mut cur));
                    started = false;
                }
            }
            '\'' => {
                started = true;
                let mut closed = false;
                for q in chars.by_ref() {
                    if q == '\'' {
                        closed = true;
                        break;
                    }
                    cur.push(q);
                }
                assert!(closed, "{directive} has an unterminated single quote");
            }
            '"' => {
                started = true;
                let mut closed = false;
                while let Some(q) = chars.next() {
                    match q {
                        '"' => {
                            closed = true;
                            break;
                        }
                        '\\' => cur.extend(chars.next()),
                        '$' => push_variable(&mut cur, &mut chars, env, directive),
                        _ => cur.push(q),
                    }
                }
                assert!(closed, "{directive} has an unterminated double quote");
            }
            '\\' => {
                started = true;
                cur.extend(chars.next());
            }
            '$' => {
                started = true;
                push_variable(&mut cur, &mut chars, env, directive);
            }
            _ => {
                started = true;
                cur.push(c);
            }
        }
    }
    if started {
        argv.push(cur);
    }
    argv
}

/// Fold systemd's backslash line continuations into single logical lines.
fn join_continuations(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut pending = String::new();
    for raw in text.lines() {
        if let Some(head) = raw.strip_suffix('\\') {
            pending.push_str(head);
            pending.push(' ');
        } else {
            pending.push_str(raw);
            lines.push(std::mem::take(&mut pending));
        }
    }
    if !pending.is_empty() {
        lines.push(pending);
    }
    lines
}

/// What the guard needs out of a unit: the environment systemd would hand the
/// process, and the commands it would run in it.
#[derive(Debug, Default)]
struct Unit {
    env: BTreeMap<String, String>,
    execs: Vec<ExecLine>,
}

/// Every `Exec*=` line in `[Service]`, in file order.
///
/// Honours the three systemd rules that decide what actually runs: the section
/// a directive sits in, an empty assignment resetting the list, and the
/// `-@:+!` execution prefixes.
fn parse_unit(text: &str) -> Unit {
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    let mut section = String::new();
    let mut execs: Vec<ExecLine> = Vec::new();

    for line in join_continuations(text) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some(name) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = name.to_string();
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        // systemd directive names are case-sensitive, and only [Service] runs
        // anything.
        if section != "Service" {
            continue;
        }
        let key = key.trim_end();

        if key == "Environment" {
            let value = expand_specifiers(value, key);
            for token in split_argv(&value, &env, key) {
                if let Some((k, v)) = token.split_once('=') {
                    env.insert(k.to_string(), v.to_string());
                }
            }
            continue;
        }
        if !key.starts_with("ExecStart")
            && !key.starts_with("ExecStop")
            && !key.starts_with("ExecReload")
            && !key.starts_with("ExecCondition")
        {
            continue;
        }

        // An empty assignment resets the list. Anything collected so far for
        // that directive never runs.
        if value.trim().is_empty() {
            execs.retain(|e| e.directive != key);
            continue;
        }

        let mut rest = expand_specifiers(value.trim_start(), key);
        let mut ignore_failure = false;
        loop {
            let stripped = match rest.chars().next() {
                Some('-') => {
                    ignore_failure = true;
                    &rest[1..]
                }
                // @ (argv[0] override), : (no env expansion), + ! (privilege).
                // None of them change whether the command is well-formed.
                Some('@' | ':' | '+') => &rest[1..],
                Some('!') => rest.trim_start_matches('!'),
                _ => break,
            };
            rest = stripped.to_string();
        }

        let argv = split_argv(&rest, &env, key);
        assert!(!argv.is_empty(), "{key}= has a prefix but no command");
        execs.push(ExecLine {
            directive: key.to_string(),
            ignore_failure,
            argv,
        });
    }
    Unit { env, execs }
}

/// The `Exec*=` lines only; for the parser's own tests.
fn parse_exec_lines(text: &str) -> Vec<ExecLine> {
    parse_unit(text).execs
}

fn exec_lines_named(text: &str, directive: &str) -> Vec<ExecLine> {
    parse_exec_lines(text)
        .into_iter()
        .filter(|e| e.directive == directive)
        .collect()
}

/// The value the unit passes to `--config`, whichever spelling it uses.
fn config_argument(argv: &[String]) -> Option<String> {
    let mut it = argv.iter();
    while let Some(arg) = it.next() {
        if let Some(v) = arg.strip_prefix("--config=") {
            return Some(v.to_string());
        }
        if arg == "--config" || arg == "-c" {
            return it.next().cloned();
        }
    }
    None
}

/// Point an Exec line at the binary Cargo built and a throwaway config, and
/// change nothing else.
///
/// argv[0] is the program by systemd's own rule, so substituting it needs no
/// guesswork; the config is whatever the unit already passes to `--config`.
fn retarget(argv: &[String], config: &Path) -> Vec<String> {
    let declared = config_argument(argv).unwrap_or_else(|| {
        panic!(
            "the unit runs `{}` without --config. It would then fall back to \
             the search path, so the file it validates and the file it serves \
             need not be the same one.",
            argv.join(" ")
        )
    });
    let fixture = config.to_string_lossy().into_owned();

    let mut out = Vec::with_capacity(argv.len());
    out.push(bin().to_string_lossy().into_owned());
    for arg in &argv[1..] {
        if arg == &declared {
            out.push(fixture.clone());
        } else if arg == &format!("--config={declared}") {
            out.push(format!("--config={fixture}"));
        } else {
            out.push(arg.clone());
        }
    }
    out
}

/// Run a retargeted Exec line, refusing to wait forever.
///
/// The unit's own `Environment=` block goes in, because systemd puts it there
/// and `VEGA_*` variables can change what the command does. Two deliberate
/// departures: `NO_COLOR` for readable failure output, and dropping any
/// `VEGA_CONFIG` the developer's shell is carrying, which systemd would not
/// have and which would otherwise decide the test's outcome.
///
/// A command that does not exit is itself the finding: `ExecStartPre` blocks
/// startup, so one that hangs is an outage, not a slow test.
fn run_bounded(argv: &[String], env: &BTreeMap<String, String>, dir: &Path) -> Output {
    const LIMIT: Duration = Duration::from_secs(30);

    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(dir)
        .envs(env)
        .env("NO_COLOR", "1")
        .env_remove("VEGA_CONFIG")
        .env_remove("RUST_LOG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("could not run {argv:?}: {e}"));

    let deadline = Instant::now() + LIMIT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(25));
            }
            // Kill before panicking, both times. `Child`'s Drop detaches rather
            // than reaps, so an unwinding test would leave the process behind —
            // and a test suite that leaks processes is its own incident.
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "{argv:?} was still running after {LIMIT:?}. An ExecStartPre \
                     that does not exit holds the service in `activating` forever."
                );
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("could not wait for {argv:?}: {e}");
            }
        }
    }
    child.wait_with_output().expect("collect output")
}

#[test]
fn systemd_unit_declares_exactly_one_execstart_and_validates_before_it() {
    let text = unit_text();
    let starts = exec_lines_named(&text, "ExecStart");
    let pres = exec_lines_named(&text, "ExecStartPre");

    assert_eq!(
        starts.len(),
        1,
        "Type=simple takes exactly one ExecStart; got {starts:#?}"
    );
    assert!(
        !pres.is_empty(),
        "the unit no longer validates its config before starting. That is a \
         deployment decision, not a tidy-up: without it a typo in \
         /etc/vega/vega.toml is discovered by the restart loop."
    );

    // Validating one file and serving another is worse than not validating:
    // the operator gets a green ExecStartPre and a server on the old zone.
    // Both missing it would compare equal, hence the is_some().
    let served = config_argument(&starts[0].argv);
    assert!(
        served.is_some(),
        "ExecStart passes no --config, so which file it serves depends on the \
         search path and the working directory systemd happens to give it"
    );
    for pre in &pres {
        assert_eq!(
            config_argument(&pre.argv),
            served,
            "{} checks a different config than ExecStart serves",
            pre.directive
        );
    }
}

#[test]
fn systemd_unit_execstartpre_runs_and_exits_zero() {
    let dir = workspace();
    let config = dir.path().join("vega.toml");
    let unit = parse_unit(&unit_text());

    for pre in unit.execs.iter().filter(|e| e.directive == "ExecStartPre") {
        let argv = retarget(&pre.argv, &config);
        let out = run_bounded(&argv, &unit.env, dir.path());
        if pre.ignore_failure {
            // `-` means systemd ignores the exit status, so exit 0 is not the
            // contract. That the binary understands the arguments still is.
            Cli::try_parse_from(&argv).unwrap_or_else(|e| {
                panic!("ExecStartPre- is not a command this binary accepts: {e}")
            });
            continue;
        }
        assert!(
            out.status.success(),
            "ExecStartPre `{}` exited {:?}. With Type=simple that means \
             ExecStart never runs and the service cannot start at all.\n\
             stdout: {}\nstderr: {}",
            pre.argv.join(" "),
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
}

#[test]
fn systemd_unit_execstartpre_rejects_a_broken_config() {
    let dir = TempDir::new().expect("temp dir");
    let config = dir.path().join("vega.toml");
    fs::write(&config, "this is not = [valid toml\n").expect("write");
    let unit = parse_unit(&unit_text());

    for pre in unit.execs.iter().filter(|e| e.directive == "ExecStartPre") {
        if pre.ignore_failure {
            continue;
        }
        let argv = retarget(&pre.argv, &config);
        let out = run_bounded(&argv, &unit.env, dir.path());
        assert!(
            !out.status.success(),
            "ExecStartPre `{}` exited 0 on a config that is not even valid \
             TOML, so it is not a gate. `vega --version` would pass the \
             exit-zero test too; this is what stops that.",
            pre.argv.join(" ")
        );
    }
}

#[test]
fn systemd_unit_execstart_is_a_serve_invocation_the_binary_accepts() {
    let text = unit_text();
    let start = exec_lines_named(&text, "ExecStart")
        .pop()
        .expect("the unit must have an ExecStart");

    // The verbatim line, not a retargeted one: nothing here touches the
    // filesystem, so there is no reason to check a command other than the one
    // systemd would run. It is parsed rather than executed because it starts a
    // name server that binds :53 and never exits — see the section header.
    // `Cli` is the type src/main.rs calls `Cli::parse()` on, so a flag that does
    // not exist or a renamed subcommand fails here rather than on first boot.
    let cli = Cli::try_parse_from(&start.argv).unwrap_or_else(|e| {
        panic!(
            "ExecStart `{}` is not a command this binary accepts: {e}",
            start.argv.join(" ")
        )
    });

    assert!(
        matches!(cli.command, None | Some(CliCommand::Serve)),
        "ExecStart parses but does not run the server: {:?}. systemd would \
         start it, watch it exit, and Restart=always would loop.",
        cli.command
    );
    // `--config` has to survive parsing into the path resolution the server
    // actually uses; a global flag that clap accepts but nothing reads would
    // leave the unit serving whatever the search path found.
    assert_eq!(
        cli.config_path().map(|p| p.to_string_lossy().into_owned()),
        config_argument(&start.argv),
        "ExecStart does not resolve to the config it is given"
    );
}

#[test]
fn systemd_unit_and_installer_agree_on_where_things_live() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let installer = fs::read_to_string(root.join("install.sh")).expect("read install.sh");

    // `NAME="${NAME:-default}"` or `NAME="literal"`.
    let sh_value = |var: &str| -> String {
        let prefix = format!("{var}=");
        let raw = installer
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with(&prefix))
            .unwrap_or_else(|| panic!("install.sh no longer sets {var}"))
            .trim_start_matches(&prefix)
            .trim_matches('"')
            .to_string();
        match raw.strip_prefix(&format!("${{{var}:-")) {
            Some(rest) => rest.trim_end_matches('}').to_string(),
            None => raw,
        }
    };

    let bin_name = sh_value("BIN_NAME");
    let expected_bin = format!("{}/{}", sh_value("INSTALL_DIR"), bin_name);
    let expected_config = format!("{}/{bin_name}.toml", sh_value("CONFIG_DIR"));

    let text = unit_text();
    let start = exec_lines_named(&text, "ExecStart")
        .pop()
        .expect("the unit must have an ExecStart");

    assert_eq!(
        start.argv[0], expected_bin,
        "the unit runs a binary the installer does not put there; \
         `systemctl start vega` would fail with status=203/EXEC"
    );
    assert_eq!(
        config_argument(&start.argv),
        Some(expected_config),
        "the unit reads a config the installer does not write; the service \
         would start on built-in defaults or not at all"
    );
}

// --- the parser above is itself load-bearing, so it is tested ---------------
//
// These use inline fixtures on purpose: they check the parser, not the unit.
// Named `systemd_exec_parser_*` so the `systemd_unit` filter that CI uses for
// the mutation proof runs only the tests that read the real file.

#[test]
fn systemd_exec_parser_reads_only_the_service_section() {
    let unit = "[Unit]\nExecStart=/bin/never\n\n[Service]\nExecStart=/usr/bin/vega serve\n";
    let execs = parse_exec_lines(unit);
    assert_eq!(execs.len(), 1);
    assert_eq!(execs[0].argv, ["/usr/bin/vega", "serve"]);
}

#[test]
fn systemd_exec_parser_folds_continuation_lines() {
    let unit = "[Service]\nExecStartPre=/usr/bin/vega check \\\n    --config /etc/vega/vega.toml\n";
    let execs = parse_exec_lines(unit);
    assert_eq!(
        execs[0].argv,
        ["/usr/bin/vega", "check", "--config", "/etc/vega/vega.toml"]
    );
}

#[test]
fn systemd_exec_parser_strips_prefixes_and_records_ignored_failure() {
    let unit = "[Service]\nExecStartPre=-@!/usr/bin/vega check\nExecStart=/usr/bin/vega\n";
    let execs = parse_exec_lines(unit);
    assert!(execs[0].ignore_failure);
    assert_eq!(execs[0].argv, ["/usr/bin/vega", "check"]);
    assert!(!execs[1].ignore_failure);
}

#[test]
fn systemd_exec_parser_honours_an_empty_assignment_as_a_reset() {
    let unit =
        "[Service]\nExecStartPre=/usr/bin/vega check\nExecStartPre=\nExecStart=/usr/bin/vega\n";
    assert!(exec_lines_named(unit, "ExecStartPre").is_empty());
    assert_eq!(exec_lines_named(unit, "ExecStart").len(), 1);
}

#[test]
fn systemd_exec_parser_unquotes_and_expands_the_units_own_environment() {
    let unit = concat!(
        "[Service]\n",
        "Environment=CONF=/etc/vega/vega.toml\n",
        "ExecStart=/usr/bin/vega --config ${CONF} \"a b\" 'c d'\n",
    );
    let parsed = parse_unit(unit);
    assert_eq!(
        parsed.execs[0].argv,
        [
            "/usr/bin/vega",
            "--config",
            "/etc/vega/vega.toml",
            "a b",
            "c d"
        ]
    );
    // The same block is handed to the process we run, because systemd does.
    assert_eq!(
        parsed.env.get("CONF").map(String::as_str),
        Some("/etc/vega/vega.toml")
    );
}

#[test]
#[should_panic(expected = "cannot expand")]
fn systemd_exec_parser_refuses_to_guess_a_specifier() {
    // %i has no value outside a template unit. Substituting anything would test
    // a command systemd would never run.
    parse_exec_lines("[Service]\nExecStart=/usr/bin/vega --config /etc/vega/%i.toml\n");
}

#[test]
fn systemd_exec_parser_finds_the_config_argument_in_either_spelling() {
    let split = ["vega".to_string(), "--config".into(), "/a.toml".into()];
    let joined = ["vega".to_string(), "--config=/a.toml".into()];
    assert_eq!(config_argument(&split).as_deref(), Some("/a.toml"));
    assert_eq!(config_argument(&joined).as_deref(), Some("/a.toml"));
    assert_eq!(config_argument(&["vega".to_string()]), None);
}
