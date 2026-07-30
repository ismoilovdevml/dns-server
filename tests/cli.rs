//! End-to-end tests for the command-line interface.
//!
//! These run the real binary as a subprocess, so they cover argument parsing,
//! exit codes, file writes and JSON shape — the contract that scripts and agents
//! actually depend on, and none of which the library tests can see.

use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

use tempfile::TempDir;

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
