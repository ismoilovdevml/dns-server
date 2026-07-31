Feature: Configuration precedence and validation
  # WHY THIS MATTERS
  # Precedence is what an operator relies on at three in the morning: the ability
  # to override one setting on the command line without editing a file they do
  # not fully trust, and the certainty that the override actually wins. Get it
  # backwards and the emergency flag silently does nothing. Get it partially
  # right — CLI beating the file but the environment silently beating both — and
  # a container inherits a stale VEGA_DOMAIN from its orchestrator and starts
  # serving the wrong zone.
  #
  # Validation matters for a different reason: everything is resolved and checked
  # in Config::load so that a bad configuration fails at startup rather than on
  # the first query. A name server that starts happily and then answers wrongly
  # is far more damaging than one that refuses to start.
  #
  # Implementation: src/config.rs (GlobalArgs clap definitions with `env`,
  #                 Config::merge, reject_duplicates)
  #                 src/cli.rs (CONFIG_SEARCH_PATH, Cli::config_path)
  #
  # ORDER UNDER TEST: CLI flag > environment variable > config file > default.
  # The CLI-vs-env half is resolved by clap (`#[arg(env = "...")]`); the
  # flag-or-env vs file half is resolved by Config::merge.

  # ------------------------------------------------- CLI BEATS FILE

  @happy @enforced src/config.rs:505
  Scenario: A CLI listener address overrides the one in the file
    Given a config file setting udp to 127.0.0.1:5300
    When the command line passes --udp 127.0.0.1:5301
    Then the effective udp listeners are 127.0.0.1:5301 only

  @happy @enforced src/config.rs:505
  Scenario: A CLI domain overrides the origin in the file
    Given a config file setting zone origin to "from-file.test"
    When the command line passes --domain "from-cli.test"
    Then the effective origin is "from-cli.test"

  @happy @enforced src/config.rs:505
  Scenario: A file setting not overridden on the command line survives
    Given a config file setting log_level to "debug"
    When the command line passes only --udp and --domain
    Then the effective log level is "debug"

  @happy @enforced src/config.rs:571
  Scenario: The no-builtins flag overrides a file that enables built-ins
    Given a config file setting zone builtins to true
    When the command line passes --no-builtins
    Then built-ins are disabled

  @boundary @gap
  Scenario: A CLI admin listener overrides the one in the file
    # `cli.admin_listen.or(file.server.admin_listen)`. Untested.
    Given a config file setting admin_listen to 127.0.0.1:9100
    When the command line passes --admin-listen 127.0.0.1:9999
    Then the effective admin listener is 127.0.0.1:9999

  @boundary @gap
  Scenario: A CLI TCP timeout overrides the one in the file
    Given a config file setting tcp_timeout_secs to 30
    When the command line passes --tcp-timeout-secs 5
    Then the effective TCP idle timeout is 5 seconds

  @boundary @gap
  Scenario: A CLI rate limit overrides the one in the file
    Given a config file setting rate_limit qps to 10
    When the command line passes --rate-limit-qps 100
    Then the effective qps is 100

  @boundary @gap
  Scenario: A CLI admin token overrides the one in the file
    # The security-relevant one: an operator rotating a token on the command line
    # must not be silently served the file's stale value.
    Given a config file setting admin_token to "old"
    When the command line passes --admin-token "new"
    Then the effective admin token is "new"

  @boundary @gap
  Scenario: A CLI log format overrides the one in the file
    Given a config file setting log_format to json
    When the command line passes --log-format pretty
    Then the effective log format is pretty

  @boundary @gap
  Scenario: A CLI TCP listener overrides the one in the file
    # pick_addrs applies to tcp identically to udp, but only udp is tested.
    Given a config file setting tcp to 127.0.0.1:5300
    When the command line passes --tcp 127.0.0.1:5301
    Then the effective tcp listeners are 127.0.0.1:5301 only

  @boundary @gap
  Scenario: A CLI listener list replaces the file list rather than appending to it
    # pick_addrs returns the CLI list wholesale when it is non-empty. An operator
    # who expects union semantics would be exposing a listener they did not mean
    # to; one who expects replacement would be missing one they did.
    Given a config file setting udp to two addresses
    When the command line passes one --udp address
    Then the effective udp listeners are exactly the one from the command line

  # ------------------------------------------------- ENV BEATS FILE

  @boundary @gap
  Scenario: An environment variable overrides the config file
    # Every GlobalArgs field carries `env = "DNS_..."`, so clap materialises the
    # environment value into the same Option the flag would fill, which then
    # beats the file. NOTHING in the entire suite sets any DNS_* variable — the
    # env half of the documented precedence chain is completely unenforced.
    Given a config file setting zone origin to "from-file.test"
    And the environment sets VEGA_DOMAIN to "from-env.test"
    When the configuration is resolved
    Then the effective origin is "from-env.test"

  @hostile @enforced tests/reload.rs:624
  Scenario: A reload keeps an origin supplied by the environment
    # The env tier must survive a reload for the same reason the CLI tier must.
    # Re-reading std::env at reload would be a fiction anyway: editing a systemd
    # EnvironmentFile does not touch a live process's environment, and calling
    # setenv from a worker thread is the data race Rust marks unsafe — which
    # `unsafe_code = "forbid"` rules out regardless. The already-parsed GlobalArgs
    # is frozen instead.
    Given a config file setting zone origin to "from-the-file.test"
    And the environment sets VEGA_DOMAIN to "from-the-env.test"
    When a loopback caller posts to /reload
    Then the response status is 200
    And the effective origin is still "from-the-env.test"

  @boundary @gap
  Scenario: A CLI flag overrides an environment variable
    Given the environment sets VEGA_DOMAIN to "from-env.test"
    When the command line passes --domain "from-cli.test"
    Then the effective origin is "from-cli.test"

  @boundary @gap
  Scenario: VEGA_CONFIG selects the config file when no --config is given
    # tests/cli.rs deliberately env_remove("VEGA_CONFIG") in every run, so the
    # variable's effect is never observed.
    Given the environment sets VEGA_CONFIG to a specific file
    When a record command runs with no --config
    Then that file is the one edited

  @boundary @gap
  Scenario: VEGA_ADMIN_TOKEN supplies the admin token
    Given the environment sets VEGA_ADMIN_TOKEN to "s3cret"
    When the configuration is resolved
    Then the effective admin token is "s3cret"

  @boundary @gap
  Scenario: VEGA_UDP accepts a comma-separated list
    # value_delimiter = ',' applies to the env var as well as the flag.
    Given the environment sets VEGA_UDP to "127.0.0.1:5300,127.0.0.1:5301"
    When the configuration is resolved
    Then there are 2 udp listeners

  @boundary @gap
  Scenario: RUST_LOG overrides the resolved log level
    # src/main.rs:469 tries EnvFilter::try_from_default_env() first and warns when
    # RUST_LOG is set. Untested; init_tracing is entirely uncovered.
    Given the configuration resolves a log level of "info"
    And the environment sets RUST_LOG to "trace"
    When tracing is initialised
    Then the trace filter is used
    And a warning notes that RUST_LOG overrides --log-level

  # -------------------------------------- ONE PRECEDENCE IMPLEMENTATION
  #
  # VEGA-005 group B. `reload_hook` must hold no precedence logic of its own: it
  # calls Config::load against the frozen startup invocation — the same function
  # serve_command calls — and then compares. One precedence implementation, or the
  # two paths drift again, which is exactly how VEGA-005 happened. These are the
  # structural guarantees; the behavioural ones live in features/live-reload.feature.

  @hostile @enforced tests/reload.rs:676
  Scenario: A reloaded server and a freshly started server resolve the same config
    # Differential, not tautological: one process is reloaded and the other is
    # started fresh from the identical invocation and file, and the two are then
    # compared through every channel the effective config is observable on. A
    # precedence rule added to only one path changes one of them and fails this.
    Given an invocation and a config file that disagree about every setting
    When one server is started from them and reloaded
    And a second server is started from them and not reloaded
    Then the two resolve the same origin, records, built-ins, token and answers

  @hostile @enforced tests/reload.rs:733
  Scenario: No serving code resolves a configuration from a default invocation
    # GlobalArgs::default() is not a neutral element. Config::merge treats an
    # absent CLI value as "fall through to the file, then to the hardcoded
    # default" at src/config.rs:338, so feeding it default() does not merely lose
    # the flags — it silently selects a different zone. Test code may build one;
    # serving code may not.
    Given the serving code under src/, with its #[cfg(test)] modules excluded
    When it is scanned for GlobalArgs::default()
    Then there is no occurrence

  @boundary @enforced tests/reload.rs:761
  Scenario: Every configuration field is classified reloadable or fixed
    # The ruling's partition table, made executable. The test destructures Config
    # exhaustively, so adding a field is a compile error until it is classified
    # and a reload scenario covers it.
    Given the Config struct
    When every field is enumerated
    Then each one is reloadable, fixed for the process lifetime, or not operator-settable

  # ------------------------------------------------ FILE BEATS DEFAULT

  @happy @enforced src/config.rs:578
  Scenario: Records declared in the file are loaded
    Given a config file declaring 2 record sets
    When the configuration is resolved
    Then 2 record sets are loaded

  @happy @enforced src/config.rs:578
  Scenario: A per-record TTL in the file is preserved through resolution
    Given a config file declaring a record with ttl 900
    When the configuration is resolved
    Then that record's TTL is 900

  @boundary @gap
  Scenario: A default TTL in the file overrides the built-in default
    # There is no CLI flag for default_ttl; the file is the only source above the
    # DEFAULT_TTL constant. Only the rejection of 0 is tested, never a successful
    # override.
    Given a config file setting zone default_ttl to 60
    When the configuration is resolved
    Then the effective default TTL is 60

  @boundary @gap
  Scenario: A file that disables built-ins is honoured without any flag
    # `file.zone.builtins.unwrap_or(true)` — the false-from-file path is untested.
    Given a config file setting zone builtins to false
    When the configuration is resolved
    Then built-ins are disabled

  @boundary @gap
  Scenario: A file-supplied SOA is carried into the zone configuration
    Given a config file with a [zone.soa] table
    When the configuration is resolved
    Then the zone configuration carries that SOA

  # ------------------------------------------------------------ DEFAULTS

  @happy @enforced src/config.rs:494
  Scenario: With no configuration at all the server binds the unprivileged UDP port
    When the configuration is resolved from nothing
    Then the effective udp listeners are 0.0.0.0:1053
    And there are no tcp listeners

  @happy @enforced src/config.rs:494
  Scenario: The default zone origin is dnsserver.dev
    When the configuration is resolved from nothing
    Then the effective origin is "dnsserver.dev"

  @happy @enforced src/config.rs:494
  Scenario: The default TTL is 300 seconds
    When the configuration is resolved from nothing
    Then the effective default TTL is 300

  @happy @enforced src/config.rs:494
  Scenario: Built-ins are enabled by default
    When the configuration is resolved from nothing
    Then built-ins are enabled

  @happy @enforced src/config.rs:494
  Scenario: Rate limiting is disabled by default
    When the configuration is resolved from nothing
    Then no rate limiter is configured

  @boundary @gap
  Scenario: The default TCP idle timeout is 10 seconds
    Given no tcp_timeout_secs anywhere
    When the configuration is resolved
    Then the effective TCP idle timeout is 10 seconds

  @boundary @gap
  Scenario: The default log filter quietens the Hickory request log
    # DEFAULT_LOG_FILTER exists specifically so a busy name server does not log a
    # line per request at INFO. Nothing asserts the default is applied.
    When the configuration is resolved from nothing
    Then the effective log level is "info,hickory_server=warn,hickory_proto=warn"

  @boundary @gap
  Scenario: The default log format is pretty
    When the configuration is resolved from nothing
    Then the effective log format is pretty

  @boundary @gap
  Scenario: The admin listener is disabled by default
    # No admin listener means no /metrics and no /readyz. Worth pinning so the
    # default is a decision rather than an accident.
    When the configuration is resolved from nothing
    Then no admin listener is configured

  @boundary @gap
  Scenario: A file that sets only TCP listeners does not get the default UDP listener
    # The `if udp.is_empty() && tcp.is_empty()` guard. A regression that added the
    # default UDP listener anyway would silently open a port the operator did not
    # ask for.
    Given a config file setting only tcp listeners
    When the configuration is resolved
    Then there are no udp listeners

  # ---------------------------------------------------------- CONFIG SEARCH

  @happy @enforced tests/cli.rs:101
  Scenario: A config file in the working directory is discovered without --config
    Given a workspace containing vega.toml
    When `vega zone show --json` runs with no --config
    Then the origin from that file is reported

  @happy @enforced src/cli.rs:314
  Scenario: An explicit --config wins over the search path
    When --config /tmp/custom.toml is given
    Then the resolved config path is /tmp/custom.toml

  @happy @enforced tests/cli.rs:488
  Scenario: A global flag is accepted before the subcommand
    Given a workspace
    When --config is given before the subcommand
    Then the command succeeds

  @happy @enforced tests/cli.rs:488
  Scenario: A global flag is accepted after the subcommand
    Given a workspace
    When --config is given after the subcommand
    Then the command succeeds
    And the result matches the flag-before form

  @empty @enforced tests/cli.rs:110
  Scenario: No config file anywhere on the search path is an error naming the paths tried
    Given a directory with no config file
    When a record command runs
    Then the process exits non-zero
    And stderr names the search path

  @boundary @gap
  Scenario: The search path is tried in order
    # CONFIG_SEARCH_PATH puts ./vega.toml ahead of /etc. Nothing asserts the
    # ordering, so a reordering would silently pick up a system-wide config in
    # preference to the operator's local one.
    Given both ./vega.toml and the system path exist
    When the config path is resolved
    Then ./vega.toml is chosen

  @empty @enforced src/cli.rs:213
  Scenario: No subcommand means serve
    When `vega` runs with no subcommand
    Then the parsed command is none and serve is selected

  # ------------------------------------------------------------ VALIDATION

  @malformed @enforced src/config.rs:548
  Scenario: A duplicate UDP listener address is rejected
    When the command line passes the same --udp address twice
    Then the configuration is rejected with an error mentioning "duplicate udp"

  @malformed @gap
  Scenario: A duplicate TCP listener address is rejected
    # reject_duplicates is called for tcp too, and that call is untested. Two
    # binds of the same TCP address fail at bind time with a much worse error.
    When the command line passes the same --tcp address twice
    Then the configuration is rejected with an error mentioning "duplicate tcp"

  @malformed @enforced src/config.rs:558
  Scenario: A zero default TTL is rejected
    Given a config file setting zone default_ttl to 0
    When the configuration is resolved
    Then the configuration is rejected with an error mentioning "default_ttl"

  @malformed @gap
  Scenario: An empty zone origin is rejected
    # src/config.rs:335 bails. The line is uncovered. An empty origin would build
    # a zone that matches nothing and refuses every query.
    Given a config file setting zone origin to "   "
    When the configuration is resolved
    Then the configuration is rejected with an error mentioning "origin"

  @malformed @gap
  Scenario: A zero TCP timeout is rejected
    # src/config.rs:353-356. Uncovered.
    Given a config file setting tcp_timeout_secs to 0
    When the configuration is resolved
    Then the configuration is rejected with an error mentioning "tcp_timeout_secs"

  @malformed @gap
  Scenario: A zero burst alongside a non-zero qps is rejected
    # src/config.rs:368. Uncovered.
    Given a config file setting rate_limit qps to 10 and burst to 0
    When the configuration is resolved
    Then the configuration is rejected with an error mentioning "burst"

  @malformed @enforced src/config.rs:565
  Scenario: An unknown key in the config file is rejected rather than ignored
    # serde(deny_unknown_fields). A silently ignored typo in a security setting
    # is the worst possible failure mode.
    Given a config file containing the key "udpp"
    When the file is parsed
    Then parsing fails with an error naming "udpp"

  @malformed @gap
  Scenario: An unknown key inside [zone] is rejected
    # ZoneSection also denies unknown fields, but only [server] is tested.
    Given a config file containing the key "originn" under [zone]
    When the file is parsed
    Then parsing fails with an error naming "originn"

  @malformed @gap
  Scenario: An unknown key inside a record entry is rejected
    Given a config file containing the key "valuess" in a record entry
    When the file is parsed
    Then parsing fails with an error naming "valuess"

  @malformed @gap
  Scenario: A record entry missing its type is rejected
    # RecordSpec.record_type has no serde default, so it is required.
    Given a config file with a record entry that has no type
    When the file is parsed
    Then parsing fails

  @malformed @gap
  Scenario: An SOA table missing mname is rejected
    # SoaSpec.mname and .rname have no defaults; every other field does.
    Given a config file with a [zone.soa] table that has no mname
    When the file is parsed
    Then parsing fails

  @boundary @gap
  Scenario: An SOA table with only mname and rname takes RFC 1912 defaults
    # serial 1, refresh 3600, retry 900, expire 604800, minimum 60. The default
    # functions at src/config.rs:205-219 are uncovered.
    Given a config file with a [zone.soa] table declaring only mname and rname
    When the file is parsed
    Then the serial is 1
    And the minimum is 60

  @malformed @gap
  Scenario: A config file that cannot be read is reported with its path
    # src/config.rs:308-310 contexts "reading config file <path>". Untested at the
    # Config layer.
    Given --config pointing at a file that does not exist
    When the configuration is resolved
    Then the error names the file path

  @malformed @gap
  Scenario: A config file that is not valid TOML is reported with its path
    Given --config pointing at a file of unparseable TOML
    When the configuration is resolved
    Then the error mentions "parsing config file"

  @empty @gap
  Scenario: A completely empty config file resolves to the built-in defaults
    # FileConfig derives Default with #[serde(default)] on both sections.
    Given a config file that is empty
    When the configuration is resolved
    Then the effective origin is "dnsserver.dev"

  @hostile @enforced src/cli.rs:206
  Scenario: The command-line definition has no conflicting flags
    # debug_assert catches duplicate short flags, which would otherwise surface as
    # a runtime panic on a machine that is trying to serve DNS.
    When the CLI definition is asserted
    Then it is internally consistent

  @hostile @enforced tests/cli.rs:366
  Scenario: A startup failure does not echo the admin_token line
    # VEGA-082's reproduction was this path, not /reload: `vega serve` on a
    # config whose admin_token line will not parse printed the line, secret and
    # all, to the terminal and the journal. Both renderings are covered — prose
    # on stderr and --json on stdout — because each is a separate way out.
    Given a config file whose admin_token line is not valid TOML
    When `vega serve`, `vega serve --json` or `vega check` runs
    Then the process exits non-zero
    And the output does not contain the token
    And the output still names the line the parser stopped at

  @hostile @gap
  Scenario: The admin token is never printed in help output
    # hide_env_values = true on --admin-token. Nothing asserts a secret cannot
    # leak into a help dump or a log line.
    When `vega --help` runs
    Then the output does not contain any token value

  @hostile @enforced tests/cli.rs:438
  Scenario: No command echoes the admin_token line from a broken config
    # VEGA-089, the sibling of the scenario above. VEGA-082 fixed the two
    # commands that parse through Config::read_file; every editing command parses
    # the same file with toml_edit, a second crate with its own Display, and went
    # on printing the line. The list is exhaustive on purpose — the defect was
    # never "this one command", it was "the redaction was not at a chokepoint".
    Given a config file whose admin_token line is not valid TOML
    When any of `vega check`, `serve`, `record list`, `record get`, `record add`,
      `record delete`, `zone show`, `zone export` or `zone bump-serial` runs,
      with and without --json
    Then the process exits non-zero
    And the output does not contain the token
    And the output still names the line and column the parser stopped at

  @hostile @enforced tests/single_gate.rs:145
  Scenario: A new call site cannot render a raw TOML parse error
    # The property, not the instance: this one is checked against the source
    # rather than against the output, because the bug was that a *second* call
    # site existed at all. src/tomlparse.rs is the only module that may name a
    # TOML parser, and clippy.toml refuses the same paths at compile time.
    Given the crate's own source under src/
    When the single-gate rules are checked
    Then no module but src/tomlparse.rs names a TOML parser or its error type
    And no module but src/rdata.rs names hickory's presentation-format parser
