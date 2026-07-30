//! The command-line surface.
//!
//! Two audiences share it: a human running `dns-server record add www A 1.2.3.4`,
//! and a script or agent running the same thing with `--json` and reading the
//! result. Every subcommand therefore has a machine-readable mode, exits
//! non-zero on failure, and says exactly what it changed.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::config::GlobalArgs;

/// Config paths tried, in order, when `--config` is not given.
pub const CONFIG_SEARCH_PATH: [&str; 3] = [
    "dns-server.toml",
    "/etc/dns-server/dns-server.toml",
    "/usr/local/etc/dns-server/dns-server.toml",
];

/// `dns-server`.
#[derive(Parser, Debug)]
#[command(
    name = "dns-server",
    version,
    about = "Authoritative DNS server built on Hickory DNS",
    long_about = "Authoritative DNS server built on Hickory DNS.\n\n\
                  With no subcommand it runs the server. The other subcommands \
                  manage the zone in the config file and inspect a running \
                  instance, so the whole thing can be driven from scripts.",
    propagate_version = true,
    disable_help_subcommand = false
)]
pub struct Cli {
    /// What to do. Defaults to `serve`.
    #[command(subcommand)]
    pub command: Option<Command>,

    #[command(flatten)]
    pub global: GlobalArgs,
}

impl Cli {
    /// The config file to operate on.
    ///
    /// Uses `--config` if given, otherwise the first existing entry in
    /// [`CONFIG_SEARCH_PATH`]. Returns `None` when nothing is found, so callers
    /// can decide whether that is fatal.
    pub fn config_path(&self) -> Option<PathBuf> {
        if let Some(path) = &self.global.config {
            return Some(path.clone());
        }
        CONFIG_SEARCH_PATH
            .iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
    }
}

/// Top-level subcommands.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run the DNS server (the default).
    Serve,

    /// Parse the configuration, build the zone, report what it would serve.
    Check,

    /// Write a starter configuration file.
    Init {
        /// Zone this server will be authoritative for.
        #[arg(long, default_value = "example.com")]
        origin: String,
        /// Where to write it. Defaults to ./dns-server.toml.
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
    },

    /// Inspect and edit the records in the config file.
    Record {
        #[command(subcommand)]
        action: RecordAction,
    },

    /// Inspect the zone as a whole.
    Zone {
        #[command(subcommand)]
        action: ZoneAction,
    },

    /// Send a DNS query and print the answer. A small `dig`.
    Query {
        /// Name to look up.
        name: String,
        /// Record type. Case-insensitive.
        #[arg(default_value = "A")]
        record_type: String,
        /// Server to ask, as `host:port` or `host` (port 53). Defaults to the
        /// first configured UDP listener, then 127.0.0.1:53.
        #[arg(long, short = 's', value_name = "ADDR")]
        server: Option<String>,
        /// Send the query over TCP instead of UDP.
        ///
        /// Named `--use-tcp` because `--tcp` is the global listener flag.
        #[arg(long = "use-tcp")]
        use_tcp: bool,
    },

    /// Ask a running instance to re-read its config file.
    Reload,

    /// Report a running instance's health, version and traffic counters.
    Status,

    /// Probe `/healthz` and exit 0 (healthy) or 1 (not). For container probes.
    Healthcheck,

    /// Print a shell completion script.
    Completions {
        /// Shell to generate for.
        shell: clap_complete::Shell,
    },
}

/// `dns-server record ...`
#[derive(Subcommand, Debug)]
pub enum RecordAction {
    /// List record sets, optionally filtered.
    List {
        /// Only records with this owner name.
        #[arg(long, short = 'n')]
        name: Option<String>,
        /// Only records of this type.
        #[arg(long = "type", short = 'T', value_name = "TYPE")]
        record_type: Option<String>,
    },

    /// Show the record sets at one name.
    Get {
        /// Owner name, relative to the origin. `@` for the apex.
        name: String,
        /// Narrow to a single type.
        record_type: Option<String>,
    },

    /// Add values to a record set, creating it if needed.
    Add {
        /// Owner name, relative to the origin. `@` for the apex, `*.sub` for a wildcard.
        name: String,
        /// Record type, e.g. A, AAAA, CNAME, TXT, MX, NS, SRV, CAA.
        record_type: String,
        /// One or more values, in zone-file syntax (`"10 mail.example.com."`).
        #[arg(required = true)]
        values: Vec<String>,
        /// TTL for this record set. Falls back to the zone default.
        #[arg(long)]
        ttl: Option<u32>,
        /// Overwrite the existing values instead of appending to them.
        #[arg(long)]
        replace: bool,
        /// Bump the SOA serial after the edit.
        #[arg(long)]
        bump_serial: bool,
        /// Tell the running server to reload once the file is written.
        #[arg(long)]
        reload: bool,
    },

    /// Remove a record set, or specific values from one.
    Delete {
        /// Owner name, relative to the origin.
        name: String,
        /// Type to remove. Omit to remove every type at this name.
        record_type: Option<String>,
        /// Remove only these values, keeping the rest of the set.
        #[arg(long = "value", value_name = "VALUE")]
        values: Vec<String>,
        /// Bump the SOA serial after the edit.
        #[arg(long)]
        bump_serial: bool,
        /// Tell the running server to reload once the file is written.
        #[arg(long)]
        reload: bool,
    },
}

/// `dns-server zone ...`
#[derive(Subcommand, Debug)]
pub enum ZoneAction {
    /// Summarise the zone: origin, SOA, record and name counts.
    Show,

    /// Print the zone in BIND zone-file format, for diffing or importing.
    Export,

    /// Set the SOA serial to today's date plus a counter (`YYYYMMDDnn`).
    BumpSerial,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn cli_definition_is_valid() {
        // Catches duplicate short flags and other clap misconfiguration that
        // would otherwise only blow up at runtime.
        Cli::command().debug_assert();
    }

    #[test]
    fn no_subcommand_means_serve() {
        let cli = Cli::try_parse_from(["dns-server"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[test]
    fn global_flags_work_before_and_after_a_subcommand() {
        let before = Cli::try_parse_from(["dns-server", "--config", "a.toml", "check"]).unwrap();
        assert_eq!(before.global.config, Some(PathBuf::from("a.toml")));

        let after = Cli::try_parse_from(["dns-server", "check", "--config", "a.toml"]).unwrap();
        assert_eq!(after.global.config, Some(PathBuf::from("a.toml")));
    }

    #[test]
    fn record_add_takes_multiple_values() {
        let cli = Cli::try_parse_from([
            "dns-server",
            "record",
            "add",
            "www",
            "A",
            "203.0.113.1",
            "203.0.113.2",
            "--ttl",
            "60",
        ])
        .unwrap();

        let Some(Command::Record {
            action:
                RecordAction::Add {
                    name,
                    record_type,
                    values,
                    ttl,
                    replace,
                    ..
                },
        }) = cli.command
        else {
            panic!("expected record add");
        };
        assert_eq!(name, "www");
        assert_eq!(record_type, "A");
        assert_eq!(values, ["203.0.113.1", "203.0.113.2"]);
        assert_eq!(ttl, Some(60));
        assert!(!replace);
    }

    #[test]
    fn record_add_requires_at_least_one_value() {
        assert!(Cli::try_parse_from(["dns-server", "record", "add", "www", "A"]).is_err());
    }

    #[test]
    fn record_delete_collects_repeated_value_flags() {
        let cli = Cli::try_parse_from([
            "dns-server",
            "record",
            "delete",
            "www",
            "A",
            "--value",
            "203.0.113.1",
            "--value",
            "203.0.113.2",
        ])
        .unwrap();

        let Some(Command::Record {
            action: RecordAction::Delete { values, .. },
        }) = cli.command
        else {
            panic!("expected record delete");
        };
        assert_eq!(values, ["203.0.113.1", "203.0.113.2"]);
    }

    #[test]
    fn query_defaults_to_an_a_lookup() {
        let cli = Cli::try_parse_from(["dns-server", "query", "www.example.com"]).unwrap();
        let Some(Command::Query {
            record_type,
            use_tcp,
            ..
        }) = cli.command
        else {
            panic!("expected query");
        };
        assert_eq!(record_type, "A");
        assert!(!use_tcp);
    }

    #[test]
    fn json_flag_is_accepted_on_subcommands() {
        let cli = Cli::try_parse_from(["dns-server", "record", "list", "--json"]).unwrap();
        assert!(cli.global.json);
    }

    #[test]
    fn explicit_config_wins_over_the_search_path() {
        let cli = Cli::try_parse_from(["dns-server", "--config", "/tmp/custom.toml"]).unwrap();
        assert_eq!(cli.config_path(), Some(PathBuf::from("/tmp/custom.toml")));
    }
}
