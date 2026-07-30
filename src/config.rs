//! Configuration: command-line flags, an optional TOML file, and the validated
//! [`Config`] the rest of the process is built from.
//!
//! Precedence is the usual one — CLI flag beats environment variable beats file
//! beats built-in default. Everything is resolved and validated in
//! [`Config::load`] so that a bad config fails at startup rather than on the
//! first query.

use std::{
    collections::BTreeSet,
    fmt,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{bail, Context, Result};
use clap::{Args, ValueEnum};
use serde::Deserialize;

/// Default TTL handed to records that do not specify one.
pub const DEFAULT_TTL: u32 = 300;

/// Default idle timeout for TCP connections.
pub const DEFAULT_TCP_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-connection outgoing buffer size for TCP, in messages.
const TCP_RESPONSE_BUFFER: usize = 32;

/// Default log filter.
///
/// Hickory logs a line per request at INFO, which is a lot of volume for a busy
/// name server and duplicates our own per-query DEBUG line. Its warnings and
/// errors still come through. Raise it with `--log-level info` (or `RUST_LOG`)
/// when you want the library's view of a specific problem.
pub const DEFAULT_LOG_FILTER: &str = "info,hickory_server=warn,hickory_proto=warn";

/// How a log line is rendered.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, ValueEnum, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human readable, one line per event. Good for a terminal.
    #[default]
    Pretty,
    /// Newline-delimited JSON. Good for Loki / Elasticsearch / CloudWatch.
    Json,
}

/// Options shared by every subcommand.
#[derive(Args, Clone, Debug, Default)]
pub struct GlobalArgs {
    /// Path to a TOML configuration file holding the zone and its records.
    #[arg(
        long,
        short = 'c',
        env = "VEGA_CONFIG",
        value_name = "FILE",
        global = true
    )]
    pub config: Option<PathBuf>,

    /// UDP socket(s) to listen on. Repeat the flag for multiple addresses.
    #[arg(
        long,
        short = 'u',
        env = "VEGA_UDP",
        value_delimiter = ',',
        global = true
    )]
    pub udp: Vec<SocketAddr>,

    /// TCP socket(s) to listen on. Repeat the flag for multiple addresses.
    #[arg(
        long,
        short = 't',
        env = "VEGA_TCP",
        value_delimiter = ',',
        global = true
    )]
    pub tcp: Vec<SocketAddr>,

    /// Address for the admin HTTP server (`/healthz`, `/readyz`, `/metrics`).
    ///
    /// Bind this to a private interface — it is not authenticated.
    #[arg(long, env = "VEGA_ADMIN_LISTEN", value_name = "ADDR", global = true)]
    pub admin_listen: Option<SocketAddr>,

    /// Zone origin this server is authoritative for, e.g. `example.com`.
    #[arg(
        long,
        short = 'd',
        env = "VEGA_DOMAIN",
        value_name = "ZONE",
        global = true
    )]
    pub domain: Option<String>,

    /// Sustained queries per second allowed from a single source IP. `0` disables limiting.
    #[arg(long, env = "VEGA_RATE_LIMIT_QPS", value_name = "QPS", global = true)]
    pub rate_limit_qps: Option<u32>,

    /// Burst size for the per-IP rate limiter. Defaults to `2 * qps`.
    #[arg(long, env = "VEGA_RATE_LIMIT_BURST", value_name = "N", global = true)]
    pub rate_limit_burst: Option<u32>,

    /// Idle timeout for TCP connections, in seconds.
    #[arg(
        long,
        env = "VEGA_TCP_TIMEOUT_SECS",
        value_name = "SECS",
        global = true
    )]
    pub tcp_timeout_secs: Option<u64>,

    /// Disable the diagnostic `hello.` / `counter.` / `myip.` / `version.` sub-zones.
    #[arg(long, env = "VEGA_NO_BUILTINS", global = true)]
    pub no_builtins: bool,

    /// Log output format.
    #[arg(long, env = "VEGA_LOG_FORMAT", value_enum, global = true)]
    pub log_format: Option<LogFormat>,

    /// Log filter, in `RUST_LOG` syntax, e.g. `info,vega=debug`.
    #[arg(long, env = "VEGA_LOG_LEVEL", value_name = "FILTER", global = true)]
    pub log_level: Option<String>,

    /// Shared secret required by the mutating admin endpoints (`/reload`).
    ///
    /// When unset, those endpoints only accept requests from loopback.
    #[arg(
        long,
        env = "VEGA_ADMIN_TOKEN",
        value_name = "TOKEN",
        hide_env_values = true,
        global = true
    )]
    pub admin_token: Option<String>,

    /// Emit machine-readable JSON instead of human-readable text.
    #[arg(long, global = true)]
    pub json: bool,

    /// Show extra detail: full record values, timings, raw counters.
    #[arg(long, short = 'v', global = true)]
    pub verbose: bool,
}

/// The `[server]` table of the TOML file.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerSection {
    #[serde(default)]
    udp: Vec<SocketAddr>,
    #[serde(default)]
    tcp: Vec<SocketAddr>,
    admin_listen: Option<SocketAddr>,
    tcp_timeout_secs: Option<u64>,
    log_format: Option<LogFormat>,
    log_level: Option<String>,
    admin_token: Option<String>,
    #[serde(default)]
    rate_limit: RateLimitSection,
}

/// The `[server.rate_limit]` table.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RateLimitSection {
    qps: Option<u32>,
    burst: Option<u32>,
}

/// The `[zone]` table.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ZoneSection {
    origin: Option<String>,
    default_ttl: Option<u32>,
    builtins: Option<bool>,
    soa: Option<SoaSpec>,
    #[serde(default)]
    records: Vec<RecordSpec>,
}

/// A `[zone.soa]` table. Every field has an RFC 1912 friendly default.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoaSpec {
    /// Primary name server for the zone.
    pub mname: String,
    /// Mailbox of the zone administrator, in DNS form (`hostmaster.example.com.`).
    pub rname: String,
    /// Zone serial. Bump it whenever records change.
    #[serde(default = "default_serial")]
    pub serial: u32,
    /// Secondary refresh interval, seconds.
    #[serde(default = "default_refresh")]
    pub refresh: i32,
    /// Secondary retry interval, seconds.
    #[serde(default = "default_retry")]
    pub retry: i32,
    /// Secondary expiry, seconds.
    #[serde(default = "default_expire")]
    pub expire: i32,
    /// Negative-caching TTL, seconds. Also the TTL of the SOA record itself.
    #[serde(default = "default_minimum")]
    pub minimum: u32,
}

const fn default_serial() -> u32 {
    1
}
const fn default_refresh() -> i32 {
    3600
}
const fn default_retry() -> i32 {
    900
}
const fn default_expire() -> i32 {
    604_800
}
const fn default_minimum() -> u32 {
    60
}

/// One `[[zone.records]]` entry.
///
/// ```toml
/// [[zone.records]]
/// name = "@"          # "@" or "" is the zone apex; "*" and "*.dev" are wildcards
/// type = "A"
/// ttl = 60            # optional, falls back to zone.default_ttl
/// values = ["203.0.113.10", "203.0.113.11"]
/// ```
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordSpec {
    /// Owner name, relative to the zone origin. `@` or `""` means the apex.
    #[serde(default)]
    pub name: String,
    /// Record type, e.g. `A`, `AAAA`, `CNAME`, `TXT`, `MX`, `NS`, `SRV`, `CAA`.
    #[serde(rename = "type")]
    pub record_type: String,
    /// TTL override for this record set.
    pub ttl: Option<u32>,
    /// Presentation-format values, exactly as they would appear in a zone file.
    pub values: Vec<String>,
}

/// Everything the server needs, validated.
#[derive(Clone, Debug)]
pub struct Config {
    /// The config file this was loaded from, if any. `reload` re-reads it.
    pub source: Option<PathBuf>,
    /// UDP listen addresses. Never empty unless `tcp` is non-empty.
    pub udp: Vec<SocketAddr>,
    /// TCP listen addresses.
    pub tcp: Vec<SocketAddr>,
    /// Admin HTTP listen address, if enabled.
    pub admin_listen: Option<SocketAddr>,
    /// TCP idle timeout.
    pub tcp_timeout: Duration,
    /// Per-connection outgoing buffer size for TCP.
    pub tcp_response_buffer: usize,
    /// Zone configuration.
    pub zone: ZoneConfig,
    /// Rate limiter configuration, `None` when disabled.
    pub rate_limit: Option<RateLimitConfig>,
    /// Log rendering.
    pub log_format: LogFormat,
    /// Log filter directives.
    pub log_level: String,
    /// Bearer token required by the mutating admin endpoints, if configured.
    pub admin_token: Option<String>,
}

/// Validated zone configuration.
#[derive(Clone, Debug)]
pub struct ZoneConfig {
    /// Zone origin, as written by the operator (not yet a [`hickory_proto::rr::Name`]).
    pub origin: String,
    /// TTL applied to records without an explicit one.
    pub default_ttl: u32,
    /// Whether the diagnostic sub-zones are served.
    pub builtins: bool,
    /// Optional SOA definition.
    pub soa: Option<SoaSpec>,
    /// Static record sets.
    pub records: Vec<RecordSpec>,
}

/// Validated rate limiter configuration.
#[derive(Copy, Clone, Debug)]
pub struct RateLimitConfig {
    /// Sustained queries per second per source IP.
    pub qps: u32,
    /// Maximum burst.
    pub burst: u32,
}

impl Config {
    /// Build a [`Config`] from parsed CLI arguments, reading the TOML file if one
    /// was given.
    pub fn load(cli: &GlobalArgs) -> Result<Self> {
        let file = match &cli.config {
            Some(path) => Self::read_file(path)?,
            None => FileConfig::default(),
        };
        Self::merge(cli, file)
    }

    fn read_file(path: &Path) -> Result<FileConfig> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        toml::from_str(&raw).with_context(|| format!("parsing config file {}", path.display()))
    }

    fn merge(cli: &GlobalArgs, file: FileConfig) -> Result<Self> {
        let mut udp = pick_addrs(&cli.udp, &file.server.udp);
        let tcp = pick_addrs(&cli.tcp, &file.server.tcp);

        // A DNS server with no listener is a no-op; default to the conventional
        // unprivileged port so `cargo run` does something useful.
        if udp.is_empty() && tcp.is_empty() {
            udp.push(
                "0.0.0.0:1053"
                    .parse()
                    .expect("literal is a valid SocketAddr"),
            );
        }
        reject_duplicates("udp", &udp)?;
        reject_duplicates("tcp", &tcp)?;

        let origin = cli
            .domain
            .clone()
            .or(file.zone.origin)
            .unwrap_or_else(|| "dnsserver.dev".to_owned());
        if origin.trim().is_empty() {
            bail!("zone origin must not be empty");
        }

        let default_ttl = file.zone.default_ttl.unwrap_or(DEFAULT_TTL);
        if default_ttl == 0 {
            bail!("zone.default_ttl must be greater than 0");
        }

        let builtins = if cli.no_builtins {
            false
        } else {
            file.zone.builtins.unwrap_or(true)
        };

        let tcp_timeout = cli
            .tcp_timeout_secs
            .or(file.server.tcp_timeout_secs)
            .map_or(Ok(DEFAULT_TCP_TIMEOUT), |secs| {
                if secs == 0 {
                    bail!("tcp_timeout_secs must be greater than 0");
                }
                Ok(Duration::from_secs(secs))
            })?;

        let qps = cli.rate_limit_qps.or(file.server.rate_limit.qps);
        let rate_limit = match qps {
            None | Some(0) => None,
            Some(qps) => {
                let burst = cli
                    .rate_limit_burst
                    .or(file.server.rate_limit.burst)
                    .unwrap_or_else(|| qps.saturating_mul(2));
                if burst == 0 {
                    bail!("rate_limit.burst must be greater than 0 when qps is set");
                }
                Some(RateLimitConfig { qps, burst })
            }
        };

        Ok(Self {
            source: cli.config.clone(),
            udp,
            tcp,
            admin_listen: cli.admin_listen.or(file.server.admin_listen),
            tcp_timeout,
            tcp_response_buffer: TCP_RESPONSE_BUFFER,
            zone: ZoneConfig {
                origin,
                default_ttl,
                builtins,
                soa: file.zone.soa,
                records: file.zone.records,
            },
            rate_limit,
            log_format: cli
                .log_format
                .or(file.server.log_format)
                .unwrap_or_default(),
            log_level: cli
                .log_level
                .clone()
                .or(file.server.log_level)
                .unwrap_or_else(|| DEFAULT_LOG_FILTER.to_owned()),
            admin_token: cli.admin_token.clone().or(file.server.admin_token),
        })
    }
}

/// A short, operator-facing summary of the effective configuration.
impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "zone            : {}", self.zone.origin)?;
        writeln!(f, "record sets     : {}", self.zone.records.len())?;
        writeln!(f, "default ttl     : {}s", self.zone.default_ttl)?;
        writeln!(f, "builtins        : {}", self.zone.builtins)?;
        writeln!(f, "udp listeners   : {}", join_addrs(&self.udp))?;
        writeln!(f, "tcp listeners   : {}", join_addrs(&self.tcp))?;
        writeln!(
            f,
            "admin listener  : {}",
            self.admin_listen
                .map_or_else(|| "disabled".to_owned(), |a| a.to_string())
        )?;
        writeln!(
            f,
            "rate limit      : {}",
            self.rate_limit.map_or_else(
                || "disabled".to_owned(),
                |r| format!("{} qps / burst {} per source IP", r.qps, r.burst)
            )
        )?;
        write!(
            f,
            "log             : {:?} @ {}",
            self.log_format, self.log_level
        )
    }
}

/// Raw, unvalidated file contents.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    #[serde(default)]
    server: ServerSection,
    #[serde(default)]
    zone: ZoneSection,
}

fn pick_addrs(cli: &[SocketAddr], file: &[SocketAddr]) -> Vec<SocketAddr> {
    if cli.is_empty() {
        file.to_vec()
    } else {
        cli.to_vec()
    }
}

fn reject_duplicates(what: &str, addrs: &[SocketAddr]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for addr in addrs {
        if !seen.insert(addr) {
            bail!("duplicate {what} listen address: {addr}");
        }
    }
    Ok(())
}

fn join_addrs(addrs: &[SocketAddr]) -> String {
    if addrs.is_empty() {
        return "none".to_owned();
    }
    addrs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;

    /// GlobalArgs is a clap `Args` group, so it needs a `Parser` to be reached.
    #[derive(clap::Parser)]
    struct TestCli {
        #[command(flatten)]
        global: GlobalArgs,
    }

    fn cli(args: &[&str]) -> GlobalArgs {
        let mut full = vec!["vega"];
        full.extend_from_slice(args);
        TestCli::try_parse_from(full)
            .expect("args should parse")
            .global
    }

    #[test]
    fn defaults_bind_the_unprivileged_udp_port() {
        let cfg = Config::merge(&cli(&[]), FileConfig::default()).unwrap();
        assert_eq!(cfg.udp, vec!["0.0.0.0:1053".parse::<SocketAddr>().unwrap()]);
        assert!(cfg.tcp.is_empty());
        assert_eq!(cfg.zone.origin, "dnsserver.dev");
        assert_eq!(cfg.zone.default_ttl, DEFAULT_TTL);
        assert!(cfg.zone.builtins);
        assert!(cfg.rate_limit.is_none());
    }

    #[test]
    fn cli_overrides_file() {
        let file: FileConfig = toml::from_str(
            r#"
            [server]
            udp = ["127.0.0.1:5300"]
            log_level = "debug"

            [zone]
            origin = "from-file.test"
            "#,
        )
        .unwrap();

        let cfg = Config::merge(
            &cli(&["--udp", "127.0.0.1:5301", "--domain", "from-cli.test"]),
            file,
        )
        .unwrap();

        assert_eq!(
            cfg.udp,
            vec!["127.0.0.1:5301".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(cfg.zone.origin, "from-cli.test");
        // Not overridden on the CLI, so the file value survives.
        assert_eq!(cfg.log_level, "debug");
    }

    #[test]
    fn burst_defaults_to_twice_qps() {
        let cfg = Config::merge(&cli(&["--rate-limit-qps", "25"]), FileConfig::default()).unwrap();
        let rl = cfg.rate_limit.expect("rate limiting should be enabled");
        assert_eq!(rl.qps, 25);
        assert_eq!(rl.burst, 50);
    }

    #[test]
    fn zero_qps_disables_rate_limiting() {
        let cfg = Config::merge(&cli(&["--rate-limit-qps", "0"]), FileConfig::default()).unwrap();
        assert!(cfg.rate_limit.is_none());
    }

    #[test]
    fn duplicate_listeners_are_rejected() {
        let err = Config::merge(
            &cli(&["--udp", "127.0.0.1:5300", "--udp", "127.0.0.1:5300"]),
            FileConfig::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("duplicate udp"), "{err}");
    }

    #[test]
    fn zero_ttl_is_rejected() {
        let file: FileConfig = toml::from_str("[zone]\ndefault_ttl = 0\n").unwrap();
        let err = Config::merge(&cli(&[]), file).unwrap_err();
        assert!(err.to_string().contains("default_ttl"), "{err}");
    }

    #[test]
    fn unknown_file_keys_are_rejected() {
        let err = toml::from_str::<FileConfig>("[server]\nudpp = []\n").unwrap_err();
        assert!(err.to_string().contains("udpp"), "{err}");
    }

    #[test]
    fn no_builtins_flag_wins_over_file() {
        let file: FileConfig = toml::from_str("[zone]\nbuiltins = true\n").unwrap();
        let cfg = Config::merge(&cli(&["--no-builtins"]), file).unwrap();
        assert!(!cfg.zone.builtins);
    }

    #[test]
    fn records_round_trip_from_toml() {
        let file: FileConfig = toml::from_str(
            r#"
            [zone]
            origin = "example.com"

            [[zone.records]]
            name = "@"
            type = "A"
            values = ["203.0.113.10"]

            [[zone.records]]
            name = "www"
            type = "CNAME"
            ttl = 900
            values = ["example.com."]
            "#,
        )
        .unwrap();

        let cfg = Config::merge(&cli(&[]), file).unwrap();
        assert_eq!(cfg.zone.records.len(), 2);
        assert_eq!(cfg.zone.records[1].ttl, Some(900));
    }

    // -----------------------------------------------------------------------
    // Regression tests from mutation testing.
    // -----------------------------------------------------------------------

    #[test]
    fn soa_defaults_follow_rfc_1912() {
        // Kills every `default_serial / default_refresh / default_retry /
        // default_expire / default_minimum -> 0 | 1 | -1` mutant. These values
        // end up on the wire in the SOA and drive secondary and negative-cache
        // behaviour, and nothing asserted on any of them.
        let file: FileConfig = toml::from_str(
            r#"
            [zone]
            origin = "example.com"

            [zone.soa]
            mname = "ns1.example.com."
            rname = "hostmaster.example.com."
            "#,
        )
        .unwrap();
        let cfg = Config::merge(&cli(&[]), file).unwrap();
        let soa = cfg.zone.soa.expect("soa parsed");
        assert_eq!(soa.serial, 1);
        assert_eq!(soa.refresh, 3600);
        assert_eq!(soa.retry, 900);
        assert_eq!(soa.expire, 604_800);
        assert_eq!(soa.minimum, 60);
    }

    #[test]
    fn a_zero_tcp_timeout_is_rejected() {
        // Kills `secs == 0` -> `secs != 0` in the tcp_timeout branch.
        let err =
            Config::merge(&cli(&["--tcp-timeout-secs", "0"]), FileConfig::default()).unwrap_err();
        assert!(err.to_string().contains("tcp_timeout_secs"), "{err}");
    }

    #[test]
    fn a_non_zero_tcp_timeout_is_taken_verbatim() {
        let cfg =
            Config::merge(&cli(&["--tcp-timeout-secs", "45"]), FileConfig::default()).unwrap();
        assert_eq!(cfg.tcp_timeout, Duration::from_secs(45));
        // And the default when nothing is set.
        let cfg = Config::merge(&cli(&[]), FileConfig::default()).unwrap();
        assert_eq!(cfg.tcp_timeout, DEFAULT_TCP_TIMEOUT);
    }

    #[test]
    fn the_summary_names_the_zone_and_every_listener() {
        // Kills `Display::fmt -> Ok(())` and `join_addrs -> String::new() |
        // "xyzzy"`. This text is what an operator reads from `vega check`
        // before restarting a name server.
        let cfg = Config::merge(
            &cli(&[
                "--domain",
                "example.test",
                "--udp",
                "127.0.0.1:5300",
                "--udp",
                "127.0.0.1:5301",
                "--rate-limit-qps",
                "25",
            ]),
            FileConfig::default(),
        )
        .unwrap();

        let text = cfg.to_string();
        assert!(text.contains("example.test"), "{text}");
        assert!(text.contains("127.0.0.1:5300, 127.0.0.1:5301"), "{text}");
        assert!(text.contains("25 qps / burst 50"), "{text}");
        assert!(text.contains("default ttl     : 300s"), "{text}");
    }

    #[test]
    fn the_summary_says_none_when_a_transport_has_no_listener() {
        let cfg = Config::merge(&cli(&[]), FileConfig::default()).unwrap();
        let text = cfg.to_string();
        assert!(text.contains("tcp listeners   : none"), "{text}");
        assert!(text.contains("admin listener  : disabled"), "{text}");
        assert!(text.contains("rate limit      : disabled"), "{text}");
    }
}
