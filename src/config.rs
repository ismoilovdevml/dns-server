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

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, ValueEnum};
use serde::Deserialize;

use crate::tomlparse;

/// Default TTL handed to records that do not specify one.
pub const DEFAULT_TTL: u32 = 300;

/// Default idle timeout for TCP connections.
pub const DEFAULT_TCP_TIMEOUT: Duration = Duration::from_secs(10);

/// Default seconds to keep answering DNS after `SIGTERM` while `/readyz` says 503.
///
/// Derived in `.claude/backlog/decisions/VEGA-046-shutdown-drain.md` §2.2:
/// readiness observation (7s = probe period 2 × (threshold 2 + 1) + timeout 1)
/// plus kube-proxy propagation (5s), and at least the TCP idle timeout (10s) so
/// idle keep-alive connections are closed by their own timeout — cleanly, from
/// the read side — rather than by the process exiting.
pub const DEFAULT_SHUTDOWN_DRAIN: Duration = Duration::from_secs(15);

/// Upper bound on the configurable drain.
///
/// Beyond five minutes the value is a typo (`1500` for `15`) and it exceeds
/// every grace period a sane deployment sets, so the only outcome is a
/// guaranteed `SIGKILL`. Refusing it at startup is cheaper than discovering it
/// during a rollout.
pub const MAX_SHUTDOWN_DRAIN: Duration = Duration::from_secs(300);

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

    /// Seconds to keep answering DNS after `SIGTERM` while `/readyz` reports 503.
    ///
    /// `0` runs the same shutdown sequence with no waiting, which is what CI and
    /// `cargo run` want. The maximum is 300.
    #[arg(
        long,
        env = "VEGA_SHUTDOWN_DRAIN_SECS",
        value_name = "SECS",
        global = true
    )]
    pub shutdown_drain_secs: Option<u64>,

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
    /// Signed, so `-1` is rejected by the range check with a message naming the
    /// setting, rather than by the deserializer with one that names a type an
    /// operator never wrote.
    shutdown_drain_secs: Option<i64>,
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
    /// How long to keep answering DNS after a `SIGTERM`, while `/readyz`
    /// reports 503 so a load balancer can take us out of rotation first.
    pub shutdown_drain: Duration,
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

/// Which step of [`Config::resolve`] failed.
///
/// A reload has to tell an operator *which* runbook applies — a missing file is
/// restored, a syntax error is edited, a rejected value is corrected — and the
/// three are indistinguishable once the error has been flattened to a string.
/// Keeping the stage lets [`crate::reload`] name a stable machine-readable code
/// without pattern-matching on prose.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LoadStage {
    /// The file could not be read at all: deleted, unreadable, mid-rename.
    Read,
    /// The bytes are not valid TOML, or carry a key the schema does not know.
    Parse,
    /// Parsed, but rejected by `Config::merge`: empty origin, zero TTL, …
    Validate,
}

/// A configuration failure, tagged with the stage that produced it.
#[derive(Debug)]
pub struct LoadError {
    /// Where in the pipeline it went wrong.
    pub stage: LoadStage,
    /// The underlying error, with its `.context` chain intact.
    pub error: anyhow::Error,
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The alternate form prints the whole context chain, which is what names
        // the offending file and value.
        write!(f, "{:#}", self.error)
    }
}

impl std::error::Error for LoadError {}

/// A resolved configuration together with the file tier it was resolved from.
///
/// The reload path needs both: the effective [`Config`] to serve from, and what
/// the *file alone* asked for, so a key the file changed but the process cannot
/// apply can be reported instead of silently dropped.
#[derive(Clone, Debug)]
pub struct Resolved {
    /// The effective configuration, after CLI > env > file > default.
    pub config: Config,
    /// What the file itself states for the settings a reload cannot apply.
    pub stated: FileSettings,
}

/// The values a config *file* states for the settings that are fixed for the
/// life of the process.
///
/// This is deliberately the file tier only, unmerged: "the operator edited this
/// key and it did not take effect" is a statement about the file, not about the
/// resolved config — under CLI precedence a shadowed key resolves to the value
/// it already had, so a resolved-vs-resolved comparison reports nothing at all.
///
/// `admin_token` is here to be *compared*, never rendered: no caller may put its
/// value in a response body or a log line.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileSettings {
    /// `[zone] origin`.
    pub origin: Option<String>,
    /// `[server] udp`. Empty means the key is absent.
    pub udp: Vec<SocketAddr>,
    /// `[server] tcp`. Empty means the key is absent.
    pub tcp: Vec<SocketAddr>,
    /// `[server] admin_listen`.
    pub admin_listen: Option<SocketAddr>,
    /// `[server] tcp_timeout_secs`.
    pub tcp_timeout_secs: Option<u64>,
    /// `[server] shutdown_drain_secs`, exactly as the file states it — signed,
    /// because a negative value is rejected by the merge and never reaches a
    /// comparison.
    pub shutdown_drain_secs: Option<i64>,
    /// `[server] log_format`.
    pub log_format: Option<LogFormat>,
    /// `[server] log_level`.
    pub log_level: Option<String>,
    /// `[server] admin_token`. Compared, never printed.
    pub admin_token: Option<String>,
    /// `[server.rate_limit] qps`.
    pub rate_limit_qps: Option<u32>,
    /// `[server.rate_limit] burst`.
    pub rate_limit_burst: Option<u32>,
}

impl Config {
    /// Build a [`Config`] from parsed CLI arguments, reading the TOML file if one
    /// was given.
    pub fn load(cli: &GlobalArgs) -> Result<Self> {
        Self::resolve(cli)
            .map(|resolved| resolved.config)
            .map_err(|failure| failure.error)
    }

    /// [`Config::load`], keeping the failing stage and the file tier.
    ///
    /// This is the single precedence implementation: startup and reload both come
    /// through here, so a rule added for one is a rule added for both. VEGA-005
    /// happened because a second, simplified copy of this resolution existed in
    /// the reload path.
    pub fn resolve(cli: &GlobalArgs) -> Result<Resolved, LoadError> {
        let file = match &cli.config {
            Some(path) => Self::read_file(path)?,
            None => FileConfig::default(),
        };
        let stated = FileSettings::from(&file);
        let config = Self::merge(cli, file).map_err(|error| LoadError {
            stage: LoadStage::Validate,
            error,
        })?;
        Ok(Resolved { config, stated })
    }

    fn read_file(path: &Path) -> Result<FileConfig, LoadError> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))
            .map_err(|error| LoadError {
                stage: LoadStage::Read,
                error,
            })?;
        // Through `tomlparse` like every other TOML parse in the crate: its
        // error carries the position and not the source line, which is what
        // keeps `admin_token` out of a `/reload` body and a WARN log (VEGA-082,
        // then VEGA-089 for the sibling path that did not come through here).
        tomlparse::deserialize(&raw).map_err(|error| LoadError {
            stage: LoadStage::Parse,
            error: anyhow!("parsing config file {}: {error}", path.display()),
        })
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

        let shutdown_drain = shutdown_drain(cli, file.server.shutdown_drain_secs)?;

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
            shutdown_drain,
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

impl From<&FileConfig> for FileSettings {
    fn from(file: &FileConfig) -> Self {
        // Destructured exhaustively, every table of it, with the reloadable keys
        // bound to `_`: adding a key to the file schema is a compile error here
        // until someone decides whether a reload may apply it. Without this, a new
        // `[server]` key would parse, merge, and then silently never appear in a
        // reload's `ignored` — the same silence VEGA-005 is about, in a new key.
        // `crate::reload::Running::apply_reloadable` forces the same question for
        // the other half of the partition.
        let FileConfig { server, zone } = file;
        let ServerSection {
            udp,
            tcp,
            admin_listen,
            tcp_timeout_secs,
            shutdown_drain_secs,
            log_format,
            log_level,
            admin_token,
            rate_limit,
        } = server;
        let RateLimitSection { qps, burst } = rate_limit;
        let ZoneSection {
            origin,
            // Reloadable: applied on every reload, so never reported as ignored.
            default_ttl: _,
            builtins: _,
            soa: _,
            records: _,
        } = zone;

        Self {
            origin: origin.clone(),
            udp: udp.clone(),
            tcp: tcp.clone(),
            admin_listen: *admin_listen,
            tcp_timeout_secs: *tcp_timeout_secs,
            shutdown_drain_secs: *shutdown_drain_secs,
            log_format: *log_format,
            log_level: log_level.clone(),
            admin_token: admin_token.clone(),
            rate_limit_qps: *qps,
            rate_limit_burst: *burst,
        }
    }
}

fn pick_addrs(cli: &[SocketAddr], file: &[SocketAddr]) -> Vec<SocketAddr> {
    if cli.is_empty() {
        file.to_vec()
    } else {
        cli.to_vec()
    }
}

/// Resolve and validate the shutdown drain window.
///
/// CLI (and its `VEGA_SHUTDOWN_DRAIN_SECS` env form) beats the file beats the
/// default, like everything else here. Out of range is a hard error at startup
/// rather than a clamp: a window longer than any grace period an operator can
/// set guarantees a `SIGKILL` mid-drain, and finding that during a rollout costs
/// far more than failing to start.
fn shutdown_drain(cli: &GlobalArgs, file: Option<i64>) -> Result<Duration> {
    let max = MAX_SHUTDOWN_DRAIN.as_secs();
    let refuse = |value: &dyn fmt::Display| {
        anyhow::anyhow!("shutdown_drain_secs must be between 0 and {max} seconds, got {value}")
    };

    if let Some(secs) = cli.shutdown_drain_secs {
        if secs > max {
            return Err(refuse(&secs));
        }
        return Ok(Duration::from_secs(secs));
    }

    let Some(secs) = file else {
        return Ok(DEFAULT_SHUTDOWN_DRAIN);
    };
    // Signed on the way in so a negative is refused by name here, not by the
    // deserializer talking about `u64`.
    match u64::try_from(secs).ok().filter(|secs| *secs <= max) {
        Some(secs) => Ok(Duration::from_secs(secs)),
        None => Err(refuse(&secs)),
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
        let file: FileConfig = tomlparse::deserialize(
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
        let file: FileConfig = tomlparse::deserialize("[zone]\ndefault_ttl = 0\n").unwrap();
        let err = Config::merge(&cli(&[]), file).unwrap_err();
        assert!(err.to_string().contains("default_ttl"), "{err}");
    }

    #[test]
    fn unknown_file_keys_are_rejected() {
        let err = tomlparse::deserialize::<FileConfig>("[server]\nudpp = []\n").unwrap_err();
        assert!(err.to_string().contains("udpp"), "{err}");
    }

    #[test]
    fn no_builtins_flag_wins_over_file() {
        let file: FileConfig = tomlparse::deserialize("[zone]\nbuiltins = true\n").unwrap();
        let cfg = Config::merge(&cli(&["--no-builtins"]), file).unwrap();
        assert!(!cfg.zone.builtins);
    }

    #[test]
    fn records_round_trip_from_toml() {
        let file: FileConfig = tomlparse::deserialize(
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
        let file: FileConfig = tomlparse::deserialize(
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

    // -----------------------------------------------------------------------
    // VEGA-046. The drain window, on all three configuration surfaces.
    // Scenarios in features/shutdown.feature.
    // -----------------------------------------------------------------------

    /// Scenario: Startup states the drain, the hard deadline and the grace-period floor
    /// features/shutdown.feature:141
    #[test]
    fn the_drain_window_defaults_to_fifteen_seconds() {
        // The shipped default is derived, not chosen: §2.2 of the ruling. A
        // change here moves the deadline, the watchdog and the grace period an
        // operator has to configure, so it is pinned by value.
        let cfg = Config::merge(&cli(&[]), FileConfig::default()).unwrap();
        assert_eq!(cfg.shutdown_drain, DEFAULT_SHUTDOWN_DRAIN);
        assert_eq!(cfg.shutdown_drain, Duration::from_secs(15));
    }

    #[test]
    fn the_drain_window_comes_from_the_file_unless_the_command_line_states_one() {
        let file: FileConfig =
            tomlparse::deserialize("[server]\nshutdown_drain_secs = 42\n").unwrap();
        let cfg = Config::merge(&cli(&[]), file.clone()).unwrap();
        assert_eq!(cfg.shutdown_drain, Duration::from_secs(42));

        // The env form is clap's, so it lands in the same field as the flag.
        let cfg = Config::merge(&cli(&["--shutdown-drain-secs", "7"]), file).unwrap();
        assert_eq!(cfg.shutdown_drain, Duration::from_secs(7));
    }

    /// Scenario: A zero-length drain still passes through every phase in order
    /// features/shutdown.feature:82
    #[test]
    fn a_zero_drain_window_is_legal() {
        // 0 is the right value for CI and `cargo run`; it must not be confused
        // with "unset", which resolves to 15.
        let file: FileConfig =
            tomlparse::deserialize("[server]\nshutdown_drain_secs = 0\n").unwrap();
        assert_eq!(
            Config::merge(&cli(&[]), file).unwrap().shutdown_drain,
            Duration::ZERO
        );
    }

    /// Scenario: A drain window above the 300 second maximum is refused at startup
    /// features/shutdown.feature:100
    #[test]
    fn a_drain_window_above_the_maximum_is_refused_naming_the_setting_and_the_limit() {
        let file: FileConfig =
            tomlparse::deserialize("[server]\nshutdown_drain_secs = 301\n").unwrap();
        let error = Config::merge(&cli(&[]), file).unwrap_err().to_string();
        assert!(error.contains("shutdown_drain_secs"), "{error}");
        assert!(
            error.contains("300"),
            "the limit has to be in the message: {error}"
        );
        assert!(
            error.contains("301"),
            "and so does the offending value: {error}"
        );

        // The same limit on the command line, so one surface cannot be laxer.
        let error = Config::merge(
            &cli(&["--shutdown-drain-secs", "301"]),
            FileConfig::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("shutdown_drain_secs"), "{error}");
        assert!(error.contains("300"), "{error}");
    }

    /// Scenario: The 300 second maximum is itself accepted
    /// features/shutdown.feature:109
    #[test]
    fn the_maximum_drain_window_is_inclusive() {
        // Kills `secs <= max` -> `secs < max`, which would refuse a legal config.
        let file: FileConfig =
            tomlparse::deserialize("[server]\nshutdown_drain_secs = 300\n").unwrap();
        assert_eq!(
            Config::merge(&cli(&[]), file).unwrap().shutdown_drain,
            MAX_SHUTDOWN_DRAIN
        );
    }

    /// Scenario: A negative drain window is refused at startup
    /// features/shutdown.feature:116
    #[test]
    fn a_negative_drain_window_is_refused_by_name_rather_than_by_type() {
        // The field is signed precisely so this message names the setting an
        // operator wrote, instead of the deserializer complaining about u64.
        let file: FileConfig = tomlparse::deserialize("[server]\nshutdown_drain_secs = -1\n")
            .expect("a negative integer parses; it is the range check that rejects it");
        let error = Config::merge(&cli(&[]), file).unwrap_err().to_string();
        assert!(error.contains("shutdown_drain_secs"), "{error}");
        assert!(error.contains("-1"), "{error}");
    }

    // -----------------------------------------------------------------------
    // VEGA-005. Stage-tagged loading and the file tier the reload path reports
    // shadowed keys from. Scenarios in features/config-precedence.feature.
    // -----------------------------------------------------------------------

    /// A file that is not there fails at the read stage, naming the path.
    #[test]
    fn a_missing_config_file_fails_at_the_read_stage() {
        let dir = tempfile::tempdir().expect("temp dir");
        let missing = dir.path().join("nope.toml");
        let failure = Config::resolve(&GlobalArgs {
            config: Some(missing.clone()),
            ..cli(&[])
        })
        .expect_err("a missing file cannot resolve");

        assert_eq!(failure.stage, LoadStage::Read);
        assert!(
            failure.to_string().contains(&missing.display().to_string()),
            "an operator at 3am needs the path: {failure}"
        );
    }

    #[test]
    fn unparseable_toml_fails_at_the_parse_stage() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("vega.toml");
        std::fs::write(&path, "[zone\norigin = ").expect("file writes");

        let failure = Config::resolve(&GlobalArgs {
            config: Some(path),
            ..cli(&[])
        })
        .expect_err("broken TOML cannot resolve");
        assert_eq!(failure.stage, LoadStage::Parse);
    }

    #[test]
    fn a_value_the_merge_rejects_fails_at_the_validate_stage() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("vega.toml");
        std::fs::write(&path, "[zone]\ndefault_ttl = 0\n").expect("file writes");

        let failure = Config::resolve(&GlobalArgs {
            config: Some(path),
            ..cli(&[])
        })
        .expect_err("a zero TTL cannot resolve");
        assert_eq!(failure.stage, LoadStage::Validate);
        assert!(failure.to_string().contains("default_ttl"), "{failure}");
    }

    #[test]
    fn the_file_tier_is_kept_even_where_the_command_line_shadows_it() {
        // The point of `stated`: after the merge, `origin` is the CLI's value and
        // the file's is gone. A reload has to report the file's key as shadowed,
        // so the unmerged value has to survive the merge.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("vega.toml");
        std::fs::write(
            &path,
            "[server]\nudp = [\"127.0.0.1:5399\"]\nadmin_token = \"from-the-file\"\n\
             rate_limit = { qps = 1000, burst = 2000 }\n\
             [zone]\norigin = \"from-the-file.test\"\n",
        )
        .expect("file writes");

        let resolved = Config::resolve(&GlobalArgs {
            config: Some(path),
            ..cli(&["--domain", "from-the-cli.test", "--udp", "127.0.0.1:5300"])
        })
        .expect("the config resolves");

        assert_eq!(resolved.config.zone.origin, "from-the-cli.test");
        assert_eq!(
            resolved.stated.origin.as_deref(),
            Some("from-the-file.test")
        );
        assert_eq!(
            resolved.stated.udp,
            vec!["127.0.0.1:5399".parse::<SocketAddr>().unwrap()]
        );
        assert_eq!(
            resolved.stated.admin_token.as_deref(),
            Some("from-the-file")
        );
        assert_eq!(resolved.stated.rate_limit_qps, Some(1000));
        assert_eq!(resolved.stated.rate_limit_burst, Some(2000));
    }

    #[test]
    fn a_file_that_states_nothing_yields_an_empty_file_tier() {
        // The empty-input case: no keys stated means nothing can be shadowed, so
        // a reload of an unchanged minimal file reports no drift at all.
        let resolved = Config::resolve(&cli(&[])).expect("defaults resolve");
        assert_eq!(resolved.stated, FileSettings::default());
    }

    // -----------------------------------------------------------------------
    // VEGA-082. A config failure is rendered for an operator, never by quoting
    // the file back: the offending line is the secret when the key is
    // `server.admin_token`. All three stages, because all three reach a
    // `/reload` response body and a WARN log line.
    // -----------------------------------------------------------------------

    /// The secret used by every leak test below. Distinctive enough that a
    /// substring search cannot match anything the renderer legitimately emits.
    const SECRET: &str = "SUPER-SECRET-TOKEN-1";

    /// Resolve `toml` from a real file and return the failure.
    fn resolve_failure(bytes: &[u8]) -> LoadError {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("vega.toml");
        std::fs::write(&path, bytes).expect("file writes");
        Config::resolve(&GlobalArgs {
            config: Some(path),
            ..cli(&[])
        })
        .expect_err("this config cannot resolve")
    }

    /// A parse failure keeps its position and its message — the positive
    /// control for the redaction below. Without this, "redact everything"
    /// passes and the operator is left with an error they cannot act on.
    #[test]
    fn a_parse_failure_still_names_the_line_the_column_and_what_was_expected() {
        // `log_level = "oops` is 17 characters, so the unterminated string is
        // reported at line 2, column 18 — the position an editor's gutter shows.
        let failure = resolve_failure(b"[server]\nlog_level = \"oops\n");
        assert_eq!(failure.stage, LoadStage::Parse);
        let rendered = failure.to_string();
        for needle in ["line 2", "column 18", "invalid basic string"] {
            assert!(
                rendered.contains(needle),
                "a redacted parse error still has to be actionable; {needle:?} is missing \
                 from: {rendered}"
            );
        }
    }

    /// Scenario: A startup failure does not echo the admin_token line
    /// features/config-precedence.feature:462
    #[test]
    fn a_parse_failure_on_the_admin_token_line_does_not_echo_the_token() {
        let toml = format!("[server]\nadmin_token = \"{SECRET}\nudp = [\"127.0.0.1:5300\"]\n");
        let failure = resolve_failure(toml.as_bytes());

        assert_eq!(failure.stage, LoadStage::Parse);
        // The exact position `toml` itself reported for this input before the
        // redaction: proof that reimplementing the offset-to-position arithmetic
        // did not move the numbers an operator reads.
        assert!(
            failure.to_string().contains("line 2, column 36"),
            "{failure}"
        );
        assert!(
            !failure.to_string().contains(SECRET),
            "toml's own Display quotes the offending source line, so an unterminated \
             string on the admin_token line puts the secret into the /reload body and \
             the WARN log: {failure}"
        );
        assert!(
            !format!("{:?}", failure.error).contains(SECRET),
            "the Debug form must not carry it either: a `source` chain holding the raw \
             toml error leaks through anyhow's `{{:?}}`"
        );
    }

    /// Scenario: A duplicated admin_token key does not echo either value
    /// features/live-reload.feature:380
    #[test]
    fn a_duplicate_admin_token_key_does_not_echo_either_value() {
        let toml = format!("[server]\nadmin_token = \"{SECRET}\"\nadmin_token = \"{SECRET}\"\n");
        let failure = resolve_failure(toml.as_bytes());

        assert_eq!(failure.stage, LoadStage::Parse);
        let rendered = failure.to_string();
        assert!(!rendered.contains(SECRET), "{rendered}");
        assert!(
            rendered.contains("duplicate key"),
            "the operator still has to be told what is wrong: {rendered}"
        );
    }

    /// Every shape of parse failure we could reach with the secret on the
    /// `admin_token` line, not only the two the audit reproduced.
    ///
    /// The claim being defended is stronger than "those two inputs are fixed":
    /// nothing the parser or serde says about `server.admin_token` can contain
    /// its value. It holds because the field is a `String` — every TOML string
    /// deserializes into it, so the only failures reachable on that key are
    /// positional ones, and the position is a pair of integers. What serde does
    /// still quote is *key names*, *unknown enum variants* and *values of the
    /// wrong type for a typed field*; none of the three can be reached by a
    /// well-formed token sitting where a token belongs.
    #[test]
    fn no_parse_failure_shape_echoes_the_value_of_admin_token() {
        let shapes = [
            format!("[server]\nadmin_token = \"{SECRET}\n"),
            format!("[server]\nadmin_token = '{SECRET}\n"),
            format!("[server]\nadmin_token = \"{SECRET}\" trailing\n"),
            format!("[server]\nadmin_token = {{ inner = \"{SECRET}\" }}\n"),
            format!("[server\nadmin_token = \"{SECRET}\"\n"),
            format!("[server]\nadmin_token = \"{SECRET}\"\n[[zone.records]\n"),
            format!("[server]\nadmin_token = \"{SECRET}\"\nadmin_token = \"other\"\n"),
            format!("[server]\nadmin_token = \"{SECRET}\"\nudp = \"not-a-list\"\n"),
        ];

        for toml in shapes {
            let failure = resolve_failure(toml.as_bytes());
            assert_eq!(failure.stage, LoadStage::Parse, "{toml:?}");
            assert!(
                !failure.to_string().contains(SECRET),
                "{toml:?} leaked the token: {failure}"
            );
            assert!(
                failure.to_string().contains("TOML parse error at line"),
                "{toml:?} lost the position: {failure}"
            );
        }
    }

    /// The read stage reads the file whole before decoding it, so a file that is
    /// not UTF-8 fails *after* the bytes are in hand. The io error must describe
    /// the decode, not the content.
    #[test]
    fn a_read_failure_on_undecodable_bytes_does_not_echo_them() {
        let mut bytes = format!("[server]\nadmin_token = \"{SECRET}\"\n").into_bytes();
        bytes.push(0xff);
        let failure = resolve_failure(&bytes);

        assert_eq!(failure.stage, LoadStage::Read);
        assert!(!failure.to_string().contains(SECRET), "{failure}");
    }

    /// The validate stage never sees the file's bytes — only parsed values — and
    /// `merge` copies `admin_token` without ever formatting it. Asserted rather
    /// than assumed: a future `bail!` that quotes a rejected value would land
    /// here.
    #[test]
    fn a_validate_failure_does_not_echo_the_admin_token_beside_it() {
        let toml = format!("[server]\nadmin_token = \"{SECRET}\"\n[zone]\ndefault_ttl = 0\n");
        let failure = resolve_failure(toml.as_bytes());

        assert_eq!(failure.stage, LoadStage::Validate);
        assert!(!failure.to_string().contains(SECRET), "{failure}");
        assert!(failure.to_string().contains("default_ttl"), "{failure}");
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
