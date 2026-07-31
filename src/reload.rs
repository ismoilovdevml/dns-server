//! Live reload: re-resolve the configuration from the file and swap the zone.
//!
//! This module owns the whole `POST /reload` pipeline — the gates, their order,
//! the one mutation, and the report of what could not be applied. It lives in the
//! library rather than in `main.rs` so the invariants below are reachable from a
//! test; the binary keeps only the wiring.
//!
//! Three rules shape everything here, and all three come from
//! `.claude/backlog/decisions/VEGA-005-reload-precedence.md`:
//!
//! * **The invocation is frozen.** A reload re-resolves through the same
//!   precedence function as startup — CLI > env > file > default — against the
//!   command line and environment captured at process start. Only the *file* tier
//!   is re-read. A running process's invocation genuinely cannot change: editing
//!   a systemd `EnvironmentFile=` does not touch a live process's environment,
//!   and re-entering the environment from a worker thread is the `setenv` data
//!   race that `unsafe_code = "forbid"` puts out of reach anyway.
//! * **The origin is the process's identity, not its data.** RFC 8499 §7 defines
//!   a zone by its apex and RFC 1034 §4.2 makes authority a property of a zone,
//!   so moving the origin does not edit a zone, it replaces one. Every
//!   in-bailiwick query would become REFUSED, and RFC 2308 defines negative
//!   caching only for NXDOMAIN and NODATA, so resolvers would retry at full rate
//!   forever. A resolved-origin change is refused outright.
//! * **Silence is the bug.** A setting that cannot take effect without rebinding
//!   a socket, re-registering a listener or rebuilding a subsystem the handler
//!   already owns is fixed for the life of the process — and every fixed setting
//!   the file changed is named in the response and logged at WARN. Refusing the
//!   whole reload over one restart-only key would stop the urgent record change
//!   from shipping, which is the opposite of what a reload is for.
//!
//! Nothing here runs on the query path. The state mutex lives in
//! [`ReloadContext`], never in `DnsHandler`, and the only mutation is a single
//! `ArcSwap` store, so `Zone::lookup` and `DnsHandler::handle_request` keep taking
//! no locks and loading the zone exactly once per query.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex, TryLockError},
    time::Duration,
};

use anyhow::Context as _;
use hickory_proto::rr::{LowerName, Name};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::{
    admin::{ReloadError, ReloadErrorCode, ReloadFn, ReloadOutcome},
    config::{Config, FileSettings, GlobalArgs, LoadStage},
    handler::DnsHandler,
    metrics::Metrics,
    zone::Zone,
};

/// TOML key paths for the settings that are fixed for the life of the process.
///
/// Spelled out as constants because they are an API: they appear in the `ignored`
/// array, in log lines, in runbooks, and (via VEGA-049) in alert labels.
const KEY_ORIGIN: &str = "zone.origin";
const KEY_UDP: &str = "server.udp";
const KEY_TCP: &str = "server.tcp";
const KEY_ADMIN_LISTEN: &str = "server.admin_listen";
const KEY_TCP_TIMEOUT: &str = "server.tcp_timeout_secs";
const KEY_SHUTDOWN_DRAIN: &str = "server.shutdown_drain_secs";
const KEY_LOG_FORMAT: &str = "server.log_format";
const KEY_LOG_LEVEL: &str = "server.log_level";
const KEY_ADMIN_TOKEN: &str = "server.admin_token";
const KEY_RATE_LIMIT_QPS: &str = "server.rate_limit.qps";
const KEY_RATE_LIMIT_BURST: &str = "server.rate_limit.burst";

/// Upper bound on `ignored`: the fixed keys above, and no more.
///
/// The array is bounded by construction, not by a check — but the capacity is
/// stated so the allocation is exact and so a future key addition has to come
/// past this line.
const MAX_IGNORED: usize = 11;

/// Everything a reload needs that cannot be re-derived from the file.
///
/// Built once in `serve` and shared with the admin endpoint. Holding it apart
/// from `DnsHandler` is deliberate: the query path must not be able to reach this
/// mutex even by accident.
pub struct ReloadContext {
    /// The command line and environment exactly as parsed at startup.
    ///
    /// Frozen, because a running process's invocation cannot change — and because
    /// a blank invocation is not a neutral element: `Config::merge` treats an
    /// absent CLI value as "fall through to the file, then to the built-in
    /// default", so resolving against a blank one does not merely lose the flags,
    /// it silently substitutes a different zone. That was VEGA-005.
    invocation: GlobalArgs,

    /// The file re-read on every reload.
    ///
    /// Frozen to the path resolved at startup so a reload can never switch files:
    /// a `./vega.toml` appearing in the working directory after startup must not
    /// displace the `/etc` file we booted from. Always equal to
    /// `invocation.config`, which [`ReloadContext::new`] enforces.
    source: PathBuf,

    handler: Arc<DnsHandler>,
    metrics: Arc<Metrics>,

    /// Serialises reloads and carries the configuration actually being served.
    state: Mutex<Running>,

    /// Drain-start signal. A reload fails closed once it fires, so a zone is
    /// never installed into a process that is going away (VEGA-046 I1/I3).
    draining: CancellationToken,
}

/// The configuration this process is actually running.
///
/// Not "what the file last said": the fixed half of this keeps its startup values
/// for the life of the process, so `udp` means "what we are bound to" and drift
/// reporting stays truthful on the second reload as well as the first.
struct Running {
    config: Config,
}

impl Running {
    /// Take the reloadable half of a freshly resolved config, and only that.
    fn apply_reloadable(&mut self, fresh: Config) {
        // Destructured on purpose: a new zone field is a compile error here until
        // someone decides whether a reload may change it.
        let crate::config::ZoneConfig {
            origin: _,
            default_ttl,
            builtins,
            soa,
            records,
        } = fresh.zone;

        self.config.zone.default_ttl = default_ttl;
        self.config.zone.builtins = builtins;
        self.config.zone.soa = soa;
        self.config.zone.records = records;
    }
}

impl ReloadContext {
    /// Freeze an invocation and a config file into a reloadable context.
    ///
    /// `running` is the configuration `serve` actually started from; its fixed
    /// fields are the baseline every later reload is compared against.
    pub fn new(
        invocation: GlobalArgs,
        source: PathBuf,
        handler: Arc<DnsHandler>,
        metrics: Arc<Metrics>,
        running: Config,
        draining: CancellationToken,
    ) -> Self {
        // The two cannot be allowed to diverge: whichever path resolved `source`
        // is the path a reload must keep re-reading.
        let invocation = GlobalArgs {
            config: Some(source.clone()),
            ..invocation
        };
        Self {
            invocation,
            source,
            handler,
            metrics,
            state: Mutex::new(Running { config: running }),
            draining,
        }
    }

    /// The file every reload re-reads.
    pub fn source(&self) -> &Path {
        &self.source
    }
}

/// Wrap a context as the closure the admin endpoint calls.
///
/// Keeps `admin` a dumb transport: it holds no configuration knowledge, and no
/// precedence knowledge, which is the structural half of not regressing VEGA-005.
pub fn hook(ctx: Arc<ReloadContext>) -> ReloadFn {
    Arc::new(move || reload(&ctx))
}

/// Re-read the config file and swap the zone in place.
///
/// The order of the gates is the atomicity guarantee: everything up to the swap
/// only reads the world and allocates privately, so a refused reload has touched
/// nothing shared — not the `ArcSwap`, not the gauge, not the running config, not
/// the reload counter. There is no rollback path because there is nothing to roll
/// back. Callers must not "optimise" by building the zone before the origin gate.
pub fn reload(ctx: &ReloadContext) -> Result<ReloadOutcome, ReloadError> {
    // 0. Refuse before doing any work if the process is on its way out.
    if ctx.draining.is_cancelled() {
        return Err(shutting_down());
    }

    // 1. One reload at a time. A loser returns immediately and does no IO;
    //    queueing would pin a blocking-pool thread on identical work for an
    //    identical result, and buys no ordering guarantee anyway.
    let mut running = match ctx.state.try_lock() {
        Ok(guard) => guard,
        // The guarded state is a baseline snapshot; the steps below mutate
        // nothing shared until every gate has passed, so a panic mid-build
        // cannot have broken an invariant. Recovering beats disabling reload for
        // the rest of the process's life.
        Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        Err(TryLockError::WouldBlock) => {
            return Err(ReloadError::new(
                ReloadErrorCode::ReloadInProgress,
                "a reload is already in progress",
            ))
        }
    };

    // 2-4. Read, parse and merge — the same precedence function startup uses,
    //      against the frozen invocation.
    let resolved = Config::resolve(&ctx.invocation).map_err(|failure| {
        ReloadError::new(
            match failure.stage {
                LoadStage::Read => ReloadErrorCode::ConfigReadFailed,
                LoadStage::Parse => ReloadErrorCode::ConfigParseFailed,
                LoadStage::Validate => ReloadErrorCode::ConfigInvalid,
            },
            // Safe to render whole only because `Config::resolve` parses through
            // `crate::tomlparse`, the one module allowed to touch a TOML parser:
            // a parser's own Display quotes the offending source line, and that
            // line is the operator's secret when the key is `server.admin_token`.
            // This string goes into the response body and into `admin.rs`'s
            // WARN. See `crate::tomlparse` (VEGA-082, then VEGA-089), and do not
            // reach around it for a parser error to re-wrap here.
            format!("{:#}", failure.error),
        )
    })?;
    let fresh = resolved.config;

    // 5. The origin gate, on canonicalised names so that `example.com.` and
    //    `EXAMPLE.COM` are the same zone (RFC 1035 §5.1, RFC 4343) and a cosmetic
    //    edit is not a spurious 409.
    let requested = canonical_origin(&fresh.zone.origin)
        .map_err(|error| ReloadError::new(ReloadErrorCode::ConfigInvalid, format!("{error:#}")))?;
    let current = canonical_origin(&running.config.zone.origin).map_err(|error| {
        // Unreachable in practice: this origin built a zone at startup. Reported
        // rather than asserted, because /reload is reachable from the network.
        ReloadError::new(
            ReloadErrorCode::Internal,
            format!("the running zone origin is unparseable: {error:#}"),
        )
    })?;
    if requested != current {
        let running_origin = running.config.zone.origin.clone();
        warn!(
            running_origin = %running_origin,
            requested_origin = %fresh.zone.origin,
            "refusing a reload that would change the zone this server is authoritative for"
        );
        return Err(ReloadError::new(
            ReloadErrorCode::OriginChanged,
            format!(
                "refusing to reload: the config file changes the zone origin from {running_origin:?} \
                 to {:?}; a running server cannot change the zone it is authoritative for. \
                 Restart to serve a different origin.",
                fresh.zone.origin
            ),
        )
        .with_origins(running_origin, fresh.zone.origin.clone()));
    }

    // 6. Build the whole zone before touching anything shared, so a bad record
    //    fails the reload instead of half-applying it.
    let zone = Zone::from_config(&fresh.zone).map_err(|error| {
        ReloadError::new(ReloadErrorCode::ZoneBuildFailed, format!("{error:#}"))
    })?;

    // 7. Extension point: VEGA-048's empty-zone gate belongs here, still before
    //    the swap.

    // 8. Re-check the drain: one that started while the zone was building must
    //    abandon the new zone rather than install it into a dying process.
    if ctx.draining.is_cancelled() {
        return Err(shutting_down());
    }

    // ---------------------------- linearisation point ----------------------
    let records = zone.record_count();
    let origin = fresh.zone.origin.clone();

    // 9. One atomic store. A reader holding a guard finishes against the zone it
    //    loaded; the next reader sees this one.
    ctx.handler
        .replace_zone(Arc::new(zone), fresh.zone.builtins);
    // 10. Gauge *after* the swap. The other order lets a Prometheus scrape landing
    //     between the two report the new record count for the old zone.
    ctx.metrics.set_zone_records(records as u64);
    // 11. Report what the file asked for and this process could not do. Computed
    //     before step 12 consumes `fresh`, which is safe and gives the same
    //     answer: `apply_reloadable` touches only reloadable zone fields and
    //     `drift` reads only fixed ones.
    let ignored = drift(&running.config, &resolved.stated, &fresh);
    // 12. Only the reloadable half moves; the fixed half keeps its startup values
    //     so drift stays truthful on every later reload.
    running.apply_reloadable(fresh);

    for &key in &ignored {
        warn!(
            key,
            "the config file changes a setting that is fixed for the life of the process; \
             it was not applied — restart to change it"
        );
    }

    Ok(ReloadOutcome {
        origin,
        records,
        ignored,
    })
}

/// The refusal used at both drain checks.
fn shutting_down() -> ReloadError {
    ReloadError::new(
        ReloadErrorCode::ShuttingDown,
        "the server is shutting down; reload refused",
    )
}

/// The fixed settings this file asks to change, in the order of the partition
/// table.
///
/// A key is reported when *either* disjunct holds:
///
/// * **(a)** the file states the key and states something this process is not
///   doing. Under CLI precedence a shadowed key resolves to the value it already
///   had, so a resolved-vs-resolved comparison sees nothing — and a `--domain`
///   shadowing a `[zone] origin` edit, or a `--udp` shadowing a listener edit,
///   would go unmentioned. That is the silence VEGA-005 is about, one layer up.
/// * **(b)** what a *restart* would now resolve differs from what is running.
///   This is the case (a) cannot see: a fixed key deleted from the file that the
///   invocation does not supply. The running process keeps its socket and its
///   token, but the next restart falls through to the built-in default — a 200
///   that does not say so stages an outage for the next restart. Because the
///   invocation is frozen, (b) can only ever fire from a file change, so it never
///   reports invocation noise.
///
/// Neither disjunct fires for a key the file states and the process already
/// honours, which is what keeps a no-op reload's `ignored` empty.
///
/// Pure, bounded, allocation-exact, each key pushed at most once, and called once
/// per reload. Never returns a value, only a key path: `server.admin_token` must
/// not put a secret in a response body or a log line.
fn drift(running: &Config, stated: &FileSettings, fresh: &Config) -> Vec<&'static str> {
    let mut ignored = Vec::with_capacity(MAX_IGNORED);

    // The origin compares as a DNS name on both sides, so a trailing dot or a
    // case change is not drift. (b) is unreachable here in practice — the origin
    // gate has already refused any resolved change — and is kept for uniformity.
    let stated_origin = stated
        .origin
        .as_ref()
        .is_some_and(|origin| !same_origin(origin, &running.zone.origin));
    if stated_origin || !same_origin(&fresh.zone.origin, &running.zone.origin) {
        ignored.push(KEY_ORIGIN);
    }
    // An empty list in the *file tier* is an absent key, not a request for no
    // listeners: the merge treats the two identically, so (a) must too. `fresh`
    // is never empty — the merge injects the built-in listener — so (b) needs no
    // such guard.
    let stated_udp = !stated.udp.is_empty() && stated.udp != running.udp;
    if stated_udp || fresh.udp != running.udp {
        ignored.push(KEY_UDP);
    }
    let stated_tcp = !stated.tcp.is_empty() && stated.tcp != running.tcp;
    if stated_tcp || fresh.tcp != running.tcp {
        ignored.push(KEY_TCP);
    }
    let stated_admin_listen = stated
        .admin_listen
        .is_some_and(|addr| Some(addr) != running.admin_listen);
    if stated_admin_listen || fresh.admin_listen != running.admin_listen {
        ignored.push(KEY_ADMIN_LISTEN);
    }
    let stated_timeout = stated
        .tcp_timeout_secs
        .is_some_and(|secs| Duration::from_secs(secs) != running.tcp_timeout);
    if stated_timeout || fresh.tcp_timeout != running.tcp_timeout {
        ignored.push(KEY_TCP_TIMEOUT);
    }
    // VEGA-046's drain window. Fixed for the same reason as `tcp_timeout_secs`:
    // `serve` hands it to the shutdown path once, at startup, so a file edit
    // cannot reach the sequence this process will actually run. Reported here
    // provisionally — the partition table predates the key, and the architect
    // owns the final classification.
    let stated_drain = stated.shutdown_drain_secs.is_some_and(|secs| {
        u64::try_from(secs).map_or(true, |secs| {
            Duration::from_secs(secs) != running.shutdown_drain
        })
    });
    if stated_drain || fresh.shutdown_drain != running.shutdown_drain {
        ignored.push(KEY_SHUTDOWN_DRAIN);
    }
    let stated_log_format = stated
        .log_format
        .is_some_and(|format| format != running.log_format);
    if stated_log_format || fresh.log_format != running.log_format {
        ignored.push(KEY_LOG_FORMAT);
    }
    let stated_log_level = stated
        .log_level
        .as_ref()
        .is_some_and(|level| level != &running.log_level);
    if stated_log_level || fresh.log_level != running.log_level {
        ignored.push(KEY_LOG_LEVEL);
    }
    let stated_token = stated.admin_token.is_some() && stated.admin_token != running.admin_token;
    if stated_token || fresh.admin_token != running.admin_token {
        ignored.push(KEY_ADMIN_TOKEN);
    }
    // `qps = 0` means "limiting off", which is the same state as no limiter at
    // all, so every side is compared as an effective rate rather than as an
    // Option.
    let running_qps = running.rate_limit.map_or(0, |limit| limit.qps);
    let stated_qps = stated.rate_limit_qps.is_some_and(|qps| qps != running_qps);
    if stated_qps || fresh.rate_limit.map_or(0, |limit| limit.qps) != running_qps {
        ignored.push(KEY_RATE_LIMIT_QPS);
    }
    let running_burst = running.rate_limit.map_or(0, |limit| limit.burst);
    let stated_burst = stated
        .rate_limit_burst
        .is_some_and(|burst| burst != running_burst);
    if stated_burst || fresh.rate_limit.map_or(0, |limit| limit.burst) != running_burst {
        ignored.push(KEY_RATE_LIMIT_BURST);
    }

    ignored
}

/// Canonicalise an origin so two spellings of one zone compare equal.
///
/// RFC 1035 §5.1: a trailing dot marks an already-fully-qualified name, so
/// `example.com` and `example.com.` name the same zone. RFC 1034 §3.1 and RFC
/// 4343: DNS names compare case-insensitively over ASCII.
fn canonical_origin(origin: &str) -> anyhow::Result<LowerName> {
    let mut name: Name = origin
        .parse()
        .with_context(|| format!("invalid zone origin {origin:?}"))?;
    name.set_fqdn(true);
    Ok(LowerName::from(name))
}

/// Whether two origins name the same zone. An unparseable side is not the same
/// zone as anything, including itself.
fn same_origin(left: &str, right: &str) -> bool {
    match (canonical_origin(left), canonical_origin(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{LogFormat, RecordSpec},
        metrics::Metrics,
    };
    use clap::Parser as _;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use tempfile::TempDir;

    /// GlobalArgs is a clap `Args` group, so it needs a `Parser` to be reached.
    #[derive(clap::Parser)]
    struct TestCli {
        #[command(flatten)]
        global: GlobalArgs,
    }

    /// An invocation, parsed exactly as the real command line would be.
    fn invocation(args: &[&str]) -> GlobalArgs {
        let mut full = vec!["vega"];
        full.extend_from_slice(args);
        TestCli::try_parse_from(full)
            .expect("args should parse")
            .global
    }

    /// A config file with `count` A records under `origin`.
    fn zone_toml(origin: &str, count: usize, server: &str) -> String {
        use std::fmt::Write as _;

        let mut toml = format!("[server]\n{server}\n[zone]\norigin = \"{origin}\"\n");
        for index in 0..count {
            let _ = write!(
                toml,
                "\n[[zone.records]]\nname = \"host{index}\"\ntype = \"A\"\nvalues = [\"203.0.113.{}\"]\n",
                index + 1
            );
        }
        toml
    }

    /// A started server, as far as reload cares about one.
    struct Fixture {
        _dir: TempDir,
        path: PathBuf,
        ctx: Arc<ReloadContext>,
        handler: Arc<DnsHandler>,
        metrics: Arc<Metrics>,
        draining: CancellationToken,
    }

    impl Fixture {
        fn start(toml: &str, args: &[&str]) -> Self {
            let dir = TempDir::new().expect("temp dir");
            let path = dir.path().join("vega.toml");
            std::fs::write(&path, toml).expect("config writes");

            let mut full: Vec<String> = vec!["--config".to_owned(), path.display().to_string()];
            full.extend(args.iter().map(|arg| (*arg).to_owned()));
            let borrowed: Vec<&str> = full.iter().map(String::as_str).collect();
            let args = invocation(&borrowed);

            let config = Config::load(&args).expect("the fixture config resolves");
            let zone = Arc::new(Zone::from_config(&config.zone).expect("the fixture zone builds"));
            let metrics = Arc::new(Metrics::new());
            metrics.set_zone_records(zone.record_count() as u64);
            let handler = Arc::new(DnsHandler::new(
                zone,
                &config.zone,
                Arc::clone(&metrics),
                None,
            ));
            let draining = CancellationToken::new();

            let ctx = Arc::new(ReloadContext::new(
                args,
                path.clone(),
                Arc::clone(&handler),
                Arc::clone(&metrics),
                config,
                draining.clone(),
            ));

            Self {
                _dir: dir,
                path,
                ctx,
                handler,
                metrics,
                draining,
            }
        }

        fn write(&self, toml: &str) {
            std::fs::write(&self.path, toml).expect("config rewrites");
        }

        fn reload(&self) -> Result<ReloadOutcome, ReloadError> {
            reload(&self.ctx)
        }
    }

    /// The gauge as a scrape would see it.
    fn gauge(metrics: &Metrics) -> u64 {
        metrics
            .render_prometheus()
            .lines()
            .find_map(|line| line.strip_prefix("dns_zone_records ")?.trim().parse().ok())
            .expect("the gauge is exposed")
    }

    // -----------------------------------------------------------------------
    // The invocation survives, and one precedence implementation serves both
    // paths. features/config-precedence.feature.
    // -----------------------------------------------------------------------

    /// Scenario: A reloaded server and a freshly started server resolve the same config
    /// features/config-precedence.feature:172
    ///
    /// Acceptance #7, field for field. The file disagrees with the invocation
    /// about everything, so a precedence rule that exists on only one of the two
    /// paths changes one side of this comparison.
    #[test]
    fn a_reload_resolves_the_same_config_as_startup_field_for_field() {
        let toml = zone_toml(
            "from-the-file.test",
            1,
            "log_level = \"trace\"\nadmin_token = \"from-the-file\"\n\
             tcp_timeout_secs = 30\nudp = [\"127.0.0.1:5399\"]\n",
        );
        let fixture = Fixture::start(
            &toml,
            &[
                "--domain",
                "example.test",
                "--no-builtins",
                "--udp",
                "127.0.0.1:5300",
                "--tcp-timeout-secs",
                "7",
                "--admin-token",
                "from-the-cli",
            ],
        );

        let startup = format!(
            "{:?}",
            Config::load(&fixture.ctx.invocation).expect("loads")
        );
        fixture.reload().expect("the reload succeeds");
        let after = {
            let running = fixture.ctx.state.lock().expect("the state lock is free");
            format!("{:?}", running.config)
        };

        assert_eq!(
            after, startup,
            "the reload path resolved a different configuration from the startup path"
        );
    }

    #[test]
    fn a_reload_keeps_the_origin_and_builtins_the_invocation_asked_for() {
        let fixture = Fixture::start(
            &zone_toml("from-the-file.test", 1, ""),
            &["--domain", "example.test", "--no-builtins"],
        );

        let outcome = fixture.reload().expect("the reload succeeds");
        assert_eq!(outcome.origin, "example.test");
        assert!(
            outcome.ignored.contains(&KEY_ORIGIN),
            "the shadowed file origin must be reported: {:?}",
            outcome.ignored
        );
        // `--no-builtins` is the value handed to `replace_zone`, so this is the
        // resolved state the diagnostic sub-zones are rebuilt from. The
        // end-to-end NXDOMAIN proof is
        // `tests/reload.rs::a_reload_does_not_re_enable_builtins_turned_off_on_the_command_line`.
        let running = fixture.ctx.state.lock().expect("the state lock is free");
        assert!(
            !running.config.zone.builtins,
            "the reload re-enabled built-ins the operator turned off"
        );
        assert_eq!(running.config.zone.origin, "example.test");
    }

    #[test]
    fn ten_reloads_with_no_file_change_report_the_same_thing_every_time() {
        let fixture = Fixture::start(&zone_toml("example.test", 2, ""), &[]);
        let first = fixture.reload().expect("the first reload succeeds");

        for round in 1..10u32 {
            let outcome = fixture.reload().expect("a later reload succeeds");
            assert_eq!(outcome, first, "round {round} drifted");
        }
    }

    // -----------------------------------------------------------------------
    // The origin is fixed for the process lifetime.
    // features/live-reload.feature.
    // -----------------------------------------------------------------------

    /// Scenario: A refused origin change never builds the new zone
    /// features/live-reload.feature:206
    #[test]
    fn an_origin_change_is_refused_before_the_zone_is_built() {
        let fixture = Fixture::start(&zone_toml("example.test", 1, ""), &[]);
        let before = fixture.handler.zone().record_count();

        // Wrong in two ways: a new origin *and* a record that cannot be built.
        // The origin gate is step 5 and the build is step 6, so the origin is what
        // must be reported.
        let mut toml = zone_toml("example.net", 0, "");
        toml.push_str(
            "\n[[zone.records]]\nname = \"bad\"\ntype = \"A\"\nvalues = [\"not-an-ip\"]\n",
        );
        fixture.write(&toml);

        let error = fixture.reload().expect_err("an origin change is refused");
        assert_eq!(error.code, ReloadErrorCode::OriginChanged);
        assert_eq!(error.running_origin.as_deref(), Some("example.test"));
        assert_eq!(error.requested_origin.as_deref(), Some("example.net"));
        assert_eq!(
            fixture.handler.zone().record_count(),
            before,
            "a refused reload replaced the serving zone"
        );
        assert_eq!(gauge(&fixture.metrics), before as u64);
    }

    /// Scenario: Adding a trailing dot to the origin is not an origin change
    /// features/live-reload.feature:190
    #[test]
    fn a_cosmetic_origin_edit_is_not_an_origin_change() {
        for spelling in ["example.test.", "EXAMPLE.TEST", "Example.Test."] {
            let fixture = Fixture::start(&zone_toml("example.test", 1, ""), &[]);
            fixture.write(&zone_toml(spelling, 2, ""));

            let outcome = fixture
                .reload()
                .unwrap_or_else(|error| panic!("{spelling} was refused: {error}"));
            assert_eq!(outcome.records, 2, "{spelling} did not apply its records");
            assert!(
                !outcome.ignored.contains(&KEY_ORIGIN),
                "{spelling} is the same zone, so it is not shadowed drift"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Fixed settings are reported, never silent.
    // -----------------------------------------------------------------------

    /// Disjunct (a) on its own: `fresh` is byte-identical to `running`, which is
    /// what a CLI-shadowed file edit produces, so every key here comes from the
    /// file tier alone.
    #[test]
    fn drift_names_every_fixed_key_the_file_changed() {
        let running = Config::load(&invocation(&[
            "--domain",
            "example.test",
            "--udp",
            "127.0.0.1:5300",
        ]))
        .expect("the running config resolves");
        let fresh = Config::load(&invocation(&[
            "--domain",
            "example.test",
            "--udp",
            "127.0.0.1:5300",
        ]))
        .expect("the fresh config resolves");

        let stated = FileSettings {
            origin: Some("other.test".to_owned()),
            udp: vec!["127.0.0.1:5399".parse().expect("addr")],
            tcp: vec!["127.0.0.1:5398".parse().expect("addr")],
            admin_listen: Some("127.0.0.1:5397".parse().expect("addr")),
            tcp_timeout_secs: Some(30),
            shutdown_drain_secs: Some(42),
            log_format: Some(LogFormat::Json),
            log_level: Some("trace".to_owned()),
            admin_token: Some("from-the-file".to_owned()),
            rate_limit_qps: Some(1000),
            rate_limit_burst: Some(2000),
        };

        assert_eq!(
            drift(&running, &stated, &fresh),
            vec![
                KEY_ORIGIN,
                KEY_UDP,
                KEY_TCP,
                KEY_ADMIN_LISTEN,
                KEY_TCP_TIMEOUT,
                KEY_SHUTDOWN_DRAIN,
                KEY_LOG_FORMAT,
                KEY_LOG_LEVEL,
                KEY_ADMIN_TOKEN,
                KEY_RATE_LIMIT_QPS,
                KEY_RATE_LIMIT_BURST,
            ]
        );
    }

    #[test]
    fn drift_is_empty_when_the_file_asks_for_what_the_process_already_does() {
        let args = [
            "--domain",
            "example.test",
            "--udp",
            "127.0.0.1:5300",
            "--rate-limit-qps",
            "10",
        ];
        let running = Config::load(&invocation(&args)).expect("the running config resolves");
        let fresh = Config::load(&invocation(&args)).expect("the fresh config resolves");

        let stated = FileSettings {
            origin: Some("EXAMPLE.TEST.".to_owned()),
            udp: vec!["127.0.0.1:5300".parse().expect("addr")],
            tcp: Vec::new(),
            admin_listen: None,
            tcp_timeout_secs: Some(10),
            shutdown_drain_secs: Some(
                i64::try_from(crate::config::DEFAULT_SHUTDOWN_DRAIN.as_secs()).expect("in range"),
            ),
            log_format: Some(LogFormat::Pretty),
            log_level: Some(crate::config::DEFAULT_LOG_FILTER.to_owned()),
            admin_token: None,
            rate_limit_qps: Some(10),
            rate_limit_burst: Some(20),
        };

        assert!(drift(&running, &stated, &fresh).is_empty());
        // Criterion 31 as a pure function: a file that mentions nothing, against
        // an invocation that supplies everything, is not drift.
        assert!(drift(&running, &FileSettings::default(), &fresh).is_empty());
    }

    /// Disjunct (b) on its own: the file states nothing, so (a) is silent, but a
    /// restart would now resolve something else. Ruling Amendment 1.
    #[test]
    fn drift_names_a_fixed_key_only_a_restart_would_move() {
        let running = Config::load(&invocation(&["--domain", "example.test"]))
            .expect("the running config resolves");
        let mut fresh = Config::load(&invocation(&["--domain", "example.test"]))
            .expect("the fresh config resolves");

        // What deleting `[server] udp` and `[server] admin_token` from the file
        // leaves behind, with nothing on the command line to hold them up.
        fresh.udp = vec!["0.0.0.0:1053".parse().expect("addr")];
        fresh.admin_token = None;
        let mut running = running;
        running.udp = vec!["0.0.0.0:53".parse().expect("addr")];
        running.admin_token = Some("s3cret".to_owned());

        assert_eq!(
            drift(&running, &FileSettings::default(), &fresh),
            vec![KEY_UDP, KEY_ADMIN_TOKEN]
        );
    }

    #[test]
    fn a_key_both_disjuncts_report_appears_once() {
        let running = Config::load(&invocation(&["--domain", "example.test"]))
            .expect("the running config resolves");
        let mut fresh = Config::load(&invocation(&["--domain", "example.test"]))
            .expect("the fresh config resolves");
        fresh.log_level = "trace".to_owned();

        let stated = FileSettings {
            log_level: Some("trace".to_owned()),
            ..FileSettings::default()
        };

        assert_eq!(drift(&running, &stated, &fresh), vec![KEY_LOG_LEVEL]);
    }

    /// Scenario: A fixed setting that still drifts is reported on every reload
    /// features/live-reload.feature:270
    #[test]
    fn a_fixed_setting_that_still_drifts_is_reported_on_every_reload() {
        let fixture = Fixture::start(&zone_toml("example.test", 1, ""), &[]);
        fixture.write(&zone_toml(
            "example.test",
            1,
            "udp = [\"127.0.0.1:5399\"]\nlog_level = \"trace\"\n",
        ));

        for round in 1..=3u32 {
            let outcome = fixture.reload().expect("the reload succeeds");
            assert!(
                outcome.ignored.contains(&KEY_UDP) && outcome.ignored.contains(&KEY_LOG_LEVEL),
                "round {round}: the drift from what is actually bound still exists, so it must \
                 still be reported; a `running = fresh` assignment silences this: {:?}",
                outcome.ignored
            );
        }
    }

    /// Criterion 30: a deleted fixed key falls through and is reported.
    /// features/live-reload.feature group D, ruling Amendment 1 disjunct (b).
    #[test]
    fn a_fixed_key_deleted_from_the_file_is_reported_because_a_restart_would_move_it() {
        // Nothing on the command line supplies these, so the file is their only
        // source and deleting them changes what a restart would resolve: the
        // listener falls back to the built-in `0.0.0.0:1053`, and `/reload` would
        // come back loopback-only. The running process is unaffected — which is
        // exactly why silence here stages an outage for the next restart.
        let fixture = Fixture::start(
            &zone_toml(
                "example.test",
                1,
                "udp = [\"127.0.0.1:5399\"]\nadmin_token = \"s3cret\"\n",
            ),
            &[],
        );

        fixture.write(&zone_toml("example.test", 1, ""));
        let outcome = fixture.reload().expect("the reload succeeds");

        assert!(
            outcome.ignored.contains(&KEY_UDP),
            "a deleted listener key falls through to the built-in default at the next \
             restart; a 200 that does not say so stages an outage: {:?}",
            outcome.ignored
        );
        assert!(
            outcome.ignored.contains(&KEY_ADMIN_TOKEN),
            "a deleted admin_token makes the next restart's /reload loopback-only: {:?}",
            outcome.ignored
        );

        let running = fixture.ctx.state.lock().expect("the state lock is free");
        assert_eq!(
            running.config.udp,
            vec!["127.0.0.1:5399"
                .parse::<std::net::SocketAddr>()
                .expect("addr")],
            "the running process keeps the socket it actually has"
        );
        assert_eq!(running.config.admin_token.as_deref(), Some("s3cret"));
    }

    /// Criterion 31: absent-and-shadowed is silent.
    /// features/live-reload.feature group D, ruling Amendment 1.
    #[test]
    fn a_key_the_file_never_mentions_is_silent_when_the_invocation_supplies_it() {
        // The guard against over-correcting: `ignored` means "the file's view of
        // this key is not this process's view", not "you passed a flag". An
        // operator who never wrote the key asked for nothing, so nothing was
        // ignored.
        let fixture = Fixture::start(
            &zone_toml("example.test", 1, ""),
            &[
                "--udp",
                "127.0.0.1:5300",
                "--admin-token",
                "from-the-cli",
                "--tcp-timeout-secs",
                "45",
                "--rate-limit-qps",
                "10",
            ],
        );

        let outcome = fixture.reload().expect("the reload succeeds");
        assert!(
            outcome.ignored.is_empty(),
            "a flag the file does not mention is not drift: {:?}",
            outcome.ignored
        );
    }

    #[test]
    fn a_reloadable_setting_is_applied_and_never_reported_as_ignored() {
        let fixture = Fixture::start(&zone_toml("example.test", 1, ""), &[]);
        fixture.write(&zone_toml("example.test", 4, ""));

        let outcome = fixture.reload().expect("the reload succeeds");
        assert_eq!(outcome.records, 4);
        assert_eq!(fixture.handler.zone().record_count(), 4);
        assert!(outcome.ignored.is_empty(), "{:?}", outcome.ignored);
    }

    // -----------------------------------------------------------------------
    // Failure modes leave the zone untouched.
    // -----------------------------------------------------------------------

    #[test]
    fn every_failure_mode_names_its_code_and_leaves_the_zone_alone() {
        let good = zone_toml("example.test", 3, "");
        let mut broken = zone_toml("example.test", 0, "");
        broken.push_str("\n[[zone.records]]\nname = \"bad\"\ntype = \"A\"\nvalues = [\"nope\"]\n");

        let cases: Vec<(ReloadErrorCode, Option<String>)> = vec![
            (ReloadErrorCode::ConfigReadFailed, None),
            (
                ReloadErrorCode::ConfigParseFailed,
                Some("[zone\norigin = ".to_owned()),
            ),
            (
                ReloadErrorCode::ConfigInvalid,
                // No record tables, so the key lands in `[zone]` and not inside a
                // `[[zone.records]]` entry — this has to be rejected by the merge,
                // not by the parser.
                Some(format!(
                    "{}default_ttl = 0\n",
                    zone_toml("example.test", 0, "")
                )),
            ),
            (ReloadErrorCode::ZoneBuildFailed, Some(broken)),
            (
                ReloadErrorCode::OriginChanged,
                Some(zone_toml("example.net", 1, "")),
            ),
        ];

        for (code, toml) in cases {
            let fixture = Fixture::start(&good, &[]);
            match &toml {
                Some(toml) => fixture.write(toml),
                None => std::fs::remove_file(&fixture.path).expect("the config is removable"),
            }

            let error = fixture.reload().expect_err("a broken config is refused");
            assert_eq!(error.code, code, "{}", error.detail);
            assert_eq!(
                fixture.handler.zone().record_count(),
                3,
                "{code} replaced the serving zone"
            );
            assert_eq!(gauge(&fixture.metrics), 3, "{code} moved the gauge");
        }
    }

    /// Scenario: A refused reload never echoes the admin_token line
    /// features/live-reload.feature:339
    ///
    /// The counterpart to `drift`'s rule three lines above its body: the key
    /// path is reportable, the value never is. `drift` honoured it and this
    /// path did not (VEGA-082) — the failure detail goes into the `/reload`
    /// response body *and* into `admin.rs`'s WARN line, which ships as JSON to
    /// stdout under the shipped k8s manifest.
    #[test]
    fn a_refused_reload_reports_where_the_parse_failed_and_never_the_line_itself() {
        const SECRET: &str = "SUPER-SECRET-TOKEN-1";
        let broken =
            format!("[server]\nadmin_token = \"{SECRET}\n[zone]\norigin = \"example.test\"\n");
        let duplicated = format!(
            "[server]\nadmin_token = \"{SECRET}\"\nadmin_token = \"{SECRET}\"\n\
             [zone]\norigin = \"example.test\"\n"
        );

        for toml in [broken, duplicated] {
            let fixture = Fixture::start(&zone_toml("example.test", 1, ""), &[]);
            fixture.write(&toml);

            let error = fixture.reload().expect_err("broken TOML is refused");
            assert_eq!(error.code, ReloadErrorCode::ConfigParseFailed);
            assert!(
                !error.detail.contains(SECRET),
                "the detail is rendered into the response body and the WARN log: {}",
                error.detail
            );
            assert!(
                error.detail.contains("line 2") || error.detail.contains("line 3"),
                "an operator still needs to be sent to the offending line: {}",
                error.detail
            );
            assert!(
                error.detail.contains("column"),
                "an operator still needs the column: {}",
                error.detail
            );
        }
    }

    #[test]
    fn a_read_failure_names_the_file_an_operator_has_to_restore() {
        let fixture = Fixture::start(&zone_toml("example.test", 1, ""), &[]);
        let path = fixture.path.display().to_string();
        std::fs::remove_file(&fixture.path).expect("the config is removable");

        let error = fixture.reload().expect_err("a missing file is refused");
        assert!(error.detail.contains(&path), "{}", error.detail);
    }

    // -----------------------------------------------------------------------
    // Concurrency, shutdown and ordering. These are the four criteria that were
    // @gap while the hook lived in src/main.rs.
    // -----------------------------------------------------------------------

    /// Scenario: A reload arriving after the drain has started is refused
    /// features/live-reload.feature (group F, VEGA-046 invariant I1)
    #[test]
    fn a_reload_after_the_drain_has_started_is_refused_and_swaps_nothing() {
        let fixture = Fixture::start(&zone_toml("example.test", 1, ""), &[]);
        fixture.write(&zone_toml("example.test", 5, ""));
        fixture.draining.cancel();

        let error = fixture.reload().expect_err("a draining process refuses");
        assert_eq!(error.code, ReloadErrorCode::ShuttingDown);
        assert_eq!(
            fixture.handler.zone().record_count(),
            1,
            "a zone was installed into a process that is going away"
        );
        assert_eq!(gauge(&fixture.metrics), 1);
    }

    /// Scenario: Concurrent reload requests are each applied or refused as in progress
    /// features/live-reload.feature:436
    #[test]
    fn a_second_reload_holding_no_lock_is_refused_as_in_progress() {
        let fixture = Fixture::start(&zone_toml("example.test", 1, ""), &[]);
        let held = fixture.ctx.state.lock().expect("the state lock is free");

        let error = fixture
            .reload()
            .expect_err("a concurrent reload is refused");
        assert_eq!(error.code, ReloadErrorCode::ReloadInProgress);

        drop(held);
        fixture.reload().expect("the winner's successor succeeds");
    }

    /// Scenario: A panicking reload does not leave the reload mutex poisoned
    /// features/live-reload.feature (group F)
    #[test]
    fn a_poisoned_state_lock_is_recovered_rather_than_bricking_reload() {
        // Debug builds only in production terms — `panic = "abort"` means a
        // release build never sees a poisoned mutex. The recovery still matters:
        // the alternative is a process whose reload endpoint is dead until it is
        // restarted, which is precisely the outage a reload exists to avoid.
        let fixture = Fixture::start(&zone_toml("example.test", 1, ""), &[]);
        let ctx = Arc::clone(&fixture.ctx);
        let poisoner = std::thread::spawn(move || {
            let _guard = ctx.state.lock().expect("the state lock is free");
            panic!("a reload panicked while holding the state lock");
        });
        assert!(poisoner.join().is_err(), "the poisoning thread must panic");
        assert!(fixture.ctx.state.is_poisoned(), "the lock must be poisoned");

        fixture.write(&zone_toml("example.test", 2, ""));
        let outcome = fixture
            .reload()
            .expect("a poisoned lock must not brick reload for the process's life");
        assert_eq!(outcome.records, 2);
    }

    /// Scenario: The record-count gauge never describes a zone that is not installed
    /// features/live-reload.feature (group G)
    #[test]
    fn the_records_gauge_never_leads_the_zone_swap() {
        // The zones only ever grow, so "the gauge is ahead of the installed zone"
        // is decidable from a sample: with the gauge set *before* the swap there
        // is a window where it advertises a record count no installed zone has
        // had yet. Sampling it concurrently catches that; the fixed order cannot
        // produce it at all.
        let rounds = 40usize;
        let fixture = Fixture::start(&zone_toml("example.test", 1, ""), &[]);

        let stop = Arc::new(AtomicBool::new(false));
        let violations = Arc::new(AtomicU64::new(0));
        let sampler = {
            let handler = Arc::clone(&fixture.handler);
            let metrics = Arc::clone(&fixture.metrics);
            let stop = Arc::clone(&stop);
            let violations = Arc::clone(&violations);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let scraped = gauge(&metrics);
                    let installed = handler.zone().record_count() as u64;
                    if scraped > installed {
                        violations.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        };

        for count in 2..=rounds {
            fixture.write(&zone_toml("example.test", count, ""));
            let outcome = fixture.reload().expect("the reload succeeds");
            assert_eq!(outcome.records, count);
        }
        stop.store(true, Ordering::Relaxed);
        sampler.join().expect("the sampler finishes");

        assert_eq!(
            violations.load(Ordering::Relaxed),
            0,
            "dns_zone_records reported a count no installed zone had: the gauge is \
             being set before the swap"
        );
    }

    #[test]
    fn the_frozen_source_is_the_file_every_reload_reads() {
        let fixture = Fixture::start(&zone_toml("example.test", 1, ""), &[]);
        assert_eq!(fixture.ctx.source(), fixture.path);
        assert_eq!(
            fixture.ctx.invocation.config.as_deref(),
            Some(&*fixture.path)
        );
    }

    #[test]
    fn apply_reloadable_moves_the_reloadable_half_and_nothing_else() {
        let mut running = Running {
            config: Config::load(&invocation(&["--domain", "example.test"]))
                .expect("the running config resolves"),
        };
        let mut fresh = Config::load(&invocation(&["--domain", "example.test"]))
            .expect("the fresh config resolves");
        fresh.zone.default_ttl = 60;
        fresh.zone.builtins = false;
        fresh.zone.records = vec![RecordSpec {
            name: "www".to_owned(),
            record_type: "A".to_owned(),
            ttl: None,
            values: vec!["203.0.113.10".to_owned()],
        }];
        fresh.udp = vec!["127.0.0.1:5399".parse().expect("addr")];
        fresh.log_level = "trace".to_owned();

        let bound = running.config.udp.clone();
        running.apply_reloadable(fresh);

        assert_eq!(running.config.zone.default_ttl, 60);
        assert!(!running.config.zone.builtins);
        assert_eq!(running.config.zone.records.len(), 1);
        assert_eq!(
            running.config.udp, bound,
            "a fixed field followed the file; drift reporting would then go quiet \
             while the socket stayed where it was"
        );
        assert_ne!(running.config.log_level, "trace");
    }

    #[test]
    fn origins_compare_as_dns_names_not_as_strings() {
        assert!(same_origin("example.test", "example.test."));
        assert!(same_origin("EXAMPLE.TEST", "example.test"));
        assert!(!same_origin("example.test", "example.net"));
        assert!(!same_origin("sub.example.test", "example.test"));
        // An unparseable origin is not equal to anything, so it reports as drift
        // rather than being quietly treated as unchanged.
        assert!(!same_origin("bad..name", "bad..name"));
    }
}
