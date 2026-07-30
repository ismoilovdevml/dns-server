//! Entry point: parse the command line, then either run the server or one of the
//! management subcommands.

use std::{
    net::SocketAddr,
    process::ExitCode,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use clap::{CommandFactory as _, Parser as _};
use hickory_server::Server;
use tokio::net::{TcpListener, UdpSocket};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, layer::SubscriberExt as _, util::SubscriberInitExt as _, EnvFilter};
use vega::{
    admin::{self, AdminState},
    cli::{Cli, Command, RecordAction, ZoneAction},
    commands::{inspect, record, zone as zone_cmd},
    config::{Config, GlobalArgs, LogFormat},
    dnsclient,
    handler::DnsHandler,
    healthcheck,
    lifecycle::{Lifecycle, Phase},
    metrics::Metrics,
    ratelimit::{RateLimiter, DEFAULT_IDLE_TTL},
    reload::ReloadContext,
    shutdown::{self, Signals},
    ui,
    zone::Zone,
};

/// How often the rate-limiter janitor sweeps out idle buckets.
const JANITOR_INTERVAL: Duration = Duration::from_secs(60);

/// How long `Stopping` waits for in-flight requests before cancelling the DNS
/// token.
///
/// Hickory drops the `JoinSet` holding every connection task the instant its
/// token is cancelled, which aborts them mid-response, so this is the only
/// window an in-flight TCP query has (RFC 7766 §6.2.4 permits the close and puts
/// retry on the client — but a retry is seconds the client did not have to pay).
/// Capped rather than unbounded: the listeners are still accepting throughout,
/// so under sustained load in-flight never reaches zero and the only way out
/// would be `SIGKILL`.
const QUIESCE_CAP: Duration = Duration::from_secs(1);

/// How often the quiesce loop re-reads the in-flight count. Small enough that a
/// finished request is noticed immediately, large enough not to spin.
const QUIESCE_POLL: Duration = Duration::from_millis(5);

/// Budget for `Stopping` plus `Closing`, on top of the drain window.
///
/// Covers the quiesce cap (1s), joining the accept tasks (microseconds) and
/// axum's graceful shutdown of open admin connections. An order of magnitude
/// over the measured cost of all three, and deliberately not configurable: one
/// knob for the drain is enough for an operator to reason about.
const STOP_BUDGET: Duration = Duration::from_secs(5);

/// Grace on top of the hard deadline before the OS-thread watchdog exits.
const WATCHDOG_GRACE: Duration = Duration::from_secs(2);

/// Exit code for a shutdown that overran its hard deadline.
///
/// Distinct from clean (0), startup failure (1) and clap's usage error (2), so
/// `lastState.terminated.exitCode` or `systemctl status` says what happened.
const OVERRUN_EXIT_CODE: u8 = 3;

/// Environment variables renamed by the `dns-server` → `vega` rebrand.
///
/// Kept working so an upgrade does not silently change what a running
/// deployment listens on — the failure mode of dropping these is a name server
/// that comes back on the wrong port, with nothing in the logs to say why.
const RENAMED_ENV: &[(&str, &str)] = &[
    ("DNS_CONFIG", "VEGA_CONFIG"),
    ("DNS_UDP", "VEGA_UDP"),
    ("DNS_TCP", "VEGA_TCP"),
    ("DNS_ADMIN_LISTEN", "VEGA_ADMIN_LISTEN"),
    ("DNS_ADMIN_TOKEN", "VEGA_ADMIN_TOKEN"),
    ("DNS_DOMAIN", "VEGA_DOMAIN"),
    ("DNS_RATE_LIMIT_QPS", "VEGA_RATE_LIMIT_QPS"),
    ("DNS_RATE_LIMIT_BURST", "VEGA_RATE_LIMIT_BURST"),
    ("DNS_TCP_TIMEOUT_SECS", "VEGA_TCP_TIMEOUT_SECS"),
    ("DNS_NO_BUILTINS", "VEGA_NO_BUILTINS"),
    ("DNS_LOG_FORMAT", "VEGA_LOG_FORMAT"),
    ("DNS_LOG_LEVEL", "VEGA_LOG_LEVEL"),
];

/// Promote any legacy `DNS_*` variable to its `VEGA_*` name.
///
/// Runs before clap reads the environment. The new name always wins, so setting
/// both is unambiguous rather than order-dependent. Warnings go to stderr
/// because tracing is not initialised this early, and an operator running an
/// upgrade needs to see this on the terminal regardless of log configuration.
fn migrate_legacy_env() {
    for (old, new) in RENAMED_ENV {
        if std::env::var_os(new).is_some() {
            continue;
        }
        if let Some(value) = std::env::var_os(old) {
            // SAFETY-adjacent: single-threaded, before any runtime starts.
            std::env::set_var(new, value);
            eprintln!("warning: {old} is deprecated and will be removed; use {new}");
        }
    }
}

fn main() -> ExitCode {
    migrate_legacy_env();

    let cli = Cli::parse();
    ui::init(cli.global.json, cli.global.verbose);

    match dispatch(&cli) {
        Ok(code) => code,
        Err(error) => {
            report(&error, cli.global.json);
            ExitCode::FAILURE
        }
    }
}

/// Route to the right subcommand. Returns the process exit code.
fn dispatch(cli: &Cli) -> Result<ExitCode> {
    let config_path = cli.config_path();

    // Everything that loads a Config must see the file the search path found, not
    // only an explicit --config. Otherwise `vega check` run next to a
    // vega.toml would silently validate the built-in defaults instead.
    let global = GlobalArgs {
        config: config_path.clone(),
        ..cli.global.clone()
    };

    match &cli.command {
        // `None` is the default so plain `vega` still starts the server.
        None | Some(Command::Serve) => serve_command(&global),

        Some(Command::Check) => {
            let config = Config::load(&global)?;
            zone_cmd::check(&config, config_path.as_deref(), cli.global.json)?;
            Ok(ExitCode::SUCCESS)
        }

        Some(Command::Init { origin, output }) => {
            zone_cmd::init(output.as_deref(), origin, cli.global.json)?;
            Ok(ExitCode::SUCCESS)
        }

        Some(Command::Record { action }) => record_command(cli, config_path.as_deref(), action),

        Some(Command::Zone { action }) => match action {
            ZoneAction::Show => {
                zone_cmd::show(config_path.as_deref(), cli.global.json)?;
                Ok(ExitCode::SUCCESS)
            }
            ZoneAction::Export => {
                zone_cmd::export(config_path.as_deref())?;
                Ok(ExitCode::SUCCESS)
            }
            ZoneAction::BumpSerial => {
                zone_cmd::bump_serial(config_path.as_deref(), cli.global.json)?;
                Ok(ExitCode::SUCCESS)
            }
        },

        Some(Command::Query {
            name,
            record_type,
            server,
            use_tcp,
        }) => {
            let target = query_target(&global, server.as_deref())?;
            let ok = block_on(inspect::query(
                target,
                name,
                record_type,
                *use_tcp,
                cli.global.json,
            ))?;
            Ok(exit_code(ok))
        }

        Some(Command::Status) => {
            let addr = admin_addr(&cli.global);
            let ok = block_on(inspect::status(
                addr,
                cli.global.admin_token.as_deref(),
                cli.global.json,
            ))?;
            Ok(exit_code(ok))
        }

        Some(Command::Reload) => {
            let addr = admin_addr(&cli.global);
            let ok = block_on(inspect::reload(
                addr,
                cli.global.admin_token.as_deref(),
                cli.global.json,
            ))?;
            Ok(exit_code(ok))
        }

        Some(Command::Healthcheck) => {
            let addr = admin_addr(&cli.global);
            match block_on(healthcheck::probe(addr)) {
                Ok(()) => Ok(ExitCode::SUCCESS),
                Err(error) => {
                    report(&error, cli.global.json);
                    Ok(ExitCode::FAILURE)
                }
            }
        }

        Some(Command::Completions { shell }) => {
            let mut command = Cli::command();
            let name = command.get_name().to_owned();
            clap_complete::generate(*shell, &mut command, name, &mut std::io::stdout());
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn record_command(
    cli: &Cli,
    config_path: Option<&std::path::Path>,
    action: &RecordAction,
) -> Result<ExitCode> {
    let json = cli.global.json;

    match action {
        RecordAction::List { name, record_type } => {
            record::list(config_path, name.as_deref(), record_type.as_deref(), json)?;
            Ok(ExitCode::SUCCESS)
        }

        RecordAction::Get { name, record_type } => {
            // Exit non-zero when nothing matched, so `if vega record get …`
            // works in a shell script.
            let found = record::get(config_path, name, record_type.as_deref(), json)?;
            Ok(exit_code(found))
        }

        RecordAction::Add {
            name,
            record_type,
            values,
            ttl,
            replace,
            bump_serial,
            reload,
        } => {
            record::add(
                config_path,
                name,
                record_type,
                values,
                *ttl,
                *replace,
                *bump_serial,
                json,
            )?;
            finish_edit(cli, *reload)
        }

        RecordAction::Delete {
            name,
            record_type,
            values,
            bump_serial,
            reload,
        } => {
            record::delete(
                config_path,
                name,
                record_type.as_deref(),
                values,
                *bump_serial,
                json,
            )?;
            finish_edit(cli, *reload)
        }
    }
}

/// After an edit, optionally tell the running server to pick it up.
fn finish_edit(cli: &Cli, reload: bool) -> Result<ExitCode> {
    if !reload {
        return Ok(ExitCode::SUCCESS);
    }
    let addr = admin_addr(&cli.global);
    let ok = block_on(record::reload_server(
        addr,
        cli.global.admin_token.as_deref(),
        cli.global.json,
    ))?;
    Ok(exit_code(ok))
}

fn serve_command(global: &GlobalArgs) -> Result<ExitCode> {
    let config = Config::load(global)?;
    init_tracing(&config);

    // `global` is the invocation a reload re-resolves against, forever: the
    // command line and environment as parsed here, with `config` already resolved
    // through the search path.
    match run(config, global.clone()) {
        // The code comes from the shutdown path: 0 when every phase completed
        // inside the deadline, 3 when it did not.
        Ok(code) => Ok(code),
        Err(error) => {
            error!("{error:#}");
            Ok(ExitCode::FAILURE)
        }
    }
}

/// The admin endpoint a client subcommand should talk to.
fn admin_addr(global: &GlobalArgs) -> SocketAddr {
    global.admin_listen.unwrap_or_else(|| {
        healthcheck::DEFAULT_ADMIN_ADDR
            .parse()
            .expect("the default admin address is a valid SocketAddr")
    })
}

/// Where `query` should send its question.
///
/// `--server` wins; otherwise the first configured listener, so `query` follows
/// whatever the local config describes; otherwise `127.0.0.1:53`.
fn query_target(global: &GlobalArgs, server: Option<&str>) -> Result<SocketAddr> {
    if let Some(server) = server {
        return dnsclient::parse_server(server);
    }
    if let Ok(config) = Config::load(global) {
        if let Some(addr) = config.udp.first().or_else(|| config.tcp.first()) {
            // A wildcard bind is not a usable destination; talk to loopback instead.
            return Ok(if addr.ip().is_unspecified() {
                SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), addr.port())
            } else {
                *addr
            });
        }
    }
    dnsclient::parse_server("127.0.0.1:53")
}

/// A short-lived runtime for the client subcommands.
fn block_on<T>(future: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building a tokio runtime")?
        .block_on(future)
}

fn exit_code(ok: bool) -> ExitCode {
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Report an error, honouring `--json` so a script gets something parseable.
fn report(error: &anyhow::Error, as_json: bool) {
    if as_json {
        let value = serde_json::json!({
            "ok": false,
            "error": format!("{error:#}"),
        });
        println!("{value}");
    } else {
        eprintln!("{} {error:#}", ui::cross());
    }
}

fn run(config: Config, invocation: GlobalArgs) -> Result<ExitCode> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building the tokio runtime")?;
    runtime.block_on(serve(config, invocation))
}

/// Bind the listeners, serve, and run the shutdown state machine.
///
/// The ordering below is the whole of VEGA-046 and is the reason the three
/// cancellation tokens are never shared:
///
/// 1. `drain_start` — cancelled first. `/readyz` answers 503 and `/reload` fails
///    closed, while every DNS listener is still bound and answering.
/// 2. `dns` (hickory's own) — cancelled when the window has elapsed and
///    in-flight requests have quiesced.
/// 3. `admin` — cancelled last, so a probe still gets an answer after DNS has
///    gone rather than a connection refused it cannot distinguish from a crash.
///
/// Handing any of these to something that cancels another was the defect: a
/// `SIGTERM` cancelled the accept loops directly, the sockets were gone in
/// 1.3 ms, and the 503 the whole drain exists to serve was never on the wire.
async fn serve(config: Config, invocation: GlobalArgs) -> Result<ExitCode> {
    let zone = Arc::new(Zone::from_config(&config.zone).context("building the zone")?);
    let metrics = Arc::new(Metrics::new());
    metrics.set_zone_records(zone.record_count() as u64);

    let limiter = config
        .rate_limit
        .map(|rl| Arc::new(RateLimiter::new(rl.qps, rl.burst)));

    // The reload hook and the server share one handler, so a swapped zone is
    // visible to both.
    let handler = Arc::new(DnsHandler::new(
        Arc::clone(&zone),
        &config.zone,
        Arc::clone(&metrics),
        limiter.clone(),
    ));

    let lifecycle = Arc::new(Lifecycle::new());

    // Install the signal handlers before binding anything. A SIGTERM that
    // arrives mid-startup must find a handler, not the default disposition.
    let signals = shutdown::watch();

    let mut server = Server::new(SharedHandler(Arc::clone(&handler)));
    let dns = server.shutdown_token().clone();

    bind_dns(&mut server, &config).await?;

    // Bind the admin listener before reporting ready (VEGA-044). Binding inside
    // the spawned task meant a taken port surfaced as a task that quietly died
    // after startup, with the process still claiming success.
    let admin_listener = match config.admin_listen {
        Some(addr) => Some(admin::bind(addr).await?),
        None => None,
    };

    // Two tokens of our own, cancelled at opposite ends of the sequence, and
    // neither of them hickory's.
    let drain_start = CancellationToken::new();
    let admin_shutdown = CancellationToken::new();

    let mut admin_state = AdminState::new(Arc::clone(&metrics))
        .with_lifecycle(Arc::clone(&lifecycle))
        .with_token(config.admin_token.clone());
    // Reload only makes sense when there is a file to re-read.
    if let Some(source) = config.source.clone() {
        // The *drain-start* token, not the listener-cancel one. The two were the
        // same instant before this change and are seconds apart after it, so
        // gating a reload on the later half would let a new zone be installed
        // throughout the whole drain — strictly worse than the old behaviour.
        admin_state = admin_state.with_reload(vega::reload::hook(Arc::new(ReloadContext::new(
            invocation,
            source,
            Arc::clone(&handler),
            Arc::clone(&metrics),
            config.clone(),
            drain_start.clone(),
        ))));
    }

    let admin_task = admin_listener.map(|listener| {
        let state = admin_state.clone();
        let token = admin_shutdown.clone();
        let signals = signals.clone();
        tokio::spawn(async move {
            if let Err(error) = admin::serve(listener, state, token).await {
                error!("{error:#}");
                // A dead metrics endpoint means a blind operator, so this is
                // fatal — but it goes through the same machine a signal uses, so
                // DNS drains instead of dying in the same instant.
                signals.abort();
            }
        })
    });

    if let Some(limiter) = limiter.clone() {
        // A background sweeper with no client-visible state: it must not outlive
        // the listeners it serves, and it must not be able to stop them.
        spawn_janitor(limiter, dns.child_token());
    }

    log_shutdown_plan(&config);
    info!(
        version = vega::VERSION,
        zone = %config.zone.origin,
        records = zone.record_count(),
        builtins = config.zone.builtins,
        rate_limited = config.rate_limit.is_some(),
        reloadable = config.source.is_some(),
        "vega ready"
    );
    lifecycle.enter(Phase::Serving);

    // Steady state. `block_until_done` is in the select so that listeners dying
    // on their own is still a failure rather than a silent hang.
    let cause = tokio::select! {
        cause = signals.first() => cause,
        result = server.block_until_done() => {
            admin_shutdown.cancel();
            result.context("dns server terminated with an error")?;
            bail!("the DNS listeners stopped before any shutdown signal arrived");
        }
    };

    let window = cause.drain_window(config.shutdown_drain);
    let deadline = Instant::now() + window + STOP_BUDGET;
    lifecycle.arm_deadline(deadline);
    // Armed before the first await of the sequence, because the failure it
    // covers is precisely a runtime that never gets to another await.
    arm_watchdog(deadline + WATCHDOG_GRACE, Arc::clone(&lifecycle));
    info!(
        signal = cause.as_str(),
        drain_secs = window.as_secs(),
        "shutdown starting"
    );

    let sequence = Shutdown {
        lifecycle: &lifecycle,
        signals: &signals,
        metrics: &metrics,
        drain_start,
        dns,
        admin: admin_shutdown,
        admin_task,
        window,
    };
    Ok(sequence.execute(&mut server, deadline).await)
}

/// Bind every configured DNS listener and hand it to the server.
///
/// A bind failure is a startup failure: naming the address is what turns
/// "vega exited 1" into "port 53 is already in use" at 3am.
async fn bind_dns(server: &mut Server<SharedHandler>, config: &Config) -> Result<()> {
    for addr in &config.udp {
        let socket = UdpSocket::bind(addr)
            .await
            .with_context(|| format!("binding UDP {addr}"))?;
        info!(%addr, "listening on UDP");
        server.register_socket(socket);
    }

    for addr in &config.tcp {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding TCP {addr}"))?;
        info!(%addr, "listening on TCP");
        server.register_listener(listener, config.tcp_timeout, config.tcp_response_buffer);
    }

    Ok(())
}

/// Everything the shutdown sequence touches, gathered so that the ordering reads
/// as one list in one place.
struct Shutdown<'a> {
    lifecycle: &'a Lifecycle,
    signals: &'a Signals,
    metrics: &'a Metrics,
    /// Cancelled first: `/reload` fails closed from here on.
    drain_start: CancellationToken,
    /// Hickory's own token: the UDP and TCP accept loops, and by `JoinSet` drop
    /// every connection task with them.
    dns: CancellationToken,
    /// The admin server's token. Cancelled last.
    admin: CancellationToken,
    admin_task: Option<tokio::task::JoinHandle<()>>,
    /// How long to keep answering after the 503 goes out.
    window: Duration,
}

impl Shutdown<'_> {
    /// Run the sequence under the hard deadline and report the process exit code.
    ///
    /// The deadline is enforced here, on the main task, by a timer. That covers
    /// everything except a runtime with nothing left to poll it — which is what
    /// [`arm_watchdog`] is for.
    async fn execute(self, server: &mut Server<SharedHandler>, deadline: Instant) -> ExitCode {
        let (lifecycle, metrics) = (self.lifecycle, self.metrics);
        match tokio::time::timeout_at(deadline.into(), self.run(server)).await {
            Ok(()) => {
                info!("shutdown complete");
                ExitCode::SUCCESS
            }
            Err(_elapsed) => {
                error!(
                    phase = %lifecycle.phase(),
                    in_flight = metrics.in_flight(),
                    "shutdown exceeded its hard deadline; abandoning in-flight work and exiting \
                     {OVERRUN_EXIT_CODE}"
                );
                ExitCode::from(OVERRUN_EXIT_CODE)
            }
        }
    }

    /// Drain, stop, close — in that order, always, whatever the window is.
    async fn run(self, server: &mut Server<SharedHandler>) {
        // Published before the first `.await`, on this task, so the 503 is on the
        // wire for the whole window rather than most of it.
        self.drain_start.cancel();
        self.lifecycle.enter(Phase::Draining);
        info!(
            window_secs = self.window.as_secs(),
            "shutdown: draining — /readyz reports 503 while DNS keeps answering"
        );

        tokio::select! {
            () = tokio::time::sleep(self.window) => {}
            () = self.signals.again() => {
                info!("shutdown: a further signal collapsed the remaining drain window");
            }
        }

        self.lifecycle.enter(Phase::Stopping);
        info!(
            in_flight = self.metrics.in_flight(),
            "shutdown: stopping — letting in-flight queries finish before the DNS sockets go"
        );
        let abandoned = self.quiesce().await;
        if abandoned > 0 {
            warn!(
                in_flight = abandoned,
                "the quiesce cap elapsed with requests still in flight; hickory aborts their \
                 tasks on cancel, so those clients will have to retry"
            );
        }

        self.dns.cancel();
        if let Err(error) = server.block_until_done().await {
            // Hickory returns Ok whenever its token is cancelled, so an error
            // here is an independent socket failure on the way out. The operator
            // asked us to stop; a socket error while stopping is not a failed
            // shutdown, and reporting it as one would restart-loop a healthy
            // deployment.
            warn!(%error, "a DNS listener reported an error while shutting down");
        }

        self.lifecycle.enter(Phase::Closing);
        info!("shutdown: closing — DNS is down, the admin listener goes last");
        self.admin.cancel();
        if let Some(task) = self.admin_task {
            // The admin task's own errors are already logged by the task.
            let _ = task.await;
        }
    }

    /// Wait for in-flight requests to finish, capped at [`QUIESCE_CAP`].
    ///
    /// Returns whatever is still in flight when it gives up, which is zero on
    /// every path a rollout takes: by the time `Stopping` is reached the endpoint
    /// has been out of rotation for the whole window.
    async fn quiesce(&self) -> u64 {
        let cap = Instant::now() + QUIESCE_CAP;
        loop {
            let in_flight = self.metrics.in_flight();
            if in_flight == 0 {
                return 0;
            }
            let now = Instant::now();
            if now >= cap {
                return in_flight;
            }
            tokio::select! {
                () = tokio::time::sleep(QUIESCE_POLL.min(cap - now)) => {}
                () = self.signals.again() => return self.metrics.in_flight(),
            }
        }
    }
}

/// Arm an OS-thread watchdog that ends the process if the runtime is wedged.
///
/// This is the only layer that survives a wedged tokio runtime — a blocking
/// reload hook that never returns, a task that never yields, a worker deadlock —
/// because a tokio timer cannot fire when nothing is polling it, and an OS
/// thread can. It is not belt and braces: a `spawn_blocking` task stuck on a
/// FIFO with no writer keeps `Runtime::drop` waiting *after* a clean shutdown
/// has already been logged, and nothing inside the runtime can observe that.
///
/// `std::process::exit` skips destructors, which is acceptable and cheap to
/// justify: Vega has nothing to flush, and systemd or the kubelet would
/// `SIGKILL` us moments later anyway. The watchdog buys a log line and a
/// distinguishable exit code first. It is safe code, so `unsafe_code = "forbid"`
/// is untouched.
fn arm_watchdog(at: Instant, lifecycle: Arc<Lifecycle>) {
    std::thread::spawn(move || {
        std::thread::sleep(at.saturating_duration_since(Instant::now()));
        error!(
            phase = %lifecycle.phase(),
            "watchdog: the shutdown hard deadline and its grace have both elapsed and this \
             process is still alive; exiting {OVERRUN_EXIT_CODE}"
        );
        std::process::exit(i32::from(OVERRUN_EXIT_CODE));
    });
}

/// State the shutdown timings at startup, and warn about the two configurations
/// that make the drain useless.
///
/// We cannot read `terminationGracePeriodSeconds` or `TimeoutStopSec` from
/// inside the container, so we publish the number the operator has to beat and
/// let them check it against their manifest.
fn log_shutdown_plan(config: &Config) {
    let drain = config.shutdown_drain;
    let deadline = drain + STOP_BUDGET;
    let watchdog = deadline + WATCHDOG_GRACE;

    if !drain.is_zero() && drain < config.tcp_timeout {
        warn!(
            "shutdown drain {}s is shorter than the TCP idle timeout {}s; idle TCP connections \
             will be closed by process exit rather than by their own timeout",
            drain.as_secs(),
            config.tcp_timeout.as_secs()
        );
    }
    if config.admin_listen.is_none() && !drain.is_zero() {
        warn!(
            "no admin listener: the {}s shutdown drain cannot be observed by a readiness probe",
            drain.as_secs()
        );
    }

    info!(
        "shutdown drain {}s, hard deadline {}s from signal; set terminationGracePeriodSeconds / \
         TimeoutStopSec above {}s",
        drain.as_secs(),
        deadline.as_secs(),
        watchdog.as_secs()
    );
}

/// Newtype so a shared `Arc<DnsHandler>` satisfies Hickory's owned-handler bound.
struct SharedHandler(Arc<DnsHandler>);

#[async_trait::async_trait]
impl hickory_server::server::RequestHandler for SharedHandler {
    async fn handle_request<
        R: hickory_server::server::ResponseHandler,
        T: hickory_server::net::runtime::Time,
    >(
        &self,
        request: &hickory_server::server::Request,
        response_handle: R,
    ) -> hickory_server::server::ResponseInfo {
        self.0
            .handle_request::<R, T>(request, response_handle)
            .await
    }
}

/// Periodically drop rate-limiter buckets for sources we have not seen recently.
fn spawn_janitor(limiter: Arc<RateLimiter>, shutdown: CancellationToken) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(JANITOR_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                _ = ticker.tick() => {
                    let removed = limiter.prune(DEFAULT_IDLE_TTL);
                    if removed > 0 {
                        tracing::debug!(removed, tracked = limiter.tracked(), "pruned rate limiter");
                    }
                }
            }
        }
    });
}

/// Install the global tracing subscriber.
///
/// `RUST_LOG` still wins if it is set, which is what an operator debugging a
/// running container will reach for first.
fn init_tracing(config: &Config) {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&config.log_level))
        .unwrap_or_else(|_| EnvFilter::new(vega::config::DEFAULT_LOG_FILTER));

    let registry = tracing_subscriber::registry().with(filter);
    match config.log_format {
        LogFormat::Json => registry
            .with(fmt::layer().json().with_current_span(false))
            .init(),
        LogFormat::Pretty => registry.with(fmt::layer().with_target(false)).init(),
    }

    if std::env::var_os("RUST_LOG").is_some() {
        warn!("RUST_LOG is set and overrides --log-level");
    }
}
