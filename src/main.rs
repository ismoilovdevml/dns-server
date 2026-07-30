//! Entry point: parse the command line, then either run the server or one of the
//! management subcommands.

use std::{net::SocketAddr, path::PathBuf, process::ExitCode, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use clap::{CommandFactory as _, Parser as _};
use dns_server::{
    admin::{self, AdminState, ReloadOutcome},
    cli::{Cli, Command, RecordAction, ZoneAction},
    commands::{inspect, record, zone as zone_cmd},
    config::{Config, GlobalArgs, LogFormat},
    dnsclient,
    handler::DnsHandler,
    healthcheck,
    metrics::Metrics,
    ratelimit::{RateLimiter, DEFAULT_IDLE_TTL},
    shutdown, ui,
    zone::Zone,
};
use hickory_server::Server;
use tokio::net::{TcpListener, UdpSocket};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, layer::SubscriberExt as _, util::SubscriberInitExt as _, EnvFilter};

/// How often the rate-limiter janitor sweeps out idle buckets.
const JANITOR_INTERVAL: Duration = Duration::from_secs(60);

fn main() -> ExitCode {
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
    // only an explicit --config. Otherwise `dns-server check` run next to a
    // dns-server.toml would silently validate the built-in defaults instead.
    let global = GlobalArgs {
        config: config_path.clone(),
        ..cli.global.clone()
    };

    match &cli.command {
        // `None` is the default so plain `dns-server` still starts the server.
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
            // Exit non-zero when nothing matched, so `if dns-server record get …`
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

    match run(config) {
        Ok(()) => Ok(ExitCode::SUCCESS),
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

fn run(config: Config) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building the tokio runtime")?;
    runtime.block_on(serve(config))
}

async fn serve(config: Config) -> Result<()> {
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

    let mut server = Server::new(SharedHandler(Arc::clone(&handler)));
    let shutdown_token = server.shutdown_token().clone();

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

    // One token drives everything: signals cancel it, and the admin server and
    // janitor stop when it fires.
    shutdown::watch(shutdown_token.clone());

    let mut admin_state =
        AdminState::new(Arc::clone(&metrics)).with_token(config.admin_token.clone());
    // Reload only makes sense when there is a file to re-read.
    if let Some(source) = config.source.clone() {
        admin_state = admin_state.with_reload(reload_hook(
            source,
            Arc::clone(&handler),
            Arc::clone(&metrics),
            config.clone(),
        ));
    }

    if let Some(addr) = config.admin_listen {
        let state = admin_state.clone();
        let token = shutdown_token.clone();
        tokio::spawn(async move {
            if let Err(error) = admin::serve(addr, state, token.clone()).await {
                error!("{error:#}");
                // A dead metrics endpoint means a blind operator; treat it as fatal
                // so the orchestrator restarts us instead of running unobserved.
                token.cancel();
            }
        });
    }

    if let Some(limiter) = limiter.clone() {
        spawn_janitor(limiter, shutdown_token.clone());
    }

    info!(
        version = dns_server::VERSION,
        zone = %config.zone.origin,
        records = zone.record_count(),
        builtins = config.zone.builtins,
        rate_limited = config.rate_limit.is_some(),
        reloadable = config.source.is_some(),
        "dns-server ready"
    );
    admin_state.mark_ready();

    let result = server.block_until_done().await;

    // Stop reporting ready before the sockets actually close, so a load balancer
    // has a chance to take us out of rotation.
    admin_state.mark_unready();
    shutdown_token.cancel();

    result.context("dns server terminated with an error")?;
    info!("shutdown complete");
    Ok(())
}

/// Re-read the config file and swap the zone in place.
///
/// Listener addresses and the rate limiter are *not* re-applied: changing those
/// means rebinding sockets, which is a restart, not a reload. The hook logs a
/// warning if they drift so the difference is not silent.
fn reload_hook(
    source: PathBuf,
    handler: Arc<DnsHandler>,
    metrics: Arc<Metrics>,
    original: Config,
) -> admin::ReloadFn {
    Arc::new(move || {
        let args = GlobalArgs {
            config: Some(source.clone()),
            ..GlobalArgs::default()
        };
        let fresh = Config::load(&args).map_err(|e| format!("{e:#}"))?;
        let zone = Zone::from_config(&fresh.zone).map_err(|e| format!("{e:#}"))?;

        if fresh.udp != original.udp || fresh.tcp != original.tcp {
            warn!("listener addresses changed in the config; a restart is needed to apply them");
        }

        let records = zone.record_count();
        let origin = fresh.zone.origin.clone();
        metrics.set_zone_records(records as u64);
        handler.replace_zone(Arc::new(zone), fresh.zone.builtins);

        Ok(ReloadOutcome { origin, records })
    })
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
        .unwrap_or_else(|_| EnvFilter::new(dns_server::config::DEFAULT_LOG_FILTER));

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
