//! An authoritative DNS server built on [Hickory DNS](https://hickory-dns.org).
//!
//! The crate is split so that every piece is testable on its own:
//!
//! Serving:
//!
//! * [`config`] — CLI flags + TOML file, merged and validated up-front.
//! * [`zone`] — the in-memory record store and the lookup algorithm.
//! * [`handler`] — the [`hickory_server::server::RequestHandler`] implementation.
//! * [`lifecycle`] — the process phase every admin endpoint answers from.
//! * [`ratelimit`] — per-source-IP token bucket.
//! * [`metrics`] — lock-free counters plus a Prometheus text exporter.
//! * [`admin`] — HTTP endpoints for health, metrics and reload.
//! * [`reload`] — re-resolving the config and swapping the zone, live.
//! * [`shutdown`] — turns `SIGINT`/`SIGTERM`/`SIGHUP` into a shutdown signal.
//!
//! Operating, all reachable from the CLI so a deployment can be driven from
//! scripts as well as by hand:
//!
//! * [`cli`] — the command surface.
//! * [`commands`] — what each subcommand does.
//! * [`editor`] — format-preserving edits to the config file.
//! * [`dnsclient`] — a small `dig`, for verifying a live server.
//! * [`http`] — a minimal client for our own admin endpoints.
//! * [`healthcheck`] — the container probe.
//! * [`ui`] — colour, tables and formatting for terminal output.

pub mod admin;
pub mod cli;
pub mod commands;
pub mod config;
pub mod dnsclient;
pub mod editor;
pub mod handler;
pub mod healthcheck;
pub mod http;
pub mod lifecycle;
pub mod metrics;
pub mod ratelimit;
pub mod reload;
pub mod shutdown;
pub mod ui;
pub mod zone;

/// Crate version, as reported by `--version`, `/version` and the `version.<zone>` record.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Package name, used in log lines and the Prometheus `build_info` metric.
pub const NAME: &str = env!("CARGO_PKG_NAME");
