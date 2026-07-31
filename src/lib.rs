//! An authoritative DNS server built on [Hickory DNS](https://hickory-dns.org).
//!
//! The crate is split so that every piece is testable on its own:
//!
//! Serving:
//!
//! * [`config`] — CLI flags + TOML file, merged and validated up-front.
//! * [`tomlparse`] — the one place a TOML file is parsed, and the one place a
//!   parse failure is rendered without quoting the file back.
//! * [`rdata`] — the one place operator text is turned into RDATA.
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
/// The RFC 4034 §6.1 canonical name order, as a `memcmp`-able byte key.
///
/// Private: the ruling's §10.1 keeps the zone model's primitives `pub(crate)`,
/// because a `pub` API with no caller outside this crate is the thing its §12
/// fences off. `tests/canonical_order.rs` compiles the file by `#[path]`.
// S0 lands this ahead of its caller: the arena that sorts by it is S1, and one
// three-thousand-line diff is its own failure mode (§10.2). `dead_code` is
// therefore right today and wrong from S1, when this allow comes off.
#[allow(dead_code)]
mod canonical;
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
pub mod rdata;
pub mod reload;
pub mod shutdown;
pub mod tomlparse;
pub mod ui;
pub mod zone;

/// The test harness's own guard rail: a watchdog that bounds the *process*, so
/// a test for "this loop terminates" fails loudly instead of leaking a spinning
/// thread. Compiled only under `cfg(test)`; integration tests pull the same file
/// in by path so there is one implementation of the rule.
#[cfg(test)]
mod testutil;

/// Crate version, as reported by `--version`, `/version` and the `version.<zone>` record.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Package name, used in log lines and the Prometheus `build_info` metric.
pub const NAME: &str = env!("CARGO_PKG_NAME");
