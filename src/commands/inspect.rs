//! `dns-server query` and `dns-server status` — look at a running server.
//!
//! These are the debugging commands: `query` answers "what does the server
//! actually return", `status` answers "is it healthy and what has it been doing".

use std::{collections::BTreeMap, net::SocketAddr};

use anyhow::Result;
use hickory_proto::rr::Record;
use serde_json::json;

use crate::{commands::emit_json, dnsclient, http, ui};

/// `query`
pub async fn query(
    server: SocketAddr,
    name: &str,
    record_type: &str,
    force_tcp: bool,
    as_json: bool,
) -> Result<bool> {
    let record_type = dnsclient::parse_record_type(record_type)?;
    let outcome = dnsclient::query(
        server,
        name,
        record_type,
        force_tcp,
        dnsclient::DEFAULT_TIMEOUT,
    )
    .await?;

    if as_json {
        emit_json(&json!({
            "server": outcome.server.to_string(),
            "transport": outcome.transport.as_str(),
            "query": { "name": name, "type": record_type.to_string() },
            "rcode": outcome.rcode(),
            "authoritative": outcome.message.metadata.authoritative,
            "truncated": outcome.message.metadata.truncation,
            "retried_over_tcp": outcome.retried_over_tcp,
            "elapsed_ms": outcome.elapsed.as_secs_f64() * 1000.0,
            "size_bytes": outcome.size,
            "answers": outcome.message.answers.iter().map(record_json).collect::<Vec<_>>(),
            "authority": outcome.message.authorities.iter().map(record_json).collect::<Vec<_>>(),
            "additional": outcome.message.additionals.iter().map(record_json).collect::<Vec<_>>(),
        }));
        return Ok(outcome.is_noerror());
    }

    print_answer(name, &outcome);
    Ok(outcome.is_noerror())
}

/// `status`
pub async fn status(addr: SocketAddr, token: Option<&str>, as_json: bool) -> Result<bool> {
    let snapshot = Snapshot::fetch(addr, token).await;

    if as_json {
        emit_json(&json!({
            "server": addr.to_string(),
            "reachable": snapshot.reachable,
            "healthy": snapshot.healthy,
            "ready": snapshot.ready,
            "build": snapshot.build,
            "metrics": snapshot.samples,
        }));
        return Ok(snapshot.healthy && snapshot.ready);
    }

    if let Some(error) = &snapshot.error {
        println!(
            "{} {} is unreachable: {error}",
            ui::cross(),
            ui::accent(addr)
        );
        return Ok(false);
    }

    print_server(addr, &snapshot);
    print_traffic(&snapshot);
    print_breakdown(
        "RESPONSE CODES",
        &snapshot.samples,
        "dns_responses_total",
        snapshot.queries(),
    );
    print_breakdown(
        "TRANSPORT",
        &snapshot.samples,
        "dns_queries_by_transport_total",
        snapshot.queries(),
    );

    if ui::verbose() {
        ui::section("RAW METRICS");
        for (key, value) in &snapshot.samples {
            println!("{} {value}", ui::label(key));
        }
    }

    Ok(snapshot.healthy && snapshot.ready)
}

/// Everything `status` learned in one round of requests.
struct Snapshot {
    reachable: bool,
    healthy: bool,
    ready: bool,
    build: serde_json::Value,
    samples: BTreeMap<String, f64>,
    /// Set when the server could not be reached at all.
    error: Option<String>,
}

impl Snapshot {
    async fn fetch(addr: SocketAddr, token: Option<&str>) -> Self {
        let health = http::get(addr, "/healthz", token).await;
        let ready = http::get(addr, "/readyz", token).await;
        let version = http::get(addr, "/version", token).await;
        let metrics = http::get(addr, "/metrics", token).await;

        Self {
            reachable: health.is_ok(),
            healthy: health.as_ref().is_ok_and(http::Response::is_success),
            ready: ready.as_ref().is_ok_and(http::Response::is_success),
            build: version
                .as_ref()
                .ok()
                .and_then(|r| serde_json::from_str(r.body.trim()).ok())
                .unwrap_or_else(|| json!({})),
            samples: metrics
                .as_ref()
                .map(|r| parse_prometheus(&r.body))
                .unwrap_or_default(),
            error: health.err().map(|e| format!("{e:#}")),
        }
    }

    fn sample(&self, key: &str) -> Option<f64> {
        self.samples.get(key).copied()
    }

    fn queries(&self) -> f64 {
        self.sample("dns_queries_total").unwrap_or(0.0)
    }
}

fn print_server(addr: SocketAddr, snapshot: &Snapshot) {
    ui::section("SERVER");
    ui::field("admin", ui::accent(addr), 16);
    ui::field(
        "health",
        if snapshot.healthy {
            format!("{} healthy", ui::tick())
        } else {
            format!("{} unhealthy", ui::cross())
        },
        16,
    );
    ui::field(
        "ready",
        if snapshot.ready {
            format!("{} serving", ui::tick())
        } else {
            // Expected during startup and while draining on shutdown.
            format!("{} not accepting traffic", ui::bang())
        },
        16,
    );
    if let Some(v) = snapshot
        .build
        .get("version")
        .and_then(serde_json::Value::as_str)
    {
        ui::field("version", ui::accent(v), 16);
    }
    if let Some(uptime) = snapshot.sample("dns_uptime_seconds") {
        ui::field("uptime", ui::duration(uptime), 16);
    }
    if let Some(reloads) = snapshot
        .build
        .get("reloads")
        .and_then(serde_json::Value::as_u64)
    {
        ui::field("reloads", reloads, 16);
    }
    if let Some(records) = snapshot.sample("dns_zone_records") {
        ui::field("zone records", ui::accent(count(records)), 16);
    }
}

fn print_traffic(snapshot: &Snapshot) {
    let queries = snapshot.queries();

    ui::section("TRAFFIC");
    ui::field("queries", ui::accent(count(queries)), 16);
    if let Some(uptime) = snapshot.sample("dns_uptime_seconds") {
        if uptime > 0.0 {
            ui::field("average", format!("{:.2} qps", queries / uptime), 16);
        }
    }
    if let Some(latency) = mean_latency(&snapshot.samples) {
        ui::field("mean latency", format!("{:.3} ms", latency * 1000.0), 16);
    }

    let dropped = snapshot.sample("dns_rate_limited_total").unwrap_or(0.0);
    ui::field(
        "rate limited",
        if dropped > 0.0 {
            ui::warn(count(dropped))
        } else {
            "0".to_owned()
        },
        16,
    );

    let send_errors = snapshot.sample("dns_send_errors_total").unwrap_or(0.0);
    ui::field(
        "send errors",
        if send_errors > 0.0 {
            ui::bad(count(send_errors))
        } else {
            "0".to_owned()
        },
        16,
    );
}

/// `u64::MAX` rounded to the nearest f64. Any float at or above this cannot be
/// represented as a `u64`, so it is the right clamp ceiling.
#[allow(clippy::cast_precision_loss)]
const U64_MAX_AS_F64: f64 = u64::MAX as f64;

/// Prometheus samples are f64; counters are conceptually integers. Saturate
/// rather than wrap so a nonsense value reads as nonsense.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn count(value: f64) -> u64 {
    value.trunc().clamp(0.0, U64_MAX_AS_F64) as u64
}

/// `reload`
pub async fn reload(addr: SocketAddr, token: Option<&str>, as_json: bool) -> Result<bool> {
    crate::commands::record::reload_server(addr, token, as_json).await
}

fn print_answer(name: &str, outcome: &dnsclient::Outcome) {
    let meta = &outcome.message.metadata;

    ui::section("QUERY");
    ui::field("name", ui::accent(name), 16);
    ui::field("server", format!("{}", outcome.server), 16);
    ui::field(
        "transport",
        if outcome.retried_over_tcp {
            format!(
                "{} {}",
                outcome.transport.as_str(),
                ui::muted("(retried after truncation)")
            )
        } else {
            outcome.transport.as_str().to_owned()
        },
        16,
    );
    ui::field("rcode", ui::rcode(&outcome.rcode()), 16);
    ui::field(
        "flags",
        flags(
            meta.authoritative,
            meta.truncation,
            meta.recursion_available,
        ),
        16,
    );
    ui::field(
        "time",
        format!("{:.2} ms", outcome.elapsed.as_secs_f64() * 1000.0),
        16,
    );
    ui::field("size", format!("{} bytes", outcome.size), 16);

    print_section("ANSWER", &outcome.message.answers);
    print_section("AUTHORITY", &outcome.message.authorities);
    if ui::verbose() {
        print_section("ADDITIONAL", &outcome.message.additionals);
    }

    if outcome.message.answers.is_empty() {
        println!();
        let hint = match outcome.rcode().as_str() {
            "NOERROR" => "the name exists but has no records of this type (NODATA)",
            "NXDOMAIN" => "the name does not exist in this zone",
            "REFUSED" => "the server is not authoritative for this name",
            _ => "no answer records were returned",
        };
        println!("{} {}", ui::bang(), ui::muted(hint));
    }
}

fn print_section(title: &str, records: &[Record]) {
    if records.is_empty() {
        return;
    }
    ui::section(title);
    let mut table = ui::Table::new(&["NAME", "TTL", "TYPE", "DATA"]);
    for record in records {
        let name = record.name.to_string();
        let ttl = format!("{}s", record.ttl);
        let ty = record.record_type().to_string();
        let data = record.data.to_string();
        table.row(
            vec![
                ui::accent(&name),
                ui::muted(&ttl),
                ui::record_type(&ty),
                data.clone(),
            ],
            &[name, ttl, ty, data],
        );
    }
    table.print();
}

fn print_breakdown(title: &str, samples: &BTreeMap<String, f64>, prefix: &str, total: f64) {
    let rows: Vec<(String, f64)> = samples
        .iter()
        .filter_map(|(key, value)| {
            let rest = key.strip_prefix(prefix)?.strip_prefix('{')?;
            let label = rest.split_once('=')?.1.trim_matches(['"', '}'].as_ref());
            (*value > 0.0).then(|| (label.to_owned(), *value))
        })
        .collect();

    if rows.is_empty() {
        return;
    }

    ui::section(title);
    let mut table = ui::Table::new(&["LABEL", "COUNT", "SHARE", ""]);
    for (label, value) in rows {
        let share = if total > 0.0 { value / total } else { 0.0 };
        let styled_label = if title == "RESPONSE CODES" {
            ui::rcode(&label.to_uppercase())
        } else {
            ui::accent(&label)
        };
        let pct = format!("{:.1}%", share * 100.0);
        let n = count(value).to_string();
        table.row(
            vec![styled_label, n.clone(), pct.clone(), ui::bar(share, 16)],
            &[label, n, pct, String::new()],
        );
    }
    table.print();
}

fn flags(authoritative: bool, truncated: bool, recursion_available: bool) -> String {
    let mut set = Vec::new();
    if authoritative {
        set.push(ui::good("aa"));
    }
    if truncated {
        set.push(ui::warn("tc"));
    }
    if recursion_available {
        set.push(ui::muted("ra"));
    }
    if set.is_empty() {
        ui::muted("none")
    } else {
        set.join(" ")
    }
}

fn record_json(record: &Record) -> serde_json::Value {
    json!({
        "name": record.name.to_string(),
        "ttl": record.ttl,
        "type": record.record_type().to_string(),
        "data": record.data.to_string(),
    })
}

/// Mean latency from the histogram's sum and count.
fn mean_latency(samples: &BTreeMap<String, f64>) -> Option<f64> {
    let sum = samples.get("dns_query_duration_seconds_sum")?;
    let count = samples.get("dns_query_duration_seconds_count")?;
    (*count > 0.0).then(|| sum / count)
}

/// Parse the subset of the Prometheus text format that we emit ourselves:
/// comments, then `name value` or `name{labels} value`.
fn parse_prometheus(body: &str) -> BTreeMap<String, f64> {
    body.lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            let (key, value) = line.rsplit_once(' ')?;
            Some((key.trim().to_owned(), value.trim().parse::<f64>().ok()?))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::{Metrics, Transport};
    use hickory_proto::op::ResponseCode;
    use std::time::Duration;

    #[test]
    fn parses_our_own_exposition_output() {
        let metrics = Metrics::new();
        metrics.query(Transport::Udp);
        metrics.query(Transport::Tcp);
        metrics.response(ResponseCode::NoError);
        metrics.observe_latency(Duration::from_micros(250));

        let samples = parse_prometheus(&metrics.render_prometheus());

        assert_eq!(samples.get("dns_queries_total"), Some(&2.0));
        assert_eq!(
            samples.get("dns_queries_by_transport_total{transport=\"udp\"}"),
            Some(&1.0)
        );
        assert_eq!(
            samples.get("dns_responses_total{rcode=\"noerror\"}"),
            Some(&1.0)
        );
        assert_eq!(samples.get("dns_query_duration_seconds_count"), Some(&1.0));
        // HELP/TYPE comment lines must not become samples.
        assert!(!samples.keys().any(|k| k.starts_with('#')));
    }

    #[test]
    fn parses_labelled_and_unlabelled_series() {
        let samples = parse_prometheus("a 1\nb{x=\"y\"} 2.5\n\n# HELP c thing\nc 3\n");
        assert_eq!(samples.get("a"), Some(&1.0));
        assert_eq!(samples.get("b{x=\"y\"}"), Some(&2.5));
        assert_eq!(samples.get("c"), Some(&3.0));
        assert_eq!(samples.len(), 3);
    }

    #[test]
    fn ignores_lines_that_are_not_samples() {
        let samples = parse_prometheus("garbage\nnot_a_number oops\n");
        assert!(samples.is_empty(), "{samples:?}");
    }

    #[test]
    fn mean_latency_needs_both_sum_and_count() {
        let mut samples = BTreeMap::new();
        assert!(mean_latency(&samples).is_none());

        samples.insert("dns_query_duration_seconds_sum".to_owned(), 0.5);
        assert!(mean_latency(&samples).is_none());

        samples.insert("dns_query_duration_seconds_count".to_owned(), 10.0);
        assert_eq!(mean_latency(&samples), Some(0.05));
    }

    #[test]
    fn mean_latency_avoids_dividing_by_zero() {
        let samples = BTreeMap::from([
            ("dns_query_duration_seconds_sum".to_owned(), 0.0),
            ("dns_query_duration_seconds_count".to_owned(), 0.0),
        ]);
        assert!(mean_latency(&samples).is_none());
    }

    #[test]
    fn flags_render_the_set_bits_only() {
        assert_eq!(flags(false, false, false), "none");
        assert_eq!(flags(true, false, false), "aa");
        assert_eq!(flags(true, true, false), "aa tc");
    }
}
