//! Lock-free counters plus a Prometheus text-format exporter.
//!
//! Everything is a plain [`AtomicU64`], so recording a query costs a relaxed
//! fetch-add on the hot path and no allocation. The exporter is only touched by
//! `/metrics` scrapes.

use std::{
    fmt::Write as _,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use hickory_proto::op::ResponseCode;

/// Upper bounds, in seconds, of the query-latency histogram buckets.
const LATENCY_BUCKETS: [f64; 9] = [
    0.000_05, 0.000_1, 0.000_5, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5,
];

/// Response codes we track individually. Anything else lands in `other`.
const TRACKED_RCODES: [(&str, ResponseCode); 6] = [
    ("noerror", ResponseCode::NoError),
    ("nxdomain", ResponseCode::NXDomain),
    ("refused", ResponseCode::Refused),
    ("servfail", ResponseCode::ServFail),
    ("formerr", ResponseCode::FormErr),
    ("notimp", ResponseCode::NotImp),
];

/// Transport a query arrived on.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Transport {
    /// Plain DNS over UDP.
    Udp,
    /// Plain DNS over TCP.
    Tcp,
    /// Anything else Hickory reports (DoT, DoH, DoQ).
    Other,
}

/// Server-wide counters.
#[derive(Debug)]
pub struct Metrics {
    started: Instant,
    zone_records: AtomicU64,
    queries_total: AtomicU64,
    queries_udp: AtomicU64,
    queries_tcp: AtomicU64,
    queries_other: AtomicU64,
    /// Indexed in the same order as [`TRACKED_RCODES`], plus one slot for `other`.
    responses: [AtomicU64; TRACKED_RCODES.len() + 1],
    rate_limited_total: AtomicU64,
    send_errors_total: AtomicU64,
    /// Cumulative bucket counts; index `i` counts observations `<= LATENCY_BUCKETS[i]`.
    latency_buckets: [AtomicU64; LATENCY_BUCKETS.len()],
    latency_count: AtomicU64,
    /// Sum of latencies in microseconds; converted to seconds when rendering.
    latency_sum_micros: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    /// Create a fresh set of counters, with uptime starting now.
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            zone_records: AtomicU64::new(0),
            queries_total: AtomicU64::new(0),
            queries_udp: AtomicU64::new(0),
            queries_tcp: AtomicU64::new(0),
            queries_other: AtomicU64::new(0),
            responses: std::array::from_fn(|_| AtomicU64::new(0)),
            rate_limited_total: AtomicU64::new(0),
            send_errors_total: AtomicU64::new(0),
            latency_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            latency_count: AtomicU64::new(0),
            latency_sum_micros: AtomicU64::new(0),
        }
    }

    /// Publish the number of records loaded from the zone.
    pub fn set_zone_records(&self, count: u64) {
        self.zone_records.store(count, Ordering::Relaxed);
    }

    /// Record an inbound query.
    pub fn query(&self, transport: Transport) {
        self.queries_total.fetch_add(1, Ordering::Relaxed);
        let counter = match transport {
            Transport::Udp => &self.queries_udp,
            Transport::Tcp => &self.queries_tcp,
            Transport::Other => &self.queries_other,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Record the response code we answered with.
    pub fn response(&self, code: ResponseCode) {
        let idx = TRACKED_RCODES
            .iter()
            .position(|(_, tracked)| *tracked == code)
            .unwrap_or(TRACKED_RCODES.len());
        self.responses[idx].fetch_add(1, Ordering::Relaxed);
    }

    /// Record a query that was dropped by the rate limiter.
    pub fn rate_limited(&self) {
        self.rate_limited_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a failure while writing a response back to the client.
    pub fn send_error(&self) {
        self.send_errors_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Observe how long a query took to handle.
    pub fn observe_latency(&self, elapsed: Duration) {
        let secs = elapsed.as_secs_f64();
        self.latency_count.fetch_add(1, Ordering::Relaxed);
        self.latency_sum_micros.fetch_add(
            u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        for (bucket, upper) in self.latency_buckets.iter().zip(LATENCY_BUCKETS) {
            if secs <= upper {
                bucket.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Total queries seen. Handy for tests and the `counter.` built-in.
    pub fn queries(&self) -> u64 {
        self.queries_total.load(Ordering::Relaxed)
    }

    /// Seconds since the process started serving.
    pub fn uptime(&self) -> Duration {
        self.started.elapsed()
    }

    /// Render every counter in the Prometheus text exposition format.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(2048);
        self.render_info(&mut out);
        self.render_queries(&mut out);
        self.render_latency(&mut out);
        out
    }

    fn render_info(&self, out: &mut String) {
        writeln!(out, "# HELP dns_build_info Build information.").ok();
        writeln!(out, "# TYPE dns_build_info gauge").ok();
        writeln!(out, "dns_build_info{{version=\"{}\"}} 1", crate::VERSION).ok();

        gauge(
            out,
            "dns_uptime_seconds",
            "Seconds since the server started.",
            self.uptime().as_secs_f64(),
        );
        gauge(
            out,
            "dns_zone_records",
            "Number of resource records loaded from configuration.",
            as_f64(self.zone_records.load(Ordering::Relaxed)),
        );
    }

    fn render_queries(&self, out: &mut String) {
        counter(
            out,
            "dns_queries_total",
            "Total DNS queries received.",
            self.queries_total.load(Ordering::Relaxed),
        );

        writeln!(
            out,
            "# HELP dns_queries_by_transport_total DNS queries received, by transport."
        )
        .ok();
        writeln!(out, "# TYPE dns_queries_by_transport_total counter").ok();
        for (label, value) in [
            ("udp", &self.queries_udp),
            ("tcp", &self.queries_tcp),
            ("other", &self.queries_other),
        ] {
            writeln!(
                out,
                "dns_queries_by_transport_total{{transport=\"{label}\"}} {}",
                value.load(Ordering::Relaxed)
            )
            .ok();
        }

        writeln!(
            out,
            "# HELP dns_responses_total DNS responses sent, by response code."
        )
        .ok();
        writeln!(out, "# TYPE dns_responses_total counter").ok();
        for (idx, (label, _)) in TRACKED_RCODES.iter().enumerate() {
            writeln!(
                out,
                "dns_responses_total{{rcode=\"{label}\"}} {}",
                self.responses[idx].load(Ordering::Relaxed)
            )
            .ok();
        }
        writeln!(
            out,
            "dns_responses_total{{rcode=\"other\"}} {}",
            self.responses[TRACKED_RCODES.len()].load(Ordering::Relaxed)
        )
        .ok();

        counter(
            out,
            "dns_rate_limited_total",
            "Queries refused by the per-source-IP rate limiter.",
            self.rate_limited_total.load(Ordering::Relaxed),
        );
        counter(
            out,
            "dns_send_errors_total",
            "Failures while writing a response back to the client.",
            self.send_errors_total.load(Ordering::Relaxed),
        );
    }

    fn render_latency(&self, out: &mut String) {
        writeln!(
            out,
            "# HELP dns_query_duration_seconds Time spent handling a query."
        )
        .ok();
        writeln!(out, "# TYPE dns_query_duration_seconds histogram").ok();
        for (bucket, upper) in self.latency_buckets.iter().zip(LATENCY_BUCKETS) {
            writeln!(
                out,
                "dns_query_duration_seconds_bucket{{le=\"{upper}\"}} {}",
                bucket.load(Ordering::Relaxed)
            )
            .ok();
        }
        let count = self.latency_count.load(Ordering::Relaxed);
        writeln!(
            out,
            "dns_query_duration_seconds_bucket{{le=\"+Inf\"}} {count}"
        )
        .ok();
        writeln!(
            out,
            "dns_query_duration_seconds_sum {}",
            as_f64(self.latency_sum_micros.load(Ordering::Relaxed)) / 1_000_000.0
        )
        .ok();
        writeln!(out, "dns_query_duration_seconds_count {count}").ok();
    }
}

/// Counters only ever reach f64-lossy magnitudes after ~9 quadrillion events,
/// well past anything a name server will serve, and Prometheus samples are f64
/// anyway.
#[allow(clippy::cast_precision_loss)]
fn as_f64(value: u64) -> f64 {
    value as f64
}

fn gauge(out: &mut String, name: &str, help: &str, value: f64) {
    writeln!(out, "# HELP {name} {help}").ok();
    writeln!(out, "# TYPE {name} gauge").ok();
    writeln!(out, "{name} {value}").ok();
}

fn counter(out: &mut String, name: &str, help: &str, value: u64) {
    writeln!(out, "# HELP {name} {help}").ok();
    writeln!(out, "# TYPE {name} counter").ok();
    writeln!(out, "{name} {value}").ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_start_at_zero() {
        let m = Metrics::new();
        assert_eq!(m.queries(), 0);
        assert!(m.render_prometheus().contains("dns_queries_total 0"));
    }

    #[test]
    fn queries_are_counted_per_transport() {
        let m = Metrics::new();
        m.query(Transport::Udp);
        m.query(Transport::Udp);
        m.query(Transport::Tcp);
        assert_eq!(m.queries(), 3);
        let text = m.render_prometheus();
        assert!(text.contains("dns_queries_by_transport_total{transport=\"udp\"} 2"));
        assert!(text.contains("dns_queries_by_transport_total{transport=\"tcp\"} 1"));
        assert!(text.contains("dns_queries_by_transport_total{transport=\"other\"} 0"));
    }

    #[test]
    fn known_rcodes_get_their_own_series() {
        let m = Metrics::new();
        m.response(ResponseCode::NoError);
        m.response(ResponseCode::NXDomain);
        let text = m.render_prometheus();
        assert!(text.contains("dns_responses_total{rcode=\"noerror\"} 1"));
        assert!(text.contains("dns_responses_total{rcode=\"nxdomain\"} 1"));
    }

    #[test]
    fn unknown_rcodes_fall_into_other() {
        let m = Metrics::new();
        m.response(ResponseCode::NotAuth);
        let text = m.render_prometheus();
        assert!(text.contains("dns_responses_total{rcode=\"other\"} 1"));
    }

    #[test]
    fn latency_histogram_is_cumulative() {
        let m = Metrics::new();
        m.observe_latency(Duration::from_micros(80)); // 0.00008s
        let text = m.render_prometheus();
        // Below 0.00005 -> not counted; from 0.0001 upwards -> counted.
        assert!(text.contains("dns_query_duration_seconds_bucket{le=\"0.00005\"} 0"));
        assert!(text.contains("dns_query_duration_seconds_bucket{le=\"0.0001\"} 1"));
        assert!(text.contains("dns_query_duration_seconds_bucket{le=\"0.5\"} 1"));
        assert!(text.contains("dns_query_duration_seconds_bucket{le=\"+Inf\"} 1"));
        assert!(text.contains("dns_query_duration_seconds_count 1"));
    }

    #[test]
    fn build_info_reports_the_crate_version() {
        let text = Metrics::new().render_prometheus();
        assert!(text.contains(&format!(
            "dns_build_info{{version=\"{}\"}} 1",
            crate::VERSION
        )));
    }

    #[test]
    fn every_series_declares_help_and_type() {
        let text = Metrics::new().render_prometheus();
        let series: Vec<&str> = text
            .lines()
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.split(['{', ' ']).next())
            .collect();
        for name in series {
            let base = name.trim_end_matches("_bucket");
            let base = base.trim_end_matches("_sum");
            let base = base.trim_end_matches("_count");
            assert!(
                text.contains(&format!("# HELP {base}")),
                "missing HELP for {base}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Regression tests from mutation testing.
    // -----------------------------------------------------------------------

    #[test]
    fn a_latency_exactly_on_a_bucket_boundary_lands_in_that_bucket() {
        // Kills `secs <= upper` -> `secs < upper`. The existing histogram test
        // used 80us, which sits between two boundaries, so the comparison could
        // be flipped without any assertion noticing.
        let m = Metrics::new();
        m.observe_latency(Duration::from_micros(100)); // exactly 0.0001s
        let text = m.render_prometheus();
        assert!(
            text.contains("dns_query_duration_seconds_bucket{le=\"0.0001\"} 1"),
            "an observation equal to the bucket bound belongs in it:\n{text}"
        );
        assert!(text.contains("dns_query_duration_seconds_bucket{le=\"0.00005\"} 0"));
    }

    #[test]
    fn the_latency_sum_is_reported_in_seconds() {
        // Kills `as_f64 -> 0.0 / 1.0 / -1.0` on the sum path.
        let m = Metrics::new();
        m.observe_latency(Duration::from_millis(1_500));
        let text = m.render_prometheus();
        assert!(
            text.contains("dns_query_duration_seconds_sum 1.5"),
            "{text}"
        );
    }

    #[test]
    fn the_zone_record_gauge_reports_what_was_stored() {
        // Kills `set_zone_records with ()`, `gauge with ()` and
        // `as_f64 -> 0.0 / 1.0 / -1.0`.
        let m = Metrics::new();
        assert!(m.render_prometheus().contains("dns_zone_records 0"));
        m.set_zone_records(4242);
        let text = m.render_prometheus();
        assert!(text.contains("dns_zone_records 4242"), "{text}");
        assert!(text.contains("# TYPE dns_zone_records gauge"), "{text}");
    }

    #[test]
    fn rate_limited_and_send_error_counters_move() {
        // Kills `rate_limited with ()` and `send_error with ()`.
        let m = Metrics::new();
        m.rate_limited();
        m.rate_limited();
        m.send_error();
        let text = m.render_prometheus();
        assert!(text.contains("dns_rate_limited_total 2"), "{text}");
        assert!(text.contains("dns_send_errors_total 1"), "{text}");
    }

    #[test]
    fn uptime_advances_with_the_clock() {
        // Kills `uptime -> Duration::default()`.
        let m = Metrics::new();
        std::thread::sleep(Duration::from_millis(20));
        assert!(
            m.uptime() >= Duration::from_millis(15),
            "uptime was {:?}",
            m.uptime()
        );
        assert!(!m.render_prometheus().contains("dns_uptime_seconds 0\n"));
    }

    #[test]
    fn counters_reconcile_under_a_thread_storm() {
        // Every counter is Relaxed, which is fine for independent counters —
        // but the totals still have to add up exactly.
        use std::sync::{Arc, Barrier};

        const THREADS: usize = 12;
        const PER_THREAD: usize = 5_000;

        let m = Arc::new(Metrics::new());
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut handles = Vec::new();
        for t in 0..THREADS {
            let (m, barrier) = (Arc::clone(&m), Arc::clone(&barrier));
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..PER_THREAD {
                    m.query(match t % 3 {
                        0 => Transport::Udp,
                        1 => Transport::Tcp,
                        _ => Transport::Other,
                    });
                    m.response(if t % 2 == 0 {
                        ResponseCode::NoError
                    } else {
                        ResponseCode::NXDomain
                    });
                    m.observe_latency(Duration::from_micros(1));
                }
            }));
        }
        for h in handles {
            h.join().expect("worker finishes");
        }

        let total = THREADS * PER_THREAD;
        assert_eq!(usize::try_from(m.queries()).expect("fits"), total);
        let text = m.render_prometheus();
        assert!(
            text.contains(&format!("dns_queries_total {total}")),
            "{text}"
        );
        assert!(
            text.contains(&format!("dns_query_duration_seconds_count {total}")),
            "{text}"
        );

        // Per-transport counters must sum back to the grand total.
        let sum: usize = ["udp", "tcp", "other"]
            .iter()
            .map(|label| {
                let needle = format!("dns_queries_by_transport_total{{transport=\"{label}\"}} ");
                text.lines()
                    .find_map(|l| l.strip_prefix(needle.as_str()))
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or_default()
            })
            .sum();
        assert_eq!(sum, total, "transport counters must sum to the total");

        // Same for the response-code counters.
        let rcodes: usize = text
            .lines()
            .filter_map(|l| l.strip_prefix("dns_responses_total{"))
            .filter_map(|l| l.split_once("} "))
            .filter_map(|(_, v)| v.parse::<usize>().ok())
            .sum();
        assert_eq!(rcodes, total, "rcode counters must sum to the total");
    }
}
