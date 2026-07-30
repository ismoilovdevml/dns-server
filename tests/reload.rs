//! Acceptance tests for `POST /reload` — VEGA-005, driven against the real binary.
//!
//! `reload_hook` lives in `src/main.rs`, so no library test can reach it. These
//! spawn the real process, edit the real file, and speak the real admin HTTP and
//! DNS protocols. That is the only place the reload precedence contract is
//! observable today, and it is the level an operator experiences it at.
//!
//! Each test names the Gherkin scenario it enforces. The binding design ruling is
//! `.claude/backlog/decisions/VEGA-005-reload-precedence.md`.

use std::{
    io::{BufRead as _, BufReader, Read},
    net::{SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering as AtomicOrdering},
        Arc, Mutex, MutexGuard, OnceLock,
    },
    time::{Duration, Instant},
};

use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};
use serde_json::Value;
use tempfile::TempDir;
use tokio::net::UdpSocket;
use vega::config::{Config, GlobalArgs, ZoneConfig};

/// Wall-clock budget for a single query. Generous for a loaded CI runner, tight
/// enough that a hang fails instead of stalling the suite.
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a freshly spawned server gets to bind its sockets and report ready.
const READY_TIMEOUT: Duration = Duration::from_secs(20);

/// The closed set of machine-readable reload error codes, per the ruling's
/// failure-mode table. Scripts and (via VEGA-049) alert labels key on these, so a
/// code that appears without a scenario is a spec gap, not a detail.
const RELOAD_ERROR_CODES: &[&str] = &[
    "config_read_failed",
    "config_parse_failed",
    "config_invalid",
    "zone_build_failed",
    "origin_changed",
    "reload_in_progress",
    "shutting_down",
    "not_configured",
    "forbidden",
    "internal",
];

/// Environment a test must never inherit: it would silently change the
/// invocation under test.
const RESET_ENV: &[&str] = &[
    "RUST_LOG",
    "VEGA_CONFIG",
    "VEGA_UDP",
    "VEGA_TCP",
    "VEGA_ADMIN_LISTEN",
    "VEGA_ADMIN_TOKEN",
    "VEGA_DOMAIN",
    "VEGA_RATE_LIMIT_QPS",
    "VEGA_RATE_LIMIT_BURST",
    "VEGA_TCP_TIMEOUT_SECS",
    "VEGA_NO_BUILTINS",
    "VEGA_LOG_FORMAT",
    "VEGA_LOG_LEVEL",
    "DNS_CONFIG",
    "DNS_UDP",
    "DNS_TCP",
    "DNS_ADMIN_LISTEN",
    "DNS_ADMIN_TOKEN",
    "DNS_DOMAIN",
    "DNS_RATE_LIMIT_QPS",
    "DNS_RATE_LIMIT_BURST",
    "DNS_TCP_TIMEOUT_SECS",
    "DNS_NO_BUILTINS",
    "DNS_LOG_FORMAT",
    "DNS_LOG_LEVEL",
];

// ---------------------------------------------------------------- fixtures

/// Path to the binary under test, as provided by Cargo.
fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_vega"))
}

/// Serialises "probe a port, then `spawn` a child that binds it" across the whole
/// test binary.
///
/// Not a style choice — without it this file failed 7 runs in 15, always
/// `EADDRINUSE`, always on a different test. macOS has no atomic `SOCK_CLOEXEC`,
/// so `std` creates a socket with `socket(2)` and *then* sets close-on-exec with
/// `ioctl(FIOCLEX)`. A `Command::spawn` on another thread inside that gap hands
/// the child a duplicate of the probe socket. The parent then closes its copy and
/// hands the port to a *different* child — which cannot bind it, because the
/// first child is still holding the port open. That is why every collided port
/// had been handed out exactly once and why widening the port range did not help.
///
/// Measured on this machine (6 threads binding loopback sockets in a loop, 400
/// `/bin/sh -c 'ls -l /dev/fd'` children): 17 of 400 children inherited a socket
/// fd, against 0 of 400 with the probe threads stopped. Re-binding a
/// just-probed UDP port failed 7-14 times in 3000 with concurrent spawns and
/// 0 times in 3000 without.
///
/// Holding one gate from the first probe to the end of `spawn` closes the window
/// in both directions: no other thread can spawn while our probe socket exists,
/// and no other thread's probe socket exists while we spawn. It also stops one
/// child inheriting another's stdout pipe, since `pipe(2)` on macOS is
/// `pipe` + `FIOCLEX` for the same reason.
fn spawn_gate() -> &'static Mutex<()> {
    static GATE: OnceLock<Mutex<()>> = OnceLock::new();
    GATE.get_or_init(|| Mutex::new(()))
}

/// How many times the gate has been taken. Exists only so
/// `starting_a_server_takes_the_spawn_gate` can fail if the gate is ever dropped
/// from the spawn path — the flake it prevents is probabilistic, so nothing else
/// in this file would notice for weeks.
static GATE_TAKEN: AtomicUsize = AtomicUsize::new(0);

/// Take the spawn gate, recovering from a poisoning left by a failed test.
///
/// A panicking test must fail on its own assertion, not turn every later test in
/// the file into a poison error that hides it.
fn hold_spawn_gate() -> MutexGuard<'static, ()> {
    let guard = spawn_gate()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    GATE_TAKEN.fetch_add(1, AtomicOrdering::SeqCst);
    guard
}

fn free_udp_port() -> u16 {
    StdUdpSocket::bind("127.0.0.1:0")
        .expect("a free udp port")
        .local_addr()
        .expect("udp addr")
        .port()
}

fn free_tcp_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0")
        .expect("a free tcp port")
        .local_addr()
        .expect("tcp addr")
        .port()
}

/// A complete config file. `zone_extra` and `server` are pasted into the `[zone]`
/// and `[server]` tables so a test can vary exactly one key at a time.
fn config_file(origin: Option<&str>, zone_extra: &str, server: &str, ip: &str) -> String {
    let origin_line = origin.map_or_else(String::new, |o| format!("origin = \"{o}\"\n"));
    format!(
        "[server]\n{server}\n\
         [zone]\n{origin_line}default_ttl = 300\n{zone_extra}\n\
         [zone.soa]\n\
         mname = \"ns1.example.test.\"\n\
         rname = \"hostmaster.example.test.\"\n\n\
         [[zone.records]]\nname = \"www\"\ntype = \"A\"\nvalues = [\"{ip}\"]\n"
    )
}

/// The common case: origin from the file, one `www` A record.
fn zone_file(origin: Option<&str>, ip: &str) -> String {
    config_file(origin, "", "", ip)
}

// ------------------------------------------------------------- the harness

/// How to start one server under test.
struct Spawn {
    toml: String,
    args: Vec<String>,
    env: Vec<(String, String)>,
    token: Option<String>,
    with_config: bool,
}

impl Spawn {
    fn new(toml: impl Into<String>) -> Self {
        Self {
            toml: toml.into(),
            args: Vec::new(),
            env: Vec::new(),
            token: None,
            with_config: true,
        }
    }

    fn arg(mut self, value: impl Into<String>) -> Self {
        self.args.push(value.into());
        self
    }

    fn flag(self, name: &str, value: &str) -> Self {
        self.arg(name).arg(value)
    }

    fn env(mut self, name: &str, value: &str) -> Self {
        self.env.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Pass `--admin-token` and remember it, so `reload()` authenticates.
    fn token(mut self, token: &str) -> Self {
        self.token = Some(token.to_owned());
        self.flag("--admin-token", token)
    }

    /// Start with no `--config` at all, so reload has no file to re-read.
    fn without_config(mut self) -> Self {
        self.with_config = false;
        self
    }

    async fn start(self) -> Vega {
        let dir = TempDir::new().expect("temp dir");
        let config = dir.path().join("vega.toml");
        if self.with_config {
            std::fs::write(&config, &self.toml).expect("config writes");
        }

        // Held until the child is running: see `spawn_gate`.
        let gate = hold_spawn_gate();

        let dns: SocketAddr = format!("127.0.0.1:{}", free_udp_port())
            .parse()
            .expect("dns addr parses");
        let admin: SocketAddr = format!("127.0.0.1:{}", free_tcp_port())
            .parse()
            .expect("admin addr parses");

        let mut command = Command::new(bin());
        command.arg("serve");
        if self.with_config {
            command.arg("--config").arg(&config);
        }
        command
            .arg("--udp")
            .arg(dns.to_string())
            .arg("--admin-listen")
            .arg(admin.to_string())
            .args(&self.args)
            .current_dir(dir.path())
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for name in RESET_ENV {
            command.env_remove(name);
        }
        for (name, value) in &self.env {
            command.env(name, value);
        }

        let mut child = command
            .spawn()
            .expect("the server binary should be runnable");
        drop(gate);

        let log = Arc::new(Mutex::new(String::new()));
        if let Some(out) = child.stdout.take() {
            drain(out, Arc::clone(&log));
        }
        if let Some(err) = child.stderr.take() {
            drain(err, Arc::clone(&log));
        }

        let mut vega = Vega {
            child,
            dir,
            config,
            dns,
            admin,
            token: self.token,
            log,
        };
        vega.wait_ready().await;
        vega
    }
}

/// Pump a child pipe into a shared buffer, so an assertion can read the log and
/// a full pipe can never block the server.
fn drain(pipe: impl Read + Send + 'static, sink: Arc<Mutex<String>>) {
    std::thread::spawn(move || {
        let mut reader = BufReader::new(pipe);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if let Ok(mut sink) = sink.lock() {
                        sink.push_str(&line);
                    }
                }
            }
        }
    });
}

/// A running server plus everything needed to drive and observe it.
struct Vega {
    child: Child,
    dir: TempDir,
    config: PathBuf,
    dns: SocketAddr,
    admin: SocketAddr,
    token: Option<String>,
    log: Arc<Mutex<String>>,
}

impl Drop for Vega {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Vega {
    async fn wait_ready(&mut self) {
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                panic!(
                    "the server exited before becoming ready ({status}):\n{}",
                    self.logs()
                );
            }
            if let Ok(response) = vega::http::get(self.admin, "/readyz", None).await {
                if response.status == 200 {
                    return;
                }
            }
            assert!(
                Instant::now() < deadline,
                "the server never became ready:\n{}",
                self.logs()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// `POST /reload` with the token this server was started with.
    async fn reload(&self) -> (u16, Value) {
        self.reload_as(self.token.clone().as_deref()).await
    }

    async fn reload_as(&self, token: Option<&str>) -> (u16, Value) {
        let response = vega::http::post(self.admin, "/reload", token)
            .await
            .expect("the admin server answers /reload");
        let body = serde_json::from_str(response.body.trim()).unwrap_or(Value::Null);
        (response.status, body)
    }

    async fn version(&self) -> Value {
        let response = vega::http::get(self.admin, "/version", None)
            .await
            .expect("the admin server answers /version");
        serde_json::from_str(response.body.trim()).unwrap_or(Value::Null)
    }

    async fn reload_count(&self) -> u64 {
        self.version().await["reloads"].as_u64().unwrap_or_default()
    }

    async fn metrics(&self) -> String {
        vega::http::get(self.admin, "/metrics", None)
            .await
            .expect("the admin server answers /metrics")
            .body
    }

    async fn zone_records_gauge(&self) -> String {
        metric_value(&self.metrics().await, "dns_zone_records")
    }

    /// Replace the config file atomically, so a concurrent reload can never read
    /// a half-written file (that failure is VEGA-017's, not this ruling's).
    fn write_config(&self, toml: &str) {
        let staging = self.dir.path().join("staged.toml");
        std::fs::write(&staging, toml).expect("staged config writes");
        std::fs::rename(&staging, &self.config).expect("staged config renames into place");
    }

    fn delete_config(&self) {
        std::fs::remove_file(&self.config).expect("config is removable");
    }

    async fn ask(&self, name: &str, record_type: RecordType) -> Message {
        let mut qname: Name = name.parse().expect("test name parses");
        qname.set_fqdn(true);
        let mut request = Message::query();
        request.metadata.id = 0x4242;
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(qname, record_type));

        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("client binds");
        socket.connect(self.dns).await.expect("client connects");
        socket
            .send(&request.to_vec().expect("request encodes"))
            .await
            .expect("request sends");

        let mut buf = vec![0u8; 4096];
        let len = tokio::time::timeout(QUERY_TIMEOUT, socket.recv(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("no answer for {name} within {QUERY_TIMEOUT:?}"))
            .expect("response reads");
        Message::from_vec(&buf[..len]).expect("response decodes")
    }

    fn logs(&self) -> String {
        self.log.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// Wait for a log line mentioning `needle`; the log arrives over a pipe, so it
    /// can lag the HTTP response it was written next to.
    async fn wait_for_log(&self, needle: &str) {
        for _ in 0..150u32 {
            if self.logs().contains(needle) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("no log line mentioned {needle}:\n{}", self.logs());
    }
}

// ----------------------------------------------------------- small helpers

/// The raw value token a metric is exposed with.
///
/// Compared as text, not as a float: these are integer gauges and counters, and
/// an exact-text comparison says "unchanged" without inviting a float epsilon.
fn metric_value(metrics: &str, name: &str) -> String {
    metrics
        .lines()
        .find_map(|line| Some(line.strip_prefix(name)?.trim().to_owned()))
        .unwrap_or_else(|| panic!("no {name} in:\n{metrics}"))
}

fn counter_value(metrics: &str, name: &str) -> u64 {
    let raw = metric_value(metrics, name);
    raw.parse()
        .unwrap_or_else(|e| panic!("{name} was {raw:?}, which is not a count ({e})"))
}

fn a_values(message: &Message) -> Vec<String> {
    let mut values: Vec<String> = message
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(a) => Some(a.0.to_string()),
            _ => None,
        })
        .collect();
    values.sort();
    values
}

fn ignored_keys(body: &Value) -> Vec<String> {
    body.get("ignored")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn assert_code(body: &Value, expected: &str) {
    let code = body.get("code").and_then(Value::as_str);
    assert_eq!(
        code,
        Some(expected),
        "expected code {expected:?}, body was {body}"
    );
    assert!(
        RELOAD_ERROR_CODES.contains(&expected),
        "{expected} is not in the documented code set {RELOAD_ERROR_CODES:?}"
    );
}

/// Every `.rs` file under `dir`, recursively.
fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let entries = std::fs::read_dir(dir).expect("source directory is readable");
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(rust_files(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
    found
}

// ==========================================================================
// A. The invocation survives a reload
// ==========================================================================

/// Scenario: A reload keeps the origin given on the command line
/// features/live-reload.feature:100
#[tokio::test]
async fn a_reload_keeps_the_domain_given_on_the_command_line() {
    let vega = Spawn::new(zone_file(None, "203.0.113.10"))
        .flag("--domain", "prod.example.test")
        .start()
        .await;

    let (status, body) = vega.reload().await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["origin"], "prod.example.test",
        "the reload discarded --domain and fell through to the built-in origin: {body}"
    );

    let answer = vega.ask("www.prod.example.test.", RecordType::A).await;
    assert!(
        answer.metadata.authoritative,
        "the server stopped being authoritative for the zone it was started with"
    );
    assert_eq!(a_values(&answer), vec!["203.0.113.10".to_owned()]);
}

/// Scenario: A reload does not re-enable built-ins the operator turned off
/// features/live-reload.feature:111
#[tokio::test]
async fn a_reload_does_not_re_enable_builtins_turned_off_on_the_command_line() {
    let vega = Spawn::new(config_file(
        Some("example.test"),
        "builtins = true\n",
        "",
        "203.0.113.10",
    ))
    .arg("--no-builtins")
    .start()
    .await;

    let before = vega.ask("myip.example.test.", RecordType::A).await;
    assert_eq!(
        before.metadata.response_code,
        ResponseCode::NXDomain,
        "the fixture must start with built-ins off"
    );

    let (status, body) = vega.reload().await;
    assert_eq!(status, 200, "{body}");

    let after = vega.ask("myip.example.test.", RecordType::A).await;
    assert_eq!(
        after.metadata.response_code,
        ResponseCode::NXDomain,
        "the reload re-enabled diagnostic sub-zones an operator had turned off"
    );
}

/// Scenario: A file origin shadowed by --domain still reloads
/// features/live-reload.feature:117
#[tokio::test]
async fn a_file_origin_edit_shadowed_by_the_domain_flag_still_reloads() {
    let vega = Spawn::new(zone_file(Some("example.test"), "203.0.113.10"))
        .flag("--domain", "example.test")
        .start()
        .await;

    vega.write_config(&zone_file(Some("other.test"), "203.0.113.11"));
    let (status, body) = vega.reload().await;

    assert_eq!(
        status, 200,
        "the CLI wins, so this is not a conflict: {body}"
    );
    assert_eq!(
        body["origin"], "example.test",
        "the file must not overrule --domain: {body}"
    );
    let answer = vega.ask("www.example.test.", RecordType::A).await;
    assert_eq!(a_values(&answer), vec!["203.0.113.11".to_owned()]);
}

/// Scenario: A shadowed file origin is named in the ignored array and warned about
/// features/live-reload.feature:126
#[tokio::test]
async fn a_shadowed_file_origin_is_reported_as_ignored_and_warned_about() {
    let vega = Spawn::new(zone_file(Some("example.test"), "203.0.113.10"))
        .flag("--domain", "example.test")
        .start()
        .await;

    vega.write_config(&zone_file(Some("other.test"), "203.0.113.10"));
    let (status, body) = vega.reload().await;

    assert_eq!(status, 200, "{body}");
    assert!(
        ignored_keys(&body).iter().any(|key| key == "zone.origin"),
        "a shadowed zone.origin must be reported, not silently dropped: {body}"
    );
    vega.wait_for_log("zone.origin").await;
}

/// Scenario: Every flag from the invocation is still in force after a reload
/// features/live-reload.feature:135
#[tokio::test]
async fn every_flag_from_the_invocation_is_still_in_force_after_a_reload() {
    let server_section = "\
        tcp_timeout_secs = 30\n\
        log_level = \"trace\"\n\
        log_format = \"json\"\n\
        admin_token = \"from-the-file\"\n\
        rate_limit = { qps = 1000, burst = 2000 }\n";
    let vega = Spawn::new(config_file(
        Some("from-the-file.test"),
        "builtins = true\n",
        server_section,
        "203.0.113.10",
    ))
    .flag("--domain", "example.test")
    .arg("--no-builtins")
    .flag("--tcp-timeout-secs", "7")
    .flag("--rate-limit-qps", "10")
    .flag("--rate-limit-burst", "10")
    .flag("--log-format", "pretty")
    .token("from-the-cli")
    .start()
    .await;

    let (status, body) = vega.reload().await;
    assert_eq!(status, 200, "{body}");

    // Effective config, field by field, as an operator can observe it.
    assert_eq!(body["origin"], "example.test", "--domain lost: {body}");
    assert_eq!(
        vega.ask("myip.example.test.", RecordType::A)
            .await
            .metadata
            .response_code,
        ResponseCode::NXDomain,
        "--no-builtins lost"
    );
    let (unauthenticated, _) = vega.reload_as(None).await;
    assert_eq!(unauthenticated, 403, "--admin-token lost");
    let (file_token, _) = vega.reload_as(Some("from-the-file")).await;
    assert_eq!(file_token, 403, "the file's admin_token took effect");
    assert!(
        !vega.logs().contains("\"fields\""),
        "--log-format pretty lost; the log turned into JSON"
    );

    // The CLI's 10 qps must still be what limits, not the file's 1000.
    for _ in 0..40u32 {
        let _ = tokio::time::timeout(
            Duration::from_millis(120),
            vega.ask("www.example.test.", RecordType::A),
        )
        .await;
    }
    assert!(
        counter_value(&vega.metrics().await, "dns_rate_limited_total") > 0,
        "the file's rate limit replaced the one given on the command line"
    );
}

/// Scenario: A reload keeps an origin supplied by the environment
/// features/config-precedence.feature:113
#[tokio::test]
async fn a_reload_keeps_the_origin_supplied_by_the_environment() {
    let vega = Spawn::new(zone_file(Some("from-the-file.test"), "203.0.113.10"))
        .env("VEGA_DOMAIN", "from-the-env.test")
        .start()
        .await;

    let (status, body) = vega.reload().await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["origin"], "from-the-env.test",
        "the reload discarded VEGA_DOMAIN and took the file's origin: {body}"
    );
}

/// Scenario: Ten successive reloads with no file change are identical
/// features/live-reload.feature:144
#[tokio::test]
async fn ten_successive_reloads_with_no_file_change_are_identical() {
    let vega = Spawn::new(zone_file(None, "203.0.113.10"))
        .flag("--domain", "prod.example.test")
        .arg("--no-builtins")
        .start()
        .await;

    let baseline_records = vega.zone_records_gauge().await;
    for round in 1..=10u32 {
        let (status, body) = vega.reload().await;
        assert_eq!(status, 200, "round {round}: {body}");
        assert_eq!(body["origin"], "prod.example.test", "round {round}: {body}");
        assert_eq!(
            vega.zone_records_gauge().await,
            baseline_records,
            "round {round} changed the record count with no file change"
        );
        assert_eq!(
            vega.ask("myip.prod.example.test.", RecordType::A)
                .await
                .metadata
                .response_code,
            ResponseCode::NXDomain,
            "round {round} re-enabled built-ins"
        );
    }
}

// ==========================================================================
// B. Precedence identity — one implementation, not two
// ==========================================================================

/// Scenario: A reloaded server and a freshly started server resolve the same config
/// features/config-precedence.feature:172
#[tokio::test]
async fn a_reloaded_server_resolves_the_same_config_as_a_freshly_started_one() {
    let toml = config_file(
        Some("from-the-file.test"),
        "builtins = true\n",
        "log_level = \"trace\"\nadmin_token = \"from-the-file\"\n",
        "203.0.113.10",
    );
    let invocation = |spawn: Spawn| {
        spawn
            .flag("--domain", "example.test")
            .arg("--no-builtins")
            .token("from-the-cli")
    };

    let reloaded = invocation(Spawn::new(toml.clone())).start().await;
    let (status, reload_body) = reloaded.reload().await;
    assert_eq!(status, 200, "{reload_body}");

    let fresh = invocation(Spawn::new(toml)).start().await;
    let (_, fresh_body) = fresh.reload().await;

    // Probe every field of the resolved Config that is observable from outside.
    assert_eq!(
        reload_body["origin"], fresh_body["origin"],
        "the reload path resolved a different origin from the startup path"
    );
    assert_eq!(
        reload_body["records"], fresh_body["records"],
        "the reload path resolved a different record set from the startup path"
    );
    for server in [&reloaded, &fresh] {
        assert_eq!(
            server
                .ask("myip.example.test.", RecordType::A)
                .await
                .metadata
                .response_code,
            ResponseCode::NXDomain,
            "built-ins differ between the two paths"
        );
        assert_eq!(server.reload_as(None).await.0, 403, "the token differs");
        assert_eq!(
            a_values(&server.ask("www.example.test.", RecordType::A).await),
            vec!["203.0.113.10".to_owned()],
            "the served records differ between the two paths"
        );
    }
    assert_eq!(
        ignored_keys(&reload_body),
        ignored_keys(&fresh_body),
        "the two paths disagree about which file keys are shadowed"
    );
}

/// Scenario: No serving code resolves a configuration from a default invocation
/// features/config-precedence.feature:183
#[test]
fn no_serving_code_resolves_a_configuration_from_a_default_invocation() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();

    for file in rust_files(&src) {
        let text = std::fs::read_to_string(&file).expect("source file reads");
        // Unit tests may legitimately build a default invocation. Serving code may
        // not: Config::merge treats an absent CLI value as "fall through", so
        // GlobalArgs::default() silently selects the built-in origin
        // (src/config.rs:338) instead of the operator's.
        let production = text.split("#[cfg(test)]").next().unwrap_or_default();
        for (index, line) in production.lines().enumerate() {
            if line.contains("GlobalArgs::default()") {
                offenders.push(format!("{}:{}", file.display(), index + 1));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "a second precedence implementation is being fed a default invocation at {offenders:?}; \
         the reload path must call Config::load against the frozen startup invocation"
    );
}

/// Scenario: Every configuration field is classified reloadable or fixed
/// features/config-precedence.feature:194
#[test]
fn every_configuration_field_is_classified_as_reloadable_or_fixed() {
    // Reloadable from the file on every reload.
    const RELOADABLE: &[&str] = &[
        "zone.default_ttl",
        "zone.builtins",
        "zone.soa",
        "zone.records",
    ];
    // Fixed for the process lifetime; drift must be reported, never applied.
    const FIXED: &[&str] = &[
        "zone.origin",
        "server.udp",
        "server.tcp",
        "server.admin_listen",
        "server.tcp_timeout_secs",
        // VEGA-046's drain window, classified by this test doing its job.
        // Fixed by *ownership*, not timing: main.rs:508 reads it at shutdown
        // time, but from `serve`'s own Config, and main.rs:459 gave the reload
        // path a clone(), so no reload can reach the value the shutdown
        // sequence will read. Deliberately *not* analogous to
        // tcp_timeout_secs, which is baked in at bind time — this one needs no
        // rebinding and should become reloadable (VEGA-076). Fixed today only
        // because nothing re-reads it. See the partition table in
        // .claude/backlog/decisions/VEGA-005-reload-precedence.md, Amendment 3.
        "server.shutdown_drain_secs",
        "server.rate_limit",
        "server.log_format",
        "server.log_level",
        "server.admin_token",
        "source",
    ];
    // Not operator-settable, so never in `ignored`.
    const INTERNAL: &[&str] = &["tcp_response_buffer"];

    let config = Config::load(&GlobalArgs::default()).expect("built-in defaults resolve");
    // Exhaustive destructuring on purpose: adding a field to Config is a compile
    // error here until the ruling's partition table classifies it and a reload
    // scenario covers it.
    let Config {
        source,
        udp,
        tcp,
        admin_listen,
        tcp_timeout,
        shutdown_drain,
        tcp_response_buffer,
        zone,
        rate_limit,
        log_format,
        log_level,
        admin_token,
    } = &config;
    let ZoneConfig {
        origin,
        default_ttl,
        builtins,
        soa,
        records,
    } = zone;

    let observed = [
        ("source", format!("{source:?}")),
        ("server.udp", format!("{udp:?}")),
        ("server.tcp", format!("{tcp:?}")),
        ("server.admin_listen", format!("{admin_listen:?}")),
        ("server.tcp_timeout_secs", format!("{tcp_timeout:?}")),
        ("server.shutdown_drain_secs", format!("{shutdown_drain:?}")),
        ("tcp_response_buffer", format!("{tcp_response_buffer:?}")),
        ("server.rate_limit", format!("{rate_limit:?}")),
        ("server.log_format", format!("{log_format:?}")),
        ("server.log_level", format!("{log_level:?}")),
        ("server.admin_token", format!("{admin_token:?}")),
        ("zone.origin", format!("{origin:?}")),
        ("zone.default_ttl", format!("{default_ttl:?}")),
        ("zone.builtins", format!("{builtins:?}")),
        ("zone.soa", format!("{soa:?}")),
        ("zone.records", format!("{records:?}")),
    ];

    for (key, _) in &observed {
        assert!(
            RELOADABLE.contains(key) || FIXED.contains(key) || INTERNAL.contains(key),
            "{key} is not classified by the VEGA-005 partition table"
        );
    }
    assert_eq!(
        observed.len(),
        RELOADABLE.len() + FIXED.len() + INTERNAL.len(),
        "the partition table names a key that Config does not have"
    );
}

// ==========================================================================
// C. An origin change is refused
// ==========================================================================

/// Scenario: A reload that would change the origin is refused
/// features/live-reload.feature:162
#[tokio::test]
async fn a_reload_that_would_change_the_origin_is_refused_with_409() {
    let vega = Spawn::new(zone_file(Some("example.test"), "203.0.113.10"))
        .start()
        .await;

    vega.write_config(&zone_file(Some("example.net"), "203.0.113.10"));
    let (status, body) = vega.reload().await;

    assert_eq!(
        status, 409,
        "a running server must not be talked into a different zone: {body}"
    );
    assert_code(&body, "origin_changed");
    assert_eq!(body["status"], "unchanged", "{body}");
    assert_eq!(body["running_origin"], "example.test", "{body}");
    assert_eq!(body["requested_origin"], "example.net", "{body}");
}

/// Scenario: A refused origin change leaves the previous zone answering
/// features/live-reload.feature:174
#[tokio::test]
async fn a_refused_origin_change_leaves_the_previous_zone_answering() {
    let vega = Spawn::new(zone_file(Some("example.test"), "203.0.113.10"))
        .start()
        .await;

    vega.write_config(&zone_file(Some("example.net"), "198.51.100.1"));
    let (status, body) = vega.reload().await;
    assert_eq!(status, 409, "{body}");

    let answer = vega.ask("www.example.test.", RecordType::A).await;
    assert!(
        answer.metadata.authoritative,
        "the zone went dark: {answer:?}"
    );
    assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
    assert_eq!(a_values(&answer), vec!["203.0.113.10".to_owned()]);
}

/// Scenario: A refused origin change moves neither the gauge nor the reload counter
/// features/live-reload.feature:181
#[tokio::test]
async fn a_refused_origin_change_moves_neither_the_gauge_nor_the_reload_counter() {
    let vega = Spawn::new(zone_file(Some("example.test"), "203.0.113.10"))
        .start()
        .await;
    let records_before = vega.zone_records_gauge().await;
    let reloads_before = vega.reload_count().await;

    vega.write_config(&config_file(Some("example.net"), "", "", "198.51.100.1"));
    let (status, body) = vega.reload().await;
    assert_eq!(status, 409, "{body}");

    assert_eq!(
        vega.zone_records_gauge().await,
        records_before,
        "a refused reload moved dns_zone_records"
    );
    assert_eq!(
        vega.reload_count().await,
        reloads_before,
        "a refused reload incremented the reload counter, making 'reloads are succeeding' unfalsifiable"
    );
}

/// Scenario: Adding a trailing dot to the origin is not an origin change
/// features/live-reload.feature:190
#[tokio::test]
async fn a_trailing_dot_added_to_the_origin_is_not_an_origin_change() {
    let vega = Spawn::new(zone_file(Some("example.test"), "203.0.113.10"))
        .start()
        .await;

    vega.write_config(&zone_file(Some("example.test."), "198.51.100.1"));
    let (status, body) = vega.reload().await;

    assert_eq!(
        status, 200,
        "RFC 1035 §5.1: a trailing dot marks an already-qualified name, it is not a different zone: {body}"
    );
    assert_eq!(
        a_values(&vega.ask("www.example.test.", RecordType::A).await),
        vec!["198.51.100.1".to_owned()]
    );
}

/// Scenario: Changing the case of the origin is not an origin change
/// features/live-reload.feature:199
#[tokio::test]
async fn a_case_change_in_the_origin_is_not_an_origin_change() {
    let vega = Spawn::new(zone_file(Some("example.test"), "203.0.113.10"))
        .start()
        .await;

    vega.write_config(&zone_file(Some("EXAMPLE.TEST"), "198.51.100.1"));
    let (status, body) = vega.reload().await;

    assert_eq!(
        status, 200,
        "RFC 4343: DNS names compare case-insensitively over ASCII: {body}"
    );
    assert_eq!(
        a_values(&vega.ask("www.example.test.", RecordType::A).await),
        vec!["198.51.100.1".to_owned()]
    );
}

/// Scenario: A refused origin change never builds the new zone
/// features/live-reload.feature:206
#[tokio::test]
async fn a_file_that_changes_the_origin_is_refused_before_the_zone_is_built() {
    let vega = Spawn::new(zone_file(Some("example.test"), "203.0.113.10"))
        .start()
        .await;

    // Both wrong: a new origin *and* an unparseable A value. The origin gate is
    // step 5 and the zone build is step 6, so the origin must be what is reported.
    vega.write_config(&zone_file(Some("example.net"), "not-an-ip"));
    let (status, body) = vega.reload().await;

    assert_eq!(status, 409, "{body}");
    assert_code(&body, "origin_changed");
}

// ==========================================================================
// D. Fixed settings are reported, never silent
// ==========================================================================

/// Scenario: A changed UDP listener is reported and not applied
/// features/live-reload.feature:225
#[tokio::test]
async fn a_changed_udp_listener_is_reported_as_ignored_and_not_applied() {
    let vega = Spawn::new(zone_file(Some("example.test"), "203.0.113.10"))
        .start()
        .await;

    vega.write_config(&config_file(
        Some("example.test"),
        "",
        "udp = [\"127.0.0.1:5399\"]\n",
        "203.0.113.10",
    ));
    let (status, body) = vega.reload().await;

    assert_eq!(status, 200, "{body}");
    assert!(
        ignored_keys(&body).iter().any(|key| key == "server.udp"),
        "an operator who edits the listen address must not read a 200 and conclude it took effect: {body}"
    );
    vega.wait_for_log("server.udp").await;
    // Still bound where it started.
    assert_eq!(
        a_values(&vega.ask("www.example.test.", RecordType::A).await),
        vec!["203.0.113.10".to_owned()]
    );
}

/// Scenario: A changed rate limit is reported and not applied
/// features/live-reload.feature:237
#[tokio::test]
async fn a_changed_rate_limit_is_reported_as_ignored_and_not_applied() {
    let vega = Spawn::new(config_file(
        Some("example.test"),
        "",
        "rate_limit = { qps = 10, burst = 10 }\n",
        "203.0.113.10",
    ))
    .start()
    .await;

    vega.write_config(&config_file(
        Some("example.test"),
        "",
        "rate_limit = { qps = 1000, burst = 2000 }\n",
        "203.0.113.10",
    ));
    let (status, body) = vega.reload().await;

    assert_eq!(status, 200, "{body}");
    assert!(
        ignored_keys(&body)
            .iter()
            .any(|key| key == "server.rate_limit.qps"),
        "today this is not even warned about: {body}"
    );

    for _ in 0..40u32 {
        let _ = tokio::time::timeout(
            Duration::from_millis(120),
            vega.ask("www.example.test.", RecordType::A),
        )
        .await;
    }
    assert!(
        counter_value(&vega.metrics().await, "dns_rate_limited_total") > 0,
        "the limiter was rebuilt at 1000 qps; it is constructed once in serve()"
    );
}

/// Scenario: Every fixed setting that drifts is named in the ignored array
/// features/live-reload.feature:248
#[tokio::test]
async fn every_fixed_setting_that_drifts_is_named_in_the_ignored_array() {
    let vega = Spawn::new(zone_file(Some("example.test"), "203.0.113.10"))
        .start()
        .await;

    vega.write_config(&config_file(
        Some("example.test"),
        "",
        "udp = [\"127.0.0.1:5399\"]\n\
         tcp = [\"127.0.0.1:5398\"]\n\
         admin_listen = \"127.0.0.1:5397\"\n\
         tcp_timeout_secs = 30\n\
         log_level = \"trace\"\n\
         log_format = \"json\"\n\
         admin_token = \"from-the-file\"\n\
         rate_limit = { qps = 1000, burst = 2000 }\n",
        "203.0.113.10",
    ));
    let (status, body) = vega.reload().await;
    assert_eq!(status, 200, "{body}");

    let reported = ignored_keys(&body);
    for key in [
        "server.udp",
        "server.tcp",
        "server.admin_listen",
        "server.tcp_timeout_secs",
        "server.log_level",
        "server.log_format",
        "server.admin_token",
        "server.rate_limit.qps",
        "server.rate_limit.burst",
    ] {
        assert!(
            reported.iter().any(|found| found == key),
            "{key} drifted but was applied silently: {body}"
        );
    }
}

/// Scenario: A drifted admin token reports its key path and never its value
/// features/live-reload.feature:258
#[tokio::test]
async fn a_drifted_admin_token_reports_the_key_path_and_never_the_value() {
    let vega = Spawn::new(config_file(
        Some("example.test"),
        "",
        "admin_token = \"old-secret-value\"\n",
        "203.0.113.10",
    ))
    .start()
    .await;

    vega.write_config(&config_file(
        Some("example.test"),
        "",
        "admin_token = \"new-secret-value\"\n",
        "203.0.113.10",
    ));
    let (status, body) = vega.reload_as(Some("old-secret-value")).await;

    assert_eq!(status, 200, "{body}");
    assert!(
        ignored_keys(&body)
            .iter()
            .any(|key| key == "server.admin_token"),
        "{body}"
    );
    let rendered = body.to_string();
    assert!(
        !rendered.contains("old-secret-value") && !rendered.contains("new-secret-value"),
        "a token value leaked into the reload response: {rendered}"
    );
    vega.wait_for_log("server.admin_token").await;
    let logs = vega.logs();
    assert!(
        !logs.contains("old-secret-value") && !logs.contains("new-secret-value"),
        "a token value leaked into the log"
    );
}

/// Scenario: A fixed setting that still drifts is reported on every reload
/// features/live-reload.feature:270
#[tokio::test]
async fn a_fixed_setting_that_still_drifts_is_reported_on_every_reload() {
    let vega = Spawn::new(zone_file(Some("example.test"), "203.0.113.10"))
        .start()
        .await;

    vega.write_config(&config_file(
        Some("example.test"),
        "",
        "udp = [\"127.0.0.1:5399\"]\n",
        "203.0.113.10",
    ));

    let (first_status, first) = vega.reload().await;
    assert_eq!(first_status, 200, "{first}");
    assert!(
        ignored_keys(&first).iter().any(|key| key == "server.udp"),
        "{first}"
    );

    let (second_status, second) = vega.reload().await;
    assert_eq!(second_status, 200, "{second}");
    assert!(
        ignored_keys(&second).iter().any(|key| key == "server.udp"),
        "the drift from the socket actually bound still exists, so the second reload \
         must warn again; a `running = fresh` assignment silences it: {second}"
    );
}

/// Scenario: A reload with nothing drifted reports an empty ignored array
/// features/live-reload.feature:279
#[tokio::test]
async fn a_reload_with_no_drift_reports_an_empty_ignored_array() {
    let vega = Spawn::new(zone_file(Some("example.test"), "203.0.113.10"))
        .start()
        .await;

    let (status, body) = vega.reload().await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body.get("ignored"),
        Some(&Value::Array(vec![])),
        "`ignored` must always be present, so a consumer never has to guess \
         whether an absent field means 'nothing' or 'not reported': {body}"
    );
}

/// Scenario: The reload command prints the ignored keys to the terminal
/// features/live-reload.feature:288
#[tokio::test]
async fn the_reload_command_prints_the_ignored_keys_to_the_terminal() {
    let vega = Spawn::new(zone_file(Some("example.test"), "203.0.113.10"))
        .start()
        .await;
    vega.write_config(&config_file(
        Some("example.test"),
        "",
        "udp = [\"127.0.0.1:5399\"]\n",
        "203.0.113.10",
    ));

    // Under the gate like every other spawn: this child is just as capable of
    // inheriting another test's probe socket and holding its port hostage.
    let gate = hold_spawn_gate();
    let output = Command::new(bin())
        .args(["reload", "--admin-listen", &vega.admin.to_string()])
        .current_dir(vega.dir.path())
        .env("NO_COLOR", "1")
        .output()
        .expect("the reload subcommand runs");
    drop(gate);

    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(output.status.success(), "{text}");
    assert!(
        text.contains("server.udp"),
        "an operator who never reads the JSON must still see what was ignored: {text}"
    );
}

// ==========================================================================
// E. Failure modes leave the zone untouched
// ==========================================================================

/// Scenario: A reload of a deleted config file is refused as config_read_failed
/// features/live-reload.feature:349
#[tokio::test]
async fn a_reload_of_a_deleted_config_file_is_config_read_failed() {
    let vega = Spawn::new(zone_file(Some("example.test"), "203.0.113.10"))
        .start()
        .await;
    let path = vega.config.display().to_string();
    vega.delete_config();

    let (status, body) = vega.reload().await;
    assert_eq!(status, 400, "{body}");
    assert_code(&body, "config_read_failed");
    assert!(
        body["error"].as_str().is_some_and(|e| e.contains(&path)),
        "the error must name the file so the operator knows which one to restore: {body}"
    );
    assert_eq!(
        a_values(&vega.ask("www.example.test.", RecordType::A).await),
        vec!["203.0.113.10".to_owned()]
    );
}

/// Scenario: A reload of unparseable TOML is refused as config_parse_failed
/// features/live-reload.feature:331
#[tokio::test]
async fn a_reload_of_unparseable_toml_is_config_parse_failed() {
    let vega = Spawn::new(zone_file(Some("example.test"), "203.0.113.10"))
        .start()
        .await;
    vega.write_config("[zone\norigin = ");

    let (status, body) = vega.reload().await;
    assert_eq!(status, 400, "{body}");
    assert_code(&body, "config_parse_failed");
    assert_eq!(
        a_values(&vega.ask("www.example.test.", RecordType::A).await),
        vec!["203.0.113.10".to_owned()]
    );
}

/// Scenario: A semantically invalid config is refused as config_invalid
/// features/live-reload.feature:339
#[tokio::test]
async fn a_reload_of_a_semantically_invalid_config_is_config_invalid() {
    let vega = Spawn::new(zone_file(Some("example.test"), "203.0.113.10"))
        .start()
        .await;
    vega.write_config(
        &config_file(Some("example.test"), "", "", "203.0.113.10")
            .replace("default_ttl = 300", "default_ttl = 0"),
    );

    let (status, body) = vega.reload().await;
    assert_eq!(status, 400, "{body}");
    assert_code(&body, "config_invalid");
    assert_eq!(
        a_values(&vega.ask("www.example.test.", RecordType::A).await),
        vec!["203.0.113.10".to_owned()]
    );
}

/// Scenario: A config whose zone will not build is refused as zone_build_failed
/// features/live-reload.feature:321
#[tokio::test]
async fn a_reload_that_cannot_build_the_zone_is_zone_build_failed() {
    let vega = Spawn::new(zone_file(Some("example.test"), "203.0.113.10"))
        .start()
        .await;
    vega.write_config(&zone_file(Some("example.test"), "not-an-ip"));

    let (status, body) = vega.reload().await;
    assert_eq!(status, 400, "{body}");
    assert_code(&body, "zone_build_failed");
    assert_eq!(
        a_values(&vega.ask("www.example.test.", RecordType::A).await),
        vec!["203.0.113.10".to_owned()],
        "a typo in a config file must not take a name server off the internet"
    );
}

/// Scenario: No failing reload moves the reload counter or the records gauge
/// features/live-reload.feature:361
#[tokio::test]
async fn no_failing_reload_moves_the_reload_counter_or_the_records_gauge() {
    let good = zone_file(Some("example.test"), "203.0.113.10");
    let vega = Spawn::new(good.clone()).start().await;
    let records = vega.zone_records_gauge().await;
    let reloads = vega.reload_count().await;

    let broken = [
        ("config_parse_failed", "[zone\norigin = ".to_owned()),
        (
            "config_invalid",
            good.replace("default_ttl = 300", "default_ttl = 0"),
        ),
        (
            "zone_build_failed",
            zone_file(Some("example.test"), "not-an-ip"),
        ),
        (
            "origin_changed",
            zone_file(Some("example.net"), "203.0.113.10"),
        ),
    ];

    for (code, toml) in broken {
        vega.write_config(&toml);
        let (status, body) = vega.reload().await;
        assert!((400..500).contains(&status), "{code}: {body}");
        assert_code(&body, code);
        assert_eq!(
            vega.zone_records_gauge().await,
            records,
            "{code} moved dns_zone_records"
        );
        assert_eq!(
            vega.reload_count().await,
            reloads,
            "{code} incremented the reload counter"
        );
    }
}

/// Scenario: Every reload error body carries a code from the documented set
/// features/live-reload.feature:368
#[tokio::test]
async fn every_reload_error_body_carries_a_code_from_the_documented_set() {
    let vega = Spawn::new(zone_file(Some("example.test"), "203.0.113.10"))
        .token("s3cret")
        .start()
        .await;

    let (forbidden_status, forbidden) = vega.reload_as(Some("wrong")).await;
    assert_eq!(forbidden_status, 403, "{forbidden}");
    assert_code(&forbidden, "forbidden");

    let unconfigured = Spawn::new(String::new()).without_config().start().await;
    let (unconfigured_status, body) = unconfigured.reload().await;
    assert_eq!(unconfigured_status, 501, "{body}");
    assert_code(&body, "not_configured");
}

// ==========================================================================
// F. Concurrency and shutdown
// ==========================================================================

/// Scenario: Concurrent reload requests are each applied or refused as in progress
/// features/live-reload.feature:436
#[tokio::test]
async fn ten_concurrent_reloads_are_each_either_applied_or_refused_as_in_progress() {
    let vega = Spawn::new(zone_file(Some("example.test"), "203.0.113.10"))
        .start()
        .await;
    vega.write_config(&zone_file(Some("example.test"), "198.51.100.1"));

    let mut tasks = Vec::new();
    for _ in 0..10u32 {
        let admin = vega.admin;
        tasks.push(tokio::spawn(async move {
            let response = vega::http::post(admin, "/reload", None)
                .await
                .expect("the admin server answers");
            let body: Value = serde_json::from_str(response.body.trim()).unwrap_or(Value::Null);
            (response.status, body)
        }));
    }

    let mut applied = 0u32;
    for task in tasks {
        let (status, body) = task.await.expect("reload task completes");
        match status {
            200 => applied += 1,
            409 => assert_code(&body, "reload_in_progress"),
            other => panic!("a concurrent reload answered {other}: {body}"),
        }
    }
    assert!(
        applied >= 1,
        "not one of ten concurrent reloads was applied"
    );
    assert_eq!(
        a_values(&vega.ask("www.example.test.", RecordType::A).await),
        vec!["198.51.100.1".to_owned()],
        "the served zone does not match the config file"
    );
}

/// Scenario: Fifty reloads under a steady query stream never drop or mix an answer
/// features/live-reload.feature:389
#[tokio::test]
async fn fifty_reloads_under_a_steady_query_stream_never_drop_or_mix_an_answer() {
    let vega = Arc::new(
        Spawn::new(zone_file(Some("example.test"), "203.0.113.10"))
            .start()
            .await,
    );

    let reloader = {
        let vega = Arc::clone(&vega);
        tokio::spawn(async move {
            for round in 0..50u32 {
                let ip = if round % 2 == 0 {
                    "198.51.100.1"
                } else {
                    "203.0.113.10"
                };
                vega.write_config(&zone_file(Some("example.test"), ip));
                let (status, body) = vega.reload().await;
                assert_eq!(status, 200, "round {round}: {body}");
            }
        })
    };

    let mut answered = 0u32;
    while !reloader.is_finished() {
        let response = vega.ask("www.example.test.", RecordType::A).await;
        assert_eq!(
            response.metadata.response_code,
            ResponseCode::NoError,
            "a query during a reload was not answered from a complete zone"
        );
        let values = a_values(&response);
        assert!(
            values == vec!["203.0.113.10".to_owned()] || values == vec!["198.51.100.1".to_owned()],
            "an answer mixed records from two zones: {values:?}"
        );
        answered += 1;
    }
    reloader.await.expect("the reloader finishes");
    assert!(
        answered >= 50,
        "the query stream only managed {answered} queries across 50 reloads; \
         it is not exercising the swap under load"
    );
}

// ==========================================================================
// G. Ordering — see the report; `dns_zone_records` vs the swap is not
//    observable from outside the process.
// ==========================================================================

// ==========================================================================
// H. The harness itself
// ==========================================================================

/// Regression guard for the `EADDRINUSE` flake this file used to fail 7 runs in
/// 15 with (qa-adversary, VEGA-005 stage 4).
///
/// The bug is a race between `socket(2)` and `ioctl(FIOCLEX)` in `std` on macOS,
/// so a run that happens to pass proves nothing and no assertion inside a normal
/// test can see it. What *is* deterministic is that the spawn path must take the
/// gate; if a later edit drops `hold_spawn_gate` from `Spawn::start`, the flake
/// comes straight back and only this test notices.
#[tokio::test]
async fn starting_a_server_takes_the_spawn_gate() {
    let before = GATE_TAKEN.load(AtomicOrdering::SeqCst);
    let vega = Spawn::new(zone_file(Some("example.test"), "203.0.113.10"))
        .start()
        .await;
    let after = GATE_TAKEN.load(AtomicOrdering::SeqCst);

    // Other tests run concurrently and take the gate too, so this is a lower
    // bound rather than an equality — the point is that ours cannot be zero.
    assert!(
        after > before,
        "Spawn::start must probe its ports and spawn the child under the spawn \
         gate; without it a concurrent spawn inherits the probe socket and the \
         child cannot bind the port it was given"
    );

    // Prove the server that was started under the gate is the usual working one,
    // so this cannot pass against a gate bolted onto a broken spawn path.
    let response = vega.ask("www.example.test.", RecordType::A).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
}
