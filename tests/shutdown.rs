//! Acceptance tests for the shutdown drain (VEGA-046).
//!
//! Every scenario here needs a *real process under a real signal*: the defect is
//! in the ordering of signal handling, socket closure and readiness reporting,
//! and an in-process test that never sends `SIGTERM` cannot observe any of it.
//! So each test spawns the built binary, drives it over UDP/TCP/HTTP, sends it
//! signals with `kill(1)`, and reads its exit code.
//!
//! Two rules this file holds itself to, because a leaked name server holding a
//! port poisons every later run:
//!
//! * every listener — the server's and the tests' own — binds `127.0.0.1` on an
//!   ephemeral port, never a wildcard and never a fixed port;
//! * every child is owned by [`Server`], whose `Drop` kills and reaps it, so a
//!   failed assertion (which unwinds) cannot leave a process behind.
//!
//! Scenario numbers refer to §13 of
//! `.claude/backlog/decisions/VEGA-046-shutdown-drain.md`, and every test names
//! the scenario in `features/shutdown.feature` that it enforces.

// Signals are the subject; there is nothing here to run on a non-Unix host.
#![cfg(unix)]

use std::{
    fmt::Write as _,
    fs::File,
    io::Read as _,
    net::{SocketAddr, TcpListener, UdpSocket},
    path::PathBuf,
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RecordType},
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
};

/// How often the shutdown pollers sample. The ruling asks for 10 ms.
const POLL: Duration = Duration::from_millis(10);

/// Per-query timeout. A healthy answer on loopback is microseconds; this only
/// bounds the failing case so a dead server cannot stall the sampler.
const DNS_TIMEOUT: Duration = Duration::from_millis(400);

/// Per-request timeout for the admin endpoints, same reasoning.
const HTTP_TIMEOUT: Duration = Duration::from_secs(1);

/// How long a test waits for the server to come up before giving up.
const READY_TIMEOUT: Duration = Duration::from_secs(10);

/// The name every test queries. It is in the generated zone.
const QNAME: &str = "www.example.com";

// ---------------------------------------------------------------- the child

/// How a test wants the server configured.
///
/// The three drain fields exist separately on purpose: the ruling specifies
/// three configuration surfaces (§2.4) and each is pinned by at least one
/// scenario, so implementing only one of them still fails a test.
#[derive(Default)]
struct Spawn {
    /// `VEGA_SHUTDOWN_DRAIN_SECS` in the child's environment.
    drain_env: Option<String>,
    /// `[server] shutdown_drain_secs`, written verbatim into the TOML.
    drain_toml: Option<String>,
    /// `--shutdown-drain-secs` on the command line.
    drain_flag: Option<String>,
    /// `[server] tcp_timeout_secs`. `None` leaves the default (10 s).
    tcp_timeout_secs: Option<u64>,
    /// Where the admin listener goes, if anywhere.
    admin: Admin,
}

/// The admin listener a test wants.
#[derive(Clone, Copy, Default)]
enum Admin {
    /// No admin listener: the drain is unobservable, which is a scenario.
    #[default]
    Off,
    /// A loopback port picked at spawn time.
    Ephemeral,
    /// A pinned address, so a test can hold the port and force a bind failure.
    At(SocketAddr),
}

impl Spawn {
    /// The common shape: an ephemeral admin listener, no drain configured.
    fn with_admin() -> Self {
        Self {
            admin: Admin::Ephemeral,
            ..Self::default()
        }
    }

    /// Configure the drain through the environment variable.
    fn with_drain_env(mut self, secs: u64) -> Self {
        self.drain_env = Some(secs.to_string());
        self
    }
}

/// A running (or exited) `vega` process, its addresses, and its log.
struct Server {
    child: Child,
    pid: u32,
    /// UDP *and* TCP DNS, on one port, on loopback.
    dns: SocketAddr,
    admin: Option<SocketAddr>,
    log_path: PathBuf,
    config_path: PathBuf,
    /// Deleted when the server is dropped, so it has to outlive the child.
    _dir: TempDir,
}

impl Drop for Server {
    /// Reap the child unconditionally.
    ///
    /// This runs on the panic unwind of a failed assertion as well as on the
    /// happy path, which is the whole point: a test that fails half way through
    /// a drain must not leave a name server behind holding a port.
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

impl Server {
    /// Spawn the binary. Does not wait for readiness — a test that expects the
    /// process to fail at startup needs to observe exactly that.
    fn start(spawn: &Spawn) -> Self {
        let dir = TempDir::new().expect("temp dir");
        let dns_port = free_dns_port();
        let admin = match spawn.admin {
            Admin::Off => None,
            Admin::Ephemeral => Some(loopback(free_tcp_port())),
            Admin::At(addr) => Some(addr),
        };

        let config_path = dir.path().join("vega.toml");
        std::fs::write(&config_path, config_text(dns_port, admin, spawn)).expect("write config");

        let log_path = dir.path().join("vega.log");
        let log = File::create(&log_path).expect("create log");
        // One file description shared by both streams, so the interleaving is
        // real rather than two writers fighting over one offset.
        let log_err = log.try_clone().expect("clone log handle");

        let mut command = Command::new(bin());
        command
            .arg("--config")
            .arg(&config_path)
            .current_dir(dir.path())
            .env("NO_COLOR", "1")
            .env_remove("RUST_LOG")
            .env_remove("VEGA_CONFIG")
            .env_remove("VEGA_UDP")
            .env_remove("VEGA_TCP")
            .env_remove("VEGA_ADMIN_LISTEN")
            .env_remove("VEGA_SHUTDOWN_DRAIN_SECS")
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err));

        if let Some(secs) = &spawn.drain_flag {
            command.arg("--shutdown-drain-secs").arg(secs);
        }
        if let Some(secs) = &spawn.drain_env {
            command.env("VEGA_SHUTDOWN_DRAIN_SECS", secs);
        }

        let child = command.spawn().expect("the binary should be runnable");
        let pid = child.id();

        Self {
            child,
            pid,
            dns: loopback(dns_port),
            admin,
            log_path,
            config_path,
            _dir: dir,
        }
    }

    /// The admin address, for the tests that configured one.
    fn admin(&self) -> SocketAddr {
        self.admin.expect("this test configured an admin listener")
    }

    /// Everything the child has logged so far (stdout and stderr interleaved).
    fn log(&self) -> String {
        let mut text = String::new();
        if let Ok(mut file) = File::open(&self.log_path) {
            let _ = file.read_to_string(&mut text);
        }
        text
    }

    /// Send `sig` with `kill(1)` if the process is still running.
    ///
    /// `false` means it had already exited. The liveness check is not
    /// decoration: an exited-but-unreaped child is a zombie, and `kill(2)` on a
    /// zombie *succeeds*, so a test that only checked `kill`'s exit status would
    /// happily "deliver" ten signals to a process that died after the first.
    fn signal(&mut self, sig: &str) -> bool {
        if self.exited().is_some() {
            return false;
        }
        Command::new("kill")
            .arg(format!("-{sig}"))
            .arg(self.pid.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    /// Send `sig`, asserting it reached a live process.
    fn must_signal(&mut self, sig: &str) {
        assert!(
            self.signal(sig),
            "could not deliver {sig}: the process was already gone.\nlog:\n{}",
            self.log()
        );
    }

    fn exited(&mut self) -> Option<ExitStatus> {
        self.child.try_wait().ok().flatten()
    }

    /// Wait for `/readyz` to answer 200, or panic with the child's log.
    async fn wait_ready(&mut self) {
        let admin = self.admin();
        let deadline = Instant::now() + READY_TIMEOUT;
        while Instant::now() < deadline {
            if let Some(status) = self.exited() {
                panic!(
                    "the server exited during startup with {status}.\nlog:\n{}",
                    self.log()
                );
            }
            if let Ok(response) = http(admin, "GET", "/readyz").await {
                if response.status == 200 {
                    return;
                }
            }
            tokio::time::sleep(POLL).await;
        }
        panic!(
            "the server never reported ready within {READY_TIMEOUT:?}.\nlog:\n{}",
            self.log()
        );
    }

    /// Wait until DNS answers — readiness for the no-admin-listener shape.
    async fn wait_answering(&mut self) {
        let deadline = Instant::now() + READY_TIMEOUT;
        while Instant::now() < deadline {
            if let Some(status) = self.exited() {
                panic!(
                    "the server exited during startup with {status}.\nlog:\n{}",
                    self.log()
                );
            }
            if dns_answers(self.dns).await {
                return;
            }
            tokio::time::sleep(POLL).await;
        }
        panic!(
            "the server never answered a query within {READY_TIMEOUT:?}.\nlog:\n{}",
            self.log()
        );
    }

    /// Wait for exit, reporting the status and how long it took from `since`.
    async fn wait_exit(
        &mut self,
        since: Instant,
        within: Duration,
    ) -> Option<(ExitStatus, Duration)> {
        let deadline = Instant::now() + within;
        while Instant::now() < deadline {
            if let Some(status) = self.exited() {
                return Some((status, since.elapsed()));
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        None
    }
}

/// Path to the binary under test, as Cargo reports it.
fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_vega"))
}

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

/// A loopback TCP port that is free right now.
fn free_tcp_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind an ephemeral TCP port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

/// A loopback port free for *both* UDP and TCP, so the server can put its DNS
/// listeners on one number and a test can use either transport.
fn free_dns_port() -> u16 {
    for _ in 0..64 {
        let Ok(udp) = UdpSocket::bind(("127.0.0.1", 0)) else {
            continue;
        };
        let Ok(port) = udp.local_addr().map(|addr| addr.port()) else {
            continue;
        };
        drop(udp);
        if let Ok(tcp) = TcpListener::bind(("127.0.0.1", port)) {
            drop(tcp);
            return port;
        }
    }
    panic!("no loopback port was free for both UDP and TCP");
}

/// Render the child's config file.
fn config_text(dns_port: u16, admin: Option<SocketAddr>, spawn: &Spawn) -> String {
    let admin_line = admin.map_or_else(String::new, |addr| format!("admin_listen = \"{addr}\"\n"));
    let timeout_line = spawn
        .tcp_timeout_secs
        .map_or_else(String::new, |secs| format!("tcp_timeout_secs = {secs}\n"));
    let drain_line = spawn.drain_toml.as_ref().map_or_else(String::new, |value| {
        format!("shutdown_drain_secs = {value}\n")
    });

    format!(
        "[server]\n\
         udp = [\"127.0.0.1:{dns_port}\"]\n\
         tcp = [\"127.0.0.1:{dns_port}\"]\n\
         {admin_line}{timeout_line}{drain_line}\
         \n\
         [zone]\n\
         origin = \"example.com\"\n\
         builtins = false\n\
         \n\
         [zone.soa]\n\
         mname = \"ns1.example.com.\"\n\
         rname = \"hostmaster.example.com.\"\n\
         \n\
         [[zone.records]]\n\
         name = \"www\"\n\
         type = \"A\"\n\
         values = [\"192.0.2.1\"]\n"
    )
}

/// The first log line mentioning every one of `needles`, case-insensitively.
fn line_with(log: &str, needles: &[&str]) -> Option<String> {
    log.lines()
        .map(str::to_lowercase)
        .find(|line| needles.iter().all(|needle| line.contains(needle)))
}

// ------------------------------------------------------------- tiny clients

/// One admin HTTP response: status, lowercased header block, body.
struct Http {
    status: u16,
    headers: String,
    body: String,
}

impl Http {
    /// The value of `name`, which the caller passes lowercased.
    fn header(&self, name: &str) -> Option<String> {
        self.headers.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim() == name).then(|| value.trim().to_owned())
        })
    }
}

/// A single admin request. `Connection: close` keeps the reply framing trivial.
async fn http(addr: SocketAddr, method: &str, path: &str) -> Result<Http, String> {
    let exchange = async {
        let mut stream = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
        let request =
            format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .await
            .map_err(|e| e.to_string())?;
        Ok::<_, String>(raw)
    };

    let raw = tokio::time::timeout(HTTP_TIMEOUT, exchange)
        .await
        .map_err(|_| format!("{method} {path} timed out"))??;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").ok_or("truncated response")?;
    let mut lines = head.lines();
    let status_line = lines.next().ok_or("empty response")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| format!("no status code in {status_line:?}"))?;

    Ok(Http {
        status,
        headers: lines.collect::<Vec<_>>().join("\n").to_lowercase(),
        body: body.to_owned(),
    })
}

/// Status of `/readyz`, or `None` when the admin listener is unreachable.
async fn readyz(addr: SocketAddr) -> Option<u16> {
    http(addr, "GET", "/readyz")
        .await
        .ok()
        .map(|response| response.status)
}

/// True when a UDP query comes back NOERROR with the expected answer.
async fn dns_answers(addr: SocketAddr) -> bool {
    matches!(
        vega::dnsclient::query(addr, QNAME, RecordType::A, false, DNS_TIMEOUT).await,
        Ok(outcome) if outcome.is_noerror() && !outcome.message.answers.is_empty()
    )
}

/// Ask `stream` for `QNAME`/A and read the complete reply (RFC 1035 §4.2.2
/// length prefix). `Err` carries what went wrong, so a test can tell a reset
/// from a timeout.
async fn dns_tcp_ask(stream: &mut TcpStream) -> Result<Message, String> {
    let mut name: Name = QNAME.parse().map_err(|_| "bad name".to_owned())?;
    name.set_fqdn(true);
    let mut request = Message::query();
    request.metadata.id = 0x4a4a;
    request.metadata.recursion_desired = false;
    request.add_query(Query::query(name, RecordType::A));
    let wire = request.to_vec().map_err(|e| e.to_string())?;

    let exchange = async {
        let len = u16::try_from(wire.len()).map_err(|e| e.to_string())?;
        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| e.to_string())?;
        stream.write_all(&wire).await.map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;

        let mut prefix = [0u8; 2];
        stream
            .read_exact(&mut prefix)
            .await
            .map_err(|e| e.to_string())?;
        let mut body = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
        stream
            .read_exact(&mut body)
            .await
            .map_err(|e| e.to_string())?;
        Message::from_vec(&body).map_err(|e| e.to_string())
    };

    tokio::time::timeout(Duration::from_secs(2), exchange)
        .await
        .map_err(|_| "no answer within 2s".to_owned())?
}

/// The value of a bare Prometheus sample, e.g. `dns_shutdown_phase 2`.
fn metric(body: &str, name: &str) -> Option<f64> {
    body.lines().find_map(|line| {
        let rest = line.strip_prefix(name)?;
        rest.strip_prefix(' ')?.trim().parse().ok()
    })
}

// -------------------------------------------------------------- the sampler

/// One observation of the whole surface, taken every [`POLL`].
struct Sample {
    at: Duration,
    readyz: Option<u16>,
    healthz: Option<(u16, String)>,
    dns: bool,
}

/// Take one observation of `/readyz`, `/healthz` and a UDP query.
async fn sample(admin: SocketAddr, dns: SocketAddr, since: Instant) -> Sample {
    let ready = readyz(admin).await;
    let health = http(admin, "GET", "/healthz")
        .await
        .ok()
        .map(|response| (response.status, response.body));
    let answered = dns_answers(dns).await;
    Sample {
        at: since.elapsed(),
        readyz: ready,
        healthz: health,
        dns: answered,
    }
}

/// Poll every 10 ms from `since` until the process exits or `limit` elapses,
/// then take one final observation of the exited process. The caller sends the
/// signal immediately before calling this.
async fn sample_shutdown(server: &mut Server, since: Instant, limit: Duration) -> Vec<Sample> {
    let admin = server.admin();
    let dns = server.dns;
    let mut samples = Vec::new();

    while since.elapsed() < limit {
        samples.push(sample(admin, dns, since).await);
        if server.exited().is_some() {
            break;
        }
        tokio::time::sleep(POLL).await;
    }
    samples.push(sample(admin, dns, since).await);
    samples
}

/// Render the samples as a table, so a failure message can be read.
fn table(samples: &[Sample]) -> String {
    let mut out = String::from("\n       t  readyz  healthz  dns\n");
    for sample in samples {
        let ready = sample
            .readyz
            .map_or_else(|| "-----".to_owned(), |status| status.to_string());
        let health = sample
            .healthz
            .as_ref()
            .map_or_else(|| "-----".to_owned(), |(status, _)| status.to_string());
        let dns = if sample.dns { "answer" } else { "FAIL" };
        let _ = writeln!(
            out,
            "{:7.0}ms  {ready:>5}  {health:>5}  {dns}",
            sample.at.as_secs_f64() * 1000.0
        );
    }
    out
}

/// Four streams of back-to-back UDP queries, at ~4 ms spacing, which is roughly
/// the ruling's 1 kqps. Each records *when it issued* the query — before sending,
/// so the timestamp cannot drift past the moment the sockets closed — and whether
/// it was answered.
fn spawn_load(
    dns: SocketAddr,
    since: Instant,
    stop: &Arc<AtomicBool>,
) -> Vec<tokio::task::JoinHandle<Vec<(Duration, bool)>>> {
    (0..4)
        .map(|_| {
            let stop = Arc::clone(stop);
            tokio::spawn(async move {
                let mut issued: Vec<(Duration, bool)> = Vec::new();
                while !stop.load(Ordering::Relaxed) {
                    let at = since.elapsed();
                    issued.push((at, dns_answers(dns).await));
                    tokio::time::sleep(Duration::from_millis(4)).await;
                }
                issued
            })
        })
        .collect()
}

/// Scrape `/metrics` until `stop`, keeping the last body that came off a process
/// which said it was draining.
///
/// This has to run *concurrently* with the shutdown: [`sample_shutdown`] returns
/// only once the child is dead, and an exited process serves no metrics, so a
/// scrape taken after it can only ever produce a refused connection.
fn spawn_drain_scrape(
    admin: SocketAddr,
    stop: &Arc<AtomicBool>,
) -> tokio::task::JoinHandle<Option<String>> {
    let stop = Arc::clone(stop);
    tokio::spawn(async move {
        let mut draining: Option<String> = None;
        while !stop.load(Ordering::Relaxed) {
            if let Ok(response) = http(admin, "GET", "/metrics").await {
                // Phase >= 2 (Draining) is what makes a scrape evidence about the
                // drain rather than about a healthy server.
                if metric(&response.body, "dns_shutdown_phase").is_some_and(|phase| phase >= 2.0) {
                    draining = Some(response.body);
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        draining
    })
}

/// What a draining server's own counters must say once it has answered load.
///
/// The client-side timings say the answers arrived; these say the server agrees
/// it sent them. A query counted as received but never written back is a send
/// error, and this is the only thing in the test that tells "answered" apart from
/// "sent". The scrape is mid-drain, so it can only ever under-count the load.
fn assert_the_server_agrees_it_answered(drain_metrics: &str) {
    assert_eq!(
        metric(drain_metrics, "dns_send_errors_total"),
        Some(0.0),
        "sustained load right through the drain must not produce send \
         errors.\nmetrics:\n{drain_metrics}"
    );
    assert_eq!(
        metric(drain_metrics, "dns_responses_total{rcode=\"servfail\"}"),
        Some(0.0),
        "no query under load may be answered SERVFAIL during the drain.\nmetrics:\n\
         {drain_metrics}"
    );
    let answered = metric(drain_metrics, "dns_responses_total{rcode=\"noerror\"}");
    assert!(
        answered.is_some_and(|count| count >= 100.0),
        "the draining process must have counted the answers it sent, but \
         dns_responses_total{{rcode=\"noerror\"}} was {answered:?}; at ~1kqps a scrape \
         taken during the window sees hundreds.\nmetrics:\n{drain_metrics}"
    );
}

/// Time of the first `/readyz` 503.
fn first_503(samples: &[Sample]) -> Option<Duration> {
    samples
        .iter()
        .find(|sample| sample.readyz == Some(503))
        .map(|sample| sample.at)
}

/// Time of the first query that went unanswered.
fn first_dns_failure(samples: &[Sample]) -> Option<Duration> {
    samples
        .iter()
        .find(|sample| !sample.dns)
        .map(|sample| sample.at)
}

/// Time of the first `/healthz` that could not be reached at all.
fn first_healthz_gone(samples: &[Sample]) -> Option<Duration> {
    samples
        .iter()
        .find(|sample| sample.healthz.is_none())
        .map(|sample| sample.at)
}

// =============================================================== HAPPY PATH

/// Scenario: readyz reports 503 while DNS still answers (ruling §13.1)
/// features/shutdown.feature:35
#[tokio::test]
async fn readyz_returns_503_for_at_least_the_drain_window_while_dns_still_answers() {
    let mut server = Server::start(&Spawn::with_admin().with_drain_env(2));
    server.wait_ready().await;

    let t0 = Instant::now();
    server.must_signal("TERM");
    let samples = sample_shutdown(&mut server, t0, Duration::from_secs(12)).await;

    let start = first_503(&samples).unwrap_or_else(|| {
        panic!(
            "/readyz never returned 503 after SIGTERM: it went straight from 200 to \
             unreachable, which is the defect VEGA-046 reports.{}",
            table(&samples)
        )
    });
    let overlap_end = samples
        .iter()
        .skip_while(|sample| sample.at < start)
        .take_while(|sample| sample.dns)
        .last()
        .map_or_else(
            || {
                panic!(
                    "no query was answered after /readyz first said 503.{}",
                    table(&samples)
                )
            },
            |sample| sample.at,
        );

    let overlap = overlap_end.saturating_sub(start);
    assert!(
        overlap >= Duration::from_millis(1900),
        "/readyz said 503 while DNS still answered for only {overlap:?}; the ruling \
         requires at least 1.9s out of a 2s drain window.{}",
        table(&samples)
    );
}

/// Scenario: readyz goes 503 before DNS stops, and DNS stops before the admin
/// listener goes away (ruling §13.2)
/// features/shutdown.feature:45
#[tokio::test]
async fn readyz_goes_503_before_dns_fails_and_dns_fails_before_healthz_disappears() {
    let mut server = Server::start(&Spawn::with_admin().with_drain_env(2));
    server.wait_ready().await;

    let t0 = Instant::now();
    server.must_signal("TERM");
    let samples = sample_shutdown(&mut server, t0, Duration::from_secs(12)).await;

    let ready_503 = first_503(&samples)
        .unwrap_or_else(|| panic!("/readyz never returned 503.{}", table(&samples)));
    let dns_gone = first_dns_failure(&samples)
        .unwrap_or_else(|| panic!("DNS never stopped answering.{}", table(&samples)));
    let health_gone = first_healthz_gone(&samples).unwrap_or_else(|| {
        panic!(
            "the admin listener never became unreachable.{}",
            table(&samples)
        )
    });

    assert!(
        ready_503 < dns_gone,
        "/readyz must publish 503 (at {ready_503:?}) before DNS stops answering (at \
         {dns_gone:?}), or nothing can take us out of rotation first.{}",
        table(&samples)
    );
    assert!(
        dns_gone <= health_gone,
        "the admin listener must outlive the DNS listeners: DNS stopped at \
         {dns_gone:?} but /healthz was already gone at {health_gone:?}.{}",
        table(&samples)
    );
}

/// Scenario: the process does not exit before the drain window elapses
/// (ruling §13.3)
/// features/shutdown.feature:54
#[tokio::test]
async fn the_process_does_not_exit_before_the_drain_window_elapses() {
    let drain = Duration::from_secs(2);
    let mut server = Server::start(&Spawn::with_admin().with_drain_env(2));
    server.wait_ready().await;

    let t0 = Instant::now();
    server.must_signal("TERM");
    let (status, elapsed) = server
        .wait_exit(t0, Duration::from_secs(12))
        .await
        .unwrap_or_else(|| panic!("the process never exited.\nlog:\n{}", server.log()));

    assert!(
        elapsed >= drain,
        "exited {elapsed:?} after SIGTERM; a configured {drain:?} drain window means \
         it must not exit before then. terminationGracePeriodSeconds is a ceiling, \
         not a delay: it does nothing once we have already gone.\nlog:\n{}",
        server.log()
    );
    assert_eq!(
        status.code(),
        Some(0),
        "a drained shutdown exits 0.\nlog:\n{}",
        server.log()
    );
}

/// Scenario: healthz stays 200 for the whole drain (ruling §13.4)
/// features/shutdown.feature:61
#[tokio::test]
async fn healthz_stays_200_with_body_ok_for_the_whole_drain() {
    let mut server = Server::start(&Spawn::with_admin().with_drain_env(2));
    server.wait_ready().await;

    let t0 = Instant::now();
    server.must_signal("TERM");
    let samples = sample_shutdown(&mut server, t0, Duration::from_secs(12)).await;

    let live: Vec<&Sample> = samples
        .iter()
        .take_while(|sample| sample.healthz.is_some())
        .collect();
    assert!(
        live.len() >= 100,
        "expected well over a hundred samples across a 2s drain, got {}; the admin \
         listener disappeared far too early.{}",
        live.len(),
        table(&samples)
    );
    for sample in live {
        let (status, body) = sample.healthz.as_ref().expect("filtered above");
        assert_eq!(
            (*status, body.as_str()),
            (200, "ok\n"),
            "liveness must stay 200 ok throughout the drain (at {:?}). A draining \
             process is alive by definition, and a 503 here gets the container \
             restarted mid-drain.{}",
            sample.at,
            table(&samples)
        );
    }
}

/// Scenario: the draining phase is visible in metrics, version and the header
/// (ruling §13.5)
/// features/shutdown.feature:70
#[tokio::test]
async fn the_draining_phase_is_reported_by_metrics_version_and_the_phase_header() {
    let mut server = Server::start(&Spawn::with_admin().with_drain_env(3));
    server.wait_ready().await;
    let admin = server.admin();

    server.must_signal("TERM");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let metrics = http(admin, "GET", "/metrics")
        .await
        .unwrap_or_else(|e| panic!("/metrics during the drain: {e}\nlog:\n{}", server.log()));
    assert_eq!(
        metric(&metrics.body, "dns_shutdown_phase"),
        Some(2.0),
        "a scrape that catches the drain is the only record we will ever have of it, \
         so the phase has to be exported (2 = Draining).\nbody:\n{}",
        metrics.body
    );

    let version = http(admin, "GET", "/version")
        .await
        .unwrap_or_else(|e| panic!("/version during the drain: {e}"));
    assert!(
        version.body.contains("\"phase\":\"draining\"") && version.body.contains("\"ready\":false"),
        "/version must report the phase and unreadiness: {}",
        version.body
    );
    assert_eq!(
        version.header("x-vega-phase").as_deref(),
        Some("draining"),
        "every admin response carries X-Vega-Phase.\nheaders:\n{}",
        version.headers
    );
}

// ================================================================= BOUNDARY

/// Scenario: a zero-length drain still runs every phase in order (ruling §13.6)
/// features/shutdown.feature:82
#[tokio::test]
async fn a_zero_drain_still_runs_the_phases_in_order() {
    let mut server = Server::start(&Spawn::with_admin().with_drain_env(0));
    server.wait_ready().await;

    let t0 = Instant::now();
    server.must_signal("TERM");
    let (status, _) = server
        .wait_exit(t0, Duration::from_secs(12))
        .await
        .unwrap_or_else(|| panic!("the process never exited.\nlog:\n{}", server.log()));
    assert_eq!(status.code(), Some(0));

    // With W = 0 the 503 is served for microseconds, which no 10 ms poller can
    // catch, so the ordering is asserted from the transition log instead.
    let log = server.log().to_lowercase();
    let mut cursor = 0usize;
    for phase in ["draining", "stopping", "closing"] {
        let found = log[cursor..].find(phase).unwrap_or_else(|| {
            panic!(
                "the shutdown log never reaches the {phase} phase; a zero-length \
                 window is still Draining then Stopping then Closing, in that order \
                 — one code path, no shortcuts.\nlog:\n{}",
                server.log()
            )
        });
        cursor += found + phase.len();
    }
}

/// Scenario: SIGINT skips the drain window (ruling §13.7)
/// features/shutdown.feature:91
#[tokio::test]
async fn sigint_skips_the_drain_window_and_exits_promptly() {
    // Configured on the command line, so the --shutdown-drain-secs surface is
    // pinned by at least one scenario.
    let spawn = Spawn {
        drain_flag: Some("10".to_owned()),
        ..Spawn::with_admin()
    };
    let mut server = Server::start(&spawn);
    server.wait_ready().await;

    let t0 = Instant::now();
    server.must_signal("INT");
    let (status, elapsed) = server
        .wait_exit(t0, Duration::from_secs(14))
        .await
        .unwrap_or_else(|| panic!("the process never exited.\nlog:\n{}", server.log()));

    assert!(
        elapsed < Duration::from_secs(2),
        "SIGINT is the interactive signal and runs a zero-length window; against a \
         configured 10s drain it took {elapsed:?}. No orchestrator sends SIGINT, so \
         making Ctrl-C block a developer is a pure usability tax.\nlog:\n{}",
        server.log()
    );
    assert_eq!(status.code(), Some(0));
}

/// Scenario: a drain above the maximum is refused at startup (ruling §13.8)
/// features/shutdown.feature:100
#[tokio::test]
async fn a_drain_above_the_maximum_is_rejected_at_startup() {
    let spawn = Spawn {
        drain_toml: Some("301".to_owned()),
        ..Spawn::with_admin()
    };
    let mut server = Server::start(&spawn);

    let (status, _) = server
        .wait_exit(Instant::now(), Duration::from_secs(10))
        .await
        .unwrap_or_else(|| {
            panic!(
                "301 seconds must be refused at startup, but the process is still \
                 running.\nlog:\n{}",
                server.log()
            )
        });
    assert_ne!(
        status.code(),
        Some(0),
        "a config error is a startup failure.\nlog:\n{}",
        server.log()
    );

    let log = server.log();
    assert!(
        line_with(&log, &["shutdown_drain_secs", "300"]).is_some(),
        "the error must name the setting and the limit an operator has to stay \
         under: above five minutes the value is a typo and the only outcome is a \
         guaranteed SIGKILL.\nlog:\n{log}"
    );
    assert!(
        !log.contains("unknown field"),
        "the value must be rejected as out of range, not as an unrecognised \
         key.\nlog:\n{log}"
    );
}

/// Scenario: the maximum drain is accepted (ruling §13.8)
/// features/shutdown.feature:109
#[tokio::test]
async fn the_maximum_drain_of_three_hundred_seconds_starts() {
    let spawn = Spawn {
        drain_toml: Some("300".to_owned()),
        ..Spawn::with_admin()
    };
    let mut server = Server::start(&spawn);
    // The range is inclusive: 300 is legal and must not be a startup failure.
    server.wait_ready().await;
    server.must_signal("INT");
}

/// Scenario: a malformed drain value is refused at startup
/// (ruling §2.4; added by qa-spec for malformed coverage)
/// features/shutdown.feature:116
#[tokio::test]
async fn a_negative_drain_is_rejected_at_startup_naming_the_setting() {
    let spawn = Spawn {
        drain_toml: Some("-1".to_owned()),
        ..Spawn::with_admin()
    };
    let mut server = Server::start(&spawn);

    let (status, _) = server
        .wait_exit(Instant::now(), Duration::from_secs(10))
        .await
        .unwrap_or_else(|| panic!("a negative drain must not start.\nlog:\n{}", server.log()));
    assert_ne!(status.code(), Some(0));

    let log = server.log();
    assert!(
        log.contains("shutdown_drain_secs"),
        "the error must name the setting.\nlog:\n{log}"
    );
    assert!(
        !log.contains("unknown field"),
        "the value must be rejected as invalid, not as an unrecognised key.\nlog:\n{log}"
    );
}

/// Scenario: a drain shorter than the TCP idle timeout warns and still starts
/// (ruling §13.9)
/// features/shutdown.feature:123
#[tokio::test]
async fn a_drain_shorter_than_the_tcp_idle_timeout_warns_and_still_starts() {
    let spawn = Spawn {
        drain_toml: Some("2".to_owned()),
        tcp_timeout_secs: Some(10),
        ..Spawn::with_admin()
    };
    let mut server = Server::start(&spawn);
    server.wait_ready().await;

    let log = server.log();
    assert!(
        line_with(&log, &["warn", "drain", "tcp"]).is_some(),
        "a drain shorter than the TCP idle timeout means idle connections are closed \
         by process exit rather than by their own timeout; that is a warning, not \
         silence, and not a refusal to start.\nlog:\n{log}"
    );
    server.must_signal("INT");
}

/// Scenario: no admin listener warns and still drains (ruling §13.10)
/// features/shutdown.feature:132
#[tokio::test]
async fn a_server_with_no_admin_listener_warns_and_still_drains() {
    let mut server = Server::start(&Spawn::default().with_drain_env(2));
    server.wait_answering().await;

    let log = server.log();
    assert!(
        line_with(&log, &["warn", "admin", "drain"]).is_some(),
        "without an admin listener nothing can observe the 503, and the operator has \
         to be told the drain is unobservable.\nlog:\n{log}"
    );

    let t0 = Instant::now();
    server.must_signal("TERM");
    let (_, elapsed) = server
        .wait_exit(t0, Duration::from_secs(12))
        .await
        .unwrap_or_else(|| panic!("the process never exited.\nlog:\n{}", server.log()));
    assert!(
        elapsed >= Duration::from_secs(2),
        "the drain still runs without an admin listener — resolvers holding our \
         address from a cached NS RRset keep getting answers — but it exited after \
         {elapsed:?}.\nlog:\n{}",
        server.log()
    );
}

/// Scenario: startup states the drain, the deadline and the grace-period floor
/// (ruling §13.11)
/// features/shutdown.feature:141
#[tokio::test]
async fn startup_logs_the_drain_the_hard_deadline_and_the_required_grace_period() {
    // No drain configured, so this also pins the shipped default of 15s and the
    // deadline (20s) and watchdog (22s) derived from it.
    let mut server = Server::start(&Spawn::with_admin());
    server.wait_ready().await;

    let log = server.log();
    let line = line_with(&log, &["shutdown drain"]).unwrap_or_else(|| {
        panic!(
            "no startup line states the drain window. We cannot read \
             terminationGracePeriodSeconds from inside the container, so we publish \
             the number the operator has to beat.\nlog:\n{log}"
        )
    });
    for expected in ["15", "20", "22", "terminationgraceperiodseconds"] {
        assert!(
            line.contains(expected),
            "the startup line must state the drain (15s), the hard deadline (20s) and \
             the grace-period floor (22s); {expected:?} is missing from \
             {line:?}.\nlog:\n{log}"
        );
    }
    server.must_signal("INT");
}

// ================================================================= IN-FLIGHT

/// Scenario: a TCP query written after SIGTERM on an open connection is answered
/// (ruling §13.12)
/// features/shutdown.feature:151
#[tokio::test]
async fn a_tcp_query_written_after_sigterm_on_an_open_connection_is_answered() {
    let mut server = Server::start(&Spawn::with_admin().with_drain_env(2));
    server.wait_ready().await;

    let mut stream = TcpStream::connect(server.dns)
        .await
        .expect("the DNS TCP listener accepts a connection");
    server.must_signal("TERM");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let message = dns_tcp_ask(&mut stream).await.unwrap_or_else(|e| {
        panic!(
            "a query written 100ms into the drain on an already-established \
             connection got no answer: {e}. RFC 7766 §6.2.4 lets us close, but \
             dropping the query costs the client a full retry on the transport it \
             chose precisely because the answer did not fit in 512 bytes.\nlog:\n{}",
            server.log()
        )
    });
    assert_eq!(message.metadata.id, 0x4a4a);
    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert_eq!(message.answers.len(), 1, "the A record must come back");
}

/// Scenario: a TCP query in the last 50 ms of the window is still answered
/// (ruling §13.13)
/// features/shutdown.feature:162
#[tokio::test]
async fn a_tcp_query_in_the_final_fifty_milliseconds_of_the_window_is_answered() {
    let mut server = Server::start(&Spawn::with_admin().with_drain_env(3));
    server.wait_ready().await;

    let mut stream = TcpStream::connect(server.dns)
        .await
        .expect("the DNS TCP listener accepts a connection");
    let t0 = Instant::now();
    server.must_signal("TERM");
    // The server's own window starts marginally after ours, so this lands inside
    // it, in its last 50ms.
    tokio::time::sleep_until((t0 + Duration::from_millis(2950)).into()).await;

    let message = dns_tcp_ask(&mut stream).await.unwrap_or_else(|e| {
        panic!(
            "a query received in the final 50ms of the window was not answered: {e}. \
             This is what the Stopping quiesce exists for: hickory aborts every \
             connection task the instant its token is cancelled.\nlog:\n{}",
            server.log()
        )
    });
    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
}

/// Scenario: an idle TCP connection is closed cleanly, not reset (ruling §13.14)
/// features/shutdown.feature:172
#[tokio::test]
async fn an_idle_tcp_connection_sees_an_orderly_close_not_a_reset() {
    // drain (4s) >= tcp_timeout (1s), so hickory's own TimeoutStream closes the
    // idle connection from the read side *during* the window — the only way we
    // get a FIN rather than a possible RST out of hickory 0.26.1.
    let spawn = Spawn {
        tcp_timeout_secs: Some(1),
        ..Spawn::with_admin()
    }
    .with_drain_env(4);
    let mut server = Server::start(&spawn);
    server.wait_ready().await;

    let mut stream = TcpStream::connect(server.dns)
        .await
        .expect("the DNS TCP listener accepts a connection");
    let t0 = Instant::now();
    server.must_signal("TERM");

    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .unwrap_or_else(|_| {
            panic!(
                "the idle connection was neither closed by its own 1s idle timeout \
                 nor by anything else within 3s.\nlog:\n{}",
                server.log()
            )
        });
    let elapsed = t0.elapsed();
    let still_draining = server.exited().is_none();

    match read {
        Ok(0) => {}
        Ok(n) => panic!("an idle connection received {n} unexpected bytes"),
        Err(error) => panic!(
            "the idle connection was closed with an error ({error}); a reset discards \
             data the client has not read yet, including a response we finished \
             writing microseconds earlier.\nlog:\n{}",
            server.log()
        ),
    }
    assert!(
        elapsed >= Duration::from_millis(500) && elapsed <= Duration::from_millis(2500),
        "the close arrived {elapsed:?} after SIGTERM; it has to come from the 1s TCP \
         idle timeout running inside the 4s drain, not from the process \
         exiting.\nlog:\n{}",
        server.log()
    );
    assert!(
        still_draining,
        "the process must still be draining when the idle connection \
         closes.\nlog:\n{}",
        server.log()
    );
}

// ==================================================== SECOND SIGNAL / HOSTILE

/// Scenario: a second SIGTERM collapses the window (ruling §13.15)
/// features/shutdown.feature:186
#[tokio::test]
async fn a_second_sigterm_collapses_the_remaining_drain_window() {
    let mut server = Server::start(&Spawn::with_admin().with_drain_env(10));
    server.wait_ready().await;

    let t0 = Instant::now();
    server.must_signal("TERM");
    tokio::time::sleep(Duration::from_secs(1)).await;
    server.must_signal("TERM");

    let (status, elapsed) = server
        .wait_exit(t0, Duration::from_secs(14))
        .await
        .unwrap_or_else(|| panic!("the process never exited.\nlog:\n{}", server.log()));
    assert!(
        elapsed < Duration::from_secs(3),
        "a second signal means \"hurry up\": it collapses the remaining 9s of the \
         window and advances the machine, but the process took {elapsed:?}.\nlog:\n{}",
        server.log()
    );
    assert_eq!(
        status.code(),
        Some(0),
        "collapsing the window is still a clean shutdown; a second signal never calls \
         exit() and never bypasses the ordering.\nlog:\n{}",
        server.log()
    );
}

/// Scenario: a storm of SIGTERMs is absorbed (ruling §13.16)
/// features/shutdown.feature:196
///
/// §13.16 asks for exactly four things — *exits once, cleanly, exit code 0, no
/// panic, no double-cancel* — and the first draft of this test asked for a
/// fifth: that at least eight of the ten signals reach a live process. That is
/// unsatisfiable, and it contradicts §5 and the scenario above it: the **second**
/// signal collapses the remaining window, so the process is entitled to be gone
/// at t ≈ 15 ms and signals 3..10 land on a corpse. Measured: signal 1 at t=0,
/// signal 2 at t=14 ms, exit at t=14.5 ms, two signals delivered. No
/// implementation can hold both, and the drain ruling is the one that wins.
///
/// So "no double-cancel" is enforced where it is actually observable — in the
/// transition log. Each stage of the machine has exactly one line; a storm that
/// re-entered the machine (a shutdown task spawned per signal, or a
/// `Lifecycle::enter` that let the phase go backwards) prints them twice, and a
/// storm that killed us on the first signal prints none of them.
#[tokio::test]
async fn a_storm_of_sigterms_runs_the_machine_exactly_once_and_exits_clean() {
    let mut server = Server::start(&Spawn::with_admin().with_drain_env(5));
    server.wait_ready().await;

    let t0 = Instant::now();
    // The first must land on a live process or the storm proves nothing.
    server.must_signal("TERM");
    let mut delivered = 1;
    for _ in 1..10 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        if server.signal("TERM") {
            delivered += 1;
        }
    }

    let (status, elapsed) = server
        .wait_exit(t0, Duration::from_secs(14))
        .await
        .unwrap_or_else(|| panic!("the process never exited.\nlog:\n{}", server.log()));

    assert!(
        delivered >= 2,
        "only the first of ten signals reached a live process, so it died on that \
         first signal — the defect VEGA-046 reports. A supervisor retrying SIGTERM \
         10ms into a 5s window must still find us draining; what happens to the \
         signals after the second is the second one's business, because it collapses \
         the window.\nlog:\n{}",
        server.log()
    );
    assert_eq!(
        status.code(),
        Some(0),
        "a signal storm still exits once, cleanly: 0, not 3 (deadline overrun) and \
         not None (killed by a signal we failed to catch). It exited after \
         {elapsed:?}.\nlog:\n{}",
        server.log()
    );

    let log = server.log();
    assert!(
        !log.contains("panicked"),
        "tokio::signal coalesces, so a storm must not produce handler \
         re-entrancy.\nlog:\n{log}"
    );
    assert!(
        log.contains("another shutdown signal"),
        "the signals after the first must be heard and folded into the running \
         machine — that is what makes this a storm rather than one signal. \
         {delivered} of 10 were delivered.\nlog:\n{log}"
    );

    // Exactly one pass through the machine, in order. This is where "exits once"
    // and "no double-cancel" are falsifiable from outside the process.
    let mut cursor = 0usize;
    for stage in [
        "shutdown signal received",
        "shutdown starting",
        "shutdown: draining",
        "shutdown: stopping",
        "shutdown: closing",
        "shutdown complete",
    ] {
        let seen = log.matches(stage).count();
        assert_eq!(
            seen, 1,
            "{delivered} signals must drive exactly one pass through the state \
             machine, but {stage:?} appears {seen} times. Twice means the machine was \
             re-entered — a second cancel of tokens already cancelled, a phase that \
             went backwards — and none means that stage never ran at all.\nlog:\n{log}"
        );
        let found = log[cursor..].find(stage).unwrap_or_else(|| {
            panic!(
                "the shutdown log reaches {stage:?} out of order; the ordering is the \
                 guarantee (503 first, DNS last, admin after that) and a storm must \
                 not shuffle it.\nlog:\n{log}"
            )
        });
        cursor += found + stage.len();
    }
}

/// Scenario: SIGHUP does not kill the process (ruling §13.17)
/// features/shutdown.feature:213
#[tokio::test]
async fn sighup_does_not_kill_the_process() {
    let mut server = Server::start(&Spawn::with_admin());
    server.wait_ready().await;
    let admin = server.admin();

    server.must_signal("HUP");
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(
        server.exited().is_none(),
        "SIGHUP is unhandled today, so its default disposition terminates the process \
         immediately: no drain, no 503, no log. A terminal hangup or a stray killall \
         -HUP is a strictly worse outage than the SIGTERM this issue is \
         about.\nlog:\n{}",
        server.log()
    );
    assert!(
        dns_answers(server.dns).await,
        "the server must still answer after SIGHUP.\nlog:\n{}",
        server.log()
    );
    assert_eq!(
        readyz(admin).await,
        Some(200),
        "SIGHUP must not start the shutdown machine.\nlog:\n{}",
        server.log()
    );
    let log = server.log();
    assert!(
        line_with(&log, &["sighup"]).is_some(),
        "an ignored SIGHUP must say so, and point at POST /reload.\nlog:\n{log}"
    );
}

/// Scenario: reload is refused during the drain and the hook never runs
/// (ruling §13.18)
/// features/shutdown.feature:224
#[tokio::test]
async fn reload_is_refused_during_the_drain_and_the_hook_is_never_invoked() {
    let mut server = Server::start(&Spawn::with_admin().with_drain_env(3));
    server.wait_ready().await;
    let admin = server.admin();

    // One successful reload first, so the counter has somewhere to move from.
    let first = http(admin, "POST", "/reload")
        .await
        .unwrap_or_else(|e| panic!("reload before the drain: {e}"));
    assert_eq!(first.status, 200, "body: {}", first.body);

    server.must_signal("TERM");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let refused = http(admin, "POST", "/reload")
        .await
        .unwrap_or_else(|e| panic!("/reload during the drain: {e}\nlog:\n{}", server.log()));
    assert_eq!(
        refused.status, 503,
        "swapping the zone in a process that is seconds from exiting cannot help \
         anything, and is the exact window in which a reload can wedge the drain. \
         body: {}",
        refused.body
    );
    assert!(
        refused.body.contains("draining"),
        "the refusal must say why: {}",
        refused.body
    );

    let version = http(admin, "GET", "/version")
        .await
        .unwrap_or_else(|e| panic!("/version during the drain: {e}"));
    assert!(
        version.body.contains("\"reloads\":1"),
        "the reload counter must not move: that is what proves the hook was never \
         invoked, rather than merely that it failed. body: {}",
        version.body
    );
}

/// Scenario: reload is refused by the drain-start token, in the very interval
/// where the two tokens differ (ruling §13.18b)
/// features/shutdown.feature:235
///
/// Strictly stronger than §13.18, and unwritable before the lifecycle landed.
/// §13.18 observes the drain only from outside — the counter did not move — and
/// would still pass if `/reload` were gated on the *listener-cancel* token,
/// because that test never checks whether the listeners are still up. This one
/// pins **which** token gates the refusal, by asserting all three conditions in
/// one interval: `/readyz` is already 503, DNS is still answering, and `/reload`
/// is refused. Wiring `ReloadContext.draining` to the DNS token instead makes a
/// reload succeed for the whole drain window — a new zone installed into a
/// process that is seconds from exiting, which is worse than the behaviour
/// VEGA-046 replaced.
#[tokio::test]
async fn reload_is_refused_while_readyz_is_503_and_dns_still_answers() {
    let mut server = Server::start(&Spawn::with_admin().with_drain_env(3));
    server.wait_ready().await;
    let admin = server.admin();
    let dns = server.dns;

    server.must_signal("TERM");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // One interval, bracketed by /readyz at both ends, so the refusal and the
    // answered query provably happened while the 503 window was open rather than
    // at three unrelated moments.
    let opened = readyz(admin).await;
    let refused = http(admin, "POST", "/reload")
        .await
        .unwrap_or_else(|e| panic!("/reload during the drain: {e}\nlog:\n{}", server.log()));
    let answered = dns_answers(dns).await;
    let still_open = readyz(admin).await;

    assert_eq!(
        (opened, still_open),
        (Some(503), Some(503)),
        "the whole observation has to sit inside the drain window.\nlog:\n{}",
        server.log()
    );
    assert!(
        answered,
        "DNS must still be answering in this interval — that is what makes it the \
         interval where the drain-start and listener-cancel tokens differ.\nlog:\n{}",
        server.log()
    );
    assert_eq!(
        refused.status, 503,
        "/reload must fail closed from the moment Draining is published, not from \
         the moment the DNS listeners are cancelled seconds later. body: {}",
        refused.body
    );
    assert!(
        refused.body.contains("\"code\":\"shutting_down\""),
        "the refusal must carry the stable code automation keys on: {}",
        refused.body
    );
    assert_eq!(
        refused.header("x-vega-phase").as_deref(),
        Some("draining"),
        "and it must be answered by a process that says it is draining.\nheaders:\n{}",
        refused.headers
    );
}

/// Scenario: every query issued while readyz said 503 was answered, under load
/// (ruling §13.19)
/// features/shutdown.feature:253
///
/// Two things this test had to be corrected on, both of them defects in the
/// measurement rather than in the server:
///
/// * `/metrics` was scraped after [`sample_shutdown`] returned — and that only
///   returns once the child is **dead**, so the scrape drew a refused connection,
///   `map_or_else` turned it into an empty body, and the `dns_send_errors_total`
///   assertion could never pass on any implementation. The scrape now runs
///   concurrently and is kept only when the exported phase proves it came off a
///   live, draining process.
/// * the interval "while /readyz said 503 and before the listeners closed" was
///   bounded above by the first poll that *failed*, which is up to a poll period
///   after the sockets actually closed. Measured, every query that failed under
///   the old bound was issued 5–15 ms **after** the 2 s window elapsed — the
///   window `§1.5` explicitly disclaims ("a query received during Draining is
///   answered", not "a query received in the final microsecond"). The bound is
///   now the last poll that was *observed* to be answered, which is a moment the
///   server was demonstrably still up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn under_load_every_query_issued_while_readyz_said_503_is_answered() {
    let mut server = Server::start(&Spawn::with_admin().with_drain_env(2));
    server.wait_ready().await;
    let dns = server.dns;
    let admin = server.admin();

    let t0 = Instant::now();
    let stop = Arc::new(AtomicBool::new(false));
    let streams = spawn_load(dns, t0, &stop);
    let scraper = spawn_drain_scrape(admin, &stop);

    server.must_signal("TERM");
    let samples = sample_shutdown(&mut server, t0, Duration::from_secs(12)).await;
    stop.store(true, Ordering::Relaxed);
    let drain_metrics = scraper
        .await
        .expect("the metrics scraper should not panic")
        .unwrap_or_else(|| {
            panic!(
                "no /metrics scrape ever caught the process in the Draining phase, so \
                 nothing here can say whether the queries under load were answered. \
                 Either the drain never happened or the admin listener went with \
                 it.{}",
                table(&samples)
            )
        });

    let mut queries: Vec<(Duration, bool)> = Vec::new();
    for stream in streams {
        queries.extend(stream.await.expect("the load task should not panic"));
    }

    let ready_503 = first_503(&samples)
        .unwrap_or_else(|| panic!("/readyz never returned 503.{}", table(&samples)));
    let dns_gone = first_dns_failure(&samples)
        .unwrap_or_else(|| panic!("DNS never stopped answering.{}", table(&samples)));

    // The last poll that was *seen* to be answered. Between it and the first poll
    // that failed the sockets may already have closed, and a query issued in that
    // gap was never promised an answer (§1.5).
    let last_answered = samples
        .iter()
        .take_while(|sample| sample.at < dns_gone)
        .filter(|sample| sample.dns)
        .last()
        .map_or_else(
            || {
                panic!(
                    "no query was answered between the signal and the listeners \
                     closing.{}",
                    table(&samples)
                )
            },
            |sample| sample.at,
        );
    // Without this the bound above could hollow the test out: a server that closed
    // its sockets 20 ms into the window would give an empty interval and nothing
    // to fail on. The interval has to be nearly the whole 2s window.
    let observed = last_answered.saturating_sub(ready_503);
    assert!(
        observed >= Duration::from_millis(1500),
        "/readyz said 503 while DNS still answered for only {observed:?} of a 2s \
         window, so this test has almost nothing to measure over.{}",
        table(&samples)
    );

    let drained: Vec<&(Duration, bool)> = queries
        .iter()
        .filter(|(at, _)| *at >= ready_503 && *at < last_answered)
        .collect();
    assert!(
        drained.len() >= 500,
        "expected roughly two thousand queries across the drain, got {}; the load did \
         not actually span the window.",
        drained.len()
    );
    let failures: Vec<Duration> = drained
        .iter()
        .filter(|(_, answered)| !*answered)
        .map(|(at, _)| *at)
        .collect();
    assert!(
        failures.is_empty(),
        "{} of {} queries issued while /readyz reported 503 and while the listeners \
         were still observably up went unanswered, at {failures:?}.{}",
        failures.len(),
        drained.len(),
        table(&samples)
    );

    assert_the_server_agrees_it_answered(&drain_metrics);
}

// ================================================================== DEADLINE

/// Scenario: the shutdown deadline is armed and reported (ruling §13.20)
/// features/shutdown.feature:273
#[tokio::test]
async fn the_shutdown_deadline_is_exported_and_counts_down() {
    let mut server = Server::start(&Spawn::with_admin().with_drain_env(3));
    server.wait_ready().await;
    let admin = server.admin();

    let before = http(admin, "GET", "/metrics")
        .await
        .unwrap_or_else(|e| panic!("/metrics before the signal: {e}"));
    assert_eq!(
        metric(&before.body, "dns_shutdown_deadline_seconds"),
        None,
        "the deadline gauge is only emitted once a signal has armed it"
    );

    server.must_signal("TERM");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let first = http(admin, "GET", "/metrics")
        .await
        .unwrap_or_else(|e| panic!("/metrics after the signal: {e}\nlog:\n{}", server.log()));
    tokio::time::sleep(Duration::from_secs(1)).await;
    let second = http(admin, "GET", "/metrics")
        .await
        .unwrap_or_else(|e| panic!("/metrics a second later: {e}\nlog:\n{}", server.log()));

    let earlier = metric(&first.body, "dns_shutdown_deadline_seconds").unwrap_or_else(|| {
        panic!(
            "dns_shutdown_deadline_seconds must appear once the deadline is \
             armed.\nmetrics:\n{}",
            first.body
        )
    });
    let later = metric(&second.body, "dns_shutdown_deadline_seconds").unwrap_or_else(|| {
        panic!(
            "the deadline gauge vanished mid-drain.\nmetrics:\n{}",
            second.body
        )
    });
    assert!(
        later < earlier - 0.5,
        "the deadline must count down: {earlier} then {later} a second later"
    );
}

/// Scenario: a shutdown that overruns the deadline exits 3 (ruling §13.21)
/// features/shutdown.feature:281
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wedged_shutdown_exits_three_within_the_watchdog_grace() {
    // Failure mode 5: a blocking reload hook that never returns. The config path
    // is replaced by a FIFO with no writer, so the hook's spawn_blocking read
    // blocks forever — the one failure a tokio-side deadline cannot cover,
    // because a timer cannot fire if nothing is polling it.
    let mut server = Server::start(&Spawn::with_admin().with_drain_env(0));
    server.wait_ready().await;
    let admin = server.admin();

    std::fs::remove_file(&server.config_path).expect("remove the config file");
    let mkfifo = Command::new("mkfifo")
        .arg(&server.config_path)
        .status()
        .expect("mkfifo runs");
    assert!(mkfifo.success(), "mkfifo failed");

    assert!(
        http(admin, "POST", "/reload").await.is_err(),
        "the wedge did not take: /reload answered instead of blocking on the FIFO, so \
         this test would not be exercising the watchdog at all.\nlog:\n{}",
        server.log()
    );

    let t0 = Instant::now();
    server.must_signal("TERM");

    // D = drain (0) + stop budget (5s); the watchdog thread fires at D + 2s.
    let budget = Duration::from_millis(7500);
    let (status, elapsed) = server.wait_exit(t0, budget).await.unwrap_or_else(|| {
        panic!(
            "a wedged blocking task left the process alive past the watchdog deadline \
             ({budget:?}). Only an OS thread can end this: a tokio timer cannot fire \
             if nothing is polling it.\nlog:\n{}",
            server.log()
        )
    });
    assert_eq!(
        status.code(),
        Some(3),
        "an overrun shutdown exits 3, distinct from clean (0) and startup failure (1), \
         so lastState.terminated.exitCode says what happened. It exited after \
         {elapsed:?}.\nlog:\n{}",
        server.log()
    );
    let log = server.log();
    assert!(
        line_with(&log, &["deadline"]).is_some(),
        "the overrun must be logged at ERROR, naming the phase it was stuck \
         in.\nlog:\n{log}"
    );
}

// ========================================================= REGRESSION GUARDS

/// Read a source file of the crate under test.
fn source(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {relative}: {e}"))
}

/// Scenario: the signal watcher is never handed the DNS token (ruling §13.22)
/// features/shutdown.feature:296
///
/// A structural guard, because the type-level form (`let _: fn() -> Signals =
/// shutdown::watch;`) cannot compile until the API exists, and a test file that
/// does not compile reports nothing about the other twenty-odd scenarios. Once
/// `Signals` lands, rust-dev should replace this body with that one-liner.
#[test]
fn the_signal_watcher_is_constructed_without_a_caller_supplied_token() {
    let shutdown = source("src/shutdown.rs");
    let signature = shutdown.split_once("pub fn watch(").map_or_else(
        || panic!("src/shutdown.rs no longer defines `pub fn watch`"),
        |(_, rest)| rest.split(')').next().unwrap_or_default().to_owned(),
    );
    assert!(
        !signature.contains("Token"),
        "shutdown::watch must not take a caller's CancellationToken. Being handed the \
         server's own token is the whole defect: SIGTERM then cancels the DNS accept \
         loops directly and no 503 can ever be served. Signature was \
         `watch({signature})`."
    );

    let main = source("src/main.rs");
    let call = main.split_once("shutdown::watch(").map_or_else(
        || panic!("src/main.rs no longer calls shutdown::watch"),
        |(_, rest)| rest.split(')').next().unwrap_or_default().to_owned(),
    );
    assert!(
        call.trim().is_empty(),
        "src/main.rs must call shutdown::watch() with no arguments; it passed \
         `{call}`, which is the defect at src/main.rs:381."
    );
}

/// Scenario: a fatal admin error does not cancel the DNS token (ruling §13.23)
/// features/shutdown.feature:306
///
/// Structural half. The behavioural half is the test below: from outside the
/// process there is no way to make an already-bound admin server fail, so this
/// pins the wiring that failure mode 3 depends on.
#[test]
fn a_fatal_admin_error_does_not_cancel_the_dns_token() {
    let main = source("src/main.rs");
    let (_, after) = main
        .split_once("admin::serve(")
        .unwrap_or_else(|| panic!("src/main.rs no longer spawns admin::serve"));
    let region: String = after.chars().take(400).collect();
    assert!(
        !region.contains("cancel("),
        "the admin task must route a fatal error through the shutdown machine \
         (Signals::abort), not cancel a token: today src/main.rs:403 kills the DNS \
         listeners instantly, with no drain at all, when the admin server \
         dies.\nregion:\n{region}"
    );
    assert!(
        main.contains("CancellationToken::new()"),
        "the admin server needs its own token. Sharing the server's token means \
         axum's graceful shutdown fires in the same instant as the DNS cancel, and \
         the 503 can never be served to anyone."
    );
}

/// Scenario: an admin listener that cannot bind is a startup failure
/// (ruling §13.23 and §6's exit codes; VEGA-044 lands with this change)
/// features/shutdown.feature:314
#[tokio::test]
async fn an_admin_listener_that_cannot_bind_is_a_startup_failure() {
    // Hold the port so the child's bind must fail.
    let squatter = TcpListener::bind(("127.0.0.1", 0)).expect("bind the squatter");
    let addr = squatter.local_addr().expect("local addr");

    let spawn = Spawn {
        admin: Admin::At(addr),
        ..Spawn::default()
    };
    let mut server = Server::start(&spawn);

    let (status, _) = server
        .wait_exit(Instant::now(), Duration::from_secs(10))
        .await
        .unwrap_or_else(|| {
            panic!(
                "a server that cannot bind its admin listener must not keep \
                 running.\nlog:\n{}",
                server.log()
            )
        });
    drop(squatter);

    assert_eq!(
        status.code(),
        Some(1),
        "a failed bind before any signal is exit 1. Today the admin task cancels the \
         DNS token instead and the process reports success, which hides the failure \
         from every supervisor.\nlog:\n{}",
        server.log()
    );
    assert!(
        server.log().contains("admin"),
        "the failure must name the admin listener.\nlog:\n{}",
        server.log()
    );
}
