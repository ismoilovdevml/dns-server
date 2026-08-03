//! The admin HTTP server: liveness, readiness, Prometheus metrics, and reload.
//!
//! The read-only endpoints are unauthenticated by design — bind the listener to a
//! private interface and let your orchestrator decide who may scrape it.
//! `/reload` mutates server state, so it is gated: with `--admin-token` set it
//! requires that bearer token, and without one it only accepts requests from
//! loopback.

use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use anyhow::{Context, Result};
use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{
    lifecycle::{Lifecycle, Phase},
    metrics::Metrics,
};

/// Header carrying the lifecycle phase on every admin response.
///
/// The status code is the contract and the body is for humans; this is for the
/// operator who has one `curl -i` and needs to know whether a 503 means "never
/// came up" or "going away".
const PHASE_HEADER: HeaderName = HeaderName::from_static("x-vega-phase");

/// What a successful reload changed. Returned to the caller so `vega
/// reload` can print something more useful than "ok".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReloadOutcome {
    /// Zone origin after the reload.
    pub origin: String,
    /// Number of records now loaded.
    pub records: usize,
    /// TOML key paths the file changed that a running process cannot apply.
    ///
    /// Reported rather than applied, and never empty of meaning: an operator must
    /// not be able to read a 200 and conclude that a restart-only edit took
    /// effect. Bounded by the fixed half of the VEGA-005 partition table, and
    /// never contains a secret's value — only its key path.
    pub ignored: Vec<&'static str>,
}

/// Why a reload was refused.
///
/// Stable and machine-readable: scripts, runbooks and (via VEGA-049) alert labels
/// key on these, never on the prose, which is free to improve. The set is closed
/// — `features/live-reload.feature` enumerates it, and adding a variant without a
/// scenario is a spec gap, not a detail.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ReloadErrorCode {
    /// The config file could not be read: deleted, unreadable, mid-rename.
    ConfigReadFailed,
    /// The config file is not valid TOML.
    ConfigParseFailed,
    /// The config parsed but was rejected: empty origin, zero TTL, …
    ConfigInvalid,
    /// The zone would not build from the new records.
    ZoneBuildFailed,
    /// The file resolves to a different zone origin. A restart, not a reload.
    OriginChanged,
    /// Another reload holds the lock. Retry; the winner completes normally.
    ReloadInProgress,
    /// The process is draining. The next instance reads the file at startup.
    ShuttingDown,
    /// The server was started without a config file, so there is nothing to
    /// re-read.
    NotConfigured,
    /// The caller is neither on loopback nor holding the admin token.
    Forbidden,
    /// The hook itself failed — in practice only a panic in a debug build.
    Internal,
}

impl ReloadErrorCode {
    /// The wire form. Exhaustive on purpose: a new variant fails to compile here
    /// and in the test that enumerates them, instead of reaching an operator as
    /// an unknown string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfigReadFailed => "config_read_failed",
            Self::ConfigParseFailed => "config_parse_failed",
            Self::ConfigInvalid => "config_invalid",
            Self::ZoneBuildFailed => "zone_build_failed",
            Self::OriginChanged => "origin_changed",
            Self::ReloadInProgress => "reload_in_progress",
            Self::ShuttingDown => "shutting_down",
            Self::NotConfigured => "not_configured",
            Self::Forbidden => "forbidden",
            Self::Internal => "internal",
        }
    }

    /// The HTTP status this code answers with.
    ///
    /// 400 means "your edit is broken, fix the file and retry"; 409 (RFC 9110
    /// §15.5.10) means "this cannot be applied by a reload, it needs a restart"
    /// or "retry, someone else is mid-reload". Different runbooks, so different
    /// statuses.
    fn status(self) -> StatusCode {
        match self {
            Self::ConfigReadFailed
            | Self::ConfigParseFailed
            | Self::ConfigInvalid
            | Self::ZoneBuildFailed => StatusCode::BAD_REQUEST,
            Self::OriginChanged | Self::ReloadInProgress => StatusCode::CONFLICT,
            Self::ShuttingDown => StatusCode::SERVICE_UNAVAILABLE,
            Self::NotConfigured => StatusCode::NOT_IMPLEMENTED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl std::fmt::Display for ReloadErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A refused reload: a stable code plus prose an operator can act on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReloadError {
    /// What kind of refusal this is. Automation reads this.
    pub code: ReloadErrorCode,
    /// Operator-facing prose, safe to return over HTTP. Never holds a secret.
    pub detail: String,
    /// The origin still being served. Populated only for
    /// [`ReloadErrorCode::OriginChanged`].
    pub running_origin: Option<String>,
    /// The origin the file asked for. Populated only for
    /// [`ReloadErrorCode::OriginChanged`].
    pub requested_origin: Option<String>,
}

impl ReloadError {
    /// A refusal with no origins attached.
    pub fn new(code: ReloadErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
            running_origin: None,
            requested_origin: None,
        }
    }

    /// Attach the two origins an `origin_changed` refusal is about.
    #[must_use]
    pub fn with_origins(
        mut self,
        running: impl Into<String>,
        requested: impl Into<String>,
    ) -> Self {
        self.running_origin = Some(running.into());
        self.requested_origin = Some(requested.into());
        self
    }
}

impl std::fmt::Display for ReloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for ReloadError {}

/// A reload hook. Returns a description of the new state, or a structured
/// refusal safe to hand back over HTTP.
///
/// Boxed as a closure so this module stays independent of the handler, config and
/// zone types it would otherwise have to know about: the admin surface is
/// transport, and holds no configuration or precedence knowledge of its own.
pub type ReloadFn = Arc<dyn Fn() -> Result<ReloadOutcome, ReloadError> + Send + Sync>;

/// Shared state for the admin endpoints.
#[derive(Clone)]
pub struct AdminState {
    metrics: Arc<Metrics>,
    /// The one published phase. Every endpoint answers from a single `Acquire`
    /// load of it, so two probes landing in the same instant cannot disagree
    /// about whether this process is going away.
    lifecycle: Arc<Lifecycle>,
    reloads: Arc<AtomicU64>,
    reload: Option<ReloadFn>,
    token: Option<Arc<str>>,
}

impl std::fmt::Debug for AdminState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminState")
            .field("phase", &self.lifecycle.phase())
            .field("reload_enabled", &self.reload.is_some())
            .field("token_configured", &self.token.is_some())
            .finish_non_exhaustive()
    }
}

impl AdminState {
    /// Create state that starts out *not* ready, with reload disabled.
    pub fn new(metrics: Arc<Metrics>) -> Self {
        Self {
            metrics,
            lifecycle: Arc::new(Lifecycle::new()),
            reloads: Arc::new(AtomicU64::new(0)),
            reload: None,
            token: None,
        }
    }

    /// Answer from the process-wide lifecycle instead of a private one.
    ///
    /// `serve` owns the phase because it owns the ordering — the admin endpoints
    /// only report it. Without this the shutdown sequence would be publishing
    /// transitions nothing could observe.
    #[must_use]
    pub fn with_lifecycle(mut self, lifecycle: Arc<Lifecycle>) -> Self {
        self.lifecycle = lifecycle;
        self
    }

    /// Enable `POST /reload`, backed by `hook`.
    #[must_use]
    pub fn with_reload(mut self, hook: ReloadFn) -> Self {
        self.reload = Some(hook);
        self
    }

    /// Require this bearer token on mutating endpoints, from any source address.
    #[must_use]
    pub fn with_token(mut self, token: Option<String>) -> Self {
        self.token = token.map(Arc::from);
        self
    }

    /// Flip `/readyz` to 200. Call this once the DNS sockets are bound.
    ///
    /// A thin wrapper over the phase, kept because "ready" is the word every
    /// caller and every probe uses. It cannot un-drain a process: the transition
    /// is monotonic, so a `Serving` arriving after a signal is refused.
    pub fn mark_ready(&self) {
        self.lifecycle.enter(Phase::Serving);
    }

    /// Flip `/readyz` back to 503 by entering the draining phase.
    pub fn mark_unready(&self) {
        self.lifecycle.enter(Phase::Draining);
    }

    /// Whether a caller from `peer` presenting `headers` may mutate state.
    fn may_mutate(&self, peer: SocketAddr, headers: &HeaderMap) -> bool {
        match &self.token {
            Some(expected) => bearer(headers).is_some_and(|given| {
                // Length check first so the comparison below is only ever run on
                // equal-length inputs.
                given.len() == expected.len() && constant_time_eq(given, expected)
            }),
            // No token configured: only trust the local machine.
            None => is_local(peer.ip()),
        }
    }
}

/// Whether `ip` is this machine, with IPv4-mapped IPv6 folded to IPv4 first.
///
/// An IPv4 client reaching a `[::]`-bound socket arrives as `::ffff:127.0.0.1`
/// (RFC 4291 §2.5.5.2), and `is_loopback` is false for that form. So `/reload`
/// answered 403 to `vega reload` running on the same host — on exactly the
/// dual-stack `admin_listen` the Kubernetes manifest encourages — with a
/// permission error and nothing to explain it (VEGA-016).
///
/// `to_ipv4_mapped` and not `to_ipv4`, the same choice and the same reasoning as
/// `ratelimit::canonical_key` (VEGA-003). `to_ipv4` also matches the
/// IPv4-*compatible* form deprecated by RFC 4291 §2.5.5.1, and it is wrong in
/// both directions here: it would fold `::127.0.0.1` — an ordinary IPv6 address
/// an off-host caller can present — into loopback and hand it `/reload`, and it
/// maps `::1` to `0.0.0.1`, which is not loopback, so it would lock out the one
/// caller the check exists to admit.
fn is_local(ip: IpAddr) -> bool {
    let canonical = match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
    };
    canonical.is_loopback()
}

/// Extract a bearer token from an `Authorization` header.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
}

/// Compare without leaking length-prefix information through timing.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Build the admin router. Exposed so tests can drive it without a socket.
pub fn router(state: AdminState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .route("/version", get(version))
        .route("/reload", post(reload))
        // Applied to the fallback as well, so even a 404 carries the phase.
        .layer(middleware::from_fn_with_state(state.clone(), phase_header))
        .with_state(state)
}

/// Stamp `X-Vega-Phase` on every response.
///
/// Read before the handler runs, so the header describes the phase the response
/// was computed in rather than one it may have advanced to while a body was
/// being rendered.
async fn phase_header(State(state): State<AdminState>, request: Request, next: Next) -> Response {
    let phase = state.lifecycle.phase();
    let mut response = next.run(request).await;
    // Infallible for the five lowercase-ASCII phase names, but done fallibly
    // anyway: this runs on a network-reachable path, and `panic = "abort"` makes
    // one panic here a full outage.
    if let Ok(value) = HeaderValue::from_str(phase.as_str()) {
        response.headers_mut().insert(PHASE_HEADER, value);
    }
    response
}

/// Bind the admin listener.
///
/// Separate from [`serve`] so `serve` in `main.rs` can fail *at startup* when
/// the port is taken (VEGA-044). Binding inside the spawned task instead meant
/// the process reported itself ready, then lost its admin endpoint moments
/// later, with the failure visible to nothing.
pub async fn bind(addr: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding admin listener on {addr}"))
}

/// Serve the admin endpoints on `listener` until `shutdown` is cancelled.
///
/// `shutdown` is the admin server's own token, never the DNS server's: they are
/// cancelled at opposite ends of the shutdown sequence so that a probe still
/// gets an answer after the DNS listeners have gone.
pub async fn serve(
    listener: TcpListener,
    state: AdminState,
    shutdown: CancellationToken,
) -> Result<()> {
    let local = listener
        .local_addr()
        .context("reading admin listener address")?;

    let reload = if state.reload.is_some() {
        " /reload"
    } else {
        ""
    };
    info!(%local, "admin endpoints listening (/healthz /readyz /metrics /version{reload})");
    // The same fold as the gate itself, so the warning cannot claim callers will
    // be rejected on a listener that in fact accepts them.
    if state.reload.is_some() && state.token.is_none() && !is_local(local.ip()) {
        warn!(
            %local,
            "/reload is reachable off-host but no --admin-token is set; \
             non-loopback callers will be rejected"
        );
    }

    // ConnectInfo is what lets /reload see the peer address.
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move { shutdown.cancelled().await })
    .await
    .context("admin http server failed")
}

/// Liveness: the process is up and the async runtime is scheduling tasks.
///
/// **200 in every phase, including the whole drain, and the body stays exactly
/// `ok\n`.** Liveness answers "is this process alive"; a draining process is
/// alive by definition. Returning 503 here is the mistake that gets a container
/// restarted mid-drain on any `SIGTERM` that does not accompany a delete, and
/// Docker's `HEALTHCHECK` has the same shape. The phase goes in the header, in
/// `/version` and in a metric — not in this body, which operators grep.
async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

/// Readiness: whether to send this process traffic. The only traffic gate.
///
/// The 503 body distinguishes "never came up" from "going away", which is the
/// first question an operator asks at 3am.
async fn readyz(State(state): State<AdminState>) -> impl IntoResponse {
    match state.lifecycle.phase() {
        Phase::Serving => (StatusCode::OK, "ready\n"),
        Phase::Starting => (StatusCode::SERVICE_UNAVAILABLE, "not ready\n"),
        Phase::Draining | Phase::Stopping | Phase::Closing => {
            (StatusCode::SERVICE_UNAVAILABLE, "draining\n")
        }
    }
}

/// Prometheus exposition endpoint.
///
/// 200 throughout, including `Closing`: a scrape that catches the drain is the
/// only record we will ever have of it.
async fn metrics(State(state): State<AdminState>) -> impl IntoResponse {
    let mut body = state.metrics.render_prometheus();
    state.lifecycle.render_prometheus(&mut body);
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

/// Build identity, for humans and for deploy scripts.
async fn version(State(state): State<AdminState>) -> impl IntoResponse {
    let phase = state.lifecycle.phase();
    let body = serde_json::json!({
        "name": crate::NAME,
        "version": crate::VERSION,
        "phase": phase.as_str(),
        "ready": phase == Phase::Serving,
        "uptime_seconds": state.metrics.uptime().as_secs(),
        "reloads": state.reloads.load(Ordering::Relaxed),
    });
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        format!("{body}\n"),
    )
}

/// Re-read the config file and swap in the new zone.
async fn reload(
    State(state): State<AdminState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let json = |status: StatusCode, body: serde_json::Value| {
        (
            status,
            [(header::CONTENT_TYPE, "application/json")],
            format!("{body}\n"),
        )
    };

    let refused = |error: &ReloadError| {
        let mut body = serde_json::json!({
            "status": "unchanged",
            "code": error.code.as_str(),
            "error": error.detail,
        });
        // Present only where they mean something, so a consumer never has to
        // decide what a null origin would be saying.
        if let Some(map) = body.as_object_mut() {
            if let Some(running) = &error.running_origin {
                map.insert("running_origin".to_owned(), running.as_str().into());
            }
            if let Some(requested) = &error.requested_origin {
                map.insert("requested_origin".to_owned(), requested.as_str().into());
            }
        }
        json(error.code.status(), body)
    };

    let Some(hook) = state.reload.clone() else {
        return refused(&ReloadError::new(
            ReloadErrorCode::NotConfigured,
            "reload is not available: the server was started without a config file",
        ));
    };

    // The drain gate comes before the hook is ever reached, and deliberately
    // before the authorisation check: swapping the zone in a process that is
    // seconds from exiting cannot help anything, and this is the exact window in
    // which a blocking reload can wedge the drain (ruling §9.1). The counter not
    // moving is what proves the hook was never invoked.
    if state.lifecycle.is_draining() {
        return refused(&ReloadError::new(
            ReloadErrorCode::ShuttingDown,
            "draining: the process is shutting down; the next instance reads the file at startup",
        ));
    }

    if !state.may_mutate(peer, &headers) {
        warn!(%peer, "rejected unauthorised reload");
        return refused(&ReloadError::new(
            ReloadErrorCode::Forbidden,
            "forbidden: set --admin-token, or call /reload from loopback",
        ));
    }

    // The hook does file I/O and zone parsing. It is short, but it is blocking,
    // so keep it off the async worker.
    match tokio::task::spawn_blocking(move || hook()).await {
        Ok(Ok(outcome)) => {
            // Only a success moves the counter: VEGA-049 alerts on this series,
            // and a counter that also moves on failure makes "reloads are
            // succeeding" unfalsifiable.
            let count = state.reloads.fetch_add(1, Ordering::Relaxed) + 1;
            info!(
                origin = %outcome.origin,
                records = outcome.records,
                ignored = outcome.ignored.len(),
                reloads = count,
                "configuration reloaded"
            );
            json(
                StatusCode::OK,
                serde_json::json!({
                    "status": "reloaded",
                    "origin": outcome.origin,
                    "records": outcome.records,
                    "reloads": count,
                    "ignored": outcome.ignored,
                }),
            )
        }
        Ok(Err(error)) => {
            // The old zone is still serving; a bad edit does not take the server
            // down, it just fails to apply.
            warn!(code = error.code.as_str(), detail = %error.detail, "reload rejected, keeping the previous zone");
            refused(&error)
        }
        // Only reachable in a debug build: the release profile sets
        // `panic = "abort"`, so a panicking hook takes the process with it.
        Err(error) => refused(&ReloadError::new(
            ReloadErrorCode::Internal,
            format!("reload task failed: {error}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Method, Request, Response},
    };
    use tower::ServiceExt as _;

    fn state() -> AdminState {
        AdminState::new(Arc::new(Metrics::new()))
    }

    fn ok_hook() -> ReloadFn {
        Arc::new(|| {
            Ok(ReloadOutcome {
                origin: "example.com".to_owned(),
                records: 3,
                ignored: Vec::new(),
            })
        })
    }

    async fn send(
        state: AdminState,
        method: Method,
        path: &str,
        peer: &str,
        token: Option<&str>,
    ) -> Response<Body> {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let mut request = builder.body(Body::empty()).expect("request builds");

        // axum reads the peer address from this extension, which is what
        // into_make_service_with_connect_info inserts in production.
        let peer: SocketAddr = peer.parse().expect("peer address parses");
        request.extensions_mut().insert(ConnectInfo(peer));

        router(state)
            .oneshot(request)
            .await
            .expect("router responds")
    }

    async fn get_path(state: AdminState, path: &str) -> Response<Body> {
        send(state, Method::GET, path, "127.0.0.1:40000", None).await
    }

    async fn body_text(response: Response<Body>) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body reads");
        String::from_utf8(bytes.to_vec()).expect("body is utf-8")
    }

    #[tokio::test]
    async fn healthz_is_always_ok() {
        let response = get_path(state(), "/healthz").await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn readyz_starts_unavailable_and_flips_when_marked() {
        let state = state();

        let response = get_path(state.clone(), "/readyz").await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        state.mark_ready();
        let response = get_path(state.clone(), "/readyz").await;
        assert_eq!(response.status(), StatusCode::OK);

        state.mark_unready();
        let response = get_path(state, "/readyz").await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn metrics_renders_prometheus_text() {
        let metrics = Arc::new(Metrics::new());
        metrics.query(crate::metrics::Transport::Udp);
        let state = AdminState::new(metrics);

        let response = get_path(state, "/metrics").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain; version=0.0.4; charset=utf-8")
        );
        assert!(body_text(response).await.contains("dns_queries_total 1"));
    }

    #[tokio::test]
    async fn version_reports_the_build_and_readiness() {
        let state = state();
        state.mark_ready();
        let response = get_path(state, "/version").await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_text(response).await;
        assert!(body.contains(crate::VERSION), "{body}");
        assert!(body.contains("\"ready\":true"), "{body}");
    }

    #[tokio::test]
    async fn unknown_paths_are_not_found() {
        let response = get_path(state(), "/nope").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn reload_is_not_implemented_without_a_hook() {
        let response = send(state(), Method::POST, "/reload", "127.0.0.1:1", None).await;
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    /// Scenario: A successful reload reports the new origin and record count
    /// features/live-reload.feature:91
    #[tokio::test]
    async fn reload_from_loopback_succeeds_without_a_token() {
        let state = state().with_reload(ok_hook());
        let response = send(state, Method::POST, "/reload", "127.0.0.1:1", None).await;
        assert_eq!(response.status(), StatusCode::OK);

        let body = body_text(response).await;
        assert!(body.contains("\"records\":3"), "{body}");
        assert!(body.contains("example.com"), "{body}");
    }

    /// Scenario: An IPv4 client reloads through a dual-stack admin listener
    /// features/admin-api.feature:238
    ///
    /// VEGA-016. On `admin_listen = "[::]:9100"` an IPv4 peer is delivered as
    /// `::ffff:127.0.0.1`, and the bare `is_loopback` this used to call is false
    /// for that: `vega reload` on the same host got a 403.
    #[tokio::test]
    async fn an_ipv4_mapped_loopback_peer_may_reload_on_a_dual_stack_listener() {
        let state = state().with_reload(ok_hook());
        let response = send(
            state,
            Method::POST,
            "/reload",
            "[::ffff:127.0.0.1]:40000",
            None,
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "an IPv4 client on a [::] listener is on loopback and must be let in"
        );
    }

    /// Both native stacks still behave, so the fold cannot be mistaken for
    /// "trust anything that mentions 127".
    #[tokio::test]
    async fn native_v6_loopback_is_allowed_and_a_mapped_public_address_is_not() {
        let state = state().with_reload(ok_hook());
        let allowed = send(state.clone(), Method::POST, "/reload", "[::1]:40000", None).await;
        assert_eq!(allowed.status(), StatusCode::OK);

        let refused = send(
            state,
            Method::POST,
            "/reload",
            "[::ffff:203.0.113.7]:40000",
            None,
        )
        .await;
        assert_eq!(
            refused.status(),
            StatusCode::FORBIDDEN,
            "a mapped *public* address is still off-host"
        );
    }

    /// The reason the fold is `to_ipv4_mapped` and not `to_ipv4`: the deprecated
    /// IPv4-compatible form (RFC 4291 §2.5.5.1) is an ordinary IPv6 address, and
    /// `to_ipv4` would hand `/reload` to whoever presents it.
    #[tokio::test]
    async fn the_deprecated_ipv4_compatible_form_is_not_treated_as_loopback() {
        let state = state().with_reload(ok_hook());
        let response = send(state, Method::POST, "/reload", "[::127.0.0.1]:40000", None).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{response:?}");
    }

    #[tokio::test]
    async fn reload_from_off_host_is_forbidden_without_a_token() {
        let state = state().with_reload(ok_hook());
        let response = send(state, Method::POST, "/reload", "203.0.113.7:1", None).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_configured_token_is_required_even_from_loopback() {
        let state = state()
            .with_reload(ok_hook())
            .with_token(Some("s3cret".to_owned()));

        let missing = send(state.clone(), Method::POST, "/reload", "127.0.0.1:1", None).await;
        assert_eq!(missing.status(), StatusCode::FORBIDDEN);

        let wrong = send(
            state.clone(),
            Method::POST,
            "/reload",
            "127.0.0.1:1",
            Some("wrong!"),
        )
        .await;
        assert_eq!(wrong.status(), StatusCode::FORBIDDEN);

        let right = send(
            state,
            Method::POST,
            "/reload",
            "127.0.0.1:1",
            Some("s3cret"),
        )
        .await;
        assert_eq!(right.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_correct_token_works_from_anywhere() {
        let state = state()
            .with_reload(ok_hook())
            .with_token(Some("s3cret".to_owned()));
        let response = send(
            state,
            Method::POST,
            "/reload",
            "203.0.113.7:1",
            Some("s3cret"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Scenario: A reload that fails to build a zone is reported as a bad request
    /// features/live-reload.feature:328
    ///
    /// Scenario: A failed reload says the configuration is unchanged
    /// features/live-reload.feature:334
    #[tokio::test]
    async fn a_failing_reload_reports_the_error_and_keeps_serving() {
        let hook: ReloadFn = Arc::new(|| {
            Err(ReloadError::new(
                ReloadErrorCode::ZoneBuildFailed,
                "invalid A record value \"nope\"",
            ))
        });
        let state = state().with_reload(hook);

        let response = send(state, Method::POST, "/reload", "127.0.0.1:1", None).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = body_text(response).await;
        assert!(body.contains("invalid A record value"), "{body}");
        assert!(body.contains("unchanged"), "{body}");
    }

    /// Scenario: Each successful reload increments the reload counter
    /// features/live-reload.feature:99
    #[tokio::test]
    async fn reload_counter_increments() {
        let state = state().with_reload(ok_hook());

        let first = send(state.clone(), Method::POST, "/reload", "127.0.0.1:1", None).await;
        assert!(body_text(first).await.contains("\"reloads\":1"));

        let second = send(state.clone(), Method::POST, "/reload", "127.0.0.1:1", None).await;
        assert!(body_text(second).await.contains("\"reloads\":2"));

        // And /version reports the same count.
        let version = get_path(state, "/version").await;
        assert!(body_text(version).await.contains("\"reloads\":2"));
    }

    #[tokio::test]
    async fn reload_rejects_a_get() {
        let state = state().with_reload(ok_hook());
        let response = send(state, Method::GET, "/reload", "127.0.0.1:1", None).await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    // -----------------------------------------------------------------------
    // VEGA-005 acceptance. Scenarios in features/live-reload.feature.
    // -----------------------------------------------------------------------

    /// Scenario: Reload is unavailable when the server was started without a config file
    /// features/live-reload.feature:472
    #[tokio::test]
    async fn reload_without_a_hook_names_the_not_configured_code() {
        let response = send(state(), Method::POST, "/reload", "127.0.0.1:1", None).await;
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);

        let body = body_text(response).await;
        assert!(
            body.contains("\"code\":\"not_configured\""),
            "an automation must key on a stable code, never on the prose: {body}"
        );
    }

    /// Scenario: Every reload error body carries a code from the documented set
    /// features/live-reload.feature:420
    #[tokio::test]
    async fn an_unauthorised_reload_names_the_forbidden_code() {
        let state = state().with_reload(ok_hook());
        let response = send(state, Method::POST, "/reload", "203.0.113.7:1", None).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let body = body_text(response).await;
        assert!(body.contains("\"code\":\"forbidden\""), "{body}");
    }

    /// Scenario: A failed reload does not increment the reload counter
    /// features/live-reload.feature:341
    #[tokio::test]
    async fn a_failing_reload_does_not_increment_the_reload_counter() {
        // VEGA-049 is about to alert on this series. A counter that moves on
        // failure makes "reloads are succeeding" unfalsifiable.
        let hook: ReloadFn =
            Arc::new(|| Err(ReloadError::new(ReloadErrorCode::ZoneBuildFailed, "nope")));
        let state = state().with_reload(hook);

        let failed = send(state.clone(), Method::POST, "/reload", "127.0.0.1:1", None).await;
        assert_eq!(failed.status(), StatusCode::BAD_REQUEST);

        let version = get_path(state, "/version").await;
        let body = body_text(version).await;
        assert!(body.contains("\"reloads\":0"), "{body}");
    }

    /// Scenario: A reload hook that panics is reported as a server error
    /// features/live-reload.feature:480
    ///
    /// The release profile sets `panic = "abort"`, so this arm is reachable in a
    /// debug build only — which is the point of pinning it here rather than
    /// end to end.
    #[tokio::test]
    async fn a_panicking_hook_is_reported_as_500_and_a_later_reload_still_succeeds() {
        // Debug builds only: the release profile sets `panic = "abort"`, so this
        // arm is unreachable there. It is still worth pinning, because the
        // recovery path (an un-poisoned reload mutex) is what keeps reload
        // working for the rest of the process's life.
        let calls = Arc::new(AtomicU64::new(0));
        let hook: ReloadFn = {
            let calls = Arc::clone(&calls);
            Arc::new(move || {
                assert!(
                    calls.fetch_add(1, Ordering::Relaxed) > 0,
                    "the first reload panics"
                );
                Ok(ReloadOutcome {
                    origin: "example.com".to_owned(),
                    records: 3,
                    ignored: Vec::new(),
                })
            })
        };
        let state = state().with_reload(hook);

        let panicked = send(state.clone(), Method::POST, "/reload", "127.0.0.1:1", None).await;
        assert_eq!(panicked.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let recovered = send(state.clone(), Method::POST, "/reload", "127.0.0.1:1", None).await;
        assert_eq!(
            recovered.status(),
            StatusCode::OK,
            "a panic must not brick reload for the rest of the process's life"
        );
        let body = body_text(recovered).await;
        assert!(body.contains("\"reloads\":1"), "{body}");
    }

    /// Scenario: Every reload error body carries a code from the documented set
    /// features/live-reload.feature:420
    #[test]
    fn every_reload_error_code_has_a_wire_form_and_a_status() {
        // Enumerated by `match`, not by a list: a variant added without a wire
        // form, a status and a scenario fails to compile rather than reaching an
        // operator as an unknown string. The expected strings are spelled out
        // here so a rename is a deliberate, visible API break.
        let all = [
            ReloadErrorCode::ConfigReadFailed,
            ReloadErrorCode::ConfigParseFailed,
            ReloadErrorCode::ConfigInvalid,
            ReloadErrorCode::ZoneBuildFailed,
            ReloadErrorCode::OriginChanged,
            ReloadErrorCode::ReloadInProgress,
            ReloadErrorCode::ShuttingDown,
            ReloadErrorCode::NotConfigured,
            ReloadErrorCode::Forbidden,
            ReloadErrorCode::Internal,
        ];

        for code in all {
            let (wire, status) = match code {
                ReloadErrorCode::ConfigReadFailed => ("config_read_failed", 400),
                ReloadErrorCode::ConfigParseFailed => ("config_parse_failed", 400),
                ReloadErrorCode::ConfigInvalid => ("config_invalid", 400),
                ReloadErrorCode::ZoneBuildFailed => ("zone_build_failed", 400),
                ReloadErrorCode::OriginChanged => ("origin_changed", 409),
                ReloadErrorCode::ReloadInProgress => ("reload_in_progress", 409),
                ReloadErrorCode::ShuttingDown => ("shutting_down", 503),
                ReloadErrorCode::NotConfigured => ("not_configured", 501),
                ReloadErrorCode::Forbidden => ("forbidden", 403),
                ReloadErrorCode::Internal => ("internal", 500),
            };
            assert_eq!(code.as_str(), wire);
            assert_eq!(code.to_string(), wire);
            assert_eq!(code.status().as_u16(), status, "{wire}");
        }
    }

    /// Scenario: A reload that would change the origin is refused
    /// features/live-reload.feature:177
    #[tokio::test]
    async fn an_origin_change_answers_409_with_both_origins() {
        let hook: ReloadFn = Arc::new(|| {
            Err(
                ReloadError::new(ReloadErrorCode::OriginChanged, "refusing to reload")
                    .with_origins("example.com", "example.net"),
            )
        });
        let state = state().with_reload(hook);

        let response = send(state, Method::POST, "/reload", "127.0.0.1:1", None).await;
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let body = body_text(response).await;
        assert!(body.contains("\"code\":\"origin_changed\""), "{body}");
        assert!(
            body.contains("\"running_origin\":\"example.com\""),
            "{body}"
        );
        assert!(
            body.contains("\"requested_origin\":\"example.net\""),
            "{body}"
        );
    }

    /// Scenario: A reload with nothing drifted reports an empty ignored array
    /// features/live-reload.feature:305
    #[tokio::test]
    async fn the_ignored_array_is_always_present_and_carries_the_key_paths() {
        let empty = state().with_reload(ok_hook());
        let response = send(empty, Method::POST, "/reload", "127.0.0.1:1", None).await;
        let body = body_text(response).await;
        assert!(body.contains("\"ignored\":[]"), "{body}");

        let hook: ReloadFn = Arc::new(|| {
            Ok(ReloadOutcome {
                origin: "example.com".to_owned(),
                records: 3,
                ignored: vec!["server.udp", "server.rate_limit.qps"],
            })
        });
        let drifted = state().with_reload(hook);
        let response = send(drifted, Method::POST, "/reload", "127.0.0.1:1", None).await;
        let body = body_text(response).await;
        assert!(
            body.contains("\"ignored\":[\"server.udp\",\"server.rate_limit.qps\"]"),
            "{body}"
        );
    }

    /// A refusal that names no origin must not invent one.
    #[tokio::test]
    async fn a_refusal_without_origins_omits_those_fields_entirely() {
        let hook: ReloadFn =
            Arc::new(|| Err(ReloadError::new(ReloadErrorCode::ConfigReadFailed, "gone")));
        let state = state().with_reload(hook);

        let response = send(state, Method::POST, "/reload", "127.0.0.1:1", None).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = body_text(response).await;
        assert!(!body.contains("running_origin"), "{body}");
        assert!(!body.contains("requested_origin"), "{body}");
    }

    // -----------------------------------------------------------------------
    // VEGA-046 acceptance. Scenarios in features/shutdown.feature; the status
    // table is §4.2 of the ruling.
    // -----------------------------------------------------------------------

    /// A state sharing `lifecycle`, as `serve` wires it in production.
    fn state_in(lifecycle: &Arc<Lifecycle>) -> AdminState {
        AdminState::new(Arc::new(Metrics::new())).with_lifecycle(Arc::clone(lifecycle))
    }

    /// Scenario: healthz stays 200 for the whole drain
    /// features/shutdown.feature:61
    #[tokio::test]
    async fn healthz_is_200_ok_in_every_phase_including_closing() {
        // The mutation this kills: `/healthz` reporting 503 "for symmetry" with
        // `/readyz` during the drain. That is what gets the container restarted
        // mid-drain, turning a clean drain into a hard kill.
        for phase in [
            Phase::Starting,
            Phase::Serving,
            Phase::Draining,
            Phase::Stopping,
            Phase::Closing,
        ] {
            let lifecycle = Arc::new(Lifecycle::new());
            lifecycle.enter(phase);
            let response = get_path(state_in(&lifecycle), "/healthz").await;
            assert_eq!(response.status(), StatusCode::OK, "{phase}");
            assert_eq!(body_text(response).await, "ok\n", "{phase}");
        }
    }

    /// Scenario: readyz reports 503 while DNS is still answering
    /// features/shutdown.feature:35
    #[tokio::test]
    async fn readyz_distinguishes_never_came_up_from_going_away() {
        for (phase, status, body) in [
            (
                Phase::Starting,
                StatusCode::SERVICE_UNAVAILABLE,
                "not ready\n",
            ),
            (Phase::Serving, StatusCode::OK, "ready\n"),
            (
                Phase::Draining,
                StatusCode::SERVICE_UNAVAILABLE,
                "draining\n",
            ),
            (
                Phase::Stopping,
                StatusCode::SERVICE_UNAVAILABLE,
                "draining\n",
            ),
            (
                Phase::Closing,
                StatusCode::SERVICE_UNAVAILABLE,
                "draining\n",
            ),
        ] {
            let lifecycle = Arc::new(Lifecycle::new());
            lifecycle.enter(phase);
            let response = get_path(state_in(&lifecycle), "/readyz").await;
            assert_eq!(response.status(), status, "{phase}");
            assert_eq!(body_text(response).await, body, "{phase}");
        }
    }

    /// Scenario: The draining phase is observable
    /// features/shutdown.feature:70
    #[tokio::test]
    async fn every_response_carries_the_phase_header_including_a_404() {
        let lifecycle = Arc::new(Lifecycle::new());
        lifecycle.enter(Phase::Draining);

        for path in ["/healthz", "/readyz", "/metrics", "/version", "/nope"] {
            let response = get_path(state_in(&lifecycle), path).await;
            assert_eq!(
                response
                    .headers()
                    .get("x-vega-phase")
                    .and_then(|value| value.to_str().ok()),
                Some("draining"),
                "{path} answered without the phase header"
            );
        }
    }

    /// Scenario: The draining phase is observable
    /// features/shutdown.feature:70
    #[tokio::test]
    async fn metrics_and_version_report_the_phase() {
        let lifecycle = Arc::new(Lifecycle::new());
        let state = state_in(&lifecycle);
        lifecycle.enter(Phase::Serving);

        let body = body_text(get_path(state.clone(), "/metrics").await).await;
        assert!(body.contains("dns_shutdown_phase 1"), "{body}");
        assert!(
            !body.contains("dns_shutdown_deadline_seconds "),
            "the deadline gauge must not appear before a signal arms it: {body}"
        );

        lifecycle.enter(Phase::Stopping);
        let body = body_text(get_path(state.clone(), "/metrics").await).await;
        assert!(body.contains("dns_shutdown_phase 3"), "{body}");

        let body = body_text(get_path(state, "/version").await).await;
        assert!(body.contains("\"phase\":\"stopping\""), "{body}");
        assert!(body.contains("\"ready\":false"), "{body}");
    }

    /// Scenario: A reload during the drain is refused and the hook is never invoked
    /// features/shutdown.feature:214
    #[tokio::test]
    async fn a_reload_once_draining_is_refused_and_never_reaches_the_hook() {
        let calls = Arc::new(AtomicU64::new(0));
        let hook: ReloadFn = {
            let calls = Arc::clone(&calls);
            Arc::new(move || {
                calls.fetch_add(1, Ordering::Relaxed);
                Ok(ReloadOutcome {
                    origin: "example.com".to_owned(),
                    records: 3,
                    ignored: Vec::new(),
                })
            })
        };
        let lifecycle = Arc::new(Lifecycle::new());
        let state = state_in(&lifecycle).with_reload(hook);
        lifecycle.enter(Phase::Serving);

        let ok = send(state.clone(), Method::POST, "/reload", "127.0.0.1:1", None).await;
        assert_eq!(ok.status(), StatusCode::OK);

        lifecycle.enter(Phase::Draining);
        let refused = send(state.clone(), Method::POST, "/reload", "127.0.0.1:1", None).await;
        assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = body_text(refused).await;
        assert!(body.contains("\"code\":\"shutting_down\""), "{body}");
        assert!(body.contains("draining"), "{body}");
        assert!(body.contains("unchanged"), "{body}");

        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "the hook ran during the drain; the counter not moving is the only \
             thing that proves it did not"
        );
        let version = body_text(get_path(state, "/version").await).await;
        assert!(version.contains("\"reloads\":1"), "{version}");
    }

    /// The gate is the phase, not the caller: an authorised operator cannot
    /// reload a process that is going away either.
    #[tokio::test]
    async fn even_an_authorised_reload_is_refused_once_draining() {
        let lifecycle = Arc::new(Lifecycle::new());
        let state = state_in(&lifecycle)
            .with_reload(ok_hook())
            .with_token(Some("s3cret".to_owned()));
        lifecycle.enter(Phase::Stopping);

        let response = send(
            state,
            Method::POST,
            "/reload",
            "127.0.0.1:1",
            Some("s3cret"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn marking_ready_after_the_drain_has_started_cannot_re_advertise_us() {
        // A slow startup racing a fast SIGTERM. The monotonic phase is what makes
        // this impossible; without it `/readyz` would flip back to 200 and a load
        // balancer would send traffic to a process that is closing its sockets.
        let lifecycle = Arc::new(Lifecycle::new());
        let state = state_in(&lifecycle);
        lifecycle.enter(Phase::Draining);

        state.mark_ready();
        let response = get_path(state, "/readyz").await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(lifecycle.phase(), Phase::Draining);
    }

    #[test]
    fn bearer_parsing_handles_the_usual_shapes() {
        let mut headers = HeaderMap::new();
        assert_eq!(bearer(&headers), None);

        headers.insert(header::AUTHORIZATION, "Bearer abc".parse().unwrap());
        assert_eq!(bearer(&headers), Some("abc"));

        headers.insert(header::AUTHORIZATION, "Basic abc".parse().unwrap());
        assert_eq!(bearer(&headers), None);
    }

    #[test]
    fn constant_time_eq_matches_normal_equality() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
        assert!(constant_time_eq("", ""));
    }
}
