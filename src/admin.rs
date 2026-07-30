//! The admin HTTP server: liveness, readiness, Prometheus metrics, and reload.
//!
//! The read-only endpoints are unauthenticated by design — bind the listener to a
//! private interface and let your orchestrator decide who may scrape it.
//! `/reload` mutates server state, so it is gated: with `--admin-token` set it
//! requires that bearer token, and without one it only accepts requests from
//! loopback.

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
};

use anyhow::{Context, Result};
use axum::{
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::metrics::Metrics;

/// What a successful reload changed. Returned to the caller so `vega
/// reload` can print something more useful than "ok".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReloadOutcome {
    /// Zone origin after the reload.
    pub origin: String,
    /// Number of records now loaded.
    pub records: usize,
}

/// A reload hook. Returns a description of the new state, or an error message
/// safe to hand back over HTTP.
///
/// Boxed as a closure so this module stays independent of the handler and zone
/// types it would otherwise have to know about.
pub type ReloadFn = Arc<dyn Fn() -> Result<ReloadOutcome, String> + Send + Sync>;

/// Shared state for the admin endpoints.
#[derive(Clone)]
pub struct AdminState {
    metrics: Arc<Metrics>,
    ready: Arc<AtomicBool>,
    reloads: Arc<AtomicU64>,
    reload: Option<ReloadFn>,
    token: Option<Arc<str>>,
}

impl std::fmt::Debug for AdminState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminState")
            .field("ready", &self.is_ready())
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
            ready: Arc::new(AtomicBool::new(false)),
            reloads: Arc::new(AtomicU64::new(0)),
            reload: None,
            token: None,
        }
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
    pub fn mark_ready(&self) {
        self.ready.store(true, Ordering::Release);
    }

    /// Flip `/readyz` back to 503, e.g. while draining during shutdown.
    pub fn mark_unready(&self) {
        self.ready.store(false, Ordering::Release);
    }

    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
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
            None => peer.ip().is_loopback(),
        }
    }
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
        .with_state(state)
}

/// Bind and serve the admin endpoints until `shutdown` is cancelled.
pub async fn serve(addr: SocketAddr, state: AdminState, shutdown: CancellationToken) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding admin listener on {addr}"))?;
    let local = listener
        .local_addr()
        .context("reading admin listener address")?;

    let reload = if state.reload.is_some() {
        " /reload"
    } else {
        ""
    };
    info!(%local, "admin endpoints listening (/healthz /readyz /metrics /version{reload})");
    if state.reload.is_some() && state.token.is_none() && !local.ip().is_loopback() {
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
async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

/// Readiness: the DNS listeners are bound and serving.
async fn readyz(State(state): State<AdminState>) -> impl IntoResponse {
    if state.is_ready() {
        (StatusCode::OK, "ready\n")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready\n")
    }
}

/// Prometheus exposition endpoint.
async fn metrics(State(state): State<AdminState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state.metrics.render_prometheus(),
    )
}

/// Build identity, for humans and for deploy scripts.
async fn version(State(state): State<AdminState>) -> impl IntoResponse {
    let body = serde_json::json!({
        "name": crate::NAME,
        "version": crate::VERSION,
        "ready": state.is_ready(),
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

    let Some(hook) = state.reload.clone() else {
        return json(
            StatusCode::NOT_IMPLEMENTED,
            serde_json::json!({
                "error": "reload is not available: the server was started without a config file",
            }),
        );
    };

    if !state.may_mutate(peer, &headers) {
        warn!(%peer, "rejected unauthorised reload");
        return json(
            StatusCode::FORBIDDEN,
            serde_json::json!({
                "error": "forbidden: set --admin-token, or call /reload from loopback",
            }),
        );
    }

    // The hook does file I/O and zone parsing. It is short, but it is blocking,
    // so keep it off the async worker.
    match tokio::task::spawn_blocking(move || hook()).await {
        Ok(Ok(outcome)) => {
            let count = state.reloads.fetch_add(1, Ordering::Relaxed) + 1;
            info!(
                origin = %outcome.origin,
                records = outcome.records,
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
                }),
            )
        }
        Ok(Err(error)) => {
            // The old zone is still serving; a bad edit does not take the server
            // down, it just fails to apply.
            warn!(%error, "reload rejected, keeping the previous zone");
            json(
                StatusCode::BAD_REQUEST,
                serde_json::json!({ "error": error, "status": "unchanged" }),
            )
        }
        Err(error) => json(
            StatusCode::INTERNAL_SERVER_ERROR,
            serde_json::json!({ "error": format!("reload task failed: {error}") }),
        ),
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

    #[tokio::test]
    async fn reload_from_loopback_succeeds_without_a_token() {
        let state = state().with_reload(ok_hook());
        let response = send(state, Method::POST, "/reload", "127.0.0.1:1", None).await;
        assert_eq!(response.status(), StatusCode::OK);

        let body = body_text(response).await;
        assert!(body.contains("\"records\":3"), "{body}");
        assert!(body.contains("example.com"), "{body}");
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

    #[tokio::test]
    async fn a_failing_reload_reports_the_error_and_keeps_serving() {
        let hook: ReloadFn = Arc::new(|| Err("invalid A record value \"nope\"".to_owned()));
        let state = state().with_reload(hook);

        let response = send(state, Method::POST, "/reload", "127.0.0.1:1", None).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = body_text(response).await;
        assert!(body.contains("invalid A record value"), "{body}");
        assert!(body.contains("unchanged"), "{body}");
    }

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
