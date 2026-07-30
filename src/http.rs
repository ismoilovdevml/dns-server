//! A four-method HTTP/1.0 client for talking to our own admin endpoints.
//!
//! The CLI needs to GET `/metrics` and POST `/reload` against a socket it already
//! knows the address of. That does not justify a TLS stack, connection pooling,
//! or redirect handling, so this speaks the minimum: one request, one response,
//! connection closed.

use std::{net::SocketAddr, time::Duration};

use anyhow::{Context, Result};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
};

/// Requests that outlive this are treated as failures.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Cap on the response we will buffer. `/metrics` is a few kilobytes.
const MAX_BODY: usize = 1 << 20;

/// A parsed response.
#[derive(Clone, Debug)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Response body, as text.
    pub body: String,
}

impl Response {
    /// True for 2xx.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// `GET path`.
pub async fn get(addr: SocketAddr, path: &str, token: Option<&str>) -> Result<Response> {
    request(addr, "GET", path, token, DEFAULT_TIMEOUT).await
}

/// `POST path` with no body.
pub async fn post(addr: SocketAddr, path: &str, token: Option<&str>) -> Result<Response> {
    request(addr, "POST", path, token, DEFAULT_TIMEOUT).await
}

/// Send one request and read the whole response.
pub async fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
    timeout: Duration,
) -> Result<Response> {
    tokio::time::timeout(timeout, request_inner(addr, method, path, token))
        .await
        .map_err(|_| anyhow::anyhow!("{method} {path} to {addr} timed out after {timeout:?}"))?
}

async fn request_inner(
    addr: SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
) -> Result<Response> {
    let mut stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("connecting to {addr}"))?;

    let mut head = format!(
        "{method} {path} HTTP/1.0\r\nHost: {addr}\r\nUser-Agent: {}/{}\r\n",
        crate::NAME,
        crate::VERSION
    );
    if let Some(token) = token {
        use std::fmt::Write as _;
        let _ = write!(head, "Authorization: Bearer {token}\r\n");
    }
    // HTTP/1.0 with no keep-alive: the server closes, so read-to-EOF is enough.
    head.push_str("Content-Length: 0\r\nConnection: close\r\n\r\n");

    stream
        .write_all(head.as_bytes())
        .await
        .with_context(|| format!("sending {method} {path}"))?;
    stream.flush().await.context("flushing the request")?;

    let mut raw = Vec::with_capacity(4096);
    stream
        .take(MAX_BODY as u64)
        .read_to_end(&mut raw)
        .await
        .with_context(|| format!("reading the response to {method} {path}"))?;

    parse(&raw).with_context(|| format!("parsing the response to {method} {path}"))
}

/// Split a raw response into a status code and a body.
fn parse(raw: &[u8]) -> Result<Response> {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .or_else(|| text.split_once("\n\n"))
        .unwrap_or((text.as_ref(), ""));

    let status_line = head.lines().next().context("response had no status line")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .with_context(|| format!("could not read a status code from {status_line:?}"))?;

    Ok(Response {
        status,
        body: body.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn parses_a_normal_response() {
        let raw = b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nhello\n";
        let response = parse(raw).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, "hello\n");
        assert!(response.is_success());
    }

    #[test]
    fn parses_lf_only_separators() {
        let response = parse(b"HTTP/1.0 204 No Content\n\n").unwrap();
        assert_eq!(response.status, 204);
        assert!(response.body.is_empty());
    }

    #[test]
    fn treats_error_codes_as_unsuccessful() {
        let response = parse(b"HTTP/1.0 503 Service Unavailable\r\n\r\nnope").unwrap();
        assert_eq!(response.status, 503);
        assert!(!response.is_success());
    }

    #[test]
    fn a_headers_only_response_has_an_empty_body() {
        let response = parse(b"HTTP/1.0 200 OK\r\nX: y\r\n").unwrap();
        assert_eq!(response.status, 200);
        assert!(response.body.is_empty());
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse(b"not http at all\r\n\r\n").is_err());
        assert!(parse(b"").is_err());
    }

    /// Serve one canned response and return the address to talk to.
    async fn one_shot(
        response: &'static str,
        capture: bool,
    ) -> (SocketAddr, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 2048];
            let read = socket.read(&mut buf).await.unwrap_or(0);
            let request = if capture {
                String::from_utf8_lossy(&buf[..read]).into_owned()
            } else {
                String::new()
            };
            let _ = socket.write_all(response.as_bytes()).await;
            request
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn get_round_trips_over_a_real_socket() {
        let (addr, server) = one_shot("HTTP/1.0 200 OK\r\n\r\nbody-here", true).await;

        let response = get(addr, "/metrics", None).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, "body-here");

        let request = server.await.unwrap();
        assert!(request.starts_with("GET /metrics HTTP/1.0"), "{request}");
        assert!(request.contains("Connection: close"), "{request}");
    }

    #[tokio::test]
    async fn post_sends_the_bearer_token_when_given() {
        let (addr, server) = one_shot("HTTP/1.0 200 OK\r\n\r\nok", true).await;

        post(addr, "/reload", Some("s3cret")).await.unwrap();

        let request = server.await.unwrap();
        assert!(request.starts_with("POST /reload"), "{request}");
        assert!(
            request.contains("Authorization: Bearer s3cret"),
            "{request}"
        );
    }

    #[tokio::test]
    async fn no_token_means_no_authorization_header() {
        let (addr, server) = one_shot("HTTP/1.0 200 OK\r\n\r\nok", true).await;

        post(addr, "/reload", None).await.unwrap();

        let request = server.await.unwrap();
        assert!(!request.contains("Authorization"), "{request}");
    }

    #[tokio::test]
    async fn connection_refused_is_reported_with_the_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let error = get(addr, "/healthz", None).await.unwrap_err();
        assert!(error.to_string().contains("connecting to"), "{error}");
    }

    #[tokio::test]
    async fn a_silent_server_times_out_rather_than_hanging() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Accept but never respond, and never close.
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            std::future::pending::<()>().await;
            drop(socket);
        });

        let error = request(addr, "GET", "/healthz", None, Duration::from_millis(150))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("timed out"), "{error}");
    }
}
