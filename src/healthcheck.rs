//! A dependency-free `/healthz` probe, so `dns-server healthcheck` can serve as a
//! container `HEALTHCHECK` in images that ship no shell and no curl.

use std::net::SocketAddr;

use anyhow::{bail, Result};

use crate::http;

/// Where the probe looks when no admin address is configured.
pub const DEFAULT_ADMIN_ADDR: &str = "127.0.0.1:9100";

/// Ask `addr` for `/healthz`. `Ok(())` means the server answered `200`.
pub async fn probe(addr: SocketAddr) -> Result<()> {
    let response = http::get(addr, "/healthz", None).await?;
    if response.is_success() {
        Ok(())
    } else {
        bail!("unhealthy: {addr} answered HTTP {}", response.status);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Arc, time::Duration};

    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpStream,
    };
    use tokio_util::sync::CancellationToken;

    use crate::{
        admin::{self, AdminState},
        metrics::Metrics,
    };

    /// Start the real admin server on an ephemeral port.
    async fn start_admin() -> (SocketAddr, CancellationToken) {
        let state = AdminState::new(Arc::new(Metrics::new()));
        let token = CancellationToken::new();

        // Bind first so the test knows the port before the server task starts.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let serve_token = token.clone();
        tokio::spawn(async move {
            let _ = admin::serve(addr, state, serve_token).await;
        });

        // Wait for the listener to come up; the probe itself retries nothing.
        for _ in 0..50 {
            if TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        (addr, token)
    }

    #[tokio::test]
    async fn probe_succeeds_against_a_live_admin_server() {
        let (addr, token) = start_admin().await;
        probe(addr).await.expect("healthz should answer 200");
        token.cancel();
    }

    #[tokio::test]
    async fn probe_fails_when_nothing_is_listening() {
        // Bind and immediately release a port so we know it is free.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let error = probe(addr).await.expect_err("probe should fail");
        assert!(
            error.to_string().contains("connecting to"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn probe_reports_a_non_200_status() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                // Drain the request before answering; closing with unread data in
                // the receive buffer makes the peer see a reset, not our status.
                let mut scratch = [0u8; 1024];
                let _ = socket.read(&mut scratch).await;
                let _ = socket
                    .write_all(b"HTTP/1.0 503 Service Unavailable\r\n\r\n")
                    .await;
            }
        });

        let error = probe(addr).await.expect_err("probe should fail");
        assert!(
            error.to_string().contains("503"),
            "unexpected error: {error}"
        );
    }
}
