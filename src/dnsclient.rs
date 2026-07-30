//! A small DNS client, so `vega query` can verify a deployment without
//! `dig` being installed on the box.
//!
//! Deliberately not a resolver: no recursion, no cache, no search list. It sends
//! one question to one server and reports exactly what came back, including the
//! response code and the wire size — the details you actually want when a zone
//! is not answering the way you expected.

use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RecordType},
};
use tokio::net::{TcpStream, UdpSocket};

/// Default wait for an answer.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest UDP response we will read. Bigger answers arrive truncated, and we
/// retry over TCP.
const UDP_BUFFER: usize = 4096;

/// Transport used for a query.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Transport {
    /// Sent over UDP.
    Udp,
    /// Sent over TCP, either because it was asked for or after a truncated reply.
    Tcp,
}

impl Transport {
    /// Lowercase name, for output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }
}

/// A completed query.
#[derive(Clone, Debug)]
pub struct Outcome {
    /// The decoded response.
    pub message: Message,
    /// Server that answered.
    pub server: SocketAddr,
    /// Transport the answer arrived on.
    pub transport: Transport,
    /// Round-trip time.
    pub elapsed: Duration,
    /// Size of the response on the wire, in bytes.
    pub size: usize,
    /// True when a UDP answer was truncated and we retried over TCP.
    pub retried_over_tcp: bool,
}

impl Outcome {
    /// The response code's IANA mnemonic, e.g. `NOERROR`.
    pub fn rcode(&self) -> String {
        rcode_name(self.message.metadata.response_code).to_owned()
    }

    /// True when the server answered NOERROR.
    pub fn is_noerror(&self) -> bool {
        self.message.metadata.response_code == ResponseCode::NoError
    }
}

/// Send `name`/`record_type` to `server`.
///
/// Over UDP, a truncated answer is automatically retried over TCP — the same
/// thing a real resolver does, and the reason a large record set is not silently
/// reported as empty.
pub async fn query(
    server: SocketAddr,
    name: &str,
    record_type: RecordType,
    force_tcp: bool,
    timeout: Duration,
) -> Result<Outcome> {
    let mut fqdn: Name = name
        .parse()
        .with_context(|| format!("{name:?} is not a valid DNS name"))?;
    fqdn.set_fqdn(true);

    let mut request = Message::query();
    request.metadata.id = request_id();
    request.metadata.recursion_desired = false;
    request.add_query(Query::query(fqdn, record_type));
    let wire = request.to_vec().context("encoding the query")?;

    let started = Instant::now();

    if force_tcp {
        let (message, size) = ask_tcp(server, &wire, timeout).await?;
        return Ok(Outcome {
            message,
            server,
            transport: Transport::Tcp,
            elapsed: started.elapsed(),
            size,
            retried_over_tcp: false,
        });
    }

    let (message, size) = ask_udp(server, &wire, timeout).await?;
    if message.metadata.truncation {
        let (message, size) = ask_tcp(server, &wire, timeout).await?;
        return Ok(Outcome {
            message,
            server,
            transport: Transport::Tcp,
            elapsed: started.elapsed(),
            size,
            retried_over_tcp: true,
        });
    }

    Ok(Outcome {
        message,
        server,
        transport: Transport::Udp,
        elapsed: started.elapsed(),
        size,
        retried_over_tcp: false,
    })
}

async fn ask_udp(server: SocketAddr, wire: &[u8], timeout: Duration) -> Result<(Message, usize)> {
    // Bind a matching family so we can talk to an IPv6 server.
    let bind: SocketAddr = if server.is_ipv6() {
        "[::]:0".parse().expect("literal is a valid SocketAddr")
    } else {
        "0.0.0.0:0".parse().expect("literal is a valid SocketAddr")
    };

    let socket = UdpSocket::bind(bind)
        .await
        .context("binding a local UDP socket")?;
    socket
        .connect(server)
        .await
        .with_context(|| format!("connecting to {server} over UDP"))?;
    socket
        .send(wire)
        .await
        .with_context(|| format!("sending the query to {server}"))?;

    let mut buf = vec![0u8; UDP_BUFFER];
    let len = tokio::time::timeout(timeout, socket.recv(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("no answer from {server} within {timeout:?}"))?
        .with_context(|| format!("reading the answer from {server}"))?;

    let message = Message::from_vec(&buf[..len])
        .with_context(|| format!("decoding the answer from {server}"))?;
    Ok((message, len))
}

async fn ask_tcp(server: SocketAddr, wire: &[u8], timeout: Duration) -> Result<(Message, usize)> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let exchange = async {
        let mut stream = TcpStream::connect(server)
            .await
            .with_context(|| format!("connecting to {server} over TCP"))?;

        // RFC 1035 §4.2.2: TCP messages are length-prefixed with a u16.
        let len = u16::try_from(wire.len()).context("query is too large for DNS over TCP")?;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(wire).await?;
        stream.flush().await?;

        let mut prefix = [0u8; 2];
        stream.read_exact(&mut prefix).await?;
        let expected = usize::from(u16::from_be_bytes(prefix));
        let mut body = vec![0u8; expected];
        stream.read_exact(&mut body).await?;
        Ok::<_, anyhow::Error>(body)
    };

    let body = tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| anyhow::anyhow!("no answer from {server} within {timeout:?}"))??;

    let size = body.len();
    let message =
        Message::from_vec(&body).with_context(|| format!("decoding the answer from {server}"))?;
    Ok((message, size))
}

/// The IANA mnemonic for a response code.
///
/// Hickory's own `Display` renders prose ("Non-Existent Domain"); tooling and
/// humans debugging DNS both expect the short form that `dig` prints.
pub fn rcode_name(code: ResponseCode) -> &'static str {
    match code {
        ResponseCode::NoError => "NOERROR",
        ResponseCode::FormErr => "FORMERR",
        ResponseCode::ServFail => "SERVFAIL",
        ResponseCode::NXDomain => "NXDOMAIN",
        ResponseCode::NotImp => "NOTIMP",
        ResponseCode::Refused => "REFUSED",
        ResponseCode::YXDomain => "YXDOMAIN",
        ResponseCode::YXRRSet => "YXRRSET",
        ResponseCode::NXRRSet => "NXRRSET",
        ResponseCode::NotAuth => "NOTAUTH",
        ResponseCode::NotZone => "NOTZONE",
        ResponseCode::BADVERS => "BADVERS",
        ResponseCode::BADSIG => "BADSIG",
        ResponseCode::BADKEY => "BADKEY",
        ResponseCode::BADTIME => "BADTIME",
        ResponseCode::BADMODE => "BADMODE",
        ResponseCode::BADNAME => "BADNAME",
        ResponseCode::BADALG => "BADALG",
        ResponseCode::BADTRUNC => "BADTRUNC",
        ResponseCode::BADCOOKIE => "BADCOOKIE",
        ResponseCode::Unknown(_) => "UNKNOWN",
    }
}

/// Parse `host`, `host:port` or `[v6]:port` into a socket address.
///
/// A bare host gets port 53. Host names are not resolved: this is a debugging
/// tool for a server whose address you already know, and silently depending on
/// system DNS to debug DNS is a trap.
pub fn parse_server(input: &str) -> Result<SocketAddr> {
    let trimmed = input.trim().trim_start_matches('@');
    if trimmed.is_empty() {
        bail!("no server address given");
    }

    if let Ok(addr) = trimmed.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    bail!("{input:?} is not an IP address or IP:port (host names are not resolved)")
}

/// Parse a record type, case-insensitively.
pub fn parse_record_type(input: &str) -> Result<RecordType> {
    input
        .trim()
        .to_uppercase()
        .parse()
        .map_err(|e| anyhow::anyhow!("unknown record type {input:?}: {e}"))
}

/// A pseudo-random-enough query ID.
///
/// This client only ever has one outstanding query on a connected socket, so the
/// ID is not a security boundary; it just needs to vary between runs.
fn request_id() -> u16 {
    use std::hash::{BuildHasher as _, RandomState};
    #[allow(clippy::cast_possible_truncation)]
    let id = RandomState::new().hash_one(0u8) as u16;
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_ip_gets_the_default_dns_port() {
        assert_eq!(
            parse_server("127.0.0.1").unwrap(),
            "127.0.0.1:53".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_server("::1").unwrap(),
            "[::1]:53".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn explicit_ports_are_honoured() {
        assert_eq!(
            parse_server("127.0.0.1:5300").unwrap(),
            "127.0.0.1:5300".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            parse_server("[::1]:5300").unwrap(),
            "[::1]:5300".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn a_leading_at_sign_is_accepted_for_dig_muscle_memory() {
        assert_eq!(
            parse_server("@127.0.0.1:5300").unwrap(),
            "127.0.0.1:5300".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn host_names_are_rejected_with_an_explanation() {
        let error = parse_server("ns1.example.com").unwrap_err();
        assert!(error.to_string().contains("not resolved"), "{error}");
    }

    #[test]
    fn empty_server_is_rejected() {
        assert!(parse_server("   ").is_err());
        assert!(parse_server("@").is_err());
    }

    #[test]
    fn record_types_parse_case_insensitively() {
        assert_eq!(parse_record_type("a").unwrap(), RecordType::A);
        assert_eq!(parse_record_type("AaAa").unwrap(), RecordType::AAAA);
        assert_eq!(parse_record_type(" txt ").unwrap(), RecordType::TXT);
        assert!(parse_record_type("nope").is_err());
    }

    #[test]
    fn rcode_names_are_the_iana_mnemonics() {
        assert_eq!(rcode_name(ResponseCode::NoError), "NOERROR");
        assert_eq!(rcode_name(ResponseCode::NXDomain), "NXDOMAIN");
        assert_eq!(rcode_name(ResponseCode::Refused), "REFUSED");
        assert_eq!(rcode_name(ResponseCode::ServFail), "SERVFAIL");
        assert_eq!(rcode_name(ResponseCode::Unknown(200)), "UNKNOWN");
        // Every name must be a single uppercase token, the way dig prints it.
        for code in [
            ResponseCode::NoError,
            ResponseCode::FormErr,
            ResponseCode::NotImp,
            ResponseCode::BADCOOKIE,
        ] {
            let name = rcode_name(code);
            assert!(!name.contains(' '), "{name} should be one token");
            assert_eq!(name, name.to_uppercase());
        }
    }

    #[test]
    fn transport_names_are_stable() {
        assert_eq!(Transport::Udp.as_str(), "udp");
        assert_eq!(Transport::Tcp.as_str(), "tcp");
    }

    #[test]
    fn request_ids_are_not_all_identical() {
        // Not a randomness test — just a guard against a constant ID.
        let ids: std::collections::HashSet<u16> = (0..16).map(|_| request_id()).collect();
        assert!(ids.len() > 1, "request_id() looks constant");
    }

    #[tokio::test]
    async fn an_invalid_name_fails_before_any_socket_is_opened() {
        let server = "127.0.0.1:1".parse().unwrap();
        let error = query(server, "not a name", RecordType::A, false, DEFAULT_TIMEOUT)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("valid DNS name"), "{error}");
    }

    #[tokio::test]
    async fn a_silent_server_times_out() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        // Hold the socket open but never reply.
        let _guard = socket;

        let error = query(
            addr,
            "example.com",
            RecordType::A,
            false,
            Duration::from_millis(120),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("no answer"), "{error}");
    }
}
