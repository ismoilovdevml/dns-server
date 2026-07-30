//! End-to-end tests: a real Hickory server on an ephemeral port, driven by real
//! DNS messages over real sockets.
//!
//! These are the tests that would have caught a broken wire format, a listener
//! that never binds, or a response that a resolver refuses to parse — none of
//! which the unit tests can see.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use dns_server::{
    config::{RecordSpec, SoaSpec, ZoneConfig},
    handler::DnsHandler,
    metrics::Metrics,
    ratelimit::RateLimiter,
    zone::Zone,
};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};
use hickory_server::Server;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// Wall-clock budget for a single query. Generous enough for a loaded CI runner,
/// tight enough that a hang fails instead of stalling the suite.
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

const ZONE: &str = "example.test";

fn spec(name: &str, ty: &str, values: &[&str]) -> RecordSpec {
    RecordSpec {
        name: name.to_owned(),
        record_type: ty.to_owned(),
        ttl: None,
        values: values.iter().map(|v| (*v).to_owned()).collect(),
    }
}

fn zone_config(records: Vec<RecordSpec>) -> ZoneConfig {
    ZoneConfig {
        origin: ZONE.to_owned(),
        default_ttl: 300,
        builtins: true,
        soa: Some(SoaSpec {
            mname: format!("ns1.{ZONE}."),
            rname: format!("hostmaster.{ZONE}."),
            serial: 1,
            refresh: 3600,
            retry: 900,
            expire: 604_800,
            minimum: 60,
        }),
        records,
    }
}

/// A running server plus the addresses it is listening on.
struct TestServer {
    udp: SocketAddr,
    tcp: SocketAddr,
    metrics: Arc<Metrics>,
    _server: Server<DnsHandler>,
}

impl TestServer {
    async fn start(records: Vec<RecordSpec>, limiter: Option<Arc<RateLimiter>>) -> Self {
        let cfg = zone_config(records);
        let zone = Arc::new(Zone::from_config(&cfg).expect("zone builds"));
        let metrics = Arc::new(Metrics::new());
        let handler = DnsHandler::new(zone, &cfg, Arc::clone(&metrics), limiter);

        let mut server = Server::new(handler);

        // Port 0 lets the OS pick, so tests never collide with each other or with
        // whatever else is running on the machine.
        let udp_socket = UdpSocket::bind("127.0.0.1:0").await.expect("udp binds");
        let udp = udp_socket.local_addr().expect("udp addr");
        server.register_socket(udp_socket);

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.expect("tcp binds");
        let tcp = tcp_listener.local_addr().expect("tcp addr");
        server.register_listener(tcp_listener, Duration::from_secs(5), 8);

        Self {
            udp,
            tcp,
            metrics,
            _server: server,
        }
    }
}

fn query_message(name: &str, record_type: RecordType) -> Message {
    let mut name: Name = name.parse().expect("test name parses");
    name.set_fqdn(true);

    let mut message = Message::query();
    message.metadata.id = 0x4242;
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name, record_type));
    message
}

async fn ask_udp(server: &TestServer, name: &str, record_type: RecordType) -> Message {
    let request = query_message(name, record_type);
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("client binds");
    socket.connect(server.udp).await.expect("client connects");
    socket
        .send(&request.to_vec().expect("request encodes"))
        .await
        .expect("request sends");

    let mut buf = vec![0u8; 4096];
    let len = tokio::time::timeout(QUERY_TIMEOUT, socket.recv(&mut buf))
        .await
        .expect("server answers before the timeout")
        .expect("response reads");
    Message::from_vec(&buf[..len]).expect("response decodes")
}

async fn ask_tcp(server: &TestServer, name: &str, record_type: RecordType) -> Message {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let request = query_message(name, record_type)
        .to_vec()
        .expect("request encodes");
    let mut stream = TcpStream::connect(server.tcp).await.expect("tcp connects");

    // DNS over TCP prefixes each message with its length as a u16.
    let len = u16::try_from(request.len()).expect("request fits in u16");
    stream.write_all(&len.to_be_bytes()).await.expect("prefix");
    stream.write_all(&request).await.expect("body");
    stream.flush().await.expect("flush");

    let read = async {
        let mut prefix = [0u8; 2];
        stream.read_exact(&mut prefix).await?;
        let mut body = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
        stream.read_exact(&mut body).await?;
        Ok::<_, std::io::Error>(body)
    };
    let body = tokio::time::timeout(QUERY_TIMEOUT, read)
        .await
        .expect("server answers before the timeout")
        .expect("response reads");
    Message::from_vec(&body).expect("response decodes")
}

fn first_a(message: &Message) -> String {
    match &message.answers.first().expect("an answer record").data {
        RData::A(a) => a.0.to_string(),
        other => panic!("expected an A record, got {other:?}"),
    }
}

fn first_txt(message: &Message) -> String {
    match &message.answers.first().expect("an answer record").data {
        RData::TXT(txt) => txt
            .txt_data
            .iter()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect(),
        other => panic!("expected a TXT record, got {other:?}"),
    }
}

#[tokio::test]
async fn udp_query_returns_the_configured_a_record() {
    let server = TestServer::start(vec![spec("www", "A", &["203.0.113.10"])], None).await;

    let response = ask_udp(&server, &format!("www.{ZONE}"), RecordType::A).await;

    assert_eq!(
        response.metadata.id, 0x4242,
        "response must echo the query id"
    );
    assert_eq!(response.metadata.message_type, MessageType::Response);
    assert_eq!(response.metadata.op_code, OpCode::Query);
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(response.metadata.authoritative, "AA must be set");
    assert_eq!(response.queries.len(), 1, "question section must be echoed");
    assert_eq!(first_a(&response), "203.0.113.10");
}

#[tokio::test]
async fn tcp_query_returns_the_same_answer_as_udp() {
    let server = TestServer::start(vec![spec("www", "A", &["203.0.113.10"])], None).await;

    let response = ask_tcp(&server, &format!("www.{ZONE}"), RecordType::A).await;

    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(first_a(&response), "203.0.113.10");
}

#[tokio::test]
async fn unknown_name_in_zone_returns_nxdomain_with_the_soa() {
    let server = TestServer::start(vec![], None).await;

    let response = ask_udp(&server, &format!("nope.{ZONE}"), RecordType::A).await;

    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    assert!(response.answers.is_empty());
    assert_eq!(
        response
            .authorities
            .first()
            .map(hickory_proto::rr::Record::record_type),
        Some(RecordType::SOA),
        "negative answers must carry the SOA so resolvers can cache them"
    );
}

#[tokio::test]
async fn existing_name_with_no_matching_type_returns_noerror_and_no_answers() {
    let server = TestServer::start(vec![spec("www", "A", &["203.0.113.10"])], None).await;

    let response = ask_udp(&server, &format!("www.{ZONE}"), RecordType::AAAA).await;

    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(response.answers.is_empty());
    assert_eq!(
        response
            .authorities
            .first()
            .map(hickory_proto::rr::Record::record_type),
        Some(RecordType::SOA)
    );
}

#[tokio::test]
async fn out_of_zone_query_is_refused() {
    let server = TestServer::start(vec![], None).await;

    let response = ask_udp(&server, "www.google.com", RecordType::A).await;

    assert_eq!(response.metadata.response_code, ResponseCode::Refused);
    assert!(!response.metadata.authoritative);
}

#[tokio::test]
async fn cname_answer_includes_the_resolved_target() {
    let server = TestServer::start(
        vec![
            spec("alias", "CNAME", &[&format!("origin.{ZONE}.")]),
            spec("origin", "A", &["203.0.113.20"]),
        ],
        None,
    )
    .await;

    let response = ask_udp(&server, &format!("alias.{ZONE}"), RecordType::A).await;

    assert_eq!(response.answers.len(), 2);
    assert_eq!(response.answers[0].record_type(), RecordType::CNAME);
    assert_eq!(response.answers[1].record_type(), RecordType::A);
}

#[tokio::test]
async fn wildcard_answers_any_matching_subdomain() {
    let server = TestServer::start(vec![spec("*.apps", "A", &["203.0.113.30"])], None).await;

    let response = ask_udp(&server, &format!("whatever.apps.{ZONE}"), RecordType::A).await;

    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(first_a(&response), "203.0.113.30");
    assert_eq!(
        response.answers[0].name.to_string(),
        format!("whatever.apps.{ZONE}."),
        "a wildcard answer must be labelled with the queried name"
    );
}

#[tokio::test]
async fn apex_soa_query_is_answered() {
    let server = TestServer::start(vec![], None).await;

    let response = ask_udp(&server, ZONE, RecordType::SOA).await;

    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        response
            .answers
            .first()
            .map(hickory_proto::rr::Record::record_type),
        Some(RecordType::SOA)
    );
}

#[tokio::test]
async fn mx_records_survive_the_wire_round_trip() {
    let server =
        TestServer::start(vec![spec("@", "MX", &[&format!("10 mail.{ZONE}.")])], None).await;

    let response = ask_udp(&server, ZONE, RecordType::MX).await;

    match &response.answers.first().expect("an answer").data {
        RData::MX(mx) => {
            assert_eq!(mx.preference, 10);
            assert_eq!(mx.exchange.to_string(), format!("mail.{ZONE}."));
        }
        other => panic!("expected MX, got {other:?}"),
    }
}

#[tokio::test]
async fn builtin_myip_reflects_the_client_address() {
    let server = TestServer::start(vec![], None).await;

    let response = ask_udp(&server, &format!("myip.{ZONE}"), RecordType::A).await;

    assert_eq!(first_a(&response), "127.0.0.1");
}

#[tokio::test]
async fn builtin_hello_greets_the_label() {
    let server = TestServer::start(vec![], None).await;

    let response = ask_udp(
        &server,
        &format!("ismoilovdev.hello.{ZONE}"),
        RecordType::TXT,
    )
    .await;

    assert_eq!(first_txt(&response), "hello, ismoilovdev");
}

#[tokio::test]
async fn builtin_version_reports_the_build() {
    let server = TestServer::start(vec![], None).await;

    let response = ask_udp(&server, &format!("version.{ZONE}"), RecordType::TXT).await;

    assert!(first_txt(&response).contains(dns_server::VERSION));
}

#[tokio::test]
async fn builtin_counter_increases_with_traffic() {
    let server = TestServer::start(vec![], None).await;

    let first = ask_udp(&server, &format!("counter.{ZONE}"), RecordType::TXT).await;
    let second = ask_udp(&server, &format!("counter.{ZONE}"), RecordType::TXT).await;

    let first: u64 = first_txt(&first).parse().expect("counter is a number");
    let second: u64 = first_txt(&second).parse().expect("counter is a number");
    assert!(second > first, "{second} should exceed {first}");
}

#[tokio::test]
async fn rate_limited_client_gets_refused() {
    // Burst of exactly one, so the second query in the same instant is dropped.
    let limiter = Arc::new(RateLimiter::new(1, 1));
    let server = TestServer::start(
        vec![spec("www", "A", &["203.0.113.10"])],
        Some(Arc::clone(&limiter)),
    )
    .await;

    let first = ask_udp(&server, &format!("www.{ZONE}"), RecordType::A).await;
    assert_eq!(first.metadata.response_code, ResponseCode::NoError);

    let second = ask_udp(&server, &format!("www.{ZONE}"), RecordType::A).await;
    assert_eq!(second.metadata.response_code, ResponseCode::Refused);
}

#[tokio::test]
async fn metrics_reflect_served_traffic() {
    let server = TestServer::start(vec![spec("www", "A", &["203.0.113.10"])], None).await;

    ask_udp(&server, &format!("www.{ZONE}"), RecordType::A).await;
    ask_tcp(&server, &format!("www.{ZONE}"), RecordType::A).await;
    ask_udp(&server, &format!("nope.{ZONE}"), RecordType::A).await;

    let text = server.metrics.render_prometheus();
    assert!(text.contains("dns_queries_total 3"), "{text}");
    assert!(
        text.contains("dns_queries_by_transport_total{transport=\"udp\"} 2"),
        "{text}"
    );
    assert!(
        text.contains("dns_queries_by_transport_total{transport=\"tcp\"} 1"),
        "{text}"
    );
    assert!(
        text.contains("dns_responses_total{rcode=\"noerror\"} 2"),
        "{text}"
    );
    assert!(
        text.contains("dns_responses_total{rcode=\"nxdomain\"} 1"),
        "{text}"
    );
    assert!(
        text.contains("dns_query_duration_seconds_count 3"),
        "{text}"
    );
}

#[tokio::test]
async fn edns_request_gets_an_edns_response() {
    let server = TestServer::start(vec![spec("www", "A", &["203.0.113.10"])], None).await;

    let mut request = query_message(&format!("www.{ZONE}"), RecordType::A);
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_max_payload(4096);
    request.set_edns(edns);

    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("client binds");
    socket.connect(server.udp).await.expect("client connects");
    socket
        .send(&request.to_vec().expect("request encodes"))
        .await
        .expect("request sends");

    let mut buf = vec![0u8; 4096];
    let len = tokio::time::timeout(QUERY_TIMEOUT, socket.recv(&mut buf))
        .await
        .expect("server answers")
        .expect("response reads");
    let response = Message::from_vec(&buf[..len]).expect("response decodes");

    let edns = response.edns.as_ref().expect("response must carry EDNS");
    assert!(
        edns.max_payload() >= 512,
        "advertised payload must be at least the RFC 6891 minimum"
    );
}

#[tokio::test]
async fn multiple_values_are_all_returned() {
    let server = TestServer::start(
        vec![spec(
            "pool",
            "A",
            &["203.0.113.1", "203.0.113.2", "203.0.113.3"],
        )],
        None,
    )
    .await;

    let response = ask_udp(&server, &format!("pool.{ZONE}"), RecordType::A).await;

    assert_eq!(response.answers.len(), 3);
}

#[tokio::test]
async fn concurrent_queries_are_all_answered() {
    let server = Arc::new(TestServer::start(vec![spec("www", "A", &["203.0.113.10"])], None).await);

    let mut tasks = Vec::new();
    for _ in 0..25 {
        let server = Arc::clone(&server);
        tasks.push(tokio::spawn(async move {
            let response = ask_udp(&server, &format!("www.{ZONE}"), RecordType::A).await;
            response.metadata.response_code
        }));
    }

    for task in tasks {
        assert_eq!(task.await.expect("task completes"), ResponseCode::NoError);
    }
}
