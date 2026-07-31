//! End-to-end tests: a real Hickory server on an ephemeral port, driven by real
//! DNS messages over real sockets.
//!
//! These are the tests that would have caught a broken wire format, a listener
//! that never binds, or a response that a resolver refuses to parse — none of
//! which the unit tests can see.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};
use hickory_server::Server;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use vega::{
    config::{RecordSpec, SoaSpec, ZoneConfig},
    handler::DnsHandler,
    metrics::Metrics,
    ratelimit::RateLimiter,
    zone::Zone,
};

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

    assert!(first_txt(&response).contains(vega::VERSION));
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

/// Scenario: A rate-limited UDP query is answered with silence
/// features/rate-limiting.feature:201
///
/// Replying REFUSED still delivers a packet to whatever source the attacker
/// forged, so the limiter reduced our byte count and not the victim's packet
/// count — 500 attack packets produced 500 victim packets. Dropping is the
/// whole point of the control.
#[tokio::test]
async fn a_rate_limited_udp_query_gets_no_response_at_all() {
    // Burst of exactly one, so the second query in the same instant is dropped.
    let limiter = Arc::new(RateLimiter::new(1, 1));
    let server = TestServer::start(
        vec![spec("www", "A", &["203.0.113.10"])],
        Some(Arc::clone(&limiter)),
    )
    .await;

    let first = ask_udp(&server, &format!("www.{ZONE}"), RecordType::A).await;
    assert_eq!(first.metadata.response_code, ResponseCode::NoError);

    let request = query_message(&format!("www.{ZONE}"), RecordType::A);
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("client binds");
    socket.connect(server.udp).await.expect("client connects");
    socket
        .send(&request.to_vec().expect("request encodes"))
        .await
        .expect("request sends");

    let mut buf = vec![0u8; 4096];
    let outcome = tokio::time::timeout(Duration::from_millis(750), socket.recv(&mut buf)).await;
    if let Ok(read) = outcome {
        panic!(
            "a rate-limited UDP query must be answered with silence, got {} bytes",
            read.unwrap_or(0)
        );
    }
}

/// Scenario: A rate-limited TCP query is still answered
/// features/rate-limiting.feature:201
///
/// TCP completed a handshake, so the source is real and a reply cannot be
/// reflected at a third party. Silence there would just break legitimate
/// clients falling back from a truncated UDP answer.
#[tokio::test]
async fn a_rate_limited_tcp_query_is_refused_rather_than_dropped() {
    let limiter = Arc::new(RateLimiter::new(1, 1));
    let server = TestServer::start(
        vec![spec("www", "A", &["203.0.113.10"])],
        Some(Arc::clone(&limiter)),
    )
    .await;

    let first = ask_tcp(&server, &format!("www.{ZONE}"), RecordType::A).await;
    assert_eq!(first.metadata.response_code, ResponseCode::NoError);

    let second = ask_tcp(&server, &format!("www.{ZONE}"), RecordType::A).await;
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

/// Send a fully-formed message and read the reply, so a test can control every
/// header bit rather than going through `query_message`.
/// Round-trip a message and return the reply together with its wire length.
///
/// The byte count is the point: the amplification argument rests on how big the
/// datagram is, and every test that asserted only on decoded fields would pass
/// against a server emitting four kilobytes.
async fn round_trip_measured(server: &TestServer, request: &Message) -> (usize, Message) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("client binds");
    socket.connect(server.udp).await.expect("client connects");
    socket
        .send(&request.to_vec().expect("request encodes"))
        .await
        .expect("request sends");

    let mut buf = vec![0u8; 65535];
    let len = tokio::time::timeout(QUERY_TIMEOUT, socket.recv(&mut buf))
        .await
        .expect("server answers before the timeout")
        .expect("response reads");
    (
        len,
        Message::from_vec(&buf[..len]).expect("response decodes"),
    )
}

/// Scenario: A query with no OPT record is answered within 512 bytes
/// features/edns-and-transport.feature — RFC 1035 §4.2.1
///
/// Hickory sizes a non-EDNS UDP reply from its 4096-byte receive buffer, so
/// without our own cap a 33-byte query bought a 4096-byte datagram aimed at
/// whatever source the attacker forged.
#[tokio::test]
async fn a_non_edns_udp_answer_never_exceeds_512_bytes() {
    let big = "x".repeat(200);
    let server = TestServer::start(
        vec![spec(
            "big",
            "TXT",
            &[
                &format!("\"{big}\""),
                &format!("\"{big}\""),
                &format!("\"{big}\""),
                &format!("\"{big}\""),
            ],
        )],
        None,
    )
    .await;

    // No OPT record on the request at all.
    let request = query_message(&format!("big.{ZONE}"), RecordType::TXT);
    let (len, response) = round_trip_measured(&server, &request).await;

    assert!(
        len <= 512,
        "a non-EDNS UDP answer must fit in 512 bytes, got {len}"
    );
    assert!(
        response.metadata.truncation,
        "an answer that did not fit must set TC so the client retries over TCP"
    );

    // And the TCP retry must actually deliver what UDP could not.
    let over_tcp = ask_tcp(&server, &format!("big.{ZONE}"), RecordType::TXT).await;
    assert!(
        !over_tcp.metadata.truncation,
        "TCP has room, TC must be clear"
    );
    assert_eq!(
        over_tcp.answers.len(),
        4,
        "the TCP retry must carry the full RRset — every configured value"
    );
}

/// Scenario: A record type with no size arm is measured, not guessed
/// features/edns-and-transport.feature — RFC 1035 §4.2.1
///
/// TLSA, CAA, SVCB and friends carry operator-supplied blobs. A fixed 256-byte
/// guess for them let a 663-byte answer out with TC clear — the cap applied to
/// the common types and quietly did not to the rest.
#[tokio::test]
async fn a_large_record_of_an_unlisted_type_is_still_capped_at_512_bytes() {
    let server = TestServer::start(
        vec![spec(
            "tlsa",
            "TLSA",
            &[&format!("3 1 1 {}", "ab".repeat(600))],
        )],
        None,
    )
    .await;

    let request = query_message(&format!("tlsa.{ZONE}"), RecordType::TLSA);
    let (len, response) = round_trip_measured(&server, &request).await;

    assert!(
        len <= 512,
        "a non-EDNS UDP answer must fit in 512 bytes whatever the record type, got {len}"
    );
    assert!(
        response.metadata.truncation,
        "TC must be set when truncated"
    );
}

/// Scenario: An EDNS answer never exceeds the advertised ceiling
/// features/edns-and-transport.feature — DNS Flag Day 2020
///
/// The clamp is applied in two places — the OPT we advertise and the budget the
/// encoder works to. Asserting only the advertisement leaves the mutant that
/// clamps the number while emitting the bytes anyway, which is the one that
/// matters.
#[tokio::test]
async fn an_edns_answer_never_exceeds_the_clamped_ceiling_in_bytes() {
    let big = "x".repeat(200);
    let values: Vec<String> = (0..20).map(|_| format!("\"{big}\"")).collect();
    let refs: Vec<&str> = values.iter().map(String::as_str).collect();
    let server = TestServer::start(vec![spec("huge", "TXT", &refs)], None).await;

    for offered in [4096u16, 8192, u16::MAX] {
        let mut request = query_message(&format!("huge.{ZONE}"), RecordType::TXT);
        let mut edns = hickory_proto::op::Edns::new();
        edns.set_max_payload(offered);
        request.set_edns(edns);

        let (len, _) = round_trip_measured(&server, &request).await;
        assert!(
            len <= 1232,
            "a client offering {offered} must still not receive more than 1232 bytes, got {len}"
        );
    }
}

async fn round_trip(server: &TestServer, request: &Message) -> Message {
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

/// Send raw bytes and return the raw reply. `Edns::set_max_payload` clamps to
/// 512 on the way out, so a test that wants to offer a smaller payload — which
/// a non-Hickory client is perfectly able to do — has to build the packet.
async fn raw_round_trip(server: &TestServer, request: &[u8]) -> Vec<u8> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("client binds");
    socket.connect(server.udp).await.expect("client connects");
    socket.send(request).await.expect("request sends");

    let mut buf = vec![0u8; 4096];
    let len = tokio::time::timeout(QUERY_TIMEOUT, socket.recv(&mut buf))
        .await
        .expect("server answers before the timeout")
        .expect("response reads");
    buf.truncate(len);
    buf
}

/// The CLASS field of the first OPT record in a raw response, which is where
/// EDNS keeps the advertised UDP payload size.
fn opt_payload(response: &[u8]) -> u16 {
    let message = Message::from_vec(response).expect("response decodes");
    message
        .edns
        .as_ref()
        .expect("response must carry EDNS")
        .max_payload()
}

#[tokio::test]
async fn a_client_that_offers_a_tiny_edns_payload_is_raised_to_512() {
    // Kills `MIN_EDNS_PAYLOAD: 512 -> 0` and `.max(MIN) -> .min(MIN)`. The
    // existing EDNS test offered 4096, so the clamp was never exercised, and it
    // could not have been: `Edns::set_max_payload` raises anything below 512
    // before it reaches the wire. A hand-built packet is the only way to
    // present the server with the case its own clamp exists for.
    //
    // RFC 6891 s6.2.3: "Values lower than 512 MUST be treated as equal to 512."
    let server = TestServer::start(vec![spec("www", "A", &["203.0.113.10"])], None).await;

    for offered in [0u16, 1, 300, 511] {
        // Header: id 0x4242, RD, QDCOUNT 1, ARCOUNT 1.
        let mut packet: Vec<u8> = vec![0x42, 0x42, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1];
        // Question: www.<ZONE>. A IN
        for label in format!("www.{ZONE}").split('.') {
            packet.push(u8::try_from(label.len()).expect("short label"));
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
        packet.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
                                                       // OPT RR: root owner, TYPE 41, CLASS = offered payload, TTL 0, RDLEN 0.
        packet.push(0);
        packet.extend_from_slice(&41u16.to_be_bytes());
        packet.extend_from_slice(&offered.to_be_bytes());
        packet.extend_from_slice(&0u32.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());

        let response = raw_round_trip(&server, &packet).await;
        assert_eq!(
            opt_payload(&response),
            512,
            "a client offering {offered} must be answered with 512, not {offered} echoed back"
        );
    }
}

/// Scenario: A client advertising a large payload has it clamped, not echoed
/// features/edns-and-transport.feature:50
///
/// The client chooses this number, so echoing it back unclamped lets the client
/// choose our amplification factor with it — 8192 bought a 203x answer from a
/// 40-byte query. 1232 is the DNS Flag Day 2020 ceiling.
#[tokio::test]
async fn a_large_edns_payload_offer_is_clamped_to_the_flag_day_ceiling() {
    let server = TestServer::start(vec![spec("www", "A", &["203.0.113.10"])], None).await;

    for offered in [1500u16, 4096, 8192, u16::MAX] {
        let mut request = query_message(&format!("www.{ZONE}"), RecordType::A);
        let mut edns = hickory_proto::op::Edns::new();
        edns.set_max_payload(offered);
        request.set_edns(edns);

        let response = round_trip(&server, &request).await;
        assert_eq!(
            response
                .edns
                .as_ref()
                .expect("response must carry EDNS")
                .max_payload(),
            1232,
            "a client offering {offered} must be answered with 1232, not {offered} echoed back"
        );
    }
}

/// Scenario: A payload offer between the floor and the ceiling is honoured
/// features/edns-and-transport.feature:50
///
/// The clamp must not flatten every resolver to 1232 — one that can only take
/// 1000 bytes still gets 1000.
#[tokio::test]
async fn an_edns_payload_offer_inside_the_range_is_honoured() {
    let server = TestServer::start(vec![spec("www", "A", &["203.0.113.10"])], None).await;

    let mut request = query_message(&format!("www.{ZONE}"), RecordType::A);
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_max_payload(1000);
    request.set_edns(edns);

    let response = round_trip(&server, &request).await;
    assert_eq!(
        response
            .edns
            .as_ref()
            .expect("response must carry EDNS")
            .max_payload(),
        1000
    );
}

#[tokio::test]
async fn the_response_advertises_edns_version_zero() {
    // Kills `edns.set_version(0) -> set_version(1)`: a resolver seeing an
    // unknown EDNS version in a reply is entitled to drop the whole answer.
    let server = TestServer::start(vec![spec("www", "A", &["203.0.113.10"])], None).await;

    let mut request = query_message(&format!("www.{ZONE}"), RecordType::A);
    request.set_edns(hickory_proto::op::Edns::new());

    let response = round_trip(&server, &request).await;
    assert_eq!(
        response.edns.as_ref().expect("EDNS in the reply").version(),
        0
    );
}

#[tokio::test]
async fn a_query_without_edns_gets_a_reply_without_edns() {
    let server = TestServer::start(vec![spec("www", "A", &["203.0.113.10"])], None).await;
    let response = ask_udp(&server, &format!("www.{ZONE}"), RecordType::A).await;
    assert!(
        response.edns.is_none(),
        "we must not volunteer an OPT record to a plain DNS client"
    );
}

#[tokio::test]
async fn unsupported_opcodes_are_answered_notimp() {
    // Kills `ResponseCode::NotImp -> FormErr` for a non-QUERY opcode. Nothing
    // exercised any opcode other than QUERY, over any transport.
    let server = TestServer::start(vec![spec("www", "A", &["203.0.113.10"])], None).await;

    for op_code in [
        OpCode::Status,
        OpCode::Notify,
        OpCode::Update,
        OpCode::Unknown(3),
        OpCode::Unknown(15),
    ] {
        let mut request = query_message(&format!("www.{ZONE}"), RecordType::A);
        request.metadata.op_code = op_code;

        let response = round_trip(&server, &request).await;
        assert_eq!(
            response.metadata.response_code,
            ResponseCode::NotImp,
            "opcode {op_code:?} must be NOTIMP, not another error code"
        );
        assert_eq!(
            response.metadata.op_code, op_code,
            "the opcode must be echoed so the client can match the reply"
        );
        assert!(response.answers.is_empty());
        assert!(!response.metadata.authoritative);
    }
}

#[tokio::test]
async fn a_response_sent_to_the_server_is_ignored() {
    // QR=1 means "this is an answer". Replying to it turns two name servers
    // pointed at each other into a packet loop.
    let server = TestServer::start(vec![spec("www", "A", &["203.0.113.10"])], None).await;

    let mut request = query_message(&format!("www.{ZONE}"), RecordType::A);
    request.metadata.message_type = MessageType::Response;

    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("client binds");
    socket.connect(server.udp).await.expect("client connects");
    socket
        .send(&request.to_vec().expect("encodes"))
        .await
        .expect("sends");

    let mut buf = vec![0u8; 4096];
    let outcome = tokio::time::timeout(Duration::from_millis(750), socket.recv(&mut buf)).await;
    assert!(
        outcome.is_err(),
        "the server answered a message with QR=1: {:?}",
        outcome.map(|r| r.map(|n| buf[..n].to_vec()))
    );
}

#[tokio::test]
async fn queries_keep_being_answered_across_a_zone_reload() {
    // A reload swaps an ArcSwap under live traffic. Nothing covered the two
    // happening at once, so a torn swap would have gone unnoticed.
    use std::sync::atomic::{AtomicBool, Ordering};

    let cfg = zone_config(vec![spec("www", "A", &["203.0.113.10"])]);
    let zone = Arc::new(Zone::from_config(&cfg).expect("zone builds"));
    let metrics = Arc::new(Metrics::new());
    let handler = Arc::new(DnsHandler::new(zone, &cfg, Arc::clone(&metrics), None));

    let alt = zone_config(vec![spec("www", "A", &["198.51.100.7"])]);
    let stop = Arc::new(AtomicBool::new(false));

    let reloader = {
        let (handler, alt, cfg, stop) = (
            Arc::clone(&handler),
            alt.clone(),
            cfg.clone(),
            Arc::clone(&stop),
        );
        tokio::task::spawn_blocking(move || {
            let mut n = 0u32;
            while !stop.load(Ordering::Relaxed) {
                let next = if n.is_multiple_of(2) { &alt } else { &cfg };
                handler.replace_zone(
                    Arc::new(Zone::from_config(next).expect("zone builds")),
                    next.builtins,
                );
                n += 1;
            }
            n
        })
    };

    // Hammer the lookup path while the zone is being swapped underneath it.
    let mut seen_a = 0u32;
    let mut seen_b = 0u32;
    for _ in 0..20_000 {
        let z = handler.zone();
        match z.lookup(
            &hickory_proto::rr::LowerName::from(
                format!("www.{ZONE}.").parse::<Name>().expect("name"),
            ),
            RecordType::A,
        ) {
            vega::zone::Answer::Records(records) => {
                assert_eq!(records.len(), 1, "a reload must never yield a partial set");
                match &records[0].data {
                    RData::A(a) if a.0.to_string() == "203.0.113.10" => seen_a += 1,
                    RData::A(a) if a.0.to_string() == "198.51.100.7" => seen_b += 1,
                    other => panic!("unexpected record during a reload: {other:?}"),
                }
            }
            other => panic!("a query in flight during a reload lost its answer: {other:?}"),
        }
    }

    stop.store(true, Ordering::Relaxed);
    let reloads = reloader.await.expect("reloader finishes");
    assert!(reloads > 0, "the reloader never ran");
    assert_eq!(seen_a + seen_b, 20_000);
}

/// The single A value the installed zone currently answers `name` with.
fn installed_a_value(handler: &DnsHandler, name: &hickory_proto::rr::LowerName) -> String {
    match handler.zone().lookup(name, RecordType::A) {
        vega::zone::Answer::Records(records) => match records.first().map(|r| &r.data) {
            Some(RData::A(a)) => a.0.to_string(),
            other => panic!("expected one A record, got {other:?}"),
        },
        other => panic!("expected records, got {other:?}"),
    }
}

/// Scenario: A config whose zone will not build is refused
/// features/live-reload.feature:321
///
/// VEGA-027. The previous version of this test never attempted a reload: it
/// asserted the fixture was broken and then asserted the handler was unchanged,
/// which passes against a `replace_zone` gutted to do nothing. It now performs a
/// real swap first — so gutting `replace_zone` fails it — and only then attempts
/// the swap that must not happen. The end-to-end version, through the real
/// `reload_hook` and `POST /reload`, is
/// `tests/reload.rs::a_reload_that_cannot_build_the_zone_is_zone_build_failed`.
#[tokio::test]
async fn a_failing_reload_leaves_the_previous_zone_in_place() {
    let cfg = zone_config(vec![spec("www", "A", &["203.0.113.10"])]);
    let zone = Arc::new(Zone::from_config(&cfg).expect("zone builds"));
    let handler = DnsHandler::new(zone, &cfg, Arc::new(Metrics::new()), None);
    let name =
        hickory_proto::rr::LowerName::from(format!("www.{ZONE}.").parse::<Name>().expect("name"));

    // The ordering `reload_hook` must follow: build the whole zone first, and
    // swap only if that succeeded, so a zone that does not build never reaches
    // the ArcSwap.
    let build_then_swap = |candidate: &vega::config::ZoneConfig| -> Result<(), String> {
        let fresh = Zone::from_config(candidate).map_err(|e| format!("{e:#}"))?;
        handler.replace_zone(Arc::new(fresh), candidate.builtins);
        Ok(())
    };

    let updated = zone_config(vec![
        spec("www", "A", &["198.51.100.7"]),
        spec("api", "A", &["198.51.100.8"]),
    ]);
    build_then_swap(&updated).expect("a good config reloads");
    assert_eq!(
        handler.zone().record_count(),
        2,
        "the good reload did not land"
    );
    assert_eq!(installed_a_value(&handler, &name), "198.51.100.7");

    // Now the reload that must not happen. `www` is also changed, so a
    // half-applied zone would be visible as well as a wholly replaced one.
    let broken = zone_config(vec![
        spec("www", "A", &["203.0.113.99"]),
        spec("bad", "A", &["not-an-ip"]),
    ]);
    let error = build_then_swap(&broken).expect_err("a broken config must be refused");
    assert!(error.contains("invalid A record value"), "{error}");

    assert_eq!(
        handler.zone().record_count(),
        2,
        "a refused reload replaced the serving zone"
    );
    assert_eq!(
        installed_a_value(&handler, &name),
        "198.51.100.7",
        "a refused reload half-applied its records"
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

// ---------------------------------------------------------------------------
// VEGA-083 — a wildcard-covered name exists for every QTYPE, on the wire.
//
// Spec: features/zone-lookup.feature, section "WILDCARD-COVERED NAMES";
//       features/wildcards.feature, section "WRONG TYPE".
// Ruling: .claude/backlog/decisions/VEGA-083-any-at-a-wildcard-covered-name.md
//
// These are on the wire deliberately. Both the reviewer's reproduction and the
// adversary's were UDP against a live handler, and what does the damage is the
// packet a resolver caches — an authoritative NXDOMAIN carrying our SOA, held
// for the SOA MINIMUM (RFC 2308 §5) and licensing subtree-wide denial (RFC 8020
// §2). An enum comparison cannot see the aa bit, the authority section, or the
// fact that the answer is cacheable at all.
//
// One zone for all four, `*.dev A 203.0.113.50`, so the asymmetry between the
// type the wildcard carries and every other type is what fails.
// ---------------------------------------------------------------------------

/// The zone both halves of VEGA-083 are observed against.
fn wildcard_records() -> Vec<RecordSpec> {
    vec![spec("*.dev", "A", &["203.0.113.50"])]
}

/// Scenario: A wildcard answers the type it carries
/// features/zone-lookup.feature:230
///
/// The positive control, and the reason the rest of this section cannot be
/// satisfied by never answering NXDOMAIN.
#[tokio::test]
async fn a_wildcard_still_answers_the_type_it_carries_over_the_wire() {
    let server = TestServer::start(wildcard_records(), None).await;

    let response = ask_udp(&server, &format!("x.dev.{ZONE}"), RecordType::A).await;

    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(response.metadata.authoritative, "AA must be set");
    assert_eq!(response.answers.len(), 1);
    assert_eq!(first_a(&response), "203.0.113.50");
    assert_eq!(
        response.answers[0].name.to_string(),
        format!("x.dev.{ZONE}."),
        "a synthesised answer must be owned by the queried name"
    );
}

/// Scenario Outline: A wildcard-covered name exists for every type, not only the
/// one the wildcard carries
/// features/zone-lookup.feature:240
/// Scenario: A wildcard of the wrong type produces NOERROR with the SOA over the
/// wire
/// features/wildcards.feature:118
///
/// THE REGRESSION TEST FOR THIS ISSUE. AAAA is checked first because it is the
/// half that fires without an attacker: every dual-stack client sends one
/// alongside every A, so before this fix the ordinary resolution of a covered
/// name emitted an authoritative NXDOMAIN as a matter of course, and the
/// wildcard's own live A record went out of service at any resolver that
/// happened to ask AAAA first.
///
/// The SOA assertion is kept from the scenario this replaces, not dropped with
/// the NXDOMAIN: RFC 2308 §3 requires the SOA on a NODATA answer exactly as on a
/// name error, and an uncacheable NODATA would be a second bug rather than a
/// fix.
#[tokio::test]
async fn a_wildcard_covered_name_is_noerror_over_the_wire_for_every_type_the_wildcard_lacks() {
    let server = TestServer::start(wildcard_records(), None).await;

    // The wildcard is live in this zone: without this the assertions below are
    // satisfied by a zone that synthesises nothing at all.
    let carried = ask_udp(&server, &format!("x.dev.{ZONE}"), RecordType::A).await;
    assert_eq!(
        carried.metadata.response_code,
        ResponseCode::NoError,
        "fixture check: `*.dev A` must answer A at the covered name"
    );

    for qtype in [
        RecordType::AAAA,
        RecordType::TXT,
        RecordType::MX,
        RecordType::SRV,
    ] {
        let response = ask_udp(&server, &format!("x.dev.{ZONE}"), qtype).await;

        assert_eq!(
            response.metadata.response_code,
            ResponseCode::NoError,
            "{qtype} at a wildcard-covered name came back {:?}. RFC 1034 §4.3.2 \
             step 3(c) sets the name error only when the `*` node does not \
             exist; as NXDOMAIN this is cached for the SOA MINIMUM (RFC 2308 §5) \
             and RFC 8020 §2 lets the resolver deny the whole subtree, including \
             the A record the wildcard does carry",
            response.metadata.response_code
        );
        assert!(
            response.answers.is_empty(),
            "{qtype} must be NODATA, not an answer of the wrong type: {:?}",
            response.answers
        );
        assert!(
            response.metadata.authoritative,
            "{qtype}: a NODATA answer from the zone's own authority must set AA"
        );
        assert_eq!(
            response
                .authorities
                .first()
                .map(hickory_proto::rr::Record::record_type),
            Some(RecordType::SOA),
            "{qtype}: RFC 2308 §3 requires the SOA in the authority section of a \
             NODATA answer, or the resolver cannot cache it and re-asks forever"
        );
    }
}

/// Scenario: An ANY query at a wildcard-covered name is NOERROR with the RFC
/// 8482 HINFO
/// features/zone-lookup.feature:257
///
/// The rcode here must equal the rcode for AAAA above. RFC 8482 §4.1/§4.2 change
/// what goes in the answer section and license no change to the existence
/// determination, so ANY and AAAA must be decided by the same computation.
#[tokio::test]
async fn an_any_query_at_a_wildcard_covered_name_is_noerror_with_one_hinfo_over_the_wire() {
    let server = TestServer::start(wildcard_records(), None).await;

    let response = ask_udp(&server, &format!("x.dev.{ZONE}"), RecordType::ANY).await;

    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(response.answers.len(), 1, "{:?}", response.answers);
    assert_eq!(response.answers[0].record_type(), RecordType::HINFO);
}

/// Scenario: A name with no source of synthesis is still NXDOMAIN
/// features/zone-lookup.feature:268
///
/// The negative control, on the wire and against the same zone. A fix that
/// widened the existence gate too far would pass every other test in this
/// section and quietly make the server authoritative for every label an attacker
/// can invent.
#[tokio::test]
async fn a_name_with_no_source_of_synthesis_is_still_nxdomain_over_the_wire() {
    let server = TestServer::start(wildcard_records(), None).await;

    for qtype in [RecordType::A, RecordType::AAAA, RecordType::ANY] {
        let response = ask_udp(&server, &format!("x.prod.{ZONE}"), qtype).await;

        assert_eq!(
            response.metadata.response_code,
            ResponseCode::NXDomain,
            "nothing covers x.prod.{ZONE}, so {qtype} there is a real name error"
        );
        assert_eq!(
            response
                .authorities
                .first()
                .map(hickory_proto::rr::Record::record_type),
            Some(RecordType::SOA),
            "{qtype}: a name error must stay cacheable"
        );
    }
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
