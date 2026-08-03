//! Protocol-conformance tests driven from the wire, one RFC clause per test.
//!
//! These came out of fuzzing a running server with hand-built packets. Three of
//! them were `#[ignore]`d as bugs that were live at the time: the server
//! answered, and answered wrongly. They are written to the RFC rather than to
//! the code, so they stayed meaningful across the fix.
//!
//! **Nothing here is `#[ignore]`d any more.** The empty-non-terminal pair came
//! off at VEGA-032 S2 (VEGA-006) and the wildcard closest-encloser test came off
//! at S3 (VEGA-009). `src/zone.rs::every_rfc_bug_this_model_fixes_is_green_and_none_of_them_is_ignored_again`
//! reads this file with `include_str!` and fails if one goes back on, in either
//! direction — a fence that covers the zone layer but not the wire is the same
//! bug wearing a green unit test.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{DNSClass, Name, RecordType},
};
use hickory_server::Server;
use tokio::net::UdpSocket;
use vega::{
    config::{RecordSpec, SoaSpec, ZoneConfig},
    handler::DnsHandler,
    metrics::Metrics,
    zone::Zone,
};

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
        builtins: false,
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

struct TestServer {
    udp: SocketAddr,
    _server: Server<DnsHandler>,
}

async fn start(records: Vec<RecordSpec>) -> TestServer {
    let cfg = zone_config(records);
    let zone = Arc::new(Zone::from_config(&cfg).expect("zone builds"));
    let handler = DnsHandler::new(zone, &cfg, Arc::new(Metrics::new()), None);
    let mut server = Server::new(handler);

    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("udp binds");
    let udp = socket.local_addr().expect("udp addr");
    server.register_socket(socket);

    TestServer {
        udp,
        _server: server,
    }
}

fn fqdn(name: &str) -> Name {
    let mut n: Name = name.parse().expect("name parses");
    n.set_fqdn(true);
    n
}

/// Ask a question with full control over qtype and qclass.
async fn ask(server: &TestServer, name: &str, qtype: RecordType, qclass: DNSClass) -> Message {
    let mut query = Query::new();
    query
        .set_name(fqdn(name))
        .set_query_type(qtype)
        .set_query_class(qclass);

    let mut message = Message::query();
    message.metadata.id = 0x4242;
    message.add_query(query);

    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("client binds");
    socket.connect(server.udp).await.expect("client connects");
    socket
        .send(&message.to_vec().expect("request encodes"))
        .await
        .expect("request sends");

    let mut buf = vec![0u8; 4096];
    let len = tokio::time::timeout(QUERY_TIMEOUT, socket.recv(&mut buf))
        .await
        .expect("server answers before the timeout")
        .expect("response reads");
    Message::from_vec(&buf[..len]).expect("response decodes")
}

// ---------------------------------------------------------------------------
// Passing today: the shape of a correct answer, pinned so it stays that way.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_in_class_query_is_answered_normally() {
    let server = start(vec![spec("www", "A", &["203.0.113.10"])]).await;
    let response = ask(&server, &format!("www.{ZONE}"), RecordType::A, DNSClass::IN).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(response.answers.len(), 1);
}

#[tokio::test]
async fn the_question_section_is_echoed_verbatim() {
    // RFC 1035 s4.1.2: the question must come back unchanged so a client can
    // match the reply to its outstanding query.
    let server = start(vec![spec("www", "A", &["203.0.113.10"])]).await;
    let response = ask(&server, &format!("www.{ZONE}"), RecordType::A, DNSClass::IN).await;
    let question = response.queries.first().expect("a question");
    assert_eq!(question.name(), &fqdn(&format!("www.{ZONE}")));
    assert_eq!(question.query_type(), RecordType::A);
    assert_eq!(question.query_class(), DNSClass::IN);
}

// ---------------------------------------------------------------------------
// Known bugs. Each of these was found by sending the packet to a running
// server built from vega.example.toml.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_query_in_another_class_is_not_answered_with_in_data() {
    // We are authoritative for one zone, in class IN. RFC 1035 s3.2.4 and
    // RFC 6895 s3.2: a class we do not serve is not ours to answer. The handler
    // only ever looks at `query.name()` and `query.query_type()` — see
    // DnsHandler::dispatch — so the class rides straight through, and the reply
    // echoes the question with QCLASS=CH while the answer records are class IN.
    // A caching resolver is entitled to file those records under CHAOS.
    //
    // Reproduced against vega.example.toml:
    //   qclass 3 (CHAOS) www.example.com A -> NOERROR, 3 answer records
    let server = start(vec![spec("www", "A", &["203.0.113.10"])]).await;

    for class in [
        DNSClass::CH,
        DNSClass::HS,
        DNSClass::NONE,
        DNSClass::Unknown(0),
        DNSClass::Unknown(65535),
    ] {
        let response = ask(&server, &format!("www.{ZONE}"), RecordType::A, class).await;
        assert!(
            response.answers.is_empty(),
            "class {class:?} was answered with {} class-IN records",
            response.answers.len()
        );
        assert!(
            matches!(
                response.metadata.response_code,
                ResponseCode::Refused | ResponseCode::NotImp | ResponseCode::FormErr
            ),
            "class {class:?} got rcode {:?}",
            response.metadata.response_code
        );
    }
}

#[tokio::test]
async fn meta_query_types_are_not_answered_as_ordinary_types() {
    // RFC 6891 s6.1.1: OPT must never appear in the question section.
    // RFC 8945 s5.1: TSIG is a meta-RR, not a queryable type.
    // RFC 5936 s4.2: AXFR is not defined over UDP.
    // RFC 6895 s3.1: TYPE0 is reserved.
    //
    // `Zone::resolve` applies the RFC 1034 s3.6.2 CNAME substitution rule to
    // every type it does not find, so on a CNAME owner these all come back
    // NOERROR with the CNAME in the answer section.
    //
    // Reproduced against vega.example.toml:
    //   qtype 41 (OPT) www.example.com -> NOERROR, 1 answer (the CNAME)
    //   qtype 252 (AXFR) www.example.com -> NOERROR, 1 answer (the CNAME)
    let server = start(vec![
        spec("alias", "CNAME", &[&format!("origin.{ZONE}.")]),
        spec("origin", "A", &["203.0.113.20"]),
    ])
    .await;

    for qtype in [
        RecordType::OPT,
        RecordType::TSIG,
        RecordType::IXFR,
        RecordType::AXFR,
        RecordType::Unknown(0),
        // RFC 1035 s3.2.3 numbers the QTYPE-only mail types MAILB 253 and
        // MAILA 254. hickory has no variant for either — `RecordType::from`
        // ends in `_ => Self::Unknown(value)` — so they arrive here as
        // `Unknown`, which is how they slipped past the first fix and were
        // answered with the CNAME.
        RecordType::Unknown(253),
        RecordType::Unknown(254),
    ] {
        let response = ask(&server, &format!("alias.{ZONE}"), qtype, DNSClass::IN).await;
        assert!(
            response.answers.is_empty(),
            "meta type {qtype:?} was answered with {} records",
            response.answers.len()
        );
        assert!(
            matches!(
                response.metadata.response_code,
                ResponseCode::FormErr | ResponseCode::NotImp | ResponseCode::Refused
            ),
            "meta type {qtype:?} got rcode {:?}",
            response.metadata.response_code
        );
    }
}

#[tokio::test]
async fn an_unsupported_edns_version_is_answered_badvers() {
    // RFC 6891 s6.1.3: a responder that does not implement the version in the
    // request MUST answer with RCODE=BADVERS (16) and its own highest supported
    // version, and MUST NOT answer the question. `handle_request` builds the
    // response EDNS unconditionally with `set_version(0)` and never looks at
    // `req.version()`.
    //
    // Reproduced against vega.example.toml:
    //   EDNS version 1   -> NOERROR, 3 answers
    //   EDNS version 255 -> NOERROR, 3 answers
    let server = start(vec![spec("www", "A", &["203.0.113.10"])]).await;

    for version in [1u8, 2, 255] {
        let mut message = Message::query();
        message.metadata.id = 0x4242;
        message.add_query(Query::query(fqdn(&format!("www.{ZONE}")), RecordType::A));
        let mut edns = hickory_proto::op::Edns::new();
        edns.set_version(version);
        edns.set_max_payload(4096);
        message.set_edns(edns);

        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("client binds");
        socket.connect(server.udp).await.expect("connects");
        socket
            .send(&message.to_vec().expect("encodes"))
            .await
            .expect("sends");
        let mut buf = vec![0u8; 4096];
        let len = tokio::time::timeout(QUERY_TIMEOUT, socket.recv(&mut buf))
            .await
            .expect("server answers")
            .expect("reads");
        let response = Message::from_vec(&buf[..len]).expect("decodes");

        assert!(
            response.answers.is_empty(),
            "EDNS version {version} was answered with {} records",
            response.answers.len()
        );
        // Extended RCODE 16 is BADVERS in RFC 6891 §9 and BADSIG in RFC 8945
        // §4.3 — one number, two names, and hickory decodes it to the TSIG one.
        // Assert the value that is actually on the wire rather than the spelling
        // the decoder happens to pick.
        assert_eq!(
            u16::from(response.metadata.response_code),
            16,
            "EDNS version {version} must be answered with extended RCODE 16 (BADVERS), got {:?}",
            response.metadata.response_code
        );
    }
}

/// Scenario: An empty non-terminal answers NOERROR with the SOA in the
/// authority section over the wire
/// features/empty-non-terminals.feature:137
///
/// Un-`#[ignore]`d at VEGA-032 S2, which closes VEGA-006.
#[tokio::test]
async fn an_empty_non_terminal_answers_nodata_over_the_wire() {
    // The wire-level counterpart of the zone unit test. This matters more than
    // it looks: RFC 8020 lets a resolver that has cached NXDOMAIN for
    // `ent.example.test` answer NXDOMAIN for everything below it, which takes
    // the record that does exist out of service.
    //
    // The SOA in the authority section is not decoration either: RFC 2308 §3
    // requires it for a negative answer to be cacheable at all, and §5 makes its
    // MINIMUM the lifetime. Without it every miss comes back — which is the load
    // profile a random-subdomain flood wants.
    let server = start(vec![spec("a.b.ent", "A", &["203.0.113.41"])]).await;

    for name in [format!("ent.{ZONE}"), format!("b.ent.{ZONE}")] {
        let response = ask(&server, &name, RecordType::A, DNSClass::IN).await;
        assert_eq!(
            response.metadata.response_code,
            ResponseCode::NoError,
            "{name} is an empty non-terminal, so it exists"
        );
        assert!(response.answers.is_empty());
        assert_eq!(
            response
                .authorities
                .first()
                .map(hickory_proto::rr::Record::record_type),
            Some(RecordType::SOA)
        );
    }
}

/// Scenario: Asking for the empty non-terminal first does not deny the record
/// beneath it
/// features/empty-non-terminals.feature:148
///
/// AC-2.5 — RFC 8020 §2 as an experiment rather than as a citation, and the
/// reason VEGA-006 is a blocker rather than a conformance nit.
///
/// The ORDER is the test. A resolver that asks for the service name before the
/// instance name — which is what walking down from the apex does, and what a
/// human debugging with `dig` does — gets an authoritative NXDOMAIN today,
/// caches it for the SOA MINIMUM (RFC 2308 §5), and is then licensed by RFC 8020
/// §2 to answer NXDOMAIN for everything beneath it. The SRV record that is
/// configured and serving goes out of service without anything having changed.
///
/// Two queries, one server, in sequence, over UDP: the first must be NOERROR
/// with an empty answer section and the second must carry the record.
#[tokio::test]
async fn asking_for_the_empty_non_terminal_first_does_not_deny_the_record_beneath_it() {
    let server = start(vec![spec(
        "_sip._tcp",
        "SRV",
        &["10 10 5060 sip.example.test."],
    )])
    .await;

    let parent = ask(
        &server,
        &format!("_tcp.{ZONE}"),
        RecordType::SRV,
        DNSClass::IN,
    )
    .await;
    assert_eq!(
        parent.metadata.response_code,
        ResponseCode::NoError,
        "_tcp.{ZONE} exists because _sip._tcp.{ZONE} does (RFC 4592 §2.2.2); an \
         NXDOMAIN here is cached and, under RFC 8020 §2, denies the SRV below it"
    );
    assert!(
        parent.answers.is_empty(),
        "an empty non-terminal holds no records of any type"
    );
    assert_eq!(
        parent
            .authorities
            .first()
            .map(hickory_proto::rr::Record::record_type),
        Some(RecordType::SOA),
        "RFC 2308 §3: the SOA is what makes the negative answer cacheable"
    );

    let child = ask(
        &server,
        &format!("_sip._tcp.{ZONE}"),
        RecordType::SRV,
        DNSClass::IN,
    )
    .await;
    assert_eq!(child.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        child.answers.len(),
        1,
        "the configured SRV must still answer after its parent was asked for"
    );
    assert_eq!(child.answers[0].record_type(), RecordType::SRV);
}

/// VEGA-009, closed at VEGA-032 S3, over the wire.
///
/// The `#[ignore]` came off in the commit that installed the closest-encloser
/// search. `src/zone.rs::every_rfc_bug_this_model_fixes_is_green_and_none_of_them_is_ignored_again`
/// reads this file with `include_str!` and fails if it goes back on: a zone layer
/// that answers NXDOMAIN while the handler renders NOERROR is the same bug
/// wearing a green unit test, so the fence has to cover both files or it covers
/// neither.
#[tokio::test]
async fn a_wildcard_does_not_reach_below_a_name_that_exists() {
    // `deep.apps.example.test` exists, so it is the closest encloser of
    // `a.deep.apps.example.test`. The source of synthesis is therefore
    // `*.deep.apps.example.test`, which does not exist, and RFC 4592 §3.3.1
    // permits no search for an alternate — so the answer is NXDOMAIN.
    let server = start(vec![
        spec("*.apps", "A", &["203.0.113.30"]),
        spec("deep.apps", "A", &["203.0.113.31"]),
    ])
    .await;

    let response = ask(
        &server,
        &format!("a.deep.apps.{ZONE}"),
        RecordType::A,
        DNSClass::IN,
    )
    .await;
    assert_eq!(
        response.metadata.response_code,
        ResponseCode::NXDomain,
        "the wildcard leaked underneath an existing name: {:?}",
        response.answers
    );
}
