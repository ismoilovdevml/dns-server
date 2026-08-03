//! VEGA-067: what one query costs the allocator, end to end.
//!
//! **This binary contains exactly one test, on purpose** — the same rule
//! `tests/ratelimit_alloc.rs` states and for the same reason: a
//! `#[global_allocator]` counts the whole process, so a second test running
//! beside this one would be counted into it and the assertion would flake.
//!
//! The claim under test is not a number, it is a *shape*: the allocator cost of
//! answering a query must not depend on the length of the name in it. An
//! attacker picks that length, one packet at a time, up to RFC 1035 §2.3.4's
//! 255 octets. The regression this pins is a `to_string()` hoisted out of a
//! `debug!` that is switched off at the shipped log level — the `String` was
//! built and dropped untouched for every query the server ever answered, and it
//! grew with the name, so a 255-byte QNAME cost several times what a 15-byte one
//! did for a log line nobody was reading.
//!
//! The instrument is `stats_alloc`, a dev-dependency rather than a local
//! `impl GlobalAlloc`, because `unsafe_code = "forbid"` applies to every target
//! in this package and that is the lint working as intended.

use std::{
    alloc::System,
    future::Future as _,
    hint::black_box,
    net::SocketAddr,
    pin::pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use hickory_proto::{
    op::{Message, Query},
    rr::{DNSClass, Name, Record, RecordType},
};
use hickory_server::{
    net::{runtime::TokioTime, xfer::Protocol, NetError},
    server::{Request, RequestHandler as _, ResponseHandler, ResponseInfo},
    zone_handler::MessageResponse,
};
use stats_alloc::{Region, StatsAlloc, INSTRUMENTED_SYSTEM};
use vega::{
    config::{RecordSpec, SoaSpec, ZoneConfig},
    handler::DnsHandler,
    metrics::Metrics,
    ratelimit::RateLimiter,
    zone::Zone,
};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

/// Allocations one query may perform, measured after VEGA-067 landed.
///
/// A ceiling and not an equality: a later change that allocates *less* is not a
/// regression and must not turn CI red. The number is the negative-answer shape
/// below — a name error carrying the zone SOA — driven through the whole of
/// `handle_request` including the encode, so it counts the response buffer too.
const ALLOCATION_BUDGET: usize = 14;

/// A name error is the cheapest shape the server produces and the one an
/// attacker gets for free, since it needs no record in the zone to reach.
const SHORT_NAME: &str = "a.example.com.";

/// The same shape at the length an attacker would actually send: 82 labels,
/// 253 octets on the wire, two short of RFC 1035 §2.3.4's 255-octet ceiling.
///
/// `80 * 3` for the `ab` labels, plus `8 + 4` for `example.com` and one octet
/// for the root — each label is encoded as a length byte and its contents.
fn long_name() -> String {
    let mut name = String::with_capacity(256);
    for _ in 0..80 {
        name.push_str("ab.");
    }
    name.push_str("example.com.");
    name
}

/// A response handler that never touches a socket.
///
/// It runs the *real* encoder — the point is to count every allocation a query
/// causes, and the response buffer is one of them.
#[derive(Clone, Debug)]
struct Sink;

#[async_trait::async_trait]
impl ResponseHandler for Sink {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, NetError> {
        use hickory_proto::serialize::binary::BinEncoder;

        let mut bytes = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut bytes);
        encoder.set_max_size(512);
        let info = response
            .destructive_emit(&mut encoder)
            .expect("a name error plus its SOA fits in 512 bytes");
        black_box(&bytes);
        Ok(info)
    }
}

fn zone_config() -> ZoneConfig {
    ZoneConfig {
        origin: "example.com".to_owned(),
        default_ttl: 300,
        builtins: false,
        soa: Some(SoaSpec {
            mname: "ns1.example.com.".to_owned(),
            rname: "hostmaster.example.com.".to_owned(),
            serial: 1,
            refresh: 3600,
            retry: 900,
            expire: 604_800,
            minimum: 60,
        }),
        records: vec![RecordSpec {
            name: "@".to_owned(),
            record_type: "NS".to_owned(),
            ttl: None,
            values: vec!["ns1.example.com.".to_owned()],
        }],
    }
}

/// One UDP query for `name`, already decoded, so the fixture's own parsing is
/// not counted against the query it is measuring.
fn request(name: &str) -> Request {
    let mut owner: Name = name.parse().expect("fixture name parses");
    owner.set_fqdn(true);
    let mut query = Query::new();
    query
        .set_name(owner)
        .set_query_type(RecordType::A)
        .set_query_class(DNSClass::IN);
    let mut message = Message::query();
    message.add_query(query);

    let src: SocketAddr = "198.51.100.10:5353".parse().expect("source parses");
    Request::from_bytes(
        message.to_vec().expect("request encodes"),
        src,
        Protocol::Udp,
    )
    .expect("request decodes")
}

/// Drive one request to completion without a runtime.
///
/// `handle_request` awaits nothing that can pend here — the sink answers
/// inline — so a single poll with the no-op waker finishes it, and no executor
/// is left in the process to allocate on its own account.
fn serve(handler: &DnsHandler, request: &Request) -> ResponseInfo {
    let future = handler.handle_request::<Sink, TokioTime>(request, Sink);
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(info) => info,
        Poll::Pending => panic!("the sink answers inline, so the first poll must finish"),
    }
}

/// Serve `queries` copies of one request and report what they cost.
///
/// Returns (allocations, bytes, per-query wall time). A *reallocation* counts
/// as an allocation here: `String` growth is how the regression this file
/// guards actually manifested — six reallocs for a 253-octet name against two
/// for a short one — and `stats_alloc` books those in a separate field, so
/// counting only `allocations` would have watched the bug happen and reported
/// nothing.
fn measure(handler: &DnsHandler, request: &Request, queries: u32) -> (usize, usize, Duration) {
    let region = Region::new(GLOBAL);
    let started = Instant::now();
    for _ in 0..queries {
        black_box(serve(handler, black_box(request)));
    }
    let elapsed = started.elapsed() / queries;
    let stats = region.change();
    let count = stats.allocations + stats.reallocations;
    let bytes = stats.bytes_allocated;
    (count, bytes, elapsed)
}

/// Scenario: The cost of a query does not depend on the length of its name
/// features/zone-lookup.feature:82
///
/// VEGA-067. Two assertions, and both are needed: the ceiling stops the count
/// creeping up, and the equality is what actually pins the bug — the `String`
/// that was built per query grew with the QNAME, so an attacker set the cost
/// with a field they choose. A ceiling alone passes against a version that
/// allocates twice as much for a 247-octet name as for a 14-octet one, as long
/// as both stay under the bar.
#[test]
fn a_query_allocates_the_same_whatever_the_length_of_the_name_in_it() {
    const QUERIES: u32 = 5000;
    /// The same figure where a count is being divided by it.
    const N: usize = QUERIES as usize;

    let cfg = zone_config();
    let zone = Arc::new(Zone::from_config(&cfg).expect("zone builds"));
    let limiter: Option<Arc<RateLimiter>> = None;
    let handler = DnsHandler::new(zone, &cfg, Arc::new(Metrics::new()), limiter);

    // Everything the fixture allocates happens before a region opens.
    let short = request(SHORT_NAME);
    let long = request(&long_name());
    // Warm up both shapes before either is measured. The metrics histogram, the
    // allocator's own arenas and the first-touch page faults on this process's
    // heap are one-off costs, and charging them to whichever shape happens to
    // run first is how a timing comparison comes out backwards.
    for _ in 0..QUERIES {
        black_box(serve(&handler, &short));
        black_box(serve(&handler, &long));
    }

    let (short_cost, short_bytes, short_elapsed) = measure(&handler, &short, QUERIES);
    let (long_cost, long_bytes, long_elapsed) = measure(&handler, &long, QUERIES);

    println!(
        "short {SHORT_NAME:>16}: {:>3} allocs/query {:>5} B/query {short_elapsed:>10?}/query\n\
         long  {:>16}: {:>3} allocs/query {:>5} B/query {long_elapsed:>10?}/query",
        short_cost / N,
        short_bytes / N,
        format!("{} octets", long_name().len() + 1),
        long_cost / N,
        long_bytes / N,
    );

    assert_eq!(
        long_cost, short_cost,
        "{QUERIES} queries for a 253-octet name performed {long_cost} allocations \
         against {short_cost} for a 14-octet one. The QNAME is chosen by an attacker \
         one packet at a time, so anything that scales with it is a cost they set"
    );
    assert!(
        short_cost <= ALLOCATION_BUDGET * N,
        "{short_cost} allocations over {QUERIES} queries is more than the budget of \
         {ALLOCATION_BUDGET} per query"
    );
    // Bytes are printed, not asserted, and deliberately so. The long name really
    // does cost more bytes — but every one of them is inside the encoder, whose
    // name-compression table holds one entry per label emitted, and that is the
    // *sink's* buffer rather than anything the handler could borrow away.
    // Asserting equality here would be asserting that hickory does not compress
    // names, which is a different (and false) claim.
    assert!(
        long_bytes >= short_bytes,
        "sanity: the fixture measured {long_bytes} bytes for the long name and \
         {short_bytes} for the short one"
    );
}
