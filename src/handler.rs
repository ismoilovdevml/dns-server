//! The [`RequestHandler`] implementation: validation, rate limiting, zone
//! lookup, the diagnostic built-in sub-zones, and response assembly.

use std::{net::IpAddr, sync::Arc, time::Instant};

use arc_swap::ArcSwap;

use hickory_proto::{
    op::{Edns, Header, HeaderCounts, MessageType, Metadata, OpCode, ResponseCode},
    rr::{
        rdata::{A, AAAA, HINFO, TXT},
        DNSClass, LowerName, Name, RData, Record, RecordType,
    },
    serialize::binary::BinEncodable as _,
};
use hickory_server::{
    net::{runtime::Time, xfer::Protocol},
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    zone_handler::MessageResponseBuilder,
};
use tracing::{debug, error, warn};

use crate::{
    config::ZoneConfig,
    metrics::{Metrics, Transport},
    ratelimit::RateLimiter,
    zone::{Answer, Zone},
};

/// Reused for the response sections we never populate.
const NO_RECORDS: &[Record] = &[];

/// Minimum EDNS payload size we will advertise, per RFC 6891.
const MIN_EDNS_PAYLOAD: u16 = 512;

/// Ceiling on the EDNS payload we will honour, whatever the client advertises.
///
/// 1232 is the DNS Flag Day 2020 figure: it fits inside the smallest plausible
/// path MTU without IP fragmentation. Mirroring the client's number unclamped
/// lets an attacker choose our amplification factor — advertising 8192 turned a
/// 40-byte query into an 8142-byte answer, 203x, before this cap existed.
const MAX_EDNS_PAYLOAD: u16 = 1232;

/// Largest UDP response we will send to a client that offered no EDNS at all.
///
/// RFC 1035 §4.2.1. Hickory sizes a non-EDNS UDP response from its 4096-byte
/// receive buffer instead, which made every plain query a 124x amplifier, so we
/// enforce the limit ourselves rather than inheriting that default.
const MAX_UDP_NO_EDNS: usize = 512;

/// QTYPE 253, "a request for mailbox-related records (MB, MG or MR)".
///
/// RFC 1035 §3.2.3 defines it as a QTYPE, never a TYPE; RFC 973 withdrew the
/// service behind it. Spelled as a number because hickory has no variant for it
/// — `RecordType::from(u16)` ends `_ => Self::Unknown(value)`, so this is
/// exactly how it arrives off the wire, and matching a named variant here would
/// silently never fire.
const MAILB_QTYPE: RecordType = RecordType::Unknown(253);

/// QTYPE 254, "a request for mail agent RRs (Obsolete - see MX)".
///
/// RFC 1035 §3.2.3, and see [`MAILB_QTYPE`] for why it is a raw number. Note the
/// ordering is the one the RFC gives and not alphabetical: MAILB is 253 and
/// MAILA is 254.
const MAILA_QTYPE: RecordType = RecordType::Unknown(254);

/// DNS header, fixed size. RFC 1035 §4.1.1.
const HEADER_SIZE: usize = 12;

/// QTYPE + QCLASS following the QNAME in a question. RFC 1035 §4.1.2.
const QUESTION_FIXED: usize = 4;

/// TYPE + CLASS + TTL + RDLENGTH preceding a record's RDATA. RFC 1035 §4.1.3.
const RECORD_FIXED: usize = 10;

/// Fallback RDATA size used when a record cannot be encoded to measure it.
///
/// Deliberately the largest an RDATA can be. An under-count here is not a
/// pessimisation, it is the 512-byte cap silently not applying — which is
/// exactly how a 663-byte TLSA answer went out with TC clear when this was 256.
const RDATA_BOUND_FALLBACK: usize = u16::MAX as usize;

/// The diagnostic sub-zones. Handy for smoke-testing a deployment; disable them
/// with `--no-builtins` if you would rather not expose server internals.
#[derive(Clone, Debug)]
struct Builtins {
    hello: LowerName,
    counter: LowerName,
    myip: LowerName,
    version: LowerName,
    ttl: u32,
}

impl Builtins {
    fn new(origin: &LowerName, ttl: u32) -> Option<Self> {
        let origin = Name::from(origin.clone());
        let sub = |label: &str| -> Option<LowerName> {
            Name::parse(label, Some(&origin)).ok().map(LowerName::from)
        };
        Some(Self {
            hello: sub("hello")?,
            counter: sub("counter")?,
            myip: sub("myip")?,
            version: sub("version")?,
            ttl,
        })
    }
}

/// What a query resolved to, before it is serialised.
#[derive(Debug)]
struct Resolved {
    code: ResponseCode,
    answers: Vec<Record>,
    /// Records for the authority section — the zone SOA on a negative answer.
    authority: Vec<Record>,
    authoritative: bool,
}

impl Resolved {
    fn found(answers: Vec<Record>) -> Self {
        Self {
            code: ResponseCode::NoError,
            answers,
            authority: Vec::new(),
            authoritative: true,
        }
    }

    fn negative(code: ResponseCode, soa: Option<&Record>) -> Self {
        Self {
            code,
            answers: Vec::new(),
            authority: soa.cloned().into_iter().collect(),
            authoritative: true,
        }
    }

    fn refused() -> Self {
        Self {
            code: ResponseCode::Refused,
            answers: Vec::new(),
            authority: Vec::new(),
            authoritative: false,
        }
    }

    fn error(code: ResponseCode) -> Self {
        Self {
            code,
            answers: Vec::new(),
            authority: Vec::new(),
            authoritative: false,
        }
    }
}

/// The zone plus the built-in names derived from it, swapped as one unit so a
/// reload can never leave the two disagreeing about the origin.
#[derive(Debug)]
struct Active {
    zone: Arc<Zone>,
    builtins: Option<Builtins>,
}

impl Active {
    fn new(zone: Arc<Zone>, builtins_enabled: bool) -> Self {
        let builtins = if builtins_enabled {
            let b = Builtins::new(zone.origin(), zone.default_ttl());
            if b.is_none() {
                warn!(
                    origin = %zone.origin(),
                    "could not derive built-in sub-zone names; built-ins disabled"
                );
            }
            b
        } else {
            None
        };
        Self { zone, builtins }
    }
}

/// Serves a single authoritative zone.
///
/// The zone sits behind an [`ArcSwap`] so a reload can install a new one with no
/// lock on the query path: a request that already loaded the previous zone
/// finishes against it, and the next request sees the new one.
#[derive(Debug)]
pub struct DnsHandler {
    active: ArcSwap<Active>,
    metrics: Arc<Metrics>,
    limiter: Option<Arc<RateLimiter>>,
}

impl DnsHandler {
    /// Assemble a handler from a zone and the shared runtime pieces.
    pub fn new(
        zone: Arc<Zone>,
        cfg: &ZoneConfig,
        metrics: Arc<Metrics>,
        limiter: Option<Arc<RateLimiter>>,
    ) -> Self {
        Self {
            active: ArcSwap::from_pointee(Active::new(zone, cfg.builtins)),
            metrics,
            limiter,
        }
    }

    /// Install a new zone. Queries already in flight keep serving the old one.
    pub fn replace_zone(&self, zone: Arc<Zone>, builtins_enabled: bool) {
        self.active
            .store(Arc::new(Active::new(zone, builtins_enabled)));
    }

    /// A snapshot of the zone currently being served.
    pub fn zone(&self) -> Arc<Zone> {
        Arc::clone(&self.active.load().zone)
    }

    /// Resolve a query. Split out from [`RequestHandler::handle_request`] so it
    /// can be exercised without a socket.
    fn resolve(&self, name: &LowerName, qtype: RecordType, src: IpAddr) -> Resolved {
        // Load once per query: every branch below must agree on which zone it is
        // answering from.
        let active = self.active.load();
        let zone = &active.zone;

        if !zone.contains(name) {
            // We are authoritative for one zone only; anything else is not ours
            // to answer. REFUSED is the honest response code — NXDOMAIN would be
            // a claim about a namespace we know nothing about.
            return Resolved::refused();
        }

        if let Some(resolved) = self.resolve_builtin(&active, name, qtype, src) {
            return resolved;
        }

        // RFC 8482: answer ANY with one synthetic HINFO rather than everything we
        // hold at the name. Returning the whole node made ANY both the largest
        // response we could produce and — because the old lookup scanned every
        // RRset in the zone to assemble it — the most expensive. An attacker got
        // to pick both with a 29-byte packet.
        if qtype.is_any() {
            if !zone.has_name(name) {
                return Resolved::negative(ResponseCode::NXDomain, zone.soa());
            }
            // RFC 8482 §4.2 permits synthesis only when there is no CNAME at the
            // owner name, and §4.1 names the CNAME as the RRset worth returning.
            // Anything using ANY to discover an alias must still find it.
            if let Answer::Records(cnames) = zone.lookup(name, RecordType::CNAME) {
                if !cnames.is_empty() {
                    return Resolved::found(cnames);
                }
            }
            return Resolved::found(vec![minimal_any(
                Name::from(name.clone()),
                zone.default_ttl(),
            )]);
        }

        // A zone-level SOA (from `[zone.soa]`) is not part of the record map, so
        // answer apex SOA queries from it directly.
        if qtype == RecordType::SOA && name == zone.origin() {
            if let Some(soa) = zone.soa() {
                return Resolved::found(vec![soa.clone()]);
            }
        }

        match zone.lookup(name, qtype) {
            Answer::Records(records) if records.is_empty() => {
                Resolved::negative(ResponseCode::NoError, zone.soa())
            }
            Answer::Records(records) => Resolved::found(records),
            Answer::NoData => Resolved::negative(ResponseCode::NoError, zone.soa()),
            Answer::NxDomain => Resolved::negative(ResponseCode::NXDomain, zone.soa()),
        }
    }

    /// Handle the diagnostic sub-zones, if enabled and matching.
    fn resolve_builtin(
        &self,
        active: &Active,
        name: &LowerName,
        qtype: RecordType,
        src: IpAddr,
    ) -> Option<Resolved> {
        let b = active.builtins.as_ref()?;
        let soa = active.zone.soa();
        let qname = Name::from(name.clone());

        if b.myip.zone_of(name) {
            let (rdata, wanted) = match src {
                IpAddr::V4(v4) => (RData::A(A(v4)), RecordType::A),
                IpAddr::V6(v6) => (RData::AAAA(AAAA(v6)), RecordType::AAAA),
            };
            if qtype == wanted || qtype == RecordType::ANY {
                return Some(Resolved::found(vec![Record::from_rdata(
                    qname, b.ttl, rdata,
                )]));
            }
            return Some(Resolved::negative(ResponseCode::NoError, soa));
        }

        if b.counter.zone_of(name) {
            let count = self.metrics.queries().to_string();
            return Some(txt_builtin(qname, qtype, b.ttl, count, soa));
        }

        if b.version.zone_of(name) {
            let build = format!("{} {}", crate::NAME, crate::VERSION);
            return Some(txt_builtin(qname, qtype, b.ttl, build, soa));
        }

        if b.hello.zone_of(name) {
            let text = greeting(&qname, &b.hello);
            return Some(txt_builtin(qname, qtype, b.ttl, text, soa));
        }

        None
    }

    /// Validate the request and turn it into a [`Resolved`].
    ///
    /// `None` means send nothing at all. That is only ever the rate limiter on
    /// UDP: answering a query we have decided to drop still delivers a packet to
    /// whatever address the attacker forged, so a limiter that replies is not an
    /// anti-reflection control.
    fn dispatch(&self, request: &Request, src: IpAddr) -> Option<Resolved> {
        if let Some(limiter) = &self.limiter {
            if !limiter.check(src) {
                self.metrics.rate_limited();
                if request.protocol() == Protocol::Udp {
                    debug!(%src, "query dropped by rate limiter");
                    return None;
                }
                // TCP completed a handshake, so the source is not forged and a
                // reply cannot be reflected at a third party. Answer honestly.
                debug!(%src, "query refused by rate limiter (tcp)");
                return Some(Resolved::refused());
            }
        }

        if request.metadata.message_type != MessageType::Query {
            return Some(Resolved::error(ResponseCode::FormErr));
        }

        if request.metadata.op_code != OpCode::Query {
            // We are a static authoritative server: no dynamic UPDATE, no NOTIFY.
            debug!(op_code = ?request.metadata.op_code, "unsupported op code");
            return Some(Resolved::error(ResponseCode::NotImp));
        }

        // RFC 6891 §6.1.3: an OPT we do not understand is answered BADVERS with
        // the highest version we do support, not silently treated as version 0.
        if let Some(edns) = request.edns.as_ref() {
            if edns.version() > 0 {
                debug!(version = edns.version(), "unsupported EDNS version");
                return Some(Resolved::error(ResponseCode::BADVERS));
            }
        }

        // RFC 1035 allows QDCOUNT > 1 but no implementation supports it, and 0
        // makes no sense for a query.
        let [query] = request.queries.queries() else {
            return Some(Resolved::error(ResponseCode::FormErr));
        };

        // We hold IN data only. Answering a CHAOS or HESIOD query from it is a
        // spec violation, and it hands an attacker four extra reflector
        // signatures that any IDS rule keyed on QCLASS=IN will miss.
        if query.query_class() != DNSClass::IN {
            debug!(class = %query.query_class(), "unsupported query class");
            return Some(Resolved::refused());
        }

        // RFC 6895 §3.1 separates QTYPEs from TYPEs. Meta types are transaction
        // requests, not names to look up — feeding them to the zone is why AXFR
        // used to answer NOERROR with an empty body, which every secondary reads
        // as a broken transfer rather than a refusal.
        match query.query_type() {
            RecordType::AXFR | RecordType::IXFR => {
                debug!(qtype = %query.query_type(), "zone transfer requested but not implemented");
                return Some(Resolved::refused());
            }
            // OPT is only ever a pseudo-record in the additional section, TSIG
            // only ever a transaction signature, and QTYPE 0 is reserved
            // (RFC 6895 §3.1). None of them names anything to look up — and the
            // CNAME substitution rule at src/zone.rs would otherwise answer all
            // three with a CNAME whenever the owner happened to have one.
            // Note QTYPE 0 arrives as `ZERO`, not `Unknown(0)` — hickory maps the
            // value on decode, so matching `Unknown(0)` here would never fire.
            RecordType::OPT | RecordType::TSIG | RecordType::ZERO => {
                return Some(Resolved::error(ResponseCode::FormErr));
            }
            // MAILB and MAILA are QTYPE-only (RFC 1035 §3.2.3) and the service
            // they asked about was withdrawn by RFC 973, so there is no type to
            // look up and never will be: NOTIMP, not REFUSED, which would claim
            // the zone is someone else's. They reach us as `Unknown` rather than
            // as variants — see MAILB_QTYPE — which is how they escaped the
            // first pass at this and kept answering with the owner's CNAME.
            MAILB_QTYPE | MAILA_QTYPE => {
                debug!(qtype = %query.query_type(), "obsolete mail meta query");
                return Some(Resolved::error(ResponseCode::NotImp));
            }
            _ => {}
        }

        Some(self.resolve(query.name(), query.query_type(), src))
    }
}

#[async_trait::async_trait]
impl RequestHandler for DnsHandler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let started = Instant::now();
        let src = request.src();
        let transport = transport_of(request.protocol());
        self.metrics.query(transport);

        let Some(mut resolved) = self.dispatch(request, src.ip()) else {
            // Rate-limited on UDP: deliberately silent, so the forged source
            // receives nothing at all.
            self.metrics.observe_latency(started.elapsed());
            return dropped(&request.metadata);
        };

        // Mirror the request's EDNS so a resolver that offered a large UDP
        // payload gets one — but clamp it. The client picks the number, and an
        // unclamped mirror lets it pick our amplification factor with it.
        let resp_edns = request.edns.as_ref().map(|req| {
            let mut edns = Edns::new();
            edns.set_max_payload(req.max_payload().clamp(MIN_EDNS_PAYLOAD, MAX_EDNS_PAYLOAD));
            edns.set_version(0);
            edns
        });

        // A client that offered no EDNS gets 512 bytes (RFC 1035 §4.2.1). We
        // cannot leave this to the encoder: hickory sizes a non-EDNS UDP
        // response from its 4096-byte receive buffer, and we must not attach an
        // OPT record to say otherwise (RFC 6891 §6.1.1 forbids one in a reply to
        // a query that carried none). So drop the answer section ourselves and
        // set TC, which is what tells the client to come back over TCP.
        let mut truncated = false;
        if request.protocol() == Protocol::Udp
            && resp_edns.is_none()
            && response_size_bound(request, &resolved) > MAX_UDP_NO_EDNS
        {
            resolved.answers.clear();
            resolved.authority.clear();
            truncated = true;
        }

        let mut metadata = Metadata::response_from_request(&request.metadata);
        metadata.authoritative = resolved.authoritative;
        metadata.response_code = resolved.code;
        metadata.truncation = truncated;

        let mut builder = MessageResponseBuilder::from_message_request(request);
        if let Some(edns) = resp_edns.as_ref() {
            builder.edns(edns);
        }
        let response = builder.build(
            metadata,
            &resolved.answers,
            &resolved.authority,
            NO_RECORDS,
            NO_RECORDS,
        );

        let outcome = response_handle.send_response(response).await;
        let elapsed = started.elapsed();
        self.metrics.observe_latency(elapsed);
        // Record what actually went on the wire, not what we intended. An answer
        // that fails to encode is sent as SERVFAIL, and counting our own
        // intention here left the servfail series reading zero during exactly
        // the attack it exists to reveal.
        self.metrics.response(match &outcome {
            Ok(info) => info.response_code,
            Err(_) => ResponseCode::ServFail,
        });

        let qname = request
            .queries
            .queries()
            .first()
            .map(|q| q.name().to_string())
            .unwrap_or_default();

        match outcome {
            Ok(info) => {
                debug!(
                    %src,
                    ?transport,
                    query = %qname,
                    rcode = %resolved.code,
                    answers = resolved.answers.len(),
                    duration_us = elapsed.as_micros(),
                    "query handled"
                );
                info
            }
            Err(error) => {
                self.metrics.send_error();
                error!(%src, query = %qname, %error, "failed to send response");
                serve_failed(&request.metadata)
            }
        }
    }
}

/// The synthetic answer to a QTYPE=ANY query, per RFC 8482 §4.1.
///
/// One HINFO whose CPU field names the RFC, so an operator who packet-captures
/// this can find out in one search why they did not get the whole node.
fn minimal_any(owner: Name, ttl: u32) -> Record {
    Record::from_rdata(
        owner,
        ttl,
        RData::HINFO(HINFO::new("RFC8482".to_owned(), String::new())),
    )
}

/// Upper bound on the wire size of the response we are about to build.
///
/// Deliberately ignores name compression and rounds unknown RDATA up, because
/// this only decides whether a non-EDNS UDP answer fits in 512 bytes. Guessing
/// high costs a TCP retry; guessing low emits an oversized datagram at whoever
/// the attacker named as the source.
fn response_size_bound(request: &Request, resolved: &Resolved) -> usize {
    let question = request
        .queries
        .queries()
        .first()
        .map_or(0, |q| q.name().len() + 1 + QUESTION_FIXED);

    HEADER_SIZE
        + question
        + resolved
            .answers
            .iter()
            .chain(resolved.authority.iter())
            .map(record_size_bound)
            .sum::<usize>()
}

/// Upper bound on one record's wire size, owner name uncompressed.
fn record_size_bound(record: &Record) -> usize {
    record.name.len() + 1 + RECORD_FIXED + rdata_size_bound(&record.data)
}

/// Upper bound on an RDATA's wire size.
///
/// The arms are the types a zone is mostly made of, sized arithmetically so the
/// common path allocates nothing. Everything else is *measured* rather than
/// guessed: TLSA, CAA, SVCB, HTTPS, NAPTR, CERT and friends all carry
/// operator-supplied blobs that run to kilobytes, and a guess that comes in low
/// defeats the cap entirely. Measuring costs one allocation, on the non-EDNS
/// UDP path only, for record types most zones never serve.
fn rdata_size_bound(rdata: &RData) -> usize {
    match rdata {
        RData::A(_) => 4,
        RData::AAAA(_) => 16,
        RData::NS(ns) => ns.0.len() + 1,
        RData::CNAME(cname) => cname.0.len() + 1,
        RData::PTR(ptr) => ptr.0.len() + 1,
        // preference + exchange
        RData::MX(mx) => 2 + mx.exchange.len() + 1,
        // priority + weight + port + target
        RData::SRV(srv) => 6 + srv.target.len() + 1,
        // mname + rname + five 32-bit fields
        RData::SOA(soa) => soa.mname.len() + 1 + soa.rname.len() + 1 + 20,
        // each character-string carries a one-byte length prefix
        RData::TXT(txt) => txt.txt_data.iter().map(|s| s.len() + 1).sum(),
        RData::HINFO(hinfo) => hinfo.cpu.len() + 1 + hinfo.os.len() + 1,
        other => other
            .to_bytes()
            .map_or(RDATA_BOUND_FALLBACK, |bytes| bytes.len()),
    }
}

/// Build a [`ResponseInfo`] for a request we answered with silence.
///
/// `handle_request` must return one even when nothing goes on the wire.
fn dropped(request_meta: &Metadata) -> ResponseInfo {
    let mut metadata = Metadata::response_from_request(request_meta);
    metadata.response_code = ResponseCode::Refused;
    ResponseInfo::from(Header {
        metadata,
        counts: HeaderCounts {
            queries: 0,
            answers: 0,
            authorities: 0,
            additionals: 0,
        },
    })
}

/// Build a `SERVFAIL` [`ResponseInfo`] for a request we could not answer.
fn serve_failed(request_meta: &Metadata) -> ResponseInfo {
    let mut metadata = Metadata::response_from_request(request_meta);
    metadata.response_code = ResponseCode::ServFail;
    ResponseInfo::from(Header {
        metadata,
        counts: HeaderCounts {
            queries: 0,
            answers: 0,
            authorities: 0,
            additionals: 0,
        },
    })
}

/// Answer a TXT-only built-in, or NODATA when the client asked for another type.
fn txt_builtin(
    qname: Name,
    qtype: RecordType,
    ttl: u32,
    text: String,
    soa: Option<&Record>,
) -> Resolved {
    if qtype == RecordType::TXT || qtype == RecordType::ANY {
        Resolved::found(vec![Record::from_rdata(
            qname,
            ttl,
            RData::TXT(TXT::new(vec![text])),
        )])
    } else {
        Resolved::negative(ResponseCode::NoError, soa)
    }
}

fn transport_of(protocol: Protocol) -> Transport {
    if protocol == Protocol::Udp {
        Transport::Udp
    } else if protocol == Protocol::Tcp {
        Transport::Tcp
    } else {
        Transport::Other
    }
}

/// `ismoilovdev.hello.example.com` -> `hello, ismoilovdev`.
fn greeting(qname: &Name, hello_zone: &LowerName) -> String {
    let extra = usize::from(qname.num_labels().saturating_sub(hello_zone.num_labels()));
    if extra == 0 {
        return "hello, world".to_owned();
    }
    let labels = qname
        .iter()
        .take(extra)
        .map(|label| String::from_utf8_lossy(label).into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    format!("hello, {labels}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RecordSpec, SoaSpec, ZoneConfig};

    fn zone_config(records: Vec<RecordSpec>, builtins: bool) -> ZoneConfig {
        ZoneConfig {
            origin: "example.com".to_owned(),
            default_ttl: 300,
            builtins,
            soa: Some(SoaSpec {
                mname: "ns1.example.com.".to_owned(),
                rname: "hostmaster.example.com.".to_owned(),
                serial: 1,
                refresh: 3600,
                retry: 900,
                expire: 604_800,
                minimum: 60,
            }),
            records,
        }
    }

    fn handler(records: Vec<RecordSpec>, builtins: bool) -> DnsHandler {
        let cfg = zone_config(records, builtins);
        let zone = Arc::new(Zone::from_config(&cfg).unwrap());
        DnsHandler::new(zone, &cfg, Arc::new(Metrics::new()), None)
    }

    fn spec(name: &str, ty: &str, values: &[&str]) -> RecordSpec {
        RecordSpec {
            name: name.to_owned(),
            record_type: ty.to_owned(),
            ttl: None,
            values: values.iter().map(|v| (*v).to_owned()).collect(),
        }
    }

    fn lower(name: &str) -> LowerName {
        let mut n: Name = name.parse().unwrap();
        n.set_fqdn(true);
        LowerName::from(n)
    }

    fn client() -> IpAddr {
        "198.51.100.10".parse().unwrap()
    }

    fn txt_value(record: &Record) -> String {
        match &record.data {
            RData::TXT(txt) => txt
                .txt_data
                .iter()
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .collect(),
            other => panic!("expected TXT, got {other:?}"),
        }
    }

    /// Scenario: The size estimate never under-counts a record
    /// features/edns-and-transport.feature — "A spoofable query does not receive
    /// an answer larger than the advertised limit"
    ///
    /// The whole 512-byte cap rests on this bound being an *upper* one. It was
    /// not: a fixed 256-byte fallback let a TLSA record through at 663 bytes
    /// with TC clear, which is the amplifier the cap exists to close. Every arm
    /// is checked against the real encoder, including a type with no arm.
    #[test]
    fn the_rdata_size_bound_is_never_smaller_than_the_encoded_rdata() {
        let cases: &[(RecordType, &str)] = &[
            (RecordType::A, "203.0.113.10"),
            (RecordType::AAAA, "2001:db8::1"),
            (RecordType::NS, "ns1.example.com."),
            (RecordType::CNAME, "target.example.com."),
            (RecordType::PTR, "host.example.com."),
            (RecordType::MX, "10 mail.example.com."),
            (RecordType::SRV, "10 20 5060 sip.example.com."),
            (RecordType::TXT, "\"v=spf1 mx -all\""),
            (
                RecordType::TXT,
                "\"chunk-one\" \"chunk-two\" \"chunk-three\"",
            ),
            (RecordType::HINFO, "\"RFC8482\" \"\""),
            (RecordType::CAA, "0 issue \"letsencrypt.org\""),
            // No arm in the match: must be measured, not guessed.
            (RecordType::TLSA, &format!("3 1 1 {}", "ab".repeat(600))),
            (
                RecordType::SSHFP,
                "1 1 123456789abcdef67890123456789abcdef67890",
            ),
        ];

        for (rtype, value) in cases {
            let rdata = RData::try_from_str(*rtype, value)
                .unwrap_or_else(|e| panic!("{rtype} {value:?} should parse: {e}"));
            let actual = rdata
                .to_bytes()
                .unwrap_or_else(|e| panic!("{rtype} should encode: {e}"))
                .len();
            let bound = rdata_size_bound(&rdata);
            assert!(
                bound >= actual,
                "{rtype} bound {bound} under-counts the encoded {actual} bytes for {value:?}"
            );
        }
    }

    /// Scenario: An ANY query does not chase a CNAME
    /// features/zone-lookup.feature:194
    /// features/cname.feature — RFC 8482 §4.2
    ///
    /// Synthesis is only permitted when there is no CNAME at the owner name.
    /// Returning the HINFO regardless hid aliases from anything that discovers
    /// them with ANY.
    #[test]
    fn an_any_query_at_a_cname_owner_returns_the_cname_not_the_hinfo() {
        let h = handler(
            vec![
                spec("alias", "CNAME", &["origin.example.com."]),
                spec("origin", "A", &["203.0.113.20"]),
            ],
            false,
        );
        let r = h.resolve(&lower("alias.example.com."), RecordType::ANY, client());
        assert_eq!(r.code, ResponseCode::NoError);
        assert_eq!(r.answers.len(), 1, "{:?}", r.answers);
        assert_eq!(
            r.answers[0].record_type(),
            RecordType::CNAME,
            "RFC 8482 §4.2 forbids synthesising over a CNAME"
        );
    }

    #[test]
    fn out_of_zone_query_is_refused() {
        let h = handler(vec![], false);
        let r = h.resolve(&lower("google.com."), RecordType::A, client());
        assert_eq!(r.code, ResponseCode::Refused);
        assert!(!r.authoritative);
    }

    #[test]
    fn in_zone_hit_is_authoritative() {
        let h = handler(vec![spec("www", "A", &["203.0.113.20"])], false);
        let r = h.resolve(&lower("www.example.com."), RecordType::A, client());
        assert_eq!(r.code, ResponseCode::NoError);
        assert!(r.authoritative);
        assert_eq!(r.answers.len(), 1);
    }

    #[test]
    fn nxdomain_carries_the_soa_in_the_authority_section() {
        let h = handler(vec![], false);
        let r = h.resolve(&lower("missing.example.com."), RecordType::A, client());
        assert_eq!(r.code, ResponseCode::NXDomain);
        assert_eq!(r.authority.len(), 1);
        assert_eq!(r.authority[0].record_type(), RecordType::SOA);
    }

    #[test]
    fn nodata_is_noerror_with_the_soa() {
        let h = handler(vec![spec("www", "A", &["203.0.113.20"])], false);
        let r = h.resolve(&lower("www.example.com."), RecordType::AAAA, client());
        assert_eq!(r.code, ResponseCode::NoError);
        assert!(r.answers.is_empty());
        assert_eq!(r.authority.len(), 1);
    }

    #[test]
    fn apex_soa_query_is_answered_from_the_zone_soa() {
        let h = handler(vec![], false);
        let r = h.resolve(&lower("example.com."), RecordType::SOA, client());
        assert_eq!(r.code, ResponseCode::NoError);
        assert_eq!(r.answers.len(), 1);
        assert_eq!(r.answers[0].record_type(), RecordType::SOA);
    }

    #[test]
    fn myip_reflects_an_ipv4_client() {
        let h = handler(vec![], true);
        let r = h.resolve(&lower("myip.example.com."), RecordType::A, client());
        assert_eq!(r.answers.len(), 1);
        assert_eq!(
            &r.answers[0].data,
            &RData::A(A("198.51.100.10".parse().unwrap()))
        );
    }

    #[test]
    fn myip_reflects_an_ipv6_client() {
        let h = handler(vec![], true);
        let src: IpAddr = "2001:db8::5".parse().unwrap();
        let r = h.resolve(&lower("myip.example.com."), RecordType::AAAA, src);
        assert_eq!(r.answers.len(), 1);
        assert_eq!(r.answers[0].record_type(), RecordType::AAAA);
    }

    #[test]
    fn myip_returns_nodata_for_the_wrong_family() {
        let h = handler(vec![], true);
        let r = h.resolve(&lower("myip.example.com."), RecordType::AAAA, client());
        assert_eq!(r.code, ResponseCode::NoError);
        assert!(r.answers.is_empty());
    }

    #[test]
    fn counter_reports_the_query_total() {
        let cfg = zone_config(vec![], true);
        let zone = Arc::new(Zone::from_config(&cfg).unwrap());
        let metrics = Arc::new(Metrics::new());
        metrics.query(Transport::Udp);
        metrics.query(Transport::Udp);
        let h = DnsHandler::new(zone, &cfg, metrics, None);

        let r = h.resolve(&lower("counter.example.com."), RecordType::TXT, client());
        assert_eq!(txt_value(&r.answers[0]), "2");
    }

    #[test]
    fn version_reports_the_crate_version() {
        let h = handler(vec![], true);
        let r = h.resolve(&lower("version.example.com."), RecordType::TXT, client());
        assert!(txt_value(&r.answers[0]).contains(crate::VERSION));
    }

    #[test]
    fn hello_greets_the_queried_labels() {
        let h = handler(vec![], true);
        let r = h.resolve(
            &lower("ismoilovdev.hello.example.com."),
            RecordType::TXT,
            client(),
        );
        assert_eq!(txt_value(&r.answers[0]), "hello, ismoilovdev");
    }

    #[test]
    fn hello_without_labels_greets_the_world() {
        let h = handler(vec![], true);
        let r = h.resolve(&lower("hello.example.com."), RecordType::TXT, client());
        assert_eq!(txt_value(&r.answers[0]), "hello, world");
    }

    #[test]
    fn builtins_can_be_disabled() {
        let h = handler(vec![], false);
        let r = h.resolve(&lower("myip.example.com."), RecordType::A, client());
        assert_eq!(r.code, ResponseCode::NXDomain);
    }

    #[test]
    fn static_records_still_work_under_a_builtin_name_when_builtins_are_off() {
        let h = handler(vec![spec("myip", "TXT", &["\"static\""])], false);
        let r = h.resolve(&lower("myip.example.com."), RecordType::TXT, client());
        assert_eq!(txt_value(&r.answers[0]), "static");
    }

    #[test]
    fn greeting_helper_handles_multiple_labels() {
        let mut qname: Name = "a.b.hello.example.com.".parse().unwrap();
        qname.set_fqdn(true);
        assert_eq!(greeting(&qname, &lower("hello.example.com.")), "hello, a b");
    }

    #[test]
    fn transport_mapping_covers_udp_and_tcp() {
        assert_eq!(transport_of(Protocol::Udp), Transport::Udp);
        assert_eq!(transport_of(Protocol::Tcp), Transport::Tcp);
    }

    #[test]
    fn rate_limiter_refuses_once_the_bucket_is_empty() {
        let cfg = zone_config(vec![], false);
        let zone = Arc::new(Zone::from_config(&cfg).unwrap());
        let limiter = Arc::new(RateLimiter::new(1, 1));
        let metrics = Arc::new(Metrics::new());
        let _h = DnsHandler::new(zone, &cfg, metrics, Some(Arc::clone(&limiter)));

        assert!(limiter.check(client()));
        assert!(!limiter.check(client()));
    }

    // -----------------------------------------------------------------------
    // Regression tests from mutation testing.
    // -----------------------------------------------------------------------

    #[test]
    fn an_apex_soa_query_returns_only_the_soa() {
        // Kills `==` -> `!=` on the ANY check in the apex-SOA branch, which
        // splices every other apex record into the answer to a plain SOA query.
        let h = handler(
            vec![
                spec("@", "A", &["203.0.113.10"]),
                spec("@", "MX", &["10 mail.example.com."]),
            ],
            false,
        );
        let r = h.resolve(&lower("example.com."), RecordType::SOA, client());
        assert_eq!(r.answers.len(), 1, "{:?}", r.answers);
        assert_eq!(r.answers[0].record_type(), RecordType::SOA);
    }

    /// Scenario: An ANY query at the apex returns the HINFO and not the zone SOA
    /// features/zone-lookup.feature:169
    ///
    /// RFC 8482 §4.1. This used to return the whole node — every RRset at the
    /// name plus the SOA — which made ANY the largest answer we could produce
    /// from the smallest query anyone could send. Nothing in RFC 8482 licenses
    /// adding the SOA to the *answer* section; RFC 1034 §4.3.2 puts it in
    /// *authority*, and only on a negative answer.
    #[test]
    fn an_apex_any_query_is_answered_with_one_synthetic_hinfo() {
        let h = handler(
            vec![
                spec("@", "A", &["203.0.113.10"]),
                spec("@", "MX", &["10 mail.example.com."]),
            ],
            false,
        );
        let r = h.resolve(&lower("example.com."), RecordType::ANY, client());
        assert_eq!(r.code, ResponseCode::NoError);
        assert_eq!(r.answers.len(), 1, "{:?}", r.answers);
        assert_eq!(r.answers[0].record_type(), RecordType::HINFO);
        let RData::HINFO(hinfo) = &r.answers[0].data else {
            panic!("expected HINFO, got {:?}", r.answers[0].data);
        };
        assert_eq!(&*hinfo.cpu, b"RFC8482");

        let types: Vec<_> = r.answers.iter().map(Record::record_type).collect();
        assert!(!types.contains(&RecordType::A), "{types:?}");
        assert!(!types.contains(&RecordType::MX), "{types:?}");
        assert!(!types.contains(&RecordType::SOA), "{types:?}");
    }

    /// Scenario: A name with no source of synthesis is still NXDOMAIN
    /// features/zone-lookup.feature:268
    ///
    /// Kills a mutant that answers every ANY query with the HINFO regardless of
    /// whether the name exists, which would make the zone claim every name in it.
    /// Also the negative control for VEGA-083: the existence gate got *wider*
    /// there, and this is the half that must not move.
    #[test]
    fn an_any_query_for_a_missing_name_is_nxdomain() {
        let h = handler(vec![spec("www", "A", &["203.0.113.10"])], false);
        let r = h.resolve(&lower("nope.example.com."), RecordType::ANY, client());
        assert_eq!(r.code, ResponseCode::NXDomain);
        assert!(r.answers.is_empty());
        assert_eq!(r.authority.len(), 1, "the SOA must accompany an NXDOMAIN");
    }

    #[test]
    fn a_soa_query_below_the_apex_is_not_answered_from_the_zone_soa() {
        // Kills `&&` -> `||` in the apex-SOA guard, which would serve the zone
        // SOA as the answer to an SOA query for any name in the zone.
        let h = handler(vec![spec("www", "A", &["203.0.113.20"])], false);
        let r = h.resolve(&lower("www.example.com."), RecordType::SOA, client());
        assert_eq!(r.code, ResponseCode::NoError);
        assert!(
            r.answers.is_empty(),
            "the SOA is only served at the apex: {:?}",
            r.answers
        );
        assert_eq!(r.authority.len(), 1);
    }

    #[test]
    fn replace_zone_swaps_the_records_being_served() {
        // Kills `replace_zone` replaced with `()`. Nothing in the suite
        // exercised a reload at all, so a broken swap was invisible.
        let h = handler(vec![spec("www", "A", &["203.0.113.20"])], false);
        let before = h.resolve(&lower("www.example.com."), RecordType::A, client());
        assert_eq!(
            &before.answers[0].data,
            &RData::try_from_str(RecordType::A, "203.0.113.20").unwrap()
        );

        let cfg = zone_config(vec![spec("www", "A", &["198.51.100.7"])], false);
        h.replace_zone(Arc::new(Zone::from_config(&cfg).unwrap()), false);

        let after = h.resolve(&lower("www.example.com."), RecordType::A, client());
        assert_eq!(
            &after.answers[0].data,
            &RData::try_from_str(RecordType::A, "198.51.100.7").unwrap(),
            "a reload must be visible to the next query"
        );
        assert_eq!(h.zone().record_count(), 1);
    }

    #[test]
    fn replace_zone_can_turn_builtins_on_and_off() {
        let h = handler(vec![], false);
        assert_eq!(
            h.resolve(&lower("myip.example.com."), RecordType::A, client())
                .code,
            ResponseCode::NXDomain
        );

        let cfg = zone_config(vec![], true);
        h.replace_zone(Arc::new(Zone::from_config(&cfg).unwrap()), true);
        assert_eq!(
            h.resolve(&lower("myip.example.com."), RecordType::A, client())
                .answers
                .len(),
            1
        );

        h.replace_zone(Arc::new(Zone::from_config(&cfg).unwrap()), false);
        assert_eq!(
            h.resolve(&lower("myip.example.com."), RecordType::A, client())
                .code,
            ResponseCode::NXDomain
        );
    }

    #[test]
    fn a_builtin_answers_an_any_query_with_its_txt() {
        // Kills `==` -> `!=` on the ANY check in txt_builtin, which turns the
        // test into "answer TXT for everything except ANY".
        let h = handler(vec![], true);
        let r = h.resolve(&lower("version.example.com."), RecordType::ANY, client());
        assert_eq!(r.answers.len(), 1);
        assert_eq!(r.answers[0].record_type(), RecordType::TXT);
    }

    #[test]
    fn a_builtin_returns_nodata_for_a_non_txt_type() {
        let h = handler(vec![], true);
        let r = h.resolve(&lower("version.example.com."), RecordType::A, client());
        assert_eq!(r.code, ResponseCode::NoError);
        assert!(r.answers.is_empty(), "{:?}", r.answers);
        assert_eq!(r.authority.len(), 1);
    }

    #[test]
    fn builtin_answers_carry_the_zone_default_ttl() {
        // Kills `Zone::default_ttl -> 0` / `-> 1`: the built-in TTL is the only
        // consumer of that accessor.
        let h = handler(vec![], true);
        for name in [
            "version.example.com.",
            "hello.example.com.",
            "counter.example.com.",
        ] {
            let r = h.resolve(&lower(name), RecordType::TXT, client());
            assert_eq!(r.answers[0].ttl, 300, "{name}");
        }
        let r = h.resolve(&lower("myip.example.com."), RecordType::A, client());
        assert_eq!(r.answers[0].ttl, 300);
    }

    #[test]
    fn every_noerror_answer_with_no_records_carries_the_soa() {
        // Guards the `Answer::Records(records) if records.is_empty()` arm: a
        // NOERROR with an empty answer section must always be cacheable, which
        // means it must always carry the zone SOA.
        //
        // The wildcard-covered rows are VEGA-083's: RFC 2308 §3 requires the SOA
        // on a NODATA answer exactly as it does on a name error, so turning
        // those answers from NXDOMAIN into NODATA must not drop it. An
        // uncacheable NODATA is a different bug, not a fix.
        let h = handler(
            vec![
                spec("www", "A", &["203.0.113.20"]),
                spec("*.dev", "A", &["203.0.113.50"]),
            ],
            true,
        );
        for (name, qtype) in [
            ("www.example.com.", RecordType::AAAA),
            ("www.example.com.", RecordType::MX),
            ("example.com.", RecordType::TXT),
            ("x.dev.example.com.", RecordType::AAAA),
            ("x.dev.example.com.", RecordType::SRV),
            ("myip.example.com.", RecordType::AAAA),
            ("version.example.com.", RecordType::A),
            ("hello.example.com.", RecordType::MX),
            ("counter.example.com.", RecordType::SRV),
        ] {
            let r = h.resolve(&lower(name), qtype, client());
            if r.code == ResponseCode::NoError && r.answers.is_empty() {
                assert_eq!(
                    r.authority.len(),
                    1,
                    "{name}/{qtype} answered NODATA without an SOA"
                );
                assert_eq!(r.authority[0].record_type(), RecordType::SOA);
            }
        }
    }

    /// Scenario: The MAILB meta QTYPE is answered NOTIMP, not with the owner's CNAME
    /// Scenario: The MAILA meta QTYPE is answered NOTIMP, not with the owner's CNAME
    /// features/negative-answers.feature — the same clause
    /// `tests/rfc_conformance.rs::meta_query_types_are_not_answered_as_ordinary_types`
    /// covers on the wire, pinned here to the *exact* rcode.
    ///
    /// The wire test accepts any of FORMERR/NOTIMP/REFUSED, so it cannot tell a
    /// deliberate NOTIMP from a lucky REFUSED. MAILA and MAILB were withdrawn by
    /// RFC 973 and RFC 1035 §3.2.3 lists them as QTYPEs only — they name a
    /// transaction we do not implement rather than a zone we decline to serve,
    /// so NOTIMP is the answer and REFUSED is not.
    #[test]
    fn mailb_and_maila_qtypes_are_notimp_rather_than_the_owner_cname() {
        let h = handler(
            vec![
                spec("alias", "CNAME", &["origin.example.com."]),
                spec("origin", "A", &["203.0.113.20"]),
            ],
            false,
        );

        for (qtype, name) in [(MAILB_QTYPE, "MAILB"), (MAILA_QTYPE, "MAILA")] {
            let resolved = h
                .dispatch(&query_request("alias.example.com.", qtype), client())
                .unwrap_or_else(|| panic!("{name} should be answered, not dropped"));
            assert_eq!(
                resolved.code,
                ResponseCode::NotImp,
                "{name} (qtype {}) got rcode {:?}",
                u16::from(qtype),
                resolved.code
            );
            assert!(
                resolved.answers.is_empty(),
                "{name} (qtype {}) was answered with {} records",
                u16::from(qtype),
                resolved.answers.len()
            );
        }
    }

    // -----------------------------------------------------------------------
    // VEGA-083 — the rcode at a wildcard-covered name.
    //
    // Spec: features/zone-lookup.feature, sections "ANY QUERY" and
    //       "WILDCARD-COVERED NAMES".
    // Ruling: .claude/backlog/decisions/VEGA-083-any-at-a-wildcard-covered-name.md
    //
    // The handler owns the rcode, so this is where the law lands: RFC 1034
    // §4.3.2 step 3(c) sets the name error only when the `*` node does not
    // exist, and that branch is not conditioned on QTYPE anywhere. RFC 8482
    // §4.1/§4.2 change the *answer section* for ANY and license no rcode change,
    // so the existence determination for ANY must be the same computation as the
    // one for AAAA — which, before this issue, it was not: ANY was gated on a
    // raw node-set lookup that knew nothing about synthesis.
    // -----------------------------------------------------------------------

    /// Scenario: An ANY query returns one synthetic HINFO, not the whole node
    /// features/zone-lookup.feature:154
    ///
    /// The apex case is covered above; this is the ordinary-name case, and it
    /// carries the two negative assertions that make either of them mean
    /// anything. Without "no A" and "no TXT" the scenario passes against an
    /// implementation that returns the HINFO *and* the node, which is the
    /// amplification VEGA-002 closed rather than the fix.
    #[test]
    fn an_any_query_returns_one_synthetic_hinfo_and_not_the_node() {
        let h = handler(
            vec![
                spec("multi", "A", &["203.0.113.60"]),
                spec("multi", "TXT", &["\"hello\""]),
            ],
            false,
        );
        let r = h.resolve(&lower("multi.example.com."), RecordType::ANY, client());
        assert_eq!(r.code, ResponseCode::NoError);
        assert_eq!(r.answers.len(), 1, "{:?}", r.answers);
        assert_eq!(r.answers[0].record_type(), RecordType::HINFO);
        let RData::HINFO(hinfo) = &r.answers[0].data else {
            panic!("expected HINFO, got {:?}", r.answers[0].data);
        };
        assert_eq!(
            &*hinfo.cpu, b"RFC8482",
            "RFC 8482 §6 asks for a recognisable CPU field so operators can tell \
             a minimal-ANY answer from a real HINFO"
        );
        let types: Vec<_> = r.answers.iter().map(Record::record_type).collect();
        assert!(
            !types.contains(&RecordType::A),
            "the node's A came back beside the HINFO: {types:?}"
        );
        assert!(
            !types.contains(&RecordType::TXT),
            "the node's TXT came back beside the HINFO: {types:?}"
        );
    }

    /// Scenario: An ANY query at an existing name that holds no records still
    /// returns the HINFO
    /// features/zone-lookup.feature:181
    ///
    /// Ruled substantively by the architect, because both readings of RFC 8482
    /// are conformant: §4.2 conditions synthesis on the absence of a CNAME at
    /// the QNAME and on nothing else, so the shape of an ANY response does not
    /// depend on what the node holds. Taking §4.1's "subset" reading — the empty
    /// set for an empty node, i.e. a real NODATA — would make it depend on
    /// exactly that, and uniform-and-bounded is the whole value of §4.2 here.
    #[test]
    fn an_any_query_at_a_name_that_holds_no_records_still_returns_the_hinfo() {
        let h = handler(vec![], false);
        let r = h.resolve(&lower("example.com."), RecordType::ANY, client());
        assert_eq!(r.code, ResponseCode::NoError);
        assert_eq!(r.answers.len(), 1, "{:?}", r.answers);
        assert_eq!(r.answers[0].record_type(), RecordType::HINFO);
    }

    /// Scenario: An ANY query at a wildcard-covered name is NOERROR with the RFC
    /// 8482 HINFO
    /// features/zone-lookup.feature:257
    ///
    /// The half the issue was filed as. It is the least important half — ANY is
    /// rare and increasingly refused outright — but it is the one where the two
    /// existence determinations were visibly different code.
    #[test]
    fn an_any_query_at_a_wildcard_covered_name_is_noerror_with_the_hinfo() {
        let h = handler(vec![spec("*.dev", "A", &["203.0.113.50"])], false);
        let r = h.resolve(&lower("x.dev.example.com."), RecordType::ANY, client());
        assert_eq!(
            r.code,
            ResponseCode::NoError,
            "a name with a source of synthesis exists (RFC 4592 §3.3.1), and RFC \
             8482 licenses no rcode change"
        );
        assert_eq!(r.answers.len(), 1, "{:?}", r.answers);
        assert_eq!(r.answers[0].record_type(), RecordType::HINFO);
    }

    /// Scenario: An ANY query at a wildcard-covered CNAME returns the
    /// synthesised CNAME
    /// features/zone-lookup.feature:203
    ///
    /// An unfiled defect the architect found at the same site, and the reason
    /// the fix has an *order* and not just a predicate: the existence gate ran
    /// before the CNAME probe, and the CNAME probe goes through `Zone::lookup`
    /// and is therefore already wildcard-aware. So the branch was internally
    /// inconsistent — it could synthesise the CNAME but refused to admit the
    /// name existed — and a wildcard CNAME answered NXDOMAIN while holding the
    /// answer it owed. RFC 4592 §3.4.3 and RFC 8482 §4.2 violated at once.
    ///
    /// Ordering the branch `exists` → CNAME → HINFO closes it. A fix that gets
    /// the predicate right but leaves the order alone still fails this.
    #[test]
    fn an_any_query_at_a_wildcard_covered_cname_returns_the_synthesised_cname() {
        let h = handler(
            vec![
                spec("*.dev", "CNAME", &["origin.example.com."]),
                spec("origin", "A", &["203.0.113.20"]),
            ],
            false,
        );
        let r = h.resolve(&lower("x.dev.example.com."), RecordType::ANY, client());
        assert_eq!(r.code, ResponseCode::NoError);
        assert_eq!(r.answers.len(), 1, "{:?}", r.answers);
        assert_eq!(
            r.answers[0].record_type(),
            RecordType::CNAME,
            "RFC 8482 §4.2 forbids synthesising a HINFO over a CNAME, and the \
             CNAME is synthesised at a covered name like any other type"
        );
        assert_eq!(
            r.answers[0].name,
            Name::from(lower("x.dev.example.com.")),
            "a synthesised answer owned by `*.dev.example.com.` is discarded by \
             every resolver that receives it"
        );
    }

    /// Scenario: For a name with no CNAME, the rcode is a function of the name
    /// alone
    /// features/zone-lookup.feature:286
    ///
    /// AC-1 as an example, at the layer that owns the rcode. The property-test
    /// form over generated zones is
    /// `tests/properties.rs::the_rcode_of_a_cname_free_name_does_not_depend_on_the_qtype`;
    /// this one names the exact packets that were observed on the wire.
    ///
    /// Asserted as "every QTYPE agrees with A" rather than "every QTYPE is
    /// NOERROR", because the claim is the *invariance*, not the value: a server
    /// that answered NXDOMAIN to all six would be wrong in a different way, and
    /// the positive control above is what pins the value.
    #[test]
    fn the_rcode_at_a_wildcard_covered_name_does_not_depend_on_the_qtype() {
        let h = handler(vec![spec("*.dev", "A", &["203.0.113.50"])], false);
        let name = lower("x.dev.example.com.");

        let carried = h.resolve(&name, RecordType::A, client());
        assert_eq!(
            carried.code,
            ResponseCode::NoError,
            "the wildcard must still answer the type it carries"
        );

        // AAAA first: it is what a dual-stack client sends alongside every A, so
        // it is the one that poisons a resolver's cache during ordinary traffic.
        for qtype in [
            RecordType::AAAA,
            RecordType::TXT,
            RecordType::MX,
            RecordType::SRV,
            RecordType::ANY,
        ] {
            let r = h.resolve(&name, qtype, client());
            assert_eq!(
                r.code, carried.code,
                "{qtype} at x.dev.example.com. answered {:?} where A answers \
                 {:?}. RFC 1034 §4.3.2 step 3(c) conditions the name error on \
                 the `*` node's existence and on nothing else, so the rcode may \
                 not depend on the QTYPE",
                r.code, carried.code
            );
        }
    }

    /// Scenario: Coverage is decided by the wildcard's own parent, not by its
    /// depth
    /// features/zone-lookup.feature:276
    ///
    /// The same discrimination as
    /// `zone::tests::coverage_is_decided_by_the_wildcard_parent_not_by_its_depth`,
    /// carried through to the rcode: the depths-alone shortcut does not just
    /// mislabel an enum, it makes the server answer NOERROR for names it is
    /// authoritatively denying today.
    #[test]
    fn a_name_whose_parent_merely_shares_a_depth_with_a_wildcard_is_still_nxdomain() {
        let h = handler(vec![spec("*.dev", "A", &["203.0.113.50"])], false);
        for qtype in [RecordType::A, RecordType::AAAA, RecordType::ANY] {
            let r = h.resolve(&lower("q.other.example.com."), qtype, client());
            assert_eq!(
                r.code,
                ResponseCode::NXDomain,
                "`other.example.com.` sits at the same depth as the wildcard's \
                 parent but is not it, so {qtype} there is a real name error"
            );
        }
        // Anti-vacuity: the covered sibling must exist, or this passes against a
        // server that never covers anything.
        assert_eq!(
            h.resolve(&lower("q.dev.example.com."), RecordType::AAAA, client())
                .code,
            ResponseCode::NoError
        );
    }

    /// A single-question UDP request for `name`/`qtype`, as `dispatch` sees it.
    ///
    /// Goes through the wire encoding on purpose: `RecordType::from(u16)` is
    /// where 253 and 254 become `Unknown`, and a test that skipped the decode
    /// could assert against a variant no packet can ever produce.
    fn query_request(name: &str, qtype: RecordType) -> Request {
        query_request_from(name, qtype, "198.51.100.10:5353")
    }

    /// [`query_request`] with the source address spelled out.
    fn query_request_from(name: &str, qtype: RecordType, src: &str) -> Request {
        use hickory_proto::op::{Message, Query};

        let mut query = Query::new();
        let mut owner: Name = name.parse().expect("name parses");
        owner.set_fqdn(true);
        query
            .set_name(owner)
            .set_query_type(qtype)
            .set_query_class(DNSClass::IN);

        let mut message = Message::query();
        message.add_query(query);
        Request::from_bytes(
            message.to_vec().expect("request encodes"),
            src.parse().expect("source address parses"),
            Protocol::Udp,
        )
        .expect("request decodes")
    }

    // -----------------------------------------------------------------------
    // VEGA-014: what the counters say, against what actually left the socket.
    //
    // Every test above stops at `resolve` or `dispatch`, which is before a
    // single byte is encoded. These drive the whole of `handle_request` against
    // a `ResponseHandler` double, so the response-code counter can be compared
    // with the bytes the encoder produced — including the two outcomes no
    // packet can provoke from outside: hickory's bare-SERVFAIL fallback, and a
    // write that fails.
    // -----------------------------------------------------------------------

    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };

    use hickory_proto::{
        op::Message,
        serialize::binary::{BinDecodable as _, BinEncoder},
    };
    use hickory_server::{
        net::{runtime::TokioTime, NetError},
        zone_handler::MessageResponse,
    };

    /// A byte budget too small to hold a header plus a question.
    ///
    /// Twelve bytes is exactly [`HEADER_SIZE`], so the first label of the QNAME
    /// has nowhere to go and `destructive_emit` fails. Nothing a client can send
    /// gets the budget this low — [`MIN_EDNS_PAYLOAD`] floors it at 512 and a
    /// question is at most ~272 bytes — which is precisely why the fallback
    /// branch needs a double to reach it at all.
    const STARVED_BUDGET: u16 = 12;

    /// How the double treats the message it is handed.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    enum SendMode {
        /// Encode with the budget a normal UDP client gets, and keep the bytes.
        Wire,
        /// Encode with [`STARVED_BUDGET`], which drives hickory's fallback.
        Starved,
        /// The socket is gone: nothing is written, the write reports an error.
        Broken,
    }

    /// What the double did with the messages it was handed.
    #[derive(Debug, Default)]
    struct SendLog {
        /// The exact bytes the encoder produced, in send order.
        wire: Mutex<Vec<Vec<u8>>>,
        /// Times hickory's bare-SERVFAIL fallback replaced the real answer.
        fallbacks: AtomicUsize,
        /// Times the write failed and nothing at all went out.
        failures: AtomicUsize,
    }

    impl SendLog {
        /// The response code of each datagram, read back off the wire bytes.
        ///
        /// Decoded rather than remembered: the point of these tests is what a
        /// client would see, and a double that reported its own intention would
        /// be no better than the counter it is checking.
        fn wire_rcodes(&self) -> Vec<ResponseCode> {
            self.wire
                .lock()
                .expect("no test panics while holding this lock")
                .iter()
                .map(|bytes| {
                    Message::from_bytes(bytes)
                        .expect("the double only logs bytes the encoder produced")
                        .metadata
                        .response_code
                })
                .collect()
        }
    }

    /// A [`ResponseHandler`] that never touches a socket.
    #[derive(Clone, Debug)]
    struct FakeClient {
        mode: SendMode,
        log: Arc<SendLog>,
    }

    impl FakeClient {
        fn new(mode: SendMode) -> Self {
            Self {
                mode,
                log: Arc::new(SendLog::default()),
            }
        }

        fn log(&self) -> Arc<SendLog> {
            Arc::clone(&self.log)
        }
    }

    #[async_trait::async_trait]
    impl ResponseHandler for FakeClient {
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
            if self.mode == SendMode::Broken {
                self.log.failures.fetch_add(1, Ordering::Relaxed);
                return Err(NetError::from(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "client socket closed before the response was written",
                )));
            }

            let budget = match self.mode {
                SendMode::Starved => STARVED_BUDGET,
                _ => MIN_EDNS_PAYLOAD,
            };
            let (info, bytes, fell_back) = encode_with_budget(response, budget);
            if fell_back {
                self.log.fallbacks.fetch_add(1, Ordering::Relaxed);
            }
            self.log
                .wire
                .lock()
                .expect("no test panics while holding this lock")
                .push(bytes);
            Ok(info)
        }
    }

    /// hickory's `MessageResponse::encode`, with the byte budget as an argument.
    ///
    /// A transcription of hickory-server 0.26.1
    /// `zone_handler/message_response.rs:80-118`, line for line, with `max_size`
    /// lifted out of the protocol/EDNS calculation. It has to be a transcription
    /// because `encode` is `pub(crate)` and derives its budget from numbers Vega
    /// clamps to at least 512 bytes, so the fallback is unreachable from a
    /// packet. What matters is that the *real* encoder still fails on the *real*
    /// message here — the test is not asserting a SERVFAIL that a mock invented.
    ///
    /// Returns the info, the bytes, and whether the fallback fired.
    fn encode_with_budget<'a>(
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
        max_size: u16,
    ) -> (ResponseInfo, Vec<u8>, bool) {
        let id = response.metadata().id;

        let mut bytes = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut bytes);
        encoder.set_max_size(max_size);
        if let Ok(info) = response.destructive_emit(&mut encoder) {
            return (info, bytes, false);
        }

        // The encoder wrote a partial message before it ran out of room, so the
        // buffer is discarded and a bare SERVFAIL header takes its place.
        bytes.clear();
        let mut encoder = BinEncoder::new(&mut bytes);
        encoder.set_max_size(MIN_EDNS_PAYLOAD);

        let mut metadata = Metadata::new(id, MessageType::Response, OpCode::Query);
        metadata.response_code = ResponseCode::ServFail;
        let header = Header {
            metadata,
            counts: HeaderCounts::default(),
        };
        header
            .emit(&mut encoder)
            .expect("a bare 12-byte header always fits in 512");
        (ResponseInfo::from(header), bytes, true)
    }

    /// A handler over `records`, sharing `metrics` with the caller.
    fn handler_with(
        records: Vec<RecordSpec>,
        metrics: &Arc<Metrics>,
        limiter: Option<Arc<RateLimiter>>,
    ) -> DnsHandler {
        let cfg = zone_config(records, false);
        let zone = Arc::new(Zone::from_config(&cfg).unwrap());
        DnsHandler::new(zone, &cfg, Arc::clone(metrics), limiter)
    }

    /// Drive one request through the full `handle_request`, socket and all.
    async fn serve(handler: &DnsHandler, request: &Request, client: FakeClient) -> ResponseInfo {
        handler
            .handle_request::<FakeClient, TokioTime>(request, client)
            .await
    }

    /// The value of one Prometheus series, or a panic naming the whole body.
    fn series(text: &str, name: &str) -> u64 {
        let needle = format!("{name} ");
        text.lines()
            .find_map(|line| line.strip_prefix(needle.as_str()))
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or_else(|| panic!("no series {name:?} in:\n{text}"))
    }

    /// Scenario: A response that is written successfully is counted under the rcode it carried
    /// features/admin-api.feature:148
    ///
    /// The control for the two failure tests below. Without it, a double that
    /// answered SERVFAIL to everything would satisfy them both.
    #[tokio::test]
    async fn a_response_that_is_written_is_counted_under_the_rcode_it_carried() {
        let metrics = Arc::new(Metrics::new());
        let handler = handler_with(vec![spec("www", "A", &["203.0.113.10"])], &metrics, None);
        let client = FakeClient::new(SendMode::Wire);
        let log = client.log();

        let info = serve(
            &handler,
            &query_request("www.example.com.", RecordType::A),
            client,
        )
        .await;

        assert_eq!(log.wire_rcodes(), vec![ResponseCode::NoError]);
        assert_eq!(log.fallbacks.load(Ordering::Relaxed), 0);
        assert_eq!(info.response_code, ResponseCode::NoError);

        let text = metrics.render_prometheus();
        assert_eq!(series(&text, "dns_responses_total{rcode=\"noerror\"}"), 1);
        assert_eq!(series(&text, "dns_responses_total{rcode=\"servfail\"}"), 0);
        assert_eq!(series(&text, "dns_send_errors_total"), 0);
    }

    /// Scenario: An answer the encoder cannot fit is counted as the SERVFAIL that was sent
    /// features/admin-api.feature:156
    ///
    /// This is VEGA-014 itself. `MessageResponse::encode` catches an emit
    /// failure, throws the buffer away, puts a bare SERVFAIL header on the wire
    /// and returns `Ok(ResponseInfo { ServFail })`. Counting the rcode we
    /// *intended* instead of the one hickory reports back left
    /// `dns_responses_total{rcode="servfail"}` reading zero during exactly the
    /// failure it exists to reveal.
    #[tokio::test]
    async fn an_answer_the_encoder_cannot_fit_is_counted_as_the_servfail_that_was_sent() {
        let metrics = Arc::new(Metrics::new());
        let handler = handler_with(vec![spec("www", "A", &["203.0.113.10"])], &metrics, None);
        let client = FakeClient::new(SendMode::Starved);
        let log = client.log();

        let info = serve(
            &handler,
            &query_request("www.example.com.", RecordType::A),
            client,
        )
        .await;

        // If hickory ever stops falling back, this test must fail loudly rather
        // than quietly stop testing anything.
        assert_eq!(
            log.fallbacks.load(Ordering::Relaxed),
            1,
            "the encoder was expected to run out of room and fall back"
        );
        assert_eq!(
            log.wire_rcodes(),
            vec![ResponseCode::ServFail],
            "the client received SERVFAIL, whatever we resolved"
        );
        assert_eq!(info.response_code, ResponseCode::ServFail);

        let text = metrics.render_prometheus();
        assert_eq!(
            series(&text, "dns_responses_total{rcode=\"servfail\"}"),
            1,
            "the wire said SERVFAIL, so the counter must too:\n{text}"
        );
        assert_eq!(
            series(&text, "dns_responses_total{rcode=\"noerror\"}"),
            0,
            "NOERROR was resolved but never sent:\n{text}"
        );
        assert_eq!(
            series(&text, "dns_send_errors_total"),
            0,
            "the write succeeded; only its contents changed"
        );
    }

    /// Scenario: A response that cannot be written to the socket is counted as a send error
    /// features/admin-api.feature:168
    ///
    /// `dns_send_errors_total` and `serve_failed` were both 0% covered, so the
    /// one series an operator would use to tell "we are answering SERVFAIL" from
    /// "we are answering nothing" was dead instrumentation.
    #[tokio::test]
    async fn a_response_that_cannot_be_written_counts_a_send_error() {
        let metrics = Arc::new(Metrics::new());
        let handler = handler_with(vec![spec("www", "A", &["203.0.113.10"])], &metrics, None);
        let client = FakeClient::new(SendMode::Broken);
        let log = client.log();

        let info = serve(
            &handler,
            &query_request("www.example.com.", RecordType::A),
            client,
        )
        .await;

        assert_eq!(log.failures.load(Ordering::Relaxed), 1);
        assert!(
            log.wire_rcodes().is_empty(),
            "a failed write puts nothing on the wire"
        );
        assert_eq!(
            info.response_code,
            ResponseCode::ServFail,
            "the server is told the request failed, not that it succeeded"
        );

        let text = metrics.render_prometheus();
        assert_eq!(series(&text, "dns_send_errors_total"), 1, "{text}");
    }

    /// Scenario: A response that never reached the socket is still counted in dns_responses_total
    /// features/admin-api.feature:179
    ///
    /// Pins today's behaviour, and today's behaviour is the wrong one — see
    /// VEGA-088. `dns_responses_total` is documented as "DNS responses sent",
    /// the client received nothing, and the rate-limiter drop path
    /// (`dispatch` -> `None`) counts no response at all for the same outcome.
    /// Changing which of the two conventions wins moves the meaning of a series
    /// operators alert on, so it is a rust-dev change with its own issue, not a
    /// silent edit here. When it lands, this test flips to asserting 0 and the
    /// `@gap` scenario beside it becomes the enforced one.
    #[tokio::test]
    async fn a_response_that_never_reached_the_socket_is_still_counted_as_a_servfail_response() {
        let metrics = Arc::new(Metrics::new());
        let handler = handler_with(vec![spec("www", "A", &["203.0.113.10"])], &metrics, None);

        let _ = serve(
            &handler,
            &query_request("www.example.com.", RecordType::A),
            FakeClient::new(SendMode::Broken),
        )
        .await;

        let text = metrics.render_prometheus();
        assert_eq!(
            series(&text, "dns_responses_total{rcode=\"servfail\"}"),
            1,
            "current convention: a failed write is booked as a SERVFAIL:\n{text}"
        );
        assert_eq!(
            series(&text, "dns_responses_total{rcode=\"noerror\"}"),
            0,
            "the resolved rcode must not be the one recorded:\n{text}"
        );
    }

    /// Scenario: A query dropped by the rate limiter is counted as no response at all
    /// features/admin-api.feature:192
    ///
    /// The other half of the disagreement VEGA-088 records. A UDP drop is
    /// deliberately silent, and it books nothing in `dns_responses_total` — so
    /// the sum of that metric currently means "answers we tried to send", not
    /// "answers a client received". Locking it down here means the fix for
    /// VEGA-088 has to make the two paths agree rather than pick one at random.
    #[tokio::test]
    async fn a_query_dropped_by_the_rate_limiter_is_counted_as_no_response_at_all() {
        let metrics = Arc::new(Metrics::new());
        let limiter = Arc::new(RateLimiter::new(1, 1));
        let handler = handler_with(
            vec![spec("www", "A", &["203.0.113.10"])],
            &metrics,
            Some(Arc::clone(&limiter)),
        );
        // Drain the single token so the query below is the one that is dropped.
        assert!(limiter.check(client()), "the bucket starts full");

        let client_double = FakeClient::new(SendMode::Wire);
        let log = client_double.log();
        let _ = serve(
            &handler,
            &query_request("www.example.com.", RecordType::A),
            client_double,
        )
        .await;

        assert!(
            log.wire_rcodes().is_empty(),
            "a rate-limited UDP query must reach no socket at all"
        );

        let text = metrics.render_prometheus();
        assert_eq!(series(&text, "dns_rate_limited_total"), 1, "{text}");
        assert_eq!(series(&text, "dns_send_errors_total"), 0, "{text}");
        for rcode in ["noerror", "nxdomain", "refused", "servfail", "other"] {
            assert_eq!(
                series(&text, &format!("dns_responses_total{{rcode=\"{rcode}\"}}")),
                0,
                "nothing was sent, so no response code was sent either:\n{text}"
            );
        }
    }

    /// Scenario: Every failed write is counted, not just the first
    /// features/admin-api.feature:203
    ///
    /// A downstream outage produces these in bursts. A counter that moved once
    /// and then latched would make a total outage indistinguishable from a
    /// single dropped packet on the dashboard.
    #[tokio::test]
    async fn every_failed_write_is_counted_not_just_the_first() {
        const FAILURES: u64 = 5;

        let metrics = Arc::new(Metrics::new());
        let handler = handler_with(vec![spec("www", "A", &["203.0.113.10"])], &metrics, None);

        for i in 0..FAILURES {
            let src = format!("198.51.100.{}:5353", 10 + i);
            let _ = serve(
                &handler,
                &query_request_from("www.example.com.", RecordType::A, &src),
                FakeClient::new(SendMode::Broken),
            )
            .await;
        }

        let text = metrics.render_prometheus();
        assert_eq!(series(&text, "dns_send_errors_total"), FAILURES, "{text}");
        assert_eq!(
            series(&text, "dns_responses_total{rcode=\"servfail\"}"),
            FAILURES,
            "{text}"
        );
        assert_eq!(series(&text, "dns_queries_total"), FAILURES, "{text}");
    }
}
