//! The [`RequestHandler`] implementation: validation, rate limiting, zone
//! lookup, the diagnostic built-in sub-zones, and response assembly.

use std::{net::IpAddr, sync::Arc, time::Instant};

use arc_swap::ArcSwap;

use hickory_proto::{
    op::{Edns, Header, HeaderCounts, MessageType, Metadata, OpCode, ResponseCode},
    rr::{
        rdata::{A, AAAA, TXT},
        LowerName, Name, RData, Record, RecordType,
    },
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

        // A zone-level SOA (from `[zone.soa]`) is not part of the record map, so
        // answer apex SOA queries from it directly.
        if matches!(qtype, RecordType::SOA | RecordType::ANY) && name == zone.origin() {
            if let Some(soa) = zone.soa() {
                let mut answers = vec![soa.clone()];
                if qtype == RecordType::ANY {
                    if let Answer::Records(extra) = zone.lookup(name, RecordType::ANY) {
                        answers.extend(
                            extra
                                .into_iter()
                                .filter(|r| r.record_type() != RecordType::SOA),
                        );
                    }
                }
                return Resolved::found(answers);
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
    fn dispatch(&self, request: &Request, src: IpAddr) -> Resolved {
        if let Some(limiter) = &self.limiter {
            if !limiter.check(src) {
                self.metrics.rate_limited();
                debug!(%src, "query dropped by rate limiter");
                return Resolved::refused();
            }
        }

        if request.metadata.message_type != MessageType::Query {
            return Resolved::error(ResponseCode::FormErr);
        }

        if request.metadata.op_code != OpCode::Query {
            // We are a static authoritative server: no dynamic UPDATE, no NOTIFY.
            debug!(op_code = ?request.metadata.op_code, "unsupported op code");
            return Resolved::error(ResponseCode::NotImp);
        }

        // RFC 1035 allows QDCOUNT > 1 but no implementation supports it, and 0
        // makes no sense for a query.
        let [query] = request.queries.queries() else {
            return Resolved::error(ResponseCode::FormErr);
        };

        self.resolve(query.name(), query.query_type(), src)
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

        let resolved = self.dispatch(request, src.ip());

        // Mirror the request's EDNS so a resolver that offered a large UDP
        // payload gets one, instead of a needlessly truncated answer.
        let resp_edns = request.edns.as_ref().map(|req| {
            let mut edns = Edns::new();
            edns.set_max_payload(req.max_payload().max(MIN_EDNS_PAYLOAD));
            edns.set_version(0);
            edns
        });

        let mut metadata = Metadata::response_from_request(&request.metadata);
        metadata.authoritative = resolved.authoritative;
        metadata.response_code = resolved.code;

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
        self.metrics.response(resolved.code);

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
}
