use std::{sync::{atomic::{AtomicU64, Ordering}, Arc}, str::FromStr, net::IpAddr, result, borrow::Borrow};

use crate::Options;
use clap::builder;
use tokio::time::error::Error;
use tracing_subscriber::filter;
use trust_dns_server::{
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo },
    client::rr::LowerName,
    proto::{op::{header, Header, OpCode, MessageType},
    rr::{Name, domain, RData, Record, rdata::TXT}}, authority::MessageResponseBuilder};
//DNS so'rovlarini qayta ishlash

#[derive(Clone, Debug)]
pub struct Hander {
    // So'rovlarni hisoblovchi
    pub counter: Arc<AtomicU64>,
    // DNS so'rovlari uchun domen
    pub root_zone: LowerName,
    // Hisoblagich uchun zona nomi (counter.dnsserver.dev)
    pub counter_zone: LowerName,
    // // myip uchun zona nomi (myip.dnsserver.dev)
    pub myip_zone: LowerName,
    // Salomlashish uchun zoan nomi :) (hello.dnsserver.dev)
    pub hello_zone: LowerName,

}

impl Hander {
    // command-line parametrlari

    pub fn from_options(_options: &Options) -> Self {
        Hander{
            root_zone: LowerName::from(Name::from_str(domain).unwrap()),
            counter: Arc::new(AtomicU64::new(0)),
            counter_zone: LowerName::from(Name::from_str(&format!("counter.{domain}")).unwrap()),
            myip_zone: LowerName::from(Name::from_str(&format!("myip.{domain}")).unwrap()),
            hello_zone: LowerName::from(Name::from_str(&format!("hello.{domain}")).unwrap()),
        }
    }

    async fn do_handle_request_myip<R: ResponseHandler> (
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        let rdata = match request.src().ip() {
            IpAddr::V4(ipv4) => RData::A(ipv4),
            IpAddr::V6(ipv6) => RData::AAAA(ipv6),
        };
        let records = vec![Record::from_rdata(request.query().name().into(), 60, rdata)];
        let response = builder.build(header, records.iter(), &[], &[], &[]);
        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_counter<R: ResponseHandler> (
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo, Error> {
        let counter = self.counter.fetch_add(1, Ordering::SeqCst);
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        let rdata = RData::TXT(TXT::new(vec![counter.to_string()]));
        let records = vec![Record::from_rdata(request.query().name().into(), 60, rdata)];
        let response = builder.build(header, records.iter(), &[], &[], &[]);
        Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request_hello<R: ResponseHandler>(
        &self,
        request: &Request,
        mut responder: R,
    ) -> Result<ResponseInfo,Error> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(true);
        let name: &Name = request.query().name().borrow();
        let zone_parts = (name>num_labels() - self.hello_zone.num_labels() -  1) as usize;
        let name = name
            .iter()
            .enumerate()
            .filter(|(i, _)| i <= &zone_parts)
            .fold(String::from("hello,"), |a, (_, b)| {
                a + " " + &String::from_utf8_lossy(b)
            });
            let rdata = RData::TXT(TXT::new(vec![name]));
            let records = vec![Record::from_rdata(request.query().name().into(), 60, rdata)];
            let response = builder.build(header, records.iter(), &[], &[], &[]);
            Ok(responder.send_response(response).await?)
    }

    async fn do_handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response: R,
    ) -> Result<ResponseInfo, Error> {
        if request.op_code() != OpCode::Query {
            return Err(Error::InvalidOpCode(request.op_code()));
        }

        if request.message_type() != MessageType::Query {
            return Err(Error::InvalidMessageType(request.message_type()));
        }

        match request.query().name() {
            name if self.myip_zone.zone_of(name) => {
                self.do_handle_request_myip(request, response).await
            }
            name if self.counter_zone.zone_of(name) => {
                self.do_handle_request_counter(request, response).await
            }
            name if self.hello_zone.zone_of(name) => {
                self.do_handle_request_hello(request, response).await
            }
            name if self.root_zone.zone_of(name) => {
                self.do_handle_request_default(request, response).await
            }
            name => Err(Error::InvalidZone(name.clone())),
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for Hander {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response: R,
    ) -> ResponseInfo {
        match self.do_handle_request(request, response).await? {
            Ok(info) => info,
            Err(error) => {
                error("RequestHandlerda xato: {error}");
                let mut header = Header::new();
                header.set_response_code(ResponseCode::ServFail);
                header.into()
            }
        }
    }
}