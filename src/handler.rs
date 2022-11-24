use std::{sync::{atomic::AtomicU64, Arc}, str::FromStr, net::IpAddr, result};

use crate::Options;
use tokio::time::error::Error;
use trust_dns_server::{
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo },
    client::rr::LowerName,
    proto::{op::{header, Header, OpCode, MessageType},
    rr::{Name, domain, RData}}, authority::MessageResponseBuilder};
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
            name if &self.myip_zone.zone_of(name) => {
                self.do_handle_request_myip(request, response).await
            }
            name if &self.counter_zone.zone_of(name) => {
                self.do_handle_request_counter(request, response).await
            }
            name if &self.hello_zone.zone_of(name) => {
                self.do_handle_request_hello(request, response).await
            }
            name if &self.root_zone.zone_of(name) => {
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