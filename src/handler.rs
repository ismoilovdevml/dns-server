use std::sync::{atomic::AtomicU64, Arc};

use crate::Options;
use trust_dns_server::{server::{Request, RequestHandler, ResponseHandler, ResponseInfo }, client::rr::LowerName};
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
        Hander{}
    }
}

#[async_trait::async_trait]
impl RequestHandler for Hander {
    async fn handle_request<R: ResponseHandler>(
        &self,
        _request: &Request,
        _response: R,
    ) -> ResponseInfo {
        todo!()
    }
}