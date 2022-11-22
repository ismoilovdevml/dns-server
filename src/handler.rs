use crate::Options;
use trust_dns_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo };
//DNS so'rovlarini ishlash

#[derive(Clone, Debug)]
pub struct Hander {}

impl Handler {
    // command-line parametrlari

    pub fn from_options(_options: &Options) -> Self {
        Handler{}
    }
}

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        _request: &Request,
        _response: R,
    ) -> ResponseInfo {
        todo!()
    }
}