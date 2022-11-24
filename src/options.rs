use clap::Parser;
use std::net::SocketAddr;

#[derive(Parser, Clone, Debug)]
pub struct Options {
    //UDP ni o'qish
    #[clap(long, short, default_value = "0.0.0.0:1053", env = "DNS_UDP")]
    pub udp: Vec<SocketAddr>,

    // TCP ni o'qish
    #[clap(long, short, env = "DNS_TCP")]
    pub tcp: Vec<SocketAddr>,

    //Domen nomi
    #[clap(long, short, default_value = "dnsserver.dev", env = "DNS_DOMEN")]
    pub domain: String,
}

  // async fn do_handle_request_myip<R: ResponseHandler> (
    //     &self,
    //     request: &Request,
    //     mut responder: R,
    // ) -> Result<ResponseInfo, Error> {
    //     self.counter.fetch_add(1, Odering::SeqCst);
    //     let builder = MessageResponseBuilder::from_message_request(request);
    //     let mut header = Header::response_from_request(request.header());
    //     header.set_authoritative(true);
    //     let rdata = match request.src().ip() {
    //         IpAddr::V4(ipv4) => RData::A(ipv4),
    //         IpAddr::v6(ipv6) => RData::AAAA(ipv6),
    //     };
    //     let records = vec![Record::from_rdata(request.query().name().into(), 60,
    //     let response = builder.build(header, records.iter(), &[], &[], &[]);
    //     Ok(responder.send_response(response).await?)
    // }