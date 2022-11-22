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