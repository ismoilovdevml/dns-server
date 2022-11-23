use anyhow::Result;
use clap::Parser;
use handler::Hander;
use options::Options;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use trust_dns_server::ServerFuture;

mod handler;
mod options;

//TCP ulanishi uchun timeout

const TCP_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let options =Options::parse();
    let handler = Hander::from_options(&options);

    // DNS server yaratamiz

    let mut server = ServerFuture::new(handler);

    // UDP ni ro'yxatdan o'tkazish
    for udp in &options.udp {
        server.register_socket(UdpSocket::bind(&udp).await?);
    }
    // TCP ni ro'yxatdan o'tkazish

    for tcp in &options.tcp {
        server.register_listener(TcpListener::bind(&tcp).await?, TCP_TIMEOUT);
    }
    // DNS serverni ishga tushirish
    server.block_until_done().await?;
    Ok(())
}