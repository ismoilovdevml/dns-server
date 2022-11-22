use anyhow::Result;
use clap::Parser;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use trust_dns_server::ServerFuture;


#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
}