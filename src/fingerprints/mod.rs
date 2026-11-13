use std::net::SocketAddr;

use crate::store;

pub mod features;

pub mod ip;
use ip::IPFingerprint;

pub mod tcp;
use tcp::TCPFingerprint;

pub async fn fingerprint_socket(
    remote_addr: SocketAddr,
) -> anyhow::Result<(String, IPFingerprint, TCPFingerprint)> {
    let ip_str = remote_addr.ip().to_string();

    let pkts = store::consume(ip_str.clone(), remote_addr.port()).await?;

    let ip_fp = IPFingerprint::from_packet(&pkts.ip);
    let tcp_fp = TCPFingerprint::from_packet(&pkts.tcp);

    Ok((ip_str, ip_fp, tcp_fp))
}
