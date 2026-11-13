//! PROXY protocol v2: the header a front proxy puts before each connection to
//! name the client it accepted.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

const PROXY_V2_SIGNATURE: [u8; 12] = *b"\r\n\r\n\x00\r\nQUIT\n";
const PROXY_V2_VERSION: u8 = 0x20;
const PROXY_V2_CMD_LOCAL: u8 = 0x00;
const PROXY_V2_CMD_PROXY: u8 = 0x01;
const PROXY_V2_FAMILY_UNSPEC: u8 = 0x00;
const PROXY_V2_FAMILY_TCP4: u8 = 0x11;
const PROXY_V2_FAMILY_TCP6: u8 = 0x21;
const PROXY_HEADER_TIMEOUT: Duration = Duration::from_secs(5);

/// The address to match against captured SYNs: the peer itself, or, with
/// TCPFP_PROXY_PROTOCOL on, the client named in the PROXY v2 header every
/// connection must then start with. `None` drops the connection.
pub async fn client_addr(
    socket: &mut TcpStream,
    peer: SocketAddr,
    use_proxy_protocol: bool,
) -> Option<SocketAddr> {
    if !use_proxy_protocol {
        return Some(peer);
    }

    match tokio::time::timeout(PROXY_HEADER_TIMEOUT, read_proxy_header(socket, peer)).await {
        Ok(Ok(addr)) => Some(addr),
        Ok(Err(err)) => {
            eprintln!("dropping connection from {peer}: {err:#}");
            None
        }
        Err(_) => {
            eprintln!(
                "dropping connection from {peer}: no PROXY header within {PROXY_HEADER_TIMEOUT:?}"
            );
            None
        }
    }
}

async fn read_proxy_header(socket: &mut TcpStream, peer: SocketAddr) -> anyhow::Result<SocketAddr> {
    let mut head = [0u8; 16];
    socket.read_exact(&mut head).await?;

    let length = u16::from_be_bytes([head[14], head[15]]) as usize;
    let mut body = vec![0u8; length];
    socket.read_exact(&mut body).await?;

    parse_proxy_header(&head, &body, peer)
}

fn parse_proxy_header(
    head: &[u8; 16],
    body: &[u8],
    peer: SocketAddr,
) -> anyhow::Result<SocketAddr> {
    if head[..12] != PROXY_V2_SIGNATURE {
        anyhow::bail!("no PROXY protocol v2 header");
    }

    if head[12] & 0xf0 != PROXY_V2_VERSION {
        anyhow::bail!("unsupported PROXY protocol version {:#04x}", head[12] >> 4);
    }

    match head[12] & 0x0f {
        // The proxy's own connection, e.g. a health check.
        PROXY_V2_CMD_LOCAL => return Ok(peer),
        PROXY_V2_CMD_PROXY => {}
        command => anyhow::bail!("unknown PROXY protocol command {command:#04x}"),
    }

    // TLVs after the addresses are ignored.
    match head[13] {
        PROXY_V2_FAMILY_TCP4 if body.len() >= 12 => {
            let addr = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
            let port = u16::from_be_bytes([body[8], body[9]]);
            Ok(SocketAddr::new(IpAddr::V4(addr), port))
        }
        PROXY_V2_FAMILY_TCP6 if body.len() >= 36 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&body[0..16]);
            let port = u16::from_be_bytes([body[32], body[33]]);
            Ok(SocketAddr::new(IpAddr::V6(octets.into()), port))
        }
        // The proxy knows no address for the client.
        PROXY_V2_FAMILY_UNSPEC => Ok(peer),
        family => anyhow::bail!(
            "unsupported or truncated PROXY protocol address (family {family:#04x}, {} bytes)",
            body.len()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: &str = "127.0.0.1:40000";

    fn head(version_command: u8, family: u8, body_len: u16) -> [u8; 16] {
        let mut head = [0u8; 16];
        head[..12].copy_from_slice(&PROXY_V2_SIGNATURE);
        head[12] = version_command;
        head[13] = family;
        head[14..].copy_from_slice(&body_len.to_be_bytes());
        head
    }

    fn parse(head: [u8; 16], body: &[u8]) -> anyhow::Result<SocketAddr> {
        parse_proxy_header(&head, body, PEER.parse().unwrap())
    }

    #[test]
    fn tcp6_gives_the_client_address() {
        let mut body = [0u8; 36];
        body[15] = 1; // ::1
        body[32..34].copy_from_slice(&50000u16.to_be_bytes());
        let addr = parse(head(0x21, PROXY_V2_FAMILY_TCP6, 36), &body).unwrap();
        assert_eq!(addr, "[::1]:50000".parse().unwrap());
    }

    #[test]
    fn tlvs_after_the_addresses_are_ignored() {
        let mut body = vec![203, 0, 113, 7, 10, 0, 0, 1, 0xc3, 0x50, 0x01, 0xbb];
        body.extend_from_slice(&[0x01, 0x00, 0x02, b'h', b'2']); // ALPN TLV
        let addr = parse(head(0x21, PROXY_V2_FAMILY_TCP4, 17), &body).unwrap();
        assert_eq!(addr, "203.0.113.7:50000".parse().unwrap());
    }

    #[test]
    fn local_and_unspec_keep_the_peer() {
        assert_eq!(
            parse(head(0x20, 0x00, 0), &[]).unwrap(),
            PEER.parse().unwrap()
        );
        assert_eq!(
            parse(head(0x21, PROXY_V2_FAMILY_UNSPEC, 0), &[]).unwrap(),
            PEER.parse().unwrap()
        );
    }

    #[test]
    fn malformed_headers_are_rejected() {
        let mut no_signature = head(0x21, PROXY_V2_FAMILY_TCP4, 12);
        no_signature[0] = 0x16; // a TLS ClientHello instead
        assert!(parse(no_signature, &[0; 12]).is_err());

        assert!(parse(head(0x11, PROXY_V2_FAMILY_TCP4, 12), &[0; 12]).is_err()); // version 1
        assert!(parse(head(0x22, PROXY_V2_FAMILY_TCP4, 12), &[0; 12]).is_err()); // command 2
        assert!(parse(head(0x21, PROXY_V2_FAMILY_TCP4, 4), &[0; 4]).is_err()); // truncated
        assert!(parse(head(0x21, 0x12, 12), &[0; 12]).is_err()); // UDP over IPv4
    }
}
