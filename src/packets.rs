extern crate pnet;

use crate::store;
use anyhow::{Context, bail};

use std::net::IpAddr;

use pnet::datalink::{self, Channel, DataLinkSender, NetworkInterface};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};

#[allow(dead_code)]
struct HandlerCtx<'a> {
    interface: &'a NetworkInterface,
    tx: &'a mut Box<dyn DataLinkSender>,
}

impl<'a> HandlerCtx<'a> {
    fn new(interface: &'a NetworkInterface, tx: &'a mut Box<dyn DataLinkSender>) -> Self {
        Self { interface, tx }
    }

    fn handle_ethernet(&self, ethernet: EthernetPacket<'a>, target_port: u16) {
        if ethernet.get_ethertype() != EtherTypes::Ipv4 {
            return;
        }

        let Some(ip) = Ipv4Packet::new(ethernet.payload()) else {
            return;
        };

        let ip_src = IpAddr::V4(ip.get_source());

        if IpNextHeaderProtocols::Tcp != ip.get_next_level_protocol() {
            return;
        }

        let Some(tcp) = TcpPacket::new(ip.payload()) else {
            return;
        };

        if tcp.get_destination() != target_port {
            return;
        }

        if tcp.get_flags() & TcpFlags::SYN == 0 {
            return;
        }

        let ip_pkt = Ipv4Packet::owned(ip.packet().to_vec()).unwrap();
        let tcp_pkt = TcpPacket::owned(tcp.packet().to_vec()).unwrap();

        let src_ip = ip_src.to_string();
        let src_port = tcp.get_source();

        tokio::spawn(async move {
            store::publish(
                src_ip,
                src_port,
                store::StoreItem {
                    ip: ip_pkt,
                    tcp: tcp_pkt,
                },
            )
            .await;
        });
    }
}

fn capture_interface() -> anyhow::Result<NetworkInterface> {
    let interfaces = datalink::interfaces();

    if let Ok(name) = std::env::var("TCPFP_INTERFACE") {
        return interfaces
            .into_iter()
            .find(|e| e.name == name)
            .with_context(|| format!("no interface named {name}"));
    }

    interfaces
        .into_iter()
        .find(|e| e.is_up() && !e.is_loopback() && e.ips.iter().any(|ip| ip.is_ipv4()))
        .context("no interface to capture on, set TCPFP_INTERFACE")
}

pub fn capture_packets(target_port: u16) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    tokio::task::spawn_blocking(move || {
        let interface = capture_interface()?;
        println!("capturing on interface '{}'", interface.name);

        let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => bail!("unsupported channel type on {}", interface.name),
            Err(e) => bail!("can't open a raw socket on {}: {e}", interface.name),
        };

        loop {
            let packet = rx.next().context("reading packets failed")?;
            if let Some(packet) = EthernetPacket::new(packet) {
                let ctx = HandlerCtx::new(&interface, &mut tx);
                ctx.handle_ethernet(packet, target_port);
            }
        }
    })
}
