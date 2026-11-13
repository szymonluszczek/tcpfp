use pnet::packet::{
    Packet,
    tcp::{TcpOptionNumbers, TcpPacket},
};
use serde::Serialize;

#[derive(Serialize)]
pub struct TCPOption {
    pub id: u8,
    pub data: Vec<u8>,
}

#[derive(Serialize)]
pub struct TCPFingerprint {
    pub seq: u32,
    pub ack: u32,
    pub data_offset: u8,
    pub reserved: u8,
    pub flags: u8,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
    pub options: Vec<TCPOption>,
    pub max_segment_size: Option<u16>,
    pub window_scaling: Option<u8>,
    pub timestamp_my: Option<u32>,
    pub timestamp_their: Option<u32>,
    pub selective_ack: bool,
}

impl TCPFingerprint {
    pub fn from_packet(pkt: &TcpPacket) -> Self {
        let mut options: Vec<TCPOption> = vec![];

        let mut max_segment_size: Option<u16> = None;
        let mut window_scaling: Option<u8> = None;
        let mut timestamp_my: Option<u32> = None;
        let mut timestamp_their: Option<u32> = None;
        let mut selective_ack = false;

        for opt in pkt.get_options_iter() {
            let p = opt.payload();

            match opt.get_number() {
                TcpOptionNumbers::MSS => {
                    if let Some(&[a, b]) = p.get(..2) {
                        max_segment_size = Some(u16::from_be_bytes([a, b]));
                    }
                }
                TcpOptionNumbers::WSCALE => {
                    window_scaling = p.first().copied();
                }
                TcpOptionNumbers::TIMESTAMPS => {
                    if let Some(&[a, b, c, d, e, f, g, h]) = p.get(..8) {
                        timestamp_my = Some(u32::from_be_bytes([a, b, c, d]));
                        timestamp_their = Some(u32::from_be_bytes([e, f, g, h]));
                    }
                }
                TcpOptionNumbers::SACK_PERMITTED => {
                    selective_ack = true;
                }
                _ => {}
            }

            options.push(TCPOption {
                id: opt.get_number().0,
                data: p.to_vec(),
            });
        }

        Self {
            seq: pkt.get_sequence(),
            ack: pkt.get_acknowledgement(),
            data_offset: pkt.get_data_offset(),
            reserved: pkt.get_reserved(),
            flags: pkt.get_flags(),
            window_size: pkt.get_window(),
            checksum: pkt.get_checksum(),
            urgent_ptr: pkt.get_urgent_ptr(),
            options,
            max_segment_size,
            window_scaling,
            timestamp_my,
            timestamp_their,
            selective_ack,
        }
    }
}
