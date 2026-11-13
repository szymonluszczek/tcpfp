use pnet::packet::{
    Packet,
    ipv4::{Ipv4Flags, Ipv4Packet},
};
use serde::Serialize;

#[derive(Serialize)]
pub struct IPOption {
    pub id: u8,
    pub class: u8,
    pub copied: u8,
    pub data: Vec<u8>,
}

#[derive(Serialize)]
pub struct IPFingerprint {
    pub version: u8,

    pub total_length: u16,
    pub header_length: u8,

    pub dcsp: u8,
    pub ecn: u8,

    pub id: u16,
    pub ttl: u8,

    pub protocol: u8,

    pub flag_reserved: bool,       // & Ipv4Flags::Reserved (0b100)
    pub flag_dont_fragment: bool,  // & Ipv4Flags::DontFragment (0b010)
    pub flag_more_fragments: bool, // & Ipv4Flags::MoreFragments (0b001)

    pub fragment_offset: u16,

    pub options: Vec<IPOption>,

    pub checksum: u16,
}

impl IPFingerprint {
    pub fn from_packet(pkt: &Ipv4Packet) -> Self {
        Self {
            version: pkt.get_version(),

            total_length: pkt.get_total_length(),
            header_length: pkt.get_header_length(),

            dcsp: pkt.get_dscp(),
            ecn: pkt.get_ecn(),

            id: pkt.get_identification(),
            ttl: pkt.get_ttl(),

            protocol: pkt.get_next_level_protocol().0,

            flag_reserved: (pkt.get_flags() & (0b100)) != 0, // & Ipv4Flags::Reserved,
            flag_dont_fragment: (pkt.get_flags() & Ipv4Flags::DontFragment) != 0, // & Ipv4Flags::DontFragment,
            flag_more_fragments: (pkt.get_flags() & Ipv4Flags::MoreFragments) != 0, // & Ipv4Flags::MoreFragments,

            fragment_offset: pkt.get_fragment_offset(),

            options: pkt
                .get_options_iter()
                .map(|x| IPOption {
                    id: x.get_number().0,
                    class: x.get_class(),
                    copied: x.get_copied(),
                    data: x.payload().to_vec(),
                })
                .collect(),

            checksum: pkt.get_checksum(),
        }
    }
}
