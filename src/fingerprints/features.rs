use crate::fingerprints::ip::IPFingerprint;
use crate::fingerprints::tcp::TCPFingerprint;
use anyhow::{anyhow, bail};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct IPFeatures {
    pub address: String,
    pub total_length: u16,
    pub header_length: u8,
    pub dcsp: u8,
    pub ecn: u8,
    pub id: bool,
    pub initial_ttl: u8,
    pub hops_count: u8,
    pub reserved_flag: bool,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    pub fragment_offset: u16,
    pub options_count: usize,
}

#[derive(Debug, Serialize)]
pub struct TCPFeatures {
    pub data_offset: u8,
    pub reserved: u8,
    pub flags: u8,
    pub window_size: u16,
    pub window_scaling: u8,
    pub scaled_window_size: u32,
    pub window_mss_multiple: u16,
    pub urgent_ptr: u16,
    pub options_count: usize,
    pub options_order: String,
    pub max_segment_size: u16,
    pub mtu_size: u16,
    pub timestamp: bool,
    pub timestamp_echo_reply: bool,
    pub selective_ack: bool,
}

#[derive(Debug, Serialize)]
pub struct PacketFeatures {
    pub ip: IPFeatures,
    pub tcp: TCPFeatures,
}

impl PacketFeatures {
    pub fn process(
        ip: &IPFingerprint,
        tcp: &TCPFingerprint,
        address: &str,
    ) -> anyhow::Result<Self> {
        let initial_ttl = Self::estimate_initial_ttl(ip.ttl);
        let hops_count = initial_ttl - ip.ttl;

        Ok(Self {
            ip: IPFeatures {
                address: address.to_string(),
                total_length: ip.total_length,
                header_length: ip.header_length,
                dcsp: ip.dcsp,
                ecn: ip.ecn,
                id: ip.id != 0,
                initial_ttl,
                hops_count,
                reserved_flag: ip.flag_reserved,
                dont_fragment: ip.flag_dont_fragment,
                more_fragments: ip.flag_more_fragments,
                fragment_offset: ip.fragment_offset,
                options_count: ip.options.len(),
            },

            tcp: TCPFeatures {
                data_offset: tcp.data_offset,
                reserved: tcp.reserved,
                flags: tcp.flags,

                window_size: tcp.window_size,
                window_scaling: tcp.window_scaling.unwrap_or(0),

                // RFC 7323 caps the shift at 14
                scaled_window_size: (tcp.window_size as u32)
                    << tcp.window_scaling.unwrap_or(0).min(14),

                // window / mss when it divides evenly (linux: 64240 = 44 * 1460), else 0
                window_mss_multiple: match tcp.max_segment_size {
                    Some(mss) if mss > 0 && tcp.window_size.is_multiple_of(mss) => {
                        tcp.window_size / mss
                    }
                    _ => 0,
                },

                urgent_ptr: tcp.urgent_ptr,

                options_count: tcp.options.len(),
                options_order: tcp
                    .options
                    .iter()
                    .map(|x| x.id.to_string())
                    .collect::<Vec<String>>()
                    .join(","),

                max_segment_size: tcp.max_segment_size.unwrap_or(0),

                // mtu = mss + 20 + 20
                mtu_size: tcp.max_segment_size.map_or(0, |mss| mss.saturating_add(40)),

                timestamp: tcp.timestamp_my.is_some_and(|x| x != 0),
                timestamp_echo_reply: tcp.timestamp_their.is_some_and(|x| x != 0),

                selective_ack: tcp.selective_ack,
            },
        })
    }

    fn estimate_initial_ttl(ttl: u8) -> u8 {
        match ttl {
            0..=32 => 32,
            33..=64 => 64,
            65..=128 => 128,
            129..=255 => 255,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ReputationFeatures {
    // "as": "AS6167 ................",
    pub as_number: String,

    // "as": "...... Verizon Business",
    pub as_description: String,

    // "asname": "CELLCO-PART",
    pub as_name: String,

    // "org": "Verizon Business",
    pub as_org: String,

    // "isp": "Verizon Business",
    pub as_isp: String,

    // "continentCode": "NA",
    pub continent_code: String,

    // "countryCode": "US",
    pub country_code: String,

    // "city": "Linden",
    pub city: String,

    // "district": "",
    pub district: String,

    // "lat": 40.6342,
    pub lat: f64,

    // "lon": -74.2427,
    pub lon: f64,

    // "region": "NJ",
    pub region: String,

    // "zip": "07036",
    pub zip_code: String,

    // "timezone": "America/New_York",
    pub timezone: String,

    // "offset": -14400,
    pub utc_offset: i64,

    pub is_proxy: bool,
    pub is_mobile: bool,
    pub is_hosting: bool,
}

impl ReputationFeatures {
    pub fn process(ipapi: &serde_json::Value) -> anyhow::Result<Self> {
        let ipapi_as = ipapi["as"]
            .as_str()
            .ok_or(anyhow!("as info is missing"))?
            .trim();

        let (as_number, as_description) = if ipapi_as.contains(" ") {
            ipapi_as
                .split_once(" ")
                .map(|(x, y)| (x.trim(), y.trim()))
                .ok_or(anyhow!("as info split error"))?
        } else if ipapi_as.to_uppercase().starts_with("AS") {
            (ipapi_as, "")
        } else {
            bail!("malformed as info");
        };

        Ok(ReputationFeatures {
            as_number: as_number.to_string(),

            as_description: as_description.to_string(),

            as_name: ipapi["asname"]
                .as_str()
                .ok_or(anyhow!("as name is missing"))?
                .to_string(),

            as_org: ipapi["org"]
                .as_str()
                .ok_or(anyhow!("as org is missing"))?
                .to_string(),

            as_isp: ipapi["isp"]
                .as_str()
                .ok_or(anyhow!("as isp is missing"))?
                .to_string(),

            continent_code: ipapi["continentCode"]
                .as_str()
                .ok_or(anyhow!("continent code is missing"))?
                .to_string(),

            country_code: ipapi["countryCode"]
                .as_str()
                .ok_or(anyhow!("country code is missing"))?
                .to_string(),

            city: ipapi["city"]
                .as_str()
                .ok_or(anyhow!("city is missing"))?
                .to_string(),

            district: ipapi["district"]
                .as_str()
                .ok_or(anyhow!("district is missing"))?
                .to_string(),

            lat: ipapi["lat"].as_f64().ok_or(anyhow!("lat is missing"))?,

            lon: ipapi["lon"].as_f64().ok_or(anyhow!("lon is missing"))?,

            region: ipapi["region"]
                .as_str()
                .ok_or(anyhow!("region is missing"))?
                .to_string(),

            zip_code: ipapi["zip"]
                .as_str()
                .ok_or(anyhow!("zip code is missing"))?
                .to_string(),

            timezone: ipapi["timezone"]
                .as_str()
                .ok_or(anyhow!("timezone is missing"))?
                .to_string(),

            utc_offset: ipapi["offset"]
                .as_i64()
                .ok_or(anyhow!("utc offset is missing"))?,

            is_proxy: ipapi["proxy"]
                .as_bool()
                .ok_or(anyhow!("proxy is missing"))?,

            is_mobile: ipapi["mobile"]
                .as_bool()
                .ok_or(anyhow!("mobile is missing"))?,

            is_hosting: ipapi["hosting"]
                .as_bool()
                .ok_or(anyhow!("hosting is missing"))?,
        })
    }
}
