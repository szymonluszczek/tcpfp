use axum::Json;
use axum::extract::{ConnectInfo, Query};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use clickhouse::Row;
use hyper::{StatusCode, Uri};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::LazyLock;
use std::time::Instant;
use uuid::Uuid;

use crate::endpoints::metrics;
use crate::fingerprints::features::{IPFeatures, PacketFeatures, ReputationFeatures, TCPFeatures};
use crate::fingerprints::fingerprint_socket;
use crate::reputation::{self, Reputation};

static CLICKHOUSE_CLIENT: LazyLock<clickhouse::Client> = LazyLock::new(|| {
    clickhouse::Client::default()
        .with_url(
            std::env::var("TCPFP_CLICKHOUSE_URL")
                .unwrap_or_else(|_| "http://localhost:18123".to_string()),
        )
        .with_user("default")
        .with_password(std::env::var("TCPFP_CLICKHOUSE_PASSWORD").unwrap_or_default())
        .with_compression(clickhouse::Compression::None)
});

#[derive(Serialize)]
#[serde(untagged)]
pub enum ApiResponse {
    Index(IndexResponse),
    Lookup(LookupResponse),
    Error(ErrorResponse),
}

#[derive(Serialize)]
pub struct IndexResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    success: bool,
    error: String,
}

#[derive(Deserialize)]
pub struct IndexQuery {
    #[serde(rename = "p")]
    pub proxy_string_b64: String,
}

fn parse_proxy_domain(proxy_string: &str) -> Option<String> {
    let host = {
        if let Ok(uri) = Uri::from_str(proxy_string) {
            // http://user:pass@host:port / http://host:port
            uri.host().map(|x| x.to_string())
        } else if proxy_string.contains(":") {
            // host:port / host:port:user:pass
            proxy_string
                .split_once(":")
                .map(|(host, _)| host.to_string())
        } else {
            None
        }
    }?;

    let domain = addr::parse_domain_name(&host).ok()?;
    Some(domain.root()?.to_string())
}

async fn get_index_inner(
    query: Query<IndexQuery>,
    remote_addr: SocketAddr,
) -> anyhow::Result<ApiResponse> {
    let proxy_string = String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(&query.proxy_string_b64)?)?;
    let proxy_domain = parse_proxy_domain(&proxy_string);

    let (address, ip, tcp) = fingerprint_socket(remote_addr).await?;

    let fetch_duration = Instant::now();
    let reputation = reputation::lookup(address.clone()).await;

    metrics::observe_reputation_fetch(&reputation, fetch_duration.elapsed());

    let Reputation::Success { ipapi, .. } = reputation else {
        return Ok(ApiResponse::Index(IndexResponse {
            success: false,
            request_id: None,
        }));
    };

    let packet = PacketFeatures::process(&ip, &tcp, &address)?;
    let reputation = ReputationFeatures::process(&ipapi)?;

    let request_id = Uuid::new_v4();

    insert_request(RequestRow::from(
        request_id,
        proxy_string,
        proxy_domain,
        packet.ip,
        packet.tcp,
        reputation,
    ))
    .await?;

    Ok(ApiResponse::Index(IndexResponse {
        success: true,
        request_id: Some(request_id.to_string()),
    }))
}

pub async fn get_index(
    query: Query<IndexQuery>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
) -> (StatusCode, Json<ApiResponse>) {
    match get_index_inner(query, remote_addr).await {
        Ok(response) => (StatusCode::OK, Json(response)),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::Error(ErrorResponse {
                success: false,
                error: err.to_string(),
            })),
        ),
    }
}

#[derive(Deserialize)]
pub struct LookupQuery {
    pub ipv4: String,
}

#[derive(Serialize)]
pub struct LookupResponse {
    success: bool,
    ip_address: String,
    is_known_proxy: bool,
    tags: Vec<String>,
}

pub async fn get_lookup(query: Query<LookupQuery>) -> (StatusCode, Json<ApiResponse>) {
    let fetched = match fetch_request(&query.ipv4).await {
        Ok(res) => res,
        Err(err) => {
            eprintln!("lookup failed: {err:#}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::Error(ErrorResponse {
                    success: false,
                    error: "lookup failed".to_string(),
                })),
            );
        }
    };

    (
        StatusCode::OK,
        Json(ApiResponse::Lookup(match fetched {
            Some(row) => LookupResponse {
                success: true,
                ip_address: query.ipv4.clone(),
                is_known_proxy: true,
                tags: row.tags,
            },
            None => LookupResponse {
                success: true,
                ip_address: query.ipv4.clone(),
                is_known_proxy: false,
                tags: vec![],
            },
        })),
    )
}

async fn insert_request(req: RequestRow) -> anyhow::Result<()> {
    let mut insert = CLICKHOUSE_CLIENT.insert::<RequestRow>("requests").await?;
    insert.write(&req).await?;
    insert.end().await?;
    Ok(())
}

#[derive(Debug, Row, Deserialize)]
struct FetchedRequest {
    pub tags: Vec<String>,
}

async fn fetch_request(ip: &str) -> anyhow::Result<Option<FetchedRequest>> {
    let row = CLICKHOUSE_CLIENT
        .query(
            "SELECT groupArrayDistinct(proxy_domain) AS tags
            FROM requests
            WHERE ip_address = ?
            GROUP BY ip_address",
        )
        .bind(ip)
        .fetch_optional::<FetchedRequest>()
        .await?;

    Ok(row)
}

#[derive(Debug, Row, Serialize)]
pub struct RequestRow {
    #[serde(with = "clickhouse::serde::uuid")]
    pub request_id: Uuid,

    // proxy metadata
    pub proxy_string: String,
    pub proxy_domain: Option<String>,

    // ip features
    #[serde(with = "clickhouse::serde::ipv4")]
    pub ip_address: Ipv4Addr,
    pub ip_total_length: u16,
    pub ip_header_length: u8,
    pub ip_dscp: u8,
    pub ip_ecn: u8,
    pub ip_id_present: bool,
    pub ip_initial_ttl: u8,
    pub ip_hops_count: u8,
    pub ip_reserved_flag: bool,
    pub ip_dont_fragment: bool,
    pub ip_more_fragments: bool,
    pub ip_fragment_offset: u16,
    pub ip_options_count: u32,

    // tcp features
    pub tcp_data_offset: u8,
    pub tcp_reserved: u8,
    pub tcp_flags: u8,
    pub tcp_window_size: u16,
    pub tcp_window_scaling: u8,
    pub tcp_scaled_window_size: u32,
    pub tcp_window_mss_multiple: u16,
    pub tcp_urgent_ptr: u16,
    pub tcp_options_count: u32,
    pub tcp_options_order: String,
    pub tcp_max_segment_size: u16,
    pub tcp_mtu_size: u16,
    pub tcp_timestamp: bool,
    pub tcp_timestamp_echo_reply: bool,
    pub tcp_selective_ack: bool,

    // reputation/geo
    pub rep_as_number: String,
    pub rep_as_description: String,
    pub rep_as_name: String,
    pub rep_as_org: String,
    pub rep_as_isp: String,
    pub rep_continent_code: String,
    pub rep_country_code: String,
    pub rep_region: String,
    pub rep_city: String,
    pub rep_district: String,
    pub rep_zip_code: String,
    pub rep_timezone: String,
    pub rep_utc_offset: i64,
    pub rep_lat: f64,
    pub rep_lon: f64,
    pub rep_is_proxy: bool,
    pub rep_is_mobile: bool,
    pub rep_is_hosting: bool,
}

impl RequestRow {
    pub fn from(
        request_id: Uuid,
        proxy_string: String,
        proxy_domain: Option<String>,
        ip: IPFeatures,
        tcp: TCPFeatures,
        rep: ReputationFeatures,
    ) -> Self {
        Self {
            request_id,

            proxy_string,
            proxy_domain,

            ip_address: ip.address.parse().unwrap(),
            ip_total_length: ip.total_length,
            ip_header_length: ip.header_length,
            ip_dscp: ip.dcsp,
            ip_ecn: ip.ecn,
            ip_id_present: ip.id,
            ip_initial_ttl: ip.initial_ttl,
            ip_hops_count: ip.hops_count,
            ip_reserved_flag: ip.reserved_flag,
            ip_dont_fragment: ip.dont_fragment,
            ip_more_fragments: ip.more_fragments,
            ip_fragment_offset: ip.fragment_offset,
            ip_options_count: ip.options_count as u32,

            tcp_data_offset: tcp.data_offset,
            tcp_reserved: tcp.reserved,
            tcp_flags: tcp.flags,
            tcp_window_size: tcp.window_size,
            tcp_window_scaling: tcp.window_scaling,
            tcp_scaled_window_size: tcp.scaled_window_size,
            tcp_window_mss_multiple: tcp.window_mss_multiple,
            tcp_urgent_ptr: tcp.urgent_ptr,
            tcp_options_count: tcp.options_count as u32,
            tcp_options_order: tcp.options_order,
            tcp_max_segment_size: tcp.max_segment_size,
            tcp_mtu_size: tcp.mtu_size,
            tcp_timestamp: tcp.timestamp,
            tcp_timestamp_echo_reply: tcp.timestamp_echo_reply,
            tcp_selective_ack: tcp.selective_ack,

            rep_as_number: rep.as_number,
            rep_as_description: rep.as_description,
            rep_as_name: rep.as_name,
            rep_as_org: rep.as_org,
            rep_as_isp: rep.as_isp,
            rep_continent_code: rep.continent_code,
            rep_country_code: rep.country_code,
            rep_region: rep.region,
            rep_city: rep.city,
            rep_district: rep.district,
            rep_zip_code: rep.zip_code,
            rep_timezone: rep.timezone,
            rep_utc_offset: rep.utc_offset,
            rep_lat: rep.lat,
            rep_lon: rep.lon,
            rep_is_proxy: rep.is_proxy,
            rep_is_mobile: rep.is_mobile,
            rep_is_hosting: rep.is_hosting,
        }
    }
}
