use anyhow::{Result, anyhow, bail};
use moka::future::Cache;
use serde::Serialize;
use std::{
    sync::LazyLock,
    time::{Duration, Instant},
};

const IPAPI_FIELDS: &str = "query,continentCode,countryCode,region,city,district,zip,lat,lon,\
    timezone,offset,isp,org,as,asname,mobile,proxy,hosting";

static IPAPI_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .user_agent(concat!("tcpfp/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
});

static CACHE: LazyLock<Cache<String, serde_json::Value>> = LazyLock::new(|| {
    Cache::builder()
        .time_to_live(Duration::from_secs(600))
        .max_capacity(8192)
        .build()
});

#[derive(Serialize)]
#[serde(untagged)]
pub enum Reputation {
    Success {
        latency_ms: u64,
        cached: bool,
        ipapi: serde_json::Value,
    },
    Error {
        error: String,
    },
}

pub async fn lookup(source_ip: String) -> Reputation {
    match fetch_ip_api(&source_ip).await {
        Ok((cached, duration, ipapi)) => Reputation::Success {
            latency_ms: duration.as_millis() as u64,
            cached,
            ipapi,
        },
        Err(e) => {
            eprintln!("reputation lookup for {source_ip} failed: {e:#}");

            Reputation::Error {
                error: "reputation lookup failed".to_string(),
            }
        }
    }
}

async fn fetch_ip_api(lookup_ip: &str) -> Result<(bool, Duration, serde_json::Value)> {
    let cache_key = format!("ipapi:{lookup_ip}");

    if let Some(data) = CACHE.get(&cache_key).await {
        return Ok((true, Duration::ZERO, data));
    }

    let start = Instant::now();

    let key = std::env::var("TCPFP_IPAPI_KEY").unwrap_or_default();
    let response = IPAPI_CLIENT
        .get(format!("https://pro.ip-api.com/json/{lookup_ip}"))
        .query(&[("key", key.as_str()), ("fields", IPAPI_FIELDS)])
        .send()
        .await
        .map_err(reqwest::Error::without_url)?;

    let status = response.status();

    let data = response
        .json::<serde_json::Value>()
        .await
        .map_err(|_| anyhow!("failed to parse ipapi"))?;

    if !status.is_success() {
        let error_msg = data["message"]
            .as_str()
            .map(|x| format!("'{x}'"))
            .unwrap_or("unknown error".to_string());

        bail!("non-ok ipapi response: {}", error_msg);
    }

    CACHE.insert(cache_key, data.clone()).await;

    Ok((false, start.elapsed(), data))
}
