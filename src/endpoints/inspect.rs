use axum::Json;
use axum::extract::{ConnectInfo, Query};
use hyper::StatusCode;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Instant;

use crate::endpoints::metrics;
use crate::fingerprints::features::{IPFeatures, PacketFeatures, ReputationFeatures, TCPFeatures};
use crate::fingerprints::fingerprint_socket;
use crate::fingerprints::{ip::IPFingerprint, tcp::TCPFingerprint};
use crate::inference;
use crate::reputation::{self, Reputation};

#[derive(Serialize)]
#[serde(untagged)]
pub enum ApiResponse {
    Fingerprint(FingerprintResponse),
    Details(DetailsResponse),
    Error(ErrorResponse),
}

#[derive(Serialize)]
pub struct Features {
    ip: IPFeatures,
    tcp: TCPFeatures,
    rep: Option<ReputationFeatures>,
}

#[derive(Serialize)]
pub struct FingerprintResponse {
    address: String,
    ip: IPFingerprint,
    tcp: TCPFingerprint,
    features: Features,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    error: String,
}

async fn get_fingerprint_inner(remote_addr: SocketAddr) -> anyhow::Result<ApiResponse> {
    let (address, ip, tcp) = fingerprint_socket(remote_addr).await?;

    let packet = PacketFeatures::process(&ip, &tcp, &address)?;
    let features = Features {
        ip: packet.ip,
        tcp: packet.tcp,
        rep: None,
    };

    Ok(ApiResponse::Fingerprint(FingerprintResponse {
        address,
        ip,
        tcp,
        features,
    }))
}

pub async fn get_fingerprint(
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
) -> (StatusCode, Json<ApiResponse>) {
    match get_fingerprint_inner(remote_addr).await {
        Ok(response) => (StatusCode::OK, Json(response)),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::Error(ErrorResponse {
                error: err.to_string(),
            })),
        ),
    }
}

#[derive(Serialize)]
pub struct DetailsResponse {
    address: String,
    ip: IPFingerprint,
    tcp: TCPFingerprint,
    reputation: Reputation,
    features: Features,
    inference: Option<inference::MLInferenceResult>,
}

#[derive(Deserialize)]
pub struct DetailsQuery {
    infer: Option<String>,
}

async fn get_details_inner(
    query: Query<DetailsQuery>,
    remote_addr: SocketAddr,
) -> anyhow::Result<ApiResponse> {
    let (address, ip, tcp) = fingerprint_socket(remote_addr).await?;

    let fetch_duration = Instant::now();
    let reputation = reputation::lookup(address.clone()).await;

    metrics::observe_reputation_fetch(&reputation, fetch_duration.elapsed());

    let packet = PacketFeatures::process(&ip, &tcp, &address)?;
    let rep = match &reputation {
        Reputation::Success { ipapi, .. } => Some(ReputationFeatures::process(ipapi)?),
        _ => None,
    };

    let features = Features {
        ip: packet.ip,
        tcp: packet.tcp,
        rep,
    };

    let infer = if let Some(model) = &query.infer {
        Some(inference::infer_trained_model(model, &serde_json::to_value(&features).unwrap()).await)
    } else {
        None
    };

    Ok(ApiResponse::Details(DetailsResponse {
        address,
        ip,
        tcp,
        reputation,
        features,
        inference: infer.and_then(|x| x.ok()),
    }))
}

pub async fn get_details(
    query: Query<DetailsQuery>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
) -> (StatusCode, Json<ApiResponse>) {
    match get_details_inner(query, remote_addr).await {
        Ok(response) => (StatusCode::OK, Json(response)),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::Error(ErrorResponse {
                error: err.to_string(),
            })),
        ),
    }
}
