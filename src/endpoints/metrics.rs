use lazy_static::lazy_static;
use prometheus::{self, Encoder, HistogramVec, TextEncoder, register_histogram_vec};
use std::time::Duration;

use crate::reputation::Reputation;

lazy_static! {
    static ref REPUTATION_FETCH_SECONDS: HistogramVec = register_histogram_vec!(
        "reputation_fetch_duration_seconds",
        "Time to get IP reputation for a request, by whether it came from the cache",
        &["cached"]
    )
    .unwrap();
}

pub fn observe_reputation_fetch(reputation: &Reputation, elapsed: Duration) {
    let cached = match reputation {
        Reputation::Success { cached: true, .. } => "true",
        Reputation::Success { cached: false, .. } => "false",
        Reputation::Error { .. } => "unknown",
    };

    REPUTATION_FETCH_SECONDS
        .with_label_values(&[cached])
        .observe(elapsed.as_secs_f64());
}

pub async fn get_metrics() -> String {
    let mut buffer = Vec::new();
    let encoder = TextEncoder::new();
    encoder.encode(&prometheus::gather(), &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}
