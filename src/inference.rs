use anyhow::anyhow;
use elasticsearch::{
    Elasticsearch,
    auth::Credentials,
    cert::CertificateValidation,
    http::transport::{SingleNodeConnectionPool, TransportBuilder},
    ml::MlInferTrainedModelParts,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

static ELASTIC_CLIENT: LazyLock<Option<Elasticsearch>> = LazyLock::new(|| {
    let url = Url::parse(&std::env::var("TCPFP_ES_URL").ok()?).ok()?;
    let key = std::env::var("TCPFP_ES_API_KEY")
        .ok()
        .filter(|key| !key.is_empty())?;

    let transport = TransportBuilder::new(SingleNodeConnectionPool::new(url))
        .cert_validation(CertificateValidation::None)
        .auth(Credentials::EncodedApiKey(key))
        .build()
        .ok()?;

    Some(Elasticsearch::new(transport))
});

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MLInferenceClass {
    #[serde(rename = "class_name")]
    pub name: serde_json::Value,

    #[serde(rename = "class_probability")]
    pub probability: f64,

    #[serde(rename = "class_score")]
    pub score: f64,
}

#[derive(Debug, Serialize)]
pub struct MLInferenceResult {
    pub top_classes: Vec<MLInferenceClass>,
    pub true_probability: Option<f64>,
    pub true_score: Option<f64>,
}

pub async fn infer_trained_model(
    model: &str,
    data: &serde_json::Value,
) -> anyhow::Result<MLInferenceResult> {
    let client = ELASTIC_CLIENT
        .clone()
        .ok_or(anyhow!("inference is not configured"))?;

    let response = client
        .ml()
        .infer_trained_model(MlInferTrainedModelParts::ModelId(model))
        .body(serde_json::json!({ "docs": [data] }))
        .send()
        .await?;

    let body = response.json::<serde_json::Value>().await?;

    let top_classes = body["inference_results"][0]["top_classes"]
        .as_array()
        .ok_or(anyhow!("top_classes is not an array"))?
        .iter()
        .filter_map(|x| serde_json::from_value::<MLInferenceClass>(x.clone()).ok())
        .collect::<Vec<_>>();

    let true_class = top_classes
        .iter()
        .find(|x| x.name.as_bool().is_some_and(|b| b))
        .cloned();

    Ok(MLInferenceResult {
        top_classes,
        true_probability: true_class.clone().map(|x| x.probability),
        true_score: true_class.map(|x| x.score),
    })
}
