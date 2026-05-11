use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProcessorError {
    #[error("backend error: {0}")]
    Backend(String),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("store error: {0}")]
    Store(#[from] deepsec_core::StoreError),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("quota exhausted: {0:?}")]
    Quota(QuotaExhausted),
    #[error("config error: {0}")]
    Config(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Debug, Clone)]
pub struct QuotaExhausted {
    pub backend: String,
    pub detail: String,
}
