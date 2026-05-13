use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BuildRequest {
    pub nonce: String,
    #[serde(default)]
    pub repo_url: Option<String>,
    #[serde(default)]
    pub repo_ref: Option<String>,
    #[serde(default, with = "serde_with::As::<Option<serde_with::base64::Base64>>")]
    pub source_data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Queued { position: usize },
    Vm { msg: String },
    Init { msg: String },
    Detect { msg: String },
    Build { msg: String },
    Provenance { msg: String },
    Attest { msg: String },
    Complete { result: BuildResult },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BuildResult {
    Ok,
    Failed { error: String, error_type: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobIdResponse {
    pub job_id: String,
}
