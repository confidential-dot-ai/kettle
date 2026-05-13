use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;

use crate::api::{BuildRequest, JobIdResponse};
use crate::server::job::{JobRegistry, RegistryError};

#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<JobRegistry>,
    pub runner: Arc<dyn JobRunner>,
}

pub trait JobRunner: Send + Sync + 'static {
    fn spawn(&self, registry: Arc<JobRegistry>, job_id: String, req: BuildRequest);
}

pub async fn health() -> &'static str {
    "ok"
}

pub async fn post_build(
    State(state): State<AppState>,
    Json(req): Json<BuildRequest>,
) -> Result<Json<JobIdResponse>, (StatusCode, String)> {
    validate_nonce(&req.nonce)?;
    if req.repo_url.is_none() && req.source_data.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "exactly one of repo_url or source_data is required".into(),
        ));
    }
    let job_id = state
        .registry
        .try_register_with_nonce(req.nonce.clone())
        .map_err(|RegistryError::AlreadyAccepted| {
            (
                StatusCode::CONFLICT,
                "this CVM has already accepted a build".into(),
            )
        })?;
    state.runner.spawn(state.registry.clone(), job_id.clone(), req);
    Ok(Json(JobIdResponse { job_id }))
}

fn validate_nonce(nonce: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    let bytes = hex::decode(nonce)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid nonce hex: {e}")))?;
    if bytes.len() > 16 {
        return Err((StatusCode::BAD_REQUEST, "nonce must be at most 16 bytes".into()));
    }
    Ok(bytes)
}
