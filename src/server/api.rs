use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use futures_util::stream::{Stream, StreamExt};

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
    if bytes.len() != 16 {
        return Err((StatusCode::BAD_REQUEST, "nonce must be exactly 16 bytes".into()));
    }
    Ok(bytes)
}

pub async fn get_events(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl axum::response::IntoResponse, StatusCode> {
    let job = state.registry.get(&id).ok_or(StatusCode::NOT_FOUND)?;
    let rx = job.subscribe();
    let backlog = job.snapshot_events().await;

    let backlog_stream = futures_util::stream::iter(
        backlog.into_iter().map(|e| Ok::<_, Infallible>(to_sse(e)))
    );

    let live_stream = tokio_stream::wrappers::BroadcastStream::new(rx)
        .filter_map(|res| async move {
            res.ok().map(|e| Ok::<_, Infallible>(to_sse(e)))
        });

    let stream: Pin<Box<dyn Stream<Item = Result<SseEvent, Infallible>> + Send>> =
        Box::pin(backlog_stream.chain(live_stream));
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

fn to_sse(event: crate::api::Event) -> SseEvent {
    SseEvent::default().data(serde_json::to_string(&event).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_nonce_accepts_exactly_16_bytes() {
        let nonce: [u8; 16] = rand::random();
        let bytes = validate_nonce(&hex::encode(nonce))
            .expect("16-byte nonce must be accepted");
        assert_eq!(bytes, nonce);
    }

    #[test]
    fn validate_nonce_rejects_non_16_byte_lengths() {
        for nonce in [
            "",
            "00",
            "00112233445566778899aabbccddee",   // 15 bytes
            "00112233445566778899aabbccddeeff00", // 17 bytes
        ] {
            let (status, msg) = validate_nonce(nonce)
                .expect_err(&format!("nonce {nonce:?} must be rejected"));
            assert_eq!(status, StatusCode::BAD_REQUEST, "nonce {nonce:?}");
            assert!(msg.contains("16 bytes"), "nonce {nonce:?}: {msg}");
        }
    }
}

pub async fn get_result(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<axum::response::Response, StatusCode> {
    let job = state.registry.get(&id).ok_or(StatusCode::NOT_FOUND)?;
    let path = job.result.get().ok_or(StatusCode::NOT_FOUND)?;
    let file = tokio::fs::File::open(path)
        .await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let stream = tokio_util::io::ReaderStream::new(file);
    Ok(axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/gzip")
        .body(axum::body::Body::from_stream(stream))
        .unwrap())
}
