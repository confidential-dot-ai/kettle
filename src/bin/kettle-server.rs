use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use kettle::commands::attest::AttestArgs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

use kettle::commands;

struct AppState {
    busy: Mutex<bool>,
}

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("KETTLE_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let state = Arc::new(AppState {
        busy: Mutex::new(false),
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/build", post(build_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .expect("failed to bind");

    eprintln!("kettle-server listening on 0.0.0.0:{port}");
    axum::serve(listener, app).await.expect("server error");
}

async fn health() -> &'static str {
    "ok"
}

async fn build_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, [(&'static str, &'static str); 1], Vec<u8>), (StatusCode, String)> {
    let mut busy = state.busy.lock().await;
    if *busy {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "busy".to_string()));
    }
    *busy = true;

    let result = do_build(&headers, &body).await;

    *busy = false;
    result
}

async fn do_build(
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<(StatusCode, [(&'static str, &'static str); 1], Vec<u8>), (StatusCode, String)> {
    let nonce_hex = headers
        .get("x-nonce")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "missing X-Nonce header".to_string(),
            )
        })?;

    let nonce_bytes = hex::decode(nonce_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid nonce hex: {e}")))?;

    if nonce_bytes.len() > 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            "nonce must be at most 32 bytes".to_string(),
        ));
    }

    // Create work directory
    let work_id = uuid::Uuid::new_v4();
    let work_dir = PathBuf::from(format!("/tmp/kettle-work-{work_id}"));
    std::fs::create_dir_all(&work_dir)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("mkdir: {e}")))?;

    // Extract tarball
    let gz = GzDecoder::new(body.as_ref());
    let mut archive = tar::Archive::new(gz);
    archive
        .unpack(&work_dir)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("bad archive: {e}")))?;

    // Find project dir: if single top-level directory, use that
    let project_dir = find_project_dir(&work_dir)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("bad project layout: {e}")))?;

    // Initialize a git repo if one doesn't exist (tarballs don't include .git)
    if !project_dir.join(".git").exists() {
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(&project_dir)
            .output()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("git init: {e}")))?;
        std::process::Command::new("git")
            .args(["add", "."])
            .current_dir(&project_dir)
            .output()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("git add: {e}")))?;
        std::process::Command::new("git")
            .args([
                "-c",
                "user.name=kettle",
                "-c",
                "user.email=kettle@build",
                "commit",
                "-m",
                "build",
            ])
            .current_dir(&project_dir)
            .output()
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("git commit: {e}"),
                )
            })?;
    }

    // Run attest with nonce
    commands::attest::attest(AttestArgs {
        path: project_dir.clone(),
        nonce: Some(hex::encode(nonce_bytes)),
    })
    .await
    .map_err(|e| (StatusCode::CONFLICT, format!("build failed: {e}")))?;

    // Tar up kettle-build/ directory as response
    let kettle_build_dir = project_dir.join("kettle-build");
    let mut result_buf = Vec::new();
    {
        let enc = GzEncoder::new(&mut result_buf, Compression::fast());
        let mut builder = tar::Builder::new(enc);
        builder
            .append_dir_all(".", &kettle_build_dir)
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("tar result: {e}"),
                )
            })?;
        let enc = builder.into_inner().map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("tar finish: {e}"),
            )
        })?;
        enc.finish()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("gz finish: {e}")))?;
    }

    // Cleanup
    let _ = std::fs::remove_dir_all(&work_dir);

    Ok((
        StatusCode::OK,
        [("content-type", "application/gzip")],
        result_buf,
    ))
}

fn find_project_dir(work_dir: &PathBuf) -> Result<PathBuf, String> {
    let entries: Vec<_> = std::fs::read_dir(work_dir)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok())
        .collect();

    if entries.len() == 1 && entries[0].file_type().map(|t| t.is_dir()).unwrap_or(false) {
        return Ok(entries[0].path());
    }

    Ok(work_dir.clone())
}
