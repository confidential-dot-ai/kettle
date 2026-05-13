#![cfg(feature = "server")]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use kettle::api::{BuildRequest, BuildResult, Event, JobIdResponse};
use kettle::server::job::JobRegistry;
use tower::ServiceExt;

fn router_with_immediate_complete() -> axum::Router {
    use kettle::server::api::{AppState, JobRunner};
    struct ImmediateRunner;
    impl JobRunner for ImmediateRunner {
        fn spawn(
            &self,
            registry: Arc<JobRegistry>,
            job_id: String,
            _req: BuildRequest,
        ) {
            tokio::spawn(async move {
                let job = registry.get(&job_id).unwrap();
                job.push_event(Event::Detect { msg: "found cargo".into() }).await;
                job.push_event(Event::Complete { result: BuildResult::Ok }).await;
                job.mark_done().await;
            });
        }
    }
    let registry = JobRegistry::new();
    let state = AppState { registry, runner: Arc::new(ImmediateRunner) };
    use axum::{Router, routing::{get, post}};
    use kettle::server::api::{health, post_build};
    Router::new()
        .route("/health", get(health))
        .route("/build", post(post_build))
        .route("/build/{id}/events", get(kettle::server::api::get_events))
        .with_state(state)
}

#[tokio::test]
async fn events_endpoint_streams_complete_event() {
    let app = router_with_immediate_complete();
    let body = serde_json::to_vec(&BuildRequest {
        nonce: "00".into(),
        repo_url: Some("https://x".into()),
        repo_ref: None,
        source_data: None,
    }).unwrap();
    let post = app
        .clone()
        .oneshot(Request::post("/build")
            .header("content-type", "application/json")
            .body(Body::from(body)).unwrap())
        .await.unwrap();
    let bytes = axum::body::to_bytes(post.into_body(), 1024).await.unwrap();
    let JobIdResponse { job_id } = serde_json::from_slice(&bytes).unwrap();

    // Give the immediate runner a moment to publish its events.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let resp = app
        .oneshot(Request::get(format!("/build/{job_id}/events"))
            .body(Body::empty()).unwrap())
        .await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ctype = resp.headers().get("content-type").unwrap().to_str().unwrap();
    assert!(ctype.starts_with("text/event-stream"), "got {ctype}");

    let body = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let s = String::from_utf8(body.to_vec()).unwrap();
    assert!(s.contains(r#""type":"detect""#), "missing detect event: {s}");
    assert!(s.contains(r#""type":"complete""#), "missing complete event: {s}");
    assert!(s.contains(r#""status":"ok""#), "missing ok status: {s}");
}

#[tokio::test]
async fn events_endpoint_unknown_job_returns_404() {
    let app = router_with_immediate_complete();
    let resp = app
        .oneshot(Request::get("/build/nope/events").body(Body::empty()).unwrap())
        .await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn events_endpoint_does_not_drop_event_between_snapshot_and_subscribe() {
    // Race scenario: register a job, then in a tight loop alternately push events
    // and connect to /events. Every received stream must end with a Complete
    // event (no terminal-event drops).
    use kettle::server::api::{AppState, JobRunner};
    use std::sync::Arc;
    use kettle::server::job::JobRegistry;
    struct DelayedRunner;
    impl JobRunner for DelayedRunner {
        fn spawn(&self, registry: Arc<JobRegistry>, job_id: String, _req: BuildRequest) {
            tokio::spawn(async move {
                let job = registry.get(&job_id).unwrap();
                // Spam events for ~100ms then mark done; the SSE connect will race.
                for _ in 0..20 {
                    job.push_event(Event::Build { msg: "log".into() }).await;
                    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                }
                job.push_event(Event::Complete { result: BuildResult::Ok }).await;
                job.mark_done().await;
            });
        }
    }

    // Do NOT keep an extra Arc<JobRegistry> reference in this scope.
    // The SSE stream terminates only when the broadcast sender drops, which
    // requires all Arc<JobRegistry> (and thus Arc<ServerJob>) clones to drop.
    let state = AppState { registry: JobRegistry::new(), runner: Arc::new(DelayedRunner) };
    use axum::{Router, routing::{get, post}};
    use kettle::server::api::{health, post_build, get_events};
    // Build the app. We must consume `app` (not a clone) for the events request
    // so that the last Arc<JobRegistry> drops when the body finishes — that
    // causes the broadcast sender to drop, which terminates the SSE stream.
    let app = Router::new()
        .route("/health", get(health))
        .route("/build", post(post_build))
        .route("/build/{id}/events", get(get_events))
        .with_state(state);

    let body = serde_json::to_vec(&BuildRequest {
        nonce: "00".into(), repo_url: Some("https://x".into()),
        repo_ref: None, source_data: None,
    }).unwrap();
    // Use a clone for the POST so `app` is preserved for the events request.
    let post = app.clone().oneshot(Request::post("/build")
        .header("content-type", "application/json")
        .body(Body::from(body)).unwrap()).await.unwrap();
    let JobIdResponse { job_id } = serde_json::from_slice(
        &axum::body::to_bytes(post.into_body(), 1024).await.unwrap()).unwrap();

    // Connect mid-spam; consume `app` so stream can terminate when sender drops.
    tokio::time::sleep(std::time::Duration::from_millis(15)).await;
    let resp = app.oneshot(Request::get(format!("/build/{job_id}/events"))
        .body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let s = String::from_utf8(body.to_vec()).unwrap();
    assert!(s.contains(r#""type":"complete""#),
            "stream must include the terminal Complete event: {s}");
}
