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
