#![cfg(feature = "server")]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use kettle::api::{BuildRequest, BuildResult, Event, JobIdResponse};
use kettle::server::api::JobRunner;
use kettle::server::job::JobRegistry;
use kettle::server::router_with_runner_for_tests;
use std::sync::Arc;
use tower::ServiceExt;

#[tokio::test]
async fn result_endpoint_streams_tarball_when_done() {
    let runner = TestRunner::new();
    let app = router_with_runner_for_tests(runner.clone() as Arc<dyn JobRunner>);
    let body = serde_json::to_vec(&BuildRequest {
        nonce: "00".into(),
        repo_url: Some("https://x".into()),
        repo_ref: None,
        source_data: None,
    })
    .unwrap();
    let post = app
        .clone()
        .oneshot(
            Request::post("/build")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let job_id: String = serde_json::from_slice::<JobIdResponse>(
        &axum::body::to_bytes(post.into_body(), 1024).await.unwrap(),
    )
    .unwrap()
    .job_id;

    // Wait for runner to finish.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let resp = app
        .oneshot(
            Request::get(format!("/build/{job_id}/result"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/gzip"
    );
    let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    assert_eq!(&bytes[..2], &[0x1F, 0x8B], "must be a gzip");
}

#[tokio::test]
async fn result_endpoint_returns_404_when_unknown() {
    let app = kettle::server::router();
    let resp = app
        .oneshot(
            Request::get("/build/missing/result")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[derive(Clone)]
struct TestRunner;
impl TestRunner {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}
impl JobRunner for TestRunner {
    fn spawn(&self, registry: Arc<JobRegistry>, id: String, _req: BuildRequest) {
        tokio::spawn(async move {
            let job = registry.get(&id).unwrap();
            use std::io::Write;
            let f = tempfile::NamedTempFile::new().unwrap();
            let mut enc = flate2::write::GzEncoder::new(f.as_file(), flate2::Compression::fast());
            enc.write_all(b"hi").unwrap();
            enc.finish().unwrap();
            job.result.set(f.into_temp_path()).ok();
            job.push_event(Event::Complete {
                result: BuildResult::Ok,
            })
            .await;
            job.mark_done().await;
        });
    }
}
