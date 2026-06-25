#![cfg(feature = "server")]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use kettle::api::{BuildRequest, JobIdResponse};
use tower::ServiceExt;

fn make_router() -> axum::Router {
    kettle::server::router_for_tests()
}

#[tokio::test]
async fn post_build_returns_job_id() {
    let req = BuildRequest {
        nonce: "deadbeef".into(),
        repo_url: Some("https://github.com/x/y".into()),
        repo_ref: None,
        source_data: None,
        source_name: None,
    };
    let body = serde_json::to_vec(&req).unwrap();
    let app = make_router();
    let resp = app
        .oneshot(
            Request::post("/build")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let parsed: JobIdResponse = serde_json::from_slice(&bytes).unwrap();
    assert!(!parsed.job_id.is_empty());
}

#[tokio::test]
async fn post_build_second_call_returns_409() {
    let req = BuildRequest {
        nonce: "00".into(),
        repo_url: Some("https://github.com/x/y".into()),
        repo_ref: None,
        source_data: None,
        source_name: None,
    };
    let body = serde_json::to_vec(&req).unwrap();
    let app = make_router();
    let first = app
        .clone()
        .oneshot(
            Request::post("/build")
                .header("content-type", "application/json")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let second = app
        .oneshot(
            Request::post("/build")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn post_build_rejects_invalid_nonce() {
    let bad = r#"{"nonce":"zzzzzz","repo_url":"https://github.com/x/y"}"#;
    let app = make_router();
    let resp = app
        .oneshot(
            Request::post("/build")
                .header("content-type", "application/json")
                .body(Body::from(bad))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn post_build_rejects_oversize_nonce() {
    // 17 bytes hex = 34 chars; one byte over the 16-byte limit.
    let bad = r#"{"nonce":"000102030405060708090a0b0c0d0e0f10","repo_url":"https://x/y"}"#;
    let app = make_router();
    let resp = app
        .oneshot(
            Request::post("/build")
                .header("content-type", "application/json")
                .body(Body::from(bad))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn post_build_rejects_missing_source() {
    let bad = r#"{"nonce":"deadbeef"}"#;
    let app = make_router();
    let resp = app
        .oneshot(
            Request::post("/build")
                .header("content-type", "application/json")
                .body(Body::from(bad))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
