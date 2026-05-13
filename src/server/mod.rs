use axum::{Router, routing::get};

pub fn router() -> Router {
    Router::new().route("/health", get(|| async { "ok" }))
}
