pub mod api;
pub mod job;

use std::sync::Arc;

use axum::{
    Router,
    routing::{get, post},
};

use crate::api::BuildRequest;
use crate::server::api::{AppState, JobRunner, health, post_build};
use crate::server::job::JobRegistry;

pub fn router() -> Router {
    router_with_runner(Arc::new(NullRunner))
}

pub fn router_for_tests() -> Router {
    router_with_runner(Arc::new(NullRunner))
}

pub fn router_with_runner(runner: Arc<dyn JobRunner>) -> Router {
    let state = AppState { registry: JobRegistry::new(), runner };
    Router::new()
        .route("/health", get(health))
        .route("/build", post(post_build))
        .with_state(state)
}

struct NullRunner;
impl JobRunner for NullRunner {
    fn spawn(&self, _registry: Arc<JobRegistry>, _job_id: String, _req: BuildRequest) {
        // Tests use this null runner; the real BuildRunner lands in Task 2.6.
    }
}
