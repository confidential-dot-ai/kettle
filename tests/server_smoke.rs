#![cfg(feature = "server")]

#[tokio::test]
async fn server_module_exposes_router() {
    // We only verify the module compiles and exposes the expected fn.
    let _router: axum::Router = kettle::server::router();
}
