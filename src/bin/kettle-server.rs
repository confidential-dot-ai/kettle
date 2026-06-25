use kettle::server;

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("KETTLE_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let app = server::router();
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .expect("failed to bind");

    eprintln!("kettle-server listening on 0.0.0.0:{port}");

    #[cfg(not(feature = "attest"))]
    eprintln!("attestation DISABLED");
    #[cfg(feature = "attest")]
    eprintln!("attestation ENABLED");

    axum::serve(listener, app).await.expect("server error");
}
