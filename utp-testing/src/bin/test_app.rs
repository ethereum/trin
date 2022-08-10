use std::net::SocketAddr;
use utp_testing::run_test_app;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let client_port = 9002;
    let client_external_addr = SocketAddr::from(([127, 0, 0, 1], client_port));
    let _ = run_test_app(client_port, client_external_addr).await;

    tokio::signal::ctrl_c()
        .await
        .expect("failed to pause until ctrl-c");
}
