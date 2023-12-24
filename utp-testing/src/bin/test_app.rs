use clap::Parser;
use std::{net::SocketAddr, str::FromStr};
use tracing::info;
use trin_utils::log::init_tracing_logger;
use utp_testing::run_test_app;

use utp_testing::cli::TestAppConfig;

/// uTP test app, used for creation of a `test-app` docker image
#[tokio::main]
async fn main() {
    init_tracing_logger();

    let config = TestAppConfig::parse();

    let udp_listen_address = format!("{}:{}", config.udp_listen_address, config.udp_port);
    let udp_listen_address = SocketAddr::from_str(&udp_listen_address).unwrap();
    let (rpc_addr, enr, _handle) = run_test_app(
        config.udp_port,
        udp_listen_address,
        config.rpc_listen_address,
        config.rpc_port,
    )
    .await
    .unwrap();

    info!("uTP test app started. RPC address: {rpc_addr}, Enr: {enr}");

    tokio::signal::ctrl_c()
        .await
        .expect("failed to pause until ctrl-c");
}
