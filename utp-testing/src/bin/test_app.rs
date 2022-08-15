use log::info;
use std::net::SocketAddr;
use std::str::FromStr;
use utp_testing::run_test_app;

use structopt::StructOpt;
use utp_testing::cli::TestAppConfig;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let config = TestAppConfig::from_args();

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
