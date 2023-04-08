#![warn(clippy::unwrap_used)]

use clap::Parser;
use std::{thread, time};
use tracing::info;
use trin_utils::log::init_tracing_logger;

use ethportal_peertest::{
    cli::PeertestConfig,
    jsonrpc::{test_jsonrpc_endpoints_over_http, test_jsonrpc_endpoints_over_ipc},
    launch_peertest_nodes,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing_logger();

    let peertest = launch_peertest_nodes(2).await;
    // Short sleep to make sure all peertest nodes can connect
    thread::sleep(time::Duration::from_secs(1));

    tokio::spawn(async move {
        let peertest_config = PeertestConfig::parse();
        match peertest_config.target_transport.as_str() {
            "ipc" => test_jsonrpc_endpoints_over_ipc(peertest_config, &peertest).await,
            "http" => test_jsonrpc_endpoints_over_http(peertest_config, &peertest).await,
            _ => panic!(
                "Invalid target-transport provided: {:?}",
                peertest_config.target_transport
            ),
        }

        info!("All tests passed successfully!");

        peertest.exit_all_nodes();
    })
    .await?;

    Ok(())
}
