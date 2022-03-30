use log::info;
use std::{thread, time};

use ethportal_peertest::cli::PeertestConfig;
use ethportal_peertest::jsonrpc::{
    test_jsonrpc_endpoints_over_http, test_jsonrpc_endpoints_over_ipc,
};
use ethportal_peertest::launch_peertest_nodes;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let all_peertest_nodes = launch_peertest_nodes(5).await;
    // Short sleep to make sure all peertest nodes can connect
    thread::sleep(time::Duration::from_secs(1));

    tokio::spawn(async move {
        let peertest_config = PeertestConfig::from_cli();

        match peertest_config.target_transport.as_str() {
            "ipc" => test_jsonrpc_endpoints_over_ipc(peertest_config, &all_peertest_nodes).await,
            "http" => test_jsonrpc_endpoints_over_http(peertest_config, &all_peertest_nodes).await,
            _ => panic!(
                "Invalid target-transport provided: {:?}",
                peertest_config.target_transport
            ),
        }

        info!("All tests passed successfully!");

        all_peertest_nodes.exit();
    })
    .await
    .unwrap();

    Ok(())
}
