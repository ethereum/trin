use log::info;

use ethportal_peertest::cli::PeertestConfig;
use ethportal_peertest::jsonrpc::{
    test_jsonrpc_endpoints_over_http, test_jsonrpc_endpoints_over_ipc,
};
use ethportal_peertest::launch_buddy_node;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let (buddy_enode, buddy_client_exiter) = launch_buddy_node().await;

    tokio::spawn(async move {
        let peertest_config = PeertestConfig::from_cli();

        match peertest_config.target_transport.as_str() {
            "ipc" => test_jsonrpc_endpoints_over_ipc(peertest_config, buddy_enode).await,
            "http" => test_jsonrpc_endpoints_over_http(peertest_config, buddy_enode).await,
            _ => panic!(
                "Invalid target-transport provided: {:?}",
                peertest_config.target_transport
            ),
        }

        info!("All tests passed successfully!");

        buddy_client_exiter.exit();
    })
    .await
    .unwrap();

    Ok(())
}
