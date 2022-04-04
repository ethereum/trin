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

    let (bootnode, peertest_nodes) = launch_peertest_nodes(2).await;
    // Short sleep to make sure all peertest nodes can connect
    thread::sleep(time::Duration::from_secs(1));

    tokio::spawn(async move {
        let peertest_config = PeertestConfig::from_cli();
        match peertest_config.target_transport.as_str() {
            "ipc" => {
                test_jsonrpc_endpoints_over_ipc(peertest_config, bootnode.enr.to_base64()).await
            }
            "http" => {
                test_jsonrpc_endpoints_over_http(peertest_config, bootnode.enr.to_base64()).await
            }
            _ => panic!(
                "Invalid target-transport provided: {:?}",
                peertest_config.target_transport
            ),
        }

        info!("All tests passed successfully!");

        bootnode.exiter.exit();
        peertest_nodes.iter().for_each(|node| node.exiter.exit());
    })
    .await
    .unwrap();

    Ok(())
}
