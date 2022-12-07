use std::net::{IpAddr, Ipv4Addr};
use std::{thread, time};
use tracing::info;

use ethportal_peertest::{
    cli::PeertestConfig,
    jsonrpc::{test_jsonrpc_endpoints_over_http, test_jsonrpc_endpoints_over_ipc},
    launch_peertest_nodes, TransportProtocol,
};
use trin_core::cli::TrinConfig;
use trin_core::utils::provider::TrustedProvider;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let peertest = launch_peertest_nodes(2, TransportProtocol::IPC).await;
    // Short sleep to make sure all peertest nodes can connect
    thread::sleep(time::Duration::from_secs(1));

    tokio::spawn(async move {
        let test_ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let test_port = 9000;
        let external_addr = format!("{}:{}", test_ip_addr, test_port);

        let peertest_config = PeertestConfig::default();

        // Run a client, to be tested
        let trin_config = TrinConfig::new_from(
            [
                "trin",
                "--networks",
                "history,state",
                "--external-address",
                external_addr.as_str(),
                "--web3-ipc-path",
                &peertest_config.target_ipc_path,
                "--ephemeral",
            ]
            .iter(),
        )
        .unwrap();

        let server = ethportal_peertest::setup_mock_trusted_http_server();
        let trusted_provider = TrustedProvider {
            http: ureq::post(&server.url("/")),
            ws: None,
        };
        let test_client_exiter = trin::run_trin(trin_config, trusted_provider).await.unwrap();

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
        test_client_exiter.exit();
    })
    .await
    .unwrap();

    Ok(())
}
