/// Test that a 3rd-party web3 client can understand our JSON-RPC API
use std::net::{IpAddr, Ipv4Addr};

use ethers_core::types::U256;
use ethers_providers::*;
use serial_test::serial;

use ethportal_api::types::cli::{TrinConfig, DEFAULT_WEB3_IPC_PATH};
use rpc::RpcServerHandle;

mod utils;

async fn setup_web3_server() -> (RpcServerHandle, Provider<Ipc>) {
    utils::init_tracing();

    let test_ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    // Use an uncommon port for the peertest to avoid clashes.
    let test_discovery_port = 8999;
    let external_addr = format!("{test_ip_addr}:{test_discovery_port}");

    // Run a client, to be tested
    let trin_config = TrinConfig::new_from(
        [
            "trin",
            "--external-address",
            external_addr.as_str(),
            "--web3-ipc-path",
            DEFAULT_WEB3_IPC_PATH,
            "--ephemeral",
            "--discovery-port",
            &test_discovery_port.to_string(),
            "--bootnodes",
            "none",
        ]
        .iter(),
    )
    .unwrap();

    let web3_server = trin::run_trin(trin_config).await.unwrap();
    let web3_client = Provider::connect_ipc(DEFAULT_WEB3_IPC_PATH).await.unwrap();
    (web3_server, web3_client)
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_eth_chain_id() {
    let (web3_server, web3_client) = setup_web3_server().await;
    let chain_id = web3_client.get_chainid().await.unwrap();
    web3_server.stop().unwrap();
    // For now, the chain ID is always 1 -- Portal only supports mainnet Ethereum
    // Intentionally testing against the magic number 1 so that a buggy constant value will fail
    assert_eq!(chain_id, U256::from(1));
}
