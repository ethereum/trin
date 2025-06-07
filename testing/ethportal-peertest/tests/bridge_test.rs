#![cfg(unix)]

use std::net::{IpAddr, Ipv4Addr};

use ethportal_api::{
    types::{
        network::{Network, Subnetwork},
        network_spec::set_network_spec,
    },
    version::APP_NAME,
};
use ethportal_peertest as peertest;
use itertools::Itertools;
use jsonrpsee::async_client::Client;
use portalnet::constants::DEFAULT_WEB3_IPC_PATH;
use rpc::RpcServerHandle;
use serial_test::serial;
use tokio::time::{sleep, Duration};
use trin::{run_trin_from_trin_config, TrinConfig};
use trin_utils::cli::network_parser;

mod utils;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_bridge_ping() {
    let (peertest, _target, handle) =
        setup_peertest(Network::Mainnet, &[Subnetwork::History], None).await;
    peertest::scenarios::bridge::test_bridge_ping(&peertest)
        .await
        .expect("Bridge ping failed");
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_bridge_routing_table() {
    let (peertest, _target, handle) =
        setup_peertest(Network::Mainnet, &[Subnetwork::History], Some(9001)).await;
    peertest::scenarios::bridge::test_bridge_routing_table(&peertest)
        .await
        .expect("Bridge routing table test failed");
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

/// Creates a new peertest environment with a bootnode and a number of child nodes.
async fn setup_peertest(
    network: Network,
    subnetworks: &[Subnetwork],
    port: Option<i32>,
) -> (peertest::Peertest, Client, RpcServerHandle) {
    utils::init_tracing();
    set_network_spec(network_parser(&network.to_string()).expect("Failed to parse network"));

    // Run a client, as a buddy peer for ping tests, etc.
    let peertest = peertest::launch_peertest_nodes(2, network, subnetworks).await;
    // Short sleep to make sure all peertest nodes can connect
    sleep(Duration::from_millis(100)).await;

    let test_ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    // Use an uncommon port for the peertest to avoid clashes.
    let test_discovery_port = port.unwrap_or(8999);
    let external_addr = format!("{test_ip_addr}:{test_discovery_port}");

    let subnetworks = subnetworks
        .iter()
        .flat_map(Subnetwork::with_dependencies)
        .unique()
        .map(|subnetwork| subnetwork.to_cli_arg())
        .join(",");

    // Run a client, to be tested
    let trin_config = TrinConfig::new_from([
        APP_NAME,
        "--network",
        &network.to_string(),
        "--portal-subnetworks",
        &subnetworks,
        "--external-address",
        external_addr.as_str(),
        "--web3-ipc-path",
        DEFAULT_WEB3_IPC_PATH,
        "--ephemeral",
        "--discovery-port",
        test_discovery_port.to_string().as_ref(),
        "--bootnodes",
        "none",
        "--max-radius",
        "100",
    ])
    .unwrap();

    let test_client_rpc_handle = run_trin_from_trin_config(trin_config).await.unwrap();
    let target = reth_ipc::client::IpcClientBuilder::default()
        .build(DEFAULT_WEB3_IPC_PATH)
        .await
        .unwrap();
    (peertest, target, test_client_rpc_handle.rpc_server_handle)
}
