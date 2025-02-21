#![cfg(unix)]
use std::{
    env,
    net::{IpAddr, Ipv4Addr},
};

use ethportal_api::{
    types::network::{Network, Subnetwork},
    version::APP_NAME,
};
use ethportal_peertest as peertest;
use ethportal_peertest::Peertest;
use jsonrpsee::{async_client::Client, http_client::HttpClient};
use portalnet::constants::{DEFAULT_WEB3_HTTP_ADDRESS, DEFAULT_WEB3_IPC_PATH};
use rpc::RpcServerHandle;
use serial_test::serial;
use tokio::time::{sleep, Duration};
use trin::cli::TrinConfig;

mod utils;

// Logs don't show up when trying to use test_log here, maybe because of multi_thread
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_stateless() {
    // These tests are stateless with regards to the content database,
    // so they can all be run against the same set of peertest nodes
    // without needing to reset the database between tests.
    // If a scenario is testing the state of the content database,
    // it should be added to its own test function.
    let (peertest, target, handle) = setup_peertest(
        &Network::Mainnet,
        &[Subnetwork::History, Subnetwork::State, Subnetwork::Beacon],
    )
    .await;

    // peertest::scenarios::paginate::test_paginate_local_storage(&peertest).await;
    // peertest::scenarios::basic::test_web3_client_version(&target).await;
    peertest::scenarios::basic::test_discv5_node_info(&peertest).await;
    peertest::scenarios::basic::test_discv5_routing_table_info(&target).await;
    peertest::scenarios::basic::test_discv5_add_enr(&target, &peertest).await;
    peertest::scenarios::basic::test_discv5_get_enr(&target, &peertest).await;
    peertest::scenarios::basic::test_discv5_delete_enr(&target, &peertest).await;
    peertest::scenarios::basic::test_discv5_update_node_info(&target).await;
    // peertest::scenarios::basic::test_discv5_talk_req(&target, &peertest).await;
    peertest::scenarios::basic::test_discv5_recursive_find_node(&target, &peertest).await;
    peertest::scenarios::basic::test_discv5_ping(&target, &peertest).await;
    peertest::scenarios::basic::test_discv5_lookup_enr(&target, &peertest).await;
    peertest::scenarios::basic::test_discv5_find_node(&target, &peertest).await;
    // peertest::scenarios::eth_rpc::test_eth_chain_id(&peertest).await;

    // for subnetwork in [Subnetwork::History, Subnetwork::Beacon, Subnetwork::State] {
    //     peertest::scenarios::basic::test_routing_table_info(subnetwork, &target).await;
    //     peertest::scenarios::basic::test_radius(subnetwork, &target).await;
    //     peertest::scenarios::basic::test_add_enr(subnetwork, &target, &peertest).await;
    //     peertest::scenarios::basic::test_get_enr(subnetwork, &target, &peertest).await;
    //     peertest::scenarios::basic::test_delete_enr(subnetwork, &target, &peertest).await;
    //     peertest::scenarios::basic::test_lookup_enr(subnetwork, &peertest).await;
    //     peertest::scenarios::basic::test_ping(subnetwork, &target, &peertest).await;
    //     peertest::scenarios::basic::test_find_nodes(subnetwork, &target, &peertest).await;
    //     peertest::scenarios::basic::test_find_nodes_zero_distance(subnetwork, &target, &peertest)
    //         .await;
    // peertest::scenarios::find::test_recursive_find_nodes_self(subnetwork, &peertest).await;
    //     peertest::scenarios::find::test_recursive_find_nodes_peer(subnetwork, &peertest).await;
    //     peertest::scenarios::find::test_recursive_find_nodes_random(subnetwork, &peertest).await;
    // }

    // peertest::scenarios::basic::test_history_store(&target).await;
    // peertest::scenarios::basic::test_history_local_content_absent(&target).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_offer() {
    let (peertest, target, handle) =
        setup_peertest(&Network::Mainnet, &[Subnetwork::History]).await;
    peertest::scenarios::offer_accept::test_offer(&peertest, &target).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_offer_with_trace() {
    let (peertest, target, handle) =
        setup_peertest(&Network::Mainnet, &[Subnetwork::History]).await;
    peertest::scenarios::offer_accept::test_offer_with_trace(&peertest, &target).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "test is flaky: fails in some environments and in CI sporadically. Re-add #[serial] when re-enabling"]
async fn peertest_offer_concurrent_utp_transfer_limit() {
    let (peertest, target, handle) = setup_peertest_bridge(&[Subnetwork::History]).await;
    peertest::scenarios::offer_accept::test_offer_concurrent_utp_transfer_limit(&peertest, target)
        .await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_gossip_with_trace() {
    let (peertest, target, handle) =
        setup_peertest(&Network::Mainnet, &[Subnetwork::History]).await;
    peertest::scenarios::put_content::test_gossip_with_trace(&peertest, &target).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_find_content_return_enr() {
    let (peertest, target, handle) =
        setup_peertest(&Network::Mainnet, &[Subnetwork::History]).await;
    peertest::scenarios::find::test_find_content_return_enr(&target, &peertest).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_trace_get_content_local_db() {
    let (peertest, _target, handle) =
        setup_peertest(&Network::Mainnet, &[Subnetwork::History]).await;
    peertest::scenarios::find::test_trace_get_content_local_db(&peertest).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_trace_get_content_for_absent_content() {
    let (peertest, _target, handle) =
        setup_peertest(&Network::Mainnet, &[Subnetwork::History]).await;
    peertest::scenarios::find::test_trace_get_content_for_absent_content(&peertest).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_trace_get_content() {
    let (peertest, _target, handle) =
        setup_peertest(&Network::Mainnet, &[Subnetwork::History]).await;
    peertest::scenarios::find::test_trace_get_content(&peertest).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_validate_pre_merge_header_by_hash() {
    let (peertest, target, handle) =
        setup_peertest(&Network::Mainnet, &[Subnetwork::History]).await;
    peertest::scenarios::validation::test_validate_pre_merge_header_by_hash(&peertest, &target)
        .await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_validate_pre_merge_header_by_number() {
    let (peertest, target, handle) =
        setup_peertest(&Network::Mainnet, &[Subnetwork::History]).await;
    peertest::scenarios::validation::test_validate_pre_merge_header_by_number(&peertest, &target)
        .await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_invalidate_header_by_hash() {
    let (peertest, target, handle) =
        setup_peertest(&Network::Mainnet, &[Subnetwork::History]).await;
    peertest::scenarios::validation::test_invalidate_header_by_hash(&peertest, &target).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_validate_block_body() {
    let (peertest, target, handle) =
        setup_peertest(&Network::Mainnet, &[Subnetwork::History]).await;
    peertest::scenarios::validation::test_validate_pre_merge_block_body(&peertest, &target).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_validate_receipts() {
    let (peertest, target, handle) =
        setup_peertest(&Network::Mainnet, &[Subnetwork::History]).await;
    peertest::scenarios::validation::test_validate_pre_merge_receipts(&peertest, &target).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_recursive_utp() {
    let (peertest, _target, handle) =
        setup_peertest(&Network::Mainnet, &[Subnetwork::History]).await;
    peertest::scenarios::utp::test_recursive_utp(&peertest).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_trace_recursive_utp() {
    let (peertest, _target, handle) =
        setup_peertest(&Network::Mainnet, &[Subnetwork::History]).await;
    peertest::scenarios::utp::test_trace_recursive_utp(&peertest).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_state_offer_account_trie_node() {
    let (peertest, target, handle) =
        setup_peertest(&Network::Mainnet, &[Subnetwork::History, Subnetwork::State]).await;
    peertest::scenarios::state::test_state_offer_account_trie_node(&peertest, &target).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_state_offer_contract_storage_trie_node() {
    let (peertest, target, handle) =
        setup_peertest(&Network::Mainnet, &[Subnetwork::History, Subnetwork::State]).await;
    peertest::scenarios::state::test_state_gossip_contract_storage_trie_node(&peertest, &target)
        .await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_state_offer_contract_bytecode() {
    let (peertest, target, handle) =
        setup_peertest(&Network::Mainnet, &[Subnetwork::History, Subnetwork::State]).await;
    peertest::scenarios::state::test_state_gossip_contract_bytecode(&peertest, &target).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_history_offer_propagates_gossip() {
    let (peertest, target, handle) =
        setup_peertest(&Network::Mainnet, &[Subnetwork::History]).await;
    peertest::scenarios::offer_accept::test_offer_propagates_gossip(&peertest, &target).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_history_offer_propagates_gossip_with_large_content() {
    let (peertest, target, handle) =
        setup_peertest(&Network::Mainnet, &[Subnetwork::History]).await;
    peertest::scenarios::offer_accept::test_offer_propagates_gossip_with_large_content(
        &peertest, &target,
    )
    .await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_history_offer_propagates_gossip_multiple_content_values() {
    let (peertest, target, handle) =
        setup_peertest(&Network::Mainnet, &[Subnetwork::History]).await;
    peertest::scenarios::offer_accept::test_offer_propagates_gossip_multiple_content_values(
        &peertest, &target,
    )
    .await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_history_offer_propagates_gossip_multiple_large_content_values() {
    let (peertest, target, handle) =
        setup_peertest(&Network::Mainnet, &[Subnetwork::History]).await;
    peertest::scenarios::offer_accept::test_offer_propagates_gossip_multiple_large_content_values(
        &peertest, &target,
    )
    .await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_history_gossip_dropped_with_offer() {
    let (peertest, target, handle) =
        setup_peertest(&Network::Mainnet, &[Subnetwork::History]).await;
    peertest::scenarios::put_content::test_gossip_dropped_with_offer(&peertest, &target).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_history_gossip_dropped_with_find_content() {
    let (peertest, target, handle) =
        setup_peertest(&Network::Mainnet, &[Subnetwork::History]).await;
    peertest::scenarios::put_content::test_gossip_dropped_with_find_content(&peertest, &target)
        .await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_ping_cross_discv5_protocol_id() {
    // Run peernodes on angelfood
    let angelfood_peertest =
        peertest::launch_peertest_nodes(2, &Network::Angelfood, &[Subnetwork::History]).await;

    // Run a client on the mainnet, to be tested
    // Use an uncommon port for the peertest to avoid clashes.
    let test_discovery_port = 8999;
    let external_addr = format!("{}:{test_discovery_port}", Ipv4Addr::new(127, 0, 0, 1));

    let trin_config = TrinConfig::new_from([
        APP_NAME,
        "--network",
        &Network::Mainnet.to_string(),
        "--portal-subnetworks",
        &Subnetwork::History.to_cli_arg(),
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
    let mainnet_handle = trin::run_trin(trin_config).await.unwrap();
    let mainnet_target = reth_ipc::client::IpcClientBuilder::default()
        .build(DEFAULT_WEB3_IPC_PATH)
        .await
        .unwrap();

    peertest::scenarios::basic::test_ping_cross_network(
        &mainnet_target,
        &angelfood_peertest.bootnode,
    )
    .await;
    angelfood_peertest.exit_all_nodes();
    mainnet_handle.stop().unwrap();
}

async fn setup_peertest(
    network: &Network,
    subnetworks: &[Subnetwork],
) -> (peertest::Peertest, Client, RpcServerHandle) {
    utils::init_tracing();

    // Run a client, as a buddy peer for ping tests, etc.
    let peertest = peertest::launch_peertest_nodes(2, network, subnetworks).await;
    // Short sleep to make sure all peertest nodes can connect
    sleep(Duration::from_millis(100)).await;

    let test_ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    // Use an uncommon port for the peertest to avoid clashes.
    let test_discovery_port = 8999;
    let external_addr = format!("{test_ip_addr}:{test_discovery_port}");

    // Run a client, to be tested
    let trin_config = TrinConfig::new_from([
        APP_NAME,
        "--network",
        &network.to_string(),
        "--portal-subnetworks",
        &subnetworks
            .iter()
            .map(|s| s.to_cli_arg())
            .collect::<Vec<String>>()
            .join(","),
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

    let test_client_rpc_handle = trin::run_trin(trin_config).await.unwrap();
    let target = reth_ipc::client::IpcClientBuilder::default()
        .build(DEFAULT_WEB3_IPC_PATH)
        .await
        .unwrap();
    (peertest, target, test_client_rpc_handle)
}

async fn setup_peertest_bridge(
    subnetworks: &[Subnetwork],
) -> (Peertest, HttpClient, RpcServerHandle) {
    utils::init_tracing();

    let network = Network::Mainnet;
    // Run a client, as a buddy peer for ping tests, etc.
    let peertest = peertest::launch_peertest_nodes(1, &network, subnetworks).await;
    // Short sleep to make sure all peertest nodes can connect
    sleep(Duration::from_millis(100)).await;

    let test_ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    // Use an uncommon port for the peertest to avoid clashes.
    let test_discovery_port = 8999;
    let external_addr = format!("{test_ip_addr}:{test_discovery_port}");
    let subnetworks = subnetworks
        .iter()
        .map(|s| s.to_cli_arg())
        .collect::<Vec<String>>()
        .join(",");

    // add fake secrets for bridge activation
    env::set_var("PANDAOPS_CLIENT_ID", "xxx");
    env::set_var("PANDAOPS_CLIENT_SECRET", "xxx");
    // Run a client, to be tested
    let trin_config = TrinConfig::new_from([
        APP_NAME,
        "--network",
        &network.to_string(),
        "--portal-subnetworks",
        &subnetworks,
        "--external-address",
        external_addr.as_str(),
        // Run bridge test with http, since bridge doesn't support ipc yet.
        "--web3-transport",
        "http",
        "--web3-http-address",
        DEFAULT_WEB3_HTTP_ADDRESS,
        "--ephemeral",
        "--discovery-port",
        test_discovery_port.to_string().as_ref(),
        "--bootnodes",
        &peertest.bootnode.enr.to_base64(),
        "--max-radius",
        "100",
    ])
    .unwrap();

    let test_client_rpc_handle = trin::run_trin(trin_config).await.unwrap();
    let target = ethportal_api::jsonrpsee::http_client::HttpClientBuilder::default()
        .build(DEFAULT_WEB3_HTTP_ADDRESS)
        .unwrap();
    (peertest, target, test_client_rpc_handle)
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_history_bridge() {
    let (peertest, target, handle) = setup_peertest_bridge(&[Subnetwork::History]).await;
    peertest::scenarios::bridge::test_history_bridge(&peertest, &target).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_beacon_bridge() {
    let (peertest, target, handle) = setup_peertest_bridge(&[Subnetwork::Beacon]).await;
    peertest::scenarios::bridge::test_beacon_bridge(&peertest, &target).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}
