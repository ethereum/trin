#![cfg(unix)]
use rpc::RpcServerHandle;
use std::{
    env,
    net::{IpAddr, Ipv4Addr},
};

use ethportal_api::types::{
    cli::{TrinConfig, DEFAULT_WEB3_HTTP_ADDRESS, DEFAULT_WEB3_IPC_PATH},
    portal_wire::ProtocolId,
};
use ethportal_peertest as peertest;
use ethportal_peertest::Peertest;
use jsonrpsee::{async_client::Client, http_client::HttpClient};
use serial_test::serial;
use tokio::time::{sleep, Duration};

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
    let (peertest, target, handle) = setup_peertest("mainnet").await;

    peertest::scenarios::paginate::test_paginate_local_storage(&peertest).await;
    peertest::scenarios::basic::test_web3_client_version(&target).await;
    peertest::scenarios::basic::test_discv5_node_info(&peertest).await;
    peertest::scenarios::basic::test_discv5_routing_table_info(&target).await;
    peertest::scenarios::eth_rpc::test_eth_chain_id(&peertest).await;

    for protocol in [ProtocolId::History, ProtocolId::Beacon, ProtocolId::State] {
        peertest::scenarios::basic::test_routing_table_info(protocol, &target).await;
        peertest::scenarios::basic::test_radius(protocol, &target).await;
        peertest::scenarios::basic::test_add_enr(protocol, &target, &peertest).await;
        peertest::scenarios::basic::test_get_enr(protocol, &target, &peertest).await;
        peertest::scenarios::basic::test_delete_enr(protocol, &target, &peertest).await;
        peertest::scenarios::basic::test_lookup_enr(protocol, &peertest).await;
        peertest::scenarios::basic::test_ping(protocol, &target, &peertest).await;
        peertest::scenarios::basic::test_find_nodes(protocol, &target, &peertest).await;
        peertest::scenarios::basic::test_find_nodes_zero_distance(protocol, &target, &peertest)
            .await;
        peertest::scenarios::find::test_recursive_find_nodes_self(protocol, &peertest).await;
        peertest::scenarios::find::test_recursive_find_nodes_peer(protocol, &peertest).await;
        peertest::scenarios::find::test_recursive_find_nodes_random(protocol, &peertest).await;
    }

    peertest::scenarios::basic::test_history_store(&target).await;
    peertest::scenarios::basic::test_history_local_content_absent(&target).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_populated_offer() {
    let (peertest, target, handle) = setup_peertest("mainnet").await;
    peertest::scenarios::offer_accept::test_populated_offer(&peertest, &target).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_unpopulated_offer() {
    let (peertest, target, handle) = setup_peertest("mainnet").await;
    peertest::scenarios::offer_accept::test_unpopulated_offer(&peertest, &target).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_unpopulated_offer_fails_with_missing_content() {
    let (peertest, target, handle) = setup_peertest("mainnet").await;
    peertest::scenarios::offer_accept::test_unpopulated_offer_fails_with_missing_content(
        &peertest, &target,
    )
    .await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_gossip_with_trace() {
    let (peertest, target, handle) = setup_peertest("mainnet").await;
    peertest::scenarios::gossip::test_gossip_with_trace(&peertest, &target).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_find_content_return_enr() {
    let (peertest, target, handle) = setup_peertest("mainnet").await;
    peertest::scenarios::find::test_find_content_return_enr(&target, &peertest).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_trace_recursive_find_content_local_db() {
    let (peertest, _target, handle) = setup_peertest("mainnet").await;
    peertest::scenarios::find::test_trace_recursive_find_content_local_db(&peertest).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_trace_recursive_find_content_for_absent_content() {
    let (peertest, _target, handle) = setup_peertest("mainnet").await;
    peertest::scenarios::find::test_trace_recursive_find_content_for_absent_content(&peertest)
        .await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_trace_recursive_find_content() {
    let (peertest, _target, handle) = setup_peertest("mainnet").await;
    peertest::scenarios::find::test_trace_recursive_find_content(&peertest).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_validate_pre_merge_header_with_proof() {
    let (peertest, target, handle) = setup_peertest("mainnet").await;
    peertest::scenarios::validation::test_validate_pre_merge_header_with_proof(&peertest, &target)
        .await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_invalidate_header_by_hash() {
    let (peertest, target, handle) = setup_peertest("mainnet").await;
    peertest::scenarios::validation::test_invalidate_header_by_hash(&peertest, &target).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_validate_block_body() {
    let (peertest, target, handle) = setup_peertest("mainnet").await;
    peertest::scenarios::validation::test_validate_pre_merge_block_body(&peertest, &target).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_validate_receipts() {
    let (peertest, target, handle) = setup_peertest("mainnet").await;
    peertest::scenarios::validation::test_validate_pre_merge_receipts(&peertest, &target).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_recursive_utp() {
    let (peertest, _target, handle) = setup_peertest("mainnet").await;
    peertest::scenarios::utp::test_recursive_utp(&peertest).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_trace_recursive_utp() {
    let (peertest, _target, handle) = setup_peertest("mainnet").await;
    peertest::scenarios::utp::test_trace_recursive_utp(&peertest).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_state_offer_account_trie_node() {
    let (peertest, target, handle) = setup_peertest("mainnet").await;
    peertest::scenarios::state::test_state_offer_account_trie_node(&peertest, &target).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_state_offer_contract_storage_trie_node() {
    let (peertest, target, handle) = setup_peertest("mainnet").await;
    peertest::scenarios::state::test_state_gossip_contract_storage_trie_node(&peertest, &target)
        .await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_state_offer_contract_bytecode() {
    let (peertest, target, handle) = setup_peertest("mainnet").await;
    peertest::scenarios::state::test_state_gossip_contract_bytecode(&peertest, &target).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_state_recursive_gossip() {
    let (peertest, target, handle) = setup_peertest("mainnet").await;
    peertest::scenarios::state::test_state_recursive_gossip(&peertest, &target).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_history_offer_propagates_gossip() {
    let (peertest, target, handle) = setup_peertest("mainnet").await;
    peertest::scenarios::offer_accept::test_offer_propagates_gossip(&peertest, &target).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_ping_cross_discv5_protocol_id() {
    let (peertest, target, handle) = setup_peertest("angelfood").await;
    peertest::scenarios::basic::test_ping_cross_network(&target, &peertest).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

async fn setup_peertest(network: &str) -> (peertest::Peertest, Client, RpcServerHandle) {
    utils::init_tracing();
    // Run a client, as a buddy peer for ping tests, etc.
    let peertest = peertest::launch_peertest_nodes(2).await;
    // Short sleep to make sure all peertest nodes can connect
    sleep(Duration::from_millis(100)).await;

    let test_ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    // Use an uncommon port for the peertest to avoid clashes.
    let test_discovery_port = 8999;
    let external_addr = format!("{test_ip_addr}:{test_discovery_port}");

    // Run a client, to be tested
    let trin_config = TrinConfig::new_from(
        [
            "trin",
            "--portal-subnetworks",
            "history,beacon,state",
            "--external-address",
            external_addr.as_str(),
            "--web3-ipc-path",
            DEFAULT_WEB3_IPC_PATH,
            "--ephemeral",
            "--discovery-port",
            test_discovery_port.to_string().as_ref(),
            "--bootnodes",
            "none",
            "--network",
            network,
        ]
        .iter(),
    )
    .unwrap();

    let test_client_rpc_handle = trin::run_trin(trin_config).await.unwrap();
    let target = reth_ipc::client::IpcClientBuilder::default()
        .build(DEFAULT_WEB3_IPC_PATH)
        .await
        .unwrap();
    (peertest, target, test_client_rpc_handle)
}

async fn setup_peertest_bridge() -> (Peertest, HttpClient, RpcServerHandle) {
    utils::init_tracing();
    // Run a client, as a buddy peer for ping tests, etc.
    let peertest = peertest::launch_peertest_nodes(1).await;
    // Short sleep to make sure all peertest nodes can connect
    sleep(Duration::from_millis(100)).await;

    let test_ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    // Use an uncommon port for the peertest to avoid clashes.
    let test_discovery_port = 8999;
    let external_addr = format!("{test_ip_addr}:{test_discovery_port}");

    // add fake secrets for bridge activation
    env::set_var("PANDAOPS_CLIENT_ID", "xxx");
    env::set_var("PANDAOPS_CLIENT_SECRET", "xxx");
    // Run a client, to be tested
    let trin_config = TrinConfig::new_from(
        [
            "trin",
            "--portal-subnetworks",
            "history,beacon,state",
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
        ]
        .iter(),
    )
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
    let (peertest, target, handle) = setup_peertest_bridge().await;
    peertest::scenarios::bridge::test_history_bridge(&peertest, &target).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_beacon_bridge() {
    let (peertest, target, handle) = setup_peertest_bridge().await;
    peertest::scenarios::bridge::test_beacon_bridge(&peertest, &target).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}
