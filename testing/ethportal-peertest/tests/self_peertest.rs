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
use ethportal_peertest::Peertest;
use itertools::Itertools;
use jsonrpsee::{async_client::Client, http_client::HttpClient};
use portalnet::constants::{DEFAULT_WEB3_HTTP_ADDRESS, DEFAULT_WEB3_IPC_PATH};
use rpc::RpcServerHandle;
use serial_test::serial;
use tokio::time::{sleep, Duration};
use trin::{run_trin_from_trin_config, TrinConfig};
use trin_utils::cli::network_parser;

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
        Network::Mainnet,
        &[Subnetwork::History, Subnetwork::State, Subnetwork::Beacon],
    )
    .await;

    peertest::scenarios::paginate::test_paginate_local_storage(&peertest).await;
    peertest::scenarios::basic::test_web3_client_version(&target).await;
    peertest::scenarios::basic::test_discv5_node_info(&peertest).await;
    peertest::scenarios::basic::test_discv5_routing_table_info(&target).await;
    peertest::scenarios::basic::test_discv5_add_enr(&target, &peertest).await;
    peertest::scenarios::basic::test_discv5_get_enr(&target, &peertest).await;
    peertest::scenarios::basic::test_discv5_delete_enr(&target, &peertest).await;
    peertest::scenarios::basic::test_discv5_update_node_info(&target).await;
    peertest::scenarios::basic::test_discv5_talk_req(&target, &peertest).await;
    peertest::scenarios::basic::test_discv5_recursive_find_node(&target, &peertest).await;
    peertest::scenarios::basic::test_discv5_ping(&target, &peertest).await;
    peertest::scenarios::basic::test_discv5_lookup_enr(&target, &peertest).await;
    peertest::scenarios::basic::test_discv5_find_node(&target, &peertest).await;
    peertest::scenarios::eth_rpc::test_eth_chain_id(&peertest).await;

    for subnetwork in [Subnetwork::History, Subnetwork::Beacon, Subnetwork::State] {
        peertest::scenarios::basic::test_routing_table_info(subnetwork, &target).await;
        peertest::scenarios::basic::test_radius(subnetwork, &target).await;
        peertest::scenarios::basic::test_add_enr(subnetwork, &target, &peertest).await;
        peertest::scenarios::basic::test_get_enr(subnetwork, &target, &peertest).await;
        peertest::scenarios::basic::test_delete_enr(subnetwork, &target, &peertest).await;
        peertest::scenarios::basic::test_lookup_enr(subnetwork, &peertest).await;
        peertest::scenarios::ping::test_ping_no_specified_ping_payload(
            subnetwork, &target, &peertest,
        )
        .await;
        peertest::scenarios::basic::test_find_nodes(subnetwork, &target, &peertest).await;
        peertest::scenarios::basic::test_find_nodes_zero_distance(subnetwork, &target, &peertest)
            .await;
        peertest::scenarios::find::test_recursive_find_nodes_self(subnetwork, &peertest).await;
        peertest::scenarios::find::test_recursive_find_nodes_peer(subnetwork, &peertest).await;
        peertest::scenarios::find::test_recursive_find_nodes_random(subnetwork, &peertest).await;
    }

    peertest::scenarios::basic::test_history_store(&target).await;
    peertest::scenarios::basic::test_history_local_content_absent(&target).await;
    peertest::scenarios::ping::test_ping_capabilities_payload(&target, &peertest).await;
    peertest::scenarios::ping::test_ping_basic_radius_payload(&target, &peertest).await;
    peertest::scenarios::ping::test_ping_history_radius_payload(&target, &peertest).await;
    peertest::scenarios::ping::test_ping_invalid_payload_type_client(&target, &peertest).await;
    peertest::scenarios::ping::test_ping_invalid_payload_type_subnetwork(&target, &peertest).await;
    peertest::scenarios::ping::test_ping_failed_to_decode_payload(&target, &peertest).await;
    peertest::scenarios::ping::test_ping_capabilities_payload_type(&target, &peertest).await;
    peertest::scenarios::ping::test_ping_basic_radius_payload_type(&target, &peertest).await;
    peertest::scenarios::ping::test_ping_history_radius_payload_type(&target, &peertest).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

mod protocol_v0 {
    use super::*;

    const V0_NETWORK: Network = Network::Angelfood;

    // offer tests

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_put_content() {
        let (peertest, target, handle) = setup_peertest(V0_NETWORK, &[Subnetwork::History]).await;
        peertest::scenarios::put_content::test_put_content(&peertest, &target, V0_NETWORK).await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_history_gossip_dropped_with_offer() {
        let (peertest, target, handle) = setup_peertest(V0_NETWORK, &[Subnetwork::History]).await;
        peertest::scenarios::put_content::test_gossip_dropped_with_offer(
            &peertest, &target, V0_NETWORK,
        )
        .await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_history_offer_propagates_gossip() {
        let (peertest, target, handle) = setup_peertest(V0_NETWORK, &[Subnetwork::History]).await;
        peertest::scenarios::offer_accept::test_offer_propagates_gossip(&peertest, &target).await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_history_offer_propagates_gossip_multiple_content_values() {
        let (peertest, target, handle) = setup_peertest(V0_NETWORK, &[Subnetwork::History]).await;
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
        let (peertest, target, handle) = setup_peertest(V0_NETWORK, &[Subnetwork::History]).await;
        peertest::scenarios::offer_accept::test_offer_propagates_gossip_multiple_large_content_values(
        &peertest, &target,
    )
    .await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_history_offer_propagates_gossip_with_large_content() {
        let (peertest, target, handle) = setup_peertest(V0_NETWORK, &[Subnetwork::History]).await;
        peertest::scenarios::offer_accept::test_offer_propagates_gossip_with_large_content(
            &peertest, &target,
        )
        .await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_offer() {
        let (peertest, target, handle) = setup_peertest(V0_NETWORK, &[Subnetwork::History]).await;
        peertest::scenarios::offer_accept::test_offer(&peertest, &target).await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_offer_with_trace() {
        let (peertest, target, handle) = setup_peertest(V0_NETWORK, &[Subnetwork::History]).await;
        peertest::scenarios::offer_accept::test_offer_with_trace(&peertest, &target).await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_state_offer_account_trie_node() {
        let (peertest, target, handle) = setup_peertest(V0_NETWORK, &[Subnetwork::State]).await;
        peertest::scenarios::state::test_state_offer_account_trie_node(&peertest, &target).await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_state_offer_contract_bytecode() {
        let (peertest, target, handle) = setup_peertest(V0_NETWORK, &[Subnetwork::State]).await;
        peertest::scenarios::state::test_state_gossip_contract_bytecode(&peertest, &target).await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_state_offer_contract_storage_trie_node() {
        let (peertest, target, handle) = setup_peertest(V0_NETWORK, &[Subnetwork::State]).await;
        peertest::scenarios::state::test_state_gossip_contract_storage_trie_node(
            &peertest, &target,
        )
        .await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }

    // find content tests

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_validate_block_body() {
        let (peertest, target, handle) = setup_peertest(V0_NETWORK, &[Subnetwork::History]).await;
        peertest::scenarios::validation::test_validate_pre_merge_block_body(&peertest, &target)
            .await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_validate_receipts() {
        let (peertest, target, handle) = setup_peertest(V0_NETWORK, &[Subnetwork::History]).await;
        peertest::scenarios::validation::test_validate_pre_merge_receipts(&peertest, &target).await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_history_gossip_dropped_with_find_content() {
        let (peertest, target, handle) = setup_peertest(V0_NETWORK, &[Subnetwork::History]).await;
        peertest::scenarios::put_content::test_gossip_dropped_with_find_content(
            &peertest, &target, V0_NETWORK,
        )
        .await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_recursive_utp() {
        let (peertest, _target, handle) = setup_peertest(V0_NETWORK, &[Subnetwork::History]).await;
        peertest::scenarios::utp::test_recursive_utp(&peertest).await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_trace_recursive_utp() {
        let (peertest, _target, handle) = setup_peertest(V0_NETWORK, &[Subnetwork::History]).await;
        peertest::scenarios::utp::test_trace_recursive_utp(&peertest).await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }
}

mod protocol_v1 {
    use super::*;

    const V1_NETWORK: Network = Network::Mainnet;

    // offer tests

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_put_content() {
        let (peertest, target, handle) = setup_peertest(V1_NETWORK, &[Subnetwork::History]).await;
        peertest::scenarios::put_content::test_put_content(&peertest, &target, V1_NETWORK).await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_history_gossip_dropped_with_offer() {
        let (peertest, target, handle) = setup_peertest(V1_NETWORK, &[Subnetwork::History]).await;
        peertest::scenarios::put_content::test_gossip_dropped_with_offer(
            &peertest, &target, V1_NETWORK,
        )
        .await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_history_offer_propagates_gossip() {
        let (peertest, target, handle) = setup_peertest(V1_NETWORK, &[Subnetwork::History]).await;
        peertest::scenarios::offer_accept::test_offer_propagates_gossip(&peertest, &target).await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_history_offer_propagates_gossip_multiple_content_values() {
        let (peertest, target, handle) = setup_peertest(V1_NETWORK, &[Subnetwork::History]).await;
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
        let (peertest, target, handle) = setup_peertest(V1_NETWORK, &[Subnetwork::History]).await;
        peertest::scenarios::offer_accept::test_offer_propagates_gossip_multiple_large_content_values(
        &peertest, &target,
    )
    .await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_history_offer_propagates_gossip_with_large_content() {
        let (peertest, target, handle) = setup_peertest(V1_NETWORK, &[Subnetwork::History]).await;
        peertest::scenarios::offer_accept::test_offer_propagates_gossip_with_large_content(
            &peertest, &target,
        )
        .await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_offer() {
        let (peertest, target, handle) = setup_peertest(V1_NETWORK, &[Subnetwork::History]).await;
        peertest::scenarios::offer_accept::test_offer(&peertest, &target).await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_offer_with_trace() {
        let (peertest, target, handle) = setup_peertest(V1_NETWORK, &[Subnetwork::History]).await;
        peertest::scenarios::offer_accept::test_offer_with_trace(&peertest, &target).await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_state_offer_account_trie_node() {
        let (peertest, target, handle) =
            setup_peertest(Network::Angelfood, &[Subnetwork::State]).await;
        peertest::scenarios::state::test_state_offer_account_trie_node(&peertest, &target).await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_state_offer_contract_bytecode() {
        let (peertest, target, handle) =
            setup_peertest(Network::Angelfood, &[Subnetwork::State]).await;
        peertest::scenarios::state::test_state_gossip_contract_bytecode(&peertest, &target).await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_state_offer_contract_storage_trie_node() {
        let (peertest, target, handle) =
            setup_peertest(Network::Angelfood, &[Subnetwork::State]).await;
        peertest::scenarios::state::test_state_gossip_contract_storage_trie_node(
            &peertest, &target,
        )
        .await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }

    // find content tests

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_validate_block_body() {
        let (peertest, target, handle) = setup_peertest(V1_NETWORK, &[Subnetwork::History]).await;
        peertest::scenarios::validation::test_validate_pre_merge_block_body(&peertest, &target)
            .await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_validate_receipts() {
        let (peertest, target, handle) = setup_peertest(V1_NETWORK, &[Subnetwork::History]).await;
        peertest::scenarios::validation::test_validate_pre_merge_receipts(&peertest, &target).await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_history_gossip_dropped_with_find_content() {
        let (peertest, target, handle) = setup_peertest(V1_NETWORK, &[Subnetwork::History]).await;
        peertest::scenarios::put_content::test_gossip_dropped_with_find_content(
            &peertest, &target, V1_NETWORK,
        )
        .await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_recursive_utp() {
        let (peertest, _target, handle) = setup_peertest(V1_NETWORK, &[Subnetwork::History]).await;
        peertest::scenarios::utp::test_recursive_utp(&peertest).await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn peertest_trace_recursive_utp() {
        let (peertest, _target, handle) = setup_peertest(V1_NETWORK, &[Subnetwork::History]).await;
        peertest::scenarios::utp::test_trace_recursive_utp(&peertest).await;
        peertest.exit_all_nodes();
        handle.stop().unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "test is flaky: fails in some environments and in CI sporadically. Re-add #[serial] when re-enabling"]
async fn peertest_offer_concurrent_utp_transfer_limit() {
    let (peertest, target, handle) = setup_peertest_http(&[Subnetwork::History]).await;
    peertest::scenarios::offer_accept::test_offer_concurrent_utp_transfer_limit(&peertest, target)
        .await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_find_content_return_enr() {
    let (peertest, target, handle) = setup_peertest(Network::Mainnet, &[Subnetwork::History]).await;
    peertest::scenarios::find::test_find_content_return_enr(&target, &peertest).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_trace_get_content_local_db() {
    let (peertest, _target, handle) =
        setup_peertest(Network::Mainnet, &[Subnetwork::History]).await;
    peertest::scenarios::find::test_trace_get_content_local_db(&peertest).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_trace_get_content_for_absent_content() {
    let (peertest, _target, handle) =
        setup_peertest(Network::Mainnet, &[Subnetwork::History]).await;
    peertest::scenarios::find::test_trace_get_content_for_absent_content(&peertest).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_trace_get_content() {
    let (peertest, _target, handle) =
        setup_peertest(Network::Mainnet, &[Subnetwork::History]).await;
    peertest::scenarios::find::test_trace_get_content(&peertest).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_validate_pre_merge_header_by_hash() {
    let (peertest, target, handle) = setup_peertest(Network::Mainnet, &[Subnetwork::History]).await;
    peertest::scenarios::validation::test_validate_pre_merge_header_by_hash(&peertest, &target)
        .await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_validate_pre_merge_header_by_number() {
    let (peertest, target, handle) = setup_peertest(Network::Mainnet, &[Subnetwork::History]).await;
    peertest::scenarios::validation::test_validate_pre_merge_header_by_number(&peertest, &target)
        .await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peertest_invalidate_header_by_hash() {
    let (peertest, target, handle) = setup_peertest(Network::Mainnet, &[Subnetwork::History]).await;
    peertest::scenarios::validation::test_invalidate_header_by_hash(&peertest, &target).await;
    peertest.exit_all_nodes();
    handle.stop().unwrap();
}

async fn setup_peertest(
    network: Network,
    subnetworks: &[Subnetwork],
) -> (peertest::Peertest, Client, RpcServerHandle) {
    utils::init_tracing();
    set_network_spec(network_parser(&network.to_string()).expect("Failed to parse network"));

    // Run a client, as a buddy peer for ping tests, etc.
    let peertest = peertest::launch_peertest_nodes(2, network, subnetworks).await;
    // Short sleep to make sure all peertest nodes can connect
    sleep(Duration::from_millis(100)).await;

    let test_ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    // Use an uncommon port for the peertest to avoid clashes.
    let test_discovery_port = 8999;
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

async fn setup_peertest_http(
    subnetworks: &[Subnetwork],
) -> (Peertest, HttpClient, RpcServerHandle) {
    utils::init_tracing();

    let network = Network::Mainnet;
    set_network_spec(network_parser(&network.to_string()).expect("Failed to parse network"));
    // Run a client, as a buddy peer for ping tests, etc.
    let peertest = peertest::launch_peertest_nodes(1, network, subnetworks).await;
    // Short sleep to make sure all peertest nodes can connect
    sleep(Duration::from_millis(100)).await;

    let test_ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    // Use an uncommon port for the peertest to avoid clashes.
    let test_discovery_port = 8999;
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

    let test_client_rpc_handle = run_trin_from_trin_config(trin_config).await.unwrap();
    let target = ethportal_api::jsonrpsee::http_client::HttpClientBuilder::default()
        .build(DEFAULT_WEB3_HTTP_ADDRESS)
        .unwrap();
    (peertest, target, test_client_rpc_handle.rpc_server_handle)
}
