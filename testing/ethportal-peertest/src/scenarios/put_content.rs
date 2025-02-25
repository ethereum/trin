use std::net::{IpAddr, Ipv4Addr};

use ethportal_api::{
    jsonrpsee::async_client::Client, version::APP_NAME, ContentValue, Discv5ApiClient,
    HistoryNetworkApiClient,
};
use tracing::info;
use trin::cli::TrinConfig;

use crate::{
    utils::{
        fixture_block_body_15040708, fixture_header_by_hash,
        fixture_header_by_hash_with_proof_15040641, fixture_header_by_hash_with_proof_15040708,
        fixture_receipts_15040641, wait_for_history_content,
    },
    Peertest,
};
pub async fn test_gossip_with_trace(peertest: &Peertest, target: &Client) {
    info!("Testing Gossip with tracing");

    let _ = HistoryNetworkApiClient::ping(target, peertest.bootnode.enr.clone())
        .await
        .unwrap();
    let (content_key, content_value) = fixture_header_by_hash();
    let result = target
        .trace_put_content(content_key.clone(), content_value.encode())
        .await
        .unwrap();

    assert_eq!(result.offered.len(), 1);
    assert_eq!(result.accepted.len(), 1);
    assert_eq!(result.transferred.len(), 1);

    // Check if the stored content value in bootnode's DB matches the offered
    let received_content_value =
        wait_for_history_content(&peertest.bootnode.ipc_client, content_key.clone()).await;
    assert_eq!(
        content_value, received_content_value,
        "The received content {received_content_value:?}, must match the expected {content_value:?}",
    );

    // Spin up a fresh client, not connected to existing peertest
    let (fresh_ipc_path, trin_config) = fresh_node_config();
    let _test_client_rpc_handle = trin::run_trin(trin_config).await.unwrap();
    let fresh_target = reth_ipc::client::IpcClientBuilder::default()
        .build(&fresh_ipc_path)
        .await
        .unwrap();
    let fresh_enr = fresh_target.node_info().await.unwrap().enr;

    // connect to new node
    let _ = HistoryNetworkApiClient::ping(target, fresh_enr)
        .await
        .unwrap();

    // send new trace gossip request
    let result = target
        .trace_put_content(content_key.clone(), content_value.encode())
        .await
        .unwrap();

    assert_eq!(result.offered.len(), 2);
    assert_eq!(result.accepted.len(), 1);
    assert_eq!(result.transferred.len(), 1);

    // Check if the stored content value in fresh node's DB matches the offered
    let received_content_value = wait_for_history_content(&fresh_target, content_key.clone()).await;
    assert_eq!(
        content_value, received_content_value,
        "The received content {received_content_value:?}, must match the expected {content_value:?}",
    );

    // test trace gossip without any expected accepts
    let result = target
        .trace_put_content(content_key, content_value.encode())
        .await
        .unwrap();

    assert_eq!(result.offered.len(), 2);
    assert_eq!(result.accepted.len(), 0);
    assert_eq!(result.transferred.len(), 0);
}

pub async fn test_gossip_dropped_with_offer(peertest: &Peertest, target: &Client) {
    info!("Testing gossip of dropped content after an offer message.");

    // connect target to network
    let _ = HistoryNetworkApiClient::ping(target, peertest.bootnode.enr.clone())
        .await
        .unwrap();

    // Spin up a fresh client, not connected to existing peertest
    let (fresh_ipc_path, trin_config) = fresh_node_config();
    let _test_client_rpc_handle = trin::run_trin(trin_config).await.unwrap();
    let fresh_target = reth_ipc::client::IpcClientBuilder::default()
        .build(&fresh_ipc_path)
        .await
        .unwrap();
    let fresh_enr = fresh_target.node_info().await.unwrap().enr;

    // Store receipt_1 locally in client that is not connected to the network
    let (header_key_1, header_value_1) = fixture_header_by_hash_with_proof_15040641();
    let (receipts_key_1, receipts_value_1) = fixture_receipts_15040641();
    let store_result = HistoryNetworkApiClient::store(
        &fresh_target,
        header_key_1.clone(),
        header_value_1.encode(),
    )
    .await
    .unwrap();
    assert!(store_result);
    let store_result = HistoryNetworkApiClient::store(
        &fresh_target,
        receipts_key_1.clone(),
        receipts_value_1.encode(),
    )
    .await
    .unwrap();
    assert!(store_result);

    // check that fresh target has receipt_1
    assert!(
        HistoryNetworkApiClient::local_content(&fresh_target, header_key_1.clone())
            .await
            .is_ok()
    );
    assert!(
        HistoryNetworkApiClient::local_content(&fresh_target, receipts_key_1.clone())
            .await
            .is_ok()
    );
    // check that target does not have receipt_1
    assert!(
        HistoryNetworkApiClient::local_content(target, header_key_1.clone())
            .await
            .is_err()
    );
    assert!(
        HistoryNetworkApiClient::local_content(target, receipts_key_1.clone())
            .await
            .is_err()
    );
    // check that peertest node does not have receipt_1
    assert!(HistoryNetworkApiClient::local_content(
        &peertest.nodes[0].ipc_client,
        header_key_1.clone()
    )
    .await
    .is_err());
    assert!(HistoryNetworkApiClient::local_content(
        &peertest.nodes[0].ipc_client,
        receipts_key_1.clone()
    )
    .await
    .is_err());
    // check that peertest bootnode does not have receipt_1
    assert!(HistoryNetworkApiClient::local_content(
        &peertest.bootnode.ipc_client,
        header_key_1.clone()
    )
    .await
    .is_err());
    assert!(HistoryNetworkApiClient::local_content(
        &peertest.bootnode.ipc_client,
        receipts_key_1.clone()
    )
    .await
    .is_err());

    // connect fresh target to network
    let _ = HistoryNetworkApiClient::ping(&fresh_target, target.node_info().await.unwrap().enr)
        .await
        .unwrap();
    let _ = HistoryNetworkApiClient::ping(&fresh_target, peertest.bootnode.enr.clone())
        .await
        .unwrap();
    let _ = HistoryNetworkApiClient::ping(&fresh_target, peertest.nodes[0].enr.clone())
        .await
        .unwrap();

    // offer body_2 with receipt from target to fresh target
    // doesn't store the content locally in target
    let (header_key_2, header_value_2) = fixture_header_by_hash_with_proof_15040708();
    let (body_key_2, body_value_2) = fixture_block_body_15040708();
    target
        .offer(
            fresh_enr.clone(),
            vec![(header_key_2.clone(), header_value_2.encode())],
        )
        .await
        .unwrap();
    target
        .offer(
            fresh_enr.clone(),
            vec![(body_key_2.clone(), body_value_2.encode())],
        )
        .await
        .unwrap();

    // check that the fresh target has stored block_2
    assert_eq!(
        body_value_2,
        wait_for_history_content(&fresh_target, body_key_2.clone()).await
    );
    // check that the target has block_1 and block_2
    assert_eq!(
        body_value_2,
        wait_for_history_content(target, body_key_2.clone()).await
    );
    assert_eq!(
        receipts_value_1,
        wait_for_history_content(target, receipts_key_1.clone()).await
    );

    // check that the peertest bootnode has block_1 and block_2
    assert_eq!(
        body_value_2,
        wait_for_history_content(&peertest.bootnode.ipc_client, body_key_2.clone()).await
    );
    assert_eq!(
        receipts_value_1,
        wait_for_history_content(&peertest.bootnode.ipc_client, receipts_key_1.clone()).await
    );

    // check that the peertest node has block_1 and block_2
    assert_eq!(
        body_value_2,
        wait_for_history_content(&peertest.nodes[0].ipc_client, body_key_2.clone()).await
    );
    assert_eq!(
        receipts_value_1,
        wait_for_history_content(&peertest.nodes[0].ipc_client, receipts_key_1.clone()).await
    );

    // this must be at end of test, to guarantee that all propagation has concluded
    // check that the fresh target has dropped block_receipt_1
    assert!(
        HistoryNetworkApiClient::local_content(&fresh_target, receipts_key_1.clone())
            .await
            .is_err()
    );
}

pub async fn test_gossip_dropped_with_find_content(peertest: &Peertest, target: &Client) {
    info!("Testing gossip of dropped content after a find content message.");

    // connect target to network
    let _ = HistoryNetworkApiClient::ping(target, peertest.bootnode.enr.clone())
        .await
        .unwrap();

    // Spin up a fresh client, not connected to existing peertest
    let (fresh_ipc_path, trin_config) = fresh_node_config();
    let _test_client_rpc_handle = trin::run_trin(trin_config).await.unwrap();
    let fresh_target = reth_ipc::client::IpcClientBuilder::default()
        .build(&fresh_ipc_path)
        .await
        .unwrap();

    // Store receipts_1 locally in client, without validation, that is not connected to the network
    let (receipts_key_1, receipts_value_1) = fixture_receipts_15040641();
    let store_result = HistoryNetworkApiClient::store(
        &fresh_target,
        receipts_key_1.clone(),
        receipts_value_1.encode(),
    )
    .await
    .unwrap();
    assert!(store_result);

    // Store header_1, header_2, body_2 locally in target
    let (header_key_1, header_value_1) = fixture_header_by_hash_with_proof_15040641();
    let (header_key_2, header_value_2) = fixture_header_by_hash_with_proof_15040708();
    let (body_key_2, body_value_2) = fixture_block_body_15040708();
    let store_result =
        HistoryNetworkApiClient::store(target, header_key_1.clone(), header_value_1.encode())
            .await
            .unwrap();
    assert!(store_result);
    let store_result =
        HistoryNetworkApiClient::store(target, header_key_2.clone(), header_value_2.encode())
            .await
            .unwrap();
    assert!(store_result);
    let store_result =
        HistoryNetworkApiClient::store(target, body_key_2.clone(), body_value_2.encode())
            .await
            .unwrap();
    assert!(store_result);

    // connect fresh target to network
    let _ = HistoryNetworkApiClient::ping(&fresh_target, target.node_info().await.unwrap().enr)
        .await
        .unwrap();
    let _ = HistoryNetworkApiClient::ping(&fresh_target, peertest.bootnode.enr.clone())
        .await
        .unwrap();
    let _ = HistoryNetworkApiClient::ping(&fresh_target, peertest.nodes[0].enr.clone())
        .await
        .unwrap();

    // send get_content request from fresh target to target
    let _result = fresh_target.get_content(body_key_2.clone()).await.unwrap();

    // check that the fresh target has stored body_2 stored
    assert_eq!(
        body_value_2,
        wait_for_history_content(&fresh_target, body_key_2.clone()).await
    );
    // check that the target has block_1 and block_2
    assert_eq!(
        body_value_2,
        wait_for_history_content(target, body_key_2.clone()).await
    );
    assert_eq!(
        receipts_value_1,
        wait_for_history_content(target, receipts_key_1.clone()).await
    );
    // check that the peertest bootnode has block_1 and block_2
    assert_eq!(
        body_value_2,
        wait_for_history_content(&peertest.bootnode.ipc_client, body_key_2.clone()).await
    );
    assert_eq!(
        receipts_value_1,
        wait_for_history_content(&peertest.bootnode.ipc_client, receipts_key_1.clone()).await
    );

    // check that the peertest node has block_1 and block_2
    assert_eq!(
        body_value_2,
        wait_for_history_content(&peertest.nodes[0].ipc_client, body_key_2.clone()).await
    );
    assert_eq!(
        receipts_value_1,
        wait_for_history_content(&peertest.nodes[0].ipc_client, receipts_key_1.clone()).await
    );

    // this must be at end of test, to guarantee that all propagation has concluded
    // check that the fresh target has dropped block_receipt_1
    assert!(
        HistoryNetworkApiClient::local_content(&fresh_target, receipts_key_1.clone())
            .await
            .is_err()
    );
}

fn fresh_node_config() -> (String, TrinConfig) {
    // Spin up a fresh client, not connected to existing peertest
    let test_ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    // Use an uncommon port for the peertest to avoid clashes.
    let test_discovery_port = 8889;
    let external_addr = format!("{test_ip_addr}:{test_discovery_port}");
    let fresh_ipc_path = format!("/tmp/trin-jsonrpc-{test_discovery_port}.ipc");
    let trin_config = TrinConfig::new_from([
        APP_NAME,
        "--portal-subnetworks",
        "history",
        "--external-address",
        external_addr.as_str(),
        "--mb",
        "1", // set storage to 1mb so that we can easily test dropping data
        "--web3-ipc-path",
        fresh_ipc_path.as_str(),
        "--ephemeral",
        "--discovery-port",
        test_discovery_port.to_string().as_ref(),
        "--bootnodes",
        "none",
        "--max-radius",
        "100",
        "--unsafe-private-key",
        // node id: 0x27128939ed60d6f4caef0374da15361a2c1cd6baa1a5bccebac1acd18f485900
        "0x9ca7889c09ef1162132251b6284bd48e64bd3e71d75ea33b959c37be0582a2fd",
    ])
    .unwrap();
    (fresh_ipc_path, trin_config)
}
