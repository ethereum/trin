use std::time::SystemTime;

use discv5::enr::NodeId;
use jsonrpsee::async_client::Client;
use tracing::info;

use crate::{utils::fixture_header_with_proof, Peertest};
use ethportal_api::{
    types::{history::ContentInfo, portal_wire::ProtocolId},
    utils::bytes::hex_decode,
    BeaconNetworkApiClient, Enr, HistoryNetworkApiClient, OverlayContentKey, StateNetworkApiClient,
};

pub async fn test_recursive_find_nodes_self(protocol: ProtocolId, peertest: &Peertest) {
    info!("Testing recursive find nodes self for {protocol}");
    let target_enr = peertest.bootnode.enr.clone();
    let target_node_id = NodeId::from(target_enr.node_id().raw());
    let result =
        call_recursive_find_nodes(protocol, &peertest.bootnode.ipc_client, target_node_id).await;
    assert_eq!(result, vec![target_enr]);
}

pub async fn test_recursive_find_nodes_peer(protocol: ProtocolId, peertest: &Peertest) {
    info!("Testing recursive find nodes peer for {protocol}");
    let target_enr = peertest.nodes[0].enr.clone();
    let target_node_id = NodeId::from(target_enr.node_id().raw());
    let result =
        call_recursive_find_nodes(protocol, &peertest.bootnode.ipc_client, target_node_id).await;
    assert_eq!(result, vec![target_enr]);
}

pub async fn test_recursive_find_nodes_random(protocol: ProtocolId, peertest: &Peertest) {
    info!("Testing recursive find nodes random for {protocol}");
    let mut bytes = [0u8; 32];
    let random_node_id =
        hex_decode("0xcac75e7e776d84fba55a3104bdccfd716537bca3ad8465113f67f04d62694183").unwrap();
    bytes.copy_from_slice(&random_node_id);
    let target_node_id = NodeId::from(bytes);
    let result =
        call_recursive_find_nodes(protocol, &peertest.bootnode.ipc_client, target_node_id).await;
    assert_eq!(result.len(), 2);
}

pub async fn test_find_content_return_enr(target: &Client, peertest: &Peertest) {
    info!("Testing find content returns enrs properly");

    let (content_key, _) = fixture_header_with_proof();

    // check if we can fetch data from routing table
    match HistoryNetworkApiClient::get_enr(
        &peertest.bootnode.ipc_client,
        peertest.nodes[0].enr.node_id(),
    )
    .await
    {
        Ok(response) => {
            if response != peertest.nodes[0].enr.clone() {
                panic!("Response from GetEnr didn't return expected Enr");
            }
        }
        Err(err) => panic!("{err}"),
    }

    let result = HistoryNetworkApiClient::find_content(
        target,
        peertest.bootnode.enr.clone(),
        content_key.clone(),
    )
    .await;

    let enrs = if let Ok(ContentInfo::Enrs { enrs }) = result {
        enrs
    } else {
        panic!("Error: Invalid response from FINDCONTENT request, expected ENRs got: {result:?}");
    };

    // check if find_content contains an expected enr
    if !enrs.contains(&peertest.nodes[0].enr.clone()) {
        panic!("find_content didn't return expected ENR");
    }
}

pub async fn test_trace_recursive_find_content(peertest: &Peertest) {
    info!("Testing trace recursive find content");
    let (content_key, content_value) = fixture_header_with_proof();
    let store_result = HistoryNetworkApiClient::store(
        &peertest.bootnode.ipc_client,
        content_key.clone(),
        content_value.clone(),
    )
    .await
    .unwrap();

    assert!(store_result);

    let query_start_time = SystemTime::now();
    let trace_content_info = HistoryNetworkApiClient::trace_recursive_find_content(
        &peertest.nodes[0].ipc_client,
        content_key.clone(),
    )
    .await
    .unwrap();

    assert!(!trace_content_info.utp_transfer);
    let content = trace_content_info.content;
    let trace = trace_content_info.trace;

    assert_eq!(content, content_value);

    let query_origin_node: NodeId = peertest.nodes[0].enr.node_id();
    let node_with_content: NodeId = peertest.bootnode.enr.node_id();

    // Test that `origin` is set correctly
    let origin = trace.origin;
    assert_eq!(origin, query_origin_node);

    // Test that `received_from` is set correctly
    let received_from = trace.received_from.unwrap();
    assert_eq!(node_with_content, received_from);

    let responses = trace.responses;

    // Test that origin response has `responses` containing `received_content_from_node` node
    let origin_response = responses.get(&origin).unwrap();
    assert!(origin_response.responded_with.contains(&received_from));

    // Test that cancelled is present
    assert!(trace.cancelled.is_empty());
    // Test that started_at_ms is correctly set
    assert!(trace.started_at_ms >= query_start_time);
    // Test that target_id is correctly set
    assert_eq!(trace.target_id, content_key.content_id());
    // Test that metadata is present
    assert_eq!(trace.metadata.len(), 2)
}

// This test ensures that when content is not found the correct response is returned.
pub async fn test_trace_recursive_find_content_for_absent_content(peertest: &Peertest) {
    let client = &peertest.nodes[0].ipc_client;
    let (content_key, _) = fixture_header_with_proof();

    let error = HistoryNetworkApiClient::trace_recursive_find_content(client, content_key)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("Unable to locate content on the network"));
    // test that trace is present
    assert!(error.contains("respondedWith"));
    assert!(error.contains("-39001"));
}

pub async fn test_trace_recursive_find_content_local_db(peertest: &Peertest) {
    let (content_key, content_value) = fixture_header_with_proof();

    let store_result = HistoryNetworkApiClient::store(
        &peertest.bootnode.ipc_client,
        content_key.clone(),
        content_value.clone(),
    )
    .await
    .unwrap();

    assert!(store_result);

    let trace_content_info = HistoryNetworkApiClient::trace_recursive_find_content(
        &peertest.bootnode.ipc_client,
        content_key,
    )
    .await
    .unwrap();
    assert!(!trace_content_info.utp_transfer);
    assert_eq!(trace_content_info.content, content_value);

    let origin = trace_content_info.trace.origin;
    assert_eq!(trace_content_info.trace.received_from.unwrap(), origin);

    let expected_origin_id: NodeId = peertest.bootnode.enr.node_id();
    assert_eq!(expected_origin_id, origin);
}

async fn call_recursive_find_nodes(
    protocol: ProtocolId,
    client: &Client,
    node_id: NodeId,
) -> Vec<Enr> {
    match protocol {
        ProtocolId::Beacon => BeaconNetworkApiClient::recursive_find_nodes(client, node_id),
        ProtocolId::History => HistoryNetworkApiClient::recursive_find_nodes(client, node_id),
        ProtocolId::State => StateNetworkApiClient::recursive_find_nodes(client, node_id),
        _ => panic!("Unexpected protocol: {protocol}"),
    }
    .await
    .unwrap()
}
