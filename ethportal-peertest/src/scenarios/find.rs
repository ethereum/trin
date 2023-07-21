use crate::Peertest;
use discv5::enr::NodeId;
use ethportal_api::types::content_key::HistoryContentKey;
use ethportal_api::types::content_value::{HistoryContentValue, PossibleHistoryContentValue};
use ethportal_api::types::portal::TraceContentInfo;
use ethportal_api::utils::bytes::hex_decode;
use ethportal_api::HistoryNetworkApiClient;
use tracing::info;

pub async fn test_recursive_find_nodes_self(peertest: &Peertest) {
    info!("Testing trace recursive find nodes self");
    let target_enr = peertest.bootnode.enr.clone();
    let target_node_id = NodeId::from(target_enr.node_id().raw());
    let result = peertest
        .bootnode
        .ipc_client
        .recursive_find_nodes(target_node_id)
        .await
        .unwrap();
    assert_eq!(result, vec![target_enr]);
}

pub async fn test_recursive_find_nodes_peer(peertest: &Peertest) {
    info!("Testing trace recursive find nodes peer");
    let target_enr = peertest.nodes[0].enr.clone();
    let target_node_id = NodeId::from(target_enr.node_id().raw());
    let result = peertest
        .bootnode
        .ipc_client
        .recursive_find_nodes(target_node_id)
        .await
        .unwrap();
    assert_eq!(result, vec![target_enr]);
}

pub async fn test_recursive_find_nodes_random(peertest: &Peertest) {
    info!("Testing trace recursive find nodes random");
    let mut bytes = [0u8; 32];
    let random_node_id =
        hex_decode("0xcac75e7e776d84fba55a3104bdccfd716537bca3ad8465113f67f04d62694183").unwrap();
    bytes.copy_from_slice(&random_node_id);
    let target_node_id = NodeId::from(bytes);
    let result = peertest
        .bootnode
        .ipc_client
        .recursive_find_nodes(target_node_id)
        .await
        .unwrap();
    assert_eq!(result.len(), 3);
}

pub async fn test_trace_recursive_find_content(
    peertest: &Peertest,
    test_content: (HistoryContentKey, HistoryContentValue),
) {
    info!("Testing trace recursive find content");
    let (content_key, content_value) = test_content;
    let store_result = peertest
        .bootnode
        .ipc_client
        .store(content_key.clone(), content_value.clone())
        .await
        .unwrap();

    assert!(store_result);

    let trace_content_info: TraceContentInfo = peertest.nodes[0]
        .ipc_client
        .trace_recursive_find_content(content_key)
        .await
        .unwrap();

    let content = trace_content_info.content;
    let trace = trace_content_info.trace;

    assert_eq!(
        content,
        PossibleHistoryContentValue::ContentPresent(content_value)
    );

    let query_origin_node: NodeId = peertest.nodes[0].enr.node_id();
    let node_with_content: NodeId = peertest.bootnode.enr.node_id();

    // Test that `origin` is set correctly
    let origin = trace.origin;
    assert_eq!(origin, ethportal_api::NodeId::from(query_origin_node));

    // Test that `received_content_from_node` is set correctly
    let received_content_from_node = trace.received_content_from_node.unwrap();
    assert_eq!(
        ethportal_api::NodeId::from(node_with_content),
        received_content_from_node
    );

    let responses = trace.responses;

    // Test that origin response has `responses` containing `received_content_from_node` node
    let origin_response = responses.get(&origin).unwrap();
    assert!(origin_response
        .responded_with
        .contains(&received_content_from_node));
}

// This test ensures that when content is not found the correct response is returned.
pub async fn test_trace_recursive_find_content_for_absent_content(
    peertest: &Peertest,
    test_content: (HistoryContentKey, HistoryContentValue),
) {
    let client = &peertest.nodes[0].ipc_client;
    let (content_key, _) = test_content;

    let result = client
        .trace_recursive_find_content(content_key)
        .await
        .unwrap();

    assert_eq!(result.content, PossibleHistoryContentValue::ContentAbsent);
    // Check that at least one route was involved.
    assert!(result.trace.responses.len() > 1);
}

pub async fn test_trace_recursive_find_content_local_db(
    peertest: &Peertest,
    test_content: (HistoryContentKey, HistoryContentValue),
) {
    let (content_key, content_value) = test_content;

    let store_result = peertest
        .bootnode
        .ipc_client
        .store(content_key.clone(), content_value.clone())
        .await
        .unwrap();

    assert!(store_result);

    let trace_content_info: TraceContentInfo = peertest
        .bootnode
        .ipc_client
        .trace_recursive_find_content(content_key)
        .await
        .unwrap();
    assert_eq!(
        trace_content_info.content,
        PossibleHistoryContentValue::ContentPresent(content_value)
    );

    let origin = trace_content_info.trace.origin;
    assert_eq!(
        trace_content_info.trace.received_content_from_node.unwrap(),
        origin
    );

    let expected_origin_id: NodeId = peertest.bootnode.enr.node_id();
    assert_eq!(ethportal_api::NodeId::from(expected_origin_id), origin);
}
