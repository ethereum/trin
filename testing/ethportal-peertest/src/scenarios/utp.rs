use discv5::enr::NodeId;
use ethportal_api::{
    types::portal::{GetContentInfo, TraceContentInfo},
    ContentValue, LegacyHistoryNetworkApiClient,
};
use tracing::info;

use crate::{
    utils::{fixture_block_body, fixture_header_by_hash},
    Peertest,
};

pub async fn test_recursive_utp(peertest: &Peertest) {
    info!("Test recursive utp");

    // store header_with_proof to validate block body
    let (content_key, content_value) = fixture_header_by_hash();
    let store_result = peertest.nodes[0]
        .ipc_client
        .store(content_key.clone(), content_value.encode())
        .await
        .unwrap();
    assert!(store_result);

    let (content_key, content_value) = fixture_block_body();

    let store_result = peertest
        .bootnode
        .ipc_client
        .store(content_key.clone(), content_value.encode())
        .await
        .unwrap();

    assert!(store_result);

    let GetContentInfo {
        content,
        utp_transfer,
    } = peertest.nodes[0]
        .ipc_client
        .get_content(content_key)
        .await
        .unwrap();

    assert_eq!(content, content_value.encode());
    assert!(utp_transfer);
}

pub async fn test_trace_recursive_utp(peertest: &Peertest) {
    info!("Test trace recursive utp");

    // store header_with_proof to validate block body
    let (content_key, content_value) = fixture_header_by_hash();
    let store_result = peertest.nodes[0]
        .ipc_client
        .store(content_key.clone(), content_value.encode())
        .await
        .unwrap();

    assert!(store_result);

    let (content_key, content_value) = fixture_block_body();

    let store_result = peertest
        .bootnode
        .ipc_client
        .store(content_key.clone(), content_value.encode())
        .await
        .unwrap();

    assert!(store_result);

    let trace_content_info: TraceContentInfo = peertest.nodes[0]
        .ipc_client
        .trace_get_content(content_key)
        .await
        .unwrap();

    let content = trace_content_info.content;
    let trace = trace_content_info.trace;

    assert_eq!(content, content_value.encode());

    let query_origin_node: NodeId = peertest.nodes[0].enr.node_id();
    let node_with_content: NodeId = peertest.bootnode.enr.node_id();

    // Test that `origin` is set correctly
    let origin = trace.origin;
    assert_eq!(origin, query_origin_node);

    // Test that `received_content_from_node` is set correctly
    let received_content_from_node = trace.received_from.unwrap();
    assert_eq!(node_with_content, received_content_from_node);

    let responses = trace.responses;

    // Test that origin response has `responses` containing `received_content_from_node` node
    let origin_response = responses.get(&origin).unwrap();
    assert!(origin_response
        .responded_with
        .contains(&received_content_from_node));
}
