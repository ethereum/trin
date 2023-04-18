use ethereum_types::U256;
use serde_json::json;
use tracing::info;

use crate::{constants::HISTORY_CONTENT_VALUE, Peertest};
use ethportal_api::types::portal::NodeInfo;
use ethportal_api::HistoryNetworkApiClient;
use trin_types::content_key::HistoryContentKey;
use trin_types::content_value::{HistoryContentValue, PossibleHistoryContentValue};
use trin_utils::bytes::hex_decode;

pub async fn test_trace_recursive_find_content(peertest: &Peertest) {
    info!("Testing trace recursive find content");
    let uniq_content_key = "0x0015b11b918355b1ef9c5db810302ebad0bf2544255b530cdce90674d5887bb286";

    let content_key: HistoryContentKey = serde_json::from_value(json!(uniq_content_key)).unwrap();
    let content_value: HistoryContentValue =
        serde_json::from_value(json!(HISTORY_CONTENT_VALUE)).unwrap();

    // Store content in the bootnode db
    let store_result = peertest
        .bootnode
        .ipc_client
        .store(content_key.clone(), content_value.clone())
        .await
        .unwrap();
    assert!(store_result);

    // Send trace recursive find content request
    let result = peertest.nodes[0]
        .ipc_client
        .trace_recursive_find_content(content_key)
        .await
        .unwrap();
    let received_content_value = match result.content {
        PossibleHistoryContentValue::ContentPresent(c) => c,
        PossibleHistoryContentValue::ContentAbsent => panic!("Expected content to be found"),
    };
    assert_eq!(received_content_value, content_value);
    assert_eq!(
        result.route,
        vec![NodeInfo {
            enr: peertest.bootnode.enr.clone(),
            distance: U256::from_str_radix("0x100", 16).unwrap()
        }]
    );
}

// This test ensures that when content is not found the correct response is returned.
pub async fn test_trace_recursive_find_content_for_absent_content(peertest: &Peertest) {
    info!("Testing trace recursive find content for absent content");
    // Different key to other test (final character).
    let uniq_content_key = "0x0015b11b918355b1ef9c5db810302ebad0bf2544255b530cdce90674d5887bb287";
    let content_key: HistoryContentKey = serde_json::from_value(json!(uniq_content_key)).unwrap();
    // Do not store content in the bootnode db

    // Send trace recursive find content request
    let result = peertest
        .bootnode
        .ipc_client
        .trace_recursive_find_content(content_key)
        .await
        .unwrap();

    if let PossibleHistoryContentValue::ContentPresent(_) = result.content {
        panic!("Expected content to be absent");
    }
    // Check that at least one route was involved.
    assert!(!result.route.is_empty());
}

pub async fn test_trace_recursive_find_content_local_db(peertest: &Peertest) {
    info!("Testing trace recursive find content local db");
    let uniq_content_key = "0x0025b11b918355b1ef9c5db810302ebad0bf2544255b530cdce90674d5887bb286";
    let content_key: HistoryContentKey = serde_json::from_value(json!(uniq_content_key)).unwrap();
    let content_value: HistoryContentValue =
        serde_json::from_value(json!(HISTORY_CONTENT_VALUE)).unwrap();

    // Store content in the bootnode db
    let store_result = peertest
        .bootnode
        .ipc_client
        .store(content_key.clone(), content_value.clone())
        .await
        .unwrap();
    assert!(store_result);

    // Send trace recursive find content request
    let result = peertest
        .bootnode
        .ipc_client
        .trace_recursive_find_content(content_key)
        .await
        .unwrap();
    let received_content_value = match result.content {
        PossibleHistoryContentValue::ContentPresent(c) => c,
        PossibleHistoryContentValue::ContentAbsent => panic!("Expected content to be found"),
    };
    assert_eq!(received_content_value, content_value);
    assert_eq!(result.route, vec![]);
}

pub async fn test_recursive_find_nodes_self(peertest: &Peertest) {
    info!("Testing trace recursive find nodes self");
    let target_enr = peertest.bootnode.enr.clone();
    let target_node_id = trin_types::node_id::NodeId::from(target_enr.node_id().raw());
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
    let target_node_id = trin_types::node_id::NodeId::from(target_enr.node_id().raw());
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
    let target_node_id = trin_types::node_id::NodeId::from(bytes);
    let result = peertest
        .bootnode
        .ipc_client
        .recursive_find_nodes(target_node_id)
        .await
        .unwrap();
    assert_eq!(result.len(), 3);
}
