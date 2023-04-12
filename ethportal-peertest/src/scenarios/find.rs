use discv5::enr::NodeId;
use serde_json::{json, Value};

use crate::{
    jsonrpc::{make_ipc_request, JsonRpcRequest, HISTORY_CONTENT_VALUE},
    Peertest, PeertestConfig,
};
use trin_types::{constants::CONTENT_ABSENT, jsonrpc::params::Params};
use trin_utils::bytes::hex_encode;

pub fn test_trace_recursive_find_content(_peertest_config: PeertestConfig, peertest: &Peertest) {
    let uniq_content_key = "0x0015b11b918355b1ef9c5db810302ebad0bf2544255b530cdce90674d5887bb286";
    // Store content to offer in the testnode db
    let store_request = JsonRpcRequest {
        method: "portal_historyStore".to_string(),
        id: 11,
        params: Params::Array(vec![
            Value::String(uniq_content_key.to_string()),
            Value::String(HISTORY_CONTENT_VALUE.to_string()),
        ]),
    };

    let store_result = make_ipc_request(&peertest.bootnode.web3_ipc_path, &store_request).unwrap();
    assert!(store_result.as_bool().unwrap());

    // Send trace recursive find content request
    let request = JsonRpcRequest {
        method: "portal_historyTraceRecursiveFindContent".to_string(),
        id: 12,
        params: Params::Array(vec![json!(uniq_content_key)]),
    };

    let result = make_ipc_request(&peertest.nodes[0].web3_ipc_path, &request).unwrap();
    assert_eq!(result["content"], json!(HISTORY_CONTENT_VALUE.to_string()));
    assert_eq!(
        result["route"],
        json!([{"enr": &peertest.bootnode.enr.to_base64(), "distance": "0x100"}])
    );
}

// This test ensures that when content is not found the correct response is returned.
pub fn test_trace_recursive_find_content_for_absent_content(
    _peertest_config: PeertestConfig,
    peertest: &Peertest,
) {
    // Different key to other test (final character).
    let uniq_content_key = "0x0015b11b918355b1ef9c5db810302ebad0bf2544255b530cdce90674d5887bb287";
    // Do not store content to offer in the testnode db

    // Send trace recursive find content request
    let request = JsonRpcRequest {
        method: "portal_historyTraceRecursiveFindContent".to_string(),
        id: 12,
        params: Params::Array(vec![json!(uniq_content_key)]),
    };

    let result = make_ipc_request(&peertest.nodes[0].web3_ipc_path, &request).unwrap();
    assert_eq!(result["content"], json!(CONTENT_ABSENT.to_string()));
    // Check that at least one route was involved.
    assert!(!result["route"].as_array().unwrap().is_empty());
}
// This test ensures that the jsonrpc channels don't close if there is an invalid recursive find
// content request
pub fn test_recursive_find_content_invalid_params(
    _peertest_config: PeertestConfig,
    peertest: &Peertest,
) {
    let invalid_content_key = "0x00";
    // Send trace recursive find content request
    let request = JsonRpcRequest {
        method: "portal_historyRecursiveFindContent".to_string(),
        id: 12,
        params: Params::Array(vec![json!(invalid_content_key)]),
    };

    // Expect invalid parameter response for invalid request
    let response = make_ipc_request(&peertest.nodes[0].web3_ipc_path, &request);
    assert!(response.is_err());
    let error = response.err().unwrap().to_string();
    assert_eq!(error, "JsonRpc response contains an error: Object {\"code\": Number(-32602), \"message\": String(\"unable to decode key SSZ bytes 0x00 due to InvalidByteLength { len: 0, expected: 32 }\")}");
}

pub fn test_trace_recursive_find_content_local_db(
    _peertest_config: PeertestConfig,
    peertest: &Peertest,
) {
    let uniq_content_key = "0x0025b11b918355b1ef9c5db810302ebad0bf2544255b530cdce90674d5887bb286";
    // Store content to offer in the testnode db
    let store_request = JsonRpcRequest {
        method: "portal_historyStore".to_string(),
        id: 13,
        params: Params::Array(vec![
            Value::String(uniq_content_key.to_string()),
            Value::String(HISTORY_CONTENT_VALUE.to_string()),
        ]),
    };

    let store_result = make_ipc_request(&peertest.bootnode.web3_ipc_path, &store_request).unwrap();
    assert!(store_result.as_bool().unwrap());

    // Send trace recursive find content request
    let request = JsonRpcRequest {
        method: "portal_historyTraceRecursiveFindContent".to_string(),
        id: 14,
        params: Params::Array(vec![json!(uniq_content_key)]),
    };

    let result = make_ipc_request(&peertest.bootnode.web3_ipc_path, &request).unwrap();
    assert_eq!(result["content"], json!(HISTORY_CONTENT_VALUE.to_string()));
    assert_eq!(result["route"], json!([]));
}

pub async fn test_recursive_find_nodes_self(_peertest_config: PeertestConfig, peertest: &Peertest) {
    let target_node_id = hex_encode(peertest.bootnode.enr.node_id().raw());
    let request = JsonRpcRequest {
        method: "portal_historyRecursiveFindNodes".to_string(),
        id: 15,
        params: Params::Array(vec![json!(target_node_id)]),
    };
    let result = make_ipc_request(&peertest.bootnode.web3_ipc_path, &request).unwrap();
    assert_eq!(result, json!([peertest.bootnode.enr.to_base64()]));
}

pub async fn test_recursive_find_nodes_peer(_peertest_config: PeertestConfig, peertest: &Peertest) {
    let target_enr = peertest.nodes[0].enr.clone();
    let target_node_id = hex_encode(target_enr.node_id().raw());
    let request = JsonRpcRequest {
        method: "portal_historyRecursiveFindNodes".to_string(),
        id: 15,
        params: Params::Array(vec![json!(target_node_id)]),
    };
    let result = make_ipc_request(&peertest.bootnode.web3_ipc_path, &request).unwrap();
    assert_eq!(result, json!([target_enr.to_base64()]));
}

pub async fn test_recursive_find_nodes_random(
    _peertest_config: PeertestConfig,
    peertest: &Peertest,
) {
    let target_node_id = hex_encode(NodeId::random());
    let request = JsonRpcRequest {
        method: "portal_historyRecursiveFindNodes".to_string(),
        id: 15,
        params: Params::Array(vec![json!(target_node_id)]),
    };
    let result = make_ipc_request(&peertest.bootnode.web3_ipc_path, &request).unwrap();
    assert_eq!(result.as_array().unwrap().len(), 2);
}
