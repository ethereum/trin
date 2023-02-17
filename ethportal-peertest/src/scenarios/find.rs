use serde_json::{json, Value};

use crate::{
    jsonrpc::{make_ipc_request, JsonRpcRequest, HISTORY_CONTENT_VALUE},
    Peertest, PeertestConfig,
};
use trin_core::jsonrpc::types::Params;

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

    let error = make_ipc_request(&peertest.nodes[0].web3_ipc_path, &request).unwrap_err();
    assert!(error.to_string().contains("Invalid content key provided"));
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
