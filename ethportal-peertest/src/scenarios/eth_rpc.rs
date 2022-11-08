use serde_json::{json, Value};

use crate::{
    jsonrpc::{make_ipc_request, JsonRpcRequest, HISTORY_CONTENT_KEY, HISTORY_CONTENT_VALUE},
    Peertest, PeertestConfig,
};
use trin_core::jsonrpc::types::Params;

pub fn test_eth_get_block_by_hash(_peertest_config: PeertestConfig, peertest: &Peertest) {
    // Store content to offer in the testnode db
    let store_request = JsonRpcRequest {
        method: "portal_historyStore".to_string(),
        id: 11,
        params: Params::Array(vec![
            Value::String(HISTORY_CONTENT_KEY.to_string()),
            Value::String(HISTORY_CONTENT_VALUE.to_string()),
        ]),
    };

    let store_result = make_ipc_request(&peertest.bootnode.web3_ipc_path, &store_request).unwrap();
    assert_eq!(store_result.as_str().unwrap(), "true");

    // Send eth_getBlockByHash request
    let request = JsonRpcRequest {
        method: "eth_getBlockByHash".to_string(),
        id: 11,
        params: Params::Array(vec![
            json!("0x55b11b918355b1ef9c5db810302ebad0bf2544255b530cdce90674d5887bb286"),
            json!(false),
        ]),
    };

    let result = make_ipc_request(&peertest.nodes[0].web3_ipc_path, &request).unwrap();
    assert_eq!(json!(15537393), result["number"]);
}

pub fn test_eth_get_block_by_number(_peertest_config: PeertestConfig, peertest: &Peertest) {
    // Store content to offer in the testnode db
    let store_request = JsonRpcRequest {
        method: "portal_historyStore".to_string(),
        id: 11,
        params: Params::Array(vec![
            Value::String(HISTORY_CONTENT_KEY.to_string()),
            Value::String(HISTORY_CONTENT_VALUE.to_string()),
        ]),
    };

    let store_result = make_ipc_request(&peertest.bootnode.web3_ipc_path, &store_request).unwrap();
    assert_eq!(store_result.as_str().unwrap(), "true");

    // Send supported eth_getBlockByNumber request (pre-merge)
    let request = JsonRpcRequest {
        method: "eth_getBlockByNumber".to_string(),
        id: 11,
        params: Params::Array(vec![json!("0xed14f1"), json!(false)]),
    };

    let result = make_ipc_request(&peertest.nodes[0].web3_ipc_path, &request).unwrap();
    assert_eq!(json!(15537393), result["number"]);

    // Send unsupported eth_getBlockByNumber request (post-merge)
    let request = JsonRpcRequest {
        method: "eth_getBlockByNumber".to_string(),
        id: 11,
        params: Params::Array(vec![
            // Block #15537395
            json!("0xed14f3"),
            json!(false),
        ]),
    };

    let result = make_ipc_request(&peertest.nodes[0].web3_ipc_path, &request).unwrap_err();
    assert_eq!(result.to_string(), "JsonRpc response contains an error: String(\"Error while processing eth_getBlockByNumber: eth_getBlockByNumber not currently supported for blocks after the merge (#15537393)\")");
}
