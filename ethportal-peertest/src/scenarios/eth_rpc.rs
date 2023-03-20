use serde_json::{json, Value};
use tracing::info;

use crate::{
    jsonrpc::{make_ipc_request, JsonRpcRequest, HISTORY_CONTENT_KEY, HISTORY_CONTENT_VALUE},
    Peertest, PeertestConfig,
};
use trin_types::jsonrpc::params::Params;

pub fn test_eth_get_block_by_hash(_peertest_config: PeertestConfig, peertest: &Peertest) {
    info!("Testing eth_getBlockByHash");
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
    assert!(store_result.as_bool().unwrap());

    // Send eth_getBlockByHash request
    let request = JsonRpcRequest {
        method: "eth_getBlockByHash".to_string(),
        id: 11,
        params: Params::Array(vec![
            json!("0x6251d65b8a8668efabe2f89c96a5b6332d83b3bbe585089ea6b2ab9b6754f5e9"),
            json!(false),
        ]),
    };

    let result = make_ipc_request(&peertest.nodes[0].web3_ipc_path, &request).unwrap();
    assert_eq!(json!(1000010), result["number"]);
}

pub fn test_eth_get_block_by_number(_peertest_config: PeertestConfig, peertest: &Peertest) {
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
