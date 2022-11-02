use std::{thread, time};

use serde_json::{json, Value};
use tracing::{error, info};

use crate::{
    jsonrpc::{
        make_ipc_request, validate_portal_offer, JsonRpcRequest, HISTORY_CONTENT_KEY,
        HISTORY_CONTENT_VALUE,
    },
    Peertest, PeertestConfig,
};
use trin_core::jsonrpc::types::Params;

pub fn test_offer_accept(peertest_config: PeertestConfig, peertest: &Peertest) {
    info!("Testing OFFER/ACCEPT flow");

    // Store content to offer in the testnode db
    let store_request = JsonRpcRequest {
        method: "portal_historyStore".to_string(),
        id: 11,
        params: Params::Array(vec![
            Value::String(HISTORY_CONTENT_KEY.to_string()),
            Value::String(HISTORY_CONTENT_VALUE.to_string()),
        ]),
    };

    let store_result = make_ipc_request(&peertest_config.target_ipc_path, &store_request).unwrap();
    assert_eq!(store_result.as_str().unwrap(), "true");

    // Send offer request from testnode to bootnode
    let offer_request = JsonRpcRequest {
        method: "portal_historySendOffer".to_string(),
        id: 11,
        params: Params::Array(vec![
            Value::String(peertest.bootnode.enr.to_base64()),
            Value::Array(vec![json!(HISTORY_CONTENT_KEY)]),
        ]),
    };

    let accept = make_ipc_request(&peertest_config.target_ipc_path, &offer_request).unwrap();

    // Check that ACCEPT response sent by bootnode accepted the offered content
    validate_portal_offer(&accept, peertest);

    // Check if the stored content item in bootnode's DB matches the offered
    let local_content_request = JsonRpcRequest {
        method: "portal_historyLocalContent".to_string(),
        id: 16,
        params: Params::Array(vec![Value::String(HISTORY_CONTENT_KEY.to_string())]),
    };
    let mut received_content_value =
        make_ipc_request(&peertest.bootnode.web3_ipc_path, &local_content_request);
    while let Err(err) = received_content_value {
        error!("Retrying after 0.5sec, because content should have been present: {err}");
        thread::sleep(time::Duration::from_millis(500));
        received_content_value =
            make_ipc_request(&peertest.bootnode.web3_ipc_path, &local_content_request);
    }

    let received_content_value = match received_content_value {
        Ok(val) => val,
        Err(err) => {
            error!("Failed to find content that should be present: {err}");
            panic!("Could not get local content");
        }
    };

    let received_content_str = received_content_value.as_str().unwrap();
    assert_eq!(
        HISTORY_CONTENT_VALUE, received_content_str,
        "The received content {}, must match the expected {}",
        HISTORY_CONTENT_VALUE, received_content_str,
    );
}

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
