use std::{thread, time};

use serde_json::Value;
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
    assert!(store_result.as_bool().unwrap());

    // Send offer request from testnode to bootnode
    let offer_request = JsonRpcRequest {
        method: "portal_historyOffer".to_string(),
        id: 11,
        params: Params::Array(vec![
            Value::String(peertest.bootnode.enr.to_base64()),
            Value::String(HISTORY_CONTENT_KEY.to_string()),
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
        make_ipc_request(&peertest.bootnode.web3_ipc_path, &local_content_request)
            .expect("Could not get local content");

    let mut counter = 0;
    while received_content_value == Value::String("0x0".to_owned()) && counter < 5 {
        error!("Retrying after 1s, because content should have been present");
        thread::sleep(time::Duration::from_millis(1000));
        received_content_value =
            make_ipc_request(&peertest.bootnode.web3_ipc_path, &local_content_request).unwrap();
        counter += 1;
    }

    let received_content_str = received_content_value.as_str().unwrap();
    assert_eq!(
        HISTORY_CONTENT_VALUE, received_content_str,
        "The received content {received_content_str}, must match the expected {HISTORY_CONTENT_VALUE}",
    );
}
