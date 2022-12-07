use std::{thread, time};

use serde_json::{json, Value};
use tracing::{error, info};

use crate::{
    jsonrpc::{
        make_jsonrpc_request, validate_portal_offer, JsonRpcRequest, HISTORY_CONTENT_KEY,
        HISTORY_CONTENT_VALUE,
    },
    Peertest, PeertestConfig,
};
use trin_core::jsonrpc::types::Params;

pub async fn test_offer_accept(_peertest_config: PeertestConfig, peertest: &Peertest) {
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

    let store_result = make_jsonrpc_request(&peertest.nodes[0].transport, &store_request)
        .await
        .unwrap();
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

    let accept = make_jsonrpc_request(&peertest.nodes[0].transport, &offer_request)
        .await
        .unwrap();

    // Check that ACCEPT response sent by bootnode accepted the offered content
    validate_portal_offer(&accept, peertest);

    // Check if the stored content item in bootnode's DB matches the offered
    let local_content_request = JsonRpcRequest {
        method: "portal_historyLocalContent".to_string(),
        id: 16,
        params: Params::Array(vec![Value::String(HISTORY_CONTENT_KEY.to_string())]),
    };
    let mut received_content_value =
        make_jsonrpc_request(&peertest.bootnode.transport, &local_content_request).await;
    while let Err(err) = received_content_value {
        error!("Retrying after 0.5sec, because content should have been present: {err}");
        thread::sleep(time::Duration::from_millis(500));
        received_content_value =
            make_jsonrpc_request(&peertest.bootnode.transport, &local_content_request).await;
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
