use std::str::FromStr;

use serde_json::json;
use tracing::info;

use ethportal_api::types::enr::Enr;
use ethportal_api::utils::bytes::hex_encode;
use ethportal_api::{
    jsonrpsee::async_client::Client, HistoryContentKey, HistoryContentValue,
    HistoryNetworkApiClient, PossibleHistoryContentValue,
};

use crate::{
    constants::{HISTORY_CONTENT_KEY, HISTORY_CONTENT_VALUE},
    utils::wait_for_content,
    Peertest,
};

pub async fn test_unpopulated_offer(peertest: &Peertest, target: &Client) {
    info!("Testing Unpopulated OFFER/ACCEPT flow");

    let content_key: HistoryContentKey =
        serde_json::from_value(json!(HISTORY_CONTENT_KEY)).unwrap();
    let content_value: HistoryContentValue =
        serde_json::from_value(json!(HISTORY_CONTENT_VALUE)).unwrap();

    // Store content to offer in the testnode db
    let store_result = target
        .store(content_key.clone(), content_value.clone())
        .await
        .unwrap();

    assert!(store_result);

    // Send unpopulated offer request from testnode to bootnode
    let result = target
        .offer(
            Enr::from_str(&peertest.bootnode.enr.to_base64()).unwrap(),
            content_key.clone(),
            None,
        )
        .await
        .unwrap();

    // Check that ACCEPT response sent by bootnode accepted the offered content
    assert_eq!(hex_encode(result.content_keys.into_bytes()), "0x03");

    // Check if the stored content value in bootnode's DB matches the offered
    let response = wait_for_content(target, content_key).await;
    let received_content_value = match response {
        PossibleHistoryContentValue::ContentPresent(c) => c,
        PossibleHistoryContentValue::ContentAbsent => panic!("Expected content to be found"),
    };
    assert_eq!(
        content_value, received_content_value,
        "The received content {received_content_value:?}, must match the expected {content_value:?}",
    );
}

pub async fn test_populated_offer(peertest: &Peertest, target: &Client) {
    info!("Testing Populated Offer/ACCEPT flow");

    // Offer unique content key to bootnode
    let content_key: HistoryContentKey = serde_json::from_value(json!(
        "0x00cb5cab7266694daa0d28cbf40496c08dd30bf732c41e0455e7ad389c10d79f4f"
    ))
    .unwrap();
    let content_value: HistoryContentValue =
        serde_json::from_value(json!(HISTORY_CONTENT_VALUE)).unwrap();

    let result = target
        .offer(
            Enr::from_str(&peertest.bootnode.enr.to_base64()).unwrap(),
            content_key.clone(),
            Some(content_value.clone()),
        )
        .await
        .unwrap();

    // Check that ACCEPT response sent by bootnode accepted the offered content
    assert_eq!(hex_encode(result.content_keys.into_bytes()), "0x03");

    // Check if the stored content value in bootnode's DB matches the offered
    let response = wait_for_content(&peertest.bootnode.ipc_client, content_key).await;
    let received_content_value = match response {
        PossibleHistoryContentValue::ContentPresent(c) => c,
        PossibleHistoryContentValue::ContentAbsent => panic!("Expected content to be found"),
    };
    assert_eq!(
        content_value, received_content_value,
        "The received content {received_content_value:?}, must match the expected {content_value:?}",
    );
}
