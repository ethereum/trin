use std::str::FromStr;

use tracing::info;

use crate::{utils::wait_for_content, Peertest};
use ethportal_api::types::{content_value::PossibleHistoryContentValue, enr::Enr};
use ethportal_api::utils::bytes::hex_encode;
use ethportal_api::{
    jsonrpsee::async_client::Client, HistoryContentKey, HistoryContentValue,
    HistoryNetworkApiClient,
};

pub async fn test_unpopulated_offer(
    peertest: &Peertest,
    target: &Client,
    test_content: (HistoryContentKey, HistoryContentValue),
) {
    info!("Testing Unpopulated OFFER/ACCEPT flow");

    let (content_key, content_value) = test_content;
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

pub async fn test_populated_offer(
    peertest: &Peertest,
    target: &Client,
    test_content: (HistoryContentKey, HistoryContentValue),
) {
    info!("Testing Populated Offer/ACCEPT flow");

    let (content_key, content_value) = test_content;
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
