use std::str::FromStr;

use serde_json::json;
use tracing::{error, info};

use ethportal_api::{
    jsonrpsee::async_client::Client, HistoryContentKey, HistoryContentValue,
    HistoryNetworkApiClient,
};
use trin_types::{content_value::PossibleHistoryContentValue, enr::Enr};

use crate::{
    jsonrpc::{validate_portal_offer, HISTORY_CONTENT_KEY, HISTORY_CONTENT_VALUE},
    Peertest, PeertestConfig,
};

pub async fn test_unpopulated_offer(peertest_config: PeertestConfig, peertest: &Peertest) {
    info!("Testing Unpopulated OFFER/ACCEPT flow");

    let ipc_client = reth_ipc::client::IpcClientBuilder::default()
        .build(&peertest_config.target_ipc_path)
        .await
        .unwrap();

    let content_key: HistoryContentKey =
        serde_json::from_value(json!(HISTORY_CONTENT_KEY)).unwrap();
    let content_value: HistoryContentValue =
        serde_json::from_value(json!(HISTORY_CONTENT_VALUE)).unwrap();

    // Store content to offer in the testnode db
    let store_result = ipc_client
        .store(content_key.clone(), content_value.clone())
        .await
        .unwrap();

    assert!(store_result);

    // Send unpopulated offer request from testnode to bootnode
    let result = ipc_client
        .offer(
            Enr::from_str(&peertest.bootnode.enr.to_base64()).unwrap(),
            content_key.clone(),
            None,
        )
        .await
        .unwrap();

    // Check that ACCEPT response sent by bootnode accepted the offered content
    validate_portal_offer(result, peertest);

    // Check if the stored content value in bootnode's DB matches the offered
    let response = wait_for_content(ipc_client, content_key).await;
    let received_content_value = match response {
        PossibleHistoryContentValue::ContentPresent(c) => c,
        PossibleHistoryContentValue::ContentAbsent => panic!("Expected content to be found"),
    };
    assert_eq!(
        content_value, received_content_value,
        "The received content {received_content_value:?}, must match the expected {content_value:?}",
    );
}

pub async fn test_populated_offer(peertest_config: PeertestConfig, peertest: &Peertest) {
    info!("Testing Populated Offer/ACCEPT flow");

    let ipc_client = reth_ipc::client::IpcClientBuilder::default()
        .build(&peertest_config.target_ipc_path)
        .await
        .unwrap();

    // Offer unique content key to bootnode
    let content_key: HistoryContentKey = serde_json::from_value(json!(
        "0x00cb5cab7266694daa0d28cbf40496c08dd30bf732c41e0455e7ad389c10d79f4f"
    ))
    .unwrap();
    let content_value: HistoryContentValue =
        serde_json::from_value(json!(HISTORY_CONTENT_VALUE)).unwrap();

    let result = ipc_client
        .offer(
            Enr::from_str(&peertest.bootnode.enr.to_base64()).unwrap(),
            content_key.clone(),
            Some(content_value.clone()),
        )
        .await
        .unwrap();

    // Check that ACCEPT response sent by bootnode accepted the offered content
    validate_portal_offer(result, peertest);

    // Check if the stored content value in bootnode's DB matches the offered
    let response = wait_for_content(ipc_client, content_key).await;
    let received_content_value = match response {
        PossibleHistoryContentValue::ContentPresent(c) => c,
        PossibleHistoryContentValue::ContentAbsent => panic!("Expected content to be found"),
    };
    assert_eq!(
        content_value, received_content_value,
        "The received content {received_content_value:?}, must match the expected {content_value:?}",
    );
}

/// Wait for the content to be transferred
async fn wait_for_content(
    ipc_client: Client,
    content_key: HistoryContentKey,
) -> PossibleHistoryContentValue {
    let mut received_content_value = ipc_client.local_content(content_key.clone()).await;

    let mut counter = 0;

    // If content is absent an error will be returned.
    while counter < 5 {
        let message = match received_content_value {
            x @ Ok(PossibleHistoryContentValue::ContentPresent(_)) => return x.unwrap(),
            Ok(PossibleHistoryContentValue::ContentAbsent) => {
                "absent content response received".to_string()
            }
            Err(e) => format!("received an error {e}"),
        };
        error!("Retrying after 0.5s, because {message}");
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        received_content_value = ipc_client.local_content(content_key.clone()).await;
        counter += 1;
    }

    received_content_value.unwrap()
}
