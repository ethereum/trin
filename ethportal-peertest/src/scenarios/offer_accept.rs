use std::str::FromStr;
use std::time::Duration;

use tracing::info;

use crate::constants::fixture_receipts;
use crate::{constants::fixture_header_with_proof, utils::wait_for_history_content, Peertest};
use ethportal_api::{
    jsonrpsee::async_client::Client, types::enr::Enr, utils::bytes::hex_encode,
    HistoryNetworkApiClient, PossibleHistoryContentValue,
};

pub async fn test_unpopulated_offer(peertest: &Peertest, target: &Client) {
    info!("Testing Unpopulated OFFER/ACCEPT flow");

    let (content_key, content_value) = fixture_header_with_proof();
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
    let response = wait_for_history_content(target, content_key).await;
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

    let (content_key, content_value) = fixture_header_with_proof();
    let result = target
        .offer(
            Enr::from_str(&peertest.bootnode.enr.to_base64()).unwrap(),
            content_key.clone(),
            Some(content_value.clone()),
        )
        .await
        .unwrap();

    // sleep one second for no reason
    tokio::time::sleep(Duration::from_secs(1)).await;
    // count_times_accepted would be how many uTP transfers were initiated
    let mut count_times_accepted = 0;
    for i in 1..=10 {
        let (target_key, target_value) = fixture_receipts();
        let accept_result = target
            .offer(
                Enr::from_str(&peertest.bootnode.enr.to_base64()).unwrap(),
                target_key,
                Some(target_value),
            )
            .await
            .unwrap();
        if hex_encode(accept_result.content_keys.into_bytes()) == "0x03" {
            count_times_accepted += 1;
        }
    }

    tracing::warn!("big man {count_times_accepted}")
}
