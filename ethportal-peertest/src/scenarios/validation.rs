use ethportal_api::types::enr::Enr;
use ethportal_api::types::portal::ContentInfo;
use ethportal_api::{
    jsonrpsee::async_client::Client, HistoryContentKey, HistoryContentValue,
    HistoryNetworkApiClient,
};
use serde_json::json;
use std::str::FromStr;
use tracing::info;

use crate::{
    constants::{
        BLOCK_BODY_CONTENT_KEY, BLOCK_BODY_CONTENT_VALUE, HEADER_WITH_PROOF_CONTENT_KEY,
        HEADER_WITH_PROOF_CONTENT_VALUE, RECEIPTS_CONTENT_KEY, RECEIPTS_CONTENT_VALUE,
    },
    Peertest,
};

pub async fn test_validate_pre_merge_header_with_proof(peertest: &Peertest, target: &Client) {
    info!("Test validating a pre-merge header-with-proof");

    // store header_with_proof
    let header_with_proof_content_key: HistoryContentKey =
        serde_json::from_value(json!(HEADER_WITH_PROOF_CONTENT_KEY)).unwrap();
    let header_with_proof_content_value: HistoryContentValue =
        serde_json::from_value(json!(HEADER_WITH_PROOF_CONTENT_VALUE)).unwrap();

    let store_result = peertest
        .bootnode
        .ipc_client
        .store(
            header_with_proof_content_key.clone(),
            header_with_proof_content_value.clone(),
        )
        .await
        .unwrap();

    assert!(store_result);

    // calling find_content since it only returns the found data if validation was successful
    let result = target
        .find_content(
            Enr::from_str(&peertest.bootnode.enr.to_base64()).unwrap(),
            header_with_proof_content_key.clone(),
        )
        .await
        .unwrap();

    match result {
        ContentInfo::Content { content } => assert_eq!(content, header_with_proof_content_value),
        _ => panic!("Content value's should match"),
    }
}

pub async fn test_validate_pre_merge_block_body(peertest: &Peertest, target: &Client) {
    info!("Test validating a pre-merge block body");
    // store block body
    //let block_body_content_key: HistoryContentKey =
    //serde_json::from_value(json!(BLOCK_BODY_CONTENT_KEY)).unwrap();
    let content_key: HistoryContentKey = serde_json::from_value(json!(
        "0x01a468e1fc13aebc6b5e1be1db0d4e0de9ddf96b42accc69bcb726e98d4503e817"
    ))
    .unwrap();
    let block_body_content_value: HistoryContentValue =
        serde_json::from_value(json!(BLOCK_BODY_CONTENT_VALUE)).unwrap();

    let store_result = peertest
        .bootnode
        .ipc_client
        .store(content_key.clone(), block_body_content_value.clone())
        .await
        .unwrap();

    assert!(store_result);

    // calling find_content since it only returns the found data if validation was successful
    let result = target
        .find_content(
            Enr::from_str(&peertest.bootnode.enr.to_base64()).unwrap(),
            content_key.clone(),
        )
        .await
        .unwrap();

    match result {
        ContentInfo::Content { content } => {
            assert_eq!(content, block_body_content_value);
        }
        _ => panic!("Content values should match"),
    }
}

pub async fn test_validate_pre_merge_receipts(peertest: &Peertest, target: &Client) {
    info!("Test validating pre-merge receipts");
    // store receipts
    let receipts_content_key: HistoryContentKey =
        serde_json::from_value(json!(RECEIPTS_CONTENT_KEY)).unwrap();
    let receipts_content_value: HistoryContentValue =
        serde_json::from_value(json!(RECEIPTS_CONTENT_VALUE)).unwrap();

    let store_result = peertest
        .bootnode
        .ipc_client
        .store(receipts_content_key.clone(), receipts_content_value.clone())
        .await
        .unwrap();

    assert!(store_result);

    // calling find_content since it only returns the found data if validation was successful
    let result = target
        .find_content(
            Enr::from_str(&peertest.bootnode.enr.to_base64()).unwrap(),
            receipts_content_key.clone(),
        )
        .await
        .unwrap();

    match result {
        ContentInfo::Content { content } => assert_eq!(content, receipts_content_value),
        _ => panic!("Content value's should match"),
    }
}
