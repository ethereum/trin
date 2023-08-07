use ethportal_api::types::enr::Enr;
use ethportal_api::types::portal::ContentInfo;
use ethportal_api::{
    jsonrpsee::async_client::Client, HistoryContentKey, HistoryContentValue,
    HistoryNetworkApiClient, PossibleHistoryContentValue,
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
        serde_json::from_value(json!(HEADER_WITH_PROOF_CONTENT_KEY)).expect("conversion failed");
    let header_with_proof_content_value: HistoryContentValue =
        serde_json::from_value(json!(HEADER_WITH_PROOF_CONTENT_VALUE)).expect("conversion failed");

    let store_result = peertest
        .bootnode
        .ipc_client
        .store(
            header_with_proof_content_key.clone(),
            header_with_proof_content_value.clone(),
        )
        .await
        .expect("operation failed");

    assert!(store_result);

    // calling find_content since it only returns the found data if validation was successful
    let result = target
        .find_content(
            Enr::from_str(&peertest.bootnode.enr.to_base64()).expect("conversion failed"),
            header_with_proof_content_key.clone(),
        )
        .await
        .expect("operation failed");

    match result {
        ContentInfo::Content {
            content,
            utp_transfer,
        } => {
            assert_eq!(
                content,
                PossibleHistoryContentValue::ContentPresent(header_with_proof_content_value)
            );
            assert!(!utp_transfer);
        }
        _ => panic!("Content values should match"),
    }
}

pub async fn test_validate_pre_merge_block_body(peertest: &Peertest, target: &Client) {
    info!("Test validating a pre-merge block body");
    // store header_with_proof to validate block body
    let header_with_proof_content_key: HistoryContentKey =
        serde_json::from_value(json!(HEADER_WITH_PROOF_CONTENT_KEY)).expect("conversion failed");
    let header_with_proof_content_value: HistoryContentValue =
        serde_json::from_value(json!(HEADER_WITH_PROOF_CONTENT_VALUE)).expect("conversion failed");

    let store_result = target
        .store(
            header_with_proof_content_key.clone(),
            header_with_proof_content_value.clone(),
        )
        .await
        .expect("operation failed");

    assert!(store_result);

    // store block body
    let block_body_content_key: HistoryContentKey =
        serde_json::from_value(json!(BLOCK_BODY_CONTENT_KEY)).expect("conversion failed");
    let block_body_content_value: HistoryContentValue =
        serde_json::from_value(json!(BLOCK_BODY_CONTENT_VALUE)).expect("conversion failed");

    let store_result = peertest
        .bootnode
        .ipc_client
        .store(
            block_body_content_key.clone(),
            block_body_content_value.clone(),
        )
        .await
        .expect("operation failed");

    assert!(store_result);

    // calling find_content since it only returns the found data if validation was successful
    let result = target
        .find_content(
            Enr::from_str(&peertest.bootnode.enr.to_base64()).expect("conversin failed"),
            block_body_content_key.clone(),
        )
        .await
        .expect("operation failed");

    match result {
        ContentInfo::Content {
            content,
            utp_transfer,
        } => {
            assert_eq!(
                content,
                PossibleHistoryContentValue::ContentPresent(block_body_content_value)
            );
            assert!(utp_transfer);
        }
        _ => panic!("Content values should match"),
    }
}

pub async fn test_validate_pre_merge_receipts(peertest: &Peertest, target: &Client) {
    info!("Test validating pre-merge receipts");
    // store receipts
    let receipts_content_key: HistoryContentKey =
        serde_json::from_value(json!(RECEIPTS_CONTENT_KEY)).expect("operatioin failed");
    let receipts_content_value: HistoryContentValue =
        serde_json::from_value(json!(RECEIPTS_CONTENT_VALUE)).expect("operatioin failed");

    let store_result = peertest
        .bootnode
        .ipc_client
        .store(receipts_content_key.clone(), receipts_content_value.clone())
        .await
        .expect("operation failed");

    assert!(store_result);

    // calling find_content since it only returns the found data if validation was successful
    let result = target
        .find_content(
            Enr::from_str(&peertest.bootnode.enr.to_base64()).expect("conversion failed"),
            receipts_content_key.clone(),
        )
        .await
        .expect("operation failed");

    match result {
        ContentInfo::Content {
            content,
            utp_transfer,
        } => {
            assert_eq!(
                content,
                PossibleHistoryContentValue::ContentPresent(receipts_content_value)
            );
            assert!(utp_transfer);
        }
        _ => panic!("Content values should match"),
    }
}
