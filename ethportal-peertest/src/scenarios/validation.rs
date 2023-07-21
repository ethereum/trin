use ethportal_api::types::enr::Enr;
use ethportal_api::types::portal::ContentInfo;
use ethportal_api::{
    jsonrpsee::async_client::Client, HistoryContentKey, HistoryContentValue,
    HistoryNetworkApiClient,
};
use std::str::FromStr;
use tracing::info;

use crate::Peertest;

pub async fn test_validate_pre_merge_header_with_proof(
    peertest: &Peertest,
    target: &Client,
    test_content: (HistoryContentKey, HistoryContentValue),
) {
    info!("Test validating a pre-merge header-with-proof");

    // store header_with_proof
    let (content_key, content_value) = test_content;

    let store_result = peertest
        .bootnode
        .ipc_client
        .store(content_key.clone(), content_value.clone())
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
        ContentInfo::Content { content } => assert_eq!(content, content_value),
        _ => panic!("Content value's should match"),
    }
}

pub async fn test_validate_pre_merge_block_body(
    peertest: &Peertest,
    target: &Client,
    test_content: (HistoryContentKey, HistoryContentValue),
) {
    info!("Test validating a pre-merge block body");
    // store block body
    let (content_key, content_value) = test_content;

    let store_result = peertest
        .bootnode
        .ipc_client
        .store(content_key.clone(), content_value.clone())
        .await
        .unwrap();

    assert!(store_result);
    use ethportal_api::ContentValue;
    println!("XXX: length: {}", content_value.encode().len());

    // calling find_content since it only returns the found data if validation was successful
    let result = target
        .find_content(
            Enr::from_str(&peertest.bootnode.enr.to_base64()).unwrap(),
            content_key.clone(),
        )
        .await
        .unwrap();

    println!("XXX: {:?}", result);
    match result {
        ContentInfo::Content { content } => assert_eq!(content, content_value),
        _ => panic!("Content values should match"),
    }
}

pub async fn test_validate_pre_merge_receipts(
    peertest: &Peertest,
    target: &Client,
    test_content: (HistoryContentKey, HistoryContentValue),
) {
    info!("Test validating pre-merge receipts");
    // store receipts
    let (content_key, content_value) = test_content;

    let store_result = peertest
        .bootnode
        .ipc_client
        .store(content_key.clone(), content_value.clone())
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
        ContentInfo::Content { content } => assert_eq!(content, content_value),
        _ => panic!("Content values should match"),
    }
}
