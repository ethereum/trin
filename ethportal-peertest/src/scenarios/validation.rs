use crate::{
    utils::{
        fixture_block_body, fixture_header_by_hash, fixture_header_by_number, fixture_receipts,
    },
    Peertest,
};
use alloy_primitives::B256;
use ethportal_api::{
    jsonrpsee::async_client::Client,
    types::{enr::Enr, portal::ContentInfo},
    ContentValue, HistoryContentKey, HistoryNetworkApiClient,
};
use std::str::FromStr;
use tracing::info;

pub async fn test_validate_pre_merge_header_by_hash(peertest: &Peertest, target: &Client) {
    info!("Test validating a pre-merge header by block hash");

    // store header_by_hash
    let (content_key, content_value) = fixture_header_by_hash();

    let store_result = peertest
        .bootnode
        .ipc_client
        .store(content_key.clone(), content_value.encode())
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
        ContentInfo::Content {
            content,
            utp_transfer,
        } => {
            assert_eq!(content, content_value.encode());
            assert!(!utp_transfer);
        }
        _ => panic!("Content values should match"),
    }
}

pub async fn test_validate_pre_merge_header_by_number(peertest: &Peertest, target: &Client) {
    info!("Test validating a pre-merge header by block number");

    // store header_by_number
    let (content_key, content_value) = fixture_header_by_number();

    let store_result = peertest
        .bootnode
        .ipc_client
        .store(content_key.clone(), content_value.encode())
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
        ContentInfo::Content {
            content,
            utp_transfer,
        } => {
            assert_eq!(content, content_value.encode());
            assert!(!utp_transfer);
        }
        _ => panic!("Content values should match"),
    }
}

pub async fn test_invalidate_header_by_hash(peertest: &Peertest, target: &Client) {
    info!("Test invalidating a pre-merge header-with-proof by header hash");

    // store header_with_proof - doesn't perform validation
    let (_, content_value) = fixture_header_by_hash();
    let invalid_content_key = HistoryContentKey::new_block_header_by_hash(B256::random());

    let store_result = peertest
        .bootnode
        .ipc_client
        .store(invalid_content_key.clone(), content_value.encode())
        .await
        .unwrap();
    assert!(store_result);

    // calling find_content since it only returns the found data if validation was successful
    if let Err(msg) = target
        .find_content(
            Enr::from_str(&peertest.bootnode.enr.to_base64()).unwrap(),
            invalid_content_key.clone(),
        )
        .await
    {
        assert!(msg.to_string().contains("Invalid header hash"));
    } else {
        panic!("Content should be invalid");
    }
}

pub async fn test_validate_pre_merge_block_body(peertest: &Peertest, target: &Client) {
    info!("Test validating a pre-merge block body");
    // store header_with_proof to validate block body
    let (content_key, content_value) = fixture_header_by_hash();
    let store_result = target
        .store(content_key, content_value.encode())
        .await
        .unwrap();
    assert!(store_result);

    // store block body
    let (content_key, content_value) = fixture_block_body();

    let store_result = peertest
        .bootnode
        .ipc_client
        .store(content_key.clone(), content_value.encode())
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
        ContentInfo::Content {
            content,
            utp_transfer,
        } => {
            assert_eq!(content, content_value.encode());
            assert!(utp_transfer);
        }
        _ => panic!("Content values should match"),
    }
}

pub async fn test_validate_pre_merge_receipts(peertest: &Peertest, target: &Client) {
    info!("Test validating pre-merge receipts");
    // store header_with_proof to validate block body
    let (content_key, content_value) = fixture_header_by_hash();
    let store_result = target
        .store(content_key, content_value.encode())
        .await
        .unwrap();
    assert!(store_result);

    // store receipts
    let (content_key, content_value) = fixture_receipts();

    let store_result = peertest
        .bootnode
        .ipc_client
        .store(content_key.clone(), content_value.encode())
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
        ContentInfo::Content {
            content,
            utp_transfer,
        } => {
            assert_eq!(content, content_value.encode());
            assert!(utp_transfer);
        }
        _ => panic!("Content values should match"),
    }
}
