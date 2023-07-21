use ethportal_api::types::enr::Enr;
use ethportal_api::types::portal::ContentInfo;
use ethportal_api::utils::bytes::hex_encode;
use ethportal_api::{
    jsonrpsee::async_client::Client, HistoryContentKey, HistoryContentValue,
    HistoryNetworkApiClient,
};
use serde_json::json;
use std::str::FromStr;
use tracing::info;

use crate::Peertest;

pub async fn test_large(peertest: &Peertest, target: &Client) {
    info!("Test validating a pre-merge block body");
    println!("Test validating a pre-merge block body");
    let content_key = "0x00a468e1fc13aebc6b5e1be1db0d4e0de9ddf96b42accc69bcb726e98d4503e817";
    let block_body = std::fs::read("./test_assets/mainnet/block_body_17139055.bin").unwrap();
    println!("block_body.len(): {}", block_body.len());
    // store block body
    let block_body_content_key: HistoryContentKey =
        serde_json::from_value(json!(content_key)).unwrap();
    let block_body_content_value: HistoryContentValue =
        serde_json::from_value(json!(hex_encode(block_body))).unwrap();

    let store_result = peertest
        .bootnode
        .ipc_client
        .store(
            block_body_content_key.clone(),
            block_body_content_value.clone(),
        )
        .await
        .unwrap();

    assert!(store_result);
    println!("Xstore result: {:?}", store_result);

    // calling find_content since it only returns the found data if validation was successful
    let result = target
        .find_content(
            Enr::from_str(&peertest.bootnode.enr.to_base64()).unwrap(),
            block_body_content_key.clone(),
        )
        .await
        .unwrap();

    match result {
        ContentInfo::Content { content } => {
            assert_eq!(content, block_body_content_value);
            panic!("fuck");
        }
        _ => panic!("Content value's should match"),
    }
}
