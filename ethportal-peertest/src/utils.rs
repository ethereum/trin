use tracing::error;

use ethportal_api::types::content_value::PossibleHistoryContentValue;
use ethportal_api::{HistoryContentKey, HistoryContentValue, HistoryNetworkApiClient};
use serde::Deserialize;

/// Wait for the content to be transferred
pub async fn wait_for_content<P: HistoryNetworkApiClient + std::marker::Sync>(
    ipc_client: &P,
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

#[derive(Debug, Deserialize)]
pub struct TypeData {
    pub key: HistoryContentKey,
    pub value: HistoryContentValue,
}

#[derive(Debug, Deserialize)]
pub struct BlockData {
    pub header_with_proof: TypeData,
    pub block_body: TypeData,
    pub receipts: TypeData,
}

#[derive(Debug)]
pub struct TestData {
    pub header_with_proof: (HistoryContentKey, HistoryContentValue),
    pub block_body: (HistoryContentKey, HistoryContentValue),
    pub receipts: (HistoryContentKey, HistoryContentValue),
}

pub struct AllTestData {
    pub small: Vec<TestData>,
    pub large: Vec<TestData>,
}

pub fn generate_test_content() -> AllTestData {
    let raw = std::fs::read_to_string("./test_assets/mainnet/1_10.json").unwrap();
    let result: Vec<BlockData> = serde_json::from_str(&raw).unwrap();
    let large_raw = std::fs::read_to_string("./test_assets/mainnet/large.json").unwrap();
    let large_result: Vec<BlockData> = serde_json::from_str(&large_raw).unwrap();
    let small_result: Vec<TestData> = result
        .into_iter()
        .map(|x| TestData {
            header_with_proof: (x.header_with_proof.key, x.header_with_proof.value),
            block_body: (x.block_body.key, x.block_body.value),
            receipts: (x.receipts.key, x.receipts.value),
        })
        .collect();
    let large_result: Vec<TestData> = large_result
        .into_iter()
        .map(|x| TestData {
            header_with_proof: (x.header_with_proof.key, x.header_with_proof.value),
            block_body: (x.block_body.key, x.block_body.value),
            receipts: (x.receipts.key, x.receipts.value),
        })
        .collect();
    AllTestData {
        small: small_result,
        large: large_result,
    }
}
