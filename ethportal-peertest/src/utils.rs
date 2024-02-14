use tracing::error;

use anyhow::Result;
use serde_yaml::Value;
use std::fs;

use ethportal_api::{
    BeaconContentKey, BeaconContentValue, BeaconNetworkApiClient, HistoryContentKey,
    HistoryContentValue, HistoryNetworkApiClient,
};

/// Wait for the history content to be transferred
pub async fn wait_for_history_content<P: HistoryNetworkApiClient + std::marker::Sync>(
    ipc_client: &P,
    content_key: HistoryContentKey,
) -> HistoryContentValue {
    let mut received_content_value = ipc_client.local_content(content_key.clone()).await;

    let mut counter = 0;

    // If content is absent an error will be returned.
    while counter < 5 {
        let message = match received_content_value {
            Ok(val) => return val,
            Err(e) => format!("received an error {e}"),
        };
        error!("Retrying after 0.5s, because {message}");
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        received_content_value = ipc_client.local_content(content_key.clone()).await;
        counter += 1;
    }

    received_content_value.unwrap()
}

/// Wait for the beacon content to be transferred
pub async fn wait_for_beacon_content<P: BeaconNetworkApiClient + std::marker::Sync>(
    ipc_client: &P,
    content_key: BeaconContentKey,
) -> BeaconContentValue {
    let mut received_content_value = ipc_client.local_content(content_key.clone()).await;

    let mut counter = 0;

    // If content is absent an error will be returned.
    while counter < 60 {
        let message = match received_content_value {
            Ok(val) => return val,
            Err(e) => format!("received an error {e}"),
        };
        counter += 1;
        error!("Retry attempt #{counter} in 0.5s to find beacon content, because {message}");
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        received_content_value = ipc_client.local_content(content_key.clone()).await;
    }

    received_content_value.unwrap()
}

fn read_history_content_key_value(
    file_name: &str,
) -> Result<(HistoryContentKey, HistoryContentValue)> {
    let yaml_content = fs::read_to_string(file_name)?;

    let value: Value = serde_yaml::from_str(&yaml_content)?;

    let content_key: HistoryContentKey =
        serde_yaml::from_value(value.get("content_key").unwrap().clone())?;
    let content_value: HistoryContentValue =
        serde_yaml::from_value(value.get("content_value").unwrap().clone())?;

    Ok((content_key, content_value))
}

/// Wrapper function for fixtures that directly returns the tuple.
fn read_fixture(file_name: &str) -> (HistoryContentKey, HistoryContentValue) {
    read_history_content_key_value(file_name)
        .unwrap_or_else(|err| panic!("Error reading fixture: {err}"))
}

/// History HeaderWithProof content key & value
/// Block #1000010
pub fn fixture_header_with_proof_1000010() -> (HistoryContentKey, HistoryContentValue) {
    read_fixture("portal-spec-tests/tests/mainnet/history/headers_with_proof/1000010.yaml")
}

/// History HeaderWithProof content key & value
/// Block #14764013 (pre-merge)
pub fn fixture_header_with_proof() -> (HistoryContentKey, HistoryContentValue) {
    read_fixture("portal-spec-tests/tests/mainnet/history/headers_with_proof/14764013.yaml")
}

/// History BlockBody content key & value
/// Block #14764013 (pre-merge)
pub fn fixture_block_body() -> (HistoryContentKey, HistoryContentValue) {
    read_fixture("portal-spec-tests/tests/mainnet/history/bodies/14764013.yaml")
}

/// History Receipts content key & value
/// Block #14764013 (pre-merge)
pub fn fixture_receipts() -> (HistoryContentKey, HistoryContentValue) {
    read_fixture("portal-spec-tests/tests/mainnet/history/receipts/14764013.yaml")
}
