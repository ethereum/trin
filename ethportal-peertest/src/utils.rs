use std::fs;

use alloy_primitives::B256;
use futures::{Future, TryFutureExt};
use tracing::error;

use anyhow::Result;
use serde_yaml::Value;
use ureq::serde::Deserialize;

use ethportal_api::{
    BeaconContentKey, BeaconContentValue, BeaconNetworkApiClient, HistoryContentKey,
    HistoryContentValue, HistoryNetworkApiClient, StateContentKey, StateContentValue,
    StateNetworkApiClient,
};

pub async fn wait_for_successful_result<Fut, O>(f: impl Fn() -> Fut) -> O
where
    Fut: Future<Output = Result<O>>,
{
    // If content is absent an error will be returned.
    for counter in 0..60 {
        let result = f().await;
        match result {
            Ok(val) => return val,
            Err(e) => {
                if counter > 0 {
                    error!("Retry attempt #{counter} after 0.5s, because we received an error {e}")
                }
            }
        };
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }

    panic!("Retried too many times");
}

/// Wait for the history content to be transferred
pub async fn wait_for_history_content<P: HistoryNetworkApiClient + std::marker::Sync>(
    ipc_client: &P,
    content_key: HistoryContentKey,
) -> HistoryContentValue {
    wait_for_successful_result(|| {
        ipc_client
            .local_content(content_key.clone())
            .map_err(anyhow::Error::from)
    })
    .await
}

/// Wait for the beacon content to be transferred
pub async fn wait_for_beacon_content<P: BeaconNetworkApiClient + std::marker::Sync>(
    ipc_client: &P,
    content_key: BeaconContentKey,
) -> BeaconContentValue {
    wait_for_successful_result(|| {
        ipc_client
            .local_content(content_key.clone())
            .map_err(anyhow::Error::from)
    })
    .await
}

/// Wait for the state content to be transferred
pub async fn wait_for_state_content<P: StateNetworkApiClient + std::marker::Sync>(
    ipc_client: &P,
    content_key: StateContentKey,
) -> StateContentValue {
    wait_for_successful_result(|| {
        ipc_client
            .local_content(content_key.clone())
            .map_err(anyhow::Error::from)
    })
    .await
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

#[derive(Debug, Clone, Deserialize)]
pub struct StateContentData {
    #[serde(rename = "content_key")]
    pub key: StateContentKey,
    #[serde(rename = "content_value_offer")]
    pub offer_value: StateContentValue,
    #[serde(rename = "content_value_retrieval")]
    pub lookup_value: StateContentValue,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StateFixture {
    pub state_root: B256,
    #[serde(flatten)]
    pub content_data: StateContentData,
    pub recursive_gossip: Option<StateContentData>,
}

fn read_state_fixture_from_file(file_name: &str) -> Result<Vec<StateFixture>> {
    let yaml_content = fs::read_to_string(file_name)?;
    let value: Value = serde_yaml::from_str(&yaml_content)?;

    let result = Vec::<StateFixture>::deserialize(value)?;
    Ok(result)
}

fn read_state_fixture(file_name: &str) -> Vec<StateFixture> {
    read_state_fixture_from_file(file_name)
        .unwrap_or_else(|err| panic!("Error reading fixture: {err}"))
}

pub fn fixtures_state_account_trie_node() -> Vec<StateFixture> {
    read_state_fixture("portal-spec-tests/tests/mainnet/state/validation/account_trie_node.yaml")
}

pub fn fixtures_state_contract_storage_trie_node() -> Vec<StateFixture> {
    read_state_fixture(
        "portal-spec-tests/tests/mainnet/state/validation/contract_storage_trie_node.yaml",
    )
}

pub fn fixtures_state_contract_bytecode() -> Vec<StateFixture> {
    read_state_fixture("portal-spec-tests/tests/mainnet/state/validation/contract_bytecode.yaml")
}

pub struct StateRecursiveGossipFixture {
    pub state_root: B256,
    pub key_value_pairs: Vec<(StateContentKey, StateContentValue)>,
}

pub fn fixtures_state_recursive_gossip() -> Result<Vec<StateRecursiveGossipFixture>> {
    let yaml_content = fs::read_to_string(
        "portal-spec-tests/tests/mainnet/state/validation/recursive_gossip.yaml",
    )?;
    let value: Value = serde_yaml::from_str(&yaml_content)?;

    let mut result = vec![];

    for fixture in value.as_sequence().unwrap() {
        result.push(StateRecursiveGossipFixture {
            state_root: B256::deserialize(&fixture["state_root"])?,
            key_value_pairs: fixture["recursive_gossip"]
                .as_sequence()
                .unwrap()
                .iter()
                .map(|key_value_container| {
                    let key =
                        StateContentKey::deserialize(&key_value_container["content_key"]).unwrap();
                    let value =
                        StateContentValue::deserialize(&key_value_container["content_value"])
                            .unwrap();
                    (key, value)
                })
                .collect(),
        })
    }

    Ok(result)
}
