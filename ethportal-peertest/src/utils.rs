use std::fs;

use alloy_primitives::Bytes;
use alloy_rlp::Decodable;
use futures::{Future, TryFutureExt};
use serde::Deserializer;
use tracing::error;

use anyhow::Result;
use serde_yaml::Value;
use ureq::serde::Deserialize;

use ethportal_api::{
    BeaconContentKey, BeaconContentValue, BeaconNetworkApiClient, ContentValue, Header,
    HistoryContentKey, HistoryContentValue, HistoryNetworkApiClient, RawContentValue,
    StateContentKey, StateContentValue, StateNetworkApiClient,
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
        let content_key = content_key.clone();
        ipc_client
            .local_content(content_key.clone())
            .map_err(anyhow::Error::from)
            .and_then(|content| async move {
                HistoryContentValue::decode(&content_key, &content).map_err(anyhow::Error::from)
            })
    })
    .await
}

/// Wait for the beacon content to be transferred
pub async fn wait_for_beacon_content<P: BeaconNetworkApiClient + std::marker::Sync>(
    ipc_client: &P,
    content_key: BeaconContentKey,
) -> BeaconContentValue {
    wait_for_successful_result(|| {
        let content_key = content_key.clone();
        ipc_client
            .local_content(content_key.clone())
            .map_err(anyhow::Error::from)
            .and_then(|content| async move {
                BeaconContentValue::decode(&content_key, &content).map_err(anyhow::Error::from)
            })
    })
    .await
}

/// Wait for the state content to be transferred
pub async fn wait_for_state_content<P: StateNetworkApiClient + std::marker::Sync>(
    ipc_client: &P,
    content_key: StateContentKey,
) -> StateContentValue {
    wait_for_successful_result(|| {
        let content_key = content_key.clone();
        ipc_client
            .local_content(content_key.clone())
            .map_err(anyhow::Error::from)
            .and_then(|content| async move {
                StateContentValue::decode(&content_key, &content).map_err(anyhow::Error::from)
            })
    })
    .await
}

fn read_history_content_key_value(
    file_name: &str,
) -> Result<(HistoryContentKey, HistoryContentValue)> {
    let yaml_content = fs::read_to_string(file_name)?;

    let value: Value = serde_yaml::from_str(&yaml_content)?;

    let content_key = HistoryContentKey::deserialize(&value["content_key"])?;
    let content_value = RawContentValue::deserialize(&value["content_value"])?;
    let content_value = HistoryContentValue::decode(&content_key, &content_value)?;

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

/// Epoch Accumulator #1659
/// Content Key: 0x030013c08b64bf7e3afab80ad4f8ea9423f1a7d8b31a149fc3b832d7980719c60c
/// Content ID: 0x61f6fd26ed4fb88cfae02ad691e4f41e0053e0305cb62f7cdfde5a7967ffbe65
pub fn fixture_epoch_acc_1() -> (HistoryContentKey, HistoryContentValue) {
    read_epoch_acc("0013c08b64bf7e3afab80ad4f8ea9423f1a7d8b31a149fc3b832d7980719c60c")
}

/// Epoch Accumulator #434
/// Content Key: 0x03ed8823c84177d8ffabf104566f313a2b2a43d05304ba6c74c2f5555bae0ef329
/// Content ID: 0x29e3c0966a85ee262ef4afeccd89721fda0962ae563a3818e81798fe28bdb37e
pub fn fixture_epoch_acc_2() -> (HistoryContentKey, HistoryContentValue) {
    read_epoch_acc("ed8823c84177d8ffabf104566f313a2b2a43d05304ba6c74c2f5555bae0ef329")
}

fn read_epoch_acc(hash: &str) -> (HistoryContentKey, HistoryContentValue) {
    let epoch_acc = std::fs::read(format!("test_assets/mainnet/0x03{hash}.portalcontent")).unwrap();
    let epoch_acc_hash = ethportal_api::utils::bytes::hex_decode(&format!("0x{hash}")).unwrap();
    let content_key =
        ethportal_api::HistoryContentKey::EpochAccumulator(ethportal_api::EpochAccumulatorKey {
            epoch_hash: alloy_primitives::B256::from_slice(&epoch_acc_hash),
        });
    let content_value =
        ethportal_api::HistoryContentValue::decode(&content_key, &epoch_acc).unwrap();
    (content_key, content_value)
}

#[derive(Debug, Clone, Deserialize)]
pub struct StateFixture {
    #[serde(deserialize_with = "de_header")]
    pub block_header: Header,
    #[serde(rename = "content_key")]
    pub key: StateContentKey,
    #[serde(rename = "content_value_offer")]
    pub offer_value: RawContentValue,
    #[serde(rename = "content_value_retrieval")]
    pub lookup_value: RawContentValue,
}

fn de_header<'de, D>(deserializer: D) -> Result<Header, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes = Bytes::deserialize(deserializer)?;
    Header::decode(&mut bytes.as_ref())
        .map_err(|err| serde::de::Error::custom(format!("Error decoding header: {err}")))
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
