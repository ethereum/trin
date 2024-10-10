use std::{
    fmt::{self, Display, Formatter},
    fs,
};

use alloy_primitives::Bytes;
use alloy_rlp::Decodable;
use futures::{Future, TryFutureExt};
use serde::Deserializer;
use ssz::Decode;
use tracing::error;

use anyhow::Result;
use serde_yaml::Value;
use ureq::serde::Deserialize;

use ethportal_api::{
    types::{
        content_key::history::{BlockHeaderByHashKey, BlockHeaderByNumberKey},
        execution::header_with_proof::HeaderWithProof,
    },
    BeaconContentKey, BeaconContentValue, BeaconNetworkApiClient, BlockBodyKey, BlockReceiptsKey,
    ContentValue, Header, HistoryContentKey, HistoryContentValue, HistoryNetworkApiClient,
    RawContentValue, StateContentKey, StateContentValue, StateNetworkApiClient,
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
        .unwrap_or_else(|err| panic!("Error reading fixture in {file_name}: {err}"))
}

/// History HeaderWithProof content key & value
/// Block #1000010
pub fn fixture_header_by_hash_1000010() -> (HistoryContentKey, HistoryContentValue) {
    read_fixture("portal-spec-tests/tests/mainnet/history/headers_with_proof/1000010.yaml")
}

/// History HeaderByHash content key & value
/// Block #14764013 (pre-merge)
pub fn fixture_header_by_hash() -> (HistoryContentKey, HistoryContentValue) {
    read_fixture("portal-spec-tests/tests/mainnet/history/headers_with_proof/14764013.yaml")
}

/// History HeaderByNumber content key & value
/// Block #14764013 (pre-merge)
pub fn fixture_header_by_number() -> (HistoryContentKey, HistoryContentValue) {
    let (_, content_value) =
        read_fixture("portal-spec-tests/tests/mainnet/history/headers_with_proof/14764013.yaml");

    // Create a content key from the block number
    let HistoryContentValue::BlockHeaderWithProof(header_with_proof) = content_value.clone() else {
        panic!("Expected HistoryContentValue::BlockHeaderWithProof")
    };
    let content_key = HistoryContentKey::BlockHeaderByNumber(BlockHeaderByNumberKey {
        block_number: header_with_proof.header.number,
    });
    (content_key, content_value)
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

enum DependentType {
    BlockBody,
    Receipts,
}

impl Display for DependentType {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            DependentType::BlockBody => write!(f, "body"),
            DependentType::Receipts => write!(f, "receipts"),
        }
    }
}

/// History HeaderWithProof content key & value
/// Block #15040641 (pre-merge)
pub fn fixture_header_by_hash_with_proof_15040641() -> (HistoryContentKey, HistoryContentValue) {
    read_binary_history_fixture(15040641, None)
}

/// History BlockBody content key & value
/// Block #15040641 (pre-merge)
pub fn fixture_block_body_15040641() -> (HistoryContentKey, HistoryContentValue) {
    read_binary_history_fixture(15040641, Some(DependentType::BlockBody))
}

/// History Receipts content key & value
/// Block #15040641 (pre-merge)
pub fn fixture_receipts_15040641() -> (HistoryContentKey, HistoryContentValue) {
    read_binary_history_fixture(15040641, Some(DependentType::Receipts))
}

/// History HeaderWithProof content key & value
/// Block #15040708 (pre-merge)
pub fn fixture_header_by_hash_with_proof_15040708() -> (HistoryContentKey, HistoryContentValue) {
    read_binary_history_fixture(15040708, None)
}

/// History BlockBody content key & value
/// Block #15040708 (pre-merge)
pub fn fixture_block_body_15040708() -> (HistoryContentKey, HistoryContentValue) {
    read_binary_history_fixture(15040708, Some(DependentType::BlockBody))
}

/// History Receipts content key & value
/// Block #15040708 (pre-merge)
pub fn fixture_receipts_15040708() -> (HistoryContentKey, HistoryContentValue) {
    read_binary_history_fixture(15040708, Some(DependentType::Receipts))
}

fn read_binary_history_fixture(
    block_number: u64,
    dependent: Option<DependentType>,
) -> (HistoryContentKey, HistoryContentValue) {
    let header_value = std::fs::read(format!(
        "test_assets/mainnet/large_content/{block_number}/header.bin"
    ))
    .unwrap();
    let header_content_value: HeaderWithProof =
        HeaderWithProof::from_ssz_bytes(&header_value).unwrap();

    match dependent {
        Some(dependent_type) => {
            let dependent_value = std::fs::read(format!(
                "test_assets/mainnet/large_content/{block_number}/{dependent_type}.bin"
            ))
            .unwrap();
            match dependent_type {
                DependentType::BlockBody => {
                    let content_key = HistoryContentKey::BlockBody(BlockBodyKey {
                        block_hash: header_content_value.header.hash().0,
                    });
                    let content_value =
                        HistoryContentValue::decode(&content_key, &dependent_value).unwrap();
                    (content_key, content_value)
                }
                DependentType::Receipts => {
                    let content_key = HistoryContentKey::BlockReceipts(BlockReceiptsKey {
                        block_hash: header_content_value.header.hash().0,
                    });
                    let content_value =
                        HistoryContentValue::decode(&content_key, &dependent_value).unwrap();
                    (content_key, content_value)
                }
            }
        }
        None => {
            let content_key = HistoryContentKey::BlockHeaderByHash(BlockHeaderByHashKey {
                block_hash: header_content_value.header.hash().0,
            });
            let content_value = HistoryContentValue::BlockHeaderWithProof(header_content_value);
            (content_key, content_value)
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct StateFixture {
    #[serde(deserialize_with = "de_header")]
    pub block_header: Header,
    #[serde(rename = "content_key")]
    pub key: StateContentKey,
    #[serde(rename = "content_value_offer")]
    pub raw_offer_value: RawContentValue,
    #[serde(rename = "content_value_retrieval")]
    pub raw_lookup_value: RawContentValue,
}

impl StateFixture {
    pub fn offer_value(&self) -> StateContentValue {
        StateContentValue::decode(&self.key, &self.raw_offer_value)
            .expect("Error decoding state offer content value")
    }

    pub fn lookup_value(&self) -> StateContentValue {
        StateContentValue::decode(&self.key, &self.raw_lookup_value)
            .expect("Error decoding state lookup content value")
    }
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
