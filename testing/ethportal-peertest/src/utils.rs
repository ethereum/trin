use std::{
    fmt::{self, Display, Formatter},
    fs,
    path::{Path, PathBuf},
};

use alloy::{consensus::Header, primitives::Bytes, rlp::Decodable};
use anyhow::Result;
use ethportal_api::{
    types::{
        content_key::legacy_history::{
            BlockBodyKey, BlockHeaderByHashKey, BlockHeaderByNumberKey, BlockReceiptsKey,
        },
        execution::header_with_proof::HeaderWithProof,
    },
    BeaconContentKey, BeaconContentValue, BeaconNetworkApiClient, ContentValue,
    LegacyHistoryContentKey, LegacyHistoryContentValue, LegacyHistoryNetworkApiClient,
    RawContentValue, StateContentKey, StateContentValue, StateNetworkApiClient,
};
use futures::{Future, TryFutureExt};
use serde::{Deserialize, Deserializer};
use serde_yaml::Value;
use ssz::Decode;
use tracing::error;
use trin_utils::submodules::portal_spec_tests_file_path;

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

/// Wait for the legacy history content to be transferred
pub async fn wait_for_legacy_history_content<
    P: LegacyHistoryNetworkApiClient + std::marker::Sync,
>(
    ipc_client: &P,
    content_key: LegacyHistoryContentKey,
) -> LegacyHistoryContentValue {
    wait_for_successful_result(|| {
        let content_key = content_key.clone();
        ipc_client
            .local_content(content_key.clone())
            .map_err(anyhow::Error::from)
            .and_then(|content| async move {
                LegacyHistoryContentValue::decode(&content_key, &content)
                    .map_err(anyhow::Error::from)
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

fn read_legacy_history_fixture_from_file(
    path: &Path,
) -> Result<(LegacyHistoryContentKey, LegacyHistoryContentValue)> {
    let yaml_content = fs::read_to_string(path)?;

    let value: Value = serde_yaml::from_str(&yaml_content)?;

    let content_key = LegacyHistoryContentKey::deserialize(&value["content_key"])?;
    let content_value = RawContentValue::deserialize(&value["content_value"])?;
    let content_value = LegacyHistoryContentValue::decode(&content_key, &content_value)?;

    Ok((content_key, content_value))
}

/// Wrapper function for fixtures that directly returns the tuple.
fn read_legacy_history_fixture(path: &str) -> (LegacyHistoryContentKey, LegacyHistoryContentValue) {
    let path = portal_spec_tests_file_path(PathBuf::from("tests/mainnet/history").join(path));
    read_legacy_history_fixture_from_file(&path)
        .unwrap_or_else(|err| panic!("Error reading fixture in {path:?}: {err}"))
}

/// Legacy History HeaderWithProof content key & value
/// Block #1000010
pub fn fixture_header_by_hash_1000010() -> (LegacyHistoryContentKey, LegacyHistoryContentValue) {
    read_legacy_history_fixture("headers_with_proof/1000010.yaml")
}

/// Legacy History HeaderByHash content key & value
/// Block #14764013 (pre-merge)
pub fn fixture_header_by_hash() -> (LegacyHistoryContentKey, LegacyHistoryContentValue) {
    read_legacy_history_fixture("headers_with_proof/14764013.yaml")
}

/// Legacy History HeaderByNumber content key & value
/// Block #14764013 (pre-merge)
pub fn fixture_header_by_number() -> (LegacyHistoryContentKey, LegacyHistoryContentValue) {
    let (_, content_value) = read_legacy_history_fixture("headers_with_proof/14764013.yaml");

    // Create a content key from the block number
    let LegacyHistoryContentValue::BlockHeaderWithProof(header_with_proof) = content_value.clone()
    else {
        panic!("Expected HistoryContentValue::BlockHeaderWithProof")
    };
    let content_key = LegacyHistoryContentKey::BlockHeaderByNumber(BlockHeaderByNumberKey {
        block_number: header_with_proof.header.number,
    });
    (content_key, content_value)
}

/// Legacy History BlockBody content key & value
/// Block #14764013 (pre-merge)
pub fn fixture_block_body() -> (LegacyHistoryContentKey, LegacyHistoryContentValue) {
    read_legacy_history_fixture("bodies/14764013.yaml")
}

/// Legacy History Receipts content key & value
/// Block #14764013 (pre-merge)
pub fn fixture_receipts() -> (LegacyHistoryContentKey, LegacyHistoryContentValue) {
    read_legacy_history_fixture("receipts/14764013.yaml")
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

/// Legacy History HeaderWithProof content key & value
/// Block #15040641 (pre-merge)
pub fn fixture_header_by_hash_with_proof_15040641(
) -> (LegacyHistoryContentKey, LegacyHistoryContentValue) {
    read_binary_history_fixture(15040641, None)
}

/// Legacy History BlockBody content key & value
/// Block #15040641 (pre-merge)
pub fn fixture_block_body_15040641() -> (LegacyHistoryContentKey, LegacyHistoryContentValue) {
    read_binary_history_fixture(15040641, Some(DependentType::BlockBody))
}

/// Legacy History Receipts content key & value
/// Block #15040641 (pre-merge)
pub fn fixture_receipts_15040641() -> (LegacyHistoryContentKey, LegacyHistoryContentValue) {
    read_binary_history_fixture(15040641, Some(DependentType::Receipts))
}

/// Legacy History HeaderWithProof content key & value
/// Block #15040708 (pre-merge)
pub fn fixture_header_by_hash_with_proof_15040708(
) -> (LegacyHistoryContentKey, LegacyHistoryContentValue) {
    read_binary_history_fixture(15040708, None)
}

/// Legacy History BlockBody content key & value
/// Block #15040708 (pre-merge)
pub fn fixture_block_body_15040708() -> (LegacyHistoryContentKey, LegacyHistoryContentValue) {
    read_binary_history_fixture(15040708, Some(DependentType::BlockBody))
}

/// Legacy History Receipts content key & value
/// Block #15040708 (pre-merge)
pub fn fixture_receipts_15040708() -> (LegacyHistoryContentKey, LegacyHistoryContentValue) {
    read_binary_history_fixture(15040708, Some(DependentType::Receipts))
}

fn read_binary_history_fixture(
    block_number: u64,
    dependent: Option<DependentType>,
) -> (LegacyHistoryContentKey, LegacyHistoryContentValue) {
    let header_value = std::fs::read(format!(
        "../../test_assets/mainnet/large_content/{block_number}/header.bin"
    ))
    .unwrap();
    let header_content_value: HeaderWithProof =
        HeaderWithProof::from_ssz_bytes(&header_value).unwrap();

    match dependent {
        Some(dependent_type) => {
            let dependent_value = std::fs::read(format!(
                "../../test_assets/mainnet/large_content/{block_number}/{dependent_type}.bin"
            ))
            .unwrap();
            match dependent_type {
                DependentType::BlockBody => {
                    let content_key = LegacyHistoryContentKey::BlockBody(BlockBodyKey {
                        block_hash: header_content_value.header.hash_slow().0,
                    });
                    let content_value =
                        LegacyHistoryContentValue::decode(&content_key, &dependent_value).unwrap();
                    (content_key, content_value)
                }
                DependentType::Receipts => {
                    let content_key = LegacyHistoryContentKey::BlockReceipts(BlockReceiptsKey {
                        block_hash: header_content_value.header.hash_slow().0,
                    });
                    let content_value =
                        LegacyHistoryContentValue::decode(&content_key, &dependent_value).unwrap();
                    (content_key, content_value)
                }
            }
        }
        None => {
            let content_key = LegacyHistoryContentKey::BlockHeaderByHash(BlockHeaderByHashKey {
                block_hash: header_content_value.header.hash_slow().0,
            });
            let content_value =
                LegacyHistoryContentValue::BlockHeaderWithProof(header_content_value);
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

fn read_state_fixture_from_file(path: &Path) -> Result<Vec<StateFixture>> {
    let yaml_content = fs::read_to_string(path)?;
    let value: Value = serde_yaml::from_str(&yaml_content)?;

    let result = Vec::<StateFixture>::deserialize(value)?;
    Ok(result)
}

fn read_state_fixture(path: &str) -> Vec<StateFixture> {
    let path = portal_spec_tests_file_path(PathBuf::from("tests/mainnet/state").join(path));
    read_state_fixture_from_file(&path)
        .unwrap_or_else(|err| panic!("Error reading fixture in {path:?}: {err}"))
}

pub fn fixtures_state_account_trie_node() -> Vec<StateFixture> {
    read_state_fixture("validation/account_trie_node.yaml")
}

pub fn fixtures_state_contract_storage_trie_node() -> Vec<StateFixture> {
    read_state_fixture("validation/contract_storage_trie_node.yaml")
}

pub fn fixtures_state_contract_bytecode() -> Vec<StateFixture> {
    read_state_fixture("validation/contract_bytecode.yaml")
}
