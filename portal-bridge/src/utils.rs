use std::{
    ops::Deref,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use alloy_primitives::B256;
use anyhow::bail;
use chrono::Duration;
use discv5::enr::{CombinedKey, Enr, NodeId};
use serde::{Deserialize, Serialize};

use ethportal_api::{
    utils::bytes::hex_encode, BeaconContentKey, BeaconContentValue, HistoryContentKey,
    HistoryContentValue,
};

/// Generates a set of N private keys, with node ids that are equally spaced
/// around the 256-bit keys space.
// count as u8 is used as a safety precaution against foot-gunning, since it could
// take a long time with a bigger input. Separately, a value larger than 256
// stops getting evenly spread, because of how the code spreads the data by
// inspecting the first byte from the node ID. Also, values between 16 to
// 256 would be spread, but less and less evenly.
pub fn generate_spaced_private_keys(count: u8, root_private_key: Option<B256>) -> Vec<String> {
    let mut private_keys = vec![];
    let (root_node_id, root_private_key) = match root_private_key {
        Some(mut key) => {
            let private_key =
                CombinedKey::secp256k1_from_bytes(&mut key.0).expect("to be able to decode key");
            let enr = Enr::empty(&private_key).expect("to be able to build ENR from private key");
            (enr.node_id(), private_key)
        }
        None => random_node_id(),
    };
    private_keys.push(hex_encode(root_private_key.encode()));
    let mut root_prefix = root_node_id.raw()[0];

    let mut prefixes: Vec<u8> = vec![];
    for _ in 1..count {
        let prefix = root_prefix.wrapping_add(u8::MAX / count);
        prefixes.push(prefix);
        root_prefix = prefix;
    }

    for prefix in prefixes {
        let (mut node_id, mut private_key) = random_node_id();
        while node_id.raw()[0] != prefix {
            (node_id, private_key) = random_node_id();
        }
        private_keys.push(hex_encode(private_key.encode()));
    }
    private_keys
}

fn random_node_id() -> (NodeId, CombinedKey) {
    let random_private_key = CombinedKey::generate_secp256k1();
    let enr = Enr::empty(&random_private_key).expect("to be able to generate a random node id");
    (enr.node_id(), random_private_key)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryTestAssets(pub Vec<HistoryAsset>);

impl Deref for HistoryTestAssets {
    type Target = Vec<HistoryAsset>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconTestAssets(pub Vec<BeaconAsset>);

impl Deref for BeaconTestAssets {
    type Target = Vec<BeaconAsset>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// Struct definitions for test assets
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TestAssets {
    History(HistoryTestAssets),
    Beacon(BeaconTestAssets),
}

impl TestAssets {
    pub fn into_history_assets(self) -> anyhow::Result<HistoryTestAssets> {
        match self {
            TestAssets::History(assets) => Ok(assets),
            _ => bail!("Test assets are not of type History"),
        }
    }

    pub fn into_beacon_assets(self) -> anyhow::Result<BeaconTestAssets> {
        match self {
            TestAssets::Beacon(assets) => Ok(assets),
            _ => bail!("Test assets are not of type Beacon"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryAsset {
    pub content_key: HistoryContentKey,
    pub content_value: HistoryContentValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconAsset {
    pub content_key: BeaconContentKey,
    pub content_value: BeaconContentValue,
}

pub fn read_test_assets_from_file(test_path: PathBuf) -> TestAssets {
    let extension = test_path
        .extension()
        .and_then(|path| path.to_str())
        .expect("Unable to parse test path extension")
        .to_string();
    let test_asset = std::fs::read_to_string(test_path).expect("Error reading test asset.");

    let assets: TestAssets = match &extension[..] {
        "json" => serde_json::from_str(&test_asset).expect("Unable to parse json test asset."),
        "yaml" => serde_yaml::from_str(&test_asset).expect("Unable to parse yaml test asset."),
        _ => panic!("Invalid file extension"),
    };

    assets
}
/// Gets the duration until the next light client update
/// Updates are scheduled for 4 seconds into each slot
pub fn duration_until_next_update(genesis_time: u64, now: SystemTime) -> Duration {
    let current_slot = expected_current_slot(genesis_time, now);
    let next_slot = current_slot + 1;
    let next_slot_timestamp = slot_timestamp(next_slot, genesis_time);

    let now = now
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    let time_to_next_slot = next_slot_timestamp - now;
    let next_update = time_to_next_slot + 4;

    Duration::seconds(next_update as i64)
}

pub fn expected_current_slot(genesis_time: u64, now: SystemTime) -> u64 {
    let now = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
    let since_genesis = now - std::time::Duration::from_secs(genesis_time);

    since_genesis.as_secs() / 12
}

fn slot_timestamp(slot: u64, genesis_time: u64) -> u64 {
    slot * 12 + genesis_time
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::constants::{
        BEACON_GENESIS_TIME, HEADER_WITH_PROOF_CONTENT_KEY, HEADER_WITH_PROOF_CONTENT_VALUE,
    };
    use chrono::{DateTime, TimeZone, Utc};
    use ethportal_api::{
        types::distance::{Metric, XorMetric},
        utils::bytes::hex_decode,
    };
    use rstest::rstest;
    use serde_json::json;

    #[rstest]
    #[case(2)]
    #[case(4)]
    #[case(16)]
    fn test_generate_spaced_private_keys(#[case] count: u8) {
        use alloy_primitives::U256;

        let private_keys = generate_spaced_private_keys(count, None);
        assert_eq!(private_keys.len() as u8, count);
        let one = Enr::empty(
            &CombinedKey::secp256k1_from_bytes(&mut hex_decode(&private_keys[0]).unwrap()).unwrap(),
        )
        .unwrap();
        let two = Enr::empty(
            &CombinedKey::secp256k1_from_bytes(&mut hex_decode(&private_keys[1]).unwrap()).unwrap(),
        )
        .unwrap();
        let distance = XorMetric::distance(&one.node_id().raw(), &two.node_id().raw());
        let min_spread = (U256::MAX / U256::from(count) / U256::from(2)).into();
        let first_byte1 = one.node_id().raw()[0];
        let first_byte2 = two.node_id().raw()[0];
        assert!(
            distance > min_spread,
            "{distance} vs {min_spread}, first bytes: {first_byte1} vs {first_byte2}"
        );
    }

    #[test]
    fn test_read_test_assets_from_file_json() {
        let assets: HistoryTestAssets =
            read_test_assets_from_file(PathBuf::from("../test_assets/portalnet/bridge_data.json"))
                .into_history_assets()
                .unwrap();
        let content_key: HistoryContentKey =
            serde_json::from_value(json!(HEADER_WITH_PROOF_CONTENT_KEY)).unwrap();
        let content_value: HistoryContentValue =
            serde_json::from_value(json!(HEADER_WITH_PROOF_CONTENT_VALUE)).unwrap();

        assert_eq!(assets[0].content_key, content_key);
        assert_eq!(assets[0].content_value, content_value);
    }

    #[test]
    fn test_read_test_assets_from_file_yaml() {
        let assets: HistoryTestAssets =
            read_test_assets_from_file(PathBuf::from("../test_assets/portalnet/bridge_data.yaml"))
                .into_history_assets()
                .unwrap();
        let content_key: HistoryContentKey =
            serde_json::from_value(json!(HEADER_WITH_PROOF_CONTENT_KEY)).unwrap();
        let content_value: HistoryContentValue =
            serde_json::from_value(json!(HEADER_WITH_PROOF_CONTENT_VALUE)).unwrap();

        assert_eq!(assets[0].content_key, content_key);
        assert_eq!(assets[0].content_value, content_value);
    }

    #[rstest]
    #[case(10, 5)]
    #[case(11, 16)]
    fn test_duration_until_next_update(#[case] seconds: u32, #[case] expected_duration: i64) {
        let date: DateTime<Utc> = Utc.with_ymd_and_hms(2023, 8, 23, 11, 00, seconds).unwrap();
        let now = SystemTime::from(date);
        let duration = duration_until_next_update(BEACON_GENESIS_TIME, now);
        assert_eq!(duration, Duration::seconds(expected_duration));
    }

    #[rstest]
    #[case(10, 7163698)]
    #[case(11, 7163699)]
    fn test_expected_current_slot(#[case] seconds: u32, #[case] expected_slot: u64) {
        let date: DateTime<Utc> = Utc.with_ymd_and_hms(2023, 8, 23, 11, 00, seconds).unwrap();
        let now = SystemTime::from(date);
        let slot = expected_current_slot(BEACON_GENESIS_TIME, now);
        assert_eq!(slot, expected_slot);
    }
}
