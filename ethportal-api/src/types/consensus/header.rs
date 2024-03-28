use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_u64;
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

/// Types based off specs @
/// https://github.com/ethereum/consensus-specs/blob/5970ae56a1cd50ea06049d8aad6bed74093d49d3/specs/phase0/beacon-chain.md
#[derive(
    Debug, PartialEq, Eq, Clone, Default, Serialize, Deserialize, Encode, Decode, TreeHash,
)]
pub struct BeaconBlockHeader {
    #[serde(deserialize_with = "as_u64")]
    pub slot: u64,
    #[serde(deserialize_with = "as_u64")]
    pub proposer_index: u64,
    pub parent_root: B256,
    pub state_root: B256,
    pub body_root: B256,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use ::ssz::Encode;
    use rstest::rstest;
    use serde_json::Value;

    /// Test vectors sourced from:
    /// https://github.com/ethereum/consensus-spec-tests/commit/c6e69469a75392b35169bc6234d4d3e6c4e288da
    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    #[case("case_2")]
    #[case("case_3")]
    #[case("case_4")]
    fn serde(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/bellatrix/BeaconBlockHeader/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let body: BeaconBlockHeader = serde_json::from_value(value.clone()).unwrap();
        let serialized = serde_json::to_value(body).unwrap();
        assert_eq!(value, serialized);
    }

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    #[case("case_2")]
    #[case("case_3")]
    #[case("case_4")]
    fn ssz(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/bellatrix/BeaconBlockHeader/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let body: BeaconBlockHeader = serde_json::from_value(value).unwrap();

        let expected = std::fs::read(format!(
            "../test_assets/beacon/bellatrix/BeaconBlockHeader/ssz_random/{case}/serialized.ssz_snappy"
        ))
        .expect("cannot find test asset");
        let mut decoder = snap::raw::Decoder::new();
        let expected = decoder.decompress_vec(&expected).unwrap();
        assert_eq!(body.as_ssz_bytes(), expected);
    }
}
