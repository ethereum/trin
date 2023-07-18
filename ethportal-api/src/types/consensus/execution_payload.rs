use super::serde::{de_hex_to_txs, de_number_to_u256, se_hex_to_number, se_txs_to_hex};
use crate::types::consensus::body::Transactions;
use crate::types::wrapped::bloom::Bloom;
use crate::types::wrapped::bytes::Bytes;
use crate::types::wrapped::h160::H160;
use ethereum_types::{H256, U256};
use serde::{Deserialize, Serialize};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use superstruct::superstruct;

pub enum ForkName {
    Bellatrix,
    Capella,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Encode, Decode)]
pub struct ExecutionPayload {
    pub parent_hash: H256,
    pub fee_recipient: H160,
    pub state_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: Bloom,
    pub prev_randao: H256, // 'difficulty' in the yellow paper
    pub block_number: u64, // 'number' in the yellow paper
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Bytes,
    #[serde(deserialize_with = "de_number_to_u256")]
    #[serde(serialize_with = "se_hex_to_number")]
    pub base_fee_per_gas: U256,
    // Extra payload fields
    pub block_hash: H256, // Hash of execution block
    #[serde(serialize_with = "se_txs_to_hex")]
    #[serde(deserialize_with = "de_hex_to_txs")]
    pub transactions: Transactions,
}

#[superstruct(
    variants(Bellatrix, Capella),
    variant_attributes(derive(Default, Debug, Clone, Serialize, Deserialize, Encode, Decode,),)
)]
#[derive(Debug, Clone, Serialize, Deserialize, Encode)]
#[serde(untagged)]
#[ssz(enum_behaviour = "transparent")]
pub struct ExecutionPayloadHeader {
    #[superstruct(getter(copy))]
    pub parent_hash: H256,
    pub fee_recipient: H160,
    #[superstruct(getter(copy))]
    pub state_root: H256,
    #[superstruct(getter(copy))]
    pub receipts_root: H256,
    pub logs_bloom: Bloom,
    #[superstruct(getter(copy))]
    pub prev_randao: H256,
    #[superstruct(getter(copy))]
    pub block_number: u64,
    #[superstruct(getter(copy))]
    pub gas_limit: u64,
    #[superstruct(getter(copy))]
    pub gas_used: u64,
    #[superstruct(getter(copy))]
    pub timestamp: u64,
    pub extra_data: Bytes,
    #[superstruct(getter(copy))]
    #[serde(deserialize_with = "de_number_to_u256")]
    #[serde(serialize_with = "se_hex_to_number")]
    pub base_fee_per_gas: U256,
    #[superstruct(getter(copy))]
    pub block_hash: H256,
    #[superstruct(getter(copy))]
    pub transactions_root: H256,
    #[superstruct(only(Capella))]
    #[superstruct(getter(copy))]
    pub withdrawals_root: H256,
}

impl ExecutionPayloadHeader {
    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Bellatrix => {
                ExecutionPayloadHeaderBellatrix::from_ssz_bytes(bytes).map(Self::Bellatrix)
            }
            ForkName::Capella => {
                ExecutionPayloadHeaderCapella::from_ssz_bytes(bytes).map(Self::Capella)
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use ::ssz::{Decode, Encode};
    use rstest::rstest;
    use serde_json::Value;

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    #[case("case_2")]
    #[case("case_3")]
    #[case("case_4")]
    fn serde_execution_payload_bellatrix(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/bellatrix/ExecutionPayload/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: ExecutionPayload = serde_json::from_value(value.clone()).unwrap();
        let serialized = serde_json::to_value(content).unwrap();
        assert_eq!(serialized, value);
    }

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    #[case("case_2")]
    #[case("case_3")]
    #[case("case_4")]
    fn ssz_execution_payload_bellatrix(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/bellatrix/ExecutionPayload/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: ExecutionPayload = serde_json::from_value(value).unwrap();

        let compressed = std::fs::read(format!(
            "../test_assets/beacon/bellatrix/ExecutionPayload/ssz_random/{case}/serialized.ssz_snappy"
        ))
            .expect("cannot find test asset");
        let mut decoder = snap::raw::Decoder::new();
        let expected = decoder.decompress_vec(&compressed).unwrap();
        ExecutionPayload::from_ssz_bytes(&expected).unwrap();
        assert_eq!(content.as_ssz_bytes(), expected);
    }

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    #[case("case_2")]
    #[case("case_3")]
    #[case("case_4")]
    fn serde_execution_payload_header_bellatrix(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/bellatrix/ExecutionPayloadHeader/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let body: ExecutionPayloadHeaderBellatrix = serde_json::from_value(value.clone()).unwrap();
        let serialized = serde_json::to_value(body).unwrap();
        assert_eq!(serialized, value);
    }

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    #[case("case_2")]
    #[case("case_3")]
    #[case("case_4")]
    fn ssz_execution_payload_header_bellatrix(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/bellatrix/ExecutionPayloadHeader/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: ExecutionPayloadHeaderBellatrix = serde_json::from_value(value).unwrap();

        let compressed = std::fs::read(format!(
            "../test_assets/beacon/bellatrix/ExecutionPayloadHeader/ssz_random/{case}/serialized.ssz_snappy"
        ))
            .expect("cannot find test asset");
        let mut decoder = snap::raw::Decoder::new();
        let expected = decoder.decompress_vec(&compressed).unwrap();
        ExecutionPayloadHeader::from_ssz_bytes(&expected, ForkName::Bellatrix).unwrap();
        assert_eq!(content.as_ssz_bytes(), expected);
    }

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    #[case("case_2")]
    #[case("case_3")]
    #[case("case_4")]
    fn serde_execution_payload_header_capella(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/capella/ExecutionPayloadHeader/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let body: ExecutionPayloadHeaderCapella = serde_json::from_value(value.clone()).unwrap();
        let serialized = serde_json::to_value(body).unwrap();
        assert_eq!(serialized, value);
    }

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    #[case("case_2")]
    #[case("case_3")]
    #[case("case_4")]
    fn ssz_execution_payload_header_capella(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/capella/ExecutionPayloadHeader/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: ExecutionPayloadHeaderCapella = serde_json::from_value(value).unwrap();

        let compressed = std::fs::read(format!(
            "../test_assets/beacon/capella/ExecutionPayloadHeader/ssz_random/{case}/serialized.ssz_snappy"
        ))
            .expect("cannot find test asset");
        let mut decoder = snap::raw::Decoder::new();
        let expected = decoder.decompress_vec(&compressed).unwrap();
        ExecutionPayloadHeader::from_ssz_bytes(&expected, ForkName::Capella).unwrap();
        assert_eq!(content.as_ssz_bytes(), expected);
    }
}
