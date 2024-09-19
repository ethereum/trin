use super::serde::{de_hex_to_txs, de_number_to_u256, se_hex_to_number, se_txs_to_hex};
use crate::{
    types::{
        bytes::ByteList32,
        consensus::{body::Transactions, fork::ForkName},
    },
    utils::serde::{hex_fixed_vec, hex_var_list},
};
use alloy_primitives::{Address, B256, U256};
use rs_merkle::{algorithms::Sha256, MerkleTree};
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_u64;
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, typenum::U16, FixedVector, VariableList};
use superstruct::superstruct;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

pub type Bloom = FixedVector<u8, typenum::U256>;
pub type ExtraData = ByteList32;

#[superstruct(
    variants(Bellatrix, Capella, Deneb),
    variant_attributes(
        derive(
            Default,
            Debug,
            Clone,
            PartialEq,
            Serialize,
            Deserialize,
            Encode,
            Decode,
            TreeHash,
        ),
        serde(deny_unknown_fields),
    )
)]
#[derive(Debug, Clone, Serialize, Encode, Deserialize, TreeHash)]
#[serde(untagged)]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct ExecutionPayload {
    pub parent_hash: B256,
    pub fee_recipient: Address,
    pub state_root: B256,
    pub receipts_root: B256,
    #[serde(with = "hex_fixed_vec")]
    pub logs_bloom: Bloom,
    pub prev_randao: B256, // 'difficulty' in the yellow paper
    #[serde(deserialize_with = "as_u64")]
    pub block_number: u64, // 'number' in the yellow paper
    #[serde(deserialize_with = "as_u64")]
    pub gas_limit: u64,
    #[serde(deserialize_with = "as_u64")]
    pub gas_used: u64,
    #[serde(deserialize_with = "as_u64")]
    pub timestamp: u64,
    #[serde(with = "hex_var_list")]
    pub extra_data: ExtraData,
    #[serde(deserialize_with = "de_number_to_u256")]
    #[serde(serialize_with = "se_hex_to_number")]
    pub base_fee_per_gas: U256,
    // Extra payload fields
    pub block_hash: B256, // Hash of execution block
    #[serde(serialize_with = "se_txs_to_hex")]
    #[serde(deserialize_with = "de_hex_to_txs")]
    pub transactions: Transactions,
    #[superstruct(only(Capella, Deneb))]
    pub withdrawals: VariableList<Withdrawal, U16>,
    #[superstruct(only(Deneb))]
    #[serde(deserialize_with = "as_u64")]
    pub blob_gas_used: u64,
    #[superstruct(only(Deneb))]
    #[serde(deserialize_with = "as_u64")]
    pub excess_blob_gas: u64,
}

impl ExecutionPayload {
    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Bellatrix => {
                ExecutionPayloadBellatrix::from_ssz_bytes(bytes).map(Self::Bellatrix)
            }
            ForkName::Capella => ExecutionPayloadCapella::from_ssz_bytes(bytes).map(Self::Capella),
            ForkName::Deneb => ExecutionPayloadDeneb::from_ssz_bytes(bytes).map(Self::Deneb),
        }
    }
}

impl ExecutionPayloadBellatrix {
    pub fn build_block_hash_proof(&self) -> Vec<B256> {
        let mut leaves: Vec<[u8; 32]> = vec![
            self.parent_hash.tree_hash_root().0,
            self.fee_recipient.tree_hash_root().0,
            self.state_root.tree_hash_root().0,
            self.receipts_root.tree_hash_root().0,
            self.logs_bloom.tree_hash_root().0,
            self.prev_randao.tree_hash_root().0,
            self.block_number.tree_hash_root().0,
            self.gas_limit.tree_hash_root().0,
            self.gas_used.tree_hash_root().0,
            self.timestamp.tree_hash_root().0,
            self.extra_data.tree_hash_root().0,
            self.base_fee_per_gas.tree_hash_root().0,
            self.block_hash.tree_hash_root().0,
            self.transactions.tree_hash_root().0,
        ];
        // We want to add empty leaves to make the tree a power of 2
        while leaves.len() < 16 {
            leaves.push([0; 32]);
        }

        let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        let indices_to_prove = vec![12];
        let proof = merkle_tree.proof(&indices_to_prove);
        let proof_hashes: Vec<B256> = proof
            .proof_hashes()
            .iter()
            .map(|hash| B256::from_slice(hash))
            .collect();

        proof_hashes
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct Withdrawal {
    #[serde(deserialize_with = "as_u64")]
    pub index: u64,
    #[serde(deserialize_with = "as_u64")]
    pub validator_index: u64,
    pub address: Address,
    #[serde(deserialize_with = "as_u64")]
    pub amount: u64,
}

#[superstruct(
    variants(Bellatrix, Capella, Deneb),
    variant_attributes(derive(
        Default,
        Debug,
        Clone,
        PartialEq,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        TreeHash
    ),)
)]
#[derive(Debug, Clone, Serialize, Deserialize, Encode, TreeHash)]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
pub struct ExecutionPayloadHeader {
    #[superstruct(getter(copy))]
    pub parent_hash: B256,
    pub fee_recipient: Address,
    #[superstruct(getter(copy))]
    pub state_root: B256,
    #[superstruct(getter(copy))]
    pub receipts_root: B256,
    #[serde(with = "hex_fixed_vec")]
    pub logs_bloom: Bloom,
    #[superstruct(getter(copy))]
    pub prev_randao: B256,
    #[superstruct(getter(copy))]
    #[serde(deserialize_with = "as_u64")]
    pub block_number: u64,
    #[superstruct(getter(copy))]
    #[serde(deserialize_with = "as_u64")]
    pub gas_limit: u64,
    #[superstruct(getter(copy))]
    #[serde(deserialize_with = "as_u64")]
    pub gas_used: u64,
    #[superstruct(getter(copy))]
    #[serde(deserialize_with = "as_u64")]
    pub timestamp: u64,
    #[serde(with = "hex_var_list")]
    pub extra_data: ExtraData,
    #[superstruct(getter(copy))]
    #[serde(deserialize_with = "de_number_to_u256")]
    #[serde(serialize_with = "se_hex_to_number")]
    pub base_fee_per_gas: U256,
    #[superstruct(getter(copy))]
    pub block_hash: B256,
    #[superstruct(getter(copy))]
    pub transactions_root: B256,
    #[superstruct(only(Capella, Deneb))]
    #[superstruct(getter(copy))]
    pub withdrawals_root: B256,
    #[superstruct(only(Deneb))]
    #[superstruct(getter(copy))]
    #[serde(deserialize_with = "as_u64")]
    pub blob_gas_used: u64,
    #[superstruct(only(Deneb))]
    #[superstruct(getter(copy))]
    #[serde(deserialize_with = "as_u64")]
    pub excess_blob_gas: u64,
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
            ForkName::Deneb => ExecutionPayloadHeaderDeneb::from_ssz_bytes(bytes).map(Self::Deneb),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use ::ssz::Encode;
    use rstest::rstest;
    use serde_json::Value;
    use std::str::FromStr;

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
        ExecutionPayload::from_ssz_bytes(&expected, ForkName::Bellatrix).unwrap();
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

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    fn serde_execution_payload_header_deneb(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/deneb/ExecutionPayloadHeader/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let body: ExecutionPayloadHeaderDeneb = serde_json::from_value(value.clone()).unwrap();
        let serialized = serde_json::to_value(body).unwrap();
        assert_eq!(serialized, value);
    }

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    fn ssz_execution_payload_header_deneb(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/deneb/ExecutionPayloadHeader/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: ExecutionPayloadHeaderDeneb = serde_json::from_value(value).unwrap();

        let compressed = std::fs::read(format!(
            "../test_assets/beacon/deneb/ExecutionPayloadHeader/ssz_random/{case}/serialized.ssz_snappy"
        ))
            .expect("cannot find test asset");
        let mut decoder = snap::raw::Decoder::new();
        let expected = decoder.decompress_vec(&compressed).unwrap();
        ExecutionPayloadHeader::from_ssz_bytes(&expected, ForkName::Deneb).unwrap();
        assert_eq!(content.as_ssz_bytes(), expected);
    }

    #[test]
    fn execution_payload_block_hash_proof() {
        let value = std::fs::read_to_string(
            "../test_assets/beacon/bellatrix/ExecutionPayload/ssz_random/case_0/value.yaml",
        )
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: ExecutionPayloadBellatrix = serde_json::from_value(value).unwrap();
        let expected_block_hash_proof = [
            "0xc1c51dd941baaa59ef26f7141dc6f1b88e6c30e39c819189fcb515e8bcb41733",
            "0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
            "0x49e643aa5e1626558ec27d657101d5b7b2a0216755659e301e7d3e523bf48b49",
            "0xc81a9c5f1916aba6b34dd4e347fe9adf075debdecebd1eb65db3c1dad6757cd2",
        ]
        .map(|x| B256::from_str(x).unwrap())
        .to_vec();
        let proof = content.build_block_hash_proof();

        assert_eq!(proof.len(), 4);
        assert_eq!(proof, expected_block_hash_proof);
    }
}
