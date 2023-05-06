use ethereum_types::{H256, U256};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, BitList, BitVector, VariableList};

use super::{
    header::BeaconBlockHeader,
    proof::Proof,
    pubkey::PubKey,
    serde::{de_hex_to_txs, de_number_to_u256, se_hex_to_number, se_txs_to_hex},
    signature::BlsSignature,
};
use crate::trin_types::wrapped::{bloom::Bloom, bytes::Bytes, h160::H160};

/// Types based off specs @
/// https://github.com/ethereum/consensus-specs/blob/5970ae56a1cd50ea06049d8aad6bed74093d49d3/specs/bellatrix/beacon-chain.md
#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Decode, Encode)]
pub struct BeaconBlockBody {
    pub randao_reveal: BlsSignature,
    pub eth1_data: Eth1Data,
    pub graffiti: H256,
    pub proposer_slashings: VariableList<ProposerSlashing, typenum::U16>,
    pub attester_slashings: VariableList<AttesterSlashing, typenum::U2>,
    pub attestations: VariableList<Attestation, typenum::U128>,
    pub deposits: VariableList<Deposit, typenum::U16>,
    pub voluntary_exits: VariableList<SignedVoluntaryExit, typenum::U16>,
    pub sync_aggregate: SyncAggregate,
    pub execution_payload: ExecutionPayload,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Decode, Encode)]
pub struct SyncAggregate {
    pub sync_committee_bits: BitVector<typenum::U512>,
    pub sync_committee_signature: BlsSignature,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Decode, Encode)]
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

pub type Transaction = VariableList<u8, typenum::U1073741824>;
pub type Transactions = VariableList<Transaction, typenum::U1048576>;

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Decode, Encode)]
pub struct ProposerSlashing {
    pub signed_header_1: SignedBeaconBlockHeader,
    pub signed_header_2: SignedBeaconBlockHeader,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Decode, Encode)]
pub struct SignedBeaconBlockHeader {
    pub message: BeaconBlockHeader,
    pub signature: BlsSignature,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Decode, Encode)]
pub struct AttesterSlashing {
    pub attestation_1: IndexedAttestation,
    pub attestation_2: IndexedAttestation,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Decode, Encode)]
pub struct Attestation {
    pub aggregation_bits: BitList<typenum::U2048>,
    pub data: AttestationData,
    pub signature: BlsSignature,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Decode, Encode)]
pub struct Deposit {
    pub proof: Proof,
    pub data: DepositData,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Decode, Encode)]
pub struct DepositData {
    pub pubkey: PubKey,
    pub withdrawal_credentials: H256,
    pub amount: u64,
    pub signature: BlsSignature,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Decode, Encode)]
pub struct IndexedAttestation {
    pub attesting_indices: VariableList<u64, typenum::U2048>,
    pub data: AttestationData,
    pub signature: BlsSignature,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Decode, Encode)]
pub struct AttestationData {
    pub slot: u64,
    pub index: u64,
    pub beacon_block_root: H256,
    pub source: Checkpoint,
    pub target: Checkpoint,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Decode, Encode)]
pub struct Checkpoint {
    pub epoch: u64,
    pub root: H256,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Decode, Encode)]
pub struct SignedVoluntaryExit {
    pub message: VoluntaryExit,
    pub signature: BlsSignature,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Decode, Encode)]
pub struct VoluntaryExit {
    pub epoch: u64,
    pub validator_index: u64,
}

#[derive(Debug, PartialEq, Clone, Default, Deserialize, Serialize, Decode, Encode)]
pub struct Eth1Data {
    pub deposit_root: H256,
    pub deposit_count: u64,
    pub block_hash: H256,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use ::ssz::{Decode, Encode};
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
            "../test_assets/beacon/BeaconBlockBody/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let body: BeaconBlockBody = serde_json::from_value(value.clone()).unwrap();
        let serialized = serde_json::to_value(body).unwrap();
        assert_eq!(serialized, value);
    }

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    #[case("case_2")]
    #[case("case_3")]
    #[case("case_4")]
    fn ssz(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/BeaconBlockBody/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let body: BeaconBlockBody = serde_json::from_value(value).unwrap();

        let compressed = std::fs::read(format!(
            "../test_assets/beacon/BeaconBlockBody/ssz_random/{case}/serialized.ssz_snappy"
        ))
        .expect("cannot find test asset");
        let mut decoder = snap::raw::Decoder::new();
        let expected = decoder.decompress_vec(&compressed).unwrap();
        BeaconBlockBody::from_ssz_bytes(&expected).unwrap();
        assert_eq!(body.as_ssz_bytes(), expected);
    }
}
