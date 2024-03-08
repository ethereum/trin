use crate::{
    consensus::{
        beacon_state::Epoch,
        execution_payload::{ExecutionPayloadBellatrix, ExecutionPayloadCapella},
        fork::ForkName,
    },
    types::bytes::ByteList1G,
};
use discv5::enr::k256::elliptic_curve::consts::U16;
use ethereum_types::{Address, H256};
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_u64;
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use ssz_types::{
    typenum,
    typenum::{U128, U2, U33},
    BitList, BitVector, FixedVector, VariableList,
};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

use super::{header::BeaconBlockHeader, pubkey::PubKey, signature::BlsSignature};

type MaxBlsToExecutionChanges = U16;

/// Types based off specs @
/// https://github.com/ethereum/consensus-specs/blob/5970ae56a1cd50ea06049d8aad6bed74093d49d3/specs/bellatrix/beacon-chain.md
#[superstruct(
    variants(Bellatrix, Capella),
    variant_attributes(
        derive(
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
#[derive(Debug, Clone, PartialEq, Encode, Serialize, Deserialize)]
#[ssz(enum_behaviour = "transparent")]
#[serde(untagged)]
pub struct BeaconBlockBody {
    pub randao_reveal: BlsSignature,
    pub eth1_data: Eth1Data,
    pub graffiti: H256,
    pub proposer_slashings: VariableList<ProposerSlashing, U16>,
    pub attester_slashings: VariableList<AttesterSlashing, U2>,
    pub attestations: VariableList<Attestation, U128>,
    pub deposits: VariableList<Deposit, U16>,
    pub voluntary_exits: VariableList<SignedVoluntaryExit, U16>,
    pub sync_aggregate: SyncAggregate,
    #[superstruct(only(Bellatrix), partial_getter(rename = "execution_payload_merge"))]
    pub execution_payload: ExecutionPayloadBellatrix,
    #[superstruct(only(Capella), partial_getter(rename = "execution_payload_capella"))]
    pub execution_payload: ExecutionPayloadCapella,
    #[superstruct(only(Capella))]
    pub bls_to_execution_changes:
        VariableList<SignedBlsToExecutionChange, MaxBlsToExecutionChanges>,
}

impl BeaconBlockBody {
    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Bellatrix => {
                BeaconBlockBodyBellatrix::from_ssz_bytes(bytes).map(Self::Bellatrix)
            }
            ForkName::Capella => BeaconBlockBodyCapella::from_ssz_bytes(bytes).map(Self::Capella),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Decode, Encode, TreeHash)]
pub struct SyncAggregate {
    pub sync_committee_bits: BitVector<typenum::U512>,
    pub sync_committee_signature: BlsSignature,
}

pub type Transaction = ByteList1G;
pub type Transactions = VariableList<Transaction, typenum::U1048576>;

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Decode, Encode, TreeHash)]
pub struct ProposerSlashing {
    pub signed_header_1: SignedBeaconBlockHeader,
    pub signed_header_2: SignedBeaconBlockHeader,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Decode, Encode, TreeHash)]
pub struct SignedBeaconBlockHeader {
    pub message: BeaconBlockHeader,
    pub signature: BlsSignature,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Decode, Encode, TreeHash)]
pub struct AttesterSlashing {
    pub attestation_1: IndexedAttestation,
    pub attestation_2: IndexedAttestation,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Decode, Encode, TreeHash)]
pub struct Attestation {
    pub aggregation_bits: BitList<typenum::U2048>,
    pub data: AttestationData,
    pub signature: BlsSignature,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Decode, Encode, TreeHash)]
pub struct Deposit {
    pub proof: FixedVector<H256, U33>,
    pub data: DepositData,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Decode, Encode, TreeHash)]
pub struct DepositData {
    pub pubkey: PubKey,
    pub withdrawal_credentials: H256,
    pub amount: u64,
    pub signature: BlsSignature,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Decode, Encode, TreeHash)]
pub struct IndexedAttestation {
    pub attesting_indices: VariableList<u64, typenum::U2048>,
    pub data: AttestationData,
    pub signature: BlsSignature,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Decode, Encode, TreeHash)]
pub struct AttestationData {
    pub slot: u64,
    pub index: u64,
    pub beacon_block_root: H256,
    pub source: Checkpoint,
    pub target: Checkpoint,
}

#[derive(Debug, PartialEq, Clone, Copy, Deserialize, Serialize, Decode, Encode, TreeHash)]
pub struct Checkpoint {
    pub epoch: Epoch,
    pub root: H256,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Decode, Encode, TreeHash)]
pub struct SignedVoluntaryExit {
    pub message: VoluntaryExit,
    pub signature: BlsSignature,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Decode, Encode, TreeHash)]
pub struct VoluntaryExit {
    pub epoch: Epoch,
    #[serde(deserialize_with = "as_u64")]
    pub validator_index: u64,
}

#[derive(Debug, PartialEq, Clone, Default, Deserialize, Serialize, Decode, Encode, TreeHash)]
pub struct Eth1Data {
    pub deposit_root: H256,
    pub deposit_count: u64,
    pub block_hash: H256,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct SignedBlsToExecutionChange {
    pub message: BlsToExecutionChange,
    pub signature: BlsSignature,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct BlsToExecutionChange {
    #[serde(deserialize_with = "as_u64")]
    pub validator_index: u64,
    pub from_bls_pubkey: PubKey,
    pub to_execution_address: Address,
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
            "../test_assets/beacon/bellatrix/BeaconBlockBody/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let body: BeaconBlockBodyBellatrix = serde_json::from_value(value.clone()).unwrap();
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
            "../test_assets/beacon/bellatrix/BeaconBlockBody/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let body: BeaconBlockBodyBellatrix = serde_json::from_value(value).unwrap();

        let compressed = std::fs::read(format!(
            "../test_assets/beacon/bellatrix/BeaconBlockBody/ssz_random/{case}/serialized.ssz_snappy"
        ))
        .expect("cannot find test asset");
        let mut decoder = snap::raw::Decoder::new();
        let expected = decoder.decompress_vec(&compressed).unwrap();
        BeaconBlockBody::from_ssz_bytes(&expected, ForkName::Bellatrix).unwrap();
        assert_eq!(body.as_ssz_bytes(), expected);
    }
}
