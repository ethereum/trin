use crate::{
    consensus::{
        beacon_state::Epoch,
        execution_payload::{
            ExecutionPayloadBellatrix, ExecutionPayloadCapella, ExecutionPayloadDeneb,
        },
        fork::ForkName,
        kzg_commitment::KzgCommitment,
    },
    types::bytes::ByteList1G,
};
use alloy_primitives::{Address, B256};
use discv5::enr::k256::elliptic_curve::consts::U16;
use rs_merkle::{algorithms::Sha256, MerkleTree};
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_u64;
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use ssz_types::{
    typenum,
    typenum::{U128, U2, U33, U4096},
    BitList, BitVector, FixedVector, VariableList,
};
use superstruct::superstruct;
use tree_hash::TreeHash;
use tree_hash_derive::TreeHash;

use super::{header::BeaconBlockHeader, pubkey::PubKey, signature::BlsSignature};

type MaxBlobCommitmentsPerBlock = U4096;
type MaxBlsToExecutionChanges = U16;
pub type KzgCommitments = VariableList<KzgCommitment, MaxBlobCommitmentsPerBlock>;

/// Types based off specs @
/// https://github.com/ethereum/consensus-specs/blob/5970ae56a1cd50ea06049d8aad6bed74093d49d3/specs/bellatrix/beacon-chain.md
#[superstruct(
    variants(Bellatrix, Capella, Deneb),
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
    pub graffiti: B256,
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
    #[superstruct(only(Deneb), partial_getter(rename = "execution_payload_deneb"))]
    pub execution_payload: ExecutionPayloadDeneb,
    #[superstruct(only(Capella, Deneb))]
    pub bls_to_execution_changes:
        VariableList<SignedBlsToExecutionChange, MaxBlsToExecutionChanges>,
    #[superstruct(only(Deneb))]
    pub blob_kzg_commitments: KzgCommitments,
}

impl BeaconBlockBody {
    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Bellatrix => {
                BeaconBlockBodyBellatrix::from_ssz_bytes(bytes).map(Self::Bellatrix)
            }
            ForkName::Capella => BeaconBlockBodyCapella::from_ssz_bytes(bytes).map(Self::Capella),
            ForkName::Deneb => BeaconBlockBodyDeneb::from_ssz_bytes(bytes).map(Self::Deneb),
        }
    }
}

impl BeaconBlockBodyBellatrix {
    pub fn build_execution_payload_proof(&self) -> Vec<B256> {
        let mut leaves: Vec<[u8; 32]> = vec![
            self.randao_reveal.tree_hash_root().0,
            self.eth1_data.tree_hash_root().0,
            self.graffiti.tree_hash_root().0,
            self.proposer_slashings.tree_hash_root().0,
            self.attester_slashings.tree_hash_root().0,
            self.attestations.tree_hash_root().0,
            self.deposits.tree_hash_root().0,
            self.voluntary_exits.tree_hash_root().0,
            self.sync_aggregate.tree_hash_root().0,
            self.execution_payload.tree_hash_root().0,
        ];
        // We want to add empty leaves to make the tree a power of 2
        while leaves.len() < 16 {
            leaves.push([0; 32]);
        }

        let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);

        // We want to prove the 10th leaf
        let indices_to_prove = vec![9];
        let proof = merkle_tree.proof(&indices_to_prove);
        let proof_hashes: Vec<B256> = proof
            .proof_hashes()
            .iter()
            .map(|hash| B256::from_slice(hash))
            .collect();

        proof_hashes
    }

    pub fn build_execution_block_hash_proof(&self) -> Vec<B256> {
        let mut block_hash_proof = self.execution_payload.build_block_hash_proof();
        block_hash_proof.extend(self.build_execution_payload_proof());
        block_hash_proof
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
    pub proof: FixedVector<B256, U33>,
    pub data: DepositData,
}

#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Decode, Encode, TreeHash)]
pub struct DepositData {
    pub pubkey: PubKey,
    pub withdrawal_credentials: B256,
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
    pub beacon_block_root: B256,
    pub source: Checkpoint,
    pub target: Checkpoint,
}

#[derive(Debug, PartialEq, Clone, Copy, Deserialize, Serialize, Decode, Encode, TreeHash)]
pub struct Checkpoint {
    pub epoch: Epoch,
    pub root: B256,
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
    pub deposit_root: B256,
    pub deposit_count: u64,
    pub block_hash: B256,
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
    use std::str::FromStr;

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

    #[test]
    fn block_body_execution_payload_proof() {
        let value = std::fs::read_to_string(
            "../test_assets/beacon/bellatrix/BeaconBlockBody/ssz_random/case_0/value.yaml",
        )
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: BeaconBlockBodyBellatrix = serde_json::from_value(value).unwrap();
        let expected_execution_payload_proof = [
            "0xf5bf9e85dce9cc5f1edbed4085bf4e37da4ddec337483f847cc451f296ff0799",
            "0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
            "0xdb56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71",
            "0x38373fc5d635131b9054c0a97cf1eeb397621f2f6e54ffc54f5f2516088b87d9",
        ]
        .map(|x| B256::from_str(x).unwrap());
        let proof = content.build_execution_payload_proof();

        assert_eq!(proof.len(), 4);
        assert_eq!(proof, expected_execution_payload_proof.to_vec());

        let mut expected_block_hash_proof = [
            "0x7ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede1",
            "0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
            "0xf00e3441849a7e4228e6f48d5a5b231e153b39cb2ef283febdd9f7df1f777551",
            "0x6911c0b766b06671612d77e8f3061320f2a3471c2ba8d3f8251b53da8efb111a",
        ]
        .map(|x| B256::from_str(x).unwrap())
        .to_vec();
        let proof = content.build_execution_block_hash_proof();
        expected_block_hash_proof.extend(expected_execution_payload_proof);

        assert_eq!(proof.len(), 8);
        assert_eq!(proof, expected_block_hash_proof);
    }
}
