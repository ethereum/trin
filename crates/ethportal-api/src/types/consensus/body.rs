use alloy::primitives::{Address, B256};
use discv5::enr::k256::elliptic_curve::consts::U16;
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
use crate::{
    consensus::{
        beacon_state::Epoch,
        execution_payload::{
            ExecutionPayloadBellatrix, ExecutionPayloadCapella, ExecutionPayloadDeneb,
        },
        fork::ForkName,
        kzg_commitment::KzgCommitment,
        proof::build_merkle_proof_for_index,
    },
    types::bytes::ByteList1G,
};

type MaxBlobCommitmentsPerBlock = U4096;
type MaxBLSToExecutionChanges = U16;
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
        VariableList<SignedBLSToExecutionChange, MaxBLSToExecutionChanges>,
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

impl BeaconBlockBodyCapella {
    pub fn build_execution_payload_proof(&self) -> Vec<B256> {
        let leaves = vec![
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
            self.bls_to_execution_changes.tree_hash_root().0,
        ];
        // We want to prove the 10th leaf
        build_merkle_proof_for_index(leaves, 9)
    }

    pub fn build_execution_block_hash_proof(&self) -> Vec<B256> {
        let mut block_hash_proof = self.execution_payload.build_block_hash_proof();
        let execution_payload_proof = self.build_execution_payload_proof();
        block_hash_proof.extend(execution_payload_proof);
        block_hash_proof
    }
}

impl BeaconBlockBodyBellatrix {
    pub fn build_execution_payload_proof(&self) -> Vec<B256> {
        let leaves = vec![
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
        // We want to prove the 10th leaf
        build_merkle_proof_for_index(leaves, 9)
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
    #[serde(deserialize_with = "as_u64")]
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
    #[serde(deserialize_with = "as_u64")]
    pub slot: u64,
    #[serde(deserialize_with = "as_u64")]
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
    #[serde(deserialize_with = "as_u64")]
    pub deposit_count: u64,
    pub block_hash: B256,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct SignedBLSToExecutionChange {
    pub message: BLSToExecutionChange,
    pub signature: BlsSignature,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct BLSToExecutionChange {
    #[serde(deserialize_with = "as_u64")]
    pub validator_index: u64,
    pub from_bls_pubkey: PubKey,
    pub to_execution_address: Address,
}
