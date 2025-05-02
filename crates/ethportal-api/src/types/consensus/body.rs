use alloy::primitives::{Address, B256};
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_u64;
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use ssz_types::{
    typenum,
    typenum::{U1, U128, U131072, U16, U2, U2048, U33, U4096, U64, U8},
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
            ExecutionPayloadElectra,
        },
        execution_requests::ExecutionRequests,
        fork::ForkName,
        kzg_commitment::KzgCommitment,
        proof::build_merkle_proof_for_index,
    },
    types::bytes::ByteList1G,
};

pub type KzgCommitments = VariableList<KzgCommitment, MaxBlobCommitmentsPerBlock>;
type MaxBlobCommitmentsPerBlock = U4096;
type MaxBLSToExecutionChanges = U16;
type MaxCommitteesPerSlot = U64;
type MaxValidatorsPerCommittee = U2048;
type MaxValidatorsPerSlot = U131072;

/// Types based off specs @
/// https://github.com/ethereum/consensus-specs/blob/5970ae56a1cd50ea06049d8aad6bed74093d49d3/specs/bellatrix/beacon-chain.md
#[superstruct(
    variants(Bellatrix, Capella, Deneb, Electra),
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
    #[superstruct(
        only(Bellatrix, Capella, Deneb),
        partial_getter(rename = "attester_slashings_base")
    )]
    pub attester_slashings: VariableList<AttesterSlashingBase, U2>,
    #[superstruct(only(Electra), partial_getter(rename = "attester_slashings_electra"))]
    pub attester_slashings: VariableList<AttesterSlashingElectra, U1>,
    #[superstruct(
        only(Bellatrix, Capella, Deneb),
        partial_getter(rename = "attestations_base")
    )]
    pub attestations: VariableList<AttestationBase, U128>,
    #[superstruct(only(Electra), partial_getter(rename = "attestations_electra"))]
    pub attestations: VariableList<AttestationElectra, U8>,
    pub deposits: VariableList<Deposit, U16>,
    pub voluntary_exits: VariableList<SignedVoluntaryExit, U16>,
    pub sync_aggregate: SyncAggregate,
    #[superstruct(only(Bellatrix), partial_getter(rename = "execution_payload_merge"))]
    pub execution_payload: ExecutionPayloadBellatrix,
    #[superstruct(only(Capella), partial_getter(rename = "execution_payload_capella"))]
    pub execution_payload: ExecutionPayloadCapella,
    #[superstruct(only(Deneb), partial_getter(rename = "execution_payload_deneb"))]
    pub execution_payload: ExecutionPayloadDeneb,
    #[superstruct(only(Electra), partial_getter(rename = "execution_payload_electra"))]
    pub execution_payload: ExecutionPayloadElectra,
    #[superstruct(only(Capella, Deneb, Electra))]
    pub bls_to_execution_changes:
        VariableList<SignedBLSToExecutionChange, MaxBLSToExecutionChanges>,
    #[superstruct(only(Deneb, Electra))]
    pub blob_kzg_commitments: KzgCommitments,
    #[superstruct(only(Electra))]
    pub execution_requests: ExecutionRequests,
}

impl BeaconBlockBody {
    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, ssz::DecodeError> {
        match fork_name {
            ForkName::Bellatrix => {
                BeaconBlockBodyBellatrix::from_ssz_bytes(bytes).map(Self::Bellatrix)
            }
            ForkName::Capella => BeaconBlockBodyCapella::from_ssz_bytes(bytes).map(Self::Capella),
            ForkName::Deneb => BeaconBlockBodyDeneb::from_ssz_bytes(bytes).map(Self::Deneb),
            ForkName::Electra => BeaconBlockBodyElectra::from_ssz_bytes(bytes).map(Self::Electra),
        }
    }
}

impl BeaconBlockBodyBellatrix {
    pub fn build_execution_payload_proof(&self) -> Vec<B256> {
        let leaves = [
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
}

impl BeaconBlockBodyCapella {
    pub fn build_execution_payload_proof(&self) -> Vec<B256> {
        let leaves = [
            self.randao_reveal.tree_hash_root(),
            self.eth1_data.tree_hash_root(),
            self.graffiti.tree_hash_root(),
            self.proposer_slashings.tree_hash_root(),
            self.attester_slashings.tree_hash_root(),
            self.attestations.tree_hash_root(),
            self.deposits.tree_hash_root(),
            self.voluntary_exits.tree_hash_root(),
            self.sync_aggregate.tree_hash_root(),
            self.execution_payload.tree_hash_root(),
            self.bls_to_execution_changes.tree_hash_root(),
        ];
        // We want to prove the 10th leaf
        build_merkle_proof_for_index(leaves, 9)
    }
}

impl BeaconBlockBodyDeneb {
    pub fn build_execution_payload_proof(&self) -> Vec<B256> {
        let leaves = [
            self.randao_reveal.tree_hash_root(),
            self.eth1_data.tree_hash_root(),
            self.graffiti.tree_hash_root(),
            self.proposer_slashings.tree_hash_root(),
            self.attester_slashings.tree_hash_root(),
            self.attestations.tree_hash_root(),
            self.deposits.tree_hash_root(),
            self.voluntary_exits.tree_hash_root(),
            self.sync_aggregate.tree_hash_root(),
            self.execution_payload.tree_hash_root(),
            self.bls_to_execution_changes.tree_hash_root(),
            self.blob_kzg_commitments.tree_hash_root(),
        ];
        // We want to prove the 10th leaf
        build_merkle_proof_for_index(leaves, 9)
    }
}

impl BeaconBlockBodyElectra {
    pub fn build_execution_payload_proof(&self) -> Vec<B256> {
        let leaves = [
            self.randao_reveal.tree_hash_root(),
            self.eth1_data.tree_hash_root(),
            self.graffiti.tree_hash_root(),
            self.proposer_slashings.tree_hash_root(),
            self.attester_slashings.tree_hash_root(),
            self.attestations.tree_hash_root(),
            self.deposits.tree_hash_root(),
            self.voluntary_exits.tree_hash_root(),
            self.sync_aggregate.tree_hash_root(),
            self.execution_payload.tree_hash_root(),
            self.bls_to_execution_changes.tree_hash_root(),
            self.blob_kzg_commitments.tree_hash_root(),
            self.execution_requests.tree_hash_root(),
        ];
        // We want to prove the 10th leaf
        build_merkle_proof_for_index(leaves, 9)
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

#[superstruct(
    variants(Base, Electra),
    variant_attributes(derive(
        Debug,
        Clone,
        PartialEq,
        Serialize,
        Deserialize,
        Encode,
        Decode,
        TreeHash,
    ))
)]
#[derive(Debug, Clone, PartialEq, Serialize, Encode, Decode, Deserialize, TreeHash)]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
#[serde(untagged)]
pub struct AttesterSlashing {
    #[superstruct(only(Base), partial_getter(rename = "attestation_1_base"))]
    pub attestation_1: IndexedAttestationBase,
    #[superstruct(only(Electra), partial_getter(rename = "attestation_1_electra"))]
    pub attestation_1: IndexedAttestationElectra,
    #[superstruct(only(Base), partial_getter(rename = "attestation_2_base"))]
    pub attestation_2: IndexedAttestationBase,
    #[superstruct(only(Electra), partial_getter(rename = "attestation_2_electra"))]
    pub attestation_2: IndexedAttestationElectra,
}

#[superstruct(
    variants(Base, Electra),
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
#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Decode, Encode, TreeHash)]
#[ssz(enum_behaviour = "transparent")]
#[tree_hash(enum_behaviour = "transparent")]
#[serde(untagged)]
pub struct Attestation {
    #[superstruct(only(Base), partial_getter(rename = "aggregation_bits_base"))]
    pub aggregation_bits: BitList<MaxValidatorsPerCommittee>,
    #[superstruct(only(Electra), partial_getter(rename = "aggregation_bits_electra"))]
    pub aggregation_bits: BitList<MaxValidatorsPerSlot>,
    pub data: AttestationData,
    pub signature: BlsSignature,
    #[superstruct(only(Electra))]
    pub committee_bits: BitVector<MaxCommitteesPerSlot>,
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

#[superstruct(
    variants(Base, Electra),
    variant_attributes(derive(
        Debug,
        Clone,
        Serialize,
        Deserialize,
        Decode,
        PartialEq,
        Encode,
        TreeHash,
    ),)
)]
#[derive(Debug, PartialEq, Clone, Deserialize, Serialize, Decode, Encode, TreeHash)]
#[serde(untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
pub struct IndexedAttestation {
    #[superstruct(only(Base), partial_getter(rename = "attesting_indices_base"))]
    #[serde(with = "ssz_types::serde_utils::quoted_u64_var_list")]
    // #[serde(deserialize_with = "ssz_types::serde_utils::quoted_u64_var_list::deserialize")]
    pub attesting_indices: VariableList<u64, MaxValidatorsPerCommittee>,
    #[superstruct(only(Electra), partial_getter(rename = "attesting_indices_electra"))]
    #[serde(with = "ssz_types::serde_utils::quoted_u64_var_list")]
    // #[serde(deserialize_with = "ssz_types::serde_utils::quoted_u64_var_list::deserialize")]
    pub attesting_indices: VariableList<u64, MaxValidatorsPerSlot>,
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
