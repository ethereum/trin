use std::sync::Arc;

use alloy::primitives::B256;
use jsonrpsee::core::Serialize;
use serde::Deserialize;
use serde_this_or_that::as_u64;
use serde_utils;
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{
    typenum::{U1099511627776, U134217728, U16777216, U2048, U262144, U4, U65536, U8192},
    BitVector, FixedVector, VariableList,
};
use superstruct::superstruct;
use tree_hash::{Hash256, TreeHash};
use tree_hash_derive::TreeHash;

use crate::consensus::{
    body::{Checkpoint, Eth1Data},
    execution_payload::{
        ExecutionPayloadHeaderBellatrix, ExecutionPayloadHeaderCapella,
        ExecutionPayloadHeaderDeneb, ExecutionPayloadHeaderElectra,
    },
    fork::ForkName,
    header::BeaconBlockHeader,
    historical_summaries::{HistoricalSummaries, HistoricalSummariesProof},
    participation_flags::ParticipationFlags,
    pending_balance_deposit::PendingDeposit,
    pending_consolidation::PendingConsolidation,
    pending_partial_withdrawal::PendingPartialWithdrawal,
    proof::build_merkle_proof_for_index,
    pubkey::PubKey,
    sync_committee::SyncCommittee,
};

type SlotsPerHistoricalRoot = U8192; // uint64(2**13) (= 8,192)
type HistoricalRootsLimit = U16777216; // uint64(2**24) (= 16,777,216)
type ValidatorRegistryLimit = U1099511627776;
type SlotsPerEth1VotingPeriod = U2048; // 64 epochs * 32 slots per epoch
type EpochsPerHistoricalVector = U65536;
type EpochsPerSlashingsVector = U8192;
type JustificationBitsLength = U4;

pub type RootsPerHistoricalRoot = FixedVector<B256, SlotsPerHistoricalRoot>;
pub type HistoricalRoots = VariableList<B256, HistoricalRootsLimit>;
pub type PendingDepositsLimit = U134217728;
pub type PendingPartialWithdrawalsLimit = U134217728;
pub type PendingConsolidationsLimit = U262144;

/// The state of the `BeaconChain` at some slot.
#[superstruct(
    variants(Bellatrix, Capella, Deneb, Electra),
    variant_attributes(
        derive(
            Clone,
            Debug,
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Encode, TreeHash)]
#[serde(untagged)]
#[tree_hash(enum_behaviour = "transparent")]
#[ssz(enum_behaviour = "transparent")]
pub struct BeaconState {
    // Versioning
    #[superstruct(getter(copy))]
    #[serde(deserialize_with = "as_u64")]
    pub genesis_time: u64,
    #[superstruct(getter(copy))]
    pub genesis_validators_root: B256,
    #[superstruct(getter(copy))]
    #[serde(deserialize_with = "as_u64")]
    pub slot: u64,
    #[superstruct(getter(copy))]
    pub fork: Fork,

    // History
    pub latest_block_header: BeaconBlockHeader,
    pub block_roots: RootsPerHistoricalRoot,
    pub state_roots: RootsPerHistoricalRoot,
    // Frozen in Capella, replaced by historical_summaries
    pub historical_roots: HistoricalRoots,

    // Ethereum 1.0 chain data
    pub eth1_data: Eth1Data,
    pub eth1_data_votes: VariableList<Eth1Data, SlotsPerEth1VotingPeriod>,
    #[superstruct(getter(copy))]
    #[serde(deserialize_with = "as_u64")]
    pub eth1_deposit_index: u64,

    // Registry
    pub validators: VariableList<Validator, ValidatorRegistryLimit>,
    #[serde(deserialize_with = "ssz_types::serde_utils::quoted_u64_var_list::deserialize")]
    pub balances: VariableList<u64, ValidatorRegistryLimit>,

    // Randomness
    pub randao_mixes: FixedVector<B256, EpochsPerHistoricalVector>,

    // Slashings
    #[serde(deserialize_with = "ssz_types::serde_utils::quoted_u64_fixed_vec::deserialize")]
    pub slashings: FixedVector<u64, EpochsPerSlashingsVector>,

    // Participation (Altair and later)
    #[superstruct(only(Bellatrix, Capella, Deneb, Electra))]
    pub previous_epoch_participation: VariableList<ParticipationFlags, ValidatorRegistryLimit>,
    #[superstruct(only(Bellatrix, Capella, Deneb, Electra))]
    pub current_epoch_participation: VariableList<ParticipationFlags, ValidatorRegistryLimit>,

    // Finality
    pub justification_bits: BitVector<JustificationBitsLength>,
    #[superstruct(getter(copy))]
    pub previous_justified_checkpoint: Checkpoint,
    #[superstruct(getter(copy))]
    pub current_justified_checkpoint: Checkpoint,
    #[superstruct(getter(copy))]
    pub finalized_checkpoint: Checkpoint,

    // Inactivity
    #[superstruct(only(Bellatrix, Capella, Deneb, Electra))]
    #[serde(deserialize_with = "ssz_types::serde_utils::quoted_u64_var_list::deserialize")]
    pub inactivity_scores: VariableList<u64, ValidatorRegistryLimit>,

    // Light-client sync committees
    #[superstruct(only(Bellatrix, Capella, Deneb, Electra))]
    pub current_sync_committee: Arc<SyncCommittee>,
    #[superstruct(only(Bellatrix, Capella, Deneb, Electra))]
    pub next_sync_committee: Arc<SyncCommittee>,

    // Execution
    #[superstruct(
        only(Bellatrix),
        partial_getter(rename = "latest_execution_payload_header_bellatrix")
    )]
    pub latest_execution_payload_header: ExecutionPayloadHeaderBellatrix,
    #[superstruct(
        only(Capella),
        partial_getter(rename = "latest_execution_payload_header_capella")
    )]
    pub latest_execution_payload_header: ExecutionPayloadHeaderCapella,
    #[superstruct(
        only(Deneb),
        partial_getter(rename = "latest_execution_payload_header_deneb")
    )]
    pub latest_execution_payload_header: ExecutionPayloadHeaderDeneb,
    #[superstruct(
        only(Electra),
        partial_getter(rename = "latest_execution_payload_header_electra")
    )]
    pub latest_execution_payload_header: ExecutionPayloadHeaderElectra,

    // Capella
    #[superstruct(only(Capella, Deneb, Electra), partial_getter(copy))]
    #[serde(deserialize_with = "as_u64")]
    pub next_withdrawal_index: u64,
    #[superstruct(only(Capella, Deneb, Electra), partial_getter(copy))]
    #[serde(deserialize_with = "as_u64")]
    pub next_withdrawal_validator_index: u64,
    // Deep history valid from Capella onwards.
    #[superstruct(only(Capella, Deneb, Electra))]
    pub historical_summaries: HistoricalSummaries,

    // Electra
    #[superstruct(only(Electra), partial_getter(copy))]
    #[serde(deserialize_with = "as_u64")]
    pub deposit_requests_start_index: u64,
    #[superstruct(only(Electra), partial_getter(copy))]
    #[serde(deserialize_with = "as_u64")]
    pub deposit_balance_to_consume: u64,
    #[superstruct(only(Electra), partial_getter(copy))]
    #[serde(deserialize_with = "as_u64")]
    pub exit_balance_to_consume: u64,
    #[superstruct(only(Electra), partial_getter(copy))]
    pub earliest_exit_epoch: Epoch,
    #[superstruct(only(Electra), partial_getter(copy))]
    #[serde(deserialize_with = "as_u64")]
    pub consolidation_balance_to_consume: u64,
    #[superstruct(only(Electra), partial_getter(copy))]
    pub earliest_consolidation_epoch: Epoch,
    #[superstruct(only(Electra))]
    pub pending_deposits: VariableList<PendingDeposit, PendingDepositsLimit>,
    #[superstruct(only(Electra))]
    pub pending_partial_withdrawals:
        VariableList<PendingPartialWithdrawal, PendingPartialWithdrawalsLimit>,
    #[superstruct(only(Electra))]
    pub pending_consolidations: VariableList<PendingConsolidation, PendingConsolidationsLimit>,
}

impl BeaconState {
    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, DecodeError> {
        match fork_name {
            ForkName::Bellatrix => BeaconStateBellatrix::from_ssz_bytes(bytes).map(Self::Bellatrix),
            ForkName::Capella => BeaconStateCapella::from_ssz_bytes(bytes).map(Self::Capella),
            ForkName::Deneb => BeaconStateDeneb::from_ssz_bytes(bytes).map(Self::Deneb),
            ForkName::Electra => BeaconStateElectra::from_ssz_bytes(bytes).map(Self::Electra),
        }
    }
}

impl BeaconStateDeneb {
    pub fn build_historical_summaries_proof(&self) -> Vec<B256> {
        let leaves = [
            self.genesis_time.tree_hash_root(),
            self.genesis_validators_root.tree_hash_root(),
            self.slot.tree_hash_root(),
            self.fork.tree_hash_root(),
            self.latest_block_header.tree_hash_root(),
            self.block_roots.tree_hash_root(),
            self.state_roots.tree_hash_root(),
            self.historical_roots.tree_hash_root(),
            self.eth1_data.tree_hash_root(),
            self.eth1_data_votes.tree_hash_root(),
            self.eth1_deposit_index.tree_hash_root(),
            self.validators.tree_hash_root(),
            self.balances.tree_hash_root(),
            self.randao_mixes.tree_hash_root(),
            self.slashings.tree_hash_root(),
            self.previous_epoch_participation.tree_hash_root(),
            self.current_epoch_participation.tree_hash_root(),
            self.justification_bits.tree_hash_root(),
            self.previous_justified_checkpoint.tree_hash_root(),
            self.current_justified_checkpoint.tree_hash_root(),
            self.finalized_checkpoint.tree_hash_root(),
            self.inactivity_scores.tree_hash_root(),
            self.current_sync_committee.tree_hash_root(),
            self.next_sync_committee.tree_hash_root(),
            self.latest_execution_payload_header.tree_hash_root(),
            self.next_withdrawal_index.tree_hash_root(),
            self.next_withdrawal_validator_index.tree_hash_root(),
            self.historical_summaries.tree_hash_root(),
        ];

        build_merkle_proof_for_index(leaves, 27)
    }
}

impl BeaconStateElectra {
    pub fn build_historical_summaries_proof(&self) -> HistoricalSummariesProof {
        let leaves = [
            self.genesis_time.tree_hash_root(),
            self.genesis_validators_root.tree_hash_root(),
            self.slot.tree_hash_root(),
            self.fork.tree_hash_root(),
            self.latest_block_header.tree_hash_root(),
            self.block_roots.tree_hash_root(),
            self.state_roots.tree_hash_root(),
            self.historical_roots.tree_hash_root(),
            self.eth1_data.tree_hash_root(),
            self.eth1_data_votes.tree_hash_root(),
            self.eth1_deposit_index.tree_hash_root(),
            self.validators.tree_hash_root(),
            self.balances.tree_hash_root(),
            self.randao_mixes.tree_hash_root(),
            self.slashings.tree_hash_root(),
            self.previous_epoch_participation.tree_hash_root(),
            self.current_epoch_participation.tree_hash_root(),
            self.justification_bits.tree_hash_root(),
            self.previous_justified_checkpoint.tree_hash_root(),
            self.current_justified_checkpoint.tree_hash_root(),
            self.finalized_checkpoint.tree_hash_root(),
            self.inactivity_scores.tree_hash_root(),
            self.current_sync_committee.tree_hash_root(),
            self.next_sync_committee.tree_hash_root(),
            self.latest_execution_payload_header.tree_hash_root(),
            self.next_withdrawal_index.tree_hash_root(),
            self.next_withdrawal_validator_index.tree_hash_root(),
            self.historical_summaries.tree_hash_root(),
            self.deposit_requests_start_index.tree_hash_root(),
            self.deposit_balance_to_consume.tree_hash_root(),
            self.exit_balance_to_consume.tree_hash_root(),
            self.earliest_exit_epoch.tree_hash_root(),
            self.consolidation_balance_to_consume.tree_hash_root(),
            self.earliest_consolidation_epoch.tree_hash_root(),
            self.pending_deposits.tree_hash_root(),
            self.pending_partial_withdrawals.tree_hash_root(),
            self.pending_consolidations.tree_hash_root(),
        ];

        HistoricalSummariesProof::new(build_merkle_proof_for_index(leaves, 27))
            .expect("Created historical summaries proof for Electra should have correct length")
    }
}

/// Specifies a fork of the `BeaconChain`, to prevent replay attacks.
///
/// Spec v0.12.1
#[derive(
    Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize, Encode, Decode, TreeHash,
)]
pub struct Fork {
    #[serde(with = "serde_utils::bytes_4_hex")]
    pub previous_version: [u8; 4],
    #[serde(with = "serde_utils::bytes_4_hex")]
    pub current_version: [u8; 4],
    pub epoch: Epoch,
}

#[derive(
    Clone, Debug, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct Epoch(#[serde(deserialize_with = "as_u64")] u64);

impl Encode for Epoch {
    fn is_ssz_fixed_len() -> bool {
        <u64 as Encode>::is_ssz_fixed_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.0.ssz_append(buf)
    }

    fn ssz_fixed_len() -> usize {
        <u64 as Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        0_u64.ssz_bytes_len()
    }
}

impl Decode for Epoch {
    fn is_ssz_fixed_len() -> bool {
        <u64 as Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <u64 as Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(u64::from_ssz_bytes(bytes)?))
    }
}

impl TreeHash for Epoch {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::Basic
    }

    fn tree_hash_packed_encoding(&self) -> tree_hash::PackedEncoding {
        self.0.tree_hash_packed_encoding()
    }

    fn tree_hash_packing_factor() -> usize {
        32usize.wrapping_div(8)
    }

    fn tree_hash_root(&self) -> Hash256 {
        Hash256::from_slice(&int_to_fixed_bytes32(self.0))
    }
}

/// Returns `int` as little-endian bytes with a length of 32.
pub fn int_to_fixed_bytes32(int: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    let int_bytes = int.to_le_bytes();
    bytes[0..int_bytes.len()].copy_from_slice(&int_bytes);
    bytes
}

/// Information about a `BeaconChain` validator.
///
/// Spec v0.12.1
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct Validator {
    pub pubkey: PubKey,
    pub withdrawal_credentials: B256,
    #[serde(deserialize_with = "as_u64")]
    pub effective_balance: u64,
    pub slashed: bool,
    pub activation_eligibility_epoch: Epoch,
    pub activation_epoch: Epoch,
    pub exit_epoch: Epoch,
    pub withdrawable_epoch: Epoch,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct HistoricalBatch {
    pub block_roots: RootsPerHistoricalRoot,
    pub state_roots: RootsPerHistoricalRoot,
}

impl HistoricalBatch {
    pub fn build_block_root_proof(&self, block_root_index: usize) -> Vec<B256> {
        // Build block hash proof for self.block_roots
        let mut proof_hashes =
            build_merkle_proof_for_index(self.block_roots.clone(), block_root_index);

        // To generate proof for block root anchored to the historical batch tree_hash_root, we need
        // to add the self.state_root tree_hash_root to the proof_hashes
        proof_hashes.push(self.state_roots.tree_hash_root());

        // Proof len should always be 14
        assert_eq!(proof_hashes.len(), 14);

        proof_hashes
    }
}
