use crate::consensus::{
    body::{Checkpoint, Eth1Data},
    execution_payload::{ExecutionPayloadHeaderBellatrix, ExecutionPayloadHeaderCapella},
    fork::ForkName,
    header::BeaconBlockHeader,
    header_proof::HistoricalSummary,
    participation_flags::ParticipationFlags,
    pubkey::PubKey,
    sync_committee::SyncCommittee,
};
use discv5::enr::k256::elliptic_curve::consts::{U1099511627776, U2048, U4, U65536, U8192};
use ethereum_types::H256;
use jsonrpsee::core::Serialize;
use serde::Deserialize;
use serde_this_or_that::as_u64;
use serde_utils;
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum::U16777216, BitVector, FixedVector, VariableList};
use std::sync::Arc;
use superstruct::superstruct;
use tree_hash::{Hash256, TreeHash};
use tree_hash_derive::TreeHash;

type SlotsPerHistoricalRoot = U8192; // uint64(2**13) (= 8,192)
type HistoricalRootsLimit = U16777216; // uint64(2**24) (= 16,777,216)
type ValidatorRegistryLimit = U1099511627776;
type SlotsPerEth1VotingPeriod = U2048; // 64 epochs * 32 slots per epoch
type EpochsPerHistoricalVector = U65536;
type EpochsPerSlashingsVector = U8192;
type JustificationBitsLength = U4;

/// The state of the `BeaconChain` at some slot.
#[superstruct(
    variants(Bellatrix, Capella),
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
    pub genesis_validators_root: H256,
    #[superstruct(getter(copy))]
    pub slot: u64,
    #[superstruct(getter(copy))]
    pub fork: Fork,

    // History
    pub latest_block_header: BeaconBlockHeader,
    pub block_roots: FixedVector<H256, SlotsPerHistoricalRoot>,
    pub state_roots: FixedVector<H256, SlotsPerHistoricalRoot>,
    // Frozen in Capella, replaced by historical_summaries
    pub historical_roots: VariableList<H256, HistoricalRootsLimit>,

    // Ethereum 1.0 chain data
    pub eth1_data: Eth1Data,
    pub eth1_data_votes: VariableList<Eth1Data, SlotsPerEth1VotingPeriod>,
    #[superstruct(getter(copy))]
    #[serde(deserialize_with = "as_u64")]
    pub eth1_deposit_index: u64,

    // Registry
    pub validators: VariableList<Validator, ValidatorRegistryLimit>,
    pub balances: VariableList<u64, ValidatorRegistryLimit>,

    // Randomness
    pub randao_mixes: FixedVector<H256, EpochsPerHistoricalVector>,

    // Slashings
    pub slashings: FixedVector<u64, EpochsPerSlashingsVector>,

    // Participation (Altair and later)
    #[superstruct(only(Bellatrix, Capella))]
    pub previous_epoch_participation: VariableList<ParticipationFlags, ValidatorRegistryLimit>,
    #[superstruct(only(Bellatrix, Capella))]
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
    #[superstruct(only(Bellatrix, Capella))]
    pub inactivity_scores: VariableList<u64, ValidatorRegistryLimit>,

    // Light-client sync committees
    #[superstruct(only(Bellatrix, Capella))]
    pub current_sync_committee: Arc<SyncCommittee>,
    #[superstruct(only(Bellatrix, Capella))]
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

    // Capella
    #[superstruct(only(Capella), partial_getter(copy))]
    #[serde(deserialize_with = "as_u64")]
    pub next_withdrawal_index: u64,
    #[superstruct(only(Capella), partial_getter(copy))]
    #[serde(deserialize_with = "as_u64")]
    pub next_withdrawal_validator_index: u64,
    // Deep history valid from Capella onwards.
    #[superstruct(only(Capella))]
    pub historical_summaries: VariableList<HistoricalSummary, HistoricalRootsLimit>,
}

impl BeaconState {
    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, DecodeError> {
        match fork_name {
            ForkName::Bellatrix => BeaconStateBellatrix::from_ssz_bytes(bytes).map(Self::Bellatrix),
            ForkName::Capella => BeaconStateCapella::from_ssz_bytes(bytes).map(Self::Capella),
        }
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
    pub withdrawal_credentials: H256,
    #[serde(deserialize_with = "as_u64")]
    pub effective_balance: u64,
    pub slashed: bool,
    pub activation_eligibility_epoch: Epoch,
    pub activation_epoch: Epoch,
    pub exit_epoch: Epoch,
    pub withdrawable_epoch: Epoch,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use ::ssz::Encode;
    use rstest::rstest;
    use serde_json::Value;

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    fn serde_beacon_state_bellatrix(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/bellatrix/BeaconState/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: BeaconStateBellatrix = serde_json::from_value(value.clone()).unwrap();
        let serialized = serde_json::to_value(content).unwrap();
        assert_eq!(serialized, value);
    }

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    fn ssz_beacon_state_bellatrix(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/bellatrix/BeaconState/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: BeaconStateBellatrix = serde_json::from_value(value).unwrap();

        let compressed = std::fs::read(format!(
            "../test_assets/beacon/bellatrix/BeaconState/ssz_random/{case}/serialized.ssz_snappy"
        ))
        .expect("cannot find test asset");
        let mut decoder = snap::raw::Decoder::new();
        let expected = decoder.decompress_vec(&compressed).unwrap();
        BeaconState::from_ssz_bytes(&expected, ForkName::Bellatrix).unwrap();
        assert_eq!(content.as_ssz_bytes(), expected);
    }

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    fn serde_beacon_state_capella(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/capella/BeaconState/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: BeaconStateCapella = serde_json::from_value(value.clone()).unwrap();
        let serialized = serde_json::to_value(content).unwrap();
        assert_eq!(serialized, value);
    }

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    fn ssz_beacon_state_capella(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/capella/BeaconState/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: BeaconStateCapella = serde_json::from_value(value).unwrap();

        let compressed = std::fs::read(format!(
            "../test_assets/beacon/capella/BeaconState/ssz_random/{case}/serialized.ssz_snappy"
        ))
        .expect("cannot find test asset");
        let mut decoder = snap::raw::Decoder::new();
        let expected = decoder.decompress_vec(&compressed).unwrap();
        BeaconState::from_ssz_bytes(&expected, ForkName::Capella).unwrap();
        assert_eq!(content.as_ssz_bytes(), expected);
    }
}
