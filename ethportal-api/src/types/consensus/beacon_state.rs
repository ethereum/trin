use crate::consensus::{
    body::{Checkpoint, Eth1Data},
    execution_payload::{
        ExecutionPayloadHeaderBellatrix, ExecutionPayloadHeaderCapella, ExecutionPayloadHeaderDeneb,
    },
    fork::ForkName,
    header::BeaconBlockHeader,
    historical_summaries::HistoricalSummaries,
    participation_flags::ParticipationFlags,
    pubkey::PubKey,
    sync_committee::SyncCommittee,
};
use alloy_primitives::B256;
use discv5::enr::k256::elliptic_curve::consts::{U1099511627776, U2048, U4, U65536, U8192};
use jsonrpsee::core::Serialize;
use rs_merkle::{algorithms::Sha256, MerkleTree};
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

pub type HistoricalRoots = VariableList<B256, HistoricalRootsLimit>;

/// The state of the `BeaconChain` at some slot.
#[superstruct(
    variants(Bellatrix, Capella, Deneb),
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
    pub slot: u64,
    #[superstruct(getter(copy))]
    pub fork: Fork,

    // History
    pub latest_block_header: BeaconBlockHeader,
    pub block_roots: FixedVector<B256, SlotsPerHistoricalRoot>,
    pub state_roots: FixedVector<B256, SlotsPerHistoricalRoot>,
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
    pub balances: VariableList<u64, ValidatorRegistryLimit>,

    // Randomness
    pub randao_mixes: FixedVector<B256, EpochsPerHistoricalVector>,

    // Slashings
    pub slashings: FixedVector<u64, EpochsPerSlashingsVector>,

    // Participation (Altair and later)
    #[superstruct(only(Bellatrix, Capella, Deneb))]
    pub previous_epoch_participation: VariableList<ParticipationFlags, ValidatorRegistryLimit>,
    #[superstruct(only(Bellatrix, Capella, Deneb))]
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
    #[superstruct(only(Bellatrix, Capella, Deneb))]
    pub inactivity_scores: VariableList<u64, ValidatorRegistryLimit>,

    // Light-client sync committees
    #[superstruct(only(Bellatrix, Capella, Deneb))]
    pub current_sync_committee: Arc<SyncCommittee>,
    #[superstruct(only(Bellatrix, Capella, Deneb))]
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

    // Capella
    #[superstruct(only(Capella, Deneb), partial_getter(copy))]
    #[serde(deserialize_with = "as_u64")]
    pub next_withdrawal_index: u64,
    #[superstruct(only(Capella, Deneb), partial_getter(copy))]
    #[serde(deserialize_with = "as_u64")]
    pub next_withdrawal_validator_index: u64,
    // Deep history valid from Capella onwards.
    #[superstruct(only(Capella, Deneb))]
    pub historical_summaries: HistoricalSummaries,
}

impl BeaconState {
    pub fn from_ssz_bytes(bytes: &[u8], fork_name: ForkName) -> Result<Self, DecodeError> {
        match fork_name {
            ForkName::Bellatrix => BeaconStateBellatrix::from_ssz_bytes(bytes).map(Self::Bellatrix),
            ForkName::Capella => BeaconStateCapella::from_ssz_bytes(bytes).map(Self::Capella),
            ForkName::Deneb => BeaconStateDeneb::from_ssz_bytes(bytes).map(Self::Deneb),
        }
    }
}

impl BeaconStateDeneb {
    pub fn build_historical_summaries_proof(&self) -> Vec<B256> {
        let mut leaves: Vec<[u8; 32]> = vec![
            self.genesis_time.tree_hash_root().0,
            self.genesis_validators_root.tree_hash_root().0,
            self.slot.tree_hash_root().0,
            self.fork.tree_hash_root().0,
            self.latest_block_header.tree_hash_root().0,
            self.block_roots.tree_hash_root().0,
            self.state_roots.tree_hash_root().0,
            self.historical_roots.tree_hash_root().0,
            self.eth1_data.tree_hash_root().0,
            self.eth1_data_votes.tree_hash_root().0,
            self.eth1_deposit_index.tree_hash_root().0,
            self.validators.tree_hash_root().0,
            self.balances.tree_hash_root().0,
            self.randao_mixes.tree_hash_root().0,
            self.slashings.tree_hash_root().0,
            self.previous_epoch_participation.tree_hash_root().0,
            self.current_epoch_participation.tree_hash_root().0,
            self.justification_bits.tree_hash_root().0,
            self.previous_justified_checkpoint.tree_hash_root().0,
            self.current_justified_checkpoint.tree_hash_root().0,
            self.finalized_checkpoint.tree_hash_root().0,
            self.inactivity_scores.tree_hash_root().0,
            self.current_sync_committee.tree_hash_root().0,
            self.next_sync_committee.tree_hash_root().0,
            self.latest_execution_payload_header.tree_hash_root().0,
            self.next_withdrawal_index.tree_hash_root().0,
            self.next_withdrawal_validator_index.tree_hash_root().0,
            self.historical_summaries.tree_hash_root().0,
        ];
        // We want to add empty leaves to make the tree a power of 2
        while leaves.len() < 32 {
            leaves.push([0; 32]);
        }

        let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        let indices_to_prove = vec![27];
        let proof = merkle_tree.proof(&indices_to_prove);
        let proog_hashes: Vec<B256> = proof
            .proof_hashes()
            .iter()
            .map(|hash| B256::from_slice(hash))
            .collect();

        proog_hashes
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
    pub block_roots: FixedVector<B256, SlotsPerHistoricalRoot>,
    pub state_roots: FixedVector<B256, SlotsPerHistoricalRoot>,
}

impl HistoricalBatch {
    pub fn build_block_root_proof(&self, block_root_index: u64) -> Vec<B256> {
        // Build block hash proof for sel.block_roots
        let leaves: Vec<[u8; 32]> = self
            .block_roots
            .iter()
            .map(|root| root.tree_hash_root().0)
            .collect();

        let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
        let indices_to_prove = vec![block_root_index as usize];
        let proof = merkle_tree.proof(&indices_to_prove);
        let mut proof_hashes: Vec<B256> = proof
            .proof_hashes()
            .iter()
            .map(|hash| B256::from_slice(hash))
            .collect();

        // To generate proof for block root anchored to the historical batch tree_hash_root, we need
        // to add the self.state_root tree_hash_root to the proof_hashes
        proof_hashes.push(self.state_roots.tree_hash_root());

        // Proof len should always be 14
        assert_eq!(proof_hashes.len(), 14);

        proof_hashes
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

    #[test]
    fn serde_beacon_state_deneb() {
        let value = std::fs::read_to_string(
            "../test_assets/beacon/deneb/BeaconState/ssz_random/case_0/value.yaml",
        )
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: BeaconStateDeneb = serde_json::from_value(value.clone()).unwrap();
        let serialized = serde_json::to_value(content).unwrap();
        assert_eq!(serialized, value);
    }

    #[test]
    fn ssz_beacon_state_deneb() {
        let value = std::fs::read_to_string(
            "../test_assets/beacon/deneb/BeaconState/ssz_random/case_0/value.yaml",
        )
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: BeaconStateDeneb = serde_json::from_value(value).unwrap();

        let compressed = std::fs::read(
            "../test_assets/beacon/deneb/BeaconState/ssz_random/case_0/serialized.ssz_snappy",
        )
        .expect("cannot find test asset");
        let mut decoder = snap::raw::Decoder::new();
        let expected = decoder.decompress_vec(&compressed).unwrap();
        BeaconState::from_ssz_bytes(&expected, ForkName::Deneb).unwrap();
        assert_eq!(content.as_ssz_bytes(), expected);
    }

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    fn serde_historical_batch(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/bellatrix/HistoricalBatch/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: HistoricalBatch = serde_json::from_value(value.clone()).unwrap();
        let serialized = serde_json::to_value(content).unwrap();
        assert_eq!(serialized, value);
    }

    #[rstest]
    #[case("case_0")]
    #[case("case_1")]
    fn ssz_historical_batch(#[case] case: &str) {
        let value = std::fs::read_to_string(format!(
            "../test_assets/beacon/bellatrix/HistoricalBatch/ssz_random/{case}/value.yaml"
        ))
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: HistoricalBatch = serde_json::from_value(value).unwrap();

        let compressed = std::fs::read(format!(
            "../test_assets/beacon/bellatrix/HistoricalBatch/ssz_random/{case}/serialized.ssz_snappy"
        ))
            .expect("cannot find test asset");
        let mut decoder = snap::raw::Decoder::new();
        let expected = decoder.decompress_vec(&compressed).unwrap();
        HistoricalBatch::from_ssz_bytes(&expected).unwrap();
        assert_eq!(content.as_ssz_bytes(), expected);
    }

    #[test]
    fn historical_batch_block_root_proof() {
        let value = std::fs::read_to_string(
            "../test_assets/beacon/bellatrix/HistoricalBatch/ssz_random/case_0/value.yaml",
        )
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let content: HistoricalBatch = serde_json::from_value(value).unwrap();

        let expected_proof = [
            "0xad500369fa624b7bb451bf1c5119bb6e5e623bab76a0d06948d04a38f35a740d",
            "0x222151dcdfbace03dd6f2428ee1a12acffaa1ce03e6966aefd4a48282a776e8e",
            "0x28319c59ca450d2fba4b3225eccd994eee98276b7c77e2c3256a3df829767112",
            "0x4cd3f3ff2891ef30542d4ae1530c90120cf7718ae936204aa5b0d67ea07957ef",
            "0xab543cef2058a48bd9d327dce1ee91ac9acf114f7c0b1762689c79b7d10bb363",
            "0x410b45ebb9351cd84dd13a888de4b04d781630df726cec7eb74814f2a00f3c6e",
            "0xd213561e8cff461aa94ee50910381ff1182e3fb90a914e17060f3c0c23522911",
            "0x84b4db81fe167dd181bcab2ca02008b22f0ab11462f8bd4547e29a6b55bb6a11",
            "0x845c6bf5051749dc6b82222c664033ae301fca96c24fd32a63fc3f5adfb1a656",
            "0x19a5290c03daf8156f6941cca8feb5b16e843220e2f9b57647a90d76a459d302",
            "0x9ca2a640c85ce719174ec29710596f3315aedb4b47044f175b2c39f35bf0d15e",
            "0xb7534aed4d180eec8ac7d961e1020028c07d0c83dcdd23f56a7920a08b7393be",
            "0xf8a36457194917609bd16697972d616d8f14e71f4fcfd64666e11544bd5f193e",
            "0x1d28097093ca99336cb6b3e8c8c34d749a3e43efc9bb6fabc2cfd6ffb1701b08",
        ]
        .map(|x| B256::from_str(x).unwrap());

        let proof = content.build_block_root_proof(0);

        assert_eq!(proof.len(), 14);
        assert_eq!(proof, expected_proof.to_vec());
    }

    #[test]
    fn beacon_state_historical_summaries_proof() {
        let value = std::fs::read_to_string(
            "../test_assets/beacon/deneb/BeaconState/ssz_random/case_0/value.yaml",
        )
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let beacon_state: BeaconStateDeneb = serde_json::from_value(value).unwrap();
        let historical_summaries_proof = beacon_state.build_historical_summaries_proof();
        assert_eq!(historical_summaries_proof.len(), 5);
    }
}
