use std::path::PathBuf;

use alloy::primitives::{B256, U256};
use anyhow::anyhow;
use ethportal_api::types::execution::{
    accumulator::EpochAccumulator, header::Header,
    header_with_proof_new::BlockProofHistoricalHashesAccumulator,
};
use serde::{Deserialize, Serialize};
use ssz::Decode;
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, VariableList};
use tree_hash_derive::TreeHash;

use crate::{
    constants::{EPOCH_SIZE, MERGE_BLOCK_NUMBER},
    merkle::proof::MerkleTree,
    TrinValidationAssets,
};

/// SSZ List[Hash256, max_length = MAX_HISTORICAL_EPOCHS]
/// List of historical epoch accumulator merkle roots preceding current epoch.
pub type HistoricalEpochRoots = VariableList<tree_hash::Hash256, typenum::U131072>;

/// SSZ Container
/// Primary datatype used to maintain record of historical and current epoch.
/// Verifies canonical-ness of a given header.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq, Deserialize, Serialize, TreeHash)]
pub struct PreMergeAccumulator {
    pub historical_epochs: HistoricalEpochRoots,
}

impl Default for PreMergeAccumulator {
    fn default() -> Self {
        let raw = TrinValidationAssets::get("validation_assets/merge_macc.bin")
            .expect("Unable to find default pre-merge accumulator");
        PreMergeAccumulator::from_ssz_bytes(raw.data.as_ref())
            .expect("Unable to decode default pre-merge accumulator")
    }
}

impl PreMergeAccumulator {
    /// Load default trusted pre-merge acc
    pub fn try_from_file(pre_merge_acc_path: PathBuf) -> anyhow::Result<PreMergeAccumulator> {
        let raw = TrinValidationAssets::get(&(*pre_merge_acc_path).display().to_string()[..])
            .ok_or_else(|| {
                anyhow!("Unable to find pre-merge accumulator at path: {pre_merge_acc_path:?}")
            })?;
        PreMergeAccumulator::from_ssz_bytes(raw.data.as_ref())
            .map_err(|err| anyhow!("Unable to decode pre-merge accumulator: {err:?}"))
    }

    /// Number of the last block to be included in the accumulator
    pub fn height(&self) -> u64 {
        MERGE_BLOCK_NUMBER
    }

    pub(crate) fn get_epoch_index_of_header(&self, header: &Header) -> u64 {
        header.number / EPOCH_SIZE
    }

    pub fn construct_proof(
        header: &Header,
        epoch_acc: &EpochAccumulator,
    ) -> anyhow::Result<BlockProofHistoricalHashesAccumulator> {
        // Validate header hash matches historical hash from epoch accumulator
        let hr_index = (header.number % EPOCH_SIZE) as usize;
        let header_record = epoch_acc[hr_index];
        if header_record.block_hash != header.hash() {
            return Err(anyhow!(
                "Block hash doesn't match historical header hash found in epoch acc."
            ));
        }

        // Create a merkle tree from epoch accumulator.
        // To construct a valid proof for the header hash, we add a leaf of
        // hash(header, total difficulty) for each header record at a depth of 13.
        // This must be done to support generating valid proofs for partial
        // epochs, as opposed to adding the header and total difficulty as individual
        // leaves on a tree of depth 14.
        //
        // Then we re-insert the total difficulty as the first element
        // in the proof to be able to prove the header hash.
        //
        // convert total difficulty to B256
        let header_difficulty = B256::from(header_record.total_difficulty.to_le_bytes());
        // calculate hash of the header record
        let header_record_hash = B256::from_slice(&ethereum_hashing::hash32_concat(
            header_record.block_hash.as_slice(),
            header_difficulty.as_slice(),
        ));
        // iterate over every header record in the epoch acc to create the leaves
        let leaves = epoch_acc
            .iter()
            .map(|record| {
                B256::from_slice(&ethereum_hashing::hash32_concat(
                    record.block_hash.as_slice(),
                    record.total_difficulty.as_le_slice(),
                ))
            })
            .collect::<Vec<B256>>();
        // Create the merkle tree from leaves
        let merkle_tree = MerkleTree::create(&leaves, 13);

        // Generating the proof for the value at hr_index (leaf)
        let (leaf, mut proof) = merkle_tree
            .generate_proof(hr_index, 13)
            .map_err(|err| anyhow!("Unable to generate proof for given index: {err:?}"))?;

        // Validate that the value the proof is for (leaf) == hash(header, total_difficulty)
        assert_eq!(leaf, header_record_hash);

        // Re-insert the total difficulty as the first element in the proof
        proof.insert(0, header_difficulty);

        // Add the be encoded EPOCH_SIZE to proof to comply with ssz merkleization spec
        // https://github.com/ethereum/consensus-specs/blob/dev/ssz/merkle-proofs.md#ssz-object-to-index
        let epoch_size = B256::from(U256::from(epoch_acc.len()).to_le_bytes());
        proof.push(epoch_size);

        let final_proof: [B256; 15] = proof
            .try_into()
            .map_err(|_| anyhow!("Invalid proof length."))?;
        Ok(
            BlockProofHistoricalHashesAccumulator::new(final_proof.to_vec())
                .expect("[B256; 15] should convert to FixedVector<B256, U15>"),
        )
    }
}
