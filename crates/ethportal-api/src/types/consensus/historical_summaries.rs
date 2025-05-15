use alloy::primitives::B256;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, FixedVector, VariableList};
use tree_hash_derive::TreeHash;

use super::constants::{CAPELLA_FORK_EPOCH, SLOTS_PER_EPOCH, SLOTS_PER_HISTORICAL_ROOT};

/// The Generalized Index of the `historical_summaries` field of the
/// [BeaconState](super::beacon_state::BeaconState), for Electra fork.
pub const HISTORICAL_SUMMARIES_GINDEX: usize = 91;

/// `HistoricalSummary` matches the components of the phase0 `HistoricalBatch`
/// making the two hash_tree_root-compatible. This struct is introduced into the beacon state
/// in the Capella hard fork.
///
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/capella/beacon-chain.md#historicalsummary
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Decode, Encode, TreeHash)]
pub struct HistoricalSummary {
    pub block_summary_root: B256,
    pub state_summary_root: B256,
}

/// The historical list of [HistoricalSummary].
///
/// This correspond to the `historical_summaries` field of the
/// [BeaconState](super::beacon_state::BeaconState).
pub type HistoricalSummaries = VariableList<HistoricalSummary, typenum::U16777216>;

/// The merkle proof of the `historical_summaries` field of the
/// [BeaconState](super::beacon_state::BeaconState).
pub type HistoricalSummariesProof = FixedVector<B256, typenum::U6>;

/// The `historical_summaries` field of the BeaconState, with proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct HistoricalSummariesWithProof {
    pub epoch: u64,
    pub historical_summaries: HistoricalSummaries,
    pub proof: HistoricalSummariesProof,
}

/// Calculates the index of a [HistoricalSummary] in [HistoricalSummaries] for a given slot.
///
/// Returns `None` is slot is before Capella fork.
pub fn historical_summary_index(slot: u64) -> Option<usize> {
    let capella_slot = CAPELLA_FORK_EPOCH * SLOTS_PER_EPOCH;
    if slot < capella_slot {
        None
    } else {
        Some(((slot - capella_slot) / SLOTS_PER_HISTORICAL_ROOT) as usize)
    }
}
