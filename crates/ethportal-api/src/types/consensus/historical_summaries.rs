use alloy::primitives::B256;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, FixedVector, VariableList};
use superstruct::superstruct;
use tree_hash_derive::TreeHash;

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

pub type HistoricalSummaries = VariableList<HistoricalSummary, typenum::U16777216>;

pub const HISTORICAL_SUMMARIES_GINDEX_DENEB: usize = 59;
pub const HISTORICAL_SUMMARIES_GINDEX_ELECTRA: usize = 91;

pub type HistoricalSummariesProofDeneb = FixedVector<B256, typenum::U5>;
pub type HistoricalSummariesProofElectra = FixedVector<B256, typenum::U6>;

/// A historical summaries BeaconState field with proof.
#[superstruct(
    variants(Deneb, Electra),
    variant_attributes(
        derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode,),
        serde(deny_unknown_fields),
    )
)]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Encode)]
#[serde(untagged)]
#[ssz(enum_behaviour = "transparent")]
pub struct HistoricalSummariesWithProof {
    pub epoch: u64,
    pub historical_summaries: HistoricalSummaries,
    #[superstruct(only(Deneb), partial_getter(rename = "proof_deneb"))]
    pub proof: HistoricalSummariesProofDeneb,
    #[superstruct(only(Electra), partial_getter(rename = "proof_electra"))]
    pub proof: HistoricalSummariesProofElectra,
}
