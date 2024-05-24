use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, FixedVector, VariableList};
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
pub type HistoricalSummariesStateProof = FixedVector<B256, typenum::U5>;

/// A historical summaries BeaconState field with proof.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct HistoricalSummariesWithProof {
    pub epoch: u64,
    pub historical_summaries: HistoricalSummaries,
    pub proof: HistoricalSummariesStateProof,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use crate::consensus::{
        beacon_state::BeaconStateDeneb,
        historical_summaries::{HistoricalSummariesStateProof, HistoricalSummariesWithProof},
    };
    use serde_json::Value;
    use ssz::{Decode, Encode};

    #[test]
    fn test_historical_summaries_with_proof_deneb() {
        let value = std::fs::read_to_string(
            "../test_assets/beacon/deneb/BeaconState/ssz_random/case_0/value.yaml",
        )
        .expect("cannot find test asset");
        let value: Value = serde_yaml::from_str(&value).unwrap();
        let beacon_state: BeaconStateDeneb = serde_json::from_value(value).unwrap();
        let historical_summaries_proof = beacon_state.build_historical_summaries_proof();
        let historical_summaries_state_proof =
            HistoricalSummariesStateProof::from(historical_summaries_proof);
        let historical_summaries = beacon_state.historical_summaries.clone();

        let historical_summaries_epoch = beacon_state.slot / 32;

        let expected_summaries_with_proof = HistoricalSummariesWithProof {
            epoch: historical_summaries_epoch,
            historical_summaries,
            proof: historical_summaries_state_proof.clone(),
        };

        // Test ssz encoding and decoding
        let ssz_bytes = expected_summaries_with_proof.as_ssz_bytes();
        let historical_summaries_with_proof =
            HistoricalSummariesWithProof::from_ssz_bytes(&ssz_bytes).unwrap();
        assert_eq!(
            expected_summaries_with_proof,
            historical_summaries_with_proof
        );
    }
}
