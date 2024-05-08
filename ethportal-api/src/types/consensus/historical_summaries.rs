use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use ssz::SszEncoder;
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, VariableList};
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

/// Proof against the beacon state root hash
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoricalSummariesStateProof {
    pub proof: [B256; 5],
}

impl Default for HistoricalSummariesStateProof {
    fn default() -> Self {
        Self {
            proof: [B256::ZERO; 5],
        }
    }
}

impl ssz::Decode for HistoricalSummariesStateProof {
    fn is_ssz_fixed_len() -> bool {
        true
    }
    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let vec: Vec<[u8; 32]> = Vec::from_ssz_bytes(bytes)?;
        let mut proof = Self::default().proof;
        let raw_proof: [[u8; 32]; 5] = vec.try_into().map_err(|_| {
            ssz::DecodeError::BytesInvalid(format!(
                "Invalid length of bytes for HistoricalSummariesProof: {}",
                bytes.len()
            ))
        })?;
        for (i, item) in raw_proof.iter().enumerate() {
            proof[i] = B256::from_slice(item);
        }
        Ok(Self { proof })
    }
}

impl ssz::Encode for HistoricalSummariesStateProof {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let offset = self.ssz_bytes_len();
        let mut encoder = SszEncoder::container(buf, offset);

        for proof in self.proof {
            encoder.append(&proof);
        }
        encoder.finalize();
    }

    fn ssz_fixed_len() -> usize {
        32 * 5
    }

    fn ssz_bytes_len(&self) -> usize {
        32 * 5
    }
}

/// A historical summaries BeaconState field with proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct HistoricalSummariesWithProof {
    pub epoch: u64,
    pub historical_summaries: HistoricalSummaries,
    pub proof: HistoricalSummariesStateProof,
}

// TODO: Add test vectors for HistoricalSummariesWithProof
