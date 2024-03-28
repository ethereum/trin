use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use ssz::SszEncoder;
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, VariableList};
use tree_hash_derive::TreeHash;

/// Types sourced from Fluffy:
/// https://github.com/status-im/nimbus-eth1/blob/77135e70015de77d9ca46b196d99dc260ed3e364/fluffy/network/history/experimental/beacon_chain_block_proof.nim

//BeaconBlockBodyProof* = array[8, Digest]
pub type BeaconBlockBodyProof = [B256; 8];

//BeaconBlockHeaderProof* = array[3, Digest]
pub type BeaconBlockHeaderProof = [B256; 3];

//HistoricalRootsProof* = array[14, Digest]
pub type BeaconBlockHistoricalRootsProof = [B256; 14];

//# Total size (8 + 1 + 3 + 1 + 14) * 32 bytes + 4 bytes = 868 bytes
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconChainBlockProof {
    pub beacon_block_body_proof: BeaconBlockBodyProof,
    pub beacon_block_body_root: B256,
    pub beacon_block_header_proof: BeaconBlockHeaderProof,
    pub beacon_block_header_root: B256,
    pub historical_roots_proof: BeaconBlockHistoricalRootsProof,
    pub slot: u64,
}

/// `HistoricalSummary` matches the components of the phase0 `HistoricalBatch`
/// making the two hash_tree_root-compatible. This struct is introduced into the beacon state
/// in the Capella hard fork.
///
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/capella/beacon-chain.md#historicalsummary
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Decode, Encode, TreeHash)]
pub struct HistoricalSummary {
    block_summary_root: B256,
    state_summary_root: B256,
}

type HistoricalSummaries = VariableList<HistoricalSummary, typenum::U16777216>;

/// Proof against the beacon state root hash
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoricalSummariesProof {
    pub proof: [B256; 5],
}

impl Default for HistoricalSummariesProof {
    fn default() -> Self {
        Self {
            proof: [B256::ZERO; 5],
        }
    }
}

impl ssz::Decode for HistoricalSummariesProof {
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

impl ssz::Encode for HistoricalSummariesProof {
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
    pub proof: HistoricalSummariesProof,
}

// TODO: Add test vectors for HistoricalSummariesWithProof
