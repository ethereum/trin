use alloy::primitives::B256;
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_u64;
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

/// Types based off specs @
/// https://github.com/ethereum/consensus-specs/blob/5970ae56a1cd50ea06049d8aad6bed74093d49d3/specs/phase0/beacon-chain.md
#[derive(
    Debug, PartialEq, Eq, Clone, Default, Serialize, Deserialize, Encode, Decode, TreeHash,
)]
pub struct BeaconBlockHeader {
    #[serde(deserialize_with = "as_u64")]
    pub slot: u64,
    #[serde(deserialize_with = "as_u64")]
    pub proposer_index: u64,
    pub parent_root: B256,
    pub state_root: B256,
    pub body_root: B256,
}
