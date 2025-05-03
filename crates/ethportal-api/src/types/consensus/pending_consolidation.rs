use serde::{Deserialize, Serialize};
use serde_this_or_that::as_u64;
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct PendingConsolidation {
    #[serde(deserialize_with = "as_u64")]
    pub source_index: u64,
    #[serde(deserialize_with = "as_u64")]
    pub target_index: u64,
}
