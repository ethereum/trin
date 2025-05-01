use serde::{Deserialize, Serialize};
use serde_this_or_that::as_u64;
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use crate::consensus::beacon_state::Epoch;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct PendingPartialWithdrawal {
    #[serde(deserialize_with = "as_u64")]
    pub validator_index: u64,
    #[serde(deserialize_with = "as_u64")]
    pub amount: u64,
    pub withdrawable_epoch: Epoch,
}
