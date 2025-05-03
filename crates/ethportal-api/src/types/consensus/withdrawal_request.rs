use alloy::{eips::eip7002::WITHDRAWAL_REQUEST_TYPE, primitives::Address};
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_u64;
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use crate::consensus::pubkey::PubKey;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct WithdrawalRequest {
    pub source_address: Address,
    pub validator_pubkey: PubKey,
    #[serde(deserialize_with = "as_u64")]
    pub amount: u64,
}

impl WithdrawalRequest {
    pub const REQUEST_TYPE: u8 = WITHDRAWAL_REQUEST_TYPE;
}
