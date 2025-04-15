use alloy::primitives::B256;
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_u64;
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use crate::consensus::{pubkey::PubKey, signature::BlsSignature};

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct DepositRequest {
    pub pubkey: PubKey,
    pub withdrawal_credentials: B256,
    #[serde(deserialize_with = "as_u64")]
    pub amount: u64,
    pub signature: BlsSignature,
    #[serde(deserialize_with = "as_u64")]
    pub index: u64,
}
