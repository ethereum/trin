use alloy_primitives::Address;
use alloy_rlp::{RlpDecodable, RlpEncodable};
use serde::{Deserialize, Serialize};
use serde_this_or_that::as_u64;
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

#[derive(
    Debug,
    PartialEq,
    Eq,
    Hash,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
    TreeHash,
    RlpDecodable,
    RlpEncodable,
)]
#[serde(rename_all = "camelCase")]
pub struct Withdrawal {
    #[serde(deserialize_with = "as_u64")]
    pub index: u64,
    #[serde(deserialize_with = "as_u64")]
    pub validator_index: u64,
    pub address: Address,
    #[serde(deserialize_with = "as_u64")]
    pub amount: u64,
}
