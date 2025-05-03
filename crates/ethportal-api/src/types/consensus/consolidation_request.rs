use alloy::{eips::eip7251::CONSOLIDATION_REQUEST_TYPE, primitives::Address};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use tree_hash_derive::TreeHash;

use crate::consensus::pubkey::PubKey;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Encode, Decode, TreeHash)]
pub struct ConsolidationRequest {
    pub source_address: Address,
    pub source_pubkey: PubKey,
    pub target_pubkey: PubKey,
}

impl ConsolidationRequest {
    pub const REQUEST_TYPE: u8 = CONSOLIDATION_REQUEST_TYPE;
}
