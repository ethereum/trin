use alloy::{
    consensus::{constants::KECCAK_EMPTY, EMPTY_ROOT_HASH},
    primitives::{B256, U256},
    rlp::{RlpDecodable, RlpEncodable},
};
use serde::{Deserialize, Serialize};

/// The Account State stored in the state trie.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable, Serialize, Deserialize)]
pub struct AccountState {
    pub nonce: u64,
    pub balance: U256,
    pub storage_root: B256,
    pub code_hash: B256,
}

impl Default for AccountState {
    fn default() -> Self {
        Self {
            nonce: 0,
            balance: U256::ZERO,
            storage_root: EMPTY_ROOT_HASH,
            code_hash: KECCAK_EMPTY,
        }
    }
}
