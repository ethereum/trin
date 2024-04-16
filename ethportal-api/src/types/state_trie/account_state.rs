use alloy_primitives::{keccak256, B256, U256};
use alloy_rlp::{RlpDecodable, RlpEncodable, EMPTY_STRING_CODE};
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
            storage_root: keccak256([EMPTY_STRING_CODE]),
            code_hash: keccak256([]),
        }
    }
}
