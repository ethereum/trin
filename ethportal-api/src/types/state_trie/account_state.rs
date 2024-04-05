use alloy_primitives::{B256, U256};
use alloy_rlp::{RlpDecodable, RlpEncodable};

/// The Account State stored in the state trie.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct AccountState {
    pub nonce: u64,
    pub balance: U256,
    pub storage_root: B256,
    pub code_hash: B256,
}
