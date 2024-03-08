use ethereum_types::{H256, U256};
use rlp_derive::{RlpDecodable, RlpEncodable};

/// The Account State stored in the state trie.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct AccountState {
    pub nonce: u64,
    pub balance: U256,
    pub storage_root: H256,
    pub code_hash: H256,
}
