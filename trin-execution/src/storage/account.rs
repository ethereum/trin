use alloy_primitives::{keccak256, B256, U256};
use alloy_rlp::{RlpDecodable, RlpEncodable, EMPTY_STRING_CODE};
use ethportal_api::types::state_trie::account_state::AccountState as AccountStateInfo;
use revm_primitives::{AccountInfo, KECCAK_EMPTY};

/// The Account State stored in the state trie.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct Account {
    pub nonce: u64,
    pub balance: U256,
    pub storage_root: B256,
    pub code_hash: B256,
}

impl Default for Account {
    fn default() -> Self {
        Self {
            nonce: 0,
            balance: U256::ZERO,
            storage_root: keccak256([EMPTY_STRING_CODE]),
            code_hash: KECCAK_EMPTY,
        }
    }
}

impl From<&Account> for AccountStateInfo {
    fn from(account: &Account) -> Self {
        Self {
            nonce: account.nonce,
            balance: account.balance,
            storage_root: account.storage_root,
            code_hash: account.code_hash,
        }
    }
}

impl From<AccountInfo> for Account {
    fn from(account_info: AccountInfo) -> Self {
        Self {
            nonce: account_info.nonce,
            balance: account_info.balance,
            storage_root: keccak256([EMPTY_STRING_CODE]),
            code_hash: account_info.code_hash,
        }
    }
}
