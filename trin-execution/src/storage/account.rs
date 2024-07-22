use alloy_consensus::EMPTY_ROOT_HASH;
use alloy_primitives::{B256, U256};
use alloy_rlp::{RlpDecodable, RlpEncodable};
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
            storage_root: EMPTY_ROOT_HASH,
            code_hash: KECCAK_EMPTY,
        }
    }
}

impl From<AccountStateInfo> for Account {
    fn from(account: AccountStateInfo) -> Self {
        Self {
            nonce: account.nonce,
            balance: account.balance,
            storage_root: account.storage_root,
            code_hash: account.code_hash,
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

impl Account {
    pub fn from_account_info(account: AccountInfo, storage_root: B256) -> Self {
        Self {
            nonce: account.nonce,
            balance: account.balance,
            storage_root,
            code_hash: account.code_hash,
        }
    }
}
