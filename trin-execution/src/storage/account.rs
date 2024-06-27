use alloy_primitives::{keccak256, B256, U256};
use alloy_rlp::{Buf, Decodable, Encodable, RlpDecodable, RlpEncodable, EMPTY_STRING_CODE};
use ethportal_api::types::state_trie::account_state::AccountState as AccountStateInfo;
use revm_primitives::KECCAK_EMPTY;

/// The Account State stored in the state trie.
#[derive(Debug, Clone, PartialEq, Eq, RlpEncodable, RlpDecodable)]
pub struct Account {
    pub nonce: u64,
    pub balance: U256,
    pub storage_root: B256,
    pub code_hash: B256,
    /// If account is self destructed or newly created, storage will be cleared.
    pub account_state: AccountState,
}

impl Default for Account {
    fn default() -> Self {
        Self {
            nonce: 0,
            balance: U256::ZERO,
            storage_root: keccak256([EMPTY_STRING_CODE]),
            code_hash: KECCAK_EMPTY,
            account_state: AccountState::default(),
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub enum AccountState {
    /// Before Spurious Dragon hardfork there was a difference between empty and not existing.
    /// And we are flagging it here.
    NotExisting,
    /// EVM touched this account. For newer hardfork this means it can be cleared/removed from
    /// state.
    Touched,
    /// EVM cleared storage of this account, mostly by selfdestruct, we don't ask database for
    /// storage slots and assume they are U256::ZERO
    StorageCleared,
    /// EVM didn't interacted with this account
    #[default]
    None,
}

impl Encodable for AccountState {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        match self {
            AccountState::NotExisting => out.put_u8(0),
            AccountState::Touched => out.put_u8(1),
            AccountState::StorageCleared => out.put_u8(2),
            AccountState::None => out.put_u8(3),
        }
    }
}

impl Decodable for AccountState {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let account_state = AccountState::try_from(buf[0])
            .map_err(|_| alloy_rlp::Error::Custom("Unknown transaction id"))?;
        buf.advance(1);
        Ok(account_state)
    }
}

impl TryFrom<u8> for AccountState {
    type Error = alloy_rlp::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(AccountState::NotExisting),
            1 => Ok(AccountState::Touched),
            2 => Ok(AccountState::StorageCleared),
            3 => Ok(AccountState::None),
            _ => Err(alloy_rlp::Error::Custom("Invalid AccountState byte")),
        }
    }
}

impl AccountState {
    /// Returns `true` if EVM cleared storage of this account
    pub fn is_storage_cleared(&self) -> bool {
        matches!(self, AccountState::StorageCleared)
    }
}
