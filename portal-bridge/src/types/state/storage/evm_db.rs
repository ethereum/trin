use std::{path::PathBuf, sync::Arc};

use crate::types::state::storage::error::EVMError;
use alloy_consensus::constants::KECCAK_EMPTY;
use alloy_primitives::{Address, B256, U256};
use alloy_rlp::{Decodable, EMPTY_STRING_CODE};
use eth_trie::{EthTrie, Trie};
use ethportal_api::types::state_trie::account_state::AccountState as AccountStateInfo;
use parking_lot::Mutex;
use revm::{DatabaseCommit, DatabaseRef};
use revm_primitives::{keccak256, Account, AccountInfo, Bytecode, HashMap};
use rocksdb::DB as RocksDB;

use super::{
    account::{Account as RocksAccount, AccountState as RocksAccountState},
    account_db::AccountDB,
    trie_db::TrieRocksDB,
    utils::setup_rocksdb,
};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EvmDB {
    /// The underlying database.
    pub db: Arc<RocksDB>,
    /// To get proofs and to verify trie state.
    pub trie: Arc<Mutex<EthTrie<TrieRocksDB>>>,
}

impl EvmDB {
    pub fn new(path: Option<PathBuf>) -> anyhow::Result<Self> {
        let db = Arc::new(setup_rocksdb(path)?);
        db.put(KECCAK_EMPTY, Bytecode::new().bytes().as_ref())?;
        db.put(B256::ZERO, Bytecode::new().bytes().as_ref())?;
        let trie = Arc::new(Mutex::new(EthTrie::new(Arc::new(TrieRocksDB::new(
            false,
            db.clone(),
        )))));
        Ok(Self { db, trie })
    }

    /// Inserts the account's code into the cache.
    ///
    /// Accounts objects and code are stored separately in the cache, this will take the code from
    /// the account and instead map it to the code hash.
    ///
    /// Note: This will not insert into the underlying external database.
    pub fn insert_contract(&mut self, account: &mut AccountInfo) {
        if let Some(code) = &account.code {
            if !code.is_empty() {
                if account.code_hash == KECCAK_EMPTY {
                    account.code_hash = code.hash_slow();
                }

                self.db
                    .put(account.code_hash, code.bytes().as_ref())
                    .expect("Inserting contract shouldn't fail");
            }
        }
        if account.code_hash == B256::ZERO {
            account.code_hash = KECCAK_EMPTY;
        }
    }
}

impl DatabaseCommit for EvmDB {
    fn commit(&mut self, changes: HashMap<Address, Account>) {
        for (address, mut account) in changes {
            if !account.is_touched() {
                continue;
            }
            let address_hash = keccak256(address);
            if account.is_selfdestructed() {
                let mut rocks_account: RocksAccount = match self
                    .db
                    .get(address_hash)
                    .expect("Committing account to database should never fail")
                {
                    Some(raw_account) => Decodable::decode(&mut raw_account.as_slice())
                        .expect("Decoding account should never fail"),
                    None => RocksAccount::default(),
                };
                if rocks_account.storage_root != keccak256([EMPTY_STRING_CODE]) {
                    let account_db = AccountDB::new(address, self.db.clone());
                    let mut trie = EthTrie::from(Arc::new(account_db), rocks_account.storage_root)
                        .expect("Creating trie should never fail");
                    trie.clear_trie_from_db()
                        .expect("Clearing trie should never fail");
                }
                rocks_account = RocksAccount::default();
                rocks_account.account_state = RocksAccountState::NotExisting;
                self.db
                    .put(
                        keccak256(address.as_slice()),
                        alloy_rlp::encode(rocks_account),
                    )
                    .expect("Inserting account should never fail");

                // update trie
                let _ = self.trie.lock().remove(address_hash.as_ref());
                continue;
            }
            let is_newly_created = account.is_created();
            self.insert_contract(&mut account.info);

            let mut rocks_account: RocksAccount = match self
                .db
                .get(address_hash)
                .expect("Reading account from database should never fail")
            {
                Some(raw_account) => Decodable::decode(&mut raw_account.as_slice())
                    .expect("Decoding account should never fail"),
                None => RocksAccount::default(),
            };

            rocks_account.balance = account.info.balance;
            rocks_account.nonce = account.info.nonce;
            rocks_account.code_hash = account.info.code_hash;

            let account_db = AccountDB::new(address, self.db.clone());

            let mut trie = if rocks_account.storage_root == keccak256([EMPTY_STRING_CODE]) {
                EthTrie::new(Arc::new(account_db))
            } else {
                EthTrie::from(Arc::new(account_db), rocks_account.storage_root)
                    .expect("Creating trie should never fail")
            };

            rocks_account.account_state = if is_newly_created {
                if rocks_account.storage_root != keccak256([EMPTY_STRING_CODE]) {
                    trie.clear_trie_from_db()
                        .expect("Clearing trie should never fail");
                };

                RocksAccountState::StorageCleared
            } else if rocks_account.account_state.is_storage_cleared() {
                // Preserve old account state if it already exists
                RocksAccountState::StorageCleared
            } else {
                RocksAccountState::Touched
            };

            for (key, value) in account
                .storage
                .into_iter()
                .filter(|(_, value)| value.is_changed())
            {
                if value.present_value() > U256::ZERO {
                    let _ = trie.insert(
                        keccak256(B256::from(key)).as_ref(),
                        &alloy_rlp::encode(value.present_value()),
                    );
                } else {
                    let _ = trie.remove(keccak256(B256::from(key)).as_ref());
                }
            }

            // update trie
            let storage_root = trie
                .root_hash()
                .expect("Getting the root hash should never fail");

            let _ = self.trie.lock().insert(
                address_hash.as_ref(),
                &alloy_rlp::encode(AccountStateInfo {
                    nonce: rocks_account.nonce,
                    balance: rocks_account.balance,
                    storage_root,
                    code_hash: rocks_account.code_hash,
                }),
            );
            rocks_account.storage_root = storage_root;

            self.db
                .put(
                    keccak256(address.as_slice()),
                    alloy_rlp::encode(rocks_account),
                )
                .expect("Inserting account should never fail");
        }
    }
}

impl DatabaseRef for EvmDB {
    type Error = EVMError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        match self.db.get(keccak256(address))? {
            Some(raw_account) => {
                let account: RocksAccount = Decodable::decode(&mut raw_account.as_slice())?;

                if account.account_state == RocksAccountState::NotExisting {
                    return Ok(None);
                }

                Ok(Some(AccountInfo {
                    balance: account.balance,
                    nonce: account.nonce,
                    code_hash: account.code_hash,
                    code: None,
                }))
            }
            None => Ok(None),
        }
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        match self.db.get(code_hash)? {
            Some(raw_code) => Ok(Bytecode::new_raw(raw_code.into())),
            None => Err(Self::Error::NotFound),
        }
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let account: RocksAccount = match self.db.get(keccak256(address))? {
            Some(raw_account) => Decodable::decode(&mut raw_account.as_slice())?,
            None => return Err(Self::Error::NotFound),
        };
        let account_db = AccountDB::new(address, self.db.clone());
        let trie = if account.storage_root == keccak256([EMPTY_STRING_CODE]) {
            EthTrie::new(Arc::new(account_db))
        } else {
            EthTrie::from(Arc::new(account_db), account.storage_root)?
        };
        match trie.get(keccak256(B256::from(index)).as_ref())? {
            Some(raw_value) => Ok(Decodable::decode(&mut raw_value.as_slice())?),
            None => {
                if matches!(
                    account.account_state,
                    RocksAccountState::StorageCleared | RocksAccountState::NotExisting
                ) {
                    Ok(U256::ZERO)
                } else {
                    Err(Self::Error::NotFound)
                }
            }
        }
    }

    fn block_hash_ref(&self, number: U256) -> Result<B256, Self::Error> {
        match self.db.get(keccak256(B256::from(number)))? {
            Some(raw_hash) => Ok(B256::from_slice(&raw_hash)),
            None => Err(Self::Error::NotFound),
        }
    }
}
