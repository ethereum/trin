use std::sync::Arc;

use crate::{
    config::StateConfig,
    metrics::{
        start_timer_vec, stop_timer, BUNDLE_COMMIT_PROCESSING_TIMES, TRANSACTION_PROCESSING_TIMES,
    },
    storage::error::EVMError,
};
use alloy_consensus::EMPTY_ROOT_HASH;
use alloy_primitives::{Address, B256, U256};
use alloy_rlp::Decodable;
use eth_trie::{EthTrie, RootWithTrieDiff, Trie};
use ethportal_api::types::state_trie::account_state::AccountState as AccountStateInfo;
use hashbrown::{HashMap as BrownHashMap, HashSet};
use parking_lot::Mutex;
use prometheus_exporter::prometheus::HistogramTimer;
use revm::{
    db::{states::PlainStorageChangeset, BundleState, OriginalValuesKnown},
    Database, DatabaseRef,
};
use revm_primitives::{keccak256, AccountInfo, Bytecode, HashMap, KECCAK_EMPTY};
use rocksdb::DB as RocksDB;
use tracing::info;

use super::{
    account::Account as RocksAccount, account_db::AccountDB, execution_position::ExecutionPosition,
    trie_db::TrieRocksDB,
};

fn start_commit_timer(name: &str) -> HistogramTimer {
    start_timer_vec(&BUNDLE_COMMIT_PROCESSING_TIMES, &[name])
}

fn start_processing_timer(name: &str) -> HistogramTimer {
    start_timer_vec(&TRANSACTION_PROCESSING_TIMES, &[name])
}

#[derive(Debug, Clone)]
pub struct EvmDB {
    /// State config
    pub config: StateConfig,
    /// Storage cache for the accounts used optionally for gossiping, keyed by address hash.
    pub storage_cache: HashMap<B256, HashSet<B256>>,
    /// The underlying database.
    pub db: Arc<RocksDB>,
    /// To get proofs and to verify trie state.
    pub trie: Arc<Mutex<EthTrie<TrieRocksDB>>>,
}

impl EvmDB {
    pub fn new(
        config: StateConfig,
        db: Arc<RocksDB>,
        execution_position: &ExecutionPosition,
    ) -> anyhow::Result<Self> {
        db.put(KECCAK_EMPTY, Bytecode::new().bytes().as_ref())?;
        db.put(B256::ZERO, Bytecode::new().bytes().as_ref())?;

        let trie = Arc::new(Mutex::new(
            if execution_position.state_root() == EMPTY_ROOT_HASH {
                EthTrie::new(Arc::new(TrieRocksDB::new(false, db.clone())))
            } else {
                EthTrie::from(
                    Arc::new(TrieRocksDB::new(false, db.clone())),
                    execution_position.state_root(),
                )?
            },
        ));

        let storage_cache = HashMap::new();
        Ok(Self {
            config,
            storage_cache,
            db,
            trie,
        })
    }

    pub fn get_storage_trie_diff(&self, address_hash: B256) -> BrownHashMap<B256, Vec<u8>> {
        let mut trie_diff = BrownHashMap::new();

        for key in self
            .storage_cache
            .get(&address_hash)
            .unwrap_or(&HashSet::new())
        {
            // storage trie keys are prefixed with the address hash in the database
            let value = self
                .db
                .get(
                    [address_hash.as_slice(), key.as_slice()]
                        .concat()
                        .as_slice(),
                )
                .expect("Getting storage value should never fail");

            if let Some(raw_value) = value {
                trie_diff.insert(*key, raw_value);
            }
        }
        trie_diff
    }

    fn commit_account(
        &mut self,
        address_hash: B256,
        account_info: AccountInfo,
    ) -> anyhow::Result<()> {
        let plain_state_some_account_timer = start_commit_timer("account:plain_state_some_account");

        let timer = start_commit_timer("account:fetch_account_from_db");
        let raw_account = self.db.get(address_hash)?.unwrap_or_default();
        stop_timer(timer);

        let rocks_account = if !raw_account.is_empty() {
            let decoded_account = RocksAccount::decode(&mut raw_account.as_slice())?;
            RocksAccount::from_account_info(account_info, decoded_account.storage_root)
        } else {
            RocksAccount::from_account_info(account_info, EMPTY_ROOT_HASH)
        };

        let timer = start_commit_timer("account:insert_into_trie");
        let _ = self.trie.lock().insert(
            address_hash.as_ref(),
            &alloy_rlp::encode(AccountStateInfo::from(&rocks_account)),
        );
        stop_timer(timer);

        let timer = start_commit_timer("account:put_account_into_db");
        self.db
            .put(address_hash, alloy_rlp::encode(rocks_account))?;
        stop_timer(timer);

        stop_timer(plain_state_some_account_timer);
        Ok(())
    }

    fn wipe_account_storage(
        &mut self,
        address_hash: B256,
        delete_account: bool,
        timer_label: &str,
    ) -> anyhow::Result<()> {
        // load account from db
        let Some(raw_account) = self.db.get(address_hash)? else {
            return Ok(());
        };
        let timer = start_commit_timer(timer_label);

        let mut rocks_account = RocksAccount::decode(&mut raw_account.as_slice())?;

        // wipe storage trie and db
        if rocks_account.storage_root != EMPTY_ROOT_HASH {
            let account_db = AccountDB::new(address_hash, self.db.clone());
            let mut trie = EthTrie::from(Arc::new(account_db), rocks_account.storage_root)?;
            trie.clear_trie_from_db()?;
            rocks_account.storage_root = EMPTY_ROOT_HASH;
        }

        // update account trie and db
        if delete_account {
            self.db.delete(address_hash)?;
            let _ = self.trie.lock().remove(address_hash.as_ref());
        } else {
            self.db
                .put(address_hash, alloy_rlp::encode(&rocks_account))?;
            let _ = self.trie.lock().insert(
                address_hash.as_ref(),
                &alloy_rlp::encode(AccountStateInfo::from(&rocks_account)),
            );
        }

        stop_timer(timer);
        Ok(())
    }

    fn commit_accounts(
        &mut self,
        plain_account: Vec<(Address, Option<AccountInfo>)>,
    ) -> anyhow::Result<()> {
        for (address, account) in plain_account {
            let address_hash = keccak256(address);
            if let Some(account_info) = account {
                self.commit_account(address_hash, account_info)?;
            } else {
                self.wipe_account_storage(address_hash, true, "account:delete_account")?;
            }
        }
        Ok(())
    }

    fn commit_storage_changes(
        &mut self,
        address_hash: B256,
        storage: Vec<(U256, U256)>,
    ) -> anyhow::Result<()> {
        let timer = start_commit_timer("storage:apply_updates");

        let account_db = AccountDB::new(address_hash, self.db.clone());
        let mut rocks_account: RocksAccount = self
            .db
            .get(address_hash)?
            .map(|raw_account| {
                let rocks_account: RocksAccount = Decodable::decode(&mut raw_account.as_slice())
                    .expect("Decoding account should never fail");
                rocks_account
            })
            .unwrap_or_default();

        let mut trie = if rocks_account.storage_root == EMPTY_ROOT_HASH {
            EthTrie::new(Arc::new(account_db))
        } else {
            EthTrie::from(Arc::new(account_db), rocks_account.storage_root)?
        };

        for (key, value) in storage {
            let trie_key = keccak256(B256::from(key));
            if value.is_zero() {
                trie.remove(trie_key.as_ref())?;
            } else {
                trie.insert(trie_key.as_ref(), &alloy_rlp::encode(value))?;
            }
        }

        // update trie
        let RootWithTrieDiff {
            root: storage_root,
            trie_diff,
        } = trie.root_hash_with_changed_nodes()?;

        if self.config.cache_contract_storage_changes {
            let account_storage_cache = self.storage_cache.entry(address_hash).or_default();
            for key in trie_diff.keys() {
                account_storage_cache.insert(*key);
            }
        }

        rocks_account.storage_root = storage_root;

        let _ = self.trie.lock().insert(
            address_hash.as_ref(),
            &alloy_rlp::encode(AccountStateInfo::from(&rocks_account)),
        );

        self.db
            .put(address_hash, alloy_rlp::encode(rocks_account))?;
        stop_timer(timer);
        Ok(())
    }

    fn commit_storage(&mut self, plain_storage: Vec<PlainStorageChangeset>) -> anyhow::Result<()> {
        for PlainStorageChangeset {
            address,
            wipe_storage,
            storage,
        } in plain_storage
        {
            let plain_state_storage_timer = start_commit_timer("storage:plain_state_storage");

            let address_hash = keccak256(address);

            if wipe_storage {
                self.wipe_account_storage(address_hash, false, "storage:wipe_storage")?;
            }

            if !storage.is_empty() {
                // review comment: note that commit_storage_changes would have to load RocksAccount
                // from db this means that it's possible that we will have to load
                // it twice but I think it's quite uncommon, to have both
                // wipe_storage and non-empty storage, so I don't think it's big
                // deal
                self.commit_storage_changes(address_hash, storage)?;
            }
            stop_timer(plain_state_storage_timer);
        }
        Ok(())
    }

    pub fn commit_bundle(&mut self, bundle_state: BundleState) -> anyhow::Result<()> {
        // Currently we don't use reverts, so we can ignore them, but they are here for when we do.
        let timer = start_commit_timer("generate_plain_state_and_reverts");
        let (plain_state, _reverts) =
            bundle_state.into_plain_state_and_reverts(OriginalValuesKnown::Yes);
        stop_timer(timer);

        info!(
            "Committing bundle state with {} accounts, {} contracts, {} storage changes",
            plain_state.accounts.len(),
            plain_state.contracts.len(),
            plain_state.storage.len()
        );

        // Write Account State
        let timer = start_commit_timer("account:committing_accounts_total");
        self.commit_accounts(plain_state.accounts)?;
        stop_timer(timer);

        // Write Contract Code
        // TODO: Delete contract code if no accounts point to it: https://github.com/ethereum/trin/issues/1428
        // This can happen in 1 of 2 cases
        // - the account is deleted and the contract code is not used by any other accounts
        // - we do a revert and the contract code is not used by any other accounts
        // The solution would require keeping a count of how many accounts point to a contract code
        // and deleting the contract code if the count is 0.
        // This is very low priority due to this issue being very rare and it not taking up much
        // storage
        let timer = start_commit_timer("contract:committing_contracts_total");
        for (hash, bytecode) in plain_state.contracts {
            let timer = start_commit_timer("committing_contract");
            self.db
                .put(hash, bytecode.original_bytes().as_ref())
                .expect("Inserting contract code should never fail");
            stop_timer(timer);
        }
        stop_timer(timer);

        // Write Storage
        let timer = start_commit_timer("storage:committing_storage_total");
        self.commit_storage(plain_state.storage)?;
        stop_timer(timer);

        Ok(())
    }
}

impl Database for EvmDB {
    type Error = EVMError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        DatabaseRef::basic_ref(&self, address)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        DatabaseRef::code_by_hash_ref(&self, code_hash)
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        DatabaseRef::storage_ref(&self, address, index)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        DatabaseRef::block_hash_ref(&self, number)
    }
}

impl DatabaseRef for EvmDB {
    type Error = EVMError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let timer = start_processing_timer("database_get_basic");
        let result = match self.db.get(keccak256(address))? {
            Some(raw_account) => {
                let account: RocksAccount = Decodable::decode(&mut raw_account.as_slice())?;

                Ok(Some(AccountInfo {
                    balance: account.balance,
                    nonce: account.nonce,
                    code_hash: account.code_hash,
                    code: None,
                }))
            }
            None => Ok(None),
        };
        stop_timer(timer);
        result
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        let timer = start_processing_timer("database_get_code_by_hash");
        let result = match self.db.get(code_hash)? {
            Some(raw_code) => Ok(Bytecode::new_raw(raw_code.into())),
            None => Err(Self::Error::NotFound("code_by_hash".to_string())),
        };
        stop_timer(timer);
        result
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let timer = start_processing_timer("database_get_storage");
        let address_hash = keccak256(address);
        let account: RocksAccount = match self.db.get(address_hash)? {
            Some(raw_account) => Decodable::decode(&mut raw_account.as_slice())?,
            None => return Err(Self::Error::NotFound("storage".to_string())),
        };
        let account_db = AccountDB::new(address_hash, self.db.clone());
        let raw_value = if account.storage_root == EMPTY_ROOT_HASH {
            None
        } else {
            let trie = EthTrie::from(Arc::new(account_db), account.storage_root)?;
            trie.get(keccak256(B256::from(index)).as_ref())?
        };
        let result = match raw_value {
            Some(raw_value) => Ok(Decodable::decode(&mut raw_value.as_slice())?),
            None => Ok(U256::ZERO),
        };
        stop_timer(timer);
        result
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        let timer = start_processing_timer("database_get_block_hash");
        let result = match self.db.get(keccak256(B256::from(U256::from(number))))? {
            Some(raw_hash) => Ok(B256::from_slice(&raw_hash)),
            None => Err(Self::Error::NotFound("block_hash".to_string())),
        };
        stop_timer(timer);
        result
    }
}
