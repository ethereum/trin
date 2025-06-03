use std::sync::Arc;

use alloy::{
    consensus::EMPTY_ROOT_HASH,
    primitives::{keccak256, map::FbHashMap, Address, B256, U256},
    rlp::Decodable,
};
use eth_trie::{EthTrie, RootWithTrieDiff, Trie};
use ethportal_api::types::state_trie::account_state::AccountState;
use hashbrown::{HashMap as BrownHashMap, HashSet};
use parking_lot::Mutex;
use prometheus_exporter::prometheus::HistogramTimer;
use revm::{
    database::{states::PlainStorageChangeset, BundleState, OriginalValuesKnown},
    state::{AccountInfo, Bytecode},
    Database, DatabaseRef,
};
use revm_primitives::KECCAK_EMPTY;
use redb::{Database as ReDB, Table, TableDefinition};
use tracing::info;

use super::{account_db::AccountDB, execution_position::ExecutionPosition, trie_db::TrieReDB};
use crate::{
    config::StateConfig,
    metrics::{
        start_timer_vec, stop_timer, BUNDLE_COMMIT_PROCESSING_TIMES, TRANSACTION_PROCESSING_TIMES,
    },
    storage::error::EVMError,
};

pub const ACCOUNTS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("accounts");
pub const CONTRACTS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("contracts");
pub const STORAGE_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("storage");
pub const BLOCK_HASHES_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("block_hashes");

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
    /// Storage cache for the accounts required for gossiping stat diffs, keyed by address hash.
    storage_cache: Arc<Mutex<FbHashMap<32, HashSet<B256>>>>,
    /// Cache for newly created contracts required for gossiping stat diffs, keyed by code hash.
    newly_created_contracts: Arc<Mutex<FbHashMap<32, Bytecode>>>,
    /// The underlying database.
    pub db: Arc<ReDB>,
    /// To get proofs and to verify trie state.
    pub trie: Arc<Mutex<EthTrie<TrieReDB>>>,
} 

impl EvmDB {
    pub fn new(
        config: StateConfig,
        db: Arc<ReDB>,
        execution_position: &ExecutionPosition,
    ) -> anyhow::Result<Self> {
        // Initialize empty byte code in the database       
        let txn = db.begin_write()?;
        {
            let mut contracts_table = txn.open_table(CONTRACTS_TABLE)?;
            let empty_bytecode = Bytecode::new().bytes();
            contracts_table.insert(KECCAK_EMPTY.as_slice(), empty_bytecode.as_ref())?;
            contracts_table.insert(B256::ZERO.as_slice(), empty_bytecode.as_ref())?;
        }
        txn.commit()?;
        
        // db.put(KECCAK_EMPTY, Bytecode::new().bytes().as_ref())?;
        // db.put(B256::ZERO, Bytecode::new().bytes().as_ref())?;

        let trie = Arc::new(Mutex::new(
            if execution_position.state_root() == EMPTY_ROOT_HASH {
                EthTrie::new(Arc::new(TrieReDB::new(false, db.clone())))
            } else {
                EthTrie::from(
                    Arc::new(TrieReDB::new(false, db.clone())),
                    execution_position.state_root(),
                )?
            },
        ));

        let storage_cache = Arc::new(Mutex::new(FbHashMap::default()));
        let newly_created_contracts = Arc::new(Mutex::new(FbHashMap::default()));
        Ok(Self {
            config,
            storage_cache,
            newly_created_contracts,
            db,
            trie,
        })
    }

    pub fn get_storage_trie_diff(&self, address_hash: B256) -> BrownHashMap<B256, Vec<u8>> {
        let mut trie_diff = BrownHashMap::new();

        let txn = self.db.begin_read().expect("Redb read transaction failed");
        let storage_table = txn.open_table(STORAGE_TABLE).expect("Failed to open Redb storage table");

        for key in self
            .storage_cache
            .lock()
            .get(&address_hash)
            .unwrap_or(&HashSet::new())
        {
            let mut full_key = [0u8; 64];
            full_key[..32].copy_from_slice(address_hash.as_slice());
            full_key[32..].copy_from_slice(key.as_slice());

            if let Ok(Some(value)) = storage_table.get(&full_key[..]) {
                trie_diff.insert(*key, value.value().to_vec());
            }
        }
        trie_diff
    }

    pub fn get_newly_created_contract(&self, code_hash: B256) -> Option<Bytecode> {
        self.newly_created_contracts.lock().get(&code_hash).cloned()
    }

    pub fn clear_contract_cache(&self) {
        self.storage_cache.lock().clear();
        self.newly_created_contracts.lock().clear();
    }

    fn commit_account(
        &mut self,
        address_hash: B256,
        account_info: AccountInfo,
    ) -> anyhow::Result<()> {
        let plain_state_some_account_timer = start_commit_timer("account:plain_state_some_account");

        let timer = start_commit_timer("account:fetch_account_from_db");
        let existing_account_state = self.fetch_account(address_hash)?;
        stop_timer(timer);

        let account_state = if let Some(existing_account_state) = existing_account_state {
            AccountState {
                balance: account_info.balance,
                nonce: account_info.nonce,
                code_hash: account_info.code_hash,
                storage_root: existing_account_state.storage_root,
            }
        } else {
            AccountState {
                balance: account_info.balance,
                nonce: account_info.nonce,
                code_hash: account_info.code_hash,
                storage_root: EMPTY_ROOT_HASH,
            }
        };

        let timer = start_commit_timer("account:insert_into_trie");
        let _ = self
            .trie
            .lock()
            .insert(address_hash.as_ref(), &alloy::rlp::encode(&account_state));
        stop_timer(timer);

        let timer = start_commit_timer("account:put_account_into_db");
        {
            let txn = self.db.begin_write()?;
            {
                let mut table: Table<&[u8], &[u8]> = txn.open_table(ACCOUNTS_TABLE)?;
                let key: &[u8] = address_hash.as_slice();
                let value: Vec<u8> = alloy::rlp::encode(&account_state);
                table.insert(key, value.as_slice())?;
            }
            txn.commit()?;
        }
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
        let Some(mut account_state) = self.fetch_account(address_hash)? else {
            return Ok(());
        };
        let timer = start_commit_timer(timer_label);

        // wipe storage trie and db
        if account_state.storage_root != EMPTY_ROOT_HASH {
            let account_db = AccountDB::new(address_hash, self.db.clone())?;
            let mut trie = EthTrie::from(Arc::new(account_db), account_state.storage_root)?;
            trie.clear_trie_from_db()?;
            account_state.storage_root = EMPTY_ROOT_HASH;
        }

        // update account trie and db
        if delete_account {
            let txn = self.db.begin_write()?;
            {
                let mut table = txn.open_table(ACCOUNTS_TABLE)?;
                table.remove(address_hash.as_slice())?;
            }
            txn.commit()?;

            let _ = self.trie.lock().remove(address_hash.as_ref());
        } else {
            let txn = self.db.begin_write()?;
            {
                let mut table = txn.open_table(ACCOUNTS_TABLE)?;
                table.insert(address_hash.as_slice(), alloy::rlp::encode(&account_state).as_slice())?;
            }
            txn.commit()?;

            let _ = self
                .trie
                .lock()
                .insert(address_hash.as_ref(), &alloy::rlp::encode(&account_state));
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

        let account_db = AccountDB::new(address_hash, self.db.clone())?;
        let mut account_state = self.fetch_account(address_hash)?.unwrap_or_default();

        let mut trie = if account_state.storage_root == EMPTY_ROOT_HASH {
            EthTrie::new(Arc::new(account_db))
        } else {
            EthTrie::from(Arc::new(account_db), account_state.storage_root)?
        };

        for (key, value) in storage {
            let trie_key = keccak256(B256::from(key));
            if value.is_zero() {
                trie.remove(trie_key.as_ref())?;
            } else {
                trie.insert(trie_key.as_ref(), &alloy::rlp::encode(value))?;
            }
        }

        // update trie
        let RootWithTrieDiff {
            root: storage_root,
            trie_diff,
        } = trie.root_hash_with_changed_nodes()?;

        if self.config.cache_contract_changes {
            let mut storage_cache_guard = self.storage_cache.lock();
            let account_storage_cache = storage_cache_guard.entry(address_hash).or_default();
            for key in trie_diff.keys() {
                account_storage_cache.insert(*key);
            }
        }

        account_state.storage_root = storage_root;

        let _ = self
            .trie
            .lock()
            .insert(address_hash.as_ref(), &alloy::rlp::encode(&account_state));

        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(ACCOUNTS_TABLE)?;
            table.insert(address_hash.as_slice(), alloy::rlp::encode(&account_state).as_slice())?;
        }
        txn.commit()?;
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
            bundle_state.to_plain_state_and_reverts(OriginalValuesKnown::Yes);
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
        let timer = start_commit_timer("contract:committing_contracts_total");
        for (hash, bytecode) in plain_state.contracts {
            // Cache contract code for gossiping if flag is set
            if self.config.cache_contract_changes {
                self.newly_created_contracts
                    .lock()
                    .insert(hash, bytecode.clone());
            }
            let timer = start_commit_timer("committing_contract");

            let txn = self.db.begin_write()?;
            {
                let mut table = txn.open_table(CONTRACTS_TABLE)?;
                table.insert(hash.as_slice(), bytecode.original_bytes().as_ref()).expect("Inserting contract code should never fail");
            }
            txn.commit()?;
            
            stop_timer(timer);
        }
        stop_timer(timer);

        // Write Storage
        let timer = start_commit_timer("storage:committing_storage_total");
        self.commit_storage(plain_state.storage)?;
        stop_timer(timer);

        Ok(())
    }

    fn fetch_account(&self, address_hash: B256) -> anyhow::Result<Option<AccountState>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(ACCOUNTS_TABLE)?;

        if let Some(raw_account) = table.get(address_hash.as_slice())? {
            let decoded = AccountState::decode(&mut raw_account.value())?;
            Ok(Some(decoded))
        } else {
            Ok(None)
        }
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
        let result = match self.fetch_account(keccak256(address))? {
            Some(account) => Ok(Some(AccountInfo {
                balance: account.balance,
                nonce: account.nonce,
                code_hash: account.code_hash,
                code: None,
            })),
            None => Ok(None),
        };
        stop_timer(timer);
        result
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        let timer = start_processing_timer("database_get_code_by_hash");

        let txn = self.db.begin_read()?;
        let table = txn.open_table(CONTRACTS_TABLE)?;

        let result = match table.get(code_hash.as_slice()) {
            Ok(Some(value)) => Ok(Bytecode::new_raw(value.value().to_vec().into())),
            Ok(None) => Err(Self::Error::NotFound("code_by_hash".to_string())),
            Err(e) => Err(Self::Error::DB(e.into())),
        };
        stop_timer(timer);
        result
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let timer = start_processing_timer("database_get_storage");
        let address_hash = keccak256(address);
        let account: AccountState = match self.fetch_account(address_hash)? {
            Some(account) => account,
            None => return Err(Self::Error::NotFound("storage".to_string())),
        };
        let account_db = AccountDB::new(address_hash, self.db.clone())?;
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

        let txn = self.db.begin_read()?;
        let table = txn.open_table(BLOCK_HASHES_TABLE)?;

        let key = keccak256(B256::from(U256::from(number)));

        let result = match table.get(key.as_slice()) {
            Ok(Some(value)) => Ok(B256::from_slice(value.value())),
            Ok(None) => Err(Self::Error::NotFound("block_hash".to_string())),
            Err(e) => Err(Self::Error::DB(e.into())),
        };

        stop_timer(timer);
        result
    }
}
