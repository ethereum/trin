use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use alloy_consensus::EMPTY_ROOT_HASH;
use alloy_rlp::Decodable;
use anyhow::ensure;
use e2store::era2::{
    AccountEntry, AccountOrStorageEntry, Era2Writer, StorageEntry, StorageItem, MAX_STORAGE_ITEMS,
};
use eth_trie::{EthTrie, Trie};
use ethportal_api::{types::state_trie::account_state::AccountState, Header};
use parking_lot::Mutex;
use revm_primitives::{B256, KECCAK_EMPTY, U256};
use tracing::info;

use crate::{
    cli::ExportStateConfig,
    config::StateConfig,
    era::manager::EraManager,
    storage::{
        account_db::AccountDB, evm_db::EvmDB, execution_position::ExecutionPosition,
        utils::setup_rocksdb,
    },
};

pub struct StateExporter {
    config: ExportStateConfig,
    header: Header,
    evm_db: EvmDB,
}

impl StateExporter {
    pub async fn new(config: ExportStateConfig, data_dir: &Path) -> anyhow::Result<Self> {
        let rocks_db = Arc::new(setup_rocksdb(data_dir)?);

        let execution_position = ExecutionPosition::initialize_from_db(rocks_db.clone())?;
        ensure!(
            execution_position.next_block_number() > 0,
            "Trin execution not initialized!"
        );

        let last_executed_block_number = execution_position.next_block_number() - 1;

        let header = EraManager::new(last_executed_block_number)
            .await?
            .get_next_block()
            .await?
            .header
            .clone();

        let evm_db = EvmDB::new(StateConfig::default(), rocks_db, &execution_position)
            .expect("Failed to create EVM database");
        ensure!(
            evm_db.trie.lock().root_hash()? == header.state_root,
            "State root mismatch from block header we are trying to export"
        );

        Ok(Self {
            config,
            header,
            evm_db,
        })
    }

    pub fn export(&self) -> anyhow::Result<PathBuf> {
        info!(
            "Exporting state from block number: {} with state root: {}",
            self.header.number, self.header.state_root
        );
        let mut era2 = Era2Writer::new(&self.config.path_to_era2, self.header.clone())?;
        info!("Era2 initiated");
        info!("Trie leaf iterator initiated");
        let mut accounts_exported = 0;
        for key_hash_and_leaf_value in self.evm_db.trie.lock().iter() {
            let (raw_account_hash, account_state) = key_hash_and_leaf_value?;
            let account_hash = B256::from_slice(&raw_account_hash);

            let account_state = AccountState::decode(&mut account_state.as_slice())?;
            let bytecode = if account_state.code_hash != KECCAK_EMPTY {
                self.evm_db
                    .db
                    .get(account_state.code_hash)?
                    .expect("If code hash is not empty, code must be present")
            } else {
                vec![]
            };

            let mut storage: Vec<StorageItem> = vec![];
            if account_state.storage_root != EMPTY_ROOT_HASH {
                let account_db = AccountDB::new(account_hash, self.evm_db.db.clone());
                let account_trie = Arc::new(Mutex::new(EthTrie::from(
                    Arc::new(account_db),
                    account_state.storage_root,
                )?));
                for key_hash_and_leaf_value in account_trie.lock().iter() {
                    let (raw_storage_index_hash, storage_value) = key_hash_and_leaf_value?;
                    let storage_index_hash = B256::from_slice(&raw_storage_index_hash);
                    let storage_slot_value: U256 = Decodable::decode(&mut storage_value.as_slice())
                        .expect("Failed to decode storage slot value");
                    storage.push(StorageItem {
                        storage_index_hash,
                        value: storage_slot_value,
                    });
                }
            }

            // Get the rounded up storage count
            let storage_count = storage.len().div_ceil(MAX_STORAGE_ITEMS);

            era2.append_entry(&AccountOrStorageEntry::Account(AccountEntry {
                address_hash: account_hash,
                account_state,
                bytecode,
                storage_count: storage_count as u32,
            }))?;

            for storage_chunk in storage.chunks(MAX_STORAGE_ITEMS) {
                era2.append_entry(&AccountOrStorageEntry::Storage(StorageEntry(
                    storage_chunk.to_vec(),
                )))?;
            }

            accounts_exported += 1;
            if accounts_exported % 10000 == 0 {
                info!("Processed {} accounts", accounts_exported);
            }
        }

        era2.flush()?;

        info!("Era2 snapshot exported");

        Ok(era2.path().to_path_buf())
    }

    pub fn header(&self) -> &Header {
        &self.header
    }
}
