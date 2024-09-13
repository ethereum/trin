use std::sync::Arc;

use alloy_consensus::EMPTY_ROOT_HASH;
use alloy_rlp::Decodable;
use anyhow::{ensure, Error};
use e2store::era2::{
    AccountEntry, AccountOrStorageEntry, Era2, StorageEntry, StorageItem, MAX_STORAGE_ITEMS,
};
use eth_trie::{EthTrie, Trie};
use ethportal_api::Header;
use parking_lot::Mutex;
use revm_primitives::{keccak256, B256, KECCAK_EMPTY, U256};
use tracing::info;

use crate::{
    cli::{ExportStateConfig, ImportStateConfig},
    era::manager::EraManager,
    evm::block_executor::BLOCKHASH_SERVE_WINDOW,
    execution::TrinExecution,
    storage::{account::Account, account_db::AccountDB},
    utils::full_nibble_path_to_address_hash,
};

pub struct StateExporter {
    pub trin_execution: TrinExecution,
    exporter_config: ExportStateConfig,
}

impl StateExporter {
    pub fn new(trin_execution: TrinExecution, exporter_config: ExportStateConfig) -> Self {
        Self {
            trin_execution,
            exporter_config,
        }
    }

    pub fn export_state(&mut self, header: Header) -> anyhow::Result<()> {
        ensure!(
            header.state_root == self.trin_execution.get_root()?,
            "State root mismatch fro block header we are trying to export"
        );
        info!(
            "Exporting state from block number: {} with state root: {}",
            header.number, header.state_root
        );
        let mut era2 = Era2::create(self.exporter_config.path_to_era2.clone(), header)?;
        info!("Era2 initiated");
        info!("Trie leaf iterator initiated");
        let mut accounts_processed = 0;
        while let Some(nibble_and_leaf_value) =
            self.trin_execution.database.trie.lock().iter().next()
        {
            let (raw_nibble_path, account_state) = nibble_and_leaf_value?;
            let account_hash = full_nibble_path_to_address_hash(&raw_nibble_path);

            let account_state: Account = Decodable::decode(&mut account_state.as_slice())?;
            let bytecode = if account_state.code_hash != KECCAK_EMPTY {
                self.trin_execution
                    .database
                    .db
                    .get(account_state.code_hash)?
                    .expect("If code hash is not empty, code must be present")
            } else {
                vec![]
            };

            let mut storage: Vec<StorageItem> = vec![];
            if account_state.storage_root != EMPTY_ROOT_HASH {
                let account_db =
                    AccountDB::new(account_hash, self.trin_execution.database.db.clone());
                let account_trie = Arc::new(Mutex::new(EthTrie::from(
                    Arc::new(account_db),
                    account_state.storage_root,
                )?));
                while let Some(nibble_and_leaf_value) = account_trie.lock().iter().next() {
                    let (raw_nibble_path, storage_value) = nibble_and_leaf_value?;
                    let storage_index_hash = full_nibble_path_to_address_hash(&raw_nibble_path);
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
                account_state: (&account_state).into(),
                bytecode,
                storage_count: storage_count as u32,
            }))?;

            for storage_chunk in storage.chunks(MAX_STORAGE_ITEMS) {
                era2.append_entry(&AccountOrStorageEntry::Storage(StorageEntry(
                    storage_chunk.to_vec(),
                )))?;
            }

            accounts_processed += 1;
            if accounts_processed % 10000 == 0 {
                info!("Processed {} accounts", accounts_processed);
            }
        }

        info!("Era2 snapshot exported");

        Ok(())
    }
}

pub struct StateImporter {
    pub trin_execution: TrinExecution,
    importer_config: ImportStateConfig,
}

impl StateImporter {
    pub fn new(trin_execution: TrinExecution, importer_config: ImportStateConfig) -> Self {
        Self {
            trin_execution,
            importer_config,
        }
    }

    pub fn import_state(&mut self) -> anyhow::Result<()> {
        info!("Importing state from .era2 file");
        if self.trin_execution.next_block_number() != 0 {
            return Err(Error::msg(
                "Cannot import state from .era2, database is not empty",
            ));
        }

        let mut era2 = Era2::open(self.importer_config.path_to_era2.clone())?;
        info!("Era2 reader initiated");
        let mut accounts_imported = 0;
        while let Some(account) = era2.next() {
            let AccountOrStorageEntry::Account(account) = account else {
                return Err(Error::msg("Expected account, got storage entry"));
            };
            let AccountEntry {
                address_hash,
                account_state,
                bytecode,
                storage_count,
            } = account;

            let account_state: Account = account_state.into();

            // Build storage trie
            let account_db = AccountDB::new(address_hash, self.trin_execution.database.db.clone());
            let mut account_trie = EthTrie::new(Arc::new(account_db));
            for _ in 0..storage_count {
                let Some(AccountOrStorageEntry::Storage(storage_entry)) = era2.next() else {
                    return Err(Error::msg("Expected storage, got account entry"));
                };
                for StorageItem {
                    storage_index_hash,
                    value,
                } in storage_entry.0
                {
                    account_trie
                        .insert(storage_index_hash.as_slice(), &alloy_rlp::encode(value))?;
                }
            }

            if account_trie.root_hash()? != account_state.storage_root {
                return Err(Error::msg("Failed importing account storage trie: storage roots don't match expect value, .era2 import failed"));
            }

            // Insert contract if available
            if !bytecode.is_empty() && account_state.code_hash != KECCAK_EMPTY {
                ensure!(
                    account_state.code_hash == keccak256(&bytecode),
                    "Code hash mismatch, .era2 import failed"
                );
                self.trin_execution
                    .database
                    .db
                    .put(keccak256(&bytecode), bytecode.clone())?;
            }

            // Insert account into state trie
            self.trin_execution
                .database
                .trie
                .lock()
                .insert(address_hash.as_slice(), &alloy_rlp::encode(&account_state))?;

            self.trin_execution
                .database
                .db
                .put(address_hash, alloy_rlp::encode(account_state))
                .expect("Inserting account should never fail");

            accounts_imported += 1;
            if accounts_imported % 1000 == 0 {
                info!("Imported {} accounts", accounts_imported);
                info!("Committing changes to database");
                self.trin_execution.get_root()?;
                info!("Finished committing changes to database");
            }
        }

        // Check if the state root matches, if this fails it means either the .era2 is wrong or we
        // imported the state wrong
        if era2.header.header.state_root != self.trin_execution.get_root()? {
            return Err(Error::msg("State root mismatch, .era2 import failed"));
        }

        // Save execution position
        self.trin_execution
            .execution_position
            .update_position(self.trin_execution.database.db.clone(), era2.header.header)?;

        info!("Done importing State from .era2 file");

        Ok(())
    }

    /// insert the last 256 block hashes into the database
    pub async fn import_last_256_block_hashes(&mut self) -> anyhow::Result<()> {
        let first_block_hash_to_add = self
            .trin_execution
            .next_block_number()
            .saturating_sub(BLOCKHASH_SERVE_WINDOW);
        let mut era_manager = EraManager::new(first_block_hash_to_add).await?;
        for block_number in first_block_hash_to_add..self.trin_execution.next_block_number() {
            let block = era_manager.get_next_block().await?;
            ensure!(
                block.header.number == block_number,
                "Block number mismatch: {} != {}, well importing state",
                block.header.number,
                block_number
            );
            self.trin_execution.database.db.put(
                keccak256(B256::from(U256::from(block_number))),
                block.header.hash(),
            )?
        }

        Ok(())
    }
}
