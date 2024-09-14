use std::sync::Arc;

use anyhow::{ensure, Error};
use e2store::era2::{AccountEntry, AccountOrStorageEntry, Era2, StorageItem};
use eth_trie::{EthTrie, Trie};
use revm_primitives::{keccak256, B256, U256};
use tracing::info;

use crate::{
    cli::ImportStateConfig, era::manager::EraManager, evm::block_executor::BLOCKHASH_SERVE_WINDOW,
    execution::TrinExecution, storage::account_db::AccountDB,
};

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

            // Build storage trie
            let account_db = AccountDB::new(address_hash, self.trin_execution.database.db.clone());
            let mut storage_trie = EthTrie::new(Arc::new(account_db));
            for _ in 0..storage_count {
                let Some(AccountOrStorageEntry::Storage(storage_entry)) = era2.next() else {
                    return Err(Error::msg("Expected storage, got account entry"));
                };
                for StorageItem {
                    storage_index_hash,
                    value,
                } in storage_entry.0
                {
                    storage_trie
                        .insert(storage_index_hash.as_slice(), &alloy_rlp::encode(value))?;
                }
                // Commit storage trie every 10 million storage items, to avoid excessive memory
                // usage
                storage_trie.root_hash()?;
            }

            if storage_trie.root_hash()? != account_state.storage_root {
                return Err(Error::msg("Failed importing account storage trie: storage roots don't match expect value, .era2 import failed"));
            }

            // Insert contract if available
            ensure!(
                account_state.code_hash == keccak256(&bytecode),
                "Code hash mismatch, .era2 import failed"
            );
            if !bytecode.is_empty() {
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
        while era_manager.next_block_number() < self.trin_execution.next_block_number() {
            let block = era_manager.get_next_block().await?;
            self.trin_execution.database.db.put(
                keccak256(B256::from(U256::from(block.header.number))),
                block.header.hash(),
            )?
        }

        Ok(())
    }
}
