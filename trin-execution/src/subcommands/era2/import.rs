use std::{path::Path, sync::Arc};

use anyhow::{ensure, Error};
use e2store::era2::{AccountEntry, AccountOrStorageEntry, Era2Reader, StorageItem};
use eth_trie::{EthTrie, Trie};
use ethportal_api::Header;
use revm_primitives::{keccak256, B256, U256};
use tracing::info;

use crate::{
    cli::ImportStateConfig,
    config::StateConfig,
    era::manager::EraManager,
    evm::block_executor::BLOCKHASH_SERVE_WINDOW,
    storage::{
        account_db::AccountDB, evm_db::EvmDB, execution_position::ExecutionPosition,
        utils::setup_rocksdb,
    },
};

pub struct StateImporter {
    config: ImportStateConfig,
    evm_db: EvmDB,
}

impl StateImporter {
    pub async fn new(config: ImportStateConfig, data_dir: &Path) -> anyhow::Result<Self> {
        let rocks_db = Arc::new(setup_rocksdb(data_dir)?);

        let execution_position = ExecutionPosition::initialize_from_db(rocks_db.clone())?;
        ensure!(
            execution_position.next_block_number() == 0,
            "Cannot import state from .era2, database is not empty",
        );

        let evm_db = EvmDB::new(StateConfig::default(), rocks_db, &execution_position)
            .expect("Failed to create EVM database");

        Ok(Self { config, evm_db })
    }

    pub async fn import(&self) -> anyhow::Result<Header> {
        // Import state from era2 file
        let header = self.import_state()?;

        // Save execution position
        let mut execution_position = ExecutionPosition::default();
        execution_position.update_position(self.evm_db.db.clone(), &header)?;

        // Import last 256 block hashes
        self.import_last_256_block_hashes(header.number).await?;

        Ok(header)
    }

    pub fn import_state(&self) -> anyhow::Result<Header> {
        info!("Importing state from .era2 file");

        let mut era2 = Era2Reader::open(&self.config.path_to_era2)?;
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
            let account_db = AccountDB::new(address_hash, self.evm_db.db.clone());
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
                        .insert(storage_index_hash.as_slice(), &alloy::rlp::encode(value))?;
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
                self.evm_db.db.put(keccak256(&bytecode), bytecode.clone())?;
            }

            // Insert account into state trie
            self.evm_db
                .trie
                .lock()
                .insert(address_hash.as_slice(), &alloy::rlp::encode(&account_state))?;

            self.evm_db
                .db
                .put(address_hash, alloy::rlp::encode(account_state))
                .expect("Inserting account should never fail");

            accounts_imported += 1;
            if accounts_imported % 1000 == 0 {
                info!("Imported {} accounts", accounts_imported);
                info!("Committing changes to database");
                self.evm_db.trie.lock().root_hash()?;
                info!("Finished committing changes to database");
            }
        }

        // Check if the state root matches, if this fails it means either the .era2 is wrong or we
        // imported the state wrong
        if era2.header.header.state_root != self.evm_db.trie.lock().root_hash()? {
            return Err(Error::msg("State root mismatch, .era2 import failed"));
        }

        info!("Done importing State from .era2 file");

        Ok(era2.header.header)
    }

    /// insert the last 256 block hashes into the database
    pub async fn import_last_256_block_hashes(&self, block_number: u64) -> anyhow::Result<()> {
        let first_block_hash_to_add = block_number.saturating_sub(BLOCKHASH_SERVE_WINDOW);
        let mut era_manager = EraManager::new(first_block_hash_to_add).await?;
        while era_manager.next_block_number() < block_number {
            let block = era_manager.get_next_block().await?;
            self.evm_db.db.put(
                keccak256(B256::from(U256::from(block.header.number))),
                block.header.hash(),
            )?
        }

        Ok(())
    }
}
