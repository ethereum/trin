use std::{path::Path, sync::Arc};

use alloy::consensus::Header;
use anyhow::{ensure, Error};
use e2store::e2ss::{AccountEntry, AccountOrStorageEntry, E2SSReader, StorageItem};
use eth_trie::{EthTrie, Trie};
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
    subcommands::e2ss::utils::percentage_from_address_hash,
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
            "Cannot import state from .e2ss, database is not empty",
        );

        let evm_db = EvmDB::new(StateConfig::default(), rocks_db, &execution_position)
            .expect("Failed to create EVM database");

        Ok(Self { config, evm_db })
    }

    pub async fn import(&self) -> anyhow::Result<Header> {
        // Import state from e2ss file
        let header = self.import_state()?;

        // Save execution position
        let mut execution_position = ExecutionPosition::default();
        execution_position.update_position(self.evm_db.db.clone(), &header)?;

        // Import last 256 block hashes
        self.import_last_256_block_hashes(header.number).await?;

        Ok(header)
    }

    fn import_state(&self) -> anyhow::Result<Header> {
        info!("Importing state from .e2ss file");

        let mut e2ss = E2SSReader::open(&self.config.path_to_e2ss)?;
        info!("E2SS reader initiated");
        let mut accounts_imported = 0;
        while let Some(account) = e2ss.next() {
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
                let Some(AccountOrStorageEntry::Storage(storage_entry)) = e2ss.next() else {
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
                return Err(Error::msg("Failed importing account storage trie: storage roots don't match expect value, .e2ss import failed"));
            }

            // Insert contract if available
            ensure!(
                account_state.code_hash == keccak256(&bytecode),
                "Code hash mismatch, .e2ss import failed"
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
                info!("Processed {accounts_imported} accounts, {:.2}% done, last address_hash processed: {address_hash}", percentage_from_address_hash(address_hash));

                info!("Committing changes to database");
                self.evm_db.trie.lock().root_hash()?;
                info!("Finished committing changes to database");
            }
        }

        // Check if the state root matches, if this fails it means either the .e2ss is wrong or we
        // imported the state wrong
        if e2ss.header.header.state_root != self.evm_db.trie.lock().root_hash()? {
            return Err(Error::msg("State root mismatch, .e2ss import failed"));
        }

        info!("Done importing State from .e2ss file");

        Ok(e2ss.header.header)
    }

    /// insert the last 256 block hashes into the database
    async fn import_last_256_block_hashes(&self, block_number: u64) -> anyhow::Result<()> {
        let first_block_hash_to_add = block_number.saturating_sub(BLOCKHASH_SERVE_WINDOW);
        let mut era_manager = EraManager::new(first_block_hash_to_add).await?;
        while era_manager.next_block_number() <= block_number {
            let block = era_manager.get_next_block().await?;
            self.evm_db.db.put(
                keccak256(B256::from(U256::from(block.header.number))),
                block.header.hash_slow(),
            )?
        }

        Ok(())
    }
}
