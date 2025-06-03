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
    e2hs::manager::E2HSManager,
    evm::block_executor::BLOCKHASH_SERVE_WINDOW,
    storage::{
        account_db::AccountDB, evm_db::EvmDB, execution_position::ExecutionPosition,
        utils::setup_redb,
    },
    subcommands::e2ss::utils::percentage_from_address_hash,
};

use crate::storage::evm_db::{ACCOUNTS_TABLE, BLOCK_HASHES_TABLE, CONTRACTS_TABLE};

pub struct StateImporter {
    config: ImportStateConfig,
    evm_db: EvmDB,
}

impl StateImporter {
    pub async fn new(config: ImportStateConfig, data_dir: &Path) -> anyhow::Result<Self> {
        let red_db = Arc::new(setup_redb(data_dir)?);

        let execution_position = ExecutionPosition::initialize_from_db(red_db.clone())?;
        ensure!(
            execution_position.next_block_number() == 0,
            "Cannot import state from .e2ss, database is not empty",
        );

        let evm_db = EvmDB::new(StateConfig::default(), red_db, &execution_position)
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
            let account_db = AccountDB::new(address_hash, self.evm_db.db.clone())?;
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

            let db = &self.evm_db.db;
            let txn = db.begin_write()?;

            {
                let mut accounts = txn.open_table(ACCOUNTS_TABLE)?;
                let mut contracts = txn.open_table(CONTRACTS_TABLE)?;

                if !bytecode.is_empty() {
                    contracts.insert(keccak256(&bytecode).as_slice(), bytecode.as_slice())?;
                }

                // Insert account into accounts table
                accounts.insert(
                    address_hash.as_slice(),
                    alloy::rlp::encode(&account_state).as_slice(),
                )?;
            }
            txn.commit()?;

            self.evm_db
                .trie
                .lock()
                .insert(address_hash.as_slice(), &alloy::rlp::encode(&account_state))?;

            let txn = self.evm_db.db.begin_write()?;
            {
                let mut accounts = txn.open_table(ACCOUNTS_TABLE)?;
                accounts
                    .insert(
                        address_hash.as_slice(),
                        alloy::rlp::encode(account_state).as_slice(),
                    )
                    .expect("Inserting account should never fail");
            }
            txn.commit()?;

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
<<<<<<< HEAD
        let mut e2hs_manager = E2HSManager::new(first_block_hash_to_add).await?;
        while e2hs_manager.next_block_number() <= block_number {
            let block = e2hs_manager.get_next_block().await?;
            self.evm_db.db.put(
                keccak256(B256::from(U256::from(block.header.number))),
                block.header.hash_slow(),
            )?
=======
        let mut era_manager = EraManager::new(first_block_hash_to_add).await?;

        let txn = self.evm_db.db.begin_write()?;
        {
            let mut table = txn.open_table(BLOCK_HASHES_TABLE)?;

            while era_manager.next_block_number() <= block_number {
                let block = era_manager.get_next_block().await?;
                table.insert(
                    keccak256(B256::from(U256::from(block.header.number))).as_slice(),
                    block.header.hash_slow().as_slice(),
                )?;
            }
>>>>>>> 7c448cc7 (Replace RocksDB with Redb as backing for EVM database)
        }
        txn.commit()?;

        Ok(())
    }
}
