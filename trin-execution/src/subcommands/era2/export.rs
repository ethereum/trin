use std::sync::Arc;

use alloy_consensus::EMPTY_ROOT_HASH;
use alloy_rlp::Decodable;
use anyhow::ensure;
use e2store::era2::{
    AccountEntry, AccountOrStorageEntry, Era2, StorageEntry, StorageItem, MAX_STORAGE_ITEMS,
};
use eth_trie::EthTrie;
use ethportal_api::{types::state_trie::account_state::AccountState, Header};
use parking_lot::Mutex;
use revm_primitives::{B256, KECCAK_EMPTY, U256};
use tracing::info;

use crate::{cli::ExportStateConfig, execution::TrinExecution, storage::account_db::AccountDB};

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
        let mut accounts_exported = 0;
        for key_hash_and_leaf_value in self.trin_execution.database.trie.lock().iter() {
            let (raw_account_hash, account_state) = key_hash_and_leaf_value?;
            let account_hash = B256::from_slice(&raw_account_hash);

            let account_state = AccountState::decode(&mut account_state.as_slice())?;
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

        info!("Era2 snapshot exported");

        Ok(())
    }
}
