use std::sync::Arc;

use alloy_rlp::{Decodable, EMPTY_STRING_CODE};
use anyhow::{ensure, Error};
use e2store::era2::{
    AccountEntry, AccountOrStorageEntry, Era2, StorageEntry, StorageItem, MAX_STORAGE_ITEMS,
};
use eth_trie::{
    decode_node,
    node::{LeafNode, Node},
    EthTrie, Trie, DB,
};
use ethportal_api::Header;
use parking_lot::Mutex;
use revm_primitives::{keccak256, B256, KECCAK_EMPTY, U256};
use tracing::info;

use crate::{
    cli::{ExportState, ImportState},
    execution::TrinExecution,
    storage::{account::Account, account_db::AccountDB},
    utils::full_nibble_path_to_address_hash,
};

#[derive(Debug)]
struct LeafNodeWithKeyHash {
    key_hash: B256,
    value: Vec<u8>,
}

#[derive(Debug)]
struct TrieNode {
    node_hash: B256,
    path: Vec<u8>,
}

impl TrieNode {
    fn new(node_hash: B256, path: Vec<u8>) -> Self {
        Self { node_hash, path }
    }
}

struct TrieLeafIterator<TrieDB: DB> {
    trie: Arc<Mutex<EthTrie<TrieDB>>>,
    stack: Vec<TrieNode>,
    leafs_to_process: Vec<LeafNodeWithKeyHash>,
}

impl<TrieDB: DB> TrieLeafIterator<TrieDB> {
    pub fn new(trie: Arc<Mutex<EthTrie<TrieDB>>>) -> anyhow::Result<Self> {
        let stack = vec![TrieNode::new(trie.lock().root_hash()?, vec![])];
        Ok(Self {
            trie,
            stack,
            leafs_to_process: vec![],
        })
    }

    fn process_leaf(&mut self, leaf: Arc<LeafNode>, path: Vec<u8>) {
        // reconstruct the address hash from the path so that we can fetch the
        // address from the database
        let mut partial_key_path = leaf.key.get_data().to_vec();
        partial_key_path.pop();
        let full_key_path = [&path, partial_key_path.as_slice()].concat();
        let address_hash = full_nibble_path_to_address_hash(&full_key_path);
        self.leafs_to_process.push(LeafNodeWithKeyHash {
            key_hash: address_hash,
            value: leaf.value.clone(),
        });
    }

    fn process_node(&mut self, node: Node, path: Vec<u8>) -> anyhow::Result<()> {
        match node {
            Node::Leaf(leaf) => self.process_leaf(leaf, path),
            Node::Extension(extension) => {
                let extension = extension.read().expect("Extension node must be readable");
                let path_with_extension_prefix =
                    [path, extension.prefix.get_data().to_vec()].concat();
                match &extension.node {
                    Node::Hash(hash) => {
                        self.stack
                            .push(TrieNode::new(hash.hash, path_with_extension_prefix));
                    }
                    Node::Leaf(leaf) => self.process_leaf(leaf.clone(), path_with_extension_prefix),
                    _ => {
                        panic!("Invalid extension node, must be either a leaf or a hash");
                    }
                }
            }
            Node::Branch(branch) => {
                let branch = branch.read().expect("Branch node must be readable");
                for (i, child) in branch.children.iter().enumerate() {
                    let branch_path = [path.clone(), vec![i as u8]].concat();
                    match child {
                        Node::Leaf(leaf) => self.process_leaf(leaf.clone(), branch_path),
                        Node::Hash(hash) => self.stack.push(TrieNode::new(hash.hash, branch_path)),
                        Node::Empty => {} // Do nothing
                        _ => {
                            panic!("Invalid branch node, must be either a leaf or a hash")
                        }
                    }
                }
                if let Some(node) = &branch.value {
                    let decoded_node = decode_node(&mut node.as_slice())?;
                    if let Node::Leaf(leaf) = decoded_node {
                        self.process_leaf(leaf, path);
                    } else {
                        panic!("Invalid branch value, must be a leaf");
                    }
                }
            }
            Node::Hash(_) => {}
            Node::Empty => {}
        }

        Ok(())
    }

    pub fn next(&mut self) -> Result<Option<LeafNodeWithKeyHash>, Error> {
        // Well process the storage trie, since values can be small, they may be inlined into
        // branches, so we will process them here
        if let Some(leaf_node) = self.leafs_to_process.pop() {
            return Ok(Some(leaf_node));
        }

        while let Some(TrieNode { node_hash, path }) = self.stack.pop() {
            let node = self
                .trie
                .lock()
                .db
                .get(node_hash.as_slice())
                .expect("Unable to get node from trie db")
                .unwrap_or_else(|| panic!("Node must exist, as we are walking a valid trie | node_hash: {} path: {:?}",
                     node_hash, path));

            self.process_node(decode_node(&mut node.as_slice())?, path)?;

            if let Some(leaf_node) = self.leafs_to_process.pop() {
                return Ok(Some(leaf_node));
            }
        }

        Ok(None)
    }
}

pub struct StateExporter {
    pub trin_execution: TrinExecution,
    exporter_config: ExportState,
}

impl StateExporter {
    pub fn new(trin_execution: TrinExecution, exporter_config: ExportState) -> Self {
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
        let mut leaf_iterator = TrieLeafIterator::new(self.trin_execution.database.trie.clone())?;
        info!("Trie leaf iterator initiated");
        let mut accounts_processed = 0;
        while let Ok(Some(LeafNodeWithKeyHash {
            key_hash: account_hash,
            value: account_state,
        })) = leaf_iterator.next()
        {
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
            if account_state.storage_root != keccak256([EMPTY_STRING_CODE]) {
                let account_db =
                    AccountDB::new(account_hash, self.trin_execution.database.db.clone());
                let account_trie = Arc::new(Mutex::new(EthTrie::from(
                    Arc::new(account_db),
                    account_state.storage_root,
                )?));
                let mut storage_iterator = TrieLeafIterator::new(account_trie)?;
                while let Ok(Some(LeafNodeWithKeyHash {
                    key_hash: storage_index_hash,
                    value: storage_value,
                })) = storage_iterator.next()
                {
                    let storage_slot_value: U256 = Decodable::decode(&mut storage_value.as_slice())
                        .expect("Failed to decode storage slot value");
                    storage.push(StorageItem {
                        storage_index_hash,
                        value: storage_slot_value,
                    });
                }
            }

            // Get the rounded up storage count
            let storage_count = storage.len() / MAX_STORAGE_ITEMS
                + (storage.len() % MAX_STORAGE_ITEMS != 0) as usize;

            era2.append_entry(&AccountOrStorageEntry::Account(AccountEntry {
                address_hash: account_hash,
                account_state: (&account_state).into(),
                bytecode,
                storage_count: storage_count as u32,
            }))?;

            for _ in 0..storage_count {
                let amount_to_drain = std::cmp::min(storage.len(), MAX_STORAGE_ITEMS);
                era2.append_entry(&AccountOrStorageEntry::Storage(StorageEntry(
                    storage.drain(..amount_to_drain).collect(),
                )))?;
            }

            if accounts_processed % 10000 == 0 {
                info!("Processed {} accounts", accounts_processed);
            }
            accounts_processed += 1;
        }

        info!("Era2 snapshot exported");

        Ok(())
    }
}

pub struct StateImporter {
    pub trin_execution: TrinExecution,
    importer_config: ImportState,
}

impl StateImporter {
    pub fn new(trin_execution: TrinExecution, importer_config: ImportState) -> Self {
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
        // imported the state wrong, which is more probable
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
}
