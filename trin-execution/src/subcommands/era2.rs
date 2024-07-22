use core::hash;
use std::sync::Arc;

use alloy_rlp::{Decodable, EMPTY_STRING_CODE};
use anyhow::{anyhow, Error};
use e2store::{
    era,
    era2::{
        AccountStateEntry, AccountTuple, AddressHashEntry, BytecodeEntry, Era2, StorageEntry,
        StorageItem,
    },
};
use eth_trie::{
    decode_node,
    node::{HashNode, LeafNode, Node},
    EthTrie, Trie, DB,
};
use ethportal_api::Header;
use parking_lot::Mutex;
use revm_primitives::{keccak256, B256, KECCAK_EMPTY};
use tracing::info;

use crate::{
    cli::{ExportState, ImportState},
    execution::State,
    storage::{account::Account, account_db::AccountDB},
    utils::full_nibble_path_to_address_hash,
};

struct LeafNodeWithKeyHash {
    key_hash: B256,
    value: Vec<u8>,
}

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
            stack: stack,
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
                        return Err(anyhow!(
                            "Invalid extension node, must be either a leaf or a hash"
                        ));
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
                        _ => {
                            return Err(anyhow!(
                                "Invalid branch node, must be either a leaf or a hash"
                            ))
                        }
                    }
                }
                if let Some(node) = &branch.value {
                    let decoded_node = decode_node(&mut node.as_slice())?;
                    if let Node::Leaf(leaf) = decoded_node {
                        self.process_leaf(leaf, path);
                    } else {
                        return Err(anyhow!("Invalid branch value, must be a leaf"));
                    }
                }
            }
            Node::Hash(_) => {}
            Node::Empty => {}
        }

        Ok(())
    }

    pub fn next(&mut self) -> Result<Option<LeafNodeWithKeyHash>, Error> {
        // Well process the storage trie, since values can be small, they may be inlined into branches, so we will process them here
        while let Some(leaf_node) = self.leafs_to_process.pop() {
            return Ok(Some(leaf_node));
        }

        while let Some(TrieNode { node_hash, path }) = self.stack.pop() {
            let node = self
                .trie
                .lock()
                .get(node_hash.as_slice())?
                .expect("Node must exist, as we are walking a valid trie");

            self.process_node(decode_node(&mut node.as_slice())?, path)?;

            if let Some(leaf_node) = self.leafs_to_process.pop() {
                return Ok(Some(leaf_node));
            }
        }

        Ok(None)
    }
}

pub struct StateExporter {
    pub state: State,
    exporter_config: ExportState,
}

impl StateExporter {
    pub fn new(state: State, exporter_config: ExportState) -> Self {
        Self {
            state,
            exporter_config,
        }
    }

    pub fn export_state(&mut self, header: Header) -> Result<(), Error> {
        let mut era2 = Era2::initiate_empty_era2(&self.exporter_config.path_to_era2, header)?;

        let mut leaf_iterator = TrieLeafIterator::new(self.state.database.trie.clone())?;

        while let Ok(Some(LeafNodeWithKeyHash {
            key_hash: account_hash,
            value: account_state,
        })) = leaf_iterator.next()
        {
            let account_state: Account = Decodable::decode(&mut account_state.as_slice())?;

            let bytecode = if account_state.code_hash != KECCAK_EMPTY {
                self.state
                    .database
                    .db
                    .get(&account_state.code_hash)?
                    .expect("If code hash is not empty, code must be present")
            } else {
                vec![]
            };

            let mut storage: Vec<StorageItem> = vec![];
            if account_state.storage_root != keccak256([EMPTY_STRING_CODE]) {
                let account_db = AccountDB::new(account_hash, self.state.database.db.clone());
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
                    storage.push(StorageItem {
                        storage_index_hash,
                        value: B256::from_slice(&storage_value),
                    });
                }
            }

            era2.append_account(&AccountTuple {
                address_hash: AddressHashEntry {
                    address_hash: account_hash,
                },
                account_state: AccountStateEntry {
                    account_state: (&account_state).into(),
                },
                bytecode: BytecodeEntry { bytecode },
                storage: StorageEntry {
                    storage: storage.into(),
                },
            })?;
        }

        Ok(())
    }
}

pub struct StateImporter {
    pub state: State,
    importer_config: ImportState,
}

impl StateImporter {
    pub fn new(state: State, importer_config: ImportState) -> Self {
        Self {
            state,
            importer_config,
        }
    }

    pub fn import_state(&mut self) -> Result<(), Error> {
        if self.state.block_execution_number() != 0 {
            return Err(Error::msg(
                "Cannot import state from .era2, database is not empty",
            ));
        }

        let mut era2 = Era2::initiate_era2_reader(&self.importer_config.path_to_era2)?;

        let mut accounts_imported = 0;
        while let Ok(account_tuple) = era2.next_account() {
            let AccountTuple {
                address_hash,
                account_state,
                bytecode,
                storage,
            } = account_tuple;

            let address_hash = address_hash.address_hash;
            let account_state: Account = account_state.account_state.into();
            let bytecode = bytecode.bytecode;
            let storage = storage.storage;

            // Build storage trie
            let account_db = AccountDB::new(address_hash, self.state.database.db.clone());
            let mut account_trie = EthTrie::new(Arc::new(account_db));
            for StorageItem {
                storage_index_hash,
                value,
            } in storage
            {
                account_trie.insert(storage_index_hash.as_slice(), value.as_slice())?;
            }

            if account_trie.root_hash()? != account_state.storage_root {
                return Err(Error::msg("Failed importing account storage trie: storage roots don't match expect value, .era2 import failed"));
            }

            // Insert contract if available
            if !bytecode.is_empty() && account_state.code_hash != KECCAK_EMPTY {
                self.state.database.db.put(keccak256(&bytecode), bytecode)?;
            }

            // Insert account into state trie
            self.state
                .database
                .trie
                .lock()
                .insert(address_hash.as_slice(), &alloy_rlp::encode(account_state))?;

            accounts_imported += 1;
            if accounts_imported % 1000 == 0 {
                info!("Imported {} accounts", accounts_imported);
            }
        }

        // Check if the state root matches, if this fails it means either the .era2 is wrong or we imported the state wrong, which is more probable
        if era2.header.header.state_root != self.state.get_root()? {
            return Err(Error::msg("State root mismatch, .era2 import failed"));
        }

        // Save execution position
        self.state.execution_position.set_block_execution_number(
            self.state.database.db.clone(),
            era2.header.header.number + 1,
            era2.header.header.state_root,
        )?;

        Ok(())
    }
}
