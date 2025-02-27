pub mod db;
pub mod filter;

use std::sync::Arc;

use alloy::primitives::{Bytes, B256};
use anyhow::{anyhow, Ok};
use db::TrieWalkerDb;
use eth_trie::{decode_node, node::Node};
use filter::Filter;

use crate::types::trie_proof::TrieProof;

/// Iterates over trie nodes from the whole or partial state trie
///
/// Use cases are:
/// 1. Gossiping the whole state trie
/// 2. Gossiping the forward state diffs (partial state trie)
/// 3. Getting stats about the state trie
///
/// Panics if the trie is corrupted
pub struct TrieWalker<DB: TrieWalkerDb> {
    is_partial_trie: bool,
    trie: Arc<DB>,
    stack: Vec<TrieProof>,

    /// You can filter what slice of the trie you want to walk
    filter: Option<Filter>,
}

impl<DB: TrieWalkerDb> TrieWalker<DB> {
    pub fn new(root_hash: B256, trie: Arc<DB>, filter: Option<Filter>) -> anyhow::Result<Self> {
        let root_node_trie = match trie.get(root_hash.as_slice())? {
            Some(root_node_trie) => root_node_trie,
            None => return Err(anyhow!("Root node not found in the database")),
        };
        let root_proof = TrieProof {
            path: vec![],
            proof: vec![root_node_trie],
        };

        Ok(Self {
            is_partial_trie: false,
            trie,
            stack: vec![root_proof],
            filter,
        })
    }

    pub fn new_partial_trie(root_hash: B256, trie: DB) -> anyhow::Result<Self> {
        let root_node_trie = match trie.get(root_hash.as_slice())? {
            Some(root_node_trie) => root_node_trie,
            None => {
                // We are handling 2 potential cases here
                // - If the storage root is empty then there is no storage to gossip
                // - The trie db is empty so we can't walk it return an empty iterator
                return Ok(Self {
                    is_partial_trie: true,
                    trie: Arc::new(trie),
                    stack: vec![],
                    filter: None,
                });
            }
        };

        let root_proof = TrieProof {
            path: vec![],
            proof: vec![root_node_trie],
        };

        Ok(Self {
            is_partial_trie: true,
            trie: Arc::new(trie),
            stack: vec![root_proof],
            filter: None,
        })
    }

    fn process_node(
        &mut self,
        node: Node,
        partial_proof: Vec<Bytes>,
        path: Vec<u8>,
    ) -> anyhow::Result<()> {
        // If we have a filter, we only want to include nodes that are in the filter
        if let Some(filter) = &self.filter {
            if !filter.contains(&path) {
                return Ok(());
            }
        }

        // We only need to process hash nodes, because if the node isn't a hash node then none of
        // its children is
        if let Node::Hash(hash) = node {
            let encoded_trie_node = match self.trie.get(hash.hash.as_slice())? {
                Some(encoded_trie_node) => encoded_trie_node,
                None => {
                    // If we are walking a partial trie, some nodes won't be available in the
                    // database
                    if self.is_partial_trie {
                        return Ok(());
                    }
                    return Err(anyhow::anyhow!("Node not found in the database"));
                }
            };

            // check that node decodes correctly and to correct variant
            if matches!(
                decode_node(&mut encoded_trie_node.as_ref())?,
                Node::Empty | Node::Hash(_)
            ) {
                return Err(anyhow::anyhow!(
                    "A node hash should never lead to an empty node or a hash node"
                ));
            }

            let mut proof = partial_proof;
            proof.push(encoded_trie_node);
            self.stack.push(TrieProof { path, proof });
        }
        Ok(())
    }
}

impl<DB: TrieWalkerDb> Iterator for TrieWalker<DB> {
    type Item = TrieProof;

    fn next(&mut self) -> Option<Self::Item> {
        let next_proof = self.stack.pop()?;

        let TrieProof { path, proof } = &next_proof;
        let last_node = proof.last().expect("Proof is empty");
        let decoded_last_node =
            decode_node(&mut last_node.as_ref()).expect("Failed to decode node");

        // Process any children of the node
        match decoded_last_node {
            Node::Extension(extension) => {
                let extension = extension.read().expect("Extension node must be readable");
                self.process_node(
                    extension.node.clone(),
                    proof.clone(),
                    [
                        path.as_slice(),
                        extension.prefix.get_data().to_vec().as_slice(),
                    ]
                    .concat(),
                )
                .expect("Failed to process node");
            }
            Node::Branch(branch) => {
                let branch = branch.read().expect("Branch node must be readable");

                // We want to iterate over the children in reverse order so that we can push them to
                // the stack in order
                for (i, child) in branch.children.iter().enumerate().rev() {
                    self.process_node(
                        child.clone(),
                        proof.clone(),
                        [path.as_slice(), &[i as u8]].concat(),
                    )
                    .expect("Failed to process node");
                }
            }
            // If the node is a leaf node, we don't need to go deeper
            _ => {}
        }

        Some(next_proof)
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, sync::Arc};

    use alloy::primitives::{keccak256, Address, B256, U256};
    use eth_trie::{EthTrie, RootWithTrieDiff, Trie};
    use tracing_test::traced_test;
    use trin_utils::dir::create_temp_test_dir;

    use super::*;
    use crate::{
        config::StateConfig,
        execution::TrinExecution,
        storage::{trie_db::TrieRocksDB, utils::setup_rocksdb},
        utils::full_nibble_path_to_address_hash,
    };

    #[tokio::test]
    #[traced_test]
    async fn test_state_walker() {
        let temp_directory = create_temp_test_dir().unwrap();
        let db = Arc::new(setup_rocksdb(temp_directory.path()).unwrap());
        let mut trie = EthTrie::new(Arc::new(TrieRocksDB::new(false, db.clone())));

        for i in 1..=18 {
            trie.insert(
                B256::from(U256::from(i)).as_slice(),
                B256::from(U256::from(i)).as_slice(),
            )
            .unwrap();
        }

        let root_hash = trie.root_hash().unwrap();
        let walker = TrieWalker::new(root_hash, trie.db.clone(), None).unwrap();
        let mut count = 0;
        let mut leaf_count = 0;
        for proof in walker {
            count += 1;

            let Some(encoded_last_node) = proof.proof.last() else {
                panic!("Account proof is empty");
            };

            let Node::Leaf(leaf) =
                decode_node(&mut encoded_last_node.as_ref()).expect("Failed to decode node")
            else {
                continue;
            };
            leaf_count += 1;

            // reconstruct the address hash from the path so we can call `get_proof` on the trie
            let mut partial_key_path = leaf.key.get_data().to_vec();
            partial_key_path.pop();
            let full_key_path = [&proof.path.clone(), partial_key_path.as_slice()].concat();
            let key = full_nibble_path_to_address_hash(&full_key_path);
            let valid_proof = trie.get_proof(key.as_slice()).expect("Proof not found");
            assert_eq!(valid_proof, proof.proof);
        }
        assert_eq!(leaf_count, 18);
        assert_eq!(count, 22);
    }

    #[tokio::test]
    #[ignore = "This test downloads data from a remote server"]
    async fn test_trie_walker_builds_valid_proof() {
        let temp_directory = create_temp_test_dir().unwrap();
        let mut trin_execution = TrinExecution::new(temp_directory.path(), StateConfig::default())
            .await
            .unwrap();
        let RootWithTrieDiff { trie_diff, .. } = trin_execution.process_next_block().await.unwrap();
        let root_hash = trin_execution.get_root().unwrap();
        let walk_diff = TrieWalker::new_partial_trie(root_hash, trie_diff).unwrap();

        let address = Address::from_str("0x001d14804b399c6ef80e64576f657660804fec0b").unwrap();
        let address_hash = keccak256(address);
        let valid_proof = trin_execution
            .database
            .trie
            .lock()
            .get_proof(address_hash.as_slice())
            .unwrap()
            .into_iter()
            .map(Bytes::from)
            .collect::<Vec<_>>();

        let mut trie_iter = walk_diff.into_iter();
        let account_proof = loop {
            let proof = trie_iter.next().expect("Proof not found");
            let Some(encoded_last_node) = proof.proof.last() else {
                panic!("Account proof is empty");
            };

            let Node::Leaf(leaf) =
                decode_node(&mut encoded_last_node.as_ref()).expect("Failed to decode node")
            else {
                continue;
            };

            // reconstruct the address hash from the path so we can call `get_proof` on the trie
            let mut partial_key_path = leaf.key.get_data().to_vec();
            partial_key_path.pop();
            let full_key_path = [&proof.path.clone(), partial_key_path.as_slice()].concat();
            let key = full_nibble_path_to_address_hash(&full_key_path);
            if key == address_hash {
                break proof;
            }
        };

        assert_eq!(account_proof.path, [5, 9, 2, 13]);
        assert_eq!(account_proof.proof, valid_proof);

        temp_directory.close().unwrap();
    }
}
