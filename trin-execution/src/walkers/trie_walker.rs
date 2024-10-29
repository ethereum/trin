use std::sync::Arc;

use alloy::consensus::EMPTY_ROOT_HASH;
use eth_trie::{decode_node, node::Node, DB};
use revm_primitives::{Bytes, B256};

use crate::types::trie_proof::TrieProof;

/// This is used for walking the whole state trie and partial tries (forward state diffs)
/// use cases are
/// 1. gossiping the whole state trie
/// 2. gossiping the forward state diffs
/// 3. getting stats about the state trie
pub struct TrieWalker<TrieDB: DB> {
    is_partial_trie: bool,
    trie: Arc<TrieDB>,
    stack: Vec<TrieProof>,
}

impl<TrieDB: DB> TrieWalker<TrieDB> {
    pub fn new(root_hash: B256, trie: Arc<TrieDB>) -> anyhow::Result<Self> {
        let root_value = trie
            .get(root_hash.as_slice())
            .expect("Failed to read node from")
            .expect("Root node not found")
            .into();
        let root_proof = TrieProof {
            path: vec![],
            proof: vec![root_value],
        };

        Ok(Self {
            is_partial_trie: false,
            trie,
            stack: vec![root_proof],
        })
    }

    pub fn new_partial_trie(root_hash: B256, trie: TrieDB) -> anyhow::Result<Self> {
        // if the storage root is empty then there is no storage to gossip
        if root_hash == EMPTY_ROOT_HASH {
            return Ok(Self {
                is_partial_trie: true,
                trie: Arc::new(trie),
                stack: vec![],
            });
        }

        let root_value = match trie
            .get(root_hash.as_slice())
            .expect("Failed to read node from")
        {
            Some(root_value) => root_value.into(),
            None => {
                // The trie db is empty so we can't walk it return an empty iterator
                return Ok(Self {
                    is_partial_trie: true,
                    trie: Arc::new(trie),
                    stack: vec![],
                });
            }
        };

        let root_proof = TrieProof {
            path: vec![],
            proof: vec![root_value],
        };

        Ok(Self {
            is_partial_trie: true,
            trie: Arc::new(trie),
            stack: vec![root_proof],
        })
    }

    fn process_node(
        &mut self,
        node: Node,
        partial_proof: Vec<Bytes>,
        path: Vec<u8>,
    ) -> anyhow::Result<()> {
        // We only need to process hash nodes, because if the node isn't a hash node the leaf is
        // already embedded in the proof
        if let Node::Hash(hash) = node {
            let value_result = self
                .trie
                .get(hash.hash.as_slice())
                .expect("Failed to read node from the database");

            let value = match value_result {
                Some(value) => value,
                None => {
                    // If we are walking a partial trie, some nodes won't be available in the
                    // database
                    if self.is_partial_trie {
                        return Ok(());
                    }
                    return Err(anyhow::anyhow!("Node not found in the database"));
                }
            };
            let decoded_node = decode_node(&mut value.as_ref())?;
            match decoded_node {
                Node::Leaf(_) | Node::Extension(_) | Node::Branch(_) => {
                    self.stack.push(TrieProof {
                        path,
                        proof: [partial_proof, vec![value.into()]].concat(),
                    });
                }
                // can't be a hash node because we just decoded it
                Node::Empty | Node::Hash(_) => (),
            }
        }
        Ok(())
    }
}

impl<TrieDB: DB> Iterator for TrieWalker<TrieDB> {
    type Item = TrieProof;

    fn next(&mut self) -> Option<Self::Item> {
        let next_proof = match self.stack.pop() {
            Some(next_proof) => next_proof,
            None => return None,
        };

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

                // We don't need to check the branches value as it is already encoded in the proof

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
    use super::*;
    use crate::{
        config::StateConfig,
        execution::TrinExecution,
        storage::{trie_db::TrieRocksDB, utils::setup_rocksdb},
        utils::full_nibble_path_to_address_hash,
        walkers::memory_db::ReadOnlyMemoryDB,
    };
    use eth_trie::{EthTrie, RootWithTrieDiff, Trie};
    use parking_lot::Mutex;
    use revm_primitives::{keccak256, Address, B256, U256};
    use std::{str::FromStr, sync::Arc};
    use tracing_test::traced_test;
    use trin_utils::dir::create_temp_test_dir;

    #[tokio::test]
    #[traced_test]
    async fn test_state_walker() {
        let temp_directory = create_temp_test_dir().unwrap();
        let db = Arc::new(setup_rocksdb(temp_directory.path()).unwrap());
        let trie = Arc::new(Mutex::new(EthTrie::new(Arc::new(TrieRocksDB::new(
            false,
            db.clone(),
        )))));
        {
            let mut trie = trie.lock();
            trie.insert(
                B256::from(U256::from(1)).as_slice(),
                B256::from(U256::from(1)).as_slice(),
            )
            .unwrap();
            trie.insert(
                B256::from(U256::from(2)).as_slice(),
                B256::from(U256::from(2)).as_slice(),
            )
            .unwrap();
            trie.insert(
                B256::from(U256::from(3)).as_slice(),
                B256::from(U256::from(3)).as_slice(),
            )
            .unwrap();
            trie.insert(
                B256::from(U256::from(4)).as_slice(),
                B256::from(U256::from(4)).as_slice(),
            )
            .unwrap();
            trie.insert(
                B256::from(U256::from(5)).as_slice(),
                B256::from(U256::from(5)).as_slice(),
            )
            .unwrap();
            trie.insert(
                B256::from(U256::from(6)).as_slice(),
                B256::from(U256::from(6)).as_slice(),
            )
            .unwrap();
            trie.insert(
                B256::from(U256::from(7)).as_slice(),
                B256::from(U256::from(7)).as_slice(),
            )
            .unwrap();
            trie.insert(
                B256::from(U256::from(8)).as_slice(),
                B256::from(U256::from(8)).as_slice(),
            )
            .unwrap();
            trie.insert(
                B256::from(U256::from(9)).as_slice(),
                B256::from(U256::from(9)).as_slice(),
            )
            .unwrap();
            trie.insert(
                B256::from(U256::from(10)).as_slice(),
                B256::from(U256::from(10)).as_slice(),
            )
            .unwrap();
            trie.insert(
                B256::from(U256::from(11)).as_slice(),
                B256::from(U256::from(11)).as_slice(),
            )
            .unwrap();
            trie.insert(
                B256::from(U256::from(12)).as_slice(),
                B256::from(U256::from(12)).as_slice(),
            )
            .unwrap();
            trie.insert(
                B256::from(U256::from(13)).as_slice(),
                B256::from(U256::from(13)).as_slice(),
            )
            .unwrap();
            trie.insert(
                B256::from(U256::from(14)).as_slice(),
                B256::from(U256::from(14)).as_slice(),
            )
            .unwrap();
            trie.insert(
                B256::from(U256::from(15)).as_slice(),
                B256::from(U256::from(15)).as_slice(),
            )
            .unwrap();
            trie.insert(
                B256::from(U256::from(16)).as_slice(),
                B256::from(U256::from(16)).as_slice(),
            )
            .unwrap();
            trie.insert(
                B256::from(U256::from(17)).as_slice(),
                B256::from(U256::from(17)).as_slice(),
            )
            .unwrap();
            trie.insert(
                B256::from(U256::from(18)).as_slice(),
                B256::from(U256::from(18)).as_slice(),
            )
            .unwrap();
            trie.root_hash().unwrap();
        }

        let root_hash = trie.lock().root_hash().unwrap();
        let walker = TrieWalker::new(root_hash, trie.lock().db.clone()).unwrap();
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

            // reconstruct the address hash from the path so that we can fetch the
            // address from the database
            let mut partial_key_path = leaf.key.get_data().to_vec();
            partial_key_path.pop();
            let full_key_path = [&proof.path.clone(), partial_key_path.as_slice()].concat();
            let key = full_nibble_path_to_address_hash(&full_key_path);
            let valid_proof = trie
                .lock()
                .get_proof(key.as_slice())
                .expect("Proof not found");
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
        let walk_diff =
            TrieWalker::new_partial_trie(root_hash, ReadOnlyMemoryDB::new(trie_diff)).unwrap();

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

            // reconstruct the address hash from the path so that we can fetch the
            // address from the database
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
