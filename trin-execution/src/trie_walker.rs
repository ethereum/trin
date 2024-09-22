use std::collections::VecDeque;

use alloy_consensus::EMPTY_ROOT_HASH;
use alloy_primitives::B256;
use eth_trie::{decode_node, node::Node};
use hashbrown::HashMap as BrownHashMap;
use serde::{Deserialize, Serialize};

use super::types::trie_proof::TrieProof;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrieWalkerNode {
    /// The encoded version of the trie node.
    pub encoded_node: Vec<u8>,
    /// The hash of the parent node. It is `None` only for root of the trie.
    pub parent_hash: Option<B256>,
    /// Path from parent node to this node.
    pub path_nibbles: Vec<u8>,
}

impl TrieWalkerNode {
    pub fn new(encoded_node: Vec<u8>, parent_hash: Option<B256>, path_nibbles: Vec<u8>) -> Self {
        Self {
            encoded_node,
            parent_hash,
            path_nibbles,
        }
    }
}

/// This struct takes in a root hash and a hashmap of changed nodes, then you can call an iterator
/// which will return every proof to gossip
pub struct TrieWalker {
    pub nodes: BrownHashMap<B256, TrieWalkerNode>,
}

impl TrieWalker {
    pub fn new(root_hash: B256, nodes: BrownHashMap<B256, Vec<u8>>) -> Self {
        // if the storage root is empty then there is no storage to gossip
        if root_hash == EMPTY_ROOT_HASH {
            return Self {
                nodes: BrownHashMap::new(),
            };
        }

        if nodes.is_empty() {
            return Self {
                nodes: BrownHashMap::new(),
            };
        }

        let processed_nodes = Self::process_trie(root_hash, &nodes)
            .expect("This shouldn't fail as we only pass valid tries");
        Self {
            nodes: processed_nodes,
        }
    }

    fn process_trie(
        root_hash: B256,
        nodes: &BrownHashMap<B256, Vec<u8>>,
    ) -> anyhow::Result<BrownHashMap<B256, TrieWalkerNode>> {
        let mut trie_walker_nodes: BrownHashMap<B256, TrieWalkerNode> = BrownHashMap::new();
        let mut stack = vec![root_hash];

        trie_walker_nodes.insert(
            root_hash,
            TrieWalkerNode::new(
                nodes
                    .get(&root_hash)
                    .expect("Failed to get encoded node for root node. This should never happen.")
                    .clone(),
                None,
                vec![],
            ),
        );
        while let Some(node_key) = stack.pop() {
            let encoded_node = nodes
                .get(&node_key)
                .expect("The stack should only contain nodes that are in the changed nodes");

            let decoded_node = decode_node(&mut encoded_node.as_slice())
                .expect("Should should only be passing valid encoded nodes");

            match decoded_node {
                Node::Extension(extension) => {
                    let extension = extension.read().expect("Reading an extension should work");
                    // We look for hash nodes in order to connect them to the root. If this node is
                    // not a hash node, then neither is any of its children.
                    // We know this because any node that has a hash node as it's descendant would
                    // also become hash node, because its encoding would be longer than 32 bytes.
                    if let Node::Hash(hash_node) = &extension.node {
                        // Only process provided nodes (they belong to the partial trie that we care
                        // about)
                        if let Some(encoded_node) = nodes.get(&hash_node.hash) {
                            stack.push(hash_node.hash);
                            trie_walker_nodes.insert(
                                hash_node.hash,
                                TrieWalkerNode::new(
                                    encoded_node.clone(),
                                    Some(node_key),
                                    extension.prefix.get_data().to_vec(),
                                ),
                            );
                        }
                    }
                }
                Node::Branch(branch) => {
                    let branch = branch.read().expect("Reading a branch should work");
                    for (i, child) in branch.children.iter().enumerate() {
                        // We look for hash nodes in order to connect them to the root. If this node
                        // is not a hash node, then neither is any of its children.
                        // We know this because any node that has a hash node as it's descendant
                        // would also become hash node, because its encoding would be longer than 32
                        // bytes.
                        if let Node::Hash(hash_node) = child {
                            //Only process provided nodes (they belong to the partial trie that we
                            // care about)
                            if let Some(encoded_node) = nodes.get(&hash_node.hash) {
                                stack.push(hash_node.hash);
                                trie_walker_nodes.insert(
                                    hash_node.hash,
                                    TrieWalkerNode::new(
                                        encoded_node.clone(),
                                        Some(node_key),
                                        vec![i as u8],
                                    ),
                                );
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(trie_walker_nodes)
    }

    pub fn get_proof(&self, node_hash: B256) -> TrieProof {
        let mut path_parts = VecDeque::new();
        let mut proof = VecDeque::new();
        let mut next_node: Option<B256> = Some(node_hash);
        while let Some(current_node) = next_node {
            let Some(node) = self.nodes.get(&current_node) else {
                panic!("Node not found in trie walker nodes. This should never happen.");
            };
            path_parts.push_front(node.path_nibbles.clone());
            proof.push_front(node.encoded_node.clone().into());
            next_node = node.parent_hash;
        }

        TrieProof {
            path: Vec::from(path_parts).concat(),
            proof: Vec::from(proof),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy_primitives::{keccak256, Address, Bytes};
    use eth_trie::{RootWithTrieDiff, Trie};
    use trin_utils::dir::create_temp_test_dir;

    use crate::{config::StateConfig, execution::TrinExecution, trie_walker::TrieWalker};

    #[tokio::test]
    async fn test_trie_walker_builds_valid_proof() {
        let temp_directory = create_temp_test_dir().unwrap();
        let mut trin_execution = TrinExecution::new(temp_directory.path(), StateConfig::default())
            .await
            .unwrap();
        let RootWithTrieDiff { trie_diff, .. } = trin_execution.process_next_block().await.unwrap();
        let root_hash = trin_execution.get_root().unwrap();
        let walk_diff = TrieWalker::new(root_hash, trie_diff);

        let address = Address::from_str("0x001d14804b399c6ef80e64576f657660804fec0b").unwrap();
        let valid_proof = trin_execution
            .database
            .trie
            .lock()
            .get_proof(keccak256(address).as_slice())
            .unwrap()
            .into_iter()
            .map(Bytes::from)
            .collect::<Vec<_>>();
        let last_node = valid_proof.last().expect("Missing proof!");

        let account_proof = walk_diff.get_proof(keccak256(last_node));

        assert_eq!(account_proof.path, [5, 9, 2, 13]);
        assert_eq!(account_proof.proof, valid_proof);

        temp_directory.close().unwrap();
    }
}
