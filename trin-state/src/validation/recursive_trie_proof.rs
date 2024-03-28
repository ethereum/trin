use alloy_primitives::B256;
use anyhow::{ensure, Result};
use ethportal_api::types::state_trie::{nibbles::Nibbles, TrieProof};

use super::trie::TrieProofValidationInfo;

/// The information needed in order to construct recursive gossip content key/value.
#[derive(Debug, PartialEq, Eq)]
pub struct RecursiveGossipInfo {
    pub path: Nibbles,
    pub proof: TrieProof,
    pub last_node_hash: B256,
}

/// Returns information needed for recursive gossip.
///
/// Error should happen only if validation_info was not correctly created, or was created for a
/// different trie proof.
pub fn recursive_gossip(
    trie_proof: &TrieProof,
    validation_info: TrieProofValidationInfo,
) -> Result<Option<RecursiveGossipInfo>> {
    // Check correctness of input data
    ensure!(!trie_proof.is_empty(), "Empty trie proof");
    ensure!(
        validation_info.remaining_path.is_empty(),
        "Remaining path in the validation_info is not empty"
    );

    let new_proof_len = trie_proof.len() - 1;
    if new_proof_len == 0 {
        // Original proof contained only one item indicating that it was a proof for the root node.
        // That means that there is no recursive gossip.
        return Ok(None);
    }

    ensure!(
        validation_info.inner_nodes_consumed_path.len() == new_proof_len,
        "Invalid length of inner_nodes_consumed_path, expected: {} actual: {}",
        new_proof_len,
        validation_info.inner_nodes_consumed_path.len()
    );

    let new_last_node = &trie_proof[new_proof_len - 1];
    // The new path is concatenation of all consumed nibbles up to the last node
    let new_path: Vec<u8> = validation_info.inner_nodes_consumed_path[..new_proof_len - 1]
        .iter()
        .flatten()
        .copied()
        .collect();
    let new_proof = Vec::from(&trie_proof[..new_proof_len]);

    Ok(Some(RecursiveGossipInfo {
        path: Nibbles::try_from_unpacked_nibbles(&new_path)?,
        proof: new_proof.into(),
        last_node_hash: new_last_node.node_hash(),
    }))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use ethportal_api::types::state_trie::EncodedTrieNode;

    use super::*;

    #[test]
    fn single_node() {
        let node = EncodedTrieNode::from(vec![0x12, 0x34]);

        let recursive_gossip_info = recursive_gossip(
            &vec![node.clone()].into(),
            TrieProofValidationInfo {
                last_node: &node.clone(),
                remaining_path: &[],
                inner_nodes_consumed_path: vec![],
            },
        )
        .unwrap();
        assert_eq!(recursive_gossip_info, None);
    }

    #[test]
    fn multiple_nodes() {
        let root_node = EncodedTrieNode::from(vec![0x12, 0x34]);
        let new_last_node = EncodedTrieNode::from(vec![0x56, 0x78]);
        let last_node = EncodedTrieNode::from(vec![0x9a, 0xbc]);

        let consumed_paths: Vec<VecDeque<u8>> = vec![[1, 2, 3].into(), [4, 5, 6].into()];

        let recursive_gossip_info = recursive_gossip(
            &vec![root_node.clone(), new_last_node.clone(), last_node.clone()].into(),
            TrieProofValidationInfo {
                last_node: &last_node.clone(),
                remaining_path: &[],
                inner_nodes_consumed_path: consumed_paths,
            },
        )
        .unwrap();

        assert_eq!(
            recursive_gossip_info,
            Some(RecursiveGossipInfo {
                path: Nibbles::try_from_unpacked_nibbles(&[1, 2, 3]).unwrap(),
                proof: vec![root_node, new_last_node.clone()].into(),
                last_node_hash: new_last_node.node_hash(),
            })
        )
    }

    #[test]
    #[should_panic = "Empty trie proof"]
    fn empty_proof() {
        let node = EncodedTrieNode::from(vec![0x12, 0x34]);

        recursive_gossip(
            &vec![].into(),
            TrieProofValidationInfo {
                last_node: &node.clone(),
                remaining_path: &[],
                inner_nodes_consumed_path: vec![],
            },
        )
        .unwrap();
    }

    #[test]
    #[should_panic = "Remaining path in the validation_info is not empty"]
    fn non_empty_remaining_path() {
        let node = EncodedTrieNode::from(vec![0x12, 0x34]);

        recursive_gossip(
            &vec![node.clone()].into(),
            TrieProofValidationInfo {
                last_node: &node.clone(),
                remaining_path: &[1],
                inner_nodes_consumed_path: vec![],
            },
        )
        .unwrap();
    }

    #[test]
    #[should_panic = "Invalid length of inner_nodes_consumed_path"]
    fn invalid_inner_nodes_consumed_path_length() {
        let root_node = EncodedTrieNode::from(vec![0x12, 0x34]);
        let new_last_node = EncodedTrieNode::from(vec![0x56, 0x78]);
        let last_node = EncodedTrieNode::from(vec![0x9a, 0xbc]);

        // We have 2 inner nodes, but only one consumed_path
        let consumed_paths: Vec<VecDeque<u8>> = vec![[1, 2, 3].into()];

        recursive_gossip(
            &vec![root_node.clone(), new_last_node.clone(), last_node.clone()].into(),
            TrieProofValidationInfo {
                last_node: &last_node.clone(),
                remaining_path: &[],
                inner_nodes_consumed_path: consumed_paths,
            },
        )
        .unwrap();
    }
}
