use alloy_primitives::B256;
use eth_trie::TrieError;
use ethportal_api::types::state_trie::{
    trie_traversal::{EmptyNodeInfo, TraversalError},
    EncodedTrieNode,
};
use thiserror::Error;

// An error that happened while validating state content
#[derive(Debug, Error)]
pub enum StateValidationError {
    #[error("Reached empty node while traversing the trie: {0:?}")]
    UnexpectedEmptyNode(EmptyNodeInfo),
    #[error("Reached value while traversing the trie")]
    UnexpectedValue,
    #[error("Path is too long")]
    PathTooLong,
    #[error("The TrieProof is empty")]
    EmptyTrieProof,
    #[error("The last node of the account state proof is not leaf node")]
    LeafNodeExpected,
    #[error("Node has wrong hash: {node_hash}, expected {expected_node_hash}")]
    InvalidNodeHash {
        node_hash: B256,
        expected_node_hash: B256,
    },
    #[error("Bytecode has wrong hash: {bytecode_hash}, expected {expected_bytecode_hash}")]
    InvalidBytecodeHash {
        bytecode_hash: B256,
        expected_bytecode_hash: B256,
    },
    #[error("Error while traversing the trie node: {0}")]
    NodeTraversalError(#[from] TraversalError),
    #[error("Invalid content type for content key: {0}")]
    InvalidContentValueType(&'static str),
    #[error("Unable to decode node: {0}")]
    DecodingNode(#[from] TrieError),
    #[error("Unable to decode account state: {0}")]
    DecodingAccountState(#[from] alloy_rlp::Error),
}

/// Checks the node has expected hash.
pub fn check_node_hash(node: &EncodedTrieNode, hash: &B256) -> Result<(), StateValidationError> {
    let node_hash = node.node_hash();
    if &node_hash == hash {
        Ok(())
    } else {
        Err(StateValidationError::InvalidNodeHash {
            node_hash,
            expected_node_hash: *hash,
        })
    }
}
