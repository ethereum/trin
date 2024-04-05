use std::sync::PoisonError;

use alloy_primitives::B256;
use eth_trie::TrieError;
use thiserror::Error;

// An error that happened while validating state content
#[derive(Debug, Error)]
pub enum StateValidationError {
    #[error("Reached empty node while traversing the trie")]
    UnexpectedEmptyNode,
    #[error("Reached leaf node while traversing the trie")]
    UnexpectedLeafNode,
    #[error("Path of the leaf node {path:X?} doesn't match expected path {expected_path:X?}")]
    InvalidLeafPath {
        path: Vec<u8>,
        expected_path: Vec<u8>,
    },
    #[error("Path of the extension node is empty")]
    EmptyExtensionPath,
    #[error("Path of the extension node {path:X?} is not prefix of the path {expected_path:X?}")]
    InvalidExtensionPath {
        path: Vec<u8>,
        expected_path: Vec<u8>,
    },
    #[error("Path is too short")]
    PathTooShort,
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
    #[error("Invalid content type for content key: {0}")]
    InvalidContentValueType(&'static str),
    #[error("Unable to decode node: {0}")]
    DecodingNode(#[from] TrieError),
    #[error("Unable to decode account state: {0}")]
    DecodingAccountState(#[from] alloy_rlp::Error),
    #[error("Error while validating: {0}")]
    Custom(String),
}

impl<T> From<PoisonError<T>> for StateValidationError {
    fn from(err: PoisonError<T>) -> Self {
        StateValidationError::Custom(err.to_string())
    }
}
