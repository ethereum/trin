use std::ops::Deref;

use alloy_primitives::{keccak256, B256};
use eth_trie::{decode_node, node::Node, TrieError};
use serde::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, VariableList};

use super::bytes::{ByteList1024, ByteList32K};

pub mod account_state;
pub mod nibbles;
mod utils;

/// The RLP encoding of a trie node.
#[derive(Clone, Debug, Eq, PartialEq, Decode, Encode, Serialize, Deserialize)]
#[ssz(struct_behaviour = "transparent")]
pub struct EncodedTrieNode(ByteList1024);

impl EncodedTrieNode {
    pub fn node_hash(&self) -> B256 {
        keccak256(&self[..])
    }

    pub fn as_trie_node(&self) -> Result<Node, TrieError> {
        decode_node(&mut &self.clone()[..])
    }
}

impl Deref for EncodedTrieNode {
    type Target = ByteList1024;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for EncodedTrieNode {
    fn from(value: Vec<u8>) -> Self {
        Self(value.into())
    }
}

impl TryFrom<EncodedTrieNode> for Node {
    type Error = TrieError;

    fn try_from(value: EncodedTrieNode) -> Result<Self, Self::Error> {
        value.as_trie_node()
    }
}

impl From<&Node> for EncodedTrieNode {
    fn from(node: &Node) -> Self {
        Self::from(utils::encode_node(node))
    }
}

/// The ordered list of trie nodes. Together they make the path in a trie, first node being the
/// root, last node being the node whose inclusion we are proving.
pub type TrieProof = VariableList<EncodedTrieNode, typenum::U65>;

/// The bytecode of the contract. Current maximum size is 24KB, but we are using 32KB to be safe.
pub type ByteCode = ByteList32K;
