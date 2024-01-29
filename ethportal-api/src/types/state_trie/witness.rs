use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, VariableList};

use super::nibbles::Nibbles;

/// The RLP encoding of a trie node.
pub type EncodedTrieNode = VariableList<u8, typenum::U1024>;

/// The ordered list of trie nodes. Together they make the path in a trie, first node being the
/// root, last node being the node whose inclusion we are witnessing.
pub type TrieWitness = VariableList<EncodedTrieNode, typenum::U65>;

/// The Witness for a node in the account trie.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct AccountTrieWitness {
    /// Trie path of the node. Should match the implicit path from the proof field.
    pub path: Nibbles,
    /// The trie witness of the node.
    pub proof: TrieWitness,
}

/// The Witness for a node in the contract storage trie.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct ContractStorageTrieWitness {
    /// Trie path of the node. Should match the implicit path from the proof field.
    pub path: Nibbles,
    /// The trie witness of the node in the contract storage trie.
    pub proof: TrieWitness,
    /// The trie witness of the node in the account trie.
    pub account_witness: AccountTrieWitness,
}
