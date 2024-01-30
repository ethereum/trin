pub mod nibbles;

use ssz_types::{typenum, VariableList};

/// The RLP encoding of a trie node.
pub type EncodedTrieNode = VariableList<u8, typenum::U1024>;

/// The ordered list of trie nodes. Together they make the path in a trie, first node being the
/// root, last node being the node whose inclusion we are proving.
pub type TrieProof = VariableList<EncodedTrieNode, typenum::U65>;

/// The bytecode of the contract. Current maximum size is 24KB, but we are using 32KB to be safe.
pub type ByteCode = VariableList<u8, typenum::U32768>;
