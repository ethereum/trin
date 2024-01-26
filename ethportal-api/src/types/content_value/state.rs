use ethereum_types::H256;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};

use crate::{
    types::{
        bytes::ByteList,
        constants::CONTENT_ABSENT,
        state_trie::witness::{AccountTrieWitness, ContractStorageTrieWitness, EncodedTrieNode},
    },
    utils::bytes::hex_encode,
    ContentValue, ContentValueError,
};

/// A potential portal state content value. It can be absent if deserialization failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PossibleStateContentValue {
    ContentPresent(StateContentValue),
    ContentAbsent,
}

/// A Portal State content value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateContentValue {
    /// A content value type for retriving a trie node.
    TrieNode(TrieNode),
    /// A content value type for offering a trie node from the account trie.
    AccountTrieNodeWithProof(AccountTrieNodeWithProof),
    /// A content value type for offering a trie node from the contract storage trie.
    ContractStorageTrieNodeWithProof(ContractStorageTrieNodeWithProof),
    /// A content value type for retriving contract's bytecode.
    ContractBytecode(ContractBytecode),
    /// A content value type for offering contract's bytecode.
    ContractBytecodeWithProof(ContractBytecodeWithProof),
}

impl ContentValue for StateContentValue {
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::TrieNode(value) => value.as_ssz_bytes(),
            Self::AccountTrieNodeWithProof(value) => value.as_ssz_bytes(),
            Self::ContractStorageTrieNodeWithProof(value) => value.as_ssz_bytes(),
            Self::ContractBytecode(value) => value.as_ssz_bytes(),
            Self::ContractBytecodeWithProof(value) => value.as_ssz_bytes(),
        }
    }

    fn decode(buf: &[u8]) -> Result<Self, ContentValueError> {
        // Catch any attempt to construct a content value from "0x" improperly.
        if buf == CONTENT_ABSENT.to_string().as_bytes() {
            Err(ContentValueError::DecodeAbsentContent)
        } else if let Ok(value) = TrieNode::from_ssz_bytes(buf) {
            Ok(Self::TrieNode(value))
        } else if let Ok(value) = AccountTrieNodeWithProof::from_ssz_bytes(buf) {
            Ok(Self::AccountTrieNodeWithProof(value))
        } else if let Ok(value) = ContractStorageTrieNodeWithProof::from_ssz_bytes(buf) {
            Ok(Self::ContractStorageTrieNodeWithProof(value))
        } else if let Ok(value) = ContractBytecode::from_ssz_bytes(buf) {
            Ok(Self::ContractBytecode(value))
        } else if let Ok(value) = ContractBytecodeWithProof::from_ssz_bytes(buf) {
            Ok(Self::ContractBytecodeWithProof(value))
        } else {
            Err(ContentValueError::UnknownContent {
                bytes: hex_encode(buf),
                network: "state".to_string(),
            })
        }
    }
}

/// A content value type, used when retriving a trie node.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct TrieNode {
    pub node: EncodedTrieNode,
}

/// A content value type, used when offering a trie node from the account trie.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct AccountTrieNodeWithProof {
    /// An account trie node with a proof.
    pub proof: AccountTrieWitness,
    /// A block at which the proof is anchored.
    pub block_hash: H256,
}

/// A content value type, used when offering a trie node from the contract storage trie.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct ContractStorageTrieNodeWithProof {
    /// A contract storage trie node with a proof.
    pub proof: ContractStorageTrieWitness,
    /// A block at which the proof is anchored.
    pub block_hash: H256,
}

/// A content value type, used when retriving contract's bytecode.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct ContractBytecode {
    pub code: ByteList,
}

/// A content value type, used when offering contract's bytecode.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct ContractBytecodeWithProof {
    /// A contract's bytecode.
    pub code: ByteList,
    /// A proof for the account of the corresponding contract.
    pub account_proof: AccountTrieWitness,
    /// A block at which the proof is anchored.
    pub block_hash: H256,
}
