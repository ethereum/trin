use ethereum_types::H256;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, VariableList};

use crate::{
    types::{
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

pub type ByteCode = VariableList<u8, typenum::U65536>;

/// A content value type, used when retriving contract's bytecode.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct ContractBytecode {
    pub code: ByteCode,
}

/// A content value type, used when offering contract's bytecode.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct ContractBytecodeWithProof {
    /// A contract's bytecode.
    pub code: ByteCode,
    /// A proof for the account of the corresponding contract.
    pub account_proof: AccountTrieWitness,
    /// A block at which the proof is anchored.
    pub block_hash: H256,
}

#[cfg(test)]
mod test {
    use std::{fs, str::FromStr};

    use anyhow::Result;
    use rstest::rstest;
    use serde_json::Value;

    use crate::{
        types::state_trie::{nibbles::Nibbles, witness::TrieWitness},
        utils::bytes::hex_decode,
    };

    use super::*;

    #[test]
    fn trie_node() -> Result<()> {
        let file = fs::read_to_string("../test_assets/portalnet/content/state/trie_node.json")?;
        let value: Value = serde_json::from_str(&file)?;
        let json = value.as_object().unwrap();

        let expected_content_value = StateContentValue::TrieNode(TrieNode {
            node: EncodedTrieNode::from(json_as_hex(&json["trie_node"])),
        });
        let content_value = StateContentValue::decode(&json_as_hex(&json["content_value"]))?;

        assert_eq!(content_value, expected_content_value);

        Ok(())
    }

    #[test]
    fn account_trie_node_with_proof() -> Result<()> {
        let file = fs::read_to_string(
            "../test_assets/portalnet/content/state/account_trie_node_with_proof.json",
        )?;
        let value: Value = serde_json::from_str(&file)?;
        let json = value.as_object().unwrap();

        let expected_content_value =
            StateContentValue::AccountTrieNodeWithProof(AccountTrieNodeWithProof {
                proof: AccountTrieWitness {
                    path: json_as_nibbles(&json["nibbles"]),
                    proof: json_as_proof(&json["proof"]),
                },
                block_hash: json_as_h256(&json["block_hash"]),
            });
        let content_value = StateContentValue::decode(&json_as_hex(&json["content_value"]))?;

        assert_eq!(content_value, expected_content_value);

        Ok(())
    }

    #[test]
    fn contract_storage_trie_node_with_proof() -> Result<()> {
        let file = fs::read_to_string(
            "../test_assets/portalnet/content/state/contract_storage_trie_node_with_proof.json",
        )?;
        let value: Value = serde_json::from_str(&file)?;
        let json = value.as_object().unwrap();

        let expected_content_value =
            StateContentValue::ContractStorageTrieNodeWithProof(ContractStorageTrieNodeWithProof {
                proof: ContractStorageTrieWitness {
                    path: json_as_nibbles(&json["nibbles"]),
                    proof: json_as_proof(&json["proof"]),
                    account_witness: AccountTrieWitness {
                        path: json_as_nibbles(&json["account_nibbles"]),
                        proof: json_as_proof(&json["account_proof"]),
                    },
                },
                block_hash: json_as_h256(&json["block_hash"]),
            });
        let content_value = StateContentValue::decode(&json_as_hex(&json["content_value"]))?;

        assert_eq!(content_value, expected_content_value);

        Ok(())
    }

    #[test]
    fn contract_bytecode() -> Result<()> {
        let file =
            fs::read_to_string("../test_assets/portalnet/content/state/contract_bytecode.json")?;
        let value: Value = serde_json::from_str(&file)?;
        let json = value.as_object().unwrap();

        let expected_content_value = StateContentValue::ContractBytecode(ContractBytecode {
            code: ByteCode::from(json_as_hex(&json["bytecode"])),
        });
        let content_value = StateContentValue::decode(&json_as_hex(&json["content_value"]))?;

        assert_eq!(content_value, expected_content_value);

        Ok(())
    }

    #[test]
    fn contract_bytecode_with_proof() -> Result<()> {
        let file = fs::read_to_string(
            "../test_assets/portalnet/content/state/contract_bytecode_with_proof.json",
        )?;
        let value: Value = serde_json::from_str(&file)?;
        let json = value.as_object().unwrap();

        let expected_content_value =
            StateContentValue::ContractBytecodeWithProof(ContractBytecodeWithProof {
                code: ByteCode::from(json_as_hex(&json["bytecode"])),
                account_proof: AccountTrieWitness {
                    path: json_as_nibbles(&json["nibbles"]),
                    proof: json_as_proof(&json["proof"]),
                },
                block_hash: json_as_h256(&json["block_hash"]),
            });
        let content_value = StateContentValue::decode(&json_as_hex(&json["content_value"]))?;

        assert_eq!(content_value, expected_content_value);

        Ok(())
    }

    #[rstest]
    #[case::trie_node("trie_node.json")]
    #[case::account_trie_node_with_proof("account_trie_node_with_proof.json")]
    #[case::contract_storage_trie_node_with_proof("contract_storage_trie_node_with_proof.json")]
    #[case::contract_bytecode("contract_bytecode.json")]
    #[case::contract_bytecode_with_proof("contract_bytecode_with_proof.json")]
    fn encode_decode(#[case] filename: &str) -> Result<()> {
        let file =
            fs::read_to_string(format!("../test_assets/portalnet/content/state/{filename}"))?;
        let value: Value = serde_json::from_str(&file)?;
        let json = value.as_object().unwrap();

        let content_value_bytes = hex_decode(json["content_value"].as_str().unwrap())?;

        let content_value = StateContentValue::decode(&content_value_bytes)?;

        assert_eq!(content_value.encode(), content_value_bytes);

        Ok(())
    }

    fn json_as_h256(value: &Value) -> H256 {
        H256::from_str(value.as_str().unwrap()).unwrap()
    }

    fn json_as_hex(value: &Value) -> Vec<u8> {
        hex_decode(value.as_str().unwrap()).unwrap()
    }

    fn json_as_nibbles(value: &Value) -> Nibbles {
        let nibbles: Vec<u8> = value
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect();
        Nibbles::try_from_unpacked_nibbles(&nibbles).unwrap()
    }

    fn json_as_proof(value: &Value) -> TrieWitness {
        TrieWitness::from(
            value
                .as_array()
                .unwrap()
                .iter()
                .map(|v| EncodedTrieNode::from(json_as_hex(v)))
                .collect::<Vec<EncodedTrieNode>>(),
        )
    }
}
