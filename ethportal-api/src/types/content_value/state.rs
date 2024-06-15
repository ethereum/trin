use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};

use crate::{
    types::state_trie::{ByteCode, EncodedTrieNode, TrieProof},
    utils::bytes::hex_encode,
    ContentValue, ContentValueError,
};

/// A Portal State content value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateContentValue {
    /// A content value type for retrieving a trie node.
    TrieNode(TrieNode),
    /// A content value type for offering a trie node from the account trie.
    AccountTrieNodeWithProof(AccountTrieNodeWithProof),
    /// A content value type for offering a trie node from the contract storage trie.
    ContractStorageTrieNodeWithProof(ContractStorageTrieNodeWithProof),
    /// A content value type for retrieving contract's bytecode.
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
        if let Ok(value) = TrieNode::from_ssz_bytes(buf) {
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

impl Serialize for StateContentValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for StateContentValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// A content value type, used when retrieving a trie node.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct TrieNode {
    pub node: EncodedTrieNode,
}

/// A content value type, used when offering a trie node from the account trie.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct AccountTrieNodeWithProof {
    /// An proof for the account trie node.
    pub proof: TrieProof,
    /// A block at which the proof is anchored.
    pub block_hash: B256,
}
/// A content value type, used when offering a trie node from the contract storage trie.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct ContractStorageTrieNodeWithProof {
    /// A proof for the contract storage trie node.
    pub storage_proof: TrieProof,
    /// A proof for the account state.
    pub account_proof: TrieProof,
    /// A block at which the proof is anchored.
    pub block_hash: B256,
}

/// A content value type, used when retrieving contract's bytecode.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct ContractBytecode {
    pub code: ByteCode,
}

/// A content value type, used when offering contract's bytecode.
#[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
pub struct ContractBytecodeWithProof {
    /// A contract's bytecode.
    pub code: ByteCode,
    /// A proof for the account state of the corresponding contract.
    pub account_proof: TrieProof,
    /// A block at which the proof is anchored.
    pub block_hash: B256,
}

#[cfg(test)]
mod test {
    use std::{path::PathBuf, str::FromStr};

    use anyhow::Result;
    use rstest::rstest;
    use serde_yaml::Value;

    use crate::{test_utils::read_file_from_tests_submodule, utils::bytes::hex_decode};

    use super::*;

    const TEST_DATA_DIRECTORY: &str = "tests/mainnet/state/serialization";

    #[test]
    fn trie_node() -> Result<()> {
        let value = read_yaml_file("trie_node.yaml")?;
        let value = value.as_mapping().unwrap();

        let expected_content_value = StateContentValue::TrieNode(TrieNode {
            node: EncodedTrieNode::from(yaml_as_hex(&value["trie_node"])),
        });

        assert_content_value(&value["content_value"], expected_content_value);

        Ok(())
    }

    #[test]
    fn account_trie_node_with_proof() -> Result<()> {
        let value = read_yaml_file("account_trie_node_with_proof.yaml")?;
        let value = value.as_mapping().unwrap();

        let expected_content_value =
            StateContentValue::AccountTrieNodeWithProof(AccountTrieNodeWithProof {
                proof: yaml_as_proof(&value["proof"]),
                block_hash: yaml_as_b256(&value["block_hash"]),
            });

        assert_content_value(&value["content_value"], expected_content_value);

        Ok(())
    }

    #[test]
    fn contract_storage_trie_node_with_proof() -> Result<()> {
        let value = read_yaml_file("contract_storage_trie_node_with_proof.yaml")?;
        let value = value.as_mapping().unwrap();

        let expected_content_value =
            StateContentValue::ContractStorageTrieNodeWithProof(ContractStorageTrieNodeWithProof {
                storage_proof: yaml_as_proof(&value["storage_proof"]),
                account_proof: yaml_as_proof(&value["account_proof"]),
                block_hash: yaml_as_b256(&value["block_hash"]),
            });

        assert_content_value(&value["content_value"], expected_content_value);

        Ok(())
    }

    #[test]
    fn contract_bytecode() -> Result<()> {
        let value = read_yaml_file("contract_bytecode.yaml")?;
        let value = value.as_mapping().unwrap();

        let expected_content_value = StateContentValue::ContractBytecode(ContractBytecode {
            code: ByteCode::from(yaml_as_hex(&value["bytecode"])),
        });

        assert_content_value(&value["content_value"], expected_content_value);

        Ok(())
    }

    #[test]
    fn contract_bytecode_with_proof() -> Result<()> {
        let value = read_yaml_file("contract_bytecode_with_proof.yaml")?;
        let value = value.as_mapping().unwrap();

        let expected_content_value =
            StateContentValue::ContractBytecodeWithProof(ContractBytecodeWithProof {
                code: ByteCode::from(yaml_as_hex(&value["bytecode"])),
                account_proof: yaml_as_proof(&value["account_proof"]),
                block_hash: yaml_as_b256(&value["block_hash"]),
            });

        assert_content_value(&value["content_value"], expected_content_value);

        Ok(())
    }

    #[rstest]
    #[case::trie_node("trie_node.yaml")]
    #[case::account_trie_node_with_proof("account_trie_node_with_proof.yaml")]
    #[case::contract_storage_trie_node_with_proof("contract_storage_trie_node_with_proof.yaml")]
    #[case::contract_bytecode("contract_bytecode.yaml")]
    #[case::contract_bytecode_with_proof("contract_bytecode_with_proof.yaml")]
    fn encode_decode(#[case] filename: &str) -> Result<()> {
        let value = read_yaml_file(filename)?;
        let value = value.as_mapping().unwrap();

        let content_value_bytes = yaml_as_hex(&value["content_value"]);

        let content_value = StateContentValue::decode(&content_value_bytes)?;

        assert_eq!(content_value.encode(), content_value_bytes);

        Ok(())
    }

    #[rstest]
    #[case::trie_node("trie_node.yaml")]
    #[case::account_trie_node_with_proof("account_trie_node_with_proof.yaml")]
    #[case::contract_storage_trie_node_with_proof("contract_storage_trie_node_with_proof.yaml")]
    #[case::contract_bytecode("contract_bytecode.yaml")]
    #[case::contract_bytecode_with_proof("contract_bytecode_with_proof.yaml")]
    fn serde(#[case] filename: &str) -> Result<()> {
        let value = read_yaml_file(filename)?;
        let value = value.as_mapping().unwrap();

        let content_value = StateContentValue::deserialize(&value["content_value"])?;

        assert_eq!(
            serde_yaml::to_value(content_value).unwrap(),
            value["content_value"]
        );

        Ok(())
    }

    fn read_yaml_file(filename: &str) -> Result<Value> {
        let path = PathBuf::from(TEST_DATA_DIRECTORY).join(filename);
        let file = read_file_from_tests_submodule(path)?;
        Ok(serde_yaml::from_str(&file)?)
    }

    fn yaml_as_b256(value: &Value) -> B256 {
        B256::from_str(value.as_str().unwrap()).unwrap()
    }

    fn yaml_as_hex(value: &Value) -> Vec<u8> {
        hex_decode(value.as_str().unwrap()).unwrap()
    }

    fn yaml_as_proof(value: &Value) -> TrieProof {
        TrieProof::from(
            value
                .as_sequence()
                .unwrap()
                .iter()
                .map(|v| EncodedTrieNode::from(yaml_as_hex(v)))
                .collect::<Vec<EncodedTrieNode>>(),
        )
    }

    fn assert_content_value(value: &Value, expected_content_value: StateContentValue) {
        assert_eq!(
            StateContentValue::decode(&yaml_as_hex(value)).unwrap(),
            expected_content_value,
            "decoding from bytes {value:?} didn't match expected value {expected_content_value:?}"
        );

        assert_eq!(
            StateContentValue::deserialize(value).unwrap(),
            expected_content_value,
            "deserialization from string {value:?} didn't match expected value {expected_content_value:?}");
    }
}
