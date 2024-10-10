use alloy::primitives::B256;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};

use crate::{
    types::{
        network::Subnetwork,
        state_trie::{ByteCode, EncodedTrieNode, TrieProof},
    },
    utils::bytes::hex_encode,
    ContentValue, ContentValueError, RawContentValue, StateContentKey,
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
    type TContentKey = StateContentKey;

    fn encode(&self) -> RawContentValue {
        match self {
            Self::TrieNode(value) => value.as_ssz_bytes().into(),
            Self::AccountTrieNodeWithProof(value) => value.as_ssz_bytes().into(),
            Self::ContractStorageTrieNodeWithProof(value) => value.as_ssz_bytes().into(),
            Self::ContractBytecode(value) => value.as_ssz_bytes().into(),
            Self::ContractBytecodeWithProof(value) => value.as_ssz_bytes().into(),
        }
    }

    fn decode(key: &Self::TContentKey, buf: &[u8]) -> Result<Self, ContentValueError> {
        match key {
            StateContentKey::AccountTrieNode(_) => {
                if let Ok(value) = AccountTrieNodeWithProof::from_ssz_bytes(buf) {
                    return Ok(Self::AccountTrieNodeWithProof(value));
                }
                if let Ok(value) = TrieNode::from_ssz_bytes(buf) {
                    return Ok(Self::TrieNode(value));
                }
            }
            StateContentKey::ContractStorageTrieNode(_) => {
                if let Ok(value) = ContractStorageTrieNodeWithProof::from_ssz_bytes(buf) {
                    return Ok(Self::ContractStorageTrieNodeWithProof(value));
                }
                if let Ok(value) = TrieNode::from_ssz_bytes(buf) {
                    return Ok(Self::TrieNode(value));
                }
            }
            StateContentKey::ContractBytecode(_) => {
                if let Ok(value) = ContractBytecodeWithProof::from_ssz_bytes(buf) {
                    return Ok(Self::ContractBytecodeWithProof(value));
                }
                if let Ok(value) = ContractBytecode::from_ssz_bytes(buf) {
                    return Ok(Self::ContractBytecode(value));
                }
            }
        }
        Err(ContentValueError::UnknownContent {
            bytes: hex_encode(buf),
            subnetwork: Subnetwork::State,
        })
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
    use std::path::PathBuf;

    use alloy::primitives::Bytes;
    use anyhow::Result;
    use rstest::rstest;
    use serde::Deserialize;
    use serde_yaml::Value;

    use crate::test_utils::read_file_from_tests_submodule;

    use super::*;

    const TEST_DATA_DIRECTORY: &str = "tests/mainnet/state/serialization";

    #[test]
    fn trie_node() -> Result<()> {
        let value = read_yaml_file("trie_node.yaml")?;
        let expected_content_value = StateContentValue::TrieNode(TrieNode {
            node: yaml_to_bytes(&value["trie_node"]).into(),
        });

        assert_eq!(
            expected_content_value.encode(),
            RawContentValue::deserialize(&value["content_value"])?,
        );

        Ok(())
    }

    #[test]
    fn account_trie_node_with_proof() -> Result<()> {
        let value = read_yaml_file("account_trie_node_with_proof.yaml")?;

        let expected_content_value =
            StateContentValue::AccountTrieNodeWithProof(AccountTrieNodeWithProof {
                proof: yaml_as_proof(&value["proof"]),
                block_hash: B256::deserialize(&value["block_hash"])?,
            });

        assert_eq!(
            expected_content_value.encode(),
            RawContentValue::deserialize(&value["content_value"])?,
        );

        Ok(())
    }

    #[test]
    fn contract_storage_trie_node_with_proof() -> Result<()> {
        let value = read_yaml_file("contract_storage_trie_node_with_proof.yaml")?;

        let expected_content_value =
            StateContentValue::ContractStorageTrieNodeWithProof(ContractStorageTrieNodeWithProof {
                storage_proof: yaml_as_proof(&value["storage_proof"]),
                account_proof: yaml_as_proof(&value["account_proof"]),
                block_hash: B256::deserialize(&value["block_hash"])?,
            });

        assert_eq!(
            expected_content_value.encode(),
            RawContentValue::deserialize(&value["content_value"])?,
        );

        Ok(())
    }

    #[test]
    fn contract_bytecode() -> Result<()> {
        let value = read_yaml_file("contract_bytecode.yaml")?;

        let expected_content_value = StateContentValue::ContractBytecode(ContractBytecode {
            code: yaml_to_bytes(&value["bytecode"]).into(),
        });

        assert_eq!(
            expected_content_value.encode(),
            RawContentValue::deserialize(&value["content_value"])?,
        );

        Ok(())
    }

    #[test]
    fn contract_bytecode_with_proof() -> Result<()> {
        let value = read_yaml_file("contract_bytecode_with_proof.yaml")?;

        let expected_content_value =
            StateContentValue::ContractBytecodeWithProof(ContractBytecodeWithProof {
                code: yaml_to_bytes(&value["bytecode"]).into(),
                account_proof: yaml_as_proof(&value["account_proof"]),
                block_hash: B256::deserialize(&value["block_hash"])?,
            });

        assert_eq!(
            expected_content_value.encode(),
            RawContentValue::deserialize(&value["content_value"])?,
        );

        Ok(())
    }

    #[rstest]
    #[case::trie_node("account_trie_node_key.yaml", "trie_node.yaml")]
    #[case::account_trie_node_with_proof(
        "account_trie_node_key.yaml",
        "account_trie_node_with_proof.yaml"
    )]
    #[case::contract_storage_trie_node_with_proof(
        "contract_storage_trie_node_key.yaml",
        "contract_storage_trie_node_with_proof.yaml"
    )]
    #[case::contract_bytecode("contract_bytecode_key.yaml", "contract_bytecode.yaml")]
    #[case::contract_bytecode_with_proof(
        "contract_bytecode_key.yaml",
        "contract_bytecode_with_proof.yaml"
    )]
    fn encode_decode(#[case] key_filename: &str, #[case] value_filename: &str) -> Result<()> {
        let key_file = read_yaml_file(key_filename)?;
        let key = StateContentKey::deserialize(&key_file["content_key"])?;

        let value = read_yaml_file(value_filename)?;

        let content_value_bytes = RawContentValue::deserialize(&value["content_value"])?;
        let content_value = StateContentValue::decode(&key, &content_value_bytes)?;

        assert_eq!(content_value.encode(), content_value_bytes);
        Ok(())
    }

    #[rstest]
    #[case::trie_node("account_trie_node_key.yaml", "trie_node.yaml")]
    #[case::account_trie_node_with_proof(
        "account_trie_node_key.yaml",
        "account_trie_node_with_proof.yaml"
    )]
    #[case::contract_storage_trie_node_with_proof(
        "contract_storage_trie_node_key.yaml",
        "contract_storage_trie_node_with_proof.yaml"
    )]
    #[case::contract_bytecode("contract_bytecode_key.yaml", "contract_bytecode.yaml")]
    #[case::contract_bytecode_with_proof(
        "contract_bytecode_key.yaml",
        "contract_bytecode_with_proof.yaml"
    )]
    fn hex_str(#[case] key_filename: &str, #[case] value_filename: &str) -> Result<()> {
        let key_file = read_yaml_file(key_filename)?;
        let key = StateContentKey::deserialize(&key_file["content_key"])?;

        let value = read_yaml_file(value_filename)?;
        let content_value_str = String::deserialize(&value["content_value"])?;
        let content_value = StateContentValue::from_hex(&key, &content_value_str)?;

        assert_eq!(content_value.to_hex(), content_value_str);
        Ok(())
    }

    fn read_yaml_file(filename: &str) -> Result<Value> {
        let path = PathBuf::from(TEST_DATA_DIRECTORY).join(filename);
        let file = read_file_from_tests_submodule(path)?;
        Ok(serde_yaml::from_str(&file)?)
    }

    fn yaml_to_bytes(value: &Value) -> Vec<u8> {
        Bytes::deserialize(value).unwrap().to_vec()
    }

    fn yaml_as_proof(value: &Value) -> TrieProof {
        TrieProof::new(
            value
                .as_sequence()
                .unwrap()
                .iter()
                .map(yaml_to_bytes)
                .map(EncodedTrieNode::from)
                .collect(),
        )
        .unwrap()
    }
}
