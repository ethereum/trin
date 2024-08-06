use std::sync::Arc;

use alloy_primitives::{keccak256, B256};
use anyhow::anyhow;
use ethportal_api::{
    types::content_key::state::{
        AccountTrieNodeKey, ContractBytecodeKey, ContractStorageTrieNodeKey,
    },
    ContentValue, StateContentKey, StateContentValue,
};
use tokio::sync::RwLock;
use tracing::debug;
use trin_validation::{
    oracle::HeaderOracle,
    validator::{ValidationResult, Validator},
};

use super::{
    error::StateValidationError,
    trie::{validate_account_state, validate_node_trie_proof},
};

pub struct StateValidator {
    pub header_oracle: Arc<RwLock<HeaderOracle>>,
}

impl Validator<StateContentKey> for StateValidator {
    async fn validate_content(
        &self,
        content_key: &StateContentKey,
        content_value: &[u8],
    ) -> anyhow::Result<ValidationResult<StateContentKey>> {
        let content_value = StateContentValue::decode(content_value)
            .map_err(|err| anyhow!("Error decoding StateContentValue: {err}"))?;

        match content_key {
            StateContentKey::AccountTrieNode(key) => {
                Ok(self.validate_account_trie_node(key, content_value).await?)
            }
            StateContentKey::ContractStorageTrieNode(key) => Ok(self
                .validate_contract_storage_trie_node(key, content_value)
                .await?),
            StateContentKey::ContractBytecode(key) => {
                Ok(self.validate_contract_bytecode(key, content_value).await?)
            }
        }
    }
}

impl StateValidator {
    async fn validate_account_trie_node(
        &self,
        key: &AccountTrieNodeKey,
        value: StateContentValue,
    ) -> Result<ValidationResult<StateContentKey>, StateValidationError> {
        match value {
            StateContentValue::TrieNode(value) => {
                if value.node.node_hash() == key.node_hash {
                    Ok(ValidationResult::new(/* valid_for_storing= */ false))
                } else {
                    Err(StateValidationError::InvalidNodeHash {
                        node_hash: value.node.node_hash(),
                        expected_node_hash: key.node_hash,
                    })
                }
            }
            StateContentValue::AccountTrieNodeWithProof(value) => {
                let state_root = self.get_state_root(value.block_hash).await;
                validate_node_trie_proof(state_root, key.node_hash, &key.path, &value.proof)?;

                Ok(ValidationResult::new(/* valid_for_storing= */ true))
            }
            _ => Err(StateValidationError::InvalidContentValueType(
                "AccountTrieNodeKey",
            )),
        }
    }

    async fn validate_contract_storage_trie_node(
        &self,
        key: &ContractStorageTrieNodeKey,
        value: StateContentValue,
    ) -> Result<ValidationResult<StateContentKey>, StateValidationError> {
        match value {
            StateContentValue::TrieNode(value) => {
                if value.node.node_hash() == key.node_hash {
                    Ok(ValidationResult::new(/* valid_for_storing= */ false))
                } else {
                    Err(StateValidationError::InvalidNodeHash {
                        node_hash: value.node.node_hash(),
                        expected_node_hash: key.node_hash,
                    })
                }
            }
            StateContentValue::ContractStorageTrieNodeWithProof(value) => {
                let state_root = self.get_state_root(value.block_hash).await;
                let account_state =
                    validate_account_state(state_root, &key.address_hash, &value.account_proof)?;
                validate_node_trie_proof(
                    Some(account_state.storage_root),
                    key.node_hash,
                    &key.path,
                    &value.storage_proof,
                )?;

                Ok(ValidationResult::new(/* valid_for_storing= */ true))
            }
            _ => Err(StateValidationError::InvalidContentValueType(
                "ContractStorageTrieNodeKey",
            )),
        }
    }

    async fn validate_contract_bytecode(
        &self,
        key: &ContractBytecodeKey,
        value: StateContentValue,
    ) -> Result<ValidationResult<StateContentKey>, StateValidationError> {
        match value {
            StateContentValue::ContractBytecode(value) => {
                let bytecode_hash = keccak256(&value.code[..]);
                if bytecode_hash == key.code_hash {
                    Ok(ValidationResult::new(/* valid_for_storing= */ false))
                } else {
                    Err(StateValidationError::InvalidBytecodeHash {
                        bytecode_hash,
                        expected_bytecode_hash: key.code_hash,
                    })
                }
            }
            StateContentValue::ContractBytecodeWithProof(value) => {
                let bytecode_hash = keccak256(&value.code[..]);
                if bytecode_hash != key.code_hash {
                    return Err(StateValidationError::InvalidBytecodeHash {
                        bytecode_hash,
                        expected_bytecode_hash: key.code_hash,
                    });
                }

                let state_root = self.get_state_root(value.block_hash).await;
                let account_state =
                    validate_account_state(state_root, &key.address_hash, &value.account_proof)?;
                if account_state.code_hash == key.code_hash {
                    Ok(ValidationResult::new(/* valid_for_storing= */ true))
                } else {
                    Err(StateValidationError::InvalidBytecodeHash {
                        bytecode_hash,
                        expected_bytecode_hash: account_state.code_hash,
                    })
                }
            }
            _ => Err(StateValidationError::InvalidContentValueType(
                "ContractBytecodeKey",
            )),
        }
    }

    async fn get_state_root(&self, _block_hash: B256) -> Option<B256> {
        // Currently not implemented as history network is not reliable
        debug!("Fetching state root is not yet implemented");
        None
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use anyhow::Result;
    use ethportal_api::{utils::bytes::hex_decode, OverlayContentKey};
    use serde::Deserialize;
    use serde_yaml::Value;
    use trin_utils::submodules::read_portal_spec_tests_file;

    use super::*;

    const TEST_DIRECTORY: &str = "tests/mainnet/state/validation";

    fn create_validator() -> StateValidator {
        let header_oracle = Arc::new(RwLock::new(HeaderOracle::default()));
        StateValidator { header_oracle }
    }

    fn read_yaml_file_as_sequence(filename: &str) -> Vec<Value> {
        let yaml_file = read_portal_spec_tests_file(PathBuf::from(TEST_DIRECTORY).join(filename))
            .expect("to read yaml file");

        serde_yaml::from_str::<Value>(&yaml_file)
            .expect("to decode yaml file")
            .as_sequence()
            .expect("to be sequence")
            .clone()
    }

    #[tokio::test]
    async fn account_trie_node_retrieval() -> Result<()> {
        let validator = create_validator();

        let test_cases = read_yaml_file_as_sequence("account_trie_node.yaml");
        for test_case in test_cases {
            let content_key = StateContentKey::deserialize(&test_case["content_key"])?;
            let content_value = String::deserialize(&test_case["content_value_retrieval"])?;

            let validation_result = validator
                .validate_content(&content_key, &hex_decode(&content_value)?)
                .await?;
            assert_eq!(
                validation_result,
                ValidationResult::new(false),
                "testing content_key: {}",
                content_key.to_hex()
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn account_trie_node_offer() -> Result<()> {
        let validator = create_validator();

        let test_cases = read_yaml_file_as_sequence("account_trie_node.yaml");
        for test_case in test_cases {
            let content_key = StateContentKey::deserialize(&test_case["content_key"])?;
            let content_value = String::deserialize(&test_case["content_value_offer"])?;

            let validation_result = validator
                .validate_content(&content_key, &hex_decode(&content_value)?)
                .await?;

            assert_eq!(
                validation_result,
                ValidationResult::new(true),
                "testing content_key: {}",
                content_key.to_hex()
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn contract_storage_trie_node_retrieval() -> Result<()> {
        let validator = create_validator();

        let test_cases = read_yaml_file_as_sequence("contract_storage_trie_node.yaml");
        for test_case in test_cases {
            let content_key = StateContentKey::deserialize(&test_case["content_key"])?;
            let content_value = String::deserialize(&test_case["content_value_retrieval"])?;

            let validation_result = validator
                .validate_content(&content_key, &hex_decode(&content_value)?)
                .await?;
            assert_eq!(
                validation_result,
                ValidationResult::new(false),
                "testing content_key: {}",
                content_key.to_hex()
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn contract_storage_trie_node_offer() -> Result<()> {
        let validator = create_validator();

        let test_cases = read_yaml_file_as_sequence("contract_storage_trie_node.yaml");
        for test_case in test_cases {
            let content_key = StateContentKey::deserialize(&test_case["content_key"])?;
            let content_value = String::deserialize(&test_case["content_value_offer"])?;

            let validation_result = validator
                .validate_content(&content_key, &hex_decode(&content_value)?)
                .await?;

            assert_eq!(
                validation_result,
                ValidationResult::new(true),
                "testing content_key: {}",
                content_key.to_hex()
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn contract_bytecode_retrieval() -> Result<()> {
        let validator = create_validator();

        let test_cases = read_yaml_file_as_sequence("contract_bytecode.yaml");
        for test_case in test_cases {
            let content_key = StateContentKey::deserialize(&test_case["content_key"])?;
            let content_value = String::deserialize(&test_case["content_value_retrieval"])?;

            let validation_result = validator
                .validate_content(&content_key, &hex_decode(&content_value)?)
                .await?;
            assert_eq!(
                validation_result,
                ValidationResult::new(false),
                "testing content_key: {}",
                content_key.to_hex()
            );
        }

        Ok(())
    }

    #[tokio::test]
    async fn contract_bytecode_offer() -> Result<()> {
        let validator = create_validator();

        let test_cases = read_yaml_file_as_sequence("contract_bytecode.yaml");
        for test_case in test_cases {
            let content_key = StateContentKey::deserialize(&test_case["content_key"])?;
            let content_value = String::deserialize(&test_case["content_value_offer"])?;

            let validation_result = validator
                .validate_content(&content_key, &hex_decode(&content_value)?)
                .await?;
            assert_eq!(
                validation_result,
                ValidationResult::new(true),
                "testing content_key: {}",
                content_key.to_hex()
            );
        }

        Ok(())
    }
}
