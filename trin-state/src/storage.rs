use alloy::primitives::keccak256;
use ethportal_api::{
    types::{
        content_key::state::{AccountTrieNodeKey, ContractBytecodeKey, ContractStorageTrieNodeKey},
        content_value::state::{ContractBytecode, TrieNode},
        distance::Distance,
        network::Subnetwork,
        portal::PaginateLocalContentInfo,
    },
    ContentValue, OverlayContentKey, RawContentValue, StateContentKey, StateContentValue,
};
use trin_storage::{
    error::ContentStoreError,
    versioned::{create_store, ContentType, IdIndexedV1Store, IdIndexedV1StoreConfig},
    ContentId, ContentStore, PortalStorageConfig, ShouldWeStoreContent,
};

/// Storage layer for the state network. Encapsulates state network specific data and logic.
#[derive(Debug)]
pub struct StateStorage {
    store: IdIndexedV1Store<StateContentKey>,
}

impl ContentStore for StateStorage {
    type Key = StateContentKey;

    fn get(&self, key: &StateContentKey) -> Result<Option<RawContentValue>, ContentStoreError> {
        self.store.lookup_content_value(&key.content_id().into())
    }

    fn put<V: AsRef<[u8]>>(
        &mut self,
        key: StateContentKey,
        value: V,
    ) -> Result<Vec<(StateContentKey, RawContentValue)>, ContentStoreError> {
        let value = StateContentValue::decode(&key, value.as_ref())?;

        match &key {
            StateContentKey::AccountTrieNode(account_trie_node_key) => self
                .put_account_trie_node(&key, account_trie_node_key, value)
                // ignore any pruned content in state network
                .and(Ok(vec![])),
            StateContentKey::ContractStorageTrieNode(contract_storage_trie_key) => self
                .put_contract_storage_trie_node(&key, contract_storage_trie_key, value)
                .and(Ok(vec![])),
            StateContentKey::ContractBytecode(contract_bytecode_key) => self
                .put_contract_bytecode(&key, contract_bytecode_key, value)
                .and(Ok(vec![])),
        }
    }

    fn is_key_within_radius_and_unavailable(
        &self,
        key: &StateContentKey,
    ) -> Result<ShouldWeStoreContent, ContentStoreError> {
        let content_id = ContentId::from(key.content_id());
        if self.store.distance_to_content_id(&content_id) > self.store.radius() {
            Ok(ShouldWeStoreContent::NotWithinRadius)
        } else if self.store.has_content(&content_id)? {
            Ok(ShouldWeStoreContent::AlreadyStored)
        } else {
            Ok(ShouldWeStoreContent::Store)
        }
    }

    fn radius(&self) -> Distance {
        IdIndexedV1Store::radius(&self.store)
    }
}

impl StateStorage {
    pub fn new(config: PortalStorageConfig) -> Result<Self, ContentStoreError> {
        let sql_connection_pool = config.sql_connection_pool.clone();
        let config = IdIndexedV1StoreConfig::new(ContentType::State, Subnetwork::State, config);
        Ok(Self {
            store: create_store(ContentType::State, config, sql_connection_pool)?,
        })
    }

    /// Returns a paginated list of all locally available content keys, according to the provided
    /// offset and limit.
    pub fn paginate(
        &self,
        offset: u64,
        limit: u64,
    ) -> Result<PaginateLocalContentInfo<StateContentKey>, ContentStoreError> {
        let paginate_result = self.store.paginate(offset, limit)?;
        Ok(PaginateLocalContentInfo {
            content_keys: paginate_result.content_keys,
            total_entries: paginate_result.entry_count,
        })
    }

    /// Get a summary of the current state of storage
    pub fn get_summary_info(&self) -> String {
        self.store.get_summary_info()
    }

    fn put_account_trie_node(
        &mut self,
        content_key: &StateContentKey,
        key: &AccountTrieNodeKey,
        value: StateContentValue,
    ) -> Result<Vec<(StateContentKey, RawContentValue)>, ContentStoreError> {
        let StateContentValue::AccountTrieNodeWithProof(value) = value else {
            return Err(ContentStoreError::InvalidData {
                message: format!(
                    "Expected AccountTrieNodeWithProof, but received {value:?} instead"
                ),
            });
        };
        let Some(last_trie_node) = value.proof.last() else {
            return Err(ContentStoreError::InvalidData {
                message: "Expected Trie nodes in the proof but none were present".to_string(),
            });
        };
        let last_node_hash = keccak256(&last_trie_node[..]);

        if last_node_hash != key.node_hash {
            return Err(ContentStoreError::InvalidData {
                message: format!(
                    "Hash of the trie node ({last_node_hash}) doesn't match key's node_hash ({})",
                    key.node_hash
                ),
            });
        }

        let trie_node = TrieNode {
            node: last_trie_node.clone(),
        };
        self.store
            .insert(content_key, StateContentValue::TrieNode(trie_node).encode())
    }

    fn put_contract_storage_trie_node(
        &mut self,
        content_key: &StateContentKey,
        key: &ContractStorageTrieNodeKey,
        value: StateContentValue,
    ) -> Result<Vec<(StateContentKey, RawContentValue)>, ContentStoreError> {
        let StateContentValue::ContractStorageTrieNodeWithProof(value) = value else {
            return Err(ContentStoreError::InvalidData {
                message: format!(
                    "Expected ContractStorageTrieNodeWithProof, but received {value:?} instead"
                ),
            });
        };
        let Some(last_trie_node) = value.storage_proof.last() else {
            return Err(ContentStoreError::InvalidData {
                message: "Expected Trie nodes in the proof but none were present".to_string(),
            });
        };
        let last_node_hash = keccak256(&last_trie_node[..]);

        if last_node_hash != key.node_hash {
            return Err(ContentStoreError::InvalidData {
                message: format!(
                    "Hash of the trie node ({last_node_hash}) doesn't match key's node_hash ({})",
                    key.node_hash
                ),
            });
        }

        let trie_node = TrieNode {
            node: last_trie_node.clone(),
        };
        self.store
            .insert(content_key, StateContentValue::TrieNode(trie_node).encode())
    }

    fn put_contract_bytecode(
        &mut self,
        content_key: &StateContentKey,
        key: &ContractBytecodeKey,
        value: StateContentValue,
    ) -> Result<Vec<(StateContentKey, RawContentValue)>, ContentStoreError> {
        let StateContentValue::ContractBytecodeWithProof(value) = value else {
            return Err(ContentStoreError::InvalidData {
                message: format!(
                    "Expected ContractBytecodeWithProof, but received {value:?} instead"
                ),
            });
        };
        let bytes_hash = keccak256(&value.code[..]);

        if bytes_hash != key.code_hash {
            return Err(ContentStoreError::InvalidData {
                message: format!(
                    "Hash of the code ({bytes_hash}) doesn't match key's code_hash ({})",
                    key.code_hash
                ),
            });
        }

        let contract_code = ContractBytecode { code: value.code };

        self.store.insert(
            content_key,
            StateContentValue::ContractBytecode(contract_code).encode(),
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub mod test {
    use std::path::PathBuf;

    use anyhow::Result;
    use ethportal_api::RawContentValue;
    use rstest::rstest;
    use serde::Deserialize;
    use tracing::info;
    use trin_storage::test_utils::create_test_portal_storage_config_with_capacity;
    use trin_utils::submodules::read_portal_spec_tests_file;

    use super::*;

    const STORAGE_CAPACITY_MB: u32 = 10;

    struct ContentData {
        key: StateContentKey,
        store_value: RawContentValue,
        lookup_value: RawContentValue,
    }

    #[rstest]
    #[case::account_trie_node("account_trie_node.yaml")]
    #[case::contract_storage_trie_node("contract_storage_trie_node.yaml")]
    #[case::contract_bytecode("contract_bytecode.yaml")]
    fn put_get(#[case] file_name: &str) -> Result<()> {
        let (_temp_dir, config) =
            create_test_portal_storage_config_with_capacity(STORAGE_CAPACITY_MB)?;
        let mut storage = StateStorage::new(config)?;

        for test_case in read_test_cases(file_name)? {
            info!("Testing key: {}", test_case.key);

            storage.put(test_case.key.clone(), test_case.store_value)?;

            assert_eq!(storage.get(&test_case.key)?, Some(test_case.lookup_value));
        }

        Ok(())
    }

    #[rstest]
    #[case::account_trie_node("account_trie_node.yaml")]
    #[case::contract_storage_trie_node("contract_storage_trie_node.yaml")]
    #[case::contract_bytecode("contract_bytecode.yaml")]
    fn put_should_fail_for_lookup_value(#[case] file_name: &str) -> Result<()> {
        let (_temp_dir, config) =
            create_test_portal_storage_config_with_capacity(STORAGE_CAPACITY_MB)?;
        let mut storage = StateStorage::new(config)?;

        for test_case in read_test_cases(file_name)? {
            info!("Testing key: {}", test_case.key);

            let put_result = storage.put(test_case.key.clone(), test_case.lookup_value);
            assert!(matches!(
                put_result,
                Err(ContentStoreError::InvalidData { .. })
            ));
        }

        Ok(())
    }

    fn read_test_cases(filename: &str) -> Result<Vec<ContentData>> {
        let file = read_portal_spec_tests_file(
            PathBuf::from("tests/mainnet/state/validation").join(filename),
        )?;
        let value: serde_yaml::Value = serde_yaml::from_str(&file)?;

        let mut result = vec![];

        for value in value.as_sequence().unwrap() {
            result.push(ContentData {
                key: StateContentKey::deserialize(&value["content_key"])?,
                store_value: RawContentValue::deserialize(&value["content_value_offer"])?,
                lookup_value: RawContentValue::deserialize(&value["content_value_retrieval"])?,
            });
        }

        Ok(result)
    }
}
