use ethportal_api::{
    types::{
        content_key::state::{AccountTrieNodeKey, ContractBytecodeKey, ContractStorageTrieNodeKey},
        content_value::state::{ContractBytecode, TrieNode},
        distance::Distance,
        portal_wire::ProtocolId,
    },
    ContentValue, OverlayContentKey, StateContentKey, StateContentValue,
};
use keccak_hash::keccak;
use trin_storage::{
    error::ContentStoreError,
    versioned::{create_store, ContentType, IdIndexedV1Store, IdIndexedV1StoreConfig},
    ContentId, ContentStore, PortalStorageConfig, ShouldWeStoreContent, BYTES_IN_MB_U64,
};

/// Storage layer for the state network. Encapsulates state network specific data and logic.
#[derive(Debug)]
pub struct StateStorage {
    store: IdIndexedV1Store,
}

impl ContentStore for StateStorage {
    async fn get<K: OverlayContentKey>(
        &self,
        key: &K,
    ) -> Result<Option<Vec<u8>>, ContentStoreError> {
        self.store
            .lookup_content_value(&key.content_id().into())
            .await
    }

    async fn put<K: OverlayContentKey>(
        &mut self,
        key: K,
        value: Vec<u8>,
    ) -> Result<(), ContentStoreError> {
        let key = StateContentKey::try_from(key.to_bytes())?;
        let value = StateContentValue::decode(value.as_ref())?;

        match &key {
            StateContentKey::AccountTrieNode(account_trie_node_key) => {
                self.put_account_trie_node(&key, account_trie_node_key, value)
                    .await
            }
            StateContentKey::ContractStorageTrieNode(contract_storage_trie_key) => {
                self.put_contract_storage_trie_node(&key, contract_storage_trie_key, value)
                    .await
            }
            StateContentKey::ContractBytecode(contract_bytecode_key) => {
                self.put_contract_bytecode(&key, contract_bytecode_key, value)
                    .await
            }
        }
    }

    async fn is_key_within_radius_and_unavailable<K: OverlayContentKey>(
        &self,
        key: &K,
    ) -> Result<ShouldWeStoreContent, ContentStoreError> {
        let content_id = ContentId::from(key.content_id());
        if self.store.distance_to_content_id(&content_id) > self.store.radius() {
            Ok(ShouldWeStoreContent::NotWithinRadius)
        } else if self.store.has_content(&content_id).await? {
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
    pub async fn new(config: PortalStorageConfig) -> Result<Self, ContentStoreError> {
        let sql_connection_pool = config.sql_connection_pool.clone();
        let config = IdIndexedV1StoreConfig {
            content_type: ContentType::State,
            network: ProtocolId::State,
            node_id: config.node_id,
            node_data_dir: config.node_data_dir,
            distance_fn: config.distance_fn,
            sql_connection_pool: config.sql_connection_pool,
            storage_capacity_bytes: config.storage_capacity_mb * BYTES_IN_MB_U64,
        };
        Ok(Self {
            store: create_store(ContentType::State, config, sql_connection_pool).await?,
        })
    }

    /// Get a summary of the current state of storage
    pub async fn get_summary_info(&self) -> String {
        self.store.get_summary_info().await
    }

    async fn put_account_trie_node(
        &mut self,
        content_key: &StateContentKey,
        key: &AccountTrieNodeKey,
        value: StateContentValue,
    ) -> Result<(), ContentStoreError> {
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
        let last_node_hash = keccak(&last_trie_node[..]);

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
            .await
    }

    async fn put_contract_storage_trie_node(
        &mut self,
        content_key: &StateContentKey,
        key: &ContractStorageTrieNodeKey,
        value: StateContentValue,
    ) -> Result<(), ContentStoreError> {
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
        let last_node_hash = keccak(&last_trie_node[..]);

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
            .await
    }

    async fn put_contract_bytecode(
        &mut self,
        content_key: &StateContentKey,
        key: &ContractBytecodeKey,
        value: StateContentValue,
    ) -> Result<(), ContentStoreError> {
        let StateContentValue::ContractBytecodeWithProof(value) = value else {
            return Err(ContentStoreError::InvalidData {
                message: format!(
                    "Expected ContractBytecodeWithProof, but received {value:?} instead"
                ),
            });
        };
        let bytes_hash = keccak(&value.code[..]);

        if bytes_hash != key.code_hash {
            return Err(ContentStoreError::InvalidData {
                message: format!(
                    "Hash of the code ({bytes_hash}) doesn't match key's code_hash ({})",
                    key.code_hash
                ),
            });
        }

        let contract_code = ContractBytecode { code: value.code };

        self.store
            .insert(
                content_key,
                StateContentValue::ContractBytecode(contract_code).encode(),
            )
            .await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub mod test {
    use std::path::PathBuf;

    use anyhow::{anyhow, Result};
    use ethportal_api::utils::bytes::hex_decode;
    use serde::Deserialize;
    use trin_storage::test_utils::create_test_portal_storage_config_with_capacity;
    use trin_utils::submodules::read_portal_spec_tests_file;

    use super::*;

    const STORAGE_CAPACITY_MB: u64 = 10;

    #[tokio::test]
    async fn account_trie_node() -> Result<()> {
        let (temp_dir, config) =
            create_test_portal_storage_config_with_capacity(STORAGE_CAPACITY_MB).await?;
        let mut storage = StateStorage::new(config).await?;

        let key_yaml = read_yaml_file("account_trie_node_key.yaml")?;
        let key = StateContentKey::deserialize(&key_yaml["content_key"])?;

        let value_yaml = read_yaml_file("account_trie_node_with_proof.yaml")?;
        let value = StateContentValue::deserialize(&value_yaml["content_value"])?;

        let expected_stored_value = "0x04000000f8719d20a65bd257638cf8cf09b8238888947cc3c0bea2aa2cc3f1c4ac7a3002b851f84f018b02b4f32ee2f03d31ee3fbba046d5eb15d44b160805e80d05e2a47d434053e6c4b3ef9d1111773039e9586661a0d0a06b12ac47863b5c7be4185c2deaad1c61557033f56c7d4ea74429cbb25e23";

        storage.put(key.clone(), value.encode()).await?;

        assert_eq!(
            storage.get(&key).await.unwrap(),
            Some(hex_decode(expected_stored_value)?)
        );

        drop(temp_dir);
        Ok(())
    }

    #[tokio::test]
    async fn contract_storage_trie_node() -> Result<()> {
        let (temp_dir, config) =
            create_test_portal_storage_config_with_capacity(STORAGE_CAPACITY_MB).await?;
        let mut storage = StateStorage::new(config).await?;

        let key_yaml = read_yaml_file("contract_storage_trie_node_key.yaml")?;
        let key = StateContentKey::deserialize(&key_yaml["content_key"])?;

        let value_yaml = read_yaml_file("contract_storage_trie_node_with_proof.yaml")?;
        let value = StateContentValue::deserialize(&value_yaml["content_value"])?;

        let expected_stored_value =
            "0x04000000e09e20fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace12";

        storage.put(key.clone(), value.encode()).await?;

        assert_eq!(
            storage.get(&key).await.unwrap(),
            Some(hex_decode(expected_stored_value)?)
        );

        drop(temp_dir);
        Ok(())
    }

    #[tokio::test]
    async fn contract_bytecode() -> Result<()> {
        let (temp_dir, config) =
            create_test_portal_storage_config_with_capacity(STORAGE_CAPACITY_MB).await?;
        let mut storage = StateStorage::new(config).await?;

        let key_yaml = read_yaml_file("contract_bytecode_key.yaml")?;
        let key = StateContentKey::deserialize(&key_yaml["content_key"])?;

        let value_yaml = read_yaml_file("contract_bytecode_with_proof.yaml")?;
        let value = StateContentValue::deserialize(&value_yaml["content_value"])?;

        let expected_stored_value = "0x040000006060604052600436106100af576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806306fdde03146100b9578063095ea7b31461014757806318160ddd146101a157806323b872dd146101ca5780632e1a7d4d14610243578063313ce5671461026657806370a082311461029557806395d89b41146102e2578063a9059cbb14610370578063d0e30db0146103ca578063dd62ed3e146103d4575b6100b7610440565b005b34156100c457600080fd5b6100cc6104dd565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561010c5780820151818401526020810190506100f1565b50505050905090810190601f1680156101395780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b341561015257600080fd5b610187600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803590602001909190505061057b565b604051808215151515815260200191505060405180910390f35b34156101ac57600080fd5b6101b461066d565b6040518082815260200191505060405180910390f35b34156101d557600080fd5b610229600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803590602001909190505061068c565b604051808215151515815260200191505060405180910390f35b341561024e57600080fd5b61026460048080359060200190919050506109d9565b005b341561027157600080fd5b610279610b05565b604051808260ff1660ff16815260200191505060405180910390f35b34156102a057600080fd5b6102cc600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610b18565b6040518082815260200191505060405180910390f35b34156102ed57600080fd5b6102f5610b30565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561033557808201518184015260208101905061031a565b50505050905090810190601f1680156103625780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b341561037b57600080fd5b6103b0600480803573ffffffffffffffffffffffffffffffffffffffff16906020019091908035906020019091905050610bce565b604051808215151515815260200191505060405180910390f35b6103d2610440565b005b34156103df57600080fd5b61042a600480803573ffffffffffffffffffffffffffffffffffffffff1690602001909190803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610be3565b6040518082815260200191505060405180910390f35b34600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825401925050819055503373ffffffffffffffffffffffffffffffffffffffff167fe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c346040518082815260200191505060405180910390a2565b60008054600181600116156101000203166002900480601f0160208091040260200160405190810160405280929190818152602001828054600181600116156101000203166002900480156105735780601f1061054857610100808354040283529160200191610573565b820191906000526020600020905b81548152906001019060200180831161055657829003601f168201915b505050505081565b600081600460003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925846040518082815260200191505060405180910390a36001905092915050565b60003073ffffffffffffffffffffffffffffffffffffffff1631905090565b600081600360008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054101515156106dc57600080fd5b3373ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff16141580156107b457507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff600460008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205414155b156108cf5781600460008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020541015151561084457600080fd5b81600460008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825403925050819055505b81600360008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000828254039250508190555081600360008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825401925050819055508273ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040518082815260200191505060405180910390a3600190509392505050565b80600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205410151515610a2757600080fd5b80600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825403925050819055503373ffffffffffffffffffffffffffffffffffffffff166108fc829081150290604051600060405180830381858888f193505050501515610ab457600080fd5b3373ffffffffffffffffffffffffffffffffffffffff167f7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65826040518082815260200191505060405180910390a250565b600260009054906101000a900460ff1681565b60036020528060005260406000206000915090505481565b60018054600181600116156101000203166002900480601f016020809104026020016040519081016040528092919081815260200182805460018160011615610100020316600290048015610bc65780601f10610b9b57610100808354040283529160200191610bc6565b820191906000526020600020905b815481529060010190602001808311610ba957829003601f168201915b505050505081565b6000610bdb33848461068c565b905092915050565b60046020528160005260406000206020528060005260406000206000915091505054815600a165627a7a72305820deb4c2ccab3c2fdca32ab3f46728389c2fe2c165d5fafa07661e4e004f6c344a0029";

        storage.put(key.clone(), value.encode()).await?;

        assert_eq!(
            storage.get(&key).await.unwrap(),
            Some(hex_decode(expected_stored_value)?)
        );

        drop(temp_dir);
        Ok(())
    }

    fn read_yaml_file(filename: &str) -> Result<serde_yaml::Mapping> {
        let file = read_portal_spec_tests_file(
            PathBuf::from("tests/mainnet/state/serialization").join(filename),
        )?;
        let value: serde_yaml::Value = serde_yaml::from_str(&file)?;
        value
            .as_mapping()
            .map(Clone::clone)
            .ok_or(anyhow!("Expected mapping at the root of a file"))
    }
}
