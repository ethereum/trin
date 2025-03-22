use std::collections::HashMap;

use alloy::{
    consensus::Header,
    primitives::{keccak256, Address, Bytes, B256, U256},
    rlp::Decodable,
};
use eth_trie::{node::Node, TrieError};
use ethportal_api::{
    jsonrpsee::types::ErrorObjectOwned,
    types::{
        content_key::state::{AccountTrieNodeKey, ContractBytecodeKey, ContractStorageTrieNodeKey},
        jsonrpc::{endpoints::StateEndpoint, request::StateJsonRpcRequest},
        portal::GetContentInfo,
        state_trie::{
            account_state::AccountState,
            nibbles::Nibbles,
            trie_traversal::{NodeTraversal, TraversalError, TraversalResult},
        },
    },
    ContentValue, ContentValueError, OverlayContentKey, StateContentKey, StateContentValue,
};
use revm::primitives::{AccountInfo, Bytecode, KECCAK_EMPTY};
use tokio::sync::mpsc;
use tracing::debug;
use trin_evm::async_db::AsyncDatabase;

use crate::{errors::RpcServeError, fetch::proxy_to_subnet};

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum EvmStateError {
    #[error("Received content value has unexpected type. key: {0} value: {0}")]
    InvalidContentValueType(StateContentKey, StateContentValue),
    #[error("Error decoding content value: {0}")]
    DecodingContentValue(#[from] ContentValueError),
    #[error("Error decoding trie node: {0}")]
    DecodingTrieNode(#[from] TrieError),
    #[error("Error RLP decoding trie value: {0}")]
    DecodingTrieValue(#[from] alloy::rlp::Error),
    #[error("Error traversing trie: {0}")]
    TrieTraversal(#[from] TraversalError),
    #[error("Storage value is invalid: {0}")]
    InvalidStorageValue(Bytes),
    #[error("Internal Error: {0}")]
    InternalError(String),
}

impl From<EvmStateError> for RpcServeError {
    fn from(value: EvmStateError) -> Self {
        Self::Message(value.to_string())
    }
}

impl From<EvmStateError> for ErrorObjectOwned {
    fn from(value: EvmStateError) -> Self {
        RpcServeError::from(value).into()
    }
}

/// Provides access to the EVM state at the specific block
pub struct EvmBlockState {
    block_header: Header,
    state_network: mpsc::UnboundedSender<StateJsonRpcRequest>,
    cache: HashMap<StateContentKey, StateContentValue>,
    code_hash_to_address_hash: HashMap<B256, B256>,
}

impl EvmBlockState {
    pub fn new(
        block_header: Header,
        state_network: mpsc::UnboundedSender<StateJsonRpcRequest>,
    ) -> Self {
        Self {
            block_header,
            state_network,
            cache: HashMap::new(),
            code_hash_to_address_hash: HashMap::new(),
        }
    }

    // Public functions

    pub fn block_header(&self) -> &Header {
        &self.block_header
    }

    pub async fn account_state(
        &mut self,
        address_hash: B256,
    ) -> Result<Option<AccountState>, EvmStateError> {
        let account_state = self
            .traverse_trie::<AccountState>(
                self.block_header.state_root,
                address_hash,
                |path, node_hash| {
                    StateContentKey::AccountTrieNode(AccountTrieNodeKey { path, node_hash })
                },
            )
            .await?;

        if let Some(account_state) = &account_state {
            if account_state.code_hash != KECCAK_EMPTY {
                self.code_hash_to_address_hash
                    .entry(account_state.code_hash)
                    .or_insert(address_hash);
            }
        }

        Ok(account_state)
    }

    pub async fn contract_storage_at_slot(
        &mut self,
        storage_root: B256,
        address_hash: B256,
        storage_slot: U256,
    ) -> Result<B256, EvmStateError> {
        let path = keccak256(storage_slot.to_be_bytes::<32>());
        let value = self
            .traverse_trie::<Bytes>(storage_root, path, |path, node_hash| {
                StateContentKey::ContractStorageTrieNode(ContractStorageTrieNodeKey {
                    address_hash,
                    path,
                    node_hash,
                })
            })
            .await?
            .unwrap_or_default();
        if value.len() > B256::len_bytes() {
            return Err(EvmStateError::InvalidStorageValue(value));
        }

        Ok(B256::left_padding_from(&value))
    }

    pub async fn contract_bytecode(
        &mut self,
        address_hash: B256,
        code_hash: B256,
    ) -> Result<Bytes, EvmStateError> {
        let content_key = StateContentKey::ContractBytecode(ContractBytecodeKey {
            address_hash,
            code_hash,
        });
        let content_value = self.fetch_content(content_key.clone()).await?;
        let StateContentValue::ContractBytecode(contract_bytecode) = content_value else {
            return Err(EvmStateError::InvalidContentValueType(
                content_key,
                content_value,
            ));
        };
        let bytes = Vec::from(contract_bytecode.code);
        Ok(Bytes::from(bytes))
    }

    // Utility functions

    async fn fetch_content(
        &mut self,
        content_key: StateContentKey,
    ) -> Result<StateContentValue, EvmStateError> {
        if let Some(value) = self.cache.get(&content_key) {
            return Ok(value.clone());
        }

        debug!(
            content_id = ?Bytes::from(content_key.content_id()),
            content_key = ?content_key.to_bytes(),
            "Fetching state content");
        let endpoint = StateEndpoint::GetContent(content_key.clone());
        let GetContentInfo { content, .. } =
            proxy_to_subnet(&self.state_network, endpoint)
                .await
                .map_err(|err| EvmStateError::InternalError(err.to_string()))?;
        let content_value = StateContentValue::decode(&content_key, &content)?;
        self.cache.insert(content_key, content_value.clone());
        Ok(content_value)
    }

    async fn fetch_trie_node(
        &mut self,
        content_key: StateContentKey,
    ) -> Result<Node, EvmStateError> {
        let content_value = self.fetch_content(content_key.clone()).await?;
        let StateContentValue::TrieNode(trie_node) = content_value else {
            return Err(EvmStateError::InvalidContentValueType(
                content_key,
                content_value,
            ));
        };
        Ok(trie_node.node.as_trie_node()?)
    }

    /// Utility function for fetching trie nodes and traversing the trie.
    ///
    /// This function works both with the account trie and the contract state trie.
    async fn traverse_trie<T: Decodable>(
        &mut self,
        root: B256,
        path: B256,
        content_key_fn: impl Fn(Nibbles, B256) -> StateContentKey,
    ) -> Result<Option<T>, EvmStateError> {
        let path = Nibbles::unpack_nibbles(path.as_slice());

        let mut node_hash = root;
        let mut remaining_path = path.as_slice();

        let value = loop {
            let path_from_root = path
                .strip_suffix(remaining_path)
                .expect("Remaining path should be suffix of the path");

            let content_key = content_key_fn(
                Nibbles::try_from_unpacked_nibbles(path_from_root)
                    .expect("we should be able to create Nibbles from path"),
                node_hash,
            );
            let node = self.fetch_trie_node(content_key).await?;

            match node.traverse(remaining_path) {
                TraversalResult::Empty(_) => break None,
                TraversalResult::Value(value) => break Some(value),
                TraversalResult::Node(next_node) => {
                    node_hash = next_node.hash;
                    remaining_path = next_node.remaining_path;
                }
                TraversalResult::Error(err) => return Err(err.into()),
            }
        };

        Ok(value
            .map(|value| T::decode(&mut value.as_ref()))
            .transpose()?)
    }
}

impl AsyncDatabase for EvmBlockState {
    type Error = EvmStateError;

    async fn basic_async(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let address_hash = keccak256(address);
        let account_state = self.account_state(address_hash).await?;

        Ok(account_state.map(|account_state| AccountInfo {
            balance: account_state.balance,
            nonce: account_state.nonce,
            code_hash: account_state.code_hash,
            code: None,
        }))
    }

    async fn code_by_hash_async(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        if code_hash == KECCAK_EMPTY {
            return Ok(Bytecode::new());
        }

        let Some(address_hash) = self.code_hash_to_address_hash.get(&code_hash) else {
            return Err(EvmStateError::InternalError(format!(
                "Unknown code_hash: {code_hash}"
            )));
        };

        let bytecode_raw = self.contract_bytecode(*address_hash, code_hash).await?;
        Ok(Bytecode::new_raw(bytecode_raw))
    }

    async fn storage_async(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let address_hash = keccak256(address);
        let account_state = self.account_state(address_hash).await?;
        let Some(account_state) = account_state else {
            return Ok(U256::ZERO);
        };
        self.contract_storage_at_slot(account_state.storage_root, address_hash, index)
            .await
            .map(|value| U256::from_be_bytes(value.0))
    }

    async fn block_hash_async(&mut self, _number: u64) -> Result<B256, Self::Error> {
        Err(EvmStateError::InternalError(
            "The block_hash_async is not supported".to_string(),
        ))
    }
}
