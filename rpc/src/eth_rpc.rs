use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_rlp::Decodable;
use eth_trie::node::Node;
use reth_rpc_types::{other::OtherFields, Block, BlockId, BlockTransactions};
use tokio::sync::mpsc;

use ethportal_api::{
    types::{
        content_key::state::{AccountTrieNodeKey, ContractBytecodeKey, ContractStorageTrieNodeKey},
        execution::block_body::BlockBody,
        jsonrpc::{
            endpoints::{HistoryEndpoint, StateEndpoint},
            request::{HistoryJsonRpcRequest, StateJsonRpcRequest},
        },
        portal::ContentInfo,
        state_trie::{
            account_state::AccountState,
            nibbles::Nibbles,
            trie_traversal::{NodeTraversal, TraversalResult},
        },
    },
    ContentValue, EthApiServer, Header, HistoryContentKey, HistoryContentValue, StateContentKey,
    StateContentValue,
};
use trin_validation::constants::CHAIN_ID;

use crate::{
    errors::RpcServeError,
    fetch::proxy_to_subnet,
    jsonrpsee::core::{async_trait, RpcResult},
};

pub struct EthApi {
    history_network: mpsc::UnboundedSender<HistoryJsonRpcRequest>,
    state_network: Option<mpsc::UnboundedSender<StateJsonRpcRequest>>,
}

impl EthApi {
    pub fn new(
        history_network: mpsc::UnboundedSender<HistoryJsonRpcRequest>,
        state_network: Option<mpsc::UnboundedSender<StateJsonRpcRequest>>,
    ) -> Self {
        Self {
            history_network,
            state_network,
        }
    }
}

#[async_trait]
impl EthApiServer for EthApi {
    async fn chain_id(&self) -> RpcResult<U256> {
        Ok(U256::from(CHAIN_ID))
    }

    async fn get_block_by_hash(
        &self,
        block_hash: B256,
        hydrated_transactions: bool,
    ) -> RpcResult<Block> {
        if hydrated_transactions {
            return Err(RpcServeError::Message(
                "replying with all transaction bodies is not supported yet".into(),
            )
            .into());
        }

        let header = self.fetch_header_by_hash(block_hash).await?;
        let body = self.fetch_block_body(block_hash).await?;
        let transactions = match body {
            BlockBody::Legacy(body) => body.txs,
            BlockBody::Merge(body) => body.txs,
            BlockBody::Shanghai(body) => body.txs,
        };
        let transactions = BlockTransactions::Hashes(
            transactions
                .into_iter()
                .map(|tx| tx.hash().0.into())
                .collect(),
        );

        // Combine header and block body into the single json representation of the block.
        let block = Block {
            header: header.into(),
            transactions,
            uncles: vec![],
            size: None,
            other: OtherFields::default(),
            withdrawals: None,
        };
        Ok(block)
    }

    async fn get_balance(&self, address: Address, block: BlockId) -> RpcResult<U256> {
        let address_hash = keccak256(address);
        let block_hash = as_block_hash(block)?;
        let header = self.fetch_header_by_hash(block_hash).await?;

        let account_state = self
            .fetch_account_state(header.state_root, address_hash)
            .await?;

        match account_state {
            Some(account_state) => Ok(account_state.balance),
            None => Ok(U256::ZERO),
        }
    }

    async fn get_code(&self, address: Address, block: BlockId) -> RpcResult<Bytes> {
        let address_hash = keccak256(address);
        let block_hash = as_block_hash(block)?;
        let header = self.fetch_header_by_hash(block_hash).await?;

        let account_state = self
            .fetch_account_state(header.state_root, address_hash)
            .await?;

        match account_state {
            Some(account_state) => Ok(self
                .fetch_contract_bytecode(address_hash, account_state.code_hash)
                .await?),
            None => Ok(Bytes::new()),
        }
    }

    async fn get_storage_at(
        &self,
        address: Address,
        slot: U256,
        block: BlockId,
    ) -> RpcResult<B256> {
        let address_hash = keccak256(address);
        let block_hash = as_block_hash(block)?;
        let header = self.fetch_header_by_hash(block_hash).await?;

        let account_state = self
            .fetch_account_state(header.state_root, address_hash)
            .await?;

        match account_state {
            Some(account_state) => Ok(self
                .fetch_contract_storage_at_slot(account_state.storage_root, address_hash, slot)
                .await?),
            None => Ok(B256::ZERO),
        }
    }
}

impl EthApi {
    // History network related functions

    async fn fetch_history_content(
        &self,
        content_key: HistoryContentKey,
    ) -> Result<HistoryContentValue, RpcServeError> {
        let endpoint = HistoryEndpoint::RecursiveFindContent(content_key.clone());
        let response: ContentInfo = proxy_to_subnet(&self.history_network, endpoint).await?;
        let ContentInfo::Content { content, .. } = response else {
            return Err(RpcServeError::Message(format!(
                "Invalid response variant: History RecursiveFindContent should contain content value; got {response:?}"
            )));
        };

        let content_value = HistoryContentValue::decode(&content_key, &content)?;
        Ok(content_value)
    }

    async fn fetch_header_by_hash(&self, block_hash: B256) -> Result<Header, RpcServeError> {
        let content_value = self
            .fetch_history_content(HistoryContentKey::BlockHeaderWithProof(block_hash.into()))
            .await?;
        let HistoryContentValue::BlockHeaderWithProof(header_with_proof) = content_value else {
            return Err(RpcServeError::Message(format!(
                "Invalid response: expected block header; got {content_value:?}"
            )));
        };
        Ok(header_with_proof.header)
    }

    async fn fetch_block_body(&self, block_hash: B256) -> Result<BlockBody, RpcServeError> {
        let content_value = self
            .fetch_history_content(HistoryContentKey::BlockBody(block_hash.into()))
            .await?;
        let HistoryContentValue::BlockBody(block_body) = content_value else {
            return Err(RpcServeError::Message(format!(
                "Invalid response: expected block body; got {content_value:?}"
            )));
        };
        Ok(block_body)
    }

    // State network related functions

    async fn fetch_state_content(
        &self,
        content_key: StateContentKey,
    ) -> Result<StateContentValue, RpcServeError> {
        let Some(state_network) = &self.state_network else {
            return Err(RpcServeError::Message(format!(
                "State network not enabled. Can't find: {content_key}"
            )));
        };

        let endpoint = StateEndpoint::RecursiveFindContent(content_key.clone());
        let response: ContentInfo = proxy_to_subnet(state_network, endpoint).await?;
        let ContentInfo::Content { content, .. } = response else {
            return Err(RpcServeError::Message(format!(
                "Invalid response variant: State RecursiveFindContent should contain content value; got {response:?}"
            )));
        };

        let content_value = StateContentValue::decode(&content_key, &content)?;
        Ok(content_value)
    }

    async fn fetch_trie_node(&self, content_key: StateContentKey) -> Result<Node, RpcServeError> {
        let content_value = self.fetch_state_content(content_key).await?;
        let StateContentValue::TrieNode(trie_node) = content_value else {
            return Err(RpcServeError::Message(format!(
                "Invalid response: expected trie node; got {content_value:?}",
            )));
        };
        trie_node
            .node
            .as_trie_node()
            .map_err(|err| RpcServeError::Message(format!("Can't decode trie_node: {err}")))
    }

    async fn fetch_contract_bytecode(
        &self,
        address_hash: B256,
        code_hash: B256,
    ) -> Result<Bytes, RpcServeError> {
        let content_key = StateContentKey::ContractBytecode(ContractBytecodeKey {
            address_hash,
            code_hash,
        });
        let content_value = self.fetch_state_content(content_key).await?;
        let StateContentValue::ContractBytecode(contract_bytecode) = content_value else {
            return Err(RpcServeError::Message(format!(
                "Invalid response: expected contract bytecode; got {content_value:?}",
            )));
        };
        let bytes = Vec::from(contract_bytecode.code);
        Ok(Bytes::from(bytes))
    }

    async fn fetch_account_state(
        &self,
        state_root: B256,
        address_hash: B256,
    ) -> Result<Option<AccountState>, RpcServeError> {
        self.traverse_trie(state_root, address_hash, |path, node_hash| {
            StateContentKey::AccountTrieNode(AccountTrieNodeKey { path, node_hash })
        })
        .await
    }

    async fn fetch_contract_storage_at_slot(
        &self,
        storage_root: B256,
        address_hash: B256,
        storage_slot: U256,
    ) -> Result<B256, RpcServeError> {
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
            return Err(RpcServeError::Message(format!(
                "Storage value is too long. value: {value}"
            )));
        }

        Ok(B256::left_padding_from(&value))
    }

    /// Utility function for fetching trie nodes and traversing the trie.
    ///
    /// This function works both with the account trie and the contract state trie.
    async fn traverse_trie<T: Decodable>(
        &self,
        root: B256,
        path: B256,
        content_key_fn: impl Fn(Nibbles, B256) -> StateContentKey,
    ) -> Result<Option<T>, RpcServeError> {
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
                TraversalResult::Error(err) => {
                    return Err(RpcServeError::Message(format!(
                        "Error traversing trie node: {err}"
                    )))
                }
            }
        };

        value
            .map(|value| T::decode(&mut value.as_ref()))
            .transpose()
            .map_err(|err| {
                RpcServeError::Message(format!("Error decoding value from the leaf node: {err}"))
            })
    }
}

impl std::fmt::Debug for EthApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EthApi").finish_non_exhaustive()
    }
}

fn as_block_hash(block: BlockId) -> Result<B256, RpcServeError> {
    block.as_block_hash().ok_or_else(|| {
        RpcServeError::Message("Only block hash is accepted as block id".to_string())
    })
}
