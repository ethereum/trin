use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_rpc_types::{Block, BlockId, BlockTransactions, TransactionRequest};
use tokio::sync::mpsc;

use ethportal_api::{
    types::{
        execution::block_body::BlockBody,
        jsonrpc::{
            endpoints::HistoryEndpoint,
            request::{HistoryJsonRpcRequest, StateJsonRpcRequest},
        },
        portal::ContentInfo,
    },
    ContentValue, EthApiServer, Header, HistoryContentKey, HistoryContentValue,
};
use trin_execution::evm::{
    async_db::{execute_transaction, AsyncDatabase},
    create_block_env,
};
use trin_validation::constants::CHAIN_ID;

use crate::{
    errors::RpcServeError,
    evm_state::EvmBlockState,
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
            withdrawals: None,
        };
        Ok(block)
    }

    async fn get_balance(&self, address: Address, block: BlockId) -> RpcResult<U256> {
        let mut evm_block_state = self.evm_block_state(block).await?;

        let Some(account_info) = evm_block_state.basic_async(address).await? else {
            return Ok(U256::ZERO);
        };
        Ok(account_info.balance)
    }

    async fn get_storage_at(
        &self,
        address: Address,
        slot: U256,
        block: BlockId,
    ) -> RpcResult<B256> {
        let mut evm_block_state = self.evm_block_state(block).await?;

        let value = evm_block_state.storage_async(address, slot).await?;
        Ok(B256::from(value))
    }

    async fn get_code(&self, address: Address, block: BlockId) -> RpcResult<Bytes> {
        let mut evm_block_state = self.evm_block_state(block).await?;

        let Some(account_info) = evm_block_state.basic_async(address).await? else {
            return Ok(Bytes::new());
        };

        if account_info.is_empty_code_hash() {
            return Ok(Bytes::new());
        }

        let bytecode = match account_info.code {
            Some(code) => code,
            None => {
                evm_block_state
                    .code_by_hash_async(account_info.code_hash())
                    .await?
            }
        };
        Ok(bytecode.original_bytes())
    }

    async fn call(&self, mut transaction: TransactionRequest, block: BlockId) -> RpcResult<Bytes> {
        let evm_block_state = self.evm_block_state(block).await?;

        // If gas limit is not set, set it to block's limit
        if transaction.gas.is_none() {
            transaction.gas = Some(evm_block_state.block_header().gas_limit.to());
        }

        let result_and_state = execute_transaction(
            create_block_env(evm_block_state.block_header()),
            transaction,
            evm_block_state,
        )
        .await
        .map_err(|err| RpcServeError::Message(err.to_string()))?;
        let output = result_and_state.result.into_output().unwrap_or_default();
        Ok(output)
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
            .fetch_history_content(HistoryContentKey::new_block_header_by_hash(block_hash))
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
            .fetch_history_content(HistoryContentKey::new_block_body(block_hash))
            .await?;
        let HistoryContentValue::BlockBody(block_body) = content_value else {
            return Err(RpcServeError::Message(format!(
                "Invalid response: expected block body; got {content_value:?}"
            )));
        };
        Ok(block_body)
    }

    // State network related functions

    async fn evm_block_state(&self, block: BlockId) -> Result<EvmBlockState, RpcServeError> {
        let Some(state_network) = &self.state_network else {
            return Err(RpcServeError::Message(
                "State network not enabled. Can't process request!".to_string(),
            ));
        };
        let block_hash = as_block_hash(block)?;
        let header = self.fetch_header_by_hash(block_hash).await?;
        Ok(EvmBlockState::new(header, state_network.clone()))
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
