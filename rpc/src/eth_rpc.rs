use alloy::{
    primitives::{Address, Bytes, B256, U256},
    rpc::types::{
        Block, BlockId, BlockNumberOrTag, BlockTransactions, TransactionRequest, Withdrawal,
    },
};
use ethportal_api::{
    jsonrpsee::types::{error::CALL_EXECUTION_FAILED_CODE, ErrorObjectOwned},
    types::{
        execution::{block_body::BlockBody, transaction::Transaction},
        jsonrpc::{
            endpoints::HistoryEndpoint,
            request::{HistoryJsonRpcRequest, StateJsonRpcRequest},
        },
        portal::GetContentInfo,
    },
    ContentValue, EthApiServer, Header, HistoryContentKey, HistoryContentValue,
};
use revm::primitives::ExecutionResult;
use tokio::sync::mpsc;
use trin_evm::{
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

    async fn get_block_by_number(
        &self,
        block_number_or_tag: BlockNumberOrTag,
        hydrated_transactions: bool,
    ) -> RpcResult<Block> {
        let header = self.fetch_header_by_number(block_number_or_tag).await?;
        Ok(self.fetch_block(header, hydrated_transactions).await?)
    }

    async fn get_block_by_hash(
        &self,
        block_hash: B256,
        hydrated_transactions: bool,
    ) -> RpcResult<Block> {
        let header = self.fetch_header_by_hash(block_hash).await?;
        Ok(self.fetch_block(header, hydrated_transactions).await?)
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

        match result_and_state.result {
            ExecutionResult::Success { output, .. } => Ok(output.into_data()),
            ExecutionResult::Revert { .. } => Err(ErrorObjectOwned::borrowed(
                CALL_EXECUTION_FAILED_CODE,
                "Reverted",
                None,
            )),
            ExecutionResult::Halt { reason, .. } => Err(ErrorObjectOwned::owned(
                CALL_EXECUTION_FAILED_CODE,
                format!("{reason:?}"),
                None::<()>,
            )),
        }
    }
}

impl EthApi {
    // History network related functions

    async fn fetch_history_content(
        &self,
        content_key: HistoryContentKey,
    ) -> Result<HistoryContentValue, RpcServeError> {
        let endpoint = HistoryEndpoint::GetContent(content_key.clone());
        let GetContentInfo { content, .. } =
            proxy_to_subnet(&self.history_network, endpoint).await?;
        let content_value = HistoryContentValue::decode(&content_key, &content)?;
        Ok(content_value)
    }

    async fn fetch_header_by_number(
        &self,
        block_number_or_tag: BlockNumberOrTag,
    ) -> Result<Header, RpcServeError> {
        let block_number = block_number_or_tag
            .as_number()
            .ok_or_else(|| RpcServeError::Message("Block tag is not supported yet.".to_string()))?;
        let content_value = self
            .fetch_history_content(HistoryContentKey::new_block_header_by_number(block_number))
            .await?;
        let HistoryContentValue::BlockHeaderWithProof(header_with_proof) = content_value else {
            return Err(RpcServeError::Message(format!(
                "Invalid response: expected block header; got {content_value:?}"
            )));
        };
        Ok(header_with_proof.header)
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

    async fn fetch_block(
        &self,
        header: Header,
        hydrated_transactions: bool,
    ) -> Result<Block, RpcServeError> {
        if hydrated_transactions {
            return Err(RpcServeError::Message(
                "replying with all transaction bodies is not supported yet".to_string(),
            ));
        }

        let body = self.fetch_block_body(header.hash()).await?;
        let transactions =
            BlockTransactions::Hashes(body.transactions().iter().map(Transaction::hash).collect());
        let uncles = body.uncles().iter().map(|uncle| uncle.hash()).collect();
        let withdrawals = body
            .withdrawals()
            .map(|withdrawals| withdrawals.iter().map(Withdrawal::from).collect());

        // TODO: Add calculation for the block's size:
        //   len(rlp(header, transactions, uncles, withdrawals))
        // NOTE: Transactions should be encoded with envelope
        let size = None;

        // Combine header and block body into the single json representation of the block.
        let block = Block {
            header: header.into(),
            transactions,
            uncles,
            size,
            withdrawals,
        };
        Ok(block)
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
        let header = match block {
            BlockId::Hash(block_hash) => self.fetch_header_by_hash(block_hash.block_hash).await?,
            BlockId::Number(block_number_or_tag) => {
                self.fetch_header_by_number(block_number_or_tag).await?
            }
        };
        Ok(EvmBlockState::new(header, state_network.clone()))
    }
}

impl std::fmt::Debug for EthApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EthApi").finish_non_exhaustive()
    }
}
