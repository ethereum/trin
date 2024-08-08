use alloy_primitives::{Address, Bytes, B256, U256};
use reth_rpc_types::{other::OtherFields, Block, BlockId, BlockTransactions};
use tokio::sync::mpsc;

use ethportal_api::{
    types::{
        execution::block_body::BlockBody,
        jsonrpc::request::{HistoryJsonRpcRequest, StateJsonRpcRequest},
    },
    EthApiServer,
};
use trin_validation::constants::CHAIN_ID;

use crate::{
    errors::RpcServeError,
    fetch::{find_block_body_by_hash, find_header_by_hash},
    jsonrpsee::core::{async_trait, RpcResult},
};

pub struct EthApi {
    history_network: mpsc::UnboundedSender<HistoryJsonRpcRequest>,
    _state_network: Option<mpsc::UnboundedSender<StateJsonRpcRequest>>,
}

impl EthApi {
    pub fn new(
        history_network: mpsc::UnboundedSender<HistoryJsonRpcRequest>,
        state_network: Option<mpsc::UnboundedSender<StateJsonRpcRequest>>,
    ) -> Self {
        Self {
            history_network,
            _state_network: state_network,
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

        let header = find_header_by_hash(&self.history_network, block_hash).await?;
        let body = find_block_body_by_hash(&self.history_network, block_hash).await?;
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

    async fn get_balance(&self, _address: Address, _block: BlockId) -> RpcResult<U256> {
        todo!()
    }

    async fn get_code(&self, _address: Address, _block: BlockId) -> RpcResult<Bytes> {
        todo!()
    }

    async fn get_storage_at(
        &self,
        _address: Address,
        _slot: U256,
        _block: BlockId,
    ) -> RpcResult<Bytes> {
        todo!()
    }
}

impl std::fmt::Debug for EthApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EthApi").finish_non_exhaustive()
    }
}
