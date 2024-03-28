use alloy_primitives::{B256, U256};
use reth_rpc_types::{other::OtherFields, Block, BlockTransactions};
use tokio::sync::mpsc;

use ethportal_api::{
    types::{execution::block_body::BlockBody, jsonrpc::request::HistoryJsonRpcRequest},
    EthApiServer,
};
use trin_validation::constants::CHAIN_ID;

use crate::{
    errors::RpcServeError,
    fetch::{find_block_body_by_hash, find_header_by_hash},
    jsonrpsee::core::{async_trait, RpcResult},
};

pub struct EthApi {
    network: mpsc::UnboundedSender<HistoryJsonRpcRequest>,
}

impl EthApi {
    pub fn new(network: mpsc::UnboundedSender<HistoryJsonRpcRequest>) -> Self {
        Self { network }
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

        let header = find_header_by_hash(&self.network, block_hash).await?;
        let body = find_block_body_by_hash(&self.network, block_hash).await?;
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
}

impl std::fmt::Debug for EthApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EthApi").finish_non_exhaustive()
    }
}
