use alloy_primitives::{Address, Bytes, B256, U256};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_rpc_types::{Block, BlockId};

/// Web3 JSON-RPC endpoints
#[rpc(client, server, namespace = "eth")]
pub trait EthApi {
    #[method(name = "chainId")]
    async fn chain_id(&self) -> RpcResult<U256>;

    #[method(name = "getBlockByHash")]
    async fn get_block_by_hash(
        &self,
        block_hash: B256,
        hydrated_transactions: bool,
    ) -> RpcResult<Block>;

    #[method(name = "getBalance")]
    async fn get_balance(&self, address: Address, block: BlockId) -> RpcResult<U256>;

    #[method(name = "getCode")]
    async fn get_code(&self, address: Address, block: BlockId) -> RpcResult<Bytes>;

    #[method(name = "getStorageAt")]
    async fn get_storage_at(&self, address: Address, slot: U256, block: BlockId)
        -> RpcResult<B256>;
}
