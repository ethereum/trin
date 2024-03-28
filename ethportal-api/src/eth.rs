use alloy_primitives::{B256, U256};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_rpc_types::Block;

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
}
