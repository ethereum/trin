use ethereum_types::U256;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

/// Web3 JSON-RPC endpoints
#[rpc(client, server, namespace = "eth")]
pub trait EthApi {
    #[method(name = "chainId")]
    async fn chain_id(&self) -> RpcResult<U256>;
}
