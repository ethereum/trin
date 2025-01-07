use jsonrpsee::{core::RpcResult, proc_macros::rpc};

/// Web3 JSON-RPC endpoints
#[rpc(client, server, namespace = "web3")]
pub trait Web3Api {
    #[method(name = "clientVersion")]
    async fn client_version(&self) -> RpcResult<String>;
}
