use ethereum_types::U256;
use tokio::sync::mpsc;

use ethportal_api::types::jsonrpc::request::HistoryJsonRpcRequest;
use ethportal_api::EthApiServer;
use trin_validation::constants::CHAIN_ID;

use crate::jsonrpsee::core::{async_trait, RpcResult};

pub struct EthApi {
    _network: mpsc::UnboundedSender<HistoryJsonRpcRequest>,
}

impl EthApi {
    pub fn new(network: mpsc::UnboundedSender<HistoryJsonRpcRequest>) -> Self {
        Self { _network: network }
    }
}

#[async_trait]
impl EthApiServer for EthApi {
    async fn chain_id(&self) -> RpcResult<U256> {
        Ok(U256::from(CHAIN_ID))
    }
}

impl std::fmt::Debug for EthApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EthApi").finish_non_exhaustive()
    }
}
