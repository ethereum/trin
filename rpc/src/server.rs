use crate::jsonrpsee::server::{ServerBuilder as HttpServerBuilder, ServerHandle};
use crate::{Discv5Api, HistoryNetworkApi, Web3Api};
use ethportal_api::{Discv5ApiServer, HistoryNetworkApiServer, Web3ApiServer};
use reth_ipc::server::Builder as IpcServerBuilder;
use std::sync::Arc;
use tokio::sync::mpsc;
use trin_core::jsonrpc::types::HistoryJsonRpcRequest;
use trin_core::portalnet::discovery::Discovery;

pub struct JsonRpcServer;

impl JsonRpcServer {
    pub async fn run_http(
        web3_http_address: String,
        discv5: Arc<Discovery>,
        history_handler: mpsc::UnboundedSender<HistoryJsonRpcRequest>,
    ) -> anyhow::Result<ServerHandle> {
        let server = HttpServerBuilder::default()
            .build(web3_http_address)
            .await?;
        let discv5_api = Discv5Api::new(discv5);
        let history_network_api = HistoryNetworkApi::new(history_handler);
        let mut api = discv5_api.into_rpc();
        api.merge(history_network_api.into_rpc())?;
        api.merge(Web3Api.into_rpc())?;
        let handle = server.start(api)?;
        Ok(handle)
    }

    pub async fn run_ipc(
        ipc_path: String,
        discv5: Arc<Discovery>,
        history_handler: mpsc::UnboundedSender<HistoryJsonRpcRequest>,
    ) -> anyhow::Result<ServerHandle> {
        let server = IpcServerBuilder::default().build(ipc_path)?;
        let discv5_api = Discv5Api::new(discv5);
        let history_network_api = HistoryNetworkApi::new(history_handler);
        let mut api = discv5_api.into_rpc();
        api.merge(history_network_api.into_rpc())?;
        api.merge(Web3Api.into_rpc())?;
        let handle = server.start(api).await?;
        Ok(handle)
    }
}
