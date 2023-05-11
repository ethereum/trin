use crate::jsonrpsee::server::{ServerBuilder as HttpServerBuilder, ServerHandle};
use crate::{Discv5Api, HistoryNetworkApi, Web3Api};
use ethportal_api::types::jsonrpc::request::HistoryJsonRpcRequest;
use ethportal_api::{Discv5ApiServer, HistoryNetworkApiServer, Web3ApiServer};
use portalnet::discovery::Discovery;
#[cfg(unix)]
use reth_ipc::server::Builder as IpcServerBuilder;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;

use url::Url;

pub struct JsonRpcServer;

impl JsonRpcServer {
    pub async fn run_http(
        web3_http_address: Url,
        discv5: Arc<Discovery>,
        history_handler: mpsc::UnboundedSender<HistoryJsonRpcRequest>,
    ) -> anyhow::Result<ServerHandle> {
        let socket_addr: SocketAddr = web3_http_address.socket_addrs(|| None)?[0];

        let server = HttpServerBuilder::default().build(socket_addr).await?;
        let discv5_api = Discv5Api::new(discv5);
        let history_network_api = HistoryNetworkApi::new(history_handler);
        let mut api = discv5_api.into_rpc();
        api.merge(history_network_api.into_rpc())?;
        api.merge(Web3Api.into_rpc())?;
        let handle = server.start(api)?;
        Ok(handle)
    }

    #[cfg(unix)]
    pub async fn run_ipc(
        ipc_path: Box<dyn AsRef<Path>>,
        discv5: Arc<Discovery>,
        history_handler: mpsc::UnboundedSender<HistoryJsonRpcRequest>,
    ) -> anyhow::Result<ServerHandle> {
        let server =
            IpcServerBuilder::default().build((*ipc_path).as_ref().display().to_string())?;
        let discv5_api = Discv5Api::new(discv5);
        let history_network_api = HistoryNetworkApi::new(history_handler);
        let mut api = discv5_api.into_rpc();
        api.merge(history_network_api.into_rpc())?;
        api.merge(Web3Api.into_rpc())?;
        let handle = server.start(api).await?;
        Ok(handle)
    }

    #[cfg(windows)]
    pub async fn run_ipc(
        _ipc_path: Box<dyn AsRef<Path>>,
        _discv5: Arc<Discovery>,
        _history_handler: mpsc::UnboundedSender<HistoryJsonRpcRequest>,
    ) -> anyhow::Result<ServerHandle> {
        panic!("Windows doesn't support Unix Domain Sockets IPC, use --web3-transport http")
    }
}
