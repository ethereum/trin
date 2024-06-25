use anyhow::Result;
use log::info;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;

use crate::consensus::rpc::ConsensusRpc;
use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
    server::{Server, ServerHandle},
    Methods,
};

use crate::node::Node;

use crate::utils::u64_to_hex_string;

#[derive(Clone)]
pub struct Rpc<R: ConsensusRpc> {
    node: Arc<RwLock<Node<R>>>,
    handle: Option<ServerHandle>,
    port: u16,
}

impl<R: ConsensusRpc + 'static> Rpc<R> {
    pub fn new(node: Arc<RwLock<Node<R>>>, port: u16) -> Self {
        Rpc {
            node,
            handle: None,
            port,
        }
    }

    pub async fn start(&mut self) -> Result<SocketAddr> {
        let rpc_inner = RpcInner {
            node: self.node.clone(),
            port: self.port,
        };

        let (handle, addr) = start(rpc_inner).await?;
        self.handle = Some(handle);

        info!("rpc server started at {}", addr);

        Ok(addr)
    }
}

#[rpc(server, namespace = "eth")]
trait EthRpc {
    #[method(name = "chainId")]
    async fn chain_id(&self) -> RpcResult<String>;
}

#[rpc(client, server, namespace = "net")]
trait NetRpc {
    #[method(name = "version")]
    async fn version(&self) -> RpcResult<String>;
}

#[derive(Clone)]
struct RpcInner<R: ConsensusRpc> {
    node: Arc<RwLock<Node<R>>>,
    port: u16,
}

#[async_trait]
impl<R: ConsensusRpc + 'static> EthRpcServer for RpcInner<R> {
    async fn chain_id(&self) -> RpcResult<String> {
        let node = self.node.read().await;
        let id = node.chain_id();
        Ok(u64_to_hex_string(id))
    }
}

#[async_trait]
impl<R: ConsensusRpc + 'static> NetRpcServer for RpcInner<R> {
    async fn version(&self) -> RpcResult<String> {
        let node = self.node.read().await;
        Ok(node.chain_id().to_string())
    }
}

async fn start<R: ConsensusRpc + 'static>(rpc: RpcInner<R>) -> Result<(ServerHandle, SocketAddr)> {
    let addr = format!("127.0.0.1:{}", rpc.port);
    let server = Server::builder().build(addr).await?;

    let addr = server.local_addr()?;

    let mut methods = Methods::new();
    let eth_methods: Methods = EthRpcServer::into_rpc(rpc.clone()).into();
    let net_methods: Methods = NetRpcServer::into_rpc(rpc).into();

    methods.merge(eth_methods)?;
    methods.merge(net_methods)?;

    let handle = server.start(methods);

    Ok((handle, addr))
}
