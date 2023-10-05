use std::{net::SocketAddr, sync::Arc};

use eyre::Result;
use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
    server::{Server, ServerHandle},
    Methods,
};
use log::info;
use tokio::sync::RwLock;

use crate::node::Node;
use crate::utils::u64_to_hex_string;

pub struct Rpc {
    node: Arc<RwLock<Node>>,
    handle: Option<ServerHandle>,
    port: u16,
}

impl Rpc {
    pub fn new(node: Arc<RwLock<Node>>, port: u16) -> Self {
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
struct RpcInner {
    node: Arc<RwLock<Node>>,
    port: u16,
}

#[async_trait]
impl EthRpcServer for RpcInner {
    async fn chain_id(&self) -> RpcResult<String> {
        let node = self.node.read().await;
        let id = node.chain_id();
        Ok(u64_to_hex_string(id))
    }
}

#[async_trait]
impl NetRpcServer for RpcInner {
    async fn version(&self) -> RpcResult<String> {
        let node = self.node.read().await;
        Ok(node.chain_id().to_string())
    }
}

async fn start(rpc: RpcInner) -> Result<(ServerHandle, SocketAddr)> {
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
