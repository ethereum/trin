use ethers::{
    abi::AbiEncode,
    types::{Address, SyncingStatus, U256},
};
use eyre::Result;
use log::info;
use std::{fmt::Display, net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;

use jsonrpsee::{
    core::{async_trait, server::rpc_module::Methods, Error},
    http_server::{HttpServerBuilder, HttpServerHandle},
    proc_macros::rpc,
};

use crate::node::Node;

use crate::config::utils::hex_str_to_bytes;
use crate::types::BlockTag;
use crate::utils::u64_to_hex_string;

pub struct Rpc {
    node: Arc<RwLock<Node>>,
    handle: Option<HttpServerHandle>,
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
    #[method(name = "getBlockTransactionCountByHash")]
    async fn get_block_transaction_count_by_hash(&self, hash: &str) -> Result<String, Error>;
    #[method(name = "getBlockTransactionCountByNumber")]
    async fn get_block_transaction_count_by_number(&self, block: BlockTag)
        -> Result<String, Error>;
    #[method(name = "chainId")]
    async fn chain_id(&self) -> Result<String, Error>;
    #[method(name = "gasPrice")]
    async fn gas_price(&self) -> Result<String, Error>;
    #[method(name = "maxPriorityFeePerGas")]
    async fn max_priority_fee_per_gas(&self) -> Result<String, Error>;
    #[method(name = "blockNumber")]
    async fn block_number(&self) -> Result<String, Error>;
    #[method(name = "getCoinbase")]
    async fn get_coinbase(&self) -> Result<Address, Error>;
    #[method(name = "syncing")]
    async fn syncing(&self) -> Result<SyncingStatus, Error>;
}

#[rpc(client, server, namespace = "net")]
trait NetRpc {
    #[method(name = "version")]
    async fn version(&self) -> Result<String, Error>;
}

#[derive(Clone)]
struct RpcInner {
    node: Arc<RwLock<Node>>,
    port: u16,
}

#[async_trait]
impl EthRpcServer for RpcInner {
    async fn get_block_transaction_count_by_hash(&self, hash: &str) -> Result<String, Error> {
        let hash = convert_err(hex_str_to_bytes(hash))?;
        let node = self.node.read().await;
        let transaction_count = convert_err(node.get_block_transaction_count_by_hash(&hash))?;

        Ok(u64_to_hex_string(transaction_count))
    }

    async fn get_block_transaction_count_by_number(
        &self,
        block: BlockTag,
    ) -> Result<String, Error> {
        let node = self.node.read().await;
        let transaction_count = convert_err(node.get_block_transaction_count_by_number(block))?;
        Ok(u64_to_hex_string(transaction_count))
    }

    async fn chain_id(&self) -> Result<String, Error> {
        let node = self.node.read().await;
        let id = node.chain_id();
        Ok(u64_to_hex_string(id))
    }

    async fn gas_price(&self) -> Result<String, Error> {
        let node = self.node.read().await;
        let gas_price = convert_err(node.get_gas_price())?;
        Ok(format_hex(&gas_price))
    }

    async fn max_priority_fee_per_gas(&self) -> Result<String, Error> {
        let node = self.node.read().await;
        let tip = convert_err(node.get_priority_fee())?;
        Ok(format_hex(&tip))
    }

    async fn block_number(&self) -> Result<String, Error> {
        let node = self.node.read().await;
        let num = convert_err(node.get_block_number())?;
        Ok(u64_to_hex_string(num))
    }

    async fn get_coinbase(&self) -> Result<Address, Error> {
        let node = self.node.read().await;
        Ok(node.get_coinbase().expect("coinbase not found"))
    }

    async fn syncing(&self) -> Result<SyncingStatus, Error> {
        let node = self.node.read().await;
        convert_err(node.syncing())
    }
}

#[async_trait]
impl NetRpcServer for RpcInner {
    async fn version(&self) -> Result<String, Error> {
        let node = self.node.read().await;
        Ok(node.chain_id().to_string())
    }
}

async fn start(rpc: RpcInner) -> Result<(HttpServerHandle, SocketAddr)> {
    let addr = format!("127.0.0.1:{}", rpc.port);
    let server = HttpServerBuilder::default().build(addr).await?;

    let addr = server.local_addr()?;

    let mut methods = Methods::new();
    let eth_methods: Methods = EthRpcServer::into_rpc(rpc.clone()).into();
    let net_methods: Methods = NetRpcServer::into_rpc(rpc).into();

    methods.merge(eth_methods)?;
    methods.merge(net_methods)?;

    let handle = server.start(methods)?;

    Ok((handle, addr))
}

fn convert_err<T, E: Display>(res: Result<T, E>) -> Result<T, Error> {
    res.map_err(|err| Error::Custom(err.to_string()))
}

fn format_hex(num: &U256) -> String {
    let stripped = num
        .encode_hex()
        .strip_prefix("0x")
        .expect("prefix not found")
        .trim_start_matches('0')
        .to_string();

    let stripped = if stripped.is_empty() {
        "0".to_string()
    } else {
        stripped
    };

    format!("0x{stripped}")
}
