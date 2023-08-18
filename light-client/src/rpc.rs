use ethers::{
    abi::AbiEncode,
    types::{Address, SyncingStatus, U256},
};
use eyre::Result;
use log::info;
use std::{fmt::Display, net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;

use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
    server::{Server, ServerHandle},
    types::ErrorObject,
    Methods,
};

use crate::node::Node;

use crate::config::utils::hex_str_to_bytes;
use crate::types::BlockTag;
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
    #[method(name = "getBlockTransactionCountByHash")]
    async fn get_block_transaction_count_by_hash(&self, hash: &str) -> RpcResult<String>;
    #[method(name = "getBlockTransactionCountByNumber")]
    async fn get_block_transaction_count_by_number(&self, block: BlockTag) -> RpcResult<String>;
    #[method(name = "chainId")]
    async fn chain_id(&self) -> RpcResult<String>;
    #[method(name = "gasPrice")]
    async fn gas_price(&self) -> RpcResult<String>;
    #[method(name = "maxPriorityFeePerGas")]
    async fn max_priority_fee_per_gas(&self) -> RpcResult<String>;
    #[method(name = "blockNumber")]
    async fn block_number(&self) -> RpcResult<String>;
    #[method(name = "getCoinbase")]
    async fn get_coinbase(&self) -> RpcResult<Address>;
    #[method(name = "syncing")]
    async fn syncing(&self) -> RpcResult<SyncingStatus>;
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
    async fn get_block_transaction_count_by_hash(&self, hash: &str) -> RpcResult<String> {
        let hash = convert_err(hex_str_to_bytes(hash))?;
        let node = self.node.read().await;
        let transaction_count = convert_err(node.get_block_transaction_count_by_hash(&hash))?;

        Ok(u64_to_hex_string(transaction_count))
    }

    async fn get_block_transaction_count_by_number(&self, block: BlockTag) -> RpcResult<String> {
        let node = self.node.read().await;
        let transaction_count = convert_err(node.get_block_transaction_count_by_number(block))?;
        Ok(u64_to_hex_string(transaction_count))
    }

    async fn chain_id(&self) -> RpcResult<String> {
        let node = self.node.read().await;
        let id = node.chain_id();
        Ok(u64_to_hex_string(id))
    }

    async fn gas_price(&self) -> RpcResult<String> {
        let node = self.node.read().await;
        let gas_price = convert_err(node.get_gas_price())?;
        Ok(format_hex(&gas_price))
    }

    async fn max_priority_fee_per_gas(&self) -> RpcResult<String> {
        let node = self.node.read().await;
        let tip = convert_err(node.get_priority_fee())?;
        Ok(format_hex(&tip))
    }

    async fn block_number(&self) -> RpcResult<String> {
        let node = self.node.read().await;
        let num = convert_err(node.get_block_number())?;
        Ok(u64_to_hex_string(num))
    }

    async fn get_coinbase(&self) -> RpcResult<Address> {
        let node = self.node.read().await;
        Ok(node.get_coinbase().expect("coinbase not found"))
    }

    async fn syncing(&self) -> RpcResult<SyncingStatus> {
        let node = self.node.read().await;
        convert_err(node.syncing())
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

fn convert_err<T, E: Display>(res: Result<T, E>) -> RpcResult<T> {
    // -32099 is a custom error code for a server error
    // see: https://www.jsonrpc.org/specification#error_object
    // It's a bit of a cop-out, until we implement more specific errors, being
    // sure not to confilct with the standard Ethereum error codes:
    // https://docs.infura.io/networks/ethereum/json-rpc-methods#error-codes
    res.map_err(|err| ErrorObject::owned(-32099, err.to_string(), None::<()>))
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
