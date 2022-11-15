#![allow(dead_code)]

use std::sync::Arc;

use anyhow::anyhow;
use serde_json::Value;
use tokio::sync::{mpsc, RwLock};
use tracing::debug;

use crate::{
    jsonrpc::{
        endpoints::{Discv5Endpoint, HistoryEndpoint, PortalEndpoint, StateEndpoint, TrinEndpoint},
        types::{HistoryJsonRpcRequest, Params, PortalJsonRpcRequest, StateJsonRpcRequest},
    },
    portalnet::discovery::Discovery,
    types::validation::HeaderOracle,
    TRIN_VERSION,
};

type Responder<T, E> = mpsc::UnboundedSender<Result<T, E>>;

/// Main JSON-RPC handler. It dispatches json-rpc requests to the overlay networks.
pub struct JsonRpcHandler {
    pub discovery: Arc<Discovery>,
    pub portal_jsonrpc_rx: mpsc::UnboundedReceiver<PortalJsonRpcRequest>,
    pub header_oracle: Arc<RwLock<HeaderOracle>>,
}

impl JsonRpcHandler {
    pub async fn process_jsonrpc_requests(mut self) {
        while let Some(request) = self.portal_jsonrpc_rx.recv().await {
            debug!("Processing Portal JSON-RPC request: {:?}", request.endpoint);
            let response = match request.endpoint {
                TrinEndpoint::Discv5Endpoint(endpoint) => match endpoint {
                    Discv5Endpoint::NodeInfo => Ok(self.discovery.node_info()),
                    Discv5Endpoint::RoutingTableInfo => Ok(self.discovery.routing_table_info()),
                },
                TrinEndpoint::HistoryEndpoint(endpoint) => {
                    match self.header_oracle.read().await.history_jsonrpc_tx() {
                        Ok(tx) => {
                            proxy_query_to_history_subnet(&tx, endpoint, request.params).await
                        }
                        Err(_) => Err(anyhow!("Chain history subnetwork unavailable.")),
                    }
                }
                TrinEndpoint::StateEndpoint(endpoint) => {
                    match self.header_oracle.read().await.state_jsonrpc_tx() {
                        Ok(tx) => proxy_query_to_state_subnet(&tx, endpoint, request.params).await,
                        Err(_) => Err(anyhow!("State subnetwork unavailable.")),
                    }
                }
                TrinEndpoint::PortalEndpoint(endpoint) => match endpoint {
                    PortalEndpoint::ClientVersion => {
                        Ok(Value::String(format!("trin v{}", TRIN_VERSION)))
                    }
                },
                TrinEndpoint::EthEndpoint(endpoint) => {
                    self.header_oracle
                        .read()
                        .await
                        .process_eth_endpoint(endpoint, request.params)
                        .await
                }
                _ => Err(anyhow!(
                    "Can't process portal network endpoint {:?}",
                    request.endpoint
                )),
            };
            let _ = request.resp.send(response);
        }
    }
}

pub async fn proxy_query_to_history_subnet(
    subnet_tx: &mpsc::UnboundedSender<HistoryJsonRpcRequest>,
    endpoint: HistoryEndpoint,
    params: Params,
) -> anyhow::Result<Value> {
    let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
    let message = HistoryJsonRpcRequest {
        endpoint,
        resp: resp_tx,
        params,
    };
    let _ = subnet_tx.send(message);
    match resp_rx.recv().await {
        Some(val) => match val {
            Ok(result) => Ok(result),
            Err(msg) => Err(anyhow!(
                "Error returned from chain history subnetwork: {:?}",
                msg
            )),
        },
        None => Err(anyhow!("No response from chain history subnetwork")),
    }
}

async fn proxy_query_to_state_subnet(
    subnet_tx: &mpsc::UnboundedSender<StateJsonRpcRequest>,
    endpoint: StateEndpoint,
    params: Params,
) -> anyhow::Result<Value> {
    let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
    let message = StateJsonRpcRequest {
        endpoint,
        resp: resp_tx,
        params,
    };
    let _ = subnet_tx.send(message);
    match resp_rx.recv().await {
        Some(val) => match val {
            Ok(result) => Ok(result),
            Err(msg) => Err(anyhow!("Error returned from state subnetwork: {:?}", msg)),
        },
        None => Err(anyhow!("No response from state subnetwork")),
    }
}
