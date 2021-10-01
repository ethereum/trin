#![allow(dead_code)]

use std::sync::Arc;

use serde_json::Value;
use tokio::sync::mpsc;
use tokio::sync::RwLock;

use crate::jsonrpc::endpoints::{
    Discv5EndpointKind, HistoryEndpointKind, PortalEndpointKind, StateEndpointKind,
};
use crate::jsonrpc::types::{HistoryJsonRpcRequest, PortalJsonRpcRequest, StateJsonRpcRequest};
use crate::portalnet::discovery::Discovery;

type Responder<T, E> = mpsc::UnboundedSender<Result<T, E>>;

/// Main JSON-RPC handler. It dispatches json-rpc requests to the overlay networks.
pub struct JsonRpcHandler {
    pub discovery: Arc<RwLock<Discovery>>,
    pub portal_jsonrpc_rx: mpsc::UnboundedReceiver<PortalJsonRpcRequest>,
    pub state_jsonrpc_tx: Option<mpsc::UnboundedSender<StateJsonRpcRequest>>,
    pub history_jsonrpc_tx: Option<mpsc::UnboundedSender<HistoryJsonRpcRequest>>,
}

impl JsonRpcHandler {
    pub async fn process_jsonrpc_requests(mut self) {
        while let Some(request) = self.portal_jsonrpc_rx.recv().await {
            let response: Value = match request.endpoint {
                PortalEndpointKind::Discv5EndpointKind(endpoint) => match endpoint {
                    Discv5EndpointKind::NodeInfo => {
                        Value::String(self.discovery.read().await.node_info())
                    }
                    Discv5EndpointKind::RoutingTableInfo => {
                        Value::Array(self.discovery.read().await.routing_table_info())
                    }
                },
                PortalEndpointKind::HistoryEndpointKind(endpoint) => {
                    let response = match self.history_jsonrpc_tx.as_ref() {
                        Some(tx) => proxy_query_to_history_subnet(tx, endpoint).await,
                        None => Err("Chain history subnetwork unavailable.".to_string()),
                    };
                    response.unwrap_or_else(Value::String)
                }
                PortalEndpointKind::StateEndpointKind(endpoint) => {
                    let response = match self.state_jsonrpc_tx.as_ref() {
                        Some(tx) => proxy_query_to_state_subnet(tx, endpoint).await,
                        None => Err("State subnetwork unavailable.".to_string()),
                    };
                    response.unwrap_or_else(Value::String)
                }
                _ => Value::String(format!(
                    "Can't process portal network endpoint {:?}",
                    request.endpoint
                )),
            };
            let _ = request.resp.send(Ok(response));
        }
    }
}

async fn proxy_query_to_history_subnet(
    subnet_tx: &mpsc::UnboundedSender<HistoryJsonRpcRequest>,
    endpoint: HistoryEndpointKind,
) -> Result<Value, String> {
    let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
    let message = HistoryJsonRpcRequest {
        endpoint,
        resp: resp_tx,
    };
    let _ = subnet_tx.send(message);
    match resp_rx.recv().await {
        Some(val) => match val {
            Ok(result) => Ok(result),
            Err(msg) => Err(format!(
                "Error returned from chain history subnetwork: {:?}",
                msg
            )),
        },
        None => Err("No response from chain history subnetwork".to_string()),
    }
}

async fn proxy_query_to_state_subnet(
    subnet_tx: &mpsc::UnboundedSender<StateJsonRpcRequest>,
    endpoint: StateEndpointKind,
) -> Result<Value, String> {
    let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
    let message = StateJsonRpcRequest {
        endpoint,
        resp: resp_tx,
    };
    let _ = subnet_tx.send(message);
    match resp_rx.recv().await {
        Some(val) => match val {
            Ok(result) => Ok(result),
            Err(msg) => Err(format!("Error returned from state subnetwork: {:?}", msg)),
        },
        None => Err("No response from state subnetwork".to_string()),
    }
}
