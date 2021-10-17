#![allow(dead_code)]

use std::sync::Arc;

use serde_json::Value;
use tokio::sync::mpsc;
use tokio::sync::RwLock;

use crate::jsonrpc::endpoints::{Discv5Endpoint, HistoryEndpoint, StateEndpoint, TrinEndpoint};
use crate::jsonrpc::types::{
    HistoryJsonRpcRequest, JsonRequest, PortalJsonRpcRequest, StateJsonRpcRequest,
};
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
        while let Some(portal_jsonrpc_req) = self.portal_jsonrpc_rx.recv().await {
            let response: Value = match portal_jsonrpc_req.endpoint {
                TrinEndpoint::Discv5Endpoint(endpoint) => match endpoint {
                    Discv5Endpoint::NodeInfo => self.discovery.read().await.node_info(),
                    Discv5Endpoint::RoutingTableInfo => {
                        self.discovery.write().await.routing_table_info()
                    }
                    Discv5Endpoint::FindNodes => {
                        // TODO: Add RPC handler for every endpoint and validate parameters
                        Value::String("Disscv5 FindNodes endpoint not implemented yet!".to_owned())
                    }
                },
                TrinEndpoint::HistoryEndpoint(endpoint) => {
                    let response = match self.history_jsonrpc_tx.as_ref() {
                        Some(tx) => {
                            proxy_query_to_history_subnet(portal_jsonrpc_req.request, tx, endpoint)
                                .await
                        }
                        None => Err("Chain history subnetwork unavailable.".to_string()),
                    };
                    response.unwrap_or_else(Value::String)
                }
                TrinEndpoint::StateEndpoint(endpoint) => {
                    let response = match self.state_jsonrpc_tx.as_ref() {
                        Some(tx) => {
                            proxy_query_to_state_subnet(portal_jsonrpc_req.request, tx, endpoint)
                                .await
                        }
                        None => Err("State subnetwork unavailable.".to_string()),
                    };
                    response.unwrap_or_else(Value::String)
                }
                _ => Value::String(format!(
                    "Can't process portal network endpoint {:?}",
                    portal_jsonrpc_req.endpoint
                )),
            };
            let _ = portal_jsonrpc_req.resp.send(Ok(response));
        }
    }
}

async fn proxy_query_to_history_subnet(
    request: JsonRequest,
    subnet_tx: &mpsc::UnboundedSender<HistoryJsonRpcRequest>,
    endpoint: HistoryEndpoint,
) -> Result<Value, String> {
    let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
    let message = HistoryJsonRpcRequest {
        request,
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
    request: JsonRequest,
    subnet_tx: &mpsc::UnboundedSender<StateJsonRpcRequest>,
    endpoint: StateEndpoint,
) -> Result<Value, String> {
    let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
    let message = StateJsonRpcRequest {
        request,
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
