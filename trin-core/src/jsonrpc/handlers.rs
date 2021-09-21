#![allow(dead_code)]

use std::sync::Arc;

use serde_json::Value;
use tokio::sync::mpsc;
use tokio::sync::RwLock;

use super::types::Params;

use crate::portalnet::discovery::Discovery;

type Responder<T, E> = mpsc::UnboundedSender<Result<T, E>>;

#[derive(Debug)]
pub enum HistoryEndpointKind {
    GetHistoryNetworkData,
}

#[derive(Debug)]
pub struct HistoryNetworkEndpoint {
    pub kind: HistoryEndpointKind,
    pub resp: Responder<Value, String>,
}

#[derive(Debug)]
pub enum StateEndpointKind {
    GetStateNetworkData,
}

#[derive(Debug)]
pub struct StateNetworkEndpoint {
    pub kind: StateEndpointKind,
    pub resp: Responder<Value, String>,
}

#[derive(Debug)]
pub enum PortalEndpointKind {
    DummyHistoryNetworkData,
    DummyStateNetworkData,
    NodeInfo,
    RoutingTableInfo,
}

#[derive(Debug)]
pub struct PortalEndpoint {
    pub kind: PortalEndpointKind,
    pub params: Params,
    pub resp: Responder<Value, String>,
}

pub struct JsonRpcHandler {
    pub discovery: Arc<RwLock<Discovery>>,
    pub jsonrpc_rx: mpsc::UnboundedReceiver<PortalEndpoint>,
    pub state_tx: Option<mpsc::UnboundedSender<StateNetworkEndpoint>>,
    pub history_tx: Option<mpsc::UnboundedSender<HistoryNetworkEndpoint>>,
}

impl JsonRpcHandler {
    pub async fn process_jsonrpc_requests(mut self) {
        while let Some(cmd) = self.jsonrpc_rx.recv().await {
            use PortalEndpointKind::*;

            match cmd.kind {
                NodeInfo => {
                    let node_id = self.discovery.read().await.local_enr().to_base64();
                    let _ = cmd.resp.send(Ok(Value::String(node_id)));
                }
                RoutingTableInfo => {
                    let routing_table_info = self
                        .discovery
                        .read()
                        .await
                        .discv5
                        .table_entries_id()
                        .iter()
                        .map(|node_id| Value::String(node_id.to_string()))
                        .collect();
                    let _ = cmd.resp.send(Ok(Value::Array(routing_table_info)));
                }
                DummyHistoryNetworkData => {
                    let response = match self.history_tx.as_ref() {
                        Some(tx) => {
                            proxy_query_to_history_subnet(
                                tx,
                                HistoryEndpointKind::GetHistoryNetworkData,
                            )
                            .await
                        }
                        None => Err("Chain history subnetwork unavailable.".to_string()),
                    };
                    let _ = cmd.resp.send(response);
                }
                DummyStateNetworkData => {
                    let response = match self.state_tx.as_ref() {
                        Some(tx) => {
                            proxy_query_to_state_subnet(tx, StateEndpointKind::GetStateNetworkData)
                                .await
                        }
                        None => Err("State subnetwork unavailable.".to_string()),
                    };
                    let _ = cmd.resp.send(response);
                }
            }
        }
    }
}

async fn proxy_query_to_history_subnet(
    subnet_tx: &mpsc::UnboundedSender<HistoryNetworkEndpoint>,
    msg_kind: HistoryEndpointKind,
) -> Result<Value, String> {
    let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
    let message = HistoryNetworkEndpoint {
        kind: msg_kind,
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
    subnet_tx: &mpsc::UnboundedSender<StateNetworkEndpoint>,
    msg_kind: StateEndpointKind,
) -> Result<Value, String> {
    let (resp_tx, mut resp_rx) = mpsc::unbounded_channel::<Result<Value, String>>();
    let message = StateNetworkEndpoint {
        kind: msg_kind,
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
