use std::sync::Arc;

use serde_json::Value;
use tokio::sync::mpsc;

use crate::network::StateNetwork;
use trin_core::jsonrpc::{
    endpoints::StateEndpoint,
    types::{FindContentParams, FindNodesParams, PingParams, StateJsonRpcRequest},
};

/// Handles State network JSON-RPC requests
pub struct StateRequestHandler {
    pub network: Arc<StateNetwork>,
    pub state_rx: mpsc::UnboundedReceiver<StateJsonRpcRequest>,
}

impl StateRequestHandler {
    pub async fn handle_client_queries(mut self) {
        while let Some(request) = self.state_rx.recv().await {
            match request.endpoint {
                StateEndpoint::DataRadius => {
                    let radius = &self.network.overlay.data_radius;
                    let _ = request.resp.send(Ok(Value::String(radius.to_string())));
                }
                StateEndpoint::FindContent => {
                    let response = match FindContentParams::try_from(request.params) {
                        Ok(val) => match self
                            .network
                            .overlay
                            .send_find_content(val.enr, val.content_key.into())
                            .await
                        {
                            Ok(content) => match content.try_into() {
                                Ok(val) => Ok(val),
                                Err(_) => Err("Content response decoding error".to_string()),
                            },
                            Err(msg) => Err(format!("FindContent request timeout: {:?}", msg)),
                        },
                        Err(msg) => Err(format!("Invalid FindContent params: {:?}", msg)),
                    };
                    let _ = request.resp.send(response);
                }
                StateEndpoint::FindNodes => {
                    let response = match FindNodesParams::try_from(request.params) {
                        Ok(val) => match self
                            .network
                            .overlay
                            .send_find_nodes(val.enr, val.distances)
                            .await
                        {
                            Ok(nodes) => Ok(nodes.into()),
                            Err(msg) => Err(format!("FindNodes request timeout: {:?}", msg)),
                        },
                        Err(msg) => Err(format!("Invalid FindNodes params: {:?}", msg)),
                    };
                    let _ = request.resp.send(response);
                }
                StateEndpoint::Ping => {
                    let response = match PingParams::try_from(request.params) {
                        Ok(val) => match self.network.overlay.send_ping(val.enr).await {
                            Ok(pong) => Ok(pong.into()),
                            Err(msg) => Err(format!("Ping request timeout: {:?}", msg)),
                        },
                        Err(msg) => Err(format!("Invalid Ping params: {:?}", msg)),
                    };
                    let _ = request.resp.send(response);
                }
            }
        }
    }
}
