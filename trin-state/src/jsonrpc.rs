use crate::network::StateNetwork;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::mpsc;
use trin_core::jsonrpc::{endpoints::StateEndpoint, types::StateJsonRpcRequest};

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
            }
        }
    }
}
