use crate::network::StateNetwork;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use trin_core::jsonrpc::{endpoints::StateEndpointKind, types::StateJsonRpcRequest};

/// Handles State network JSON-RPC requests
pub struct StateRequestHandler {
    pub network: Arc<RwLock<StateNetwork>>,
    pub state_rx: mpsc::UnboundedReceiver<StateJsonRpcRequest>,
}

impl StateRequestHandler {
    pub async fn handle_client_queries(mut self) {
        while let Some(request) = self.state_rx.recv().await {
            match request.endpoint {
                StateEndpointKind::DataRadius => {
                    let _ = request.resp.send(Ok(Value::String(
                        self.network
                            .read()
                            .await
                            .overlay
                            .data_radius
                            .read()
                            .await
                            .to_string(),
                    )));
                }
            }
        }
    }
}
