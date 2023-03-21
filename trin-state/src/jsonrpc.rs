use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::error;

use crate::network::StateNetwork;
use trin_types::request::StateJsonRpcRequest;

/// Handles State network JSON-RPC requests
pub struct StateRequestHandler {
    pub network: Arc<StateNetwork>,
    pub state_rx: mpsc::UnboundedReceiver<StateJsonRpcRequest>,
}

impl StateRequestHandler {
    pub async fn handle_client_queries(mut self) {
        while let Some(_request) = self.state_rx.recv().await {
            error!("State JSON-RPC handler is not implemented!")
        }
    }
}
