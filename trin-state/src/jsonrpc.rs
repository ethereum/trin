use std::sync::Arc;

use serde_json::Value;
use tokio::sync::mpsc;

use crate::network::StateNetwork;
use ethportal_api::types::jsonrpc::request::StateJsonRpcRequest;

/// Handles State network JSON-RPC requests
pub struct StateRequestHandler {
    pub network: Arc<StateNetwork>,
    pub state_rx: mpsc::UnboundedReceiver<StateJsonRpcRequest>,
}

impl StateRequestHandler {
    pub async fn handle_client_queries(mut self) {
        while let Some(request) = self.state_rx.recv().await {
            let network = Arc::clone(&self.network);
            tokio::spawn(async move { Self::handle_request(network, request).await });
        }
    }

    async fn handle_request(_network: Arc<StateNetwork>, request: StateJsonRpcRequest) {
        let response: Result<Value, String> = Err("Not implemented".to_string());
        let _ = request.resp.send(response);
    }
}
