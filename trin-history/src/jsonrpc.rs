use crate::network::HistoryNetwork;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use trin_core::jsonrpc::{endpoints::HistoryEndpoint, types::HistoryJsonRpcRequest};

/// Handles History network JSON-RPC requests
pub struct HistoryRequestHandler {
    pub network: Arc<RwLock<HistoryNetwork>>,
    pub history_rx: mpsc::UnboundedReceiver<HistoryJsonRpcRequest>,
}

impl HistoryRequestHandler {
    pub async fn handle_client_queries(mut self) {
        while let Some(request) = self.history_rx.recv().await {
            match request.endpoint {
                HistoryEndpoint::DataRadius => {
                    let _ = request.resp.send(Ok(Value::String(
                        self.network.read().await.overlay.data_radius.to_string(),
                    )));
                }
            }
        }
    }
}
