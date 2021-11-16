use std::sync::Arc;

use serde_json::Value;
use tokio::sync::mpsc;

use crate::network::HistoryNetwork;
use trin_core::jsonrpc::{
    endpoints::HistoryEndpoint,
    types::{HistoryJsonRpcRequest, PingParams},
};

/// Handles History network JSON-RPC requests
pub struct HistoryRequestHandler {
    pub network: Arc<HistoryNetwork>,
    pub history_rx: mpsc::UnboundedReceiver<HistoryJsonRpcRequest>,
}

impl HistoryRequestHandler {
    pub async fn handle_client_queries(mut self) {
        while let Some(request) = self.history_rx.recv().await {
            match request.endpoint {
                HistoryEndpoint::DataRadius => {
                    let radius = &self.network.overlay.data_radius;
                    let _ = request.resp.send(Ok(Value::String(radius.to_string())));
                }
                HistoryEndpoint::Ping => {
                    let response = match PingParams::try_from(request.params) {
                        Ok(val) => {
                            let pong = self
                                .network
                                .read()
                                .await
                                .overlay
                                .send_ping(val.enr, None)
                                .await
                                .unwrap();
                            Ok(Value::String(format!("{:?}", pong.payload.unwrap())))
                        }
                        Err(msg) => Err(format!("Invalid Ping params: {:?}", msg)),
                    };
                    let _ = request.resp.send(response);
                }
            }
        }
    }
}
