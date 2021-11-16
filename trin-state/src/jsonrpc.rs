use std::sync::Arc;

use serde_json::Value;
use tokio::sync::mpsc;

use crate::network::StateNetwork;
use trin_core::jsonrpc::{
    endpoints::StateEndpoint,
    types::{PingParams, StateJsonRpcRequest},
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
                StateEndpoint::Ping => {
                    let response = match PingParams::try_from(request.params) {
                        Ok(val) => match self.network.overlay.send_ping(val.enr, None).await {
                            Ok(pong) => Ok(Value::String(format!("{:?}", pong.payload.unwrap()))),
                            Err(msg) => Err(format!("Ping request timeout: {:?}", msg).to_owned()),
                        },
                        Err(msg) => Err(format!("Invalid Ping params: {:?}", msg)),
                    };
                    let _ = request.resp.send(response);
                }
            }
        }
    }
}
