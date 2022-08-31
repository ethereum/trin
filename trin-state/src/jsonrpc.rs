use std::sync::Arc;

use serde_json::Value;
use tokio::sync::mpsc;

use crate::network::StateNetwork;
use trin_core::utils::bytes::hex_encode;
use trin_core::{
    jsonrpc::{
        endpoints::StateEndpoint,
        types::{
            FindContentParams, FindNodesParams, LocalContentParams, PingParams, SendOfferParams,
            StateJsonRpcRequest, StoreParams,
        },
        utils::bucket_entries_to_json,
    },
    portalnet::types::content_key::StateContentKey,
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
                StateEndpoint::LocalContent => {
                    let response =
                        match LocalContentParams::<StateContentKey>::try_from(request.params) {
                            Ok(params) => {
                                match &self.network.overlay.storage.read().get(&params.content_key)
                                {
                                    Ok(val) => match val {
                                        Some(val) => Ok(Value::String(hex_encode(val.clone()))),
                                        None => Err(format!(
                                            "Unable to find content key in local storage: {:?}",
                                            params.content_key
                                        )),
                                    },
                                    Err(_) => Err(format!(
                                        "Unable to find content key in local storage: {:?}",
                                        params.content_key
                                    )),
                                }
                            }
                            Err(msg) => Err(format!("Invalid LocalContent params: {msg:?}")),
                        };
                    let _ = request.resp.send(response);
                }
                StateEndpoint::Store => {
                    let response = match StoreParams::<StateContentKey>::try_from(request.params) {
                        Ok(params) => {
                            let content_key = params.content_key.clone();
                            let content = params.content.clone();
                            match self
                                .network
                                .overlay
                                .storage
                                .write()
                                .store(&content_key, &content)
                            {
                                Ok(_) => Ok(Value::String("true".to_string())),
                                Err(msg) => Ok(Value::String(msg.to_string())),
                            }
                        }
                        Err(msg) => Ok(Value::String(msg.to_string())),
                    };
                    let _ = request.resp.send(response);
                }
                StateEndpoint::DataRadius => {
                    let radius = &self.network.overlay.data_radius;
                    let _ = request.resp.send(Ok(Value::String(radius.to_string())));
                }
                StateEndpoint::FindContent => {
                    let response = match FindContentParams::try_from(request.params) {
                        Ok(val) => match self
                            .network
                            .overlay
                            .send_find_content(val.enr.into(), val.content_key.into())
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
                            .send_find_nodes(val.enr.into(), val.distances)
                            .await
                        {
                            Ok(nodes) => Ok(nodes.into()),
                            Err(msg) => Err(format!("FindNodes request timeout: {:?}", msg)),
                        },
                        Err(msg) => Err(format!("Invalid FindNodes params: {:?}", msg)),
                    };
                    let _ = request.resp.send(response);
                }
                StateEndpoint::SendOffer => {
                    let response = match SendOfferParams::try_from(request.params) {
                        Ok(val) => {
                            let content_keys =
                                val.content_keys.iter().map(|key| key.to_vec()).collect();

                            match self
                                .network
                                .overlay
                                .send_offer(content_keys, val.enr.into())
                                .await
                            {
                                Ok(accept) => Ok(accept.into()),
                                Err(msg) => Err(format!("Offer request timeout: {:?}", msg)),
                            }
                        }
                        Err(msg) => Err(format!("Invalid Offer params: {:?}", msg)),
                    };
                    let _ = request.resp.send(response);
                }
                StateEndpoint::Ping => {
                    let response = match PingParams::try_from(request.params) {
                        Ok(val) => match self.network.overlay.send_ping(val.enr.into()).await {
                            Ok(pong) => Ok(pong.into()),
                            Err(msg) => Err(format!("Ping request timeout: {:?}", msg)),
                        },
                        Err(msg) => Err(format!("Invalid Ping params: {:?}", msg)),
                    };
                    let _ = request.resp.send(response);
                }
                StateEndpoint::RoutingTableInfo => {
                    let bucket_entries_json =
                        bucket_entries_to_json(self.network.overlay.bucket_entries());

                    let _ = request.resp.send(Ok(bucket_entries_json));
                }
            }
        }
    }
}
