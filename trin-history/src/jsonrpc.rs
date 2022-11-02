use std::sync::Arc;

use serde_json::Value;
use tokio::sync::mpsc;
use tracing::error;

use crate::network::HistoryNetwork;
use trin_core::{
    jsonrpc::{
        endpoints::HistoryEndpoint,
        types::{
            FindContentParams, FindNodesParams, HistoryJsonRpcRequest, LocalContentParams,
            OfferParams, PingParams, RecursiveFindContentParams, RecursiveFindNodesParams,
            SendOfferParams, StoreParams,
        },
        utils::bucket_entries_to_json,
    },
    portalnet::{storage::ContentStore, types::content_key::HistoryContentKey},
    utils::bytes::hex_encode,
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
                HistoryEndpoint::LocalContent => {
                    let response = match LocalContentParams::<HistoryContentKey>::try_from(
                        request.params,
                    ) {
                        Ok(params) => {
                            match &self.network.overlay.store.read().get(&params.content_key)
                                {
                                    Ok(val) => match val {
                                        Some(val) => Ok(Value::String(hex_encode(val.clone()))),
                                        None => Err(format!(
                                            "Content key is not in local storage: {:?}",
                                            params.content_key
                                        )),
                                    },
                                    Err(err) => Err(format!(
                                        "Database error while looking for content key in local storage: {:?}, with error: {}",
                                        params.content_key, err
                                    )),
                                }
                        }
                        Err(msg) => Err(format!("Invalid LocalContent params: {msg:?}")),
                    };
                    let _ = request.resp.send(response);
                }
                HistoryEndpoint::Store => {
                    let response = match StoreParams::<HistoryContentKey>::try_from(request.params)
                    {
                        Ok(params) => {
                            let content_key = params.content_key.clone();
                            let content = params.content.clone();
                            match self
                                .network
                                .overlay
                                .store
                                .write()
                                .put(content_key, &content)
                            {
                                Ok(_) => Ok(Value::String("true".to_string())),
                                Err(msg) => Ok(Value::String(msg.to_string())),
                            }
                        }
                        Err(msg) => Ok(Value::String(msg.to_string())),
                    };
                    let _ = request.resp.send(response);
                }
                HistoryEndpoint::RecursiveFindContent => {
                    let find_content_params =
                        match RecursiveFindContentParams::try_from(request.params) {
                            Ok(params) => params,
                            Err(msg) => {
                                let _ = request.resp.send(Err(format!(
                                    "Invalid RecursiveFindContent params: {:?}",
                                    msg.code
                                )));
                                return;
                            }
                        };

                    let response =
                        match HistoryContentKey::try_from(find_content_params.content_key.to_vec())
                        {
                            Ok(content_key) => {
                                // Check whether we have the data locally.
                                let local_content: Option<Vec<u8>> =
                                    match self.network.overlay.store.read().get(&content_key) {
                                        Ok(Some(data)) => Some(data),
                                        Ok(None) => None,
                                        Err(err) => {
                                            error!(
                                                error = %err,
                                                content.key = %content_key,
                                                "Error checking data store for content",
                                            );
                                            None
                                        }
                                    };
                                match local_content {
                                    None => {
                                        match self.network.overlay.lookup_content(content_key).await
                                        {
                                            Some(content) => {
                                                let value = Value::String(hex_encode(content));
                                                Ok(value)
                                            }
                                            None => Ok(Value::Null),
                                        }
                                    }
                                    Some(content) => Ok(Value::String(hex_encode(content))),
                                }
                            }
                            Err(err) => Err(format!("Invalid content key requested: {}", err)),
                        };

                    let _ = request.resp.send(response);
                }
                HistoryEndpoint::RecursiveFindNodes => {
                    let find_nodes_params =
                        match RecursiveFindNodesParams::try_from(request.params) {
                            Ok(params) => params,
                            Err(msg) => {
                                let _ = request.resp.send(Err(format!(
                                    "Invalid RecursiveFindNodes params: {:?}",
                                    msg.code
                                )));
                                return;
                            }
                        };

                    let response =
                        {
                            match self.network.overlay.lookup_node_id(find_nodes_params.node_id).await
                            {
                                Some(found_enrs) => {
                                    Ok(found_enrs)
                                }
                                None => Ok(Value::Null),
                            }
                        };

                    let _ = request.resp.send(response);
                }
                HistoryEndpoint::DataRadius => {
                    let radius = &self.network.overlay.data_radius;
                    let _ = request.resp.send(Ok(Value::String(radius.to_string())));
                }
                HistoryEndpoint::FindContent => {
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
                HistoryEndpoint::FindNodes => {
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
                HistoryEndpoint::Offer => {
                    let response = match OfferParams::<HistoryContentKey>::try_from(request.params)
                    {
                        Ok(params) => {
                            let content_key = params.content_key.clone();
                            let content = params.content.into();
                            let content_items = vec![(content_key, content)];
                            let num_peers = self.network.overlay.propagate_gossip(content_items);
                            Ok(num_peers.into())
                        }
                        Err(msg) => Err(format!("Invalid Offer params: {:?}", msg)),
                    };
                    let _ = request.resp.send(response);
                }
                HistoryEndpoint::SendOffer => {
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
                                Err(msg) => Err(format!("SendOffer request timeout: {:?}", msg)),
                            }
                        }
                        Err(msg) => Err(format!("Invalid SendOffer params: {:?}", msg)),
                    };
                    let _ = request.resp.send(response);
                }
                HistoryEndpoint::Ping => {
                    let response = match PingParams::try_from(request.params) {
                        Ok(val) => match self.network.overlay.send_ping(val.enr.into()).await {
                            Ok(pong) => Ok(pong.into()),
                            Err(msg) => Err(format!("Ping request timeout: {:?}", msg)),
                        },
                        Err(msg) => Err(format!("Invalid Ping params: {:?}", msg)),
                    };
                    let _ = request.resp.send(response);
                }
                HistoryEndpoint::RoutingTableInfo => {
                    let bucket_entries_json =
                        bucket_entries_to_json(self.network.overlay.bucket_entries());

                    let _ = request.resp.send(Ok(bucket_entries_json));
                }
            }
        }
    }
}
