use std::sync::Arc;

use serde_json::{json, Value};
use tokio::sync::mpsc;
use tracing::error;

use crate::network::HistoryNetwork;
use trin_core::{
    jsonrpc::{
        endpoints::HistoryEndpoint,
        types::{
            FindContentParams, FindNodesParams, HistoryJsonRpcRequest, LocalContentParams,
            OfferParams, PaginateLocalContentKeysParams, PingParams, RecursiveFindContentParams,
            SendOfferParams, StoreParams,
        },
        utils::bucket_entries_to_json,
    },
    portalnet::{
        storage::ContentStore,
        types::{
            content_key::{HistoryContentKey, OverlayContentKey},
            distance::{Metric, XorMetric},
        },
    },
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
                                        None => Ok(Value::String("0x0".to_string())),
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
                HistoryEndpoint::PaginateLocalContentKeys => {
                    let response = match PaginateLocalContentKeysParams::try_from(request.params) {
                        Ok(params) => {
                            match &self.network.overlay.store.read().paginate(&params.offset, &params.limit)
                                {
                                    Ok(val) => Ok(json!(val)),
                                    Err(err) => Err(format!(
                                        "Database error while paginating local content keys with offset: {:?}, limit: {:?}. Error message: {}",
                                        params.offset, params.limit, err
                                    )),
                                }
                        }
                        Err(msg) => {
                            Err(format!("Invalid PaginateLocalContentKeys params: {msg:?}"))
                        }
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
                                Ok(_) => Ok(Value::Bool(true)),
                                Err(msg) => Ok(Value::String(msg.to_string())),
                            }
                        }
                        Err(msg) => Ok(Value::String(msg.to_string())),
                    };
                    let _ = request.resp.send(response);
                }
                HistoryEndpoint::RecursiveFindContent
                | HistoryEndpoint::TraceRecursiveFindContent => {
                    let params = match RecursiveFindContentParams::try_from(request.params) {
                        Ok(val) => val,
                        Err(err) => {
                            let response = Err(format!(
                                "Invalid RecursiveFindContent params: {:?}",
                                err.code
                            ));
                            let _ = request.resp.send(response);
                            continue;
                        }
                    };
                    let content_key = match HistoryContentKey::try_from(params.content_key.to_vec())
                    {
                        Ok(val) => val,
                        Err(err) => {
                            let response = Err(format!("Invalid content key requested: {err}"));
                            let _ = request.resp.send(response);
                            continue;
                        }
                    };
                    let is_trace = match request.endpoint {
                        HistoryEndpoint::RecursiveFindContent => false,
                        HistoryEndpoint::TraceRecursiveFindContent => true,
                        _ => panic!("Invalid state reached, error decoding jsonrpc endpoint."),
                    };
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
                    let (content, closest_nodes) = match local_content {
                        Some(val) => (Some(val), vec![]),
                        None => {
                            self.network
                                .overlay
                                .lookup_content(content_key.clone())
                                .await
                        }
                    };
                    let content = content.unwrap_or_default();
                    let response = match is_trace {
                        true => {
                            let closest_nodes: Vec<Value> = closest_nodes
                                .iter()
                                // Skip over enrs that are unable to be looked up
                                .filter_map(|node_id| {
                                    let content_id = content_key.content_id();
                                    // Return None for enrs that cannot be looked up
                                    match self.network.overlay.discovery.find_enr(node_id) {
                                        Some(enr) => {
                                            XorMetric::distance(&content_id, &enr.node_id().raw())
                                                .log2()
                                                .map(|distance| {
                                                    json!({
                                                        "enr": enr,
                                                        "distance": distance
                                                    })
                                                })
                                        }
                                        None => None,
                                    }
                                })
                                .collect();
                            Ok(json!({
                                "content": hex_encode(content),
                                "route": closest_nodes,
                            }))
                        }
                        false => Ok(Value::String(hex_encode(content))),
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
