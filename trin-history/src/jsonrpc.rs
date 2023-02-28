use anyhow::anyhow;
use std::sync::Arc;

use serde_json::{json, Value};
use tokio::sync::mpsc;
use tracing::error;

use crate::network::HistoryNetwork;
use trin_core::{
    jsonrpc::utils::bucket_entries_to_json,
    portalnet::{
        storage::ContentStore,
        types::{
            content_key::{HistoryContentKey, OverlayContentKey},
            distance::{Metric, XorMetric},
        },
    },
    utils::bytes::hex_encode,
};

use ethportal_api::types::discv5::Enr;
use ethportal_api::types::portal::{
    AcceptInfo, Distance, FindNodesInfo, NodeInfo, PongInfo, TraceContentInfo,
};
use ethportal_api::HistoryContentKey as EthHistoryContentKey;
use ethportal_api::{ContentItem, HistoryContentItem};
use ssz::Encode;
use trin_core::jsonrpc::endpoints::HistoryEndpoint;
use trin_core::jsonrpc::types::HistoryJsonRpcRequest;
use trin_core::portalnet::types::content_key::RawContentKey;

/// Handles History network JSON-RPC requests
pub struct HistoryRequestHandler {
    pub network: Arc<HistoryNetwork>,
    pub history_rx: mpsc::UnboundedReceiver<HistoryJsonRpcRequest>,
}

impl HistoryRequestHandler {
    pub async fn handle_client_queries(mut self) {
        while let Some(request) = self.history_rx.recv().await {
            match request.endpoint {
                HistoryEndpoint::LocalContent(content_key) => {
                    match convert_content_key(&content_key) {
                        Ok(content_key) => {
                            let response =
                                match &self.network.overlay.store.read().get(&content_key)
                                {
                                    Ok(val) => match val {
                                        Some(val) => {
                                            Ok(Value::String(hex_encode(val.clone())))
                                        }
                                        None => {
                                            Ok(Value::Null)
                                        }
                                    },
                                    Err(err) => Err(format!(
                                        "Database error while looking for content key in local storage: {content_key:?}, with error: {err}",
                                    )),
                                };
                            let _ = request.resp.send(response);
                        }
                        Err(_) => {
                            let _ = request
                                .resp
                                .send(Err("Invalid content key provided".to_owned()));
                        }
                    }
                }
                HistoryEndpoint::PaginateLocalContentKeys(offset, limit) => {
                    let response =
                            match &self.network.overlay.store.read().paginate(&offset, &limit)
                                {
                                    Ok(val) => Ok(json!(val)),
                                    Err(err) => Err(format!(
                                        "Database error while paginating local content keys with offset: {offset:?}, limit: {limit:?}. Error message: {err}"
                                    )),
                                };
                    let _ = request.resp.send(response);
                }
                HistoryEndpoint::Store(content_key, content_item) => {
                    match convert_content_key(&content_key) {
                        Ok(content_key) => {
                            let mut data = vec![];
                            content_item.encode(&mut data);
                            let response = match self
                                .network
                                .overlay
                                .store
                                .write()
                                .put::<HistoryContentKey, Vec<u8>>(content_key, data)
                            {
                                Ok(_) => Ok(Value::Bool(true)),
                                Err(msg) => Ok(Value::String(msg.to_string())),
                            };
                            let _ = request.resp.send(response);
                        }
                        Err(_) => {
                            let _ = request
                                .resp
                                .send(Err("Invalid content key provided".to_owned()));
                        }
                    }
                }
                HistoryEndpoint::RecursiveFindContent(content_key) => {
                    match convert_content_key(&content_key) {
                        Ok(content_key) => {
                            let response = self.recursive_find_content(content_key, false).await;
                            let _ = request.resp.send(response);
                        }
                        Err(_) => {
                            let _ = request
                                .resp
                                .send(Err("Invalid content key provided".to_owned()));
                        }
                    }
                }
                HistoryEndpoint::TraceRecursiveFindContent(content_key) => {
                    match convert_content_key(&content_key) {
                        Ok(content_key) => {
                            let response = self.recursive_find_content(content_key, true).await;
                            let _ = request.resp.send(response);
                        }
                        Err(_) => {
                            let _ = request
                                .resp
                                .send(Err("Invalid content key provided".to_owned()));
                        }
                    }
                }
                HistoryEndpoint::DataRadius => {
                    let radius = &self.network.overlay.data_radius();
                    let response = Ok(json!(**radius));
                    let _ = request.resp.send(response);
                }
                HistoryEndpoint::FindContent(enr, content_key) => {
                    let response = match self
                        .network
                        .overlay
                        .send_find_content(enr, content_key.into())
                        .await
                    {
                        Ok(content) => match content.try_into() {
                            Ok(val) => Ok(val),
                            Err(_) => Err("Content response decoding error".to_string()),
                        },
                        Err(msg) => Err(format!("FindContent request timeout: {msg:?}")),
                    };
                    let _ = request.resp.send(response);
                }
                HistoryEndpoint::FindNodes(enr, distances) => {
                    let response = match self.network.overlay.send_find_nodes(enr, distances).await
                    {
                        Ok(nodes) => Ok(json!(FindNodesInfo {
                            total: nodes.total,
                            enrs: nodes
                                .enrs
                                .into_iter()
                                .map(|enr| enr.into())
                                .collect::<Vec<Enr>>(),
                        })),
                        Err(msg) => Err(format!("FindNodes request timeout: {msg:?}")),
                    };
                    let _ = request.resp.send(response);
                }
                HistoryEndpoint::Gossip(content_key, content_item) => {
                    match convert_content_key(&content_key) {
                        Ok(content_key) => {
                            let mut data = vec![];
                            content_item.encode(&mut data);
                            let content_items = vec![(content_key, data)];
                            let num_peers = self.network.overlay.propagate_gossip(content_items);
                            let response = Ok(num_peers.into());
                            let _ = request.resp.send(response);
                        }
                        Err(_) => {
                            let response = Err("Invalid content key provided".to_owned());
                            let _ = request.resp.send(response);
                        }
                    }
                }
                HistoryEndpoint::Offer(enr, content_key, content_value) => {
                    let response = if let Some(content_value) = content_value {
                        let mut content_item = vec![];
                        content_value.encode(&mut content_item);
                        match self
                            .network
                            .overlay
                            .send_populated_offer(enr, content_key.into(), content_item)
                            .await
                        {
                            Ok(accept) => Ok(json!(AcceptInfo {
                                content_keys: accept.content_keys,
                            })),
                            Err(msg) => Err(format!("Populated Offer request timeout: {msg:?}")),
                        }
                    } else {
                        let content_key: Vec<RawContentKey> = vec![content_key.as_ssz_bytes()];

                        match self.network.overlay.send_offer(content_key, enr).await {
                            Ok(accept) => Ok(json!(AcceptInfo {
                                content_keys: accept.content_keys,
                            })),
                            Err(msg) => Err(format!("Offer request timeout: {msg:?}")),
                        }
                    };

                    let _ = request.resp.send(response);
                }
                HistoryEndpoint::Ping(enr, _) => {
                    let response = match self.network.overlay.send_ping(enr).await {
                        Ok(pong) => Ok(json!(PongInfo {
                            enr_seq: pong.enr_seq as u32,
                            data_radius: *self.network.overlay.data_radius(),
                        })),
                        Err(msg) => Err(format!("Ping request timeout: {msg:?}")),
                    };

                    let _ = request.resp.send(response);
                }
                HistoryEndpoint::RoutingTableInfo => {
                    let response = Ok(bucket_entries_to_json(
                        self.network.overlay.bucket_entries(),
                    ));

                    let _ = request.resp.send(response);
                }
            }
        }
    }

    async fn recursive_find_content(
        &mut self,
        content_key: HistoryContentKey,
        is_trace: bool,
    ) -> Result<Value, String> {
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

        if !is_trace {
            return Ok(Value::String(hex::encode(content)));
        }

        // Construct trace response
        let closest_nodes: Vec<NodeInfo> = closest_nodes
            .iter()
            // Skip over enrs that are unable to be looked up
            .filter_map(|node_id| {
                let content_id = content_key.content_id();
                // Return None for enrs that cannot be looked up
                match self.network.overlay.discovery.find_enr(node_id) {
                    Some(enr) => XorMetric::distance(&content_id, &enr.node_id().raw())
                        .log2()
                        .map(|distance| {
                            let distance = Distance::from(distance);
                            NodeInfo { enr, distance }
                        }),
                    None => None,
                }
            })
            .collect();

        let content = match HistoryContentItem::decode(&content) {
            Ok(val) => val,
            Err(err) => {
                return Err(format!(
                    "Error decoding content item: {content:?} with error: {err:?}"
                ))
            }
        };
        Ok(json!(TraceContentInfo {
            content,
            route: closest_nodes,
        }))
    }
}

// TODO: Remove this helper method when replacing content key and enr type with ethportal-api.
// Helper method to convert ethportal-api content keys to trin content keys.
fn convert_content_key(content_key: &EthHistoryContentKey) -> anyhow::Result<HistoryContentKey> {
    HistoryContentKey::try_from(content_key.as_ssz_bytes()).map_err(|err| anyhow!(err))
}
