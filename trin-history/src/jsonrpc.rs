use std::sync::Arc;

use serde_json::{json, Value};
use tokio::sync::mpsc;
use tracing::error;
use trin_types::constants::CONTENT_ABSENT;

use crate::network::HistoryNetwork;
use portalnet::storage::ContentStore;
use trin_utils::bytes::hex_encode;

use crate::utils::bucket_entries_to_json;
use ethportal_api::types::portal::{
    AcceptInfo, Distance, FindNodesInfo, NodeInfo, PongInfo, TraceContentInfo,
};
use ethportal_api::ContentValue;
use ethportal_api::{HistoryContentKey, OverlayContentKey};
use ssz::Encode;
use trin_types::content_key::RawContentKey;
use trin_types::distance::{Metric, XorMetric};
use trin_types::enr::Enr;
use trin_types::jsonrpc::endpoints::HistoryEndpoint;
use trin_types::jsonrpc::request::HistoryJsonRpcRequest;

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
                    let response =
                        match &self.network.overlay.store.read().get(&content_key)
                        {
                            Ok(val) => match val {
                                Some(val) => {
                                    Ok(Value::String(hex_encode(val.clone())))
                                }
                                None => {
                                    Ok(Value::String(CONTENT_ABSENT.to_string()))
                                }
                            },
                            Err(err) => Err(format!(
                                "Database error while looking for content key in local storage: {content_key:?}, with error: {err}",
                            )),
                        };
                    let _ = request.resp.send(response);
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
                HistoryEndpoint::Store(content_key, content_value) => {
                    let data = content_value.encode();
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
                HistoryEndpoint::RecursiveFindContent(content_key) => {
                    let response = self.recursive_find_content(content_key, false).await;
                    let _ = request.resp.send(response);
                }
                HistoryEndpoint::TraceRecursiveFindContent(content_key) => {
                    let response = self.recursive_find_content(content_key, true).await;
                    let _ = request.resp.send(response);
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
                HistoryEndpoint::Gossip(content_key, content_value) => {
                    let data = content_value.encode();
                    let content_values = vec![(content_key, data)];
                    let num_peers = self.network.overlay.propagate_gossip(content_values);
                    let response = Ok(num_peers.into());
                    let _ = request.resp.send(response);
                }
                HistoryEndpoint::Offer(enr, content_key, content_value) => {
                    let response = if let Some(content_value) = content_value {
                        let content_value = content_value.encode();
                        match self
                            .network
                            .overlay
                            .send_populated_offer(enr, content_key.into(), content_value)
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
        // Get data from peer
        let (possible_content_bytes, closest_nodes) = match local_content {
            Some(val) => (Some(val), vec![]),
            None => {
                self.network
                    .overlay
                    .lookup_content(content_key.clone())
                    .await
            }
        };

        // Format as string.
        let content_response_string = match possible_content_bytes {
            Some(bytes) => Value::String(hex_encode(bytes)),
            None => Value::String(CONTENT_ABSENT.to_string()), // "0x"
        };

        // If tracing is not required, return content.
        if !is_trace {
            return Ok(content_response_string);
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

        Ok(json!(TraceContentInfo {
            content: serde_json::from_value(content_response_string).map_err(|e| e.to_string())?,
            route: closest_nodes,
        }))
    }
}
