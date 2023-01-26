use anyhow::anyhow;
use std::str::FromStr;
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

use discv5::Enr;
use ethportal_api::types::discv5::Enr as EthEnr;
use ethportal_api::types::portal::Distance;
use ethportal_api::HistoryContentKey as EthHistoryContentKey;
use ssz::Encode;
use trin_core::jsonrpc::endpoints::HistoryEndpoint;
use trin_core::jsonrpc::types::HistoryJsonRpcRequest;

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
                                        Some(val) => Ok(Value::String(hex_encode(val.clone()))),
                                        None => Ok(Value::String("0x0".to_string())),
                                    },
                                    Err(err) => Err(format!(
                                        "Database error while looking for content key in local storage: {:?}, with error: {}",

                                        content_key, err
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
                                        "Database error while paginating local content keys with offset: {:?}, limit: {:?}. Error message: {}",
                                        offset, limit, err
                                    )),
                                };
                    let _ = request.resp.send(response);
                }
                HistoryEndpoint::Store(content_key, content_item) => {
                    match convert_content_key(&content_key) {
                        Ok(content_key) => {
                            let response = {
                                match self
                                    .network
                                    .overlay
                                    .store
                                    .write()
                                    .put::<HistoryContentKey, Vec<u8>>(
                                        content_key,
                                        content_item.into(),
                                    ) {
                                    Ok(_) => Ok(Value::Bool(true)),
                                    Err(msg) => Ok(Value::String(msg.to_string())),
                                }
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
                            let is_trace = false;

                            let response = self.recursive_find_content(content_key, is_trace).await;
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
                            let is_trace = true;

                            let response = self.recursive_find_content(content_key, is_trace).await;
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
                    let radius = &self.network.overlay.data_radius;
                    let _ = request.resp.send(Ok(Value::String(radius.to_string())));
                }
                HistoryEndpoint::FindContent(enr, content_key) => {
                    let enr = convert_enr(enr);

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
                        Err(msg) => Err(format!("FindContent request timeout: {:?}", msg)),
                    };
                    let _ = request.resp.send(response);
                }
                HistoryEndpoint::FindNodes(enr, distances) => {
                    let enr = convert_enr(enr);

                    let response = match self.network.overlay.send_find_nodes(enr, distances).await
                    {
                        Ok(nodes) => Ok(nodes.into()),
                        Err(msg) => Err(format!("FindNodes request timeout: {:?}", msg)),
                    };
                    let _ = request.resp.send(response);
                }
                HistoryEndpoint::Offer(content_key, content_item) => {
                    match convert_content_key(&content_key) {
                        Ok(content_key) => {
                            let response = {
                                let content_items = vec![(content_key, content_item.into())];
                                let num_peers =
                                    self.network.overlay.propagate_gossip(content_items);
                                Ok(num_peers.into())
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
                HistoryEndpoint::SendOffer(enr, content_keys) => {
                    let enr = convert_enr(enr);

                    let response = {
                        let content_keys =
                            content_keys.iter().map(|key| key.as_ssz_bytes()).collect();

                        match self.network.overlay.send_offer(content_keys, enr).await {
                            Ok(accept) => Ok(json!({
                                "connectionId": accept.connection_id,
                                "contentKeys": accept.content_keys
                            })),
                            Err(msg) => Err(format!("SendOffer request timeout: {:?}", msg)),
                        }
                    };
                    let _ = request.resp.send(response);
                }
                HistoryEndpoint::Ping(enr, _) => {
                    let enr = convert_enr(enr);
                    let response = match self.network.overlay.send_ping(enr).await {
                        Ok(pong) => Ok(json!({
                            "enrSeq": pong.enr_seq,
                            "dataRadius": *self.network.overlay.data_radius()
                        })),
                        Err(msg) => Err(format!("Ping request timeout: {:?}", msg)),
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
        let response = match is_trace {
            true => {
                let closest_nodes: Vec<Value> = closest_nodes
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
                                    json!({
                                        "enr": enr,
                                        "distance": distance
                                    })
                                }),
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
        response
    }
}

// TODO: Remove this helper method when replacing content key and enr type with ethportal-api.
// Helper method to convert ethportal-api content keys to trin content keys.
fn convert_content_key(content_key: &EthHistoryContentKey) -> anyhow::Result<HistoryContentKey> {
    HistoryContentKey::try_from(content_key.as_ssz_bytes()).map_err(|err| anyhow!(err))
}

// TODO: Remove this helper method when replacing content key and enr type with ethportal-api.
// Helper method to convert ethportal-api content keys to trin content keys.
fn convert_enr(enr: EthEnr) -> Enr {
    let enr = enr.to_base64();
    Enr::from_str(&enr).unwrap()
}
