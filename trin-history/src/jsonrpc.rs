use std::sync::Arc;

use discv5::enr::NodeId;
use ethportal_api::{
    types::{
        distance::Distance,
        history::{ContentInfo, TraceContentInfo},
        jsonrpc::{endpoints::HistoryEndpoint, request::HistoryJsonRpcRequest},
        portal::{AcceptInfo, FindNodesInfo, PongInfo},
        portal_wire::Content,
        query_trace::QueryTrace,
    },
    utils::bytes::hex_encode,
    ContentValue, HistoryContentKey, OverlayContentKey, RawContentKey,
};
use portalnet::overlay::errors::OverlayRequestError;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tracing::error;
use trin_storage::ContentStore;

use crate::network::HistoryNetwork;

/// Handles History network JSON-RPC requests
pub struct HistoryRequestHandler {
    pub network: Arc<HistoryNetwork>,
    pub history_rx: mpsc::UnboundedReceiver<HistoryJsonRpcRequest>,
}

impl HistoryRequestHandler {
    /// Complete RPC requests for the History network.
    pub async fn handle_client_queries(mut self) {
        while let Some(request) = self.history_rx.recv().await {
            let network = self.network.clone();
            tokio::spawn(async move { complete_request(network, request).await });
        }
    }
}

/// Generates a response for a given request and sends it to the receiver.
async fn complete_request(network: Arc<HistoryNetwork>, request: HistoryJsonRpcRequest) {
    let response: Result<Value, String> = match request.endpoint {
        HistoryEndpoint::LocalContent(content_key) => local_content(network, content_key).await,
        HistoryEndpoint::PaginateLocalContentKeys(offset, limit) => {
            paginate_local_content_keys(network, offset, limit).await
        }
        HistoryEndpoint::Store(content_key, content_value) => {
            store(network, content_key, content_value).await
        }
        HistoryEndpoint::RecursiveFindContent(content_key) => {
            recursive_find_content(network, content_key, false).await
        }
        HistoryEndpoint::TraceRecursiveFindContent(content_key) => {
            recursive_find_content(network, content_key, true).await
        }
        HistoryEndpoint::AddEnr(enr) => add_enr(network, enr).await,
        HistoryEndpoint::DataRadius => {
            let radius = network.overlay.data_radius();
            Ok(json!(*radius))
        }
        HistoryEndpoint::DeleteEnr(node_id) => delete_enr(network, node_id).await,
        HistoryEndpoint::FindContent(enr, content_key) => {
            find_content(network, enr, content_key).await
        }
        HistoryEndpoint::FindNodes(enr, distances) => find_nodes(network, enr, distances).await,
        HistoryEndpoint::GetEnr(node_id) => get_enr(network, node_id).await,
        HistoryEndpoint::Gossip(content_key, content_value) => {
            gossip(network, content_key, content_value).await
        }
        HistoryEndpoint::TraceGossip(content_key, content_value) => {
            gossip_trace(network, content_key, content_value).await
        }
        HistoryEndpoint::LookupEnr(node_id) => lookup_enr(network, node_id).await,
        HistoryEndpoint::Offer(enr, content_key, content_value) => {
            offer(network, enr, content_key, content_value).await
        }
        HistoryEndpoint::Ping(enr) => ping(network, enr).await,
        HistoryEndpoint::RoutingTableInfo => {
            serde_json::to_value(network.overlay.routing_table_info())
                .map_err(|err| err.to_string())
        }
        HistoryEndpoint::RecursiveFindNodes(node_id) => {
            recursive_find_nodes(network, node_id).await
        }
    };
    let _ = request.resp.send(response);
}

/// Constructs a JSON call for the RecursiveFindContent method.
async fn recursive_find_content(
    network: Arc<HistoryNetwork>,
    content_key: HistoryContentKey,
    is_trace: bool,
) -> Result<Value, String> {
    // Check whether we have the data locally.
    let local_content: Option<Vec<u8>> = match network.overlay.store.read().get(&content_key) {
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
    let (content_bytes, utp_transfer, trace) = match local_content {
        Some(val) => {
            let local_enr = network.overlay.local_enr();
            let mut trace = QueryTrace::new(&network.overlay.local_enr(), content_key.content_id());
            trace.node_responded_with_content(&local_enr);
            (val, false, if is_trace { Some(trace) } else { None })
        }
        // data is not available locally, make network request
        None => match network
            .overlay
            .lookup_content(content_key.clone(), is_trace)
            .await
            .map_err(|err| err.to_string())?
        {
            Ok((content_bytes, utp_transfer, trace)) => (content_bytes, utp_transfer, trace),
            Err(err) => match err.clone() {
                OverlayRequestError::ContentNotFound {
                    message,
                    utp,
                    trace,
                } => {
                    let err = json!({
                        "message": format!("{message}: utp: {utp}"),
                        "trace": trace
                    });
                    return Err(err.to_string());
                }
                _ => {
                    error!(
                        error = %err,
                        content.key = %content_key,
                        "Error looking up content",
                    );
                    return Err(err.to_string());
                }
            },
        },
    };

    // Format as string.
    let content_response_string = Value::String(hex_encode(content_bytes));

    // If tracing is not required, return content.
    if !is_trace {
        return Ok(json!(ContentInfo::Content {
            content: serde_json::from_value(content_response_string).map_err(|e| e.to_string())?,
            utp_transfer,
        }));
    }
    if let Some(trace) = trace {
        Ok(json!(TraceContentInfo {
            content: serde_json::from_value(content_response_string).map_err(|e| e.to_string())?,
            utp_transfer,
            trace,
        }))
    } else {
        Err("Content query trace requested but none provided.".to_owned())
    }
}

/// Constructs a JSON call for the LocalContent method.
async fn local_content(
    network: Arc<HistoryNetwork>,
    content_key: HistoryContentKey,
) -> Result<Value, String> {
    let response = match network.overlay.store.read().get(&content_key)
        {
            Ok(val) => match val {
                Some(val) => {
                    Ok(Value::String(hex_encode(val)))
                }
                None => {
                    let err = json!({
                        "message": "Content not found in local storage",
                    });
                    return Err(err.to_string());
                }
            },
            Err(err) => Err(format!(
                "Database error while looking for content key in local storage: {content_key:?}, with error: {err}",
            )),
        };
    response
}

/// Constructs a JSON call for the PaginateLocalContentKeys method.
async fn paginate_local_content_keys(
    network: Arc<HistoryNetwork>,
    offset: u64,
    limit: u64,
) -> Result<Value, String> {
    let response = match network.overlay.store.read().paginate(offset, limit)
        {
            Ok(val) => Ok(json!(val)),
            Err(err) => Err(format!(
                "Database error while paginating local content keys with offset: {offset:?}, limit: {limit:?}. Error message: {err}"
            )),
        };
    response
}

/// Constructs a JSON call for the Store method.
async fn store(
    network: Arc<HistoryNetwork>,
    content_key: HistoryContentKey,
    content_value: ethportal_api::HistoryContentValue,
) -> Result<Value, String> {
    let data = content_value.encode();
    let response = match network
        .overlay
        .store
        .write()
        .put::<Vec<u8>>(content_key, data)
    {
        Ok(_) => Ok(Value::Bool(true)),
        Err(err) => Ok(Value::String(err.to_string())),
    };
    response
}

/// Constructs a JSON call for the AddEnr method.
async fn add_enr(
    network: Arc<HistoryNetwork>,
    enr: discv5::enr::Enr<discv5::enr::CombinedKey>,
) -> Result<Value, String> {
    match network.overlay.add_enr(enr) {
        Ok(_) => Ok(json!(true)),
        Err(err) => Err(format!("AddEnr failed: {err:?}")),
    }
}

/// Constructs a JSON call for the GetEnr method.
async fn get_enr(network: Arc<HistoryNetwork>, node_id: NodeId) -> Result<Value, String> {
    match network.overlay.get_enr(node_id) {
        Ok(enr) => Ok(json!(enr)),
        Err(err) => Err(format!("GetEnr failed: {err:?}")),
    }
}

/// Constructs a JSON call for the deleteEnr method.
async fn delete_enr(network: Arc<HistoryNetwork>, node_id: NodeId) -> Result<Value, String> {
    let is_deleted = network.overlay.delete_enr(node_id);
    Ok(json!(is_deleted))
}

/// Constructs a JSON call for the LookupEnr method.
async fn lookup_enr(network: Arc<HistoryNetwork>, node_id: NodeId) -> Result<Value, String> {
    match network.overlay.lookup_enr(node_id).await {
        Ok(enr) => Ok(json!(enr)),
        Err(err) => Err(format!("LookupEnr failed: {err:?}")),
    }
}

/// Constructs a JSON call for the FindContent method.
async fn find_content(
    network: Arc<HistoryNetwork>,
    enr: discv5::enr::Enr<discv5::enr::CombinedKey>,
    content_key: HistoryContentKey,
) -> Result<Value, String> {
    match network.overlay.send_find_content(enr, content_key.into()).await {
        Ok((content, utp_transfer)) => match content {
            Content::ConnectionId(id) => Err(format!(
                "FindContent request returned a connection id ({id:?}) instead of conducting utp transfer."
            )),
            Content::Content(content) => Ok(json!({
                "content": hex_encode(content),
                "utpTransfer": utp_transfer,
            })),
            Content::Enrs(enrs) => Ok(json!({
                "enrs": enrs,
            })),
        },
        Err(msg) => Err(format!("FindContent request timeout: {msg:?}")),
    }
}

/// Constructs a JSON call for the FindNodes method.
async fn find_nodes(
    network: Arc<HistoryNetwork>,
    enr: discv5::enr::Enr<discv5::enr::CombinedKey>,
    distances: Vec<u16>,
) -> Result<Value, String> {
    match network.overlay.send_find_nodes(enr, distances).await {
        Ok(nodes) => Ok(json!(nodes
            .enrs
            .into_iter()
            .map(|enr| enr.into())
            .collect::<FindNodesInfo>())),
        Err(msg) => Err(format!("FindNodes request timeout: {msg:?}")),
    }
}

/// Constructs a JSON call for the Gossip method.
async fn gossip(
    network: Arc<HistoryNetwork>,
    content_key: HistoryContentKey,
    content_value: ethportal_api::HistoryContentValue,
) -> Result<Value, String> {
    let data = content_value.encode();
    Ok(network
        .overlay
        .propagate_gossip(vec![(content_key, data)])
        .into())
}

/// Constructs a JSON call for the Gossip method, with tracing enabled.
async fn gossip_trace(
    network: Arc<HistoryNetwork>,
    content_key: HistoryContentKey,
    content_value: ethportal_api::HistoryContentValue,
) -> Result<Value, String> {
    let data = content_value.encode();
    Ok(json!(
        network
            .overlay
            .propagate_gossip_trace(content_key, data)
            .await
    ))
}

/// Constructs a JSON call for the Offer method.
async fn offer(
    network: Arc<HistoryNetwork>,
    enr: discv5::enr::Enr<discv5::enr::CombinedKey>,
    content_key: HistoryContentKey,
    content_value: Option<ethportal_api::HistoryContentValue>,
) -> Result<Value, String> {
    if let Some(content_value) = content_value {
        let content_value = content_value.encode();
        match network
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
        let content_key: Vec<RawContentKey> = vec![content_key.to_bytes()];
        match network.overlay.send_offer(content_key, enr).await {
            Ok(accept) => Ok(json!(AcceptInfo {
                content_keys: accept.content_keys,
            })),
            Err(msg) => Err(format!("Offer request timeout: {msg:?}")),
        }
    }
}

/// Constructs a JSON call for the Ping method.
async fn ping(
    network: Arc<HistoryNetwork>,
    enr: discv5::enr::Enr<discv5::enr::CombinedKey>,
) -> Result<Value, String> {
    match network.overlay.send_ping(enr).await {
        Ok(pong) => Ok(json!(PongInfo {
            enr_seq: pong.enr_seq,
            data_radius: *Distance::from(pong.custom_payload),
        })),
        Err(msg) => Err(format!("Ping request timeout: {msg:?}")),
    }
}

/// Constructs a JSON call for the RecursiveFindNodes method.
async fn recursive_find_nodes(
    network: Arc<HistoryNetwork>,
    node_id: NodeId,
) -> Result<Value, String> {
    let nodes = network.overlay.lookup_node(node_id).await;
    Ok(json!(nodes))
}
