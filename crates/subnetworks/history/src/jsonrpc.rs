use std::sync::Arc;

use discv5::enr::NodeId;
use ethportal_api::{
    types::{
        jsonrpc::{endpoints::HistoryEndpoint, request::HistoryJsonRpcRequest},
        ping_extensions::decode::DecodedExtension,
        portal::{AcceptInfo, FindNodesInfo, GetContentInfo, PongInfo, TraceContentInfo},
        portal_wire::Content,
    },
    utils::bytes::hex_encode,
    ContentValue, HistoryContentKey, HistoryContentValue, OverlayContentKey,
};
use portalnet::overlay::{config::FindContentConfig, errors::OverlayRequestError};
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
        HistoryEndpoint::GetContent(content_key) => get_content(network, content_key, false).await,
        HistoryEndpoint::TraceGetContent(content_key) => {
            get_content(network, content_key, true).await
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
        HistoryEndpoint::PutContent(content_key, content_value) => {
            put_content(network, content_key, content_value).await
        }
        HistoryEndpoint::TracePutContent(content_key, content_value) => {
            trace_put_content(network, content_key, content_value).await
        }
        HistoryEndpoint::LookupEnr(node_id) => lookup_enr(network, node_id).await,
        HistoryEndpoint::Offer(enr, content_items) => offer(network, enr, content_items).await,
        HistoryEndpoint::TraceOffer(enr, content_key, content_value) => {
            trace_offer(network, enr, content_key, content_value).await
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

/// Constructs a JSON call for the GetContent method.
async fn get_content(
    network: Arc<HistoryNetwork>,
    content_key: HistoryContentKey,
    is_trace: bool,
) -> Result<Value, String> {
    // local store data lookups are handled at the overlay service level
    let (content_bytes, utp_transfer, trace) = match network
        .overlay
        .lookup_content(
            content_key.clone(),
            FindContentConfig {
                is_trace,
                ..Default::default()
            },
        )
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
    };

    // Format as string.
    let content_response_string = Value::String(hex_encode(content_bytes));
    let content = serde_json::from_value(content_response_string).map_err(|e| e.to_string())?;

    // Return the content info, including the trace if requested.
    if is_trace {
        Ok(json!(TraceContentInfo {
            content,
            utp_transfer,
            trace: trace.ok_or("Content query trace requested but none provided.".to_string())?,
        }))
    } else {
        Ok(json!(GetContentInfo {
            content,
            utp_transfer
        }))
    }
}

/// Constructs a JSON call for the LocalContent method.
async fn local_content(
    network: Arc<HistoryNetwork>,
    content_key: HistoryContentKey,
) -> Result<Value, String> {
    let response = match network.overlay.store.lock().get(&content_key)
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
    let response = match network.overlay.store.lock().paginate(offset, limit)
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
    let data = content_value.encode().to_vec();
    let response = match network
        .overlay
        .store
        .lock()
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
    match network.overlay.send_find_content(enr, content_key.to_bytes()).await {
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

/// Constructs a JSON call for the PutContent method.
async fn put_content(
    network: Arc<HistoryNetwork>,
    content_key: HistoryContentKey,
    content_value: ethportal_api::HistoryContentValue,
) -> Result<Value, String> {
    let data = content_value.encode();
    Ok(json!(network
        .overlay
        .propagate_put_content(content_key, data)))
}

/// Constructs a JSON call for the PutContent method, with tracing enabled.
async fn trace_put_content(
    network: Arc<HistoryNetwork>,
    content_key: HistoryContentKey,
    content_value: ethportal_api::HistoryContentValue,
) -> Result<Value, String> {
    let data = content_value.encode();
    Ok(json!(
        network
            .overlay
            .propagate_put_content_trace(content_key, data)
            .await
    ))
}

/// Constructs a JSON call for the Offer method.
async fn offer(
    network: Arc<HistoryNetwork>,
    enr: discv5::enr::Enr<discv5::enr::CombinedKey>,
    content_items: Vec<(HistoryContentKey, HistoryContentValue)>,
) -> Result<Value, String> {
    let content_items = content_items
        .into_iter()
        .map(|(key, value)| (key.to_bytes(), value.encode()))
        .collect();
    match network.overlay.send_offer(enr, content_items).await {
        Ok(accept) => Ok(json!(AcceptInfo {
            content_keys: accept.content_keys,
        })),
        Err(msg) => Err(format!("Offer request timeout: {msg:?}")),
    }
}

/// Constructs a JSON call for the Offer method with trace.
async fn trace_offer(
    network: Arc<HistoryNetwork>,
    enr: discv5::enr::Enr<discv5::enr::CombinedKey>,
    content_key: HistoryContentKey,
    content_value: HistoryContentValue,
) -> Result<Value, String> {
    match network
        .overlay
        .send_offer_trace(enr, content_key.to_bytes(), content_value.encode())
        .await
    {
        Ok(accept) => Ok(json!(accept)),
        Err(msg) => Err(format!("Offer request timeout: {msg:?}")),
    }
}

/// Constructs a JSON call for the Ping method.
async fn ping(
    network: Arc<HistoryNetwork>,
    enr: discv5::enr::Enr<discv5::enr::CombinedKey>,
) -> Result<Value, String> {
    match network.overlay.send_ping(enr).await {
        Ok(pong) => {
            let data_radius =
                match DecodedExtension::decode_extension(pong.payload_type, pong.payload) {
                    Ok(DecodedExtension::Capabilities(capabilities)) => *capabilities.data_radius,
                    err => return Err(format!("Failed to decode capabilities: {err:?}")),
                };

            Ok(json!(PongInfo {
                enr_seq: pong.enr_seq,
                data_radius,
            }))
        }
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
