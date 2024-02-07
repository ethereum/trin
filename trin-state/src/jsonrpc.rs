use std::sync::Arc;

use discv5::{enr::NodeId, Enr};
use portalnet::overlay_service::OverlayRequestError;
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::network::StateNetwork;
use ethportal_api::{
    jsonrpsee::core::Serialize,
    types::{
        distance::Distance,
        jsonrpc::{endpoints::StateEndpoint, request::StateJsonRpcRequest},
        portal::{FindNodesInfo, PongInfo},
    },
};

/// Handles State network JSON-RPC requests
pub struct StateRequestHandler {
    pub network: Arc<StateNetwork>,
    pub state_rx: mpsc::UnboundedReceiver<StateJsonRpcRequest>,
}

impl StateRequestHandler {
    pub async fn handle_client_queries(mut self) {
        while let Some(request) = self.state_rx.recv().await {
            let network = Arc::clone(&self.network);
            tokio::spawn(async move { Self::handle_request(network, request).await });
        }
    }

    async fn handle_request(network: Arc<StateNetwork>, request: StateJsonRpcRequest) {
        let response: Result<Value, String> = match request.endpoint {
            StateEndpoint::RoutingTableInfo => routing_table_info(network),
            StateEndpoint::Ping(enr) => ping(network, enr).await,
            StateEndpoint::AddEnr(enr) => add_enr(network, enr),
            StateEndpoint::DeleteEnr(node_id) => delete_enr(network, node_id),
            StateEndpoint::GetEnr(node_id) => get_enr(network, node_id),
            StateEndpoint::LookupEnr(node_id) => lookup_enr(network, node_id).await,
            StateEndpoint::FindNodes(enr, distances) => find_nodes(network, enr, distances).await,
            StateEndpoint::RecursiveFindNodes(node_id) => {
                recursive_find_nodes(network, node_id).await
            }
            StateEndpoint::DataRadius => radius(network),
            _ => Err("Not implemented".to_string()),
        };

        let _ = request.resp.send(response);
    }
}

fn routing_table_info(network: Arc<StateNetwork>) -> Result<Value, String> {
    serde_json::to_value(network.overlay.routing_table_info()).map_err(|err| err.to_string())
}

async fn ping(network: Arc<StateNetwork>, enr: Enr) -> Result<Value, String> {
    to_json_result(
        "Ping",
        network.overlay.send_ping(enr).await.map(|pong| PongInfo {
            enr_seq: pong.enr_seq as u32,
            data_radius: *Distance::from(pong.custom_payload),
        }),
    )
}

fn add_enr(network: Arc<StateNetwork>, enr: Enr) -> Result<Value, String> {
    to_json_result("AddEnr", network.overlay.add_enr(enr).map(|_| true))
}

fn delete_enr(network: Arc<StateNetwork>, node_id: NodeId) -> Result<Value, String> {
    let is_deleted = network.overlay.delete_enr(node_id);
    Ok(json!(is_deleted))
}

fn get_enr(network: Arc<StateNetwork>, node_id: NodeId) -> Result<Value, String> {
    to_json_result("GetEnr", network.overlay.get_enr(node_id))
}

async fn lookup_enr(network: Arc<StateNetwork>, node_id: NodeId) -> Result<Value, String> {
    to_json_result("LookupEnr", network.overlay.lookup_enr(node_id).await)
}

fn radius(network: Arc<StateNetwork>) -> Result<Value, String> {
    let radius = network.overlay.data_radius();
    Ok(json!(*radius))
}

async fn find_nodes(
    network: Arc<StateNetwork>,
    enr: Enr,
    distances: Vec<u16>,
) -> Result<Value, String> {
    to_json_result(
        "FindNodes",
        network
            .overlay
            .send_find_nodes(enr, distances)
            .await
            .map(|nodes| {
                nodes
                    .enrs
                    .into_iter()
                    .map(Enr::from)
                    .collect::<FindNodesInfo>()
            }),
    )
}

async fn recursive_find_nodes(
    network: Arc<StateNetwork>,
    node_id: NodeId,
) -> Result<Value, String> {
    let nodes = network.overlay.lookup_node(node_id).await;
    Ok(json!(nodes))
}

fn to_json_result(
    request: &str,
    result: Result<impl Serialize, OverlayRequestError>,
) -> Result<Value, String> {
    result
        .map(|value| json!(value))
        .map_err(|err| format!("{request} failed: {err:?}"))
}
