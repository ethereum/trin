#![warn(clippy::unwrap_used)]
#![warn(clippy::uninlined_format_args)]

use std::sync::Arc;

use network::StateNetwork;
use tokio::{
    sync::{broadcast, mpsc, RwLock},
    task::JoinHandle,
};
use tracing::info;
use utp_rs::socket::UtpSocket;

use crate::{events::StateEvents, jsonrpc::StateRequestHandler};
use ethportal_api::types::{enr::Enr, jsonrpc::request::StateJsonRpcRequest};
use portalnet::{
    config::PortalnetConfig,
    discovery::{Discovery, UtpEnr},
    events::{EventEnvelope, OverlayRequest},
    storage::PortalStorageConfig,
};
use trin_validation::oracle::HeaderOracle;

pub mod events;
mod jsonrpc;
pub mod network;
mod trie;
pub mod utils;
pub mod validation;

type StateHandler = Option<StateRequestHandler>;
type StateNetworkTask = Option<JoinHandle<()>>;
type StateEventTx = Option<mpsc::UnboundedSender<OverlayRequest>>;
type StateJsonRpcTx = Option<mpsc::UnboundedSender<StateJsonRpcRequest>>;
type StateEventStream = Option<broadcast::Receiver<EventEnvelope>>;

pub async fn initialize_state_network(
    discovery: &Arc<Discovery>,
    utp_socket: Arc<UtpSocket<UtpEnr>>,
    portalnet_config: PortalnetConfig,
    storage_config: PortalStorageConfig,
    header_oracle: Arc<RwLock<HeaderOracle>>,
) -> anyhow::Result<(
    StateHandler,
    StateNetworkTask,
    StateEventTx,
    StateJsonRpcTx,
    StateEventStream,
)> {
    let (state_jsonrpc_tx, state_jsonrpc_rx) = mpsc::unbounded_channel::<StateJsonRpcRequest>();
    let (state_event_tx, state_event_rx) = mpsc::unbounded_channel::<OverlayRequest>();
    let state_network = StateNetwork::new(
        Arc::clone(discovery),
        utp_socket,
        storage_config,
        portalnet_config.clone(),
        header_oracle,
    )
    .await?;
    let state_network = Arc::new(state_network);
    let state_event_stream = state_network.overlay.event_stream().await?;
    let state_handler = StateRequestHandler {
        network: Arc::clone(&state_network),
        state_rx: state_jsonrpc_rx,
    };
    let state_network_task =
        spawn_state_network(Arc::clone(&state_network), portalnet_config, state_event_rx);
    Ok((
        Some(state_handler),
        Some(state_network_task),
        Some(state_event_tx),
        Some(state_jsonrpc_tx),
        Some(state_event_stream),
    ))
}

pub fn spawn_state_network(
    network: Arc<StateNetwork>,
    portalnet_config: PortalnetConfig,
    state_message_rx: mpsc::UnboundedReceiver<OverlayRequest>,
) -> JoinHandle<()> {
    let bootnode_enrs: Vec<Enr> = portalnet_config.bootnodes.into();
    info!(
        "About to spawn State Network with {} boot nodes.",
        bootnode_enrs.len()
    );

    tokio::spawn(async move {
        let state_events = StateEvents {
            network: Arc::clone(&network),
            message_rx: state_message_rx,
        };

        // Spawn state event handler
        tokio::spawn(state_events.start());

        // hacky test: make sure we establish a session with the boot node
        network.overlay.ping_bootnodes().await;

        tokio::signal::ctrl_c()
            .await
            .expect("failed to pause until ctrl-c");
    })
}
