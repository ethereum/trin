use log::info;
use std::sync::Arc;
use tokio::{sync::mpsc, task::JoinHandle};

use crate::{events::StateEvents, jsonrpc::StateRequestHandler};
use discv5::TalkRequest;
use network::StateNetwork;
use tokio::sync::mpsc::UnboundedSender;
use trin_core::{
    jsonrpc::types::StateJsonRpcRequest,
    portalnet::{
        discovery::Discovery, storage::PortalStorageConfig, types::messages::PortalnetConfig,
    },
    utp::stream::{UtpListenerEvent, UtpListenerRequest},
};

pub mod events;
mod jsonrpc;
pub mod network;
mod trie;
pub mod utils;
pub mod validation;

type StateHandler = Option<StateRequestHandler>;
type StateNetworkTask = Option<JoinHandle<()>>;
type StateEventTx = Option<mpsc::UnboundedSender<TalkRequest>>;
type StateUtpTx = Option<mpsc::UnboundedSender<UtpListenerEvent>>;
type StateJsonRpcTx = Option<mpsc::UnboundedSender<StateJsonRpcRequest>>;

pub async fn initialize_state_network(
    discovery: &Arc<Discovery>,
    utp_listener_tx: UnboundedSender<UtpListenerRequest>,
    portalnet_config: PortalnetConfig,
    storage_config: PortalStorageConfig,
) -> (
    StateHandler,
    StateNetworkTask,
    StateEventTx,
    StateUtpTx,
    StateJsonRpcTx,
) {
    let (state_jsonrpc_tx, state_jsonrpc_rx) = mpsc::unbounded_channel::<StateJsonRpcRequest>();
    let (state_event_tx, state_event_rx) = mpsc::unbounded_channel::<TalkRequest>();
    let (utp_state_tx, utp_state_rx) = mpsc::unbounded_channel::<UtpListenerEvent>();
    let state_network = StateNetwork::new(
        Arc::clone(discovery),
        utp_listener_tx,
        storage_config,
        portalnet_config.clone(),
    )
    .await;
    let state_network = Arc::new(state_network);
    let state_handler = StateRequestHandler {
        network: Arc::clone(&state_network),
        state_rx: state_jsonrpc_rx,
    };
    let state_network_task = spawn_state_network(
        Arc::clone(&state_network),
        portalnet_config,
        utp_state_rx,
        state_event_rx,
    );
    (
        Some(state_handler),
        Some(state_network_task),
        Some(state_event_tx),
        Some(utp_state_tx),
        Some(state_jsonrpc_tx),
    )
}

pub fn spawn_state_network(
    network: Arc<StateNetwork>,
    portalnet_config: PortalnetConfig,
    utp_listener_rx: mpsc::UnboundedReceiver<UtpListenerEvent>,
    state_event_rx: mpsc::UnboundedReceiver<TalkRequest>,
) -> JoinHandle<()> {
    info!(
        "About to spawn State Network with boot nodes: {:?}",
        portalnet_config.bootnode_enrs
    );

    tokio::spawn(async move {
        let state_events = StateEvents {
            network: Arc::clone(&network),
            event_rx: state_event_rx,
            utp_listener_rx,
        };

        // Spawn state event handler
        tokio::spawn(state_events.start());

        // hacky test: make sure we establish a session with the boot node
        network.ping_bootnodes().await.unwrap();

        tokio::signal::ctrl_c()
            .await
            .expect("failed to pause until ctrl-c");
    })
}
