use std::sync::Arc;

use discv5::TalkRequest;
use network::StateNetwork;
use tokio::{
    sync::{mpsc, mpsc::UnboundedSender, RwLock},
    task::JoinHandle,
};
use tracing::info;

use crate::{events::StateEvents, jsonrpc::StateRequestHandler};
use trin_core::{
    jsonrpc::types::StateJsonRpcRequest,
    portalnet::{
        discovery::Discovery, storage::PortalStorageConfig, types::messages::PortalnetConfig,
    },
    types::oracle::HeaderOracle,
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

pub async fn initialize_state_network(
    discovery: &Arc<Discovery>,
    utp_listener_tx: UnboundedSender<UtpListenerRequest>,
    portalnet_config: PortalnetConfig,
    storage_config: PortalStorageConfig,
    header_oracle: Arc<RwLock<HeaderOracle>>,
) -> (StateHandler, StateNetworkTask, StateEventTx, StateUtpTx) {
    let (state_jsonrpc_tx, state_jsonrpc_rx) = mpsc::unbounded_channel::<StateJsonRpcRequest>();
    let _ = header_oracle
        .write()
        .await
        .network_bus
        .set_state_tx(state_jsonrpc_tx.clone());
    let (state_event_tx, state_event_rx) = mpsc::unbounded_channel::<TalkRequest>();
    let (utp_state_tx, utp_state_rx) = mpsc::unbounded_channel::<UtpListenerEvent>();
    let state_network = StateNetwork::new(
        Arc::clone(discovery),
        utp_listener_tx,
        storage_config,
        portalnet_config.clone(),
        header_oracle,
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
    )
}

pub fn spawn_state_network(
    network: Arc<StateNetwork>,
    portalnet_config: PortalnetConfig,
    utp_listener_rx: mpsc::UnboundedReceiver<UtpListenerEvent>,
    state_event_rx: mpsc::UnboundedReceiver<TalkRequest>,
) -> JoinHandle<()> {
    let bootnodes: Vec<String> = portalnet_config
        .bootnode_enrs
        .iter()
        .map(|enr| format!("{{ {}, Encoded ENR: {} }}", enr, enr.to_base64()))
        .collect();
    let bootnodes = bootnodes.join(", ");
    info!(
        "About to spawn State Network with boot nodes: {}",
        bootnodes
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
        network.overlay.ping_bootnodes().await;

        tokio::signal::ctrl_c()
            .await
            .expect("failed to pause until ctrl-c");
    })
}
