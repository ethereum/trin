#![warn(clippy::unwrap_used)]

use std::sync::Arc;

use discv5::TalkRequest;
use network::StateNetwork;
use tokio::{
    sync::{mpsc, RwLock},
    task::JoinHandle,
};
use tracing::info;
use utp_rs::socket::UtpSocket;

use crate::{events::StateEvents, jsonrpc::StateRequestHandler};
use trin_core::{
    jsonrpc::types::StateJsonRpcRequest,
    portalnet::{
        discovery::{Discovery, UtpEnr},
        storage::PortalStorageConfig,
        types::messages::PortalnetConfig,
    },
    types::validation::HeaderOracle,
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
type StateJsonRpcTx = Option<mpsc::UnboundedSender<StateJsonRpcRequest>>;

pub async fn initialize_state_network(
    discovery: &Arc<Discovery>,
    utp_socket: Arc<UtpSocket<UtpEnr>>,
    portalnet_config: PortalnetConfig,
    storage_config: PortalStorageConfig,
    header_oracle: Arc<RwLock<HeaderOracle>>,
) -> anyhow::Result<(StateHandler, StateNetworkTask, StateEventTx, StateJsonRpcTx)> {
    let (state_jsonrpc_tx, state_jsonrpc_rx) = mpsc::unbounded_channel::<StateJsonRpcRequest>();
    let (state_event_tx, state_event_rx) = mpsc::unbounded_channel::<TalkRequest>();
    let state_network = StateNetwork::new(
        Arc::clone(discovery),
        utp_socket,
        storage_config,
        portalnet_config.clone(),
        header_oracle,
    )
    .await?;
    let state_network = Arc::new(state_network);
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
    ))
}

pub fn spawn_state_network(
    network: Arc<StateNetwork>,
    portalnet_config: PortalnetConfig,
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
