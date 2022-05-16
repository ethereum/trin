use log::info;
use std::sync::Arc;
use tokio::{sync::mpsc, task::JoinHandle};

use crate::{events::StateEvents, jsonrpc::StateRequestHandler};
use discv5::TalkRequest;
use network::StateNetwork;
use tokio::sync::mpsc::UnboundedSender;
use trin_core::{
    cli::TrinConfig,
    jsonrpc::types::StateJsonRpcRequest,
    portalnet::{
        discovery::Discovery,
        events::PortalnetEvents,
        storage::{PortalStorage, PortalStorageConfig},
        types::messages::PortalnetConfig,
    },
    utils::bootnodes::parse_bootnodes,
    utp::stream::{UtpListener, UtpListenerEvent, UtpListenerRequest},
};

pub mod events;
mod jsonrpc;
pub mod network;
mod trie;
pub mod utils;
pub mod validation;

pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    info!("Launching trin-state...");

    let trin_config = TrinConfig::from_cli();
    trin_config.display_config();

    let bootnode_enrs = parse_bootnodes(&trin_config.bootnodes)?;

    let portalnet_config = PortalnetConfig {
        external_addr: trin_config.external_addr,
        private_key: trin_config.private_key.clone(),
        listen_port: trin_config.discovery_port,
        bootnode_enrs,
        ..Default::default()
    };

    let mut discovery = Discovery::new(portalnet_config.clone()).unwrap();
    discovery.start().await.unwrap();
    let discovery = Arc::new(discovery);

    // Search for discv5 peers (bucket refresh lookup)
    tokio::spawn(Arc::clone(&discovery).bucket_refresh_lookup());

    // Initialize and spawn UTP listener
    let (utp_sender, overlay_sender, utp_listener_rx, mut utp_listener) =
        UtpListener::new(Arc::clone(&discovery));
    tokio::spawn(async move { utp_listener.start().await });

    let (state_event_tx, state_event_rx) = mpsc::unbounded_channel::<TalkRequest>();
    let (state_utp_tx, state_utp_rx) = mpsc::unbounded_channel::<UtpListenerEvent>();
    let portal_events_discovery = Arc::clone(&discovery);

    // Initialize DB config
    let storage_config =
        PortalStorage::setup_config(discovery.local_enr().node_id(), trin_config.kb)?;

    // Spawn main event handler
    tokio::spawn(async move {
        let events = PortalnetEvents::new(
            portal_events_discovery,
            utp_listener_rx,
            None,
            None,
            Some(state_event_tx),
            Some(state_utp_tx),
            utp_sender,
        )
        .await;
        events.start().await;
    });

    let state_network = StateNetwork::new(
        discovery.clone(),
        overlay_sender,
        storage_config,
        portalnet_config.clone(),
    )
    .await;
    let state_network = Arc::new(state_network);

    spawn_state_network(
        state_network,
        portalnet_config,
        state_utp_rx,
        state_event_rx,
    )
    .await
    .unwrap();
    Ok(())
}

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
