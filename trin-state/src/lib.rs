use log::info;
use rocksdb::DB;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;

use crate::events::StateEvents;
use crate::jsonrpc::StateRequestHandler;
use discv5::TalkRequest;
use network::StateNetwork;
use std::collections::HashMap;
use trin_core::cli::TrinConfig;
use trin_core::jsonrpc::types::StateJsonRpcRequest;
use trin_core::portalnet::discovery::Discovery;
use trin_core::portalnet::events::PortalnetEvents;
use trin_core::portalnet::types::messages::PortalnetConfig;
use trin_core::utils::db::setup_overlay_db;
use trin_core::utp::utp::UtpListener;

pub mod events;
mod jsonrpc;
pub mod network;
mod trie;
pub mod utils;

pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    info!("Launching trin-state...");

    let trin_config = TrinConfig::from_cli();
    trin_config.display_config();

    let bootnode_enrs = trin_config
        .bootnodes
        .iter()
        .map(|nodestr| nodestr.parse().unwrap())
        .collect();

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

    // Setup Overlay database
    let db = Arc::new(setup_overlay_db(discovery.local_enr().node_id()));

    let utp_listener = Arc::new(RwLock::new(UtpListener {
        discovery: Arc::clone(&discovery),
        utp_connections: HashMap::new(),
        listening: HashMap::new(),
    }));

    let (state_event_tx, state_event_rx) = mpsc::unbounded_channel::<TalkRequest>();
    let portal_events_discovery = Arc::clone(&discovery);
    let portal_events_utp_listener = Arc::clone(&utp_listener);

    // Spawn main event handler
    tokio::spawn(async move {
        let events = PortalnetEvents::new(
            portal_events_discovery,
            portal_events_utp_listener,
            None,
            Some(state_event_tx),
        )
        .await;
        events.process_discv5_requests().await;
    });

    let state_network = StateNetwork::new(
        discovery.clone(),
        utp_listener.clone(),
        db,
        portalnet_config.clone(),
    )
    .await;
    let state_network = Arc::new(state_network);

    spawn_state_network(state_network, portalnet_config, state_event_rx)
        .await
        .unwrap();
    Ok(())
}

type StateHandler = Option<StateRequestHandler>;
type StateNetworkTask = Option<JoinHandle<()>>;
type StateEventTx = Option<mpsc::UnboundedSender<TalkRequest>>;
type StateJsonRpcTx = Option<mpsc::UnboundedSender<StateJsonRpcRequest>>;

pub async fn initialize_state_network(
    discovery: &Arc<Discovery>,
    utp_listener: &Arc<RwLock<UtpListener>>,
    portalnet_config: PortalnetConfig,
    db: Arc<DB>,
) -> (StateHandler, StateNetworkTask, StateEventTx, StateJsonRpcTx) {
    let (state_jsonrpc_tx, state_jsonrpc_rx) = mpsc::unbounded_channel::<StateJsonRpcRequest>();
    let (state_event_tx, state_event_rx) = mpsc::unbounded_channel::<TalkRequest>();
    let state_network = StateNetwork::new(
        Arc::clone(discovery),
        Arc::clone(utp_listener),
        db,
        portalnet_config.clone(),
    )
    .await;
    let state_network = Arc::new(state_network);
    let state_handler = StateRequestHandler {
        network: Arc::clone(&state_network),
        state_rx: state_jsonrpc_rx,
    };
    let state_network_task =
        spawn_state_network(Arc::clone(&state_network), portalnet_config, state_event_rx);
    (
        Some(state_handler),
        Some(state_network_task),
        Some(state_event_tx),
        Some(state_jsonrpc_tx),
    )
}

pub fn spawn_state_network(
    network: Arc<StateNetwork>,
    portalnet_config: PortalnetConfig,
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
        };

        // Spawn state event handler
        tokio::spawn(state_events.process_requests());

        // hacky test: make sure we establish a session with the boot node
        network.ping_bootnodes().await.unwrap();

        tokio::signal::ctrl_c()
            .await
            .expect("failed to pause until ctrl-c");
    })
}
