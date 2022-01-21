pub mod events;
mod jsonrpc;
pub mod network;

use log::info;
use rocksdb::DB;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;

use crate::events::HistoryEvents;
use crate::jsonrpc::HistoryRequestHandler;
use discv5::TalkRequest;
use network::HistoryNetwork;
use std::collections::HashMap;
use std::sync::Arc;
use trin_core::cli::TrinConfig;
use trin_core::jsonrpc::types::HistoryJsonRpcRequest;
use trin_core::portalnet::discovery::Discovery;
use trin_core::portalnet::events::PortalnetEvents;
use trin_core::portalnet::types::messages::PortalnetConfig;
use trin_core::utils::db::setup_overlay_db;
use trin_core::utp::utp::UtpListener;

pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Launching trin-history...");

    let mut trin_config = TrinConfig::from_cli();

    // Set chain history default params
    trin_config.discovery_port = 9001;

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

    let (history_event_tx, history_event_rx) = mpsc::unbounded_channel::<TalkRequest>();
    let portal_events_discovery = Arc::clone(&discovery);
    let portal_events_utp_listener = Arc::clone(&utp_listener);

    // Spawn main event handler
    tokio::spawn(async move {
        let events = PortalnetEvents::new(
            portal_events_discovery,
            portal_events_utp_listener,
            Some(history_event_tx),
            None,
        )
        .await;
        events.process_discv5_requests().await;
    });

    let history_network = HistoryNetwork::new(
        discovery.clone(),
        utp_listener.clone(),
        db,
        portalnet_config.clone(),
    )
    .await;
    let history_network = Arc::new(history_network);

    spawn_history_network(history_network, portalnet_config, history_event_rx)
        .await
        .unwrap();
    Ok(())
}

type HistoryHandler = Option<HistoryRequestHandler>;
type HistoryNetworkTask = Option<JoinHandle<()>>;
type HistoryEventTx = Option<mpsc::UnboundedSender<TalkRequest>>;
type HistoryJsonRpcTx = Option<mpsc::UnboundedSender<HistoryJsonRpcRequest>>;

pub async fn initialize_history_network(
    discovery: &Arc<Discovery>,
    utp_listener: &Arc<RwLock<UtpListener>>,
    portalnet_config: PortalnetConfig,
    db: Arc<DB>,
) -> (
    HistoryHandler,
    HistoryNetworkTask,
    HistoryEventTx,
    HistoryJsonRpcTx,
) {
    let (history_jsonrpc_tx, history_jsonrpc_rx) =
        mpsc::unbounded_channel::<HistoryJsonRpcRequest>();
    let (history_event_tx, history_event_rx) = mpsc::unbounded_channel::<TalkRequest>();
    let history_network = HistoryNetwork::new(
        Arc::clone(discovery),
        Arc::clone(utp_listener),
        db,
        portalnet_config.clone(),
    )
    .await;
    let history_network = Arc::new(history_network);
    let history_handler = HistoryRequestHandler {
        network: Arc::clone(&history_network),
        history_rx: history_jsonrpc_rx,
    };
    let history_network_task = spawn_history_network(
        Arc::clone(&history_network),
        portalnet_config,
        history_event_rx,
    );
    (
        Some(history_handler),
        Some(history_network_task),
        Some(history_event_tx),
        Some(history_jsonrpc_tx),
    )
}

pub fn spawn_history_network(
    network: Arc<HistoryNetwork>,
    portalnet_config: PortalnetConfig,
    history_event_rx: mpsc::UnboundedReceiver<TalkRequest>,
) -> JoinHandle<()> {
    info!(
        "About to spawn History Network with boot nodes: {:?}",
        portalnet_config.bootnode_enrs
    );

    tokio::spawn(async move {
        let history_events = HistoryEvents {
            network: Arc::clone(&network),
            event_rx: history_event_rx,
        };

        // Spawn history event handler
        tokio::spawn(history_events.process_requests());

        // hacky test: make sure we establish a session with the boot node
        network.ping_bootnodes().await.unwrap();

        tokio::signal::ctrl_c()
            .await
            .expect("failed to pause until ctrl-c");
    })
}
