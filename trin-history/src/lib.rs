pub mod events;
mod jsonrpc;
pub mod network;
pub mod validation;

use std::sync::{Arc, RwLock};

use discv5::TalkRequest;
use log::info;
use network::HistoryNetwork;
use tokio::{
    sync::{mpsc, mpsc::UnboundedSender},
    task::JoinHandle,
};

use crate::{events::HistoryEvents, jsonrpc::HistoryRequestHandler};
use trin_core::{
    cli::TrinConfig,
    jsonrpc::types::HistoryJsonRpcRequest,
    portalnet::{
        discovery::Discovery,
        events::PortalnetEvents,
        storage::{PortalStorage, PortalStorageConfig},
        types::messages::PortalnetConfig,
    },
    types::validation::HeaderOracle,
    utils::bootnodes::parse_bootnodes,
    utp::stream::{UtpListener, UtpListenerEvent, UtpListenerRequest},
};

pub async fn main(infura_url: String) -> Result<(), Box<dyn std::error::Error>> {
    println!("Launching trin-history...");

    let mut trin_config = TrinConfig::from_cli();

    // Set chain history default params
    trin_config.discovery_port = 9001;

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

    let (history_event_tx, history_event_rx) = mpsc::unbounded_channel::<TalkRequest>();
    let (history_utp_tx, history_utp_rx) = mpsc::unbounded_channel::<UtpListenerEvent>();
    let portal_events_discovery = Arc::clone(&discovery);

    // Initialize DB config
    let storage_config =
        PortalStorage::setup_config(discovery.local_enr().node_id(), trin_config.kb)?;

    // Spawn main event handler
    tokio::spawn(async move {
        let events = PortalnetEvents::new(
            portal_events_discovery,
            utp_listener_rx,
            Some(history_event_tx),
            Some(history_utp_tx),
            None,
            None,
            utp_sender,
        )
        .await;
        events.start().await;
    });

    let header_oracle = Arc::new(RwLock::new(HeaderOracle {
        infura_url,
        ..HeaderOracle::default()
    }));
    let history_network = HistoryNetwork::new(
        discovery.clone(),
        overlay_sender,
        storage_config,
        portalnet_config.clone(),
        header_oracle,
    )
    .await;
    let history_network = Arc::new(history_network);

    spawn_history_network(
        history_network,
        portalnet_config,
        history_utp_rx,
        history_event_rx,
    )
    .await
    .unwrap();
    Ok(())
}

type HistoryHandler = Option<HistoryRequestHandler>;
type HistoryNetworkTask = Option<JoinHandle<()>>;
type HistoryEventTx = Option<mpsc::UnboundedSender<TalkRequest>>;
type HistoryUtpTx = Option<mpsc::UnboundedSender<UtpListenerEvent>>;
type HistoryJsonRpcTx = Option<mpsc::UnboundedSender<HistoryJsonRpcRequest>>;

pub async fn initialize_history_network(
    discovery: &Arc<Discovery>,
    utp_listener_tx: UnboundedSender<UtpListenerRequest>,
    portalnet_config: PortalnetConfig,
    storage_config: PortalStorageConfig,
    header_oracle: Arc<RwLock<HeaderOracle>>,
) -> (
    HistoryHandler,
    HistoryNetworkTask,
    HistoryEventTx,
    HistoryUtpTx,
    HistoryJsonRpcTx,
) {
    let (history_jsonrpc_tx, history_jsonrpc_rx) =
        mpsc::unbounded_channel::<HistoryJsonRpcRequest>();
    header_oracle.write().unwrap().history_jsonrpc_tx = Some(history_jsonrpc_tx.clone());
    let (history_event_tx, history_event_rx) = mpsc::unbounded_channel::<TalkRequest>();
    let (utp_history_tx, utp_history_rx) = mpsc::unbounded_channel::<UtpListenerEvent>();
    let history_network = HistoryNetwork::new(
        Arc::clone(discovery),
        utp_listener_tx,
        storage_config,
        portalnet_config.clone(),
        header_oracle,
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
        utp_history_rx,
        history_event_rx,
    );
    (
        Some(history_handler),
        Some(history_network_task),
        Some(history_event_tx),
        Some(utp_history_tx),
        Some(history_jsonrpc_tx),
    )
}

pub fn spawn_history_network(
    network: Arc<HistoryNetwork>,
    portalnet_config: PortalnetConfig,
    utp_listener_rx: mpsc::UnboundedReceiver<UtpListenerEvent>,
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
            utp_listener_rx,
        };

        // Spawn history event handler
        tokio::spawn(history_events.start());

        // hacky test: make sure we establish a session with the boot node
        network.ping_bootnodes().await.unwrap();

        tokio::signal::ctrl_c()
            .await
            .expect("failed to pause until ctrl-c");
    })
}
