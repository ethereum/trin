pub mod events;
pub mod network;

use log::info;
use rocksdb::DB;
use serde_json::Value;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;

use crate::events::HistoryEvents;
use discv5::TalkRequest;
use network::HistoryNetwork;
use std::sync::Arc;
use trin_core::cli::TrinConfig;
use trin_core::jsonrpc::handlers::{HistoryEndpointKind, HistoryNetworkEndpoint};
use trin_core::portalnet::discovery::Discovery;
use trin_core::portalnet::events::PortalnetEvents;
use trin_core::portalnet::types::PortalnetConfig;
use trin_core::utils::setup_overlay_db;

pub struct HistoryRequestHandler {
    pub history_rx: mpsc::UnboundedReceiver<HistoryNetworkEndpoint>,
}

impl HistoryRequestHandler {
    pub async fn handle_client_queries(mut self) {
        while let Some(cmd) = self.history_rx.recv().await {
            use HistoryEndpointKind::*;

            match cmd.kind {
                GetHistoryNetworkData => {
                    let _ = cmd
                        .resp
                        .send(Ok(Value::String("0xmockhistorydata".to_string())));
                }
            }
        }
    }
}

pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Launching trin-history...");

    let mut trin_config = TrinConfig::new();

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
    let discovery = Arc::new(RwLock::new(discovery));

    // Setup Overlay database
    let db = Arc::new(setup_overlay_db(discovery.read().await.local_enr()));

    let (history_event_tx, history_event_rx) = mpsc::unbounded_channel::<TalkRequest>();
    let portal_events_discovery = Arc::clone(&discovery);

    // Spawn main event handler
    tokio::spawn(async move {
        let events =
            PortalnetEvents::new(portal_events_discovery, Some(history_event_tx), None).await;
        events.process_discv5_requests().await;
    });

    spawn_history_network(discovery, db, portalnet_config, history_event_rx)
        .await
        .unwrap();
    Ok(())
}

type HistoryHandler = Option<HistoryRequestHandler>;
type HistoryNetworkTask = Option<JoinHandle<()>>;
type HistoryEventTx = Option<mpsc::UnboundedSender<TalkRequest>>;
type HistoryJsonRpcTx = Option<mpsc::UnboundedSender<HistoryNetworkEndpoint>>;

pub fn initialize_history_network(
    discovery: &Arc<RwLock<Discovery>>,
    portalnet_config: PortalnetConfig,
    db: &Arc<DB>,
) -> (
    HistoryHandler,
    HistoryNetworkTask,
    HistoryEventTx,
    HistoryJsonRpcTx,
) {
    let (history_jsonrpc_tx, history_jsonrpc_rx) =
        mpsc::unbounded_channel::<HistoryNetworkEndpoint>();
    let (history_event_tx, history_event_rx) = mpsc::unbounded_channel::<TalkRequest>();
    let history_handler = HistoryRequestHandler {
        history_rx: history_jsonrpc_rx,
    };
    let history_network_task = spawn_history_network(
        Arc::clone(discovery),
        Arc::clone(db),
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
    discovery: Arc<RwLock<Discovery>>,
    db: Arc<DB>,
    portalnet_config: PortalnetConfig,
    history_event_rx: mpsc::UnboundedReceiver<TalkRequest>,
) -> JoinHandle<()> {
    info!(
        "About to spawn History Network with boot nodes: {:?}",
        portalnet_config.bootnode_enrs
    );

    tokio::spawn(async move {
        let mut p2p = HistoryNetwork::new(discovery.clone(), db, portalnet_config)
            .await
            .unwrap();

        let history_events = HistoryEvents {
            network: p2p.clone(),
            event_rx: history_event_rx,
        };

        // Spawn history event handler
        tokio::spawn(history_events.process_requests());

        // hacky test: make sure we establish a session with the boot node
        p2p.ping_bootnodes().await.unwrap();

        tokio::signal::ctrl_c()
            .await
            .expect("failed to pause until ctrl-c");
    })
}
