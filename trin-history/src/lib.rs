pub mod events;
mod jsonrpc;
pub mod network;
pub mod validation;

use std::sync::Arc;

use discv5::TalkRequest;
use network::HistoryNetwork;
use tokio::{
    sync::{mpsc, mpsc::UnboundedSender, RwLock},
    task::JoinHandle,
};
use tracing::info;

use crate::{events::HistoryEvents, jsonrpc::HistoryRequestHandler};
use trin_core::{
    jsonrpc::types::HistoryJsonRpcRequest,
    portalnet::{
        discovery::Discovery, storage::PortalStorageConfig, types::messages::PortalnetConfig,
    },
    types::validation::HeaderOracle,
    utp::stream::{UtpListenerEvent, UtpListenerRequest},
};

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
    header_oracle.write().await.history_jsonrpc_tx = Some(history_jsonrpc_tx.clone());
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
    let bootnodes: Vec<String> = portalnet_config
        .bootnode_enrs
        .iter()
        .map(|enr| format!("{{ {}, Encoded ENR: {} }}", enr, enr.to_base64()))
        .collect();
    let bootnodes = bootnodes.join(", ");
    info!(
        "About to spawn History Network with boot nodes: {}",
        bootnodes
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
        network.overlay.ping_bootnodes().await;

        tokio::signal::ctrl_c()
            .await
            .expect("failed to pause until ctrl-c");
    })
}
