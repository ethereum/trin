#![warn(clippy::unwrap_used)]
#![warn(clippy::uninlined_format_args)]

pub mod events;
mod jsonrpc;
pub mod network;
mod ping_extensions;
mod storage;
mod storage_migration;
pub mod validation;

use std::sync::Arc;

use ethportal_api::types::jsonrpc::request::HistoryJsonRpcRequest;
use network::HistoryNetwork;
use portalnet::{
    config::PortalnetConfig,
    discovery::{Discovery, UtpPeer},
    events::{EventEnvelope, OverlayRequest},
};
use tokio::{
    sync::{broadcast, mpsc, RwLock},
    task::JoinHandle,
    time::{interval, Duration},
};
use tracing::info;
use trin_storage::PortalStorageConfig;
use trin_validation::oracle::HeaderOracle;
use utp_rs::socket::UtpSocket;

use crate::{events::HistoryEvents, jsonrpc::HistoryRequestHandler};

type HistoryHandler = Option<HistoryRequestHandler>;
type HistoryNetworkTask = Option<JoinHandle<()>>;
type HistoryMessageTx = Option<mpsc::UnboundedSender<OverlayRequest>>;
type HistoryJsonRpcTx = Option<mpsc::UnboundedSender<HistoryJsonRpcRequest>>;
type HistoryEventStream = Option<broadcast::Receiver<EventEnvelope>>;

pub async fn initialize_history_network(
    discovery: &Arc<Discovery>,
    utp_socket: Arc<UtpSocket<UtpPeer>>,
    portalnet_config: PortalnetConfig,
    storage_config: PortalStorageConfig,
    header_oracle: Arc<RwLock<HeaderOracle>>,
    disable_history_storage: bool,
) -> anyhow::Result<(
    HistoryHandler,
    HistoryNetworkTask,
    HistoryMessageTx,
    HistoryJsonRpcTx,
    HistoryEventStream,
)> {
    let (history_jsonrpc_tx, history_jsonrpc_rx) =
        mpsc::unbounded_channel::<HistoryJsonRpcRequest>();
    header_oracle.write().await.history_jsonrpc_tx = Some(history_jsonrpc_tx.clone());
    let (history_event_tx, history_event_rx) = mpsc::unbounded_channel::<OverlayRequest>();
    let history_network = HistoryNetwork::new(
        Arc::clone(discovery),
        utp_socket,
        storage_config,
        portalnet_config.clone(),
        header_oracle,
        disable_history_storage,
    )
    .await?;
    let event_stream = history_network.overlay.event_stream().await?;
    let history_network = Arc::new(history_network);
    let history_handler = HistoryRequestHandler {
        network: history_network.clone(),
        history_rx: history_jsonrpc_rx,
    };
    let history_network_task =
        spawn_history_network(history_network.clone(), portalnet_config, history_event_rx);
    spawn_history_heartbeat(history_network);
    Ok((
        Some(history_handler),
        Some(history_network_task),
        Some(history_event_tx),
        Some(history_jsonrpc_tx),
        Some(event_stream),
    ))
}

pub fn spawn_history_network(
    network: Arc<HistoryNetwork>,
    portalnet_config: PortalnetConfig,
    history_message_rx: mpsc::UnboundedReceiver<OverlayRequest>,
) -> JoinHandle<()> {
    info!(
        "About to spawn History Network with {} boot nodes",
        portalnet_config.bootnodes.len()
    );

    tokio::spawn(async move {
        let history_events = HistoryEvents {
            network: Arc::clone(&network),
            message_rx: history_message_rx,
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

pub fn spawn_history_heartbeat(network: Arc<HistoryNetwork>) {
    tokio::spawn(async move {
        let mut heart_interval = interval(Duration::from_millis(30000));

        loop {
            // Don't want to wait to display 1st log, but a bug seems to skip the first wait, so put
            // this wait at the top. Otherwise, we get two log lines immediately on startup.
            heart_interval.tick().await;

            let storage_log = network.overlay.store.lock().get_summary_info();
            let message_log = network.overlay.get_message_summary();
            let utp_log = network.overlay.get_utp_summary();
            info!("reports~ data: {storage_log}; msgs: {message_log}");
            info!("reports~ utp: {utp_log}");
        }
    });
}
