#![warn(clippy::unwrap_used)]
#![warn(clippy::uninlined_format_args)]

pub mod events;
mod jsonrpc;
pub mod network;
mod ping_extensions;
mod storage;
pub mod validation;

use std::sync::Arc;

use ethportal_api::types::jsonrpc::request::LegacyHistoryJsonRpcRequest;
use network::LegacyHistoryNetwork;
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

use crate::{events::LegacyHistoryEvents, jsonrpc::LegacyHistoryRequestHandler};

type LegacyHistoryHandler = Option<LegacyHistoryRequestHandler>;
type LegacyHistoryNetworkTask = Option<JoinHandle<()>>;
type LegacyHistoryMessageTx = Option<mpsc::UnboundedSender<OverlayRequest>>;
type LegacyHistoryJsonRpcTx = Option<mpsc::UnboundedSender<LegacyHistoryJsonRpcRequest>>;
type LegacyHistoryEventStream = Option<broadcast::Receiver<EventEnvelope>>;

pub async fn initialize_legacy_history_network(
    discovery: &Arc<Discovery>,
    utp_socket: Arc<UtpSocket<UtpPeer>>,
    portalnet_config: PortalnetConfig,
    storage_config: PortalStorageConfig,
    header_oracle: Arc<RwLock<HeaderOracle>>,
) -> anyhow::Result<(
    LegacyHistoryHandler,
    LegacyHistoryNetworkTask,
    LegacyHistoryMessageTx,
    LegacyHistoryJsonRpcTx,
    LegacyHistoryEventStream,
)> {
    let (legacy_history_jsonrpc_tx, legacy_history_jsonrpc_rx) =
        mpsc::unbounded_channel::<LegacyHistoryJsonRpcRequest>();
    header_oracle.write().await.legacy_history_jsonrpc_tx = Some(legacy_history_jsonrpc_tx.clone());
    let (legacy_history_event_tx, legacy_history_event_rx) =
        mpsc::unbounded_channel::<OverlayRequest>();
    let legacy_history_network = LegacyHistoryNetwork::new(
        Arc::clone(discovery),
        utp_socket,
        storage_config,
        portalnet_config.clone(),
        header_oracle,
    )
    .await?;
    let event_stream = legacy_history_network.overlay.event_stream().await?;
    let legacy_history_network = Arc::new(legacy_history_network);
    let legacy_history_handler = LegacyHistoryRequestHandler {
        network: legacy_history_network.clone(),
        legacy_history_rx: legacy_history_jsonrpc_rx,
    };
    let legacy_history_network_task = spawn_history_network(
        legacy_history_network.clone(),
        portalnet_config,
        legacy_history_event_rx,
    );
    spawn_legacy_history_heartbeat(legacy_history_network);
    Ok((
        Some(legacy_history_handler),
        Some(legacy_history_network_task),
        Some(legacy_history_event_tx),
        Some(legacy_history_jsonrpc_tx),
        Some(event_stream),
    ))
}

pub fn spawn_history_network(
    network: Arc<LegacyHistoryNetwork>,
    portalnet_config: PortalnetConfig,
    legacy_history_message_rx: mpsc::UnboundedReceiver<OverlayRequest>,
) -> JoinHandle<()> {
    info!(
        "About to spawn Legacy History Network with {} boot nodes",
        portalnet_config.bootnodes.len()
    );

    tokio::spawn(async move {
        let legacy_history_events = LegacyHistoryEvents {
            network: Arc::clone(&network),
            message_rx: legacy_history_message_rx,
        };

        // Spawn legacy history event handler
        tokio::spawn(legacy_history_events.start());

        // hacky test: make sure we establish a session with the boot node
        network.overlay.ping_bootnodes().await;

        tokio::signal::ctrl_c()
            .await
            .expect("failed to pause until ctrl-c");
    })
}

pub fn spawn_legacy_history_heartbeat(network: Arc<LegacyHistoryNetwork>) {
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
