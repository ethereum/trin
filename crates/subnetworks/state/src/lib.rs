#![warn(clippy::unwrap_used)]
#![warn(clippy::uninlined_format_args)]

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use cpu_time::ProcessTime;
use ethportal_api::types::jsonrpc::request::StateJsonRpcRequest;
use network::StateNetwork;
use portalnet::{
    config::PortalnetConfig,
    discovery::{Discovery, UtpPeer},
    events::{EventEnvelope, OverlayRequest},
};
use tokio::{
    sync::{broadcast, mpsc, RwLock},
    task::JoinHandle,
    time::interval,
};
use tracing::info;
use trin_storage::PortalStorageConfig;
use trin_validation::oracle::HeaderOracle;
use utp_rs::socket::UtpSocket;

use crate::{events::StateEvents, jsonrpc::StateRequestHandler};

pub mod events;
mod jsonrpc;
pub mod network;
mod ping_extensions;
mod storage;
pub mod validation;

type StateHandler = Option<StateRequestHandler>;
type StateNetworkTask = Option<JoinHandle<()>>;
type StateEventTx = Option<mpsc::UnboundedSender<OverlayRequest>>;
type StateJsonRpcTx = Option<mpsc::UnboundedSender<StateJsonRpcRequest>>;
type StateEventStream = Option<broadcast::Receiver<EventEnvelope>>;

pub async fn initialize_state_network(
    discovery: &Arc<Discovery>,
    utp_socket: Arc<UtpSocket<UtpPeer>>,
    portalnet_config: PortalnetConfig,
    storage_config: PortalStorageConfig,
    header_oracle: Arc<RwLock<HeaderOracle>>,
) -> anyhow::Result<(
    StateHandler,
    StateNetworkTask,
    StateEventTx,
    StateJsonRpcTx,
    StateEventStream,
)> {
    let (state_jsonrpc_tx, state_jsonrpc_rx) = mpsc::unbounded_channel::<StateJsonRpcRequest>();
    header_oracle.write().await.state_jsonrpc_tx = Some(state_jsonrpc_tx.clone());
    let (state_event_tx, state_event_rx) = mpsc::unbounded_channel::<OverlayRequest>();

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
    let state_event_stream = state_network.overlay.event_stream().await?;

    spawn_state_heartbeat(state_network);

    Ok((
        Some(state_handler),
        Some(state_network_task),
        Some(state_event_tx),
        Some(state_jsonrpc_tx),
        Some(state_event_stream),
    ))
}

pub fn spawn_state_network(
    network: Arc<StateNetwork>,
    portalnet_config: PortalnetConfig,
    state_message_rx: mpsc::UnboundedReceiver<OverlayRequest>,
) -> JoinHandle<()> {
    info!(
        "About to spawn State Network with {} boot nodes.",
        portalnet_config.bootnodes.len()
    );

    tokio::spawn(async move {
        let state_events = StateEvents {
            network: Arc::clone(&network),
            message_rx: state_message_rx,
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

pub fn spawn_state_heartbeat(network: Arc<StateNetwork>) {
    tokio::spawn(async move {
        let mut heart_interval = interval(Duration::from_millis(30000));

        loop {
            let clock_time = Instant::now();
            let process_time = ProcessTime::now();
            // Don't want to wait to display 1st log, but a bug seems to skip the first wait, so put
            // this wait at the top. Otherwise, we get two log lines immediately on startup.
            heart_interval.tick().await;

            let cpu_percent =
                100.0 * process_time.elapsed().as_secs_f64() / clock_time.elapsed().as_secs_f64();

            let storage_log = network.overlay.store.lock().get_summary_info();
            let message_log = network.overlay.get_message_summary();
            let utp_log = network.overlay.get_utp_summary();
            info!("reports~ data: {storage_log}; msgs: {message_log}; cpu={cpu_percent:.1}%");
            info!("reports~ utp: {utp_log}");
        }
    });
}
