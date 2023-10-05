#![warn(clippy::unwrap_used)]

pub mod events;
mod jsonrpc;
pub mod network;
pub mod validation;

use std::sync::Arc;

use discv5::TalkRequest;
use ethportal_api::types::enr::Enr;
use ethportal_api::types::jsonrpc::request::BeaconJsonRpcRequest;
use portalnet::{
    config::PortalnetConfig,
    discovery::{Discovery, UtpEnr},
    storage::PortalStorageConfig,
};
use tokio::{
    sync::{mpsc, Mutex, RwLock},
    task::JoinHandle,
    time::{interval, Duration},
};
use tracing::info;
use trin_validation::oracle::HeaderOracle;
use utp_rs::socket::UtpSocket;

use crate::network::BeaconNetwork;
use crate::{events::BeaconEvents, jsonrpc::BeaconRequestHandler};

type BeaconHandler = Option<BeaconRequestHandler>;
type BeaconNetworkTask = Option<JoinHandle<()>>;
type BeaconEventTx = Option<mpsc::UnboundedSender<TalkRequest>>;
type BeaconJsonRpcTx = Option<mpsc::UnboundedSender<BeaconJsonRpcRequest>>;

pub async fn initialize_beacon_network(
    discovery: &Arc<Discovery>,
    utp_socket: Arc<UtpSocket<UtpEnr>>,

    portalnet_config: PortalnetConfig,
    storage_config: PortalStorageConfig,
    header_oracle: Arc<RwLock<HeaderOracle>>,
) -> anyhow::Result<(
    BeaconHandler,
    BeaconNetworkTask,
    BeaconEventTx,
    BeaconJsonRpcTx,
)> {
    let (beacon_jsonrpc_tx, beacon_jsonrpc_rx) = mpsc::unbounded_channel::<BeaconJsonRpcRequest>();
    header_oracle.write().await.beacon_jsonrpc_tx = Some(beacon_jsonrpc_tx.clone());
    let (beacon_event_tx, beacon_event_rx) = mpsc::unbounded_channel::<TalkRequest>();
    let beacon_network = BeaconNetwork::new(
        Arc::clone(discovery),
        utp_socket,
        storage_config,
        portalnet_config.clone(),
        header_oracle,
    )
    .await?;
    let beacon_handler = BeaconRequestHandler {
        network: Arc::new(RwLock::new(beacon_network.clone())),
        rpc_rx: Arc::new(Mutex::new(beacon_jsonrpc_rx)),
    };
    let beacon_network = Arc::new(beacon_network);
    let beacon_network_task =
        spawn_beacon_network(beacon_network.clone(), portalnet_config, beacon_event_rx);
    spawn_beacon_heartbeat(beacon_network);
    Ok((
        Some(beacon_handler),
        Some(beacon_network_task),
        Some(beacon_event_tx),
        Some(beacon_jsonrpc_tx),
    ))
}

pub fn spawn_beacon_network(
    network: Arc<BeaconNetwork>,
    portalnet_config: PortalnetConfig,
    beacon_event_rx: mpsc::UnboundedReceiver<TalkRequest>,
) -> JoinHandle<()> {
    let bootnode_enrs: Vec<Enr> = portalnet_config.bootnodes.into();
    info!(
        "About to spawn Beacon Network with {} boot nodes.",
        bootnode_enrs.len()
    );

    tokio::spawn(async move {
        let beacon_events = BeaconEvents {
            network: Arc::clone(&network),
            event_rx: beacon_event_rx,
        };

        // Spawn beacon event handler
        tokio::spawn(beacon_events.start());

        // hacky test: make sure we establish a session with the boot node
        network.overlay.ping_bootnodes().await;

        tokio::signal::ctrl_c()
            .await
            .expect("failed to pause until ctrl-c");
    })
}

pub fn spawn_beacon_heartbeat(network: Arc<BeaconNetwork>) {
    tokio::spawn(async move {
        let mut heart_interval = interval(Duration::from_millis(30000));

        loop {
            // Don't want to wait to display 1st log, but a bug seems to skip the first wait, so put
            // this wait at the top. Otherwise, we get two log lines immediately on startup.
            heart_interval.tick().await;

            let storage_log = network.overlay.store.read().get_summary_info();
            let message_log = network.overlay.get_message_summary();
            let utp_log = network.overlay.get_utp_summary();
            info!("reports~ data: {storage_log}; msgs: {message_log}");
            info!("reports~ utp: {utp_log}");
        }
    });
}
