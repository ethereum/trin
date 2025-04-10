#![warn(clippy::unwrap_used)]
#![warn(clippy::uninlined_format_args)]

pub mod cli;

use std::sync::Arc;

use cli::TrinConfig;
use ethportal_api::{
    types::{distance::Distance, network::Subnetwork},
    utils::bytes::hex_encode,
    version::get_trin_version,
};
use portalnet::{
    discovery::{Discovery, Discv5UdpSocket},
    events::PortalnetEvents,
    utils::db::{configure_node_data_dir, configure_trin_data_dir},
};
use rpc::{launch_jsonrpc_server, RpcServerHandle};
use tokio::sync::{mpsc, RwLock};
use tracing::info;
use tree_hash::TreeHash;
use trin_beacon::initialize_beacon_network;
use trin_history::initialize_history_network;
use trin_state::initialize_state_network;
use trin_storage::PortalStorageConfigFactory;
#[cfg(windows)]
use trin_utils::cli::Web3TransportType;
use trin_validation::oracle::HeaderOracle;
use utp_rs::socket::UtpSocket;

pub async fn run_trin(
    trin_config: TrinConfig,
) -> Result<RpcServerHandle, Box<dyn std::error::Error>> {
    // Panic early on a windows build that is trying to use IPC, which is unsupported for now
    // Make sure not to panic on non-windows configurations.
    #[cfg(windows)]
    if let Web3TransportType::IPC = trin_config.web3_transport {
        panic!("Tokio doesn't support Windows Unix Domain Sockets IPC, use --web3-transport http");
    }

    let trin_version = get_trin_version();
    info!("Launching Trin: v{trin_version}");
    info!(config = %trin_config, "With:");

    // Setup temp trin data directory if we're in ephemeral mode
    let trin_data_dir =
        configure_trin_data_dir(trin_config.data_dir.clone(), trin_config.ephemeral)?;

    // Configure node data dir based on the provided private key
    let (node_data_dir, private_key) = configure_node_data_dir(
        &trin_data_dir,
        trin_config.private_key,
        trin_config.network.network(),
    )?;

    let portalnet_config = trin_config.to_portalnet_config(private_key);

    // Initialize base discovery protocol
    let mut discovery = Discovery::new(portalnet_config.clone(), trin_config.network.clone())?;
    let talk_req_rx = discovery.start().await?;
    let discovery = Arc::new(discovery);

    // Initialize prometheus metrics
    if let Some(addr) = trin_config.enable_metrics_with_url {
        prometheus_exporter::start(addr)?;
    }

    // Initialize validation oracle
    let header_oracle = HeaderOracle::default();
    info!(
        hash_tree_root = %hex_encode(header_oracle.header_validator.pre_merge_acc.tree_hash_root().0),
        "Loaded pre-merge accumulator."
    );
    let header_oracle = Arc::new(RwLock::new(header_oracle));

    // Initialize and spawn uTP socket
    let (utp_talk_reqs_tx, utp_talk_reqs_rx) = mpsc::unbounded_channel();

    let discv5_utp_socket = Discv5UdpSocket::new(Arc::clone(&discovery), utp_talk_reqs_rx);
    let utp_socket = UtpSocket::with_socket(discv5_utp_socket);
    let utp_socket = Arc::new(utp_socket);

    let storage_config_factory = PortalStorageConfigFactory::new(
        trin_config.storage_capacity_config(),
        discovery.local_enr().node_id(),
        node_data_dir,
    )?;

    // Initialize state sub-network service and event handlers, if selected
    let (state_handler, state_network_task, state_event_tx, state_jsonrpc_tx, state_event_stream) =
        if trin_config.portal_subnetworks.contains(&Subnetwork::State) {
            initialize_state_network(
                &discovery,
                utp_socket.clone(),
                portalnet_config.clone(),
                storage_config_factory.create(&Subnetwork::State, trin_config.max_radius)?,
                header_oracle.clone(),
            )
            .await?
        } else {
            (None, None, None, None, None)
        };

    // Initialize trin-beacon sub-network service and event handlers, if selected
    let (
        beacon_handler,
        beacon_network_task,
        beacon_event_tx,
        beacon_jsonrpc_tx,
        beacon_event_stream,
    ) = if trin_config.portal_subnetworks.contains(&Subnetwork::Beacon) {
        initialize_beacon_network(
            &discovery,
            utp_socket.clone(),
            portalnet_config.clone(),
            storage_config_factory.create(&Subnetwork::Beacon, Distance::MAX)?,
            header_oracle.clone(),
        )
        .await?
    } else {
        (None, None, None, None, None)
    };

    // Initialize chain history sub-network service and event handlers, if selected
    let (
        history_handler,
        history_network_task,
        history_event_tx,
        history_jsonrpc_tx,
        history_event_stream,
    ) = if trin_config
        .portal_subnetworks
        .contains(&Subnetwork::History)
    {
        initialize_history_network(
            &discovery,
            utp_socket.clone(),
            portalnet_config.clone(),
            storage_config_factory.create(&Subnetwork::History, trin_config.max_radius)?,
            header_oracle.clone(),
            trin_config.disable_history_storage,
        )
        .await?
    } else {
        (None, None, None, None, None)
    };

    // Launch JSON-RPC server
    let jsonrpc_discovery = Arc::clone(&discovery);
    let rpc_handle: RpcServerHandle = launch_jsonrpc_server(
        (&trin_config).into(),
        jsonrpc_discovery,
        history_jsonrpc_tx,
        state_jsonrpc_tx,
        beacon_jsonrpc_tx,
    )
    .await?;

    if let Some(handler) = state_handler {
        tokio::spawn(async move { handler.handle_client_queries().await });
    }
    if let Some(handler) = history_handler {
        tokio::spawn(async move { handler.handle_client_queries().await });
    }
    if let Some(handler) = beacon_handler {
        tokio::spawn(async move { handler.handle_client_queries().await });
    }

    // Spawn main portal events handler
    tokio::spawn(async move {
        let events = PortalnetEvents::new(
            talk_req_rx,
            (history_event_tx, history_event_stream),
            (state_event_tx, state_event_stream),
            (beacon_event_tx, beacon_event_stream),
            utp_talk_reqs_tx,
            trin_config.network.clone(),
        )
        .await;
        events.start().await;
    });

    if let Some(network) = history_network_task {
        tokio::spawn(network);
    }
    if let Some(network) = state_network_task {
        tokio::spawn(network);
    }
    if let Some(network) = beacon_network_task {
        tokio::spawn(network);
    }

    Ok(rpc_handle)
}
