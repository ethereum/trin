use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use ethportal_api::{
    types::{distance::Distance, network::Subnetwork},
    version::get_trin_version,
};
use portalnet::{
    config::PortalnetConfig,
    discovery::{Discovery, Discv5UdpSocket},
    events::PortalnetEvents,
    utils::db::{configure_node_data_dir, configure_trin_data_dir},
};
use rpc::{config::RpcConfig, launch_jsonrpc_server, RpcServerHandle};
use tokio::sync::{mpsc, RwLock};
use tracing::info;
use trin_beacon::initialize_beacon_network;
use trin_history::initialize_history_network;
use trin_state::initialize_state_network;
use trin_storage::{config::StorageCapacityConfig, PortalStorageConfigFactory};
#[cfg(windows)]
use trin_utils::cli::Web3TransportType;
use trin_validation::{chain_head::ChainHead, oracle::HeaderOracle};
use utp_rs::socket::UtpSocket;

use crate::{
    handle::{SubnetworkOverlays, TrinHandle},
    TrinConfig,
};

pub struct NodeRuntimeConfig {
    pub portal_subnetworks: Arc<Vec<Subnetwork>>,
    pub max_radius: Distance,
    pub enable_metrics_with_url: Option<SocketAddr>,
    pub storage_capacity_config: StorageCapacityConfig,
    pub node_data_dir: PathBuf,
}

/// Initializes the trin node with the provided configuration, returns TrinHandle
pub async fn run_trin_from_trin_config(
    trin_config: TrinConfig,
) -> Result<TrinHandle, Box<dyn std::error::Error>> {
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

    let portalnet_config = trin_config.as_portalnet_config(private_key);
    let node_runtime_config = trin_config.as_node_runtime_config(node_data_dir);
    let rpc_config = RpcConfig::from(&trin_config);

    run_trin_with_rpc(portalnet_config, node_runtime_config, rpc_config).await
}

/// Initializes the trin node with the provided configuration, returns SubnetworkOverlays
///
/// Useful for running Trin internally without the RPC server in other applications
pub async fn run_trin(
    portalnet_config: PortalnetConfig,
    node_runtime_config: NodeRuntimeConfig,
) -> Result<SubnetworkOverlays, Box<dyn std::error::Error>> {
    let (subnetwork_overlays, _) =
        run_trin_internal(portalnet_config, node_runtime_config, None).await?;
    Ok(subnetwork_overlays)
}

/// Initializes the trin node with the provided configuration and RPC Server Config, returns
/// TrinHandle
///
/// Useful for running Trin internally with the RPC server in other applications
pub async fn run_trin_with_rpc(
    portalnet_config: PortalnetConfig,
    node_runtime_config: NodeRuntimeConfig,
    rpc_config: RpcConfig,
) -> Result<TrinHandle, Box<dyn std::error::Error>> {
    let (subnetwork_overlays, rpc_server_handle) =
        run_trin_internal(portalnet_config, node_runtime_config, Some(rpc_config)).await?;
    let Some(rpc_server_handle) = rpc_server_handle else {
        return Err("RPC server handle wasn't initialized".into());
    };
    Ok(TrinHandle {
        subnetwork_overlays,
        rpc_server_handle,
    })
}

async fn run_trin_internal(
    portalnet_config: PortalnetConfig,
    node_runtime_config: NodeRuntimeConfig,
    rpc_config: Option<RpcConfig>,
) -> Result<(SubnetworkOverlays, Option<RpcServerHandle>), Box<dyn std::error::Error>> {
    // Panic early on a windows build that is trying to use IPC, which is unsupported for now
    // Make sure not to panic on non-windows configurations.
    #[cfg(windows)]
    if rpc_config
        .as_ref()
        .is_some_and(|rpc_config| matches!(rpc_config.web3_transport, Web3TransportType::IPC))
    {
        panic!("Tokio doesn't support Windows Unix Domain Sockets IPC, use --web3-transport http");
    }

    // Initialize base discovery protocol
    let mut discovery = Discovery::new(portalnet_config.clone())?;
    let talk_req_rx = discovery.start().await?;
    let discovery = Arc::new(discovery);

    // Initialize prometheus metrics
    if let Some(addr) = node_runtime_config.enable_metrics_with_url {
        prometheus_exporter::start(addr)?;
    }

    // Initialize validation oracle
    let header_oracle = Arc::new(RwLock::new(HeaderOracle::default()));

    // Initialize head of the chain management.
    let chain_head = ChainHead::new_pectra_defaults();

    // Initialize and spawn uTP socket
    let (utp_talk_reqs_tx, utp_talk_reqs_rx) = mpsc::unbounded_channel();

    let discv5_utp_socket = Discv5UdpSocket::new(Arc::clone(&discovery), utp_talk_reqs_rx);
    let utp_socket = UtpSocket::with_socket(discv5_utp_socket);
    let utp_socket = Arc::new(utp_socket);

    let storage_config_factory = PortalStorageConfigFactory::new(
        node_runtime_config.storage_capacity_config,
        discovery.local_enr().node_id(),
        node_runtime_config.node_data_dir,
    )?;

    // Initialize state sub-network service and event handlers, if selected
    let (state_handler, state_network_task, state_event_tx, state_jsonrpc_tx, state_event_stream) =
        if node_runtime_config
            .portal_subnetworks
            .contains(&Subnetwork::State)
        {
            initialize_state_network(
                &discovery,
                utp_socket.clone(),
                portalnet_config.clone(),
                storage_config_factory
                    .create(&Subnetwork::State, node_runtime_config.max_radius)?,
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
    ) = if node_runtime_config
        .portal_subnetworks
        .contains(&Subnetwork::Beacon)
    {
        initialize_beacon_network(
            &discovery,
            utp_socket.clone(),
            portalnet_config.clone(),
            storage_config_factory.create(&Subnetwork::Beacon, Distance::MAX)?,
            header_oracle.clone(),
            chain_head,
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
    ) = if node_runtime_config
        .portal_subnetworks
        .contains(&Subnetwork::History)
    {
        initialize_history_network(
            &discovery,
            utp_socket.clone(),
            portalnet_config.clone(),
            storage_config_factory.create(&Subnetwork::History, node_runtime_config.max_radius)?,
            header_oracle.clone(),
        )
        .await?
    } else {
        (None, None, None, None, None)
    };

    // Launch JSON-RPC server
    let rpc_server_handle = if let Some(rpc_config) = rpc_config {
        let jsonrpc_discovery = Arc::clone(&discovery);
        Some(
            launch_jsonrpc_server(
                rpc_config,
                node_runtime_config.portal_subnetworks,
                jsonrpc_discovery,
                history_jsonrpc_tx,
                state_jsonrpc_tx,
                beacon_jsonrpc_tx,
            )
            .await?,
        )
    } else {
        None
    };

    let subnetwork_overlays = SubnetworkOverlays {
        history: history_handler
            .as_ref()
            .map(|handler| handler.network.clone()),
        state: state_handler
            .as_ref()
            .map(|handler| handler.network.clone()),
        beacon: beacon_handler
            .as_ref()
            .map(|handler| handler.network.clone()),
    };

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

    Ok((subnetwork_overlays, rpc_server_handle))
}
