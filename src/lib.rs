#![warn(clippy::unwrap_used)]

use std::sync::Arc;

use ethportal_api::jsonrpsee::server::ServerHandle;
use rpc::JsonRpcServer;
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tracing::info;
use utp_rs::socket::UtpSocket;

use trin_core::{
    portalnet::{
        discovery::{Discovery, Discv5UdpSocket},
        events::PortalnetEvents,
        storage::PortalStorageConfig,
        types::messages::PortalnetConfig,
    },
    utils::{bootnodes::parse_bootnodes, db::setup_temp_dir},
};
use trin_history::initialize_history_network;
use trin_state::initialize_state_network;
use trin_types::cli::{TrinConfig, Web3TransportType, HISTORY_NETWORK, STATE_NETWORK};
use trin_types::jsonrpc::request::HistoryJsonRpcRequest;
use trin_types::provider::TrustedProvider;
use trin_utils::version::get_trin_version;
use trin_validation::{accumulator::MasterAccumulator, oracle::HeaderOracle};

pub async fn run_trin(
    trin_config: TrinConfig,
    trusted_provider: TrustedProvider,
) -> Result<ServerHandle, Box<dyn std::error::Error>> {
    let trin_version = get_trin_version();
    info!("Launching Trin: v{trin_version}");
    info!(config = %trin_config, "With:");

    let bootnode_enrs = parse_bootnodes(&trin_config.bootnodes)?;
    let portalnet_config = PortalnetConfig {
        external_addr: trin_config.external_addr,
        private_key: trin_config.private_key,
        listen_port: trin_config.discovery_port,
        no_stun: trin_config.no_stun,
        enable_metrics: trin_config.enable_metrics_with_url.is_some(),
        bootnode_enrs,
        ..Default::default()
    };

    // Initialize base discovery protocol
    let mut discovery = Discovery::new(portalnet_config.clone())?;
    let talk_req_rx = discovery.start().await?;
    let discovery = Arc::new(discovery);

    // Initialize prometheus metrics
    if let Some(addr) = trin_config.enable_metrics_with_url {
        prometheus_exporter::start(addr)?;
    }

    // Initialize and spawn uTP socket
    let (utp_talk_reqs_tx, utp_talk_reqs_rx) = mpsc::unbounded_channel();
    let discv5_utp_socket = Discv5UdpSocket::new(Arc::clone(&discovery), utp_talk_reqs_rx);
    let utp_socket = UtpSocket::with_socket(discv5_utp_socket);
    let utp_socket = Arc::new(utp_socket);

    // Initialize Storage config
    if trin_config.ephemeral {
        setup_temp_dir()?;
    }

    let storage_config = PortalStorageConfig::new(
        trin_config.kb.into(),
        discovery.local_enr().node_id(),
        trin_config.enable_metrics_with_url.is_some(),
    )?;

    // Initialize validation oracle
    let master_accumulator = MasterAccumulator::try_from_file(trin_config.master_acc_path.clone())?;
    info!(
        "Loaded master accumulator from: {:?}",
        trin_config.master_acc_path
    );
    let header_oracle = HeaderOracle::new(trusted_provider.clone(), master_accumulator);
    let header_oracle = Arc::new(RwLock::new(header_oracle));

    // Initialize state sub-network service and event handlers, if selected
    let (state_handler, state_network_task, state_event_tx, _state_jsonrpc_tx) =
        if trin_config.networks.iter().any(|val| val == STATE_NETWORK) {
            initialize_state_network(
                &discovery,
                Arc::clone(&utp_socket),
                portalnet_config.clone(),
                storage_config.clone(),
                header_oracle.clone(),
            )
            .await?
        } else {
            (None, None, None, None)
        };

    // Initialize chain history sub-network service and event handlers, if selected
    let (history_handler, history_network_task, history_event_tx, history_jsonrpc_tx) =
        if trin_config
            .networks
            .iter()
            .any(|val| val == HISTORY_NETWORK)
        {
            initialize_history_network(
                &discovery,
                utp_socket,
                portalnet_config.clone(),
                storage_config.clone(),
                header_oracle.clone(),
            )
            .await?
        } else {
            (None, None, None, None)
        };

    // Launch JSON-RPC server
    let jsonrpc_trin_config = trin_config.clone();
    let jsonrpc_discovery = Arc::clone(&discovery);
    let rpc_handle =
        launch_jsonrpc_server(jsonrpc_trin_config, jsonrpc_discovery, history_jsonrpc_tx).await;

    if let Some(handler) = state_handler {
        tokio::spawn(handler.handle_client_queries());
    }
    if let Some(handler) = history_handler {
        tokio::spawn(handler.handle_client_queries());
    }

    // Spawn main portal events handler
    tokio::spawn(async move {
        let events = PortalnetEvents::new(
            talk_req_rx,
            history_event_tx,
            state_event_tx,
            utp_talk_reqs_tx,
        )
        .await;
        events.start().await;
    });

    if let Some(network) = history_network_task {
        tokio::spawn(async { network.await });
    }
    if let Some(network) = state_network_task {
        tokio::spawn(async { network.await });
    }

    Ok(rpc_handle?)
}

async fn launch_jsonrpc_server(
    trin_config: TrinConfig,
    discv5: Arc<Discovery>,
    history_handler: Option<mpsc::UnboundedSender<HistoryJsonRpcRequest>>,
) -> Result<ServerHandle, String> {
    let history_handler = history_handler.ok_or_else(|| {
        "History network must be available to use IPC transport for JSON-RPC server".to_string()
    })?;
    match trin_config.web3_transport {
        Web3TransportType::IPC => {
            // Launch jsonrpsee server with IPC transport
            let rpc_handle =
                JsonRpcServer::run_ipc(trin_config.web3_ipc_path, discv5, history_handler)
                    .await
                    .map_err(|e| format!("Launching IPC JSON-RPC server failed: {e:?}"))?;
            info!("IPC JSON-RPC server launched.");
            Ok(rpc_handle)
        }
        Web3TransportType::HTTP => {
            // Launch jsonrpsee server with http and WS transport
            let rpc_handle =
                JsonRpcServer::run_http(trin_config.web3_http_address, discv5, history_handler)
                    .await
                    .map_err(|e| format!("Launching HTTP JSON-RPC server failed: {e:?}"))?;
            info!("HTTP JSON-RPC server launched.");
            Ok(rpc_handle)
        }
    }
}
