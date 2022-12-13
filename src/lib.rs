use std::sync::Arc;

use ethportal_api::jsonrpsee::server::ServerHandle;
use rpc::JsonRpcServer;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn};

use trin_core::jsonrpc::types::HistoryJsonRpcRequest;
use trin_core::{
    cli::{TrinConfig, HISTORY_NETWORK, STATE_NETWORK},
    portalnet::{
        discovery::Discovery, events::PortalnetEvents, storage::PortalStorageConfig,
        types::messages::PortalnetConfig,
    },
    types::{accumulator::MasterAccumulator, bridge::Bridge, validation::HeaderOracle},
    utils::{bootnodes::parse_bootnodes, db::setup_temp_dir, provider::TrustedProvider},
    utp::stream::UtpListener,
};
use trin_history::initialize_history_network;
use trin_state::initialize_state_network;

pub async fn run_trin(
    trin_config: TrinConfig,
    trusted_provider: TrustedProvider,
) -> Result<ServerHandle, Box<dyn std::error::Error>> {
    info!(config = %trin_config, "Launching trin");

    let bootnode_enrs = parse_bootnodes(&trin_config.bootnodes)?;
    let portalnet_config = PortalnetConfig {
        external_addr: trin_config.external_addr,
        private_key: trin_config.private_key.clone(),
        listen_port: trin_config.discovery_port,
        no_stun: trin_config.no_stun,
        enable_metrics: trin_config.enable_metrics_with_url.is_some(),
        bootnode_enrs,
        ..Default::default()
    };

    // Initialize base discovery protocol
    let mut discovery = Discovery::new(portalnet_config.clone()).unwrap();
    let talk_req_rx = discovery.start().await.unwrap();
    let discovery = Arc::new(discovery);

    // Initialize prometheus metrics
    if let Some(addr) = trin_config.enable_metrics_with_url {
        prometheus_exporter::start(addr).unwrap();
    }

    // Initialize and spawn UTP listener
    let (utp_events_tx, utp_listener_tx, utp_listener_rx, mut utp_listener) =
        UtpListener::new(Arc::clone(&discovery));
    tokio::spawn(async move { utp_listener.start().await });

    // Initialize Storage config
    if trin_config.ephemeral {
        setup_temp_dir();
    }

    let storage_config = PortalStorageConfig::new(
        trin_config.kb.into(),
        discovery.local_enr().node_id(),
        trin_config.enable_metrics_with_url.is_some(),
    );

    // Initialize validation oracle
    let master_accumulator = MasterAccumulator::try_from_file(trin_config.master_acc_path.clone())?;
    info!(
        "Loaded master accumulator from: {:?}",
        trin_config.master_acc_path
    );
    let header_oracle = HeaderOracle::new(trusted_provider.clone(), master_accumulator);
    let header_oracle = Arc::new(RwLock::new(header_oracle));

    // Initialize state sub-network service and event handlers, if selected
    let (state_handler, state_network_task, state_event_tx, state_utp_tx, _state_jsonrpc_tx) =
        if trin_config.networks.iter().any(|val| val == STATE_NETWORK) {
            initialize_state_network(
                &discovery,
                utp_listener_tx.clone(),
                portalnet_config.clone(),
                storage_config.clone(),
                header_oracle.clone(),
            )
            .await
        } else {
            (None, None, None, None, None)
        };

    // Initialize chain history sub-network service and event handlers, if selected
    let (
        history_handler,
        history_network_task,
        history_event_tx,
        history_utp_tx,
        history_jsonrpc_tx,
    ) = if trin_config
        .networks
        .iter()
        .any(|val| val == HISTORY_NETWORK)
    {
        initialize_history_network(
            &discovery,
            utp_listener_tx,
            portalnet_config.clone(),
            storage_config.clone(),
            header_oracle.clone(),
        )
        .await
    } else {
        (None, None, None, None, None)
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
            utp_listener_rx,
            history_event_tx,
            history_utp_tx,
            state_event_tx,
            state_utp_tx,
            utp_events_tx,
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
    if let Some(mode) = trin_config.bridge {
        if trin_config.kb > 0 {
            warn!("It's strongly recommended to run bridge node with kb=0 flag.");
        }
        if trin_config.epoch_acc_path.is_none() {
            warn!(
                "It's strongly recommended to run bridge node with a local epoch acc repo,
                avoiding uncessary network traffic"
            );
        }
        let bridge = Bridge {
            header_oracle: header_oracle.clone(),
            mode,
            epoch_acc_path: trin_config.epoch_acc_path,
        };
        tokio::spawn(async move { bridge.launch().await });
    }

    Ok(rpc_handle)
}

// FIXME: Handle those unwraps in this method
async fn launch_jsonrpc_server(
    trin_config: TrinConfig,
    discv5: Arc<Discovery>,
    history_handler: Option<UnboundedSender<HistoryJsonRpcRequest>>,
) -> ServerHandle {
    match trin_config.web3_transport.as_str() {
        "ipc" => {
            // Launch jsonrpsee server with http and WS transport
            let rpc_handle =
                JsonRpcServer::run_ipc(trin_config.web3_ipc_path, discv5, history_handler.unwrap())
                    .await
                    .unwrap();
            info!("IPC JSON-RPC server launched.");
            rpc_handle
        }
        "http" => {
            // Launch jsonrpsee server with http and WS transport
            let rpc_handle = JsonRpcServer::run_http(
                trin_config.web3_http_address,
                discv5,
                history_handler.unwrap(),
            )
            .await
            .unwrap();
            info!("HTTP JSON-RPC server launched.");
            rpc_handle
        }
        val => panic!("Unsupported web3 transport: {val}"),
    }
}
