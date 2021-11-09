use std::collections::HashMap;
use std::env;
use std::sync::Arc;

use log::{debug, info};
use structopt::StructOpt;
use tokio::sync::mpsc;

use ethportal_peertest::cli::PeertestConfig;
use ethportal_peertest::events::PortalnetEvents;
use ethportal_peertest::jsonrpc::{
    test_jsonrpc_endpoints_over_http, test_jsonrpc_endpoints_over_ipc,
};
use trin_core::cli::TrinConfig;
use trin_core::jsonrpc::handlers::JsonRpcHandler;
use trin_core::jsonrpc::service::launch_jsonrpc_server;
use trin_core::jsonrpc::types::PortalJsonRpcRequest;
use trin_core::portalnet::{
    discovery::Discovery,
    overlay::{OverlayConfig, OverlayProtocol},
    types::{PortalnetConfig, ProtocolId},
    utp::UtpListener,
    U256,
};
use trin_core::utils::db::setup_overlay_db;
use trin_history::initialize_history_network;
use trin_state::initialize_state_network;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    tokio::spawn(async move {
        let peertest_config = PeertestConfig::default();
        let portal_config = PortalnetConfig {
            listen_port: peertest_config.listen_port,
            internal_ip: true,
            ..Default::default()
        };

        let mut discovery = Discovery::new(portal_config.clone()).unwrap();
        discovery.start().await.unwrap();
        let discovery = Arc::new(discovery);

        let protocol_rx = discovery
            .discv5
            .event_stream()
            .await
            .map_err(|e| e.to_string())
            .unwrap();

        let db = Arc::new(setup_overlay_db(discovery.local_enr().node_id()));

        let history_overlay = Arc::new(
            OverlayProtocol::new(
                OverlayConfig::default(),
                Arc::clone(&discovery),
                Arc::clone(&db),
                U256::max_value(),
                ProtocolId::History,
            )
            .await,
        );

        let state_overlay = Arc::new(
            OverlayProtocol::new(
                OverlayConfig::default(),
                Arc::clone(&discovery),
                Arc::clone(&db),
                U256::max_value(),
                ProtocolId::State,
            )
            .await,
        );

        let utp_listener = UtpListener {
            discovery: Arc::clone(&discovery),
            utp_connections: HashMap::new(),
        };

        let infura_project_id = match env::var("TRIN_INFURA_PROJECT_ID") {
            Ok(val) => val,
            Err(_) => panic!(
                "Must supply Infura key as environment variable, like:\n\
                TRIN_INFURA_PROJECT_ID=\"your-key-here\" trin"
            ),
        };

        // Initialize state sub-network service and event handlers, if selected
        let (state_handler, state_network_task, _state_event_tx, state_jsonrpc_tx) =
            initialize_state_network(&discovery, portal_config.clone(), Arc::clone(&db)).await;

        // Initialize chain history sub-network service and event handlers, if selected
        let (history_handler, history_network_task, _history_event_tx, history_jsonrpc_tx) =
            initialize_history_network(&discovery, portal_config.clone(), Arc::clone(&db)).await;

        // Initialize json-rpc server
        let (portal_jsonrpc_tx, portal_jsonrpc_rx) =
            mpsc::unbounded_channel::<PortalJsonRpcRequest>();
        let jsonrpc_trin_config = TrinConfig::from_iter(vec![
            "--internal-ip".to_string(),
            "--web3-transport".to_string(),
            "ipc".to_string(),
            "--web3-ipc-path".to_string(),
            peertest_config.web3_ipc_path.clone(),
            "--discovery-port".to_string(),
            peertest_config.listen_port.to_string(),
        ]);

        let (live_server_tx, mut live_server_rx) = tokio::sync::mpsc::channel::<bool>(1);

        let jsonrpc_server_task = tokio::task::spawn_blocking(|| {
            launch_jsonrpc_server(
                jsonrpc_trin_config,
                infura_project_id,
                portal_jsonrpc_tx,
                live_server_tx,
            );
        });

        while let Some(res) = live_server_rx.recv().await {
            debug!("JsonRPC server is available: {:?}", res);
            live_server_rx.close();
        }

        // Spawn main JsonRpc Handler
        let jsonrpc_discovery = Arc::clone(&discovery);
        let rpc_handler = JsonRpcHandler {
            discovery: jsonrpc_discovery,
            portal_jsonrpc_rx,
            state_jsonrpc_tx,
            history_jsonrpc_tx,
        };

        tokio::spawn(rpc_handler.process_jsonrpc_requests());
        tokio::spawn(state_handler.unwrap().handle_client_queries());
        tokio::spawn(history_handler.unwrap().handle_client_queries());

        let events = PortalnetEvents::new(
            Arc::clone(&history_overlay),
            Arc::clone(&state_overlay),
            protocol_rx,
            utp_listener,
        )
        .await;

        tokio::spawn(events.process_discv5_requests());
        tokio::spawn(async { history_network_task.unwrap().await });
        tokio::spawn(async { state_network_task.unwrap().await });
        tokio::spawn(async { jsonrpc_server_task.await.unwrap() });
        match peertest_config.target_transport.as_str() {
            "ipc" => test_jsonrpc_endpoints_over_ipc(peertest_config).await,
            "http" => test_jsonrpc_endpoints_over_http(peertest_config).await,
            _ => panic!(
                "Invalid target-transport provided: {:?}",
                peertest_config.target_transport
            ),
        }

        info!("All tests passed successfully!");
        std::process::exit(1);
    })
    .await
    .unwrap();

    Ok(())
}
