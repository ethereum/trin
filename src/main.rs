use std::env;
use std::sync::Arc;

use log::debug;
use tokio::sync::mpsc;
use tokio::sync::RwLock;

use trin_core::jsonrpc::handlers::JsonRpcHandler;
use trin_core::jsonrpc::types::PortalJsonRpcRequest;
use trin_core::portalnet::events::PortalnetEvents;
use trin_core::{
    cli::{TrinConfig, HISTORY_NETWORK, STATE_NETWORK},
    jsonrpc::service::launch_jsonrpc_server,
    portalnet::{discovery::Discovery, types::PortalnetConfig},
    utils::setup_overlay_db,
};
use trin_history::initialize_history_network;
use trin_state::initialize_state_network;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    println!("Launching trin");

    let trin_config = TrinConfig::new();
    trin_config.display_config();

    let infura_project_id = match env::var("TRIN_INFURA_PROJECT_ID") {
        Ok(val) => val,
        Err(_) => panic!(
            "Must supply Infura key as environment variable, like:\n\
            TRIN_INFURA_PROJECT_ID=\"your-key-here\" trin"
        ),
    };

    let bootnode_enrs = trin_config
        .bootnodes
        .iter()
        .map(|nodestr| nodestr.parse().unwrap())
        .collect();

    let portalnet_config = PortalnetConfig {
        external_addr: trin_config.external_addr,
        private_key: trin_config.private_key.clone(),
        listen_port: trin_config.discovery_port,
        bootnode_enrs,
        ..Default::default()
    };

    // Initialize base discovery protocol
    let discovery = Arc::new(RwLock::new(
        Discovery::new(portalnet_config.clone()).unwrap(),
    ));
    discovery.write().await.start().await.unwrap();

    // Setup Overlay database
    let db = Arc::new(setup_overlay_db(
        discovery.read().await.local_enr().node_id(),
    ));

    debug!("Selected networks to spawn: {:?}", trin_config.networks);
    // Initialize state sub-network service and event handlers, if selected
    let (state_handler, state_network_task, state_event_tx, state_jsonrpc_tx) =
        if trin_config.networks.iter().any(|val| val == STATE_NETWORK) {
            initialize_state_network(&discovery, portalnet_config.clone(), Arc::clone(&db)).await
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
            initialize_history_network(&discovery, portalnet_config.clone(), Arc::clone(&db)).await
        } else {
            (None, None, None, None)
        };

    // Initialize json-rpc server
    let (portal_jsonrpc_tx, portal_jsonrpc_rx) = mpsc::unbounded_channel::<PortalJsonRpcRequest>();
    let jsonrpc_trin_config = trin_config.clone();
    let jsonrpc_server_task = tokio::task::spawn_blocking(|| {
        launch_jsonrpc_server(jsonrpc_trin_config, infura_project_id, portal_jsonrpc_tx);
    });

    // Spawn main JsonRpc Handler
    let jsonrpc_discovery = Arc::clone(&discovery);
    let rpc_handler = JsonRpcHandler {
        discovery: jsonrpc_discovery,
        portal_jsonrpc_rx,
        state_jsonrpc_tx,
        history_jsonrpc_tx,
    };

    tokio::spawn(rpc_handler.process_jsonrpc_requests());

    if let Some(handler) = state_handler {
        tokio::spawn(handler.handle_client_queries());
    }
    if let Some(handler) = history_handler {
        tokio::spawn(handler.handle_client_queries());
    }

    let portal_events_discovery = Arc::clone(&discovery);

    tokio::spawn(async move {
        let events =
            PortalnetEvents::new(portal_events_discovery, history_event_tx, state_event_tx).await;
        events.process_discv5_requests().await;
    });

    if let Some(network) = history_network_task {
        tokio::spawn(async { network.await });
    }
    if let Some(network) = state_network_task {
        tokio::spawn(async { network.await });
    }

    jsonrpc_server_task.await.unwrap();

    tokio::signal::ctrl_c()
        .await
        .expect("failed to pause until ctrl-c");
    Ok(())
}
