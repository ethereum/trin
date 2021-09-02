use std::env;

use log::info;
use tokio::sync::mpsc;

use trin_core::cli::TrinConfig;
use trin_core::jsonrpc::launch_jsonrpc_server;
use trin_core::portalnet::protocol::{
    HistoryNetworkEndpoint, JsonRpcHandler, PortalEndpoint, PortalnetConfig, PortalnetProtocol,
    StateNetworkEndpoint,
};
use trin_history::HistoryRequestHandler;
use trin_state::StateRequestHandler;

pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    let mut state_tx = None;
    let mut history_tx = None;
    let mut state_handler: Option<StateRequestHandler> = None;
    let mut history_handler: Option<HistoryRequestHandler> = None;

    if trin_config.networks.iter().any(|val| val == "history") {
        let (raw_history_tx, history_rx) = mpsc::unbounded_channel::<HistoryNetworkEndpoint>();
        history_tx = Some(raw_history_tx);
        history_handler = match trin_history::initialize(history_rx) {
            Ok(val) => Some(val),
            Err(msg) => panic!("Error while initializing history network: {:?}", msg),
        }
    }

    if trin_config.networks.iter().any(|val| val == "state") {
        let (raw_state_tx, state_rx) = mpsc::unbounded_channel::<StateNetworkEndpoint>();
        state_tx = Some(raw_state_tx);
        state_handler = match trin_state::initialize(state_rx) {
            Ok(val) => Some(val),
            Err(msg) => panic!("Error while initializing state network: {:?}", msg),
        }
    }

    let (jsonrpc_tx, jsonrpc_rx) = mpsc::unbounded_channel::<PortalEndpoint>();
    let web3_server_task = tokio::task::spawn_blocking(|| {
        launch_jsonrpc_server(trin_config, infura_project_id, jsonrpc_tx);
    });

    tokio::spawn(async move {
        info!(
            "About to spawn portal p2p with boot nodes: {:?}",
            portalnet_config.bootnode_enrs
        );

        let (mut p2p, events) = PortalnetProtocol::new(portalnet_config).await.unwrap();

        let rpc_handler = JsonRpcHandler {
            discovery: p2p.discovery.clone(),
            jsonrpc_rx,
            state_tx,
            history_tx,
        };

        tokio::spawn(events.process_discv5_requests());
        tokio::spawn(rpc_handler.process_jsonrpc_requests());
        if let Some(handler) = state_handler {
            tokio::spawn(handler.handle_client_queries());
        }
        if let Some(handler) = history_handler {
            tokio::spawn(handler.handle_client_queries());
        }

        // hacky test: make sure we establish a session with the boot node
        p2p.ping_bootnodes().await.unwrap();

        tokio::signal::ctrl_c()
            .await
            .expect("failed to pause until ctrl-c");
    })
    .await
    .unwrap();

    web3_server_task.await.unwrap();
    Ok(())
}
