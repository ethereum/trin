use std::env;

use log::{debug, error, info};
use tokio::sync::mpsc;
use tokio::sync::RwLock;

use std::sync::Arc;
use trin_core::{
    cli::{TrinConfig, HISTORY_NETWORK, STATE_NETWORK},
    jsonrpc::launch_jsonrpc_server,
    portalnet::{
        discovery::Discovery,
        protocol::{
            HistoryNetworkEndpoint, JsonRpcHandler, PortalEndpoint, PortalnetConfig,
            StateNetworkEndpoint,
        },
    },
    utils::setup_overlay_db,
};
use trin_history::network::HistoryNetwork;
use trin_state::network::StateNetwork;

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

    // Initialize state sub-network jsonrpc handler, if selected
    let (state_tx, state_handler) = if trin_config.networks.iter().any(|val| val == STATE_NETWORK) {
        let (state_tx, state_rx) = mpsc::unbounded_channel::<StateNetworkEndpoint>();
        let state_handler = match trin_state::initialize(state_rx) {
            Ok(val) => val,
            Err(msg) => panic!("Error while initializing state network: {:?}", msg),
        };
        (Some(state_tx), Some(state_handler))
    } else {
        (None, None)
    };

    // Initialize chain history sub-network jsonrpc handler, if selected
    let (history_tx, history_handler) = if trin_config
        .networks
        .iter()
        .any(|val| val == HISTORY_NETWORK)
    {
        let (history_tx, history_rx) = mpsc::unbounded_channel::<HistoryNetworkEndpoint>();
        let history_handler = match trin_history::initialize(history_rx) {
            Ok(val) => val,
            Err(msg) => panic!("Error while initializing chain history network: {:?}", msg),
        };
        (Some(history_tx), Some(history_handler))
    } else {
        (None, None)
    };

    // Initialize jsonrpc server
    let (jsonrpc_tx, jsonrpc_rx) = mpsc::unbounded_channel::<PortalEndpoint>();
    let jsonrpc_trin_config = trin_config.clone();
    let web3_server_task = tokio::task::spawn_blocking(|| {
        launch_jsonrpc_server(jsonrpc_trin_config, infura_project_id, jsonrpc_tx);
    });

    // Setup Overlay database
    let db = Arc::new(setup_overlay_db(discovery.read().await.local_enr()));

    // Spawn main JsonRpc Handler
    let jsonrpc_discovery = Arc::clone(&discovery);
    tokio::spawn(async move {
        let rpc_handler = JsonRpcHandler {
            discovery: jsonrpc_discovery,
            jsonrpc_rx,
            state_tx,
            history_tx,
        };

        tokio::spawn(rpc_handler.process_jsonrpc_requests());

        if let Some(handler) = state_handler {
            tokio::spawn(handler.handle_client_queries());
        }
        if let Some(handler) = history_handler {
            tokio::spawn(handler.handle_client_queries());
        }
    });

    debug!("Selected networks to spawn: {:?}", trin_config.networks);

    for network in trin_config.networks.iter() {
        match network.as_str() {
            STATE_NETWORK => {
                let state_network_discovery = Arc::clone(&discovery);
                let state_network_db = Arc::clone(&db);
                let portalnet_config_state = portalnet_config.clone();

                // Spawn State network
                tokio::spawn(async move {
                    info!(
                        "About to spawn State Network with boot nodes: {:?}",
                        portalnet_config_state.bootnode_enrs
                    );

                    let (mut p2p, events) = StateNetwork::new(
                        state_network_discovery,
                        state_network_db,
                        portalnet_config_state,
                    )
                    .await
                    .unwrap();

                    tokio::spawn(events.process_discv5_requests());

                    // hacky test: make sure we establish a session with the boot node
                    p2p.ping_bootnodes().await.unwrap();
                })
                .await
                .unwrap();
            }
            HISTORY_NETWORK => {
                let history_network_discovery = Arc::clone(&discovery);
                let history_network_db = Arc::clone(&db);
                let portalnet_config_history = portalnet_config.clone();

                // Spawn History network
                tokio::spawn(async move {
                    info!(
                        "About to spawn History Network with boot nodes: {:?}",
                        portalnet_config_history.bootnode_enrs
                    );

                    let (mut p2p, _events) = HistoryNetwork::new(
                        history_network_discovery,
                        history_network_db,
                        portalnet_config_history,
                    )
                    .await
                    .unwrap();

                    // tokio::spawn(events.process_discv5_requests());

                    // hacky test: make sure we establish a session with the boot node
                    p2p.ping_bootnodes().await.unwrap();
                })
                .await
                .unwrap();
            }
            other => {
                error!("{} is unsupported network! Terminating Trin...", other);
                std::process::exit(1);
            }
        }
    }

    web3_server_task.await.unwrap();

    tokio::signal::ctrl_c()
        .await
        .expect("failed to pause until ctrl-c");
    Ok(())
}
