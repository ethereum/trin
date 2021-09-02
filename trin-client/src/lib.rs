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

// the purpose of trin-client is to act as a orchestrator for the various networks
// - trin client is meant to be an ultra-thin wrapper against only the bare minimum
//      logic necessary for interprocess communication
//
// trin-client responsibilities might include...
// - starting up base layer discv5 protocol and passing handle to selected networks
//      - sub-networks can use this base layer protocol to build their overlay networks
// - connecting to database and passing handle to selected networks
//      - does each network maintain its own db & db connection?
// - starting up the jsonrpc handler (with infura req handler)
//      - starting up individual binaries will *not* have jsonrpc
// - starting up message channels (maybe dbus protocol) for cross-network communication

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

    // get rid of mut
    let mut history_tx = None;
    let mut history_handler: Option<HistoryRequestHandler> = None;
    let mut state_tx = None;
    let mut state_handler: Option<StateRequestHandler> = None;
    if trin_config.networks.iter().any(|val| val == "history") {
        println!("starting history network");
        // create history msg channel
        let (raw_history_tx, history_rx) = mpsc::unbounded_channel::<HistoryNetworkEndpoint>();
        history_tx = Some(raw_history_tx);
        history_handler = Some(trin_history::initialize(history_rx).unwrap());
    }

    if trin_config.networks.iter().any(|val| val == "state") {
        println!("starting state network");
        // create state msg channel
        let (raw_state_tx, state_rx) = mpsc::unbounded_channel::<StateNetworkEndpoint>();
        state_tx = Some(raw_state_tx);
        state_handler = Some(trin_state::initialize(state_rx).unwrap());
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
        if state_handler.is_some() {
            tokio::spawn(state_handler.unwrap().process_network_requests());
        }
        if history_handler.is_some() {
            tokio::spawn(history_handler.unwrap().process_network_requests());
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
