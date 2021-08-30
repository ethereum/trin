use std::env;

use log::info;
use tokio::sync::mpsc;

use trin_core::cli::TrinConfig;
use trin_core::jsonrpc::launch_trin;
use trin_core::portalnet::protocol::{
    JsonRpcHandler, PortalEndpoint, PortalnetConfig, PortalnetProtocol,
};

pub mod types;

pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Launching trin-history...");

    let mut trin_config = TrinConfig::new();

    // Set chain history default params
    trin_config.discovery_port = 9001;
    trin_config.web3_ipc_path = String::from("/tmp/trin-history-jsonrpc.ipc");

    if trin_config.web3_transport == "http" {
        trin_config.web3_http_port = 8555;
    }

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

    let (jsonrpc_tx, jsonrpc_rx) = mpsc::unbounded_channel::<PortalEndpoint>();

    let web3_server_task = tokio::task::spawn_blocking(|| {
        launch_trin(trin_config, infura_project_id, jsonrpc_tx);
    });

    info!(
        "About to spawn portal p2p with boot nodes: {:?}",
        portalnet_config.bootnode_enrs
    );

    tokio::spawn(async move {
        let (mut p2p, events) = PortalnetProtocol::new(portalnet_config).await.unwrap();

        let rpc_handler = JsonRpcHandler {
            discovery: p2p.discovery.clone(),
            jsonrpc_rx,
        };

        tokio::spawn(events.process_discv5_requests());
        tokio::spawn(rpc_handler.process_jsonrpc_requests());

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
