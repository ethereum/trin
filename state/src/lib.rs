use std::env;

use log::info;
use tokio::sync::mpsc;

use trin_core::cli::TrinConfig;
use trin_core::jsonrpc::launch_trin;
use trin_core::portalnet::protocol::{PortalEndpoint, PortalnetConfig, PortalnetProtocol};

pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let trin_config = TrinConfig::new();

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
        let (mut p2p, events, rpc_handler) = PortalnetProtocol::new(portalnet_config, jsonrpc_rx)
            .await
            .unwrap();

        tokio::join!(
            events.process_discv5_requests(),
            rpc_handler.process_jsonrpc_requests()
        );

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
