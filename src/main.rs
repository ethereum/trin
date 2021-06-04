#[macro_use]
extern crate lazy_static;
extern crate log;
extern crate stunclient;
extern crate tracing;

mod cli;
use cli::TrinConfig;
mod jsonrpc;
use jsonrpc::launch_trin;
use log::info;
use std::env;

mod portalnet;
use portalnet::protocol::{PortalnetConfig, PortalnetProtocol};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let trin_config = TrinConfig::new();

    let infura_project_id = match env::var("TRIN_INFURA_PROJECT_ID") {
        Ok(val) => val,
        Err(_) => panic!(
            "Must supply Infura key as environment variable, like:\n\
            TRIN_INFURA_PROJECT_ID=\"your-key-here\" trin"
        ),
    };

    let listen_port = trin_config.discovery_port;
    let bootnode_enrs = trin_config
        .bootnodes
        .iter()
        .map(|nodestr| nodestr.parse().unwrap())
        .collect();

    let portalnet_config = PortalnetConfig {
        listen_port,
        bootnode_enrs,
        ..Default::default()
    };

    let web3_server_task = tokio::task::spawn_blocking(|| {
        launch_trin(trin_config, infura_project_id);
    });

    info!(
        "About to spawn portal p2p with boot nodes: {:?}",
        portalnet_config.bootnode_enrs
    );
    tokio::spawn(async move {
        let (mut p2p, events) = PortalnetProtocol::new(portalnet_config).await.unwrap();

        tokio::spawn(events.process_requests());

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
