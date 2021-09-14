use log::info;
use serde_json::Value;
use tokio::sync::mpsc;

use trin_core::cli::TrinConfig;
use trin_core::portalnet::discovery::Discovery;
use trin_core::portalnet::protocol::{
    PortalnetConfig, PortalnetProtocol, StateEndpointKind, StateNetworkEndpoint,
};

pub mod utils;

pub struct StateRequestHandler {
    pub state_rx: mpsc::UnboundedReceiver<StateNetworkEndpoint>,
}

impl StateRequestHandler {
    pub async fn handle_client_queries(mut self) {
        while let Some(cmd) = self.state_rx.recv().await {
            use StateEndpointKind::*;

            match cmd.kind {
                GetStateNetworkData => {
                    let _ = cmd
                        .resp
                        .send(Ok(Value::String("0xmockstatedata".to_string())));
                }
            }
        }
    }
}

pub fn initialize(
    state_rx: mpsc::UnboundedReceiver<StateNetworkEndpoint>,
) -> Result<StateRequestHandler, Box<dyn std::error::Error>> {
    let handler = StateRequestHandler { state_rx };
    Ok(handler)
}

pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Launching trin-state...");

    let trin_config = TrinConfig::new();
    trin_config.display_config();

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

    let mut discovery = Discovery::new(portalnet_config.clone()).unwrap();
    discovery.start().await.unwrap();

    info!(
        "About to spawn portal p2p with boot nodes: {:?}",
        portalnet_config.bootnode_enrs
    );

    tokio::spawn(async move {
        let (mut p2p, events) = PortalnetProtocol::new(discovery, portalnet_config)
            .await
            .unwrap();

        tokio::spawn(events.process_discv5_requests());

        // hacky test: make sure we establish a session with the boot node
        p2p.ping_bootnodes().await.unwrap();

        tokio::signal::ctrl_c()
            .await
            .expect("failed to pause until ctrl-c");
    })
    .await
    .unwrap();

    Ok(())
}
