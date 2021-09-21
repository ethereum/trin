use log::info;
use serde_json::Value;
use tokio::sync::mpsc;

use crate::events::StateEvents;
use discv5::TalkRequest;
use network::StateNetwork;
use std::sync::Arc;
use tokio::sync::RwLock;
use trin_core::cli::TrinConfig;
use trin_core::jsonrpc::handlers::{StateEndpointKind, StateNetworkEndpoint};
use trin_core::portalnet::discovery::Discovery;
use trin_core::portalnet::events::PortalnetEvents;
use trin_core::portalnet::overlay::PortalnetConfig;
use trin_core::utils::setup_overlay_db;

pub mod events;
pub mod network;
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
    let discovery = Arc::new(RwLock::new(discovery));

    // Setup Overlay database
    let db = Arc::new(setup_overlay_db(discovery.read().await.local_enr()));

    info!(
        "About to spawn State network with boot nodes: {:?}",
        portalnet_config.bootnode_enrs
    );

    let (state_sender, state_receiver) = mpsc::unbounded_channel::<TalkRequest>();
    let portal_events_discovery = Arc::clone(&discovery);

    // Spawn main event handler
    tokio::spawn(async move {
        let events = PortalnetEvents::new(portal_events_discovery, None, Some(state_sender)).await;
        events.process_discv5_requests().await;
    });

    tokio::spawn(async move {
        let mut p2p = StateNetwork::new(discovery, portalnet_config)
            .await
            .unwrap();

        let state_events = StateEvents {
            network: p2p.clone(),
            db,
            event_rx: state_receiver,
        };

        // Spawn state event handler
        tokio::spawn(state_events.process_requests());

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
