pub mod events;
pub mod network;

use log::info;
use serde_json::Value;
use tokio::sync::mpsc;

use crate::events::HistoryEvents;
use discv5::TalkRequest;
use network::HistoryNetwork;
use std::sync::Arc;
use tokio::sync::RwLock;
use trin_core::cli::TrinConfig;
use trin_core::portalnet::discovery::Discovery;
use trin_core::portalnet::events::PortalnetEvents;
use trin_core::portalnet::protocol::{
    HistoryEndpointKind, HistoryNetworkEndpoint, PortalnetConfig,
};
use trin_core::utils::setup_overlay_db;

pub struct HistoryRequestHandler {
    pub history_rx: mpsc::UnboundedReceiver<HistoryNetworkEndpoint>,
}

impl HistoryRequestHandler {
    pub async fn handle_client_queries(mut self) {
        while let Some(cmd) = self.history_rx.recv().await {
            use HistoryEndpointKind::*;

            match cmd.kind {
                GetHistoryNetworkData => {
                    let _ = cmd
                        .resp
                        .send(Ok(Value::String("0xmockhistorydata".to_string())));
                }
            }
        }
    }
}

pub fn initialize(
    history_rx: mpsc::UnboundedReceiver<HistoryNetworkEndpoint>,
) -> Result<HistoryRequestHandler, Box<dyn std::error::Error>> {
    let handler = HistoryRequestHandler { history_rx };
    Ok(handler)
}

pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Launching trin-history...");

    let mut trin_config = TrinConfig::new();

    // Set chain history default params
    trin_config.discovery_port = 9001;

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
        "About to spawn History network with boot nodes: {:?}",
        portalnet_config.bootnode_enrs
    );

    let (history_sender, history_receiver) = mpsc::unbounded_channel::<TalkRequest>();
    let portal_events_discovery = Arc::clone(&discovery);

    // Spawn main event handler
    tokio::spawn(async move {
        let events =
            PortalnetEvents::new(portal_events_discovery, Some(history_sender), None).await;
        events.process_discv5_requests().await;
    });

    // Spawn History network
    tokio::spawn(async move {
        let mut p2p = HistoryNetwork::new(discovery.clone(), portalnet_config)
            .await
            .unwrap();

        let history_events = HistoryEvents {
            network: p2p.clone(),
            db,
            event_rx: history_receiver,
        };

        // Spawn history event handler
        tokio::spawn(history_events.process_requests());

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
