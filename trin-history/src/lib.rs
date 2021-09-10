use log::info;
use serde_json::Value;
use tokio::sync::mpsc;

use trin_core::cli::TrinConfig;
use trin_core::portalnet::discovery::Discovery;
use trin_core::portalnet::protocol::{HistoryEndpointKind, HistoryNetworkEndpoint, PortalnetConfig, PortalnetEvents};
use trin_core::portalnet::overlay::OverlayProtocol;
use trin_core::utils::setup_overlay_db;
use std::sync::Arc;
use parking_lot::RwLock;

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

    info!(
        "About to spawn portal p2p with boot nodes: {:?}",
        portalnet_config.bootnode_enrs
    );

    let protocol_receiver = discovery
            .discv5
            .event_stream()
            .await
            .map_err(|e| e.to_string()).unwrap();

    tokio::spawn(async move {
        let discovery = Arc::new(discovery);
        let overlay = OverlayProtocol::new(discovery.clone(),portalnet_config.clone());
        let db = setup_overlay_db(discovery.local_enr());

        let events = PortalnetEvents {
            discovery,
            overlay,
            protocol_receiver,
            db,
        };
        // let events = PortalnetEvents::new(discovery, overlay.clone(), db).await;

        tokio::spawn(events.process_discv5_requests());

        // hacky test: make sure we establish a session with the boot node
        // overlay.ping_bootnodes().await.unwrap();

        tokio::signal::ctrl_c()
            .await
            .expect("failed to pause until ctrl-c");
    })
    .await
    .unwrap();

    Ok(())
}
