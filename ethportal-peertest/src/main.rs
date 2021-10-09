use ethportal_peertest::cli::PeertestConfig;
use ethportal_peertest::events::PortalnetEvents;
use log::info;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use trin_core::portalnet::utp::UtpListener;
use trin_core::portalnet::{
    discovery::Discovery,
    overlay::{OverlayConfig, OverlayProtocol},
    types::{PortalnetConfig, ProtocolKind},
    Enr, U256,
};
use trin_core::utils::setup_overlay_db;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    tokio::spawn(async move {
        let peertest_config = PeertestConfig::default();
        let portal_config = PortalnetConfig {
            listen_port: peertest_config.listen_port,
            ..Default::default()
        };

        let discovery = Arc::new(RwLock::new(Discovery::new(portal_config).unwrap()));
        discovery.write().await.start().await.unwrap();

        let protocol_receiver = discovery
            .write()
            .await
            .discv5
            .event_stream()
            .await
            .map_err(|e| e.to_string())
            .unwrap();

        let db = Arc::new(setup_overlay_db(
            discovery.read().await.local_enr().node_id(),
        ));

        let history_overlay = Arc::new(
            OverlayProtocol::new(
                OverlayConfig::default(),
                Arc::clone(&discovery),
                Arc::clone(&db),
                U256::max_value(),
                ProtocolKind::History,
            )
            .await,
        );

        let state_overlay = Arc::new(
            OverlayProtocol::new(
                OverlayConfig::default(),
                Arc::clone(&discovery),
                Arc::clone(&db),
                U256::max_value(),
                ProtocolKind::State,
            )
            .await,
        );

        let utp_listener = UtpListener {
            discovery: Arc::clone(&discovery),
            utp_connections: HashMap::new(),
        };

        let events = PortalnetEvents::new(
            Arc::clone(&history_overlay),
            Arc::clone(&state_overlay),
            protocol_receiver,
            utp_listener,
        )
        .await;

        tokio::spawn(events.process_discv5_requests());

        let target_node: Enr = peertest_config.target_node.parse().unwrap();

        // Test history and state network Ping request on target node
        info!("Pinging {} on history network", target_node);
        let ping_result = history_overlay
            .send_ping(target_node.clone())
            .await
            .unwrap();
        info!("History network Ping result: {:?}", ping_result);

        info!("Pinging {} on state network", target_node);
        let ping_result = state_overlay.send_ping(target_node.clone()).await.unwrap();
        info!("State network Ping result: {:?}", ping_result);

        tokio::signal::ctrl_c()
            .await
            .expect("failed to pause until ctrl-c");
    })
    .await
    .unwrap();

    Ok(())
}
