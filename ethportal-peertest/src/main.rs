use std::collections::HashMap;
use std::sync::Arc;

use log::info;
use tokio::sync::RwLock;

use ethportal_peertest::cli::PeertestConfig;
use ethportal_peertest::events::PortalnetEvents;
use ethportal_peertest::jsonrpc::{
    test_jsonrpc_endpoints_over_http, test_jsonrpc_endpoints_over_ipc,
};
use trin_core::locks::RwLoggingExt;
use trin_core::portalnet::{
    discovery::Discovery,
    overlay::{OverlayConfig, OverlayProtocol},
    types::{PortalnetConfig, ProtocolId},
    utp::UtpListener,
    Enr, U256,
};
use trin_core::utils::db::setup_overlay_db;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    tokio::spawn(async move {
        let peertest_config = PeertestConfig::default();
        let portal_config = PortalnetConfig {
            listen_port: peertest_config.listen_port,
            internal_ip: true,
            ..Default::default()
        };

        let discovery = Arc::new(RwLock::new(Discovery::new(portal_config).unwrap()));
        discovery.write_with_warn().await.start().await.unwrap();

        let db = Arc::new(setup_overlay_db(
            discovery.read_with_warn().await.local_enr().node_id(),
        ));

        let overlay = Arc::new(
            OverlayProtocol::new(
                OverlayConfig::default(),
                Arc::clone(&discovery),
                db,
                U256::max_value(),
            )
            .await,
        );

        let utp_listener = UtpListener {
            discovery: Arc::clone(&discovery),
            utp_connections: HashMap::new(),
        };

        let events = PortalnetEvents::new(Arc::clone(&overlay), utp_listener).await;

        tokio::spawn(events.process_discv5_requests());

        let target_node: Enr = peertest_config.target_node.parse().unwrap();

        // Test history and state network Ping request on target node
        info!("Pinging {} on history network", target_node);
        let ping_result = overlay
            .send_ping(
                U256::from(u64::MAX),
                target_node.clone(),
                ProtocolId::History,
                None,
            )
            .await;
        match ping_result {
            Ok(val) => info!("Successful ping to History network: {:?}", val),
            Err(msg) => panic!("Invalid ping to History network: {:?}", msg),
        }

        info!("Pinging {} on state network", target_node);
        let ping_result = overlay
            .send_ping(
                U256::from(u64::MAX),
                target_node.clone(),
                ProtocolId::State,
                None,
            )
            .await;
        match ping_result {
            Ok(val) => info!("Successful ping to State network: {:?}", val),
            Err(msg) => panic!("Invalid ping to State network: {:?}", msg),
        }

        match peertest_config.target_transport.as_str() {
            "ipc" => test_jsonrpc_endpoints_over_ipc(peertest_config.target_ipc_path).await,
            "http" => test_jsonrpc_endpoints_over_http(peertest_config.target_http_address).await,
            _ => panic!(
                "Invalid target-transport provided: {:?}",
                peertest_config.target_transport
            ),
        }

        info!("All tests passed successfully!");
        std::process::exit(1);
    })
    .await
    .unwrap();

    Ok(())
}
