use std::str::FromStr;
use std::sync::Arc;

use trin_core::{
    portalnet::{
        discovery::Discovery,
        overlay::{OverlayConfig, OverlayProtocol},
        types::{
            messages::{Message, PortalnetConfig, ProtocolId, SszEnr},
            uint::U256,
        },
    },
    utils::db::setup_overlay_db,
};

use discv5::Discv5Event;
use tokio::sync::mpsc;
use tokio::time::{self, Duration};

async fn init_overlay(discovery: Arc<Discovery>, protocol: ProtocolId) -> OverlayProtocol {
    let db = Arc::new(setup_overlay_db(discovery.local_enr().node_id()));
    let overlay_config = OverlayConfig::default();
    OverlayProtocol::new(overlay_config, discovery, db, U256::MAX, protocol).await
}

async fn spawn_overlay(discovery: Arc<Discovery>, overlay: Arc<OverlayProtocol>) {
    let (overlay_tx, mut overlay_rx) = mpsc::unbounded_channel();
    let mut discovery_rx = discovery
        .discv5
        .event_stream()
        .await
        .map_err(|err| err.to_string())
        .unwrap();

    let overlay_protocol = overlay.protocol().clone();
    tokio::spawn(async move {
        while let Some(discovery_event) = discovery_rx.recv().await {
            let talk_req = match discovery_event {
                Discv5Event::TalkRequest(req) => req,
                _ => continue,
            };

            let req_protocol = ProtocolId::from_str(&hex::encode_upper(talk_req.protocol()));

            if let Ok(req_protocol) = req_protocol {
                match (req_protocol, overlay_protocol.clone()) {
                    (ProtocolId::History, ProtocolId::History)
                    | (ProtocolId::State, ProtocolId::State) => overlay_tx.send(talk_req).unwrap(),
                    _ => panic!("Unexpected protocol"),
                }
            } else {
                panic!("Invalid protocol");
            }
        }
    });

    tokio::spawn(async move {
        while let Some(talk_req) = overlay_rx.recv().await {
            let talk_resp = match overlay.process_one_request(&talk_req).await {
                Ok(response) => Message::Response(response).to_bytes(),
                Err(err) => panic!("Error processing request: {}", err),
            };
            if let Err(err) = talk_req.respond(talk_resp) {
                panic!("Unable to respond to talk request: {}", err);
            }
        }
    });
}

// Basic tests for overlay routing table management according to messages exchanged between
// multiple nodes.
//
// Use sleeps to give time for background routing table processes.
#[tokio::test]
async fn overlay() {
    let protocol = ProtocolId::History;

    // Node one.
    let portal_config_one = PortalnetConfig {
        listen_port: 8001,
        internal_ip: true,
        ..PortalnetConfig::default()
    };
    let mut discovery_one = Discovery::new(portal_config_one).unwrap();
    let _ = discovery_one.start().await.unwrap();
    let discovery_one = Arc::new(discovery_one);
    let overlay_one = Arc::new(init_overlay(Arc::clone(&discovery_one), protocol.clone()).await);
    spawn_overlay(Arc::clone(&discovery_one), Arc::clone(&overlay_one)).await;
    time::sleep(Duration::from_millis(5)).await;

    // Node two.
    let portal_config_two = PortalnetConfig {
        listen_port: 8002,
        internal_ip: true,
        ..PortalnetConfig::default()
    };
    let mut discovery_two = Discovery::new(portal_config_two).unwrap();
    let _ = discovery_two.start().await.unwrap();
    let discovery_two = Arc::new(discovery_two);
    let overlay_two = Arc::new(init_overlay(Arc::clone(&discovery_two), protocol.clone()).await);
    spawn_overlay(Arc::clone(&discovery_two), Arc::clone(&overlay_two)).await;
    time::sleep(Duration::from_millis(5)).await;

    // Node three.
    let portal_config_three = PortalnetConfig {
        listen_port: 8003,
        internal_ip: true,
        ..PortalnetConfig::default()
    };
    let mut discovery_three = Discovery::new(portal_config_three).unwrap();
    let _ = discovery_three.start().await.unwrap();
    let discovery_three = Arc::new(discovery_three);
    let overlay_three =
        Arc::new(init_overlay(Arc::clone(&discovery_three), protocol.clone()).await);
    spawn_overlay(Arc::clone(&discovery_three), Arc::clone(&overlay_three)).await;
    time::sleep(Duration::from_millis(5)).await;

    // Node two routing table is empty.
    let overlay_two_peers = overlay_two.table_entries_enr();
    assert!(overlay_two_peers.is_empty());

    // Ping node one from node two.
    // Node one should be in node two's routing table.
    match overlay_two.send_ping(overlay_one.local_enr()).await {
        Ok(pong) => {
            assert_eq!(1, pong.enr_seq);
        }
        Err(err) => panic!("Unable to respond to ping: {}", err),
    }
    time::sleep(Duration::from_millis(5)).await;
    let overlay_two_peers = overlay_two.table_entries_enr();
    assert_eq!(1, overlay_two_peers.len());
    assert!(overlay_two_peers.contains(&overlay_one.local_enr()));

    // Send find nodes from node one to node two for node two's ENR.
    // Node two should be in node one's routing table.
    match overlay_one
        .send_find_nodes(overlay_two.local_enr(), vec![0])
        .await
    {
        Ok(nodes) => {
            assert_eq!(1, nodes.total);
            assert_eq!(1, nodes.enrs.len());
            assert!(nodes.enrs.contains(&SszEnr::new(overlay_two.local_enr())));
        }
        Err(err) => panic!("Unable to respond to find nodes: {}", err),
    }
    time::sleep(Duration::from_millis(5)).await;
    let overlay_one_peers = overlay_one.table_entries_enr();
    assert_eq!(1, overlay_one_peers.len());
    assert!(overlay_one_peers.contains(&overlay_two.local_enr()));

    // Send find nodes from node three to node one for all peers.
    // Node one and node two should be in node three's routing table.
    // Node one should be added to the routing table because it is the destination of the request.
    let distances = (1..257).collect();
    match overlay_three
        .send_find_nodes(overlay_one.local_enr(), distances)
        .await
    {
        Ok(nodes) => {
            assert_eq!(1, nodes.total);
            assert_eq!(1, nodes.enrs.len());
            assert!(nodes.enrs.contains(&SszEnr::new(overlay_two.local_enr())));
        }
        Err(err) => panic!("Unable to respond to find nodes: {}", err),
    }
    time::sleep(Duration::from_millis(5)).await;
    let overlay_three_peers = overlay_three.table_entries_enr();
    assert_eq!(2, overlay_three_peers.len());
    assert!(overlay_three_peers.contains(&overlay_one.local_enr()));
    assert!(overlay_three_peers.contains(&overlay_two.local_enr()));
}
