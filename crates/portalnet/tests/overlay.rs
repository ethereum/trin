use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use discv5::TalkRequest;
use ethportal_api::{
    types::{
        content_key::overlay::IdentityContentKey,
        distance::XorMetric,
        enr::{Enr, SszEnr},
        network::Subnetwork,
        portal_wire::{Content, Message, MAINNET},
    },
    utils::bytes::hex_encode_upper,
    OverlayContentKey,
};
use parking_lot::Mutex;
use portalnet::{
    config::PortalnetConfig,
    discovery::{Discovery, Discv5UdpSocket},
    overlay::{
        config::{FindContentConfig, OverlayConfig},
        ping_extensions::MockPingExtension,
        protocol::OverlayProtocol,
    },
};
use tokio::{
    sync::{mpsc, mpsc::unbounded_channel, RwLock as TokioRwLock},
    time::{self, Duration},
};
use trin_storage::{ContentStore, DistanceFunction, MemoryContentStore};
use trin_validation::{oracle::HeaderOracle, validator::MockValidator};
use utp_rs::socket::UtpSocket;

async fn init_overlay(
    discovery: Arc<Discovery>,
    subnetwork: Subnetwork,
) -> OverlayProtocol<
    IdentityContentKey,
    XorMetric,
    MockValidator,
    MemoryContentStore,
    MockPingExtension,
> {
    let overlay_config = OverlayConfig::default();

    let node_id = discovery.local_enr().node_id();
    let store = MemoryContentStore::new(node_id, DistanceFunction::Xor);
    let store = Arc::new(Mutex::new(store));

    let header_oracle = HeaderOracle::default();
    let header_oracle = Arc::new(TokioRwLock::new(header_oracle));
    let (_utp_talk_req_tx, utp_talk_req_rx) = unbounded_channel();
    let discv5_utp =
        Discv5UdpSocket::new(Arc::clone(&discovery), utp_talk_req_rx, header_oracle, 50);
    let utp_socket = Arc::new(UtpSocket::with_socket(discv5_utp));

    let validator = Arc::new(MockValidator {});
    let ping_extensions = Arc::new(MockPingExtension {});

    OverlayProtocol::new(
        overlay_config,
        discovery,
        utp_socket,
        store,
        subnetwork,
        validator,
        ping_extensions,
    )
    .await
}

async fn spawn_overlay(
    mut talk_req_rx: mpsc::Receiver<TalkRequest>,
    overlay: Arc<
        OverlayProtocol<
            IdentityContentKey,
            XorMetric,
            MockValidator,
            MemoryContentStore,
            MockPingExtension,
        >,
    >,
) {
    let (overlay_tx, mut overlay_rx) = mpsc::unbounded_channel();

    let overlay_protocol = *overlay.protocol();
    tokio::spawn(async move {
        while let Some(talk_req) = talk_req_rx.recv().await {
            let req_subnetwork = MAINNET
                .get_subnetwork_from_protocol_identifier(&hex_encode_upper(talk_req.protocol()));

            if let Ok(req_subnetwork) = req_subnetwork {
                match (req_subnetwork, overlay_protocol) {
                    (Subnetwork::History, Subnetwork::History)
                    | (Subnetwork::State, Subnetwork::State) => overlay_tx.send(talk_req).unwrap(),
                    _ => panic!("Unexpected subnetwork"),
                }
            } else {
                panic!("Invalid subnetwork");
            }
        }
    });

    tokio::spawn(async move {
        while let Some(talk_req) = overlay_rx.recv().await {
            let talk_resp = match overlay.process_one_request(&talk_req).await {
                Ok(response) => Message::from(response).into(),
                Err(err) => panic!("Error processing request: {err}"),
            };
            if let Err(err) = talk_req.respond(talk_resp) {
                panic!("Unable to respond to talk request: {err}");
            }
        }
    });
}

// Basic tests for overlay routing table management according to messages exchanged between
// multiple nodes.
//
// Use sleeps to give time for background routing table processes.
#[test_log::test(tokio::test)]
async fn overlay() {
    let protocol = Subnetwork::History;
    let sleep_duration = Duration::from_millis(5);
    let ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

    // Node one.
    let portal_config_one = PortalnetConfig {
        listen_port: 8001,
        external_addr: Some(SocketAddr::new(ip_addr, 8001)),
        ..PortalnetConfig::default()
    };
    let mut discovery_one = Discovery::new(portal_config_one, MAINNET.clone()).unwrap();
    let talk_req_rx_one = discovery_one.start().await.unwrap();
    let discovery_one = Arc::new(discovery_one);
    let overlay_one = Arc::new(init_overlay(Arc::clone(&discovery_one), protocol).await);
    spawn_overlay(talk_req_rx_one, Arc::clone(&overlay_one)).await;
    time::sleep(sleep_duration).await;

    // Node two.
    let portal_config_two = PortalnetConfig {
        listen_port: 8002,
        external_addr: Some(SocketAddr::new(ip_addr, 8002)),
        ..PortalnetConfig::default()
    };
    let mut discovery_two = Discovery::new(portal_config_two, MAINNET.clone()).unwrap();
    let talk_req_rx_two = discovery_two.start().await.unwrap();
    let discovery_two = Arc::new(discovery_two);
    let overlay_two = Arc::new(init_overlay(Arc::clone(&discovery_two), protocol).await);
    spawn_overlay(talk_req_rx_two, Arc::clone(&overlay_two)).await;
    time::sleep(sleep_duration).await;

    // Node three.
    let portal_config_three = PortalnetConfig {
        listen_port: 8003,
        external_addr: Some(SocketAddr::new(ip_addr, 8003)),
        ..PortalnetConfig::default()
    };
    let mut discovery_three = Discovery::new(portal_config_three, MAINNET.clone()).unwrap();
    let talk_req_rx_three = discovery_three.start().await.unwrap();
    let discovery_three = Arc::new(discovery_three);
    let overlay_three = Arc::new(init_overlay(Arc::clone(&discovery_three), protocol).await);
    spawn_overlay(talk_req_rx_three, Arc::clone(&overlay_three)).await;
    time::sleep(sleep_duration).await;

    // All routing tables are empty.
    assert!(overlay_one.table_entries_enr().is_empty());
    assert!(overlay_two.table_entries_enr().is_empty());
    assert!(overlay_three.table_entries_enr().is_empty());

    // Ping node two from node one.
    // Node two should be in node one's routing table.
    match overlay_one.send_ping(overlay_two.local_enr()).await {
        Ok(pong) => {
            assert_eq!(overlay_two.local_enr().seq(), pong.enr_seq);
        }
        Err(err) => panic!("Unable to respond to ping: {err}"),
    }
    time::sleep(sleep_duration).await;
    let overlay_one_peers = overlay_one.table_entries_enr();
    assert_eq!(1, overlay_one_peers.len());
    assert!(overlay_one_peers.contains(&overlay_two.local_enr()));

    // Send find nodes from node one to node three for node three's ENR.
    // Node three should be in node one's routing table.
    match overlay_one
        .send_find_nodes(overlay_three.local_enr(), vec![0])
        .await
    {
        Ok(nodes) => {
            assert_eq!(1, nodes.total);
            assert_eq!(1, nodes.enrs.len());
            assert!(nodes.enrs.contains(&SszEnr::new(overlay_three.local_enr())));
        }
        Err(err) => panic!("Unable to respond to find nodes: {err}"),
    }
    time::sleep(sleep_duration).await;
    let overlay_one_peers = overlay_one.table_entries_enr();
    assert_eq!(2, overlay_one_peers.len());
    assert!(overlay_one_peers.contains(&overlay_three.local_enr()));

    // Send find nodes from node three to node one for all peers.
    // The nodes response should contain node two and node three.
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
        Err(err) => panic!("Unable to respond to find nodes: {err}"),
    }
    time::sleep(sleep_duration).await;
    let overlay_three_peers = overlay_three.table_entries_enr();
    assert_eq!(2, overlay_three_peers.len());
    assert!(overlay_three_peers.contains(&overlay_one.local_enr()));
    assert!(overlay_three_peers.contains(&overlay_two.local_enr()));

    // Send find content from node two to node one for any content ID.
    // Node one should be added to the routing table because it is the destination of the request.
    // All ENRs in the content response should be added to the routing table, except for node two,
    // because node two is the local node.
    let content_key = IdentityContentKey::new([0u8; 32]);
    let content_enrs = match overlay_two
        .send_find_content(overlay_one.local_enr(), content_key.to_bytes())
        .await
    {
        Ok((content, utp_transfer)) => match content {
            Content::Enrs(enrs) => {
                assert!(!utp_transfer);
                enrs
            }
            other => panic!("Unexpected response to find content: {other:?}"),
        },
        Err(err) => panic!("Unable to respond to find content: {err}"),
    };
    time::sleep(sleep_duration).await;
    let overlay_two_peers = overlay_two.table_entries_enr();
    assert!(overlay_two_peers.contains(&overlay_one.local_enr()));
    for enr in content_enrs {
        if Into::<Enr>::into(enr.clone()) == overlay_two.local_enr() {
            continue;
        }
        assert!(overlay_two_peers.contains(&enr.into()));
    }

    // Store content with node three and perform a content lookup from node one.
    let content_key = IdentityContentKey::new([0xef; 32]);
    let content = vec![0xef];
    overlay_three
        .store
        .lock()
        .put(content_key.clone(), &content)
        .expect("Unable to store content");
    let (found_content, utp_transfer, _) = overlay_one
        .lookup_content(content_key, FindContentConfig::default())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found_content, content);
    assert!(!utp_transfer);
}

#[tokio::test]
async fn overlay_event_stream() {
    let portal_config = PortalnetConfig {
        no_stun: true,
        no_upnp: true,
        ..Default::default()
    };
    let discovery = Arc::new(Discovery::new(portal_config, MAINNET.clone()).unwrap());
    let overlay = init_overlay(discovery, Subnetwork::Beacon).await;

    overlay.event_stream().await.unwrap();
}
