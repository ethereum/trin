use ntest::timeout;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use trin_core::{
    portalnet::{
        discovery::Discovery,
        types::messages::{PortalnetConfig, ProtocolId},
        Enr,
    },
    utp::{
        stream::{UtpListener, UtpListenerEvent, UtpListenerRequest, UtpStream, BUF_SIZE},
        trin_helpers::UtpStreamId::{AcceptStream, OfferStream},
    },
};

fn next_test_port() -> u16 {
    use std::sync::atomic::{AtomicUsize, Ordering};
    // static here allow us to modify the global value and AtomicUsize can be shared safely between threads
    static NEXT_OFFSET: AtomicUsize = AtomicUsize::new(0);
    const BASE_PORT: u16 = 11600;
    BASE_PORT + NEXT_OFFSET.fetch_add(1, Ordering::Relaxed) as u16
}

/// Spawn uTP listener instance and start discv5 event handler
async fn spawn_utp_listener() -> (
    Enr,
    UnboundedSender<UtpListenerRequest>,
    UnboundedReceiver<UtpListenerEvent>,
) {
    let ip_addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let port = next_test_port();
    let config = PortalnetConfig {
        listen_port: port,
        external_addr: Some(SocketAddr::new(ip_addr, port)),
        ..Default::default()
    };
    let mut discv5 = Discovery::new(config).unwrap();
    let enr = discv5.local_enr();
    let mut talk_req_rx = discv5.start().await.unwrap();

    let discv5 = Arc::new(discv5);

    let (utp_event_tx, utp_listener_tx, utp_listener_rx, mut utp_listener) =
        UtpListener::new(Arc::clone(&discv5));

    tokio::spawn(async move {
        while let Some(request) = talk_req_rx.recv().await {
            let protocol_id = ProtocolId::from_str(&hex::encode_upper(request.protocol())).unwrap();

            match protocol_id {
                ProtocolId::Utp => utp_event_tx.send(request).unwrap(),
                _ => continue,
            }
        }
    });
    tokio::spawn(async move { utp_listener.start().await });

    (enr, utp_listener_tx, utp_listener_rx)
}

#[test_log::test(tokio::test)]
#[timeout(1000)]
/// Simulate simple OFFER -> ACCEPT uTP payload transfer
async fn utp_listener_events() {
    let protocol_id = ProtocolId::History;

    // Initialize offer uTP listener
    let (enr_offer, listener_tx_offer, mut listener_rx_offer) = spawn_utp_listener().await;
    // Initialize acceptor uTP listener
    let (enr_accept, listener_tx_accept, mut listener_rx_accept) = spawn_utp_listener().await;

    // Prepare to receive uTP stream from the offer node
    let (requested_content_key, requested_content_value) = (vec![1], vec![1, 1, 1, 1]);
    let stream_id = AcceptStream(vec![requested_content_key.clone()]);
    let conn_id = 1234;
    let request = UtpListenerRequest::InitiateConnection(
        enr_offer.clone(),
        protocol_id.clone(),
        stream_id,
        conn_id,
    );
    listener_tx_accept.send(request).unwrap();

    // Initialise an OFFER stream and send handshake uTP packet to the acceptor node
    let stream_id = OfferStream;
    let (tx, rx) = tokio::sync::oneshot::channel::<UtpStream>();
    let offer_request = UtpListenerRequest::Connect(
        conn_id,
        enr_accept.clone(),
        protocol_id.clone(),
        stream_id,
        tx,
    );
    listener_tx_offer.send(offer_request).unwrap();

    // Handle STATE packet for SYN handshake in the offer node
    let mut conn = rx.await.unwrap();
    assert_eq!(conn.connected_to, enr_accept);

    let mut buf = [0; BUF_SIZE];
    conn.recv(&mut buf).await.unwrap();

    // Send content key with content value to the acceptor node
    let utp_payload: Vec<u8> = requested_content_value;
    let expected_utp_payload = utp_payload.clone();

    tokio::spawn(async move {
        // Send the content to the acceptor over a uTP stream
        conn.send_to(&utp_payload).await.unwrap();
        // Close uTP connection
        conn.close().await.unwrap();
    });

    // Check if the expected uTP listener events match the events in offer and accept nodes
    let offer_event = listener_rx_offer.recv().await.unwrap();
    let expected_offer_event =
        UtpListenerEvent::ClosedStream(vec![], protocol_id.clone(), OfferStream);
    assert_eq!(offer_event, expected_offer_event);

    let accept_event = listener_rx_accept.recv().await.unwrap();
    let expected_accept_event = UtpListenerEvent::ClosedStream(
        expected_utp_payload,
        protocol_id.clone(),
        AcceptStream(vec![requested_content_key]),
    );
    assert_eq!(accept_event, expected_accept_event);
}
