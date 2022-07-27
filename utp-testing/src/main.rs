use discv5::TalkRequest;
use log::debug;
use std::{net::SocketAddr, str::FromStr, sync::Arc};
use tokio::sync::mpsc;
use trin_core::{
    portalnet::{
        discovery::Discovery,
        types::messages::{PortalnetConfig, ProtocolId},
        Enr,
    },
    socket,
    utp::{
        stream::{UtpListener, UtpListenerEvent, UtpListenerRequest, UtpStream},
        trin_helpers::{UtpMessage, UtpStreamId},
    },
};

#[allow(dead_code)]
pub struct TestApp {
    discovery: Arc<Discovery>,
    utp_listener_tx: mpsc::UnboundedSender<UtpListenerRequest>,
    utp_listener_rx: mpsc::UnboundedReceiver<UtpListenerEvent>,
    utp_event_tx: mpsc::UnboundedSender<TalkRequest>,
}

impl TestApp {
    async fn send_utp_request(&mut self, conn_id: u16, payload: Vec<u8>, enr: Enr) {
        let (tx, rx) = tokio::sync::oneshot::channel::<UtpStream>();
        let _ = self.utp_listener_tx.send(UtpListenerRequest::Connect(
            conn_id,
            enr,
            ProtocolId::History,
            UtpStreamId::OfferStream,
            tx,
        ));

        let mut conn = rx.await.unwrap();

        let mut buf = [0; 1500];
        conn.recv(&mut buf).await.unwrap();

        conn.send_to(&UtpMessage::new(payload.clone()).encode()[..])
            .await
            .unwrap();

        tokio::spawn(async move {
            conn.close().await.unwrap();
            debug!("connecton state: {:?}", conn.state)
        });
    }

    async fn process_utp_request(&self, mut talk_req_rx: mpsc::Receiver<TalkRequest>) {
        let utp_sender = self.utp_event_tx.clone();

        tokio::spawn(async move {
            while let Some(request) = talk_req_rx.recv().await {
                debug!("utp-testing TestApp handling talk request: {request:?}");

                let protocol_id =
                    ProtocolId::from_str(&hex::encode_upper(request.protocol())).unwrap();

                if let ProtocolId::Utp = protocol_id {
                    utp_sender.send(request).unwrap();
                };
            }
        });
    }

    async fn prepare_to_receive(&self, source: Enr, conn_id: u16) {
        // Listen for incoming connection request on conn_id, as part of uTP handshake
        let _ = self
            .utp_listener_tx
            .send(UtpListenerRequest::InitiateConnection(
                source,
                ProtocolId::History,
                UtpStreamId::AcceptStream(vec![vec![]]),
                conn_id,
            ));
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let client_port = 9002;
    let client_ip_addr =
        socket::find_assigned_ip().expect("Could not find an IP for local connections");
    let client_external_addr = SocketAddr::new(client_ip_addr, client_port);
    let mut client = run_test_app(client_port, client_external_addr).await;

    let server_port = 9003;
    let server_ip_addr =
        socket::find_assigned_ip().expect("Could not find an IP for local connections");
    let server_external_addr = SocketAddr::new(server_ip_addr, server_port);

    let server = run_test_app(server_port, server_external_addr).await;

    let server_enr = server.discovery.local_enr();

    let connection_id = 66;
    let payload = vec![6; 2000];

    client
        .discovery
        .send_talk_req(server_enr.clone(), ProtocolId::History, vec![])
        .await
        .unwrap();

    server
        .prepare_to_receive(client.discovery.local_enr(), connection_id)
        .await;

    client
        .send_utp_request(connection_id, payload, server_enr)
        .await;

    tokio::signal::ctrl_c()
        .await
        .expect("failed to pause until ctrl-c");
}

async fn run_test_app(discv5_port: u16, socket_addr: SocketAddr) -> TestApp {
    let config = PortalnetConfig {
        listen_port: discv5_port,
        external_addr: Some(socket_addr),
        ..Default::default()
    };

    let mut discovery = Discovery::new(config).unwrap();
    let talk_req_rx = discovery.start().await.unwrap();
    let discovery = Arc::new(discovery);

    let (utp_event_sender, utp_listener_tx, utp_listener_rx, mut utp_listener) =
        UtpListener::new(Arc::clone(&discovery));
    tokio::spawn(async move { utp_listener.start().await });

    let test_app = TestApp {
        discovery,
        utp_listener_tx,
        utp_listener_rx,
        utp_event_tx: utp_event_sender,
    };

    test_app.process_utp_request(talk_req_rx).await;

    test_app
}
