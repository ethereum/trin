use discv5::{Discv5Event, TalkRequest};
use log::debug;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender;
use trin_core::portalnet::discovery::Discovery;
use trin_core::portalnet::types::messages::{PortalnetConfig, ProtocolId};
use trin_core::portalnet::Enr;
use trin_core::utp::stream::{UtpListener, UtpListenerRequest, UtpSocket};
use trin_core::utp::trin_helpers::UtpMessage;

pub struct TestApp {
    discovery: Arc<Discovery>,
    utp_listener_tx: UnboundedSender<UtpListenerRequest>,
    utp_event_tx: UnboundedSender<TalkRequest>,
}

impl TestApp {
    async fn send_utp_request(&mut self, conn_id: u16, payload: Vec<u8>, enr: Enr) {
        let _ = self
            .utp_listener_tx
            .send(UtpListenerRequest::OfferStream(conn_id));

        let (tx, rx) = tokio::sync::oneshot::channel::<anyhow::Result<UtpSocket>>();
        let _ = self
            .utp_listener_tx
            .send(UtpListenerRequest::Connect(conn_id, enr.node_id(), tx));

        let mut conn = rx.await.unwrap().unwrap();

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

    async fn process_utp_request(&self) {
        let mut event_stream = self.discovery.discv5.event_stream().await.unwrap();

        let utp_sender = self.utp_event_tx.clone();

        tokio::spawn(async move {
            while let Some(event) = event_stream.recv().await {
                debug!("utp-testing TestApp handling event: {event:?}");
                let request = match event {
                    Discv5Event::TalkRequest(r) => r,
                    _ => continue,
                };

                let protocol_id =
                    ProtocolId::from_str(&hex::encode_upper(request.protocol())).unwrap();

                if let ProtocolId::Utp = protocol_id {
                    utp_sender.send(request).unwrap();
                };
            }
        });
    }

    async fn prepare_to_receive(&self, conn_id: u16) {
        // listen for incoming connection request on conn_id, as part of utp handshake
        let _ = self
            .utp_listener_tx
            .send(UtpListenerRequest::OfferStream(conn_id));

        // also listen on conn_id + 1 because this is the actual receive path for acceptor
        let conn_id_recv = conn_id.wrapping_add(1);
        let _ = self
            .utp_listener_tx
            .send(UtpListenerRequest::OfferStream(conn_id_recv));
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let client_port = 9002;
    let mut client = run_test_app(client_port).await;

    let server_port = 9003;
    let server = run_test_app(server_port).await;

    let server_enr = server.discovery.local_enr();

    let connection_id = 66;
    let payload = vec![6; 2000];

    client
        .discovery
        .send_talk_req(server_enr.clone(), ProtocolId::History, vec![])
        .await
        .unwrap();

    server.prepare_to_receive(connection_id).await;

    client
        .send_utp_request(connection_id, payload, server_enr)
        .await;

    tokio::signal::ctrl_c()
        .await
        .expect("failed to pause until ctrl-c");
}

async fn run_test_app(discv5_port: u16) -> TestApp {
    let config = PortalnetConfig {
        listen_port: discv5_port,
        internal_ip: true,
        ..Default::default()
    };

    let mut discovery = Discovery::new(config).unwrap();
    discovery.start().await.unwrap();
    let discovery = Arc::new(discovery);

    let (utp_event_sender, utp_listener_tx, mut utp_listener) =
        UtpListener::new(Arc::clone(&discovery));
    tokio::spawn(async move { utp_listener.start().await });

    let test_app = TestApp {
        discovery,
        utp_listener_tx,
        utp_event_tx: utp_event_sender,
    };

    test_app.process_utp_request().await;

    test_app
}
