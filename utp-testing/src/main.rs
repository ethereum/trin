use discv5::Discv5Event;
use log::debug;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;
use trin_core::portalnet::discovery::Discovery;
use trin_core::portalnet::types::messages::{PortalnetConfig, ProtocolId};
use trin_core::portalnet::Enr;
use trin_core::utp::stream::UtpListener;
use trin_core::utp::trin_helpers::{UtpMessage, UtpMessageId};

pub struct TestApp {
    utp_listener: Arc<RwLock<UtpListener>>,
}

impl TestApp {
    async fn send_utp_request(&mut self, connection_id: u16, payload: Vec<u8>, enr: Enr) {
        self.utp_listener
            .write()
            .await
            .listening
            .insert(connection_id, UtpMessageId::OfferAcceptStream);

        let mut conn = self
            .utp_listener
            .write()
            .await
            .connect(connection_id, enr.node_id())
            .await
            .unwrap();

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
        let mut event_stream = self
            .utp_listener
            .read()
            .await
            .discovery
            .discv5
            .event_stream()
            .await
            .unwrap();

        let listener = Arc::clone(&self.utp_listener);

        tokio::spawn(async move {
            while let Some(event) = event_stream.recv().await {
                let request = match event {
                    Discv5Event::TalkRequest(r) => r,
                    _ => continue,
                };

                let protocol_id =
                    ProtocolId::from_str(&hex::encode_upper(request.protocol())).unwrap();

                if let ProtocolId::Utp = protocol_id {
                    listener.write().await.process_utp_request(request).await;
                    listener.write().await.process_utp_byte_stream().await;
                };
            }
        });
    }

    async fn prepare_to_receive(&self, connection_id: u16) {
        // listen for incoming connection request on conn_id, as part of utp handshake
        self.utp_listener
            .write()
            .await
            .listening
            .insert(connection_id, UtpMessageId::OfferAcceptStream);

        // also listen on conn_id + 1 because this is the actual receive path for acceptor
        self.utp_listener
            .write()
            .await
            .listening
            .insert(connection_id + 1, UtpMessageId::OfferAcceptStream);
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let client_port = 9002;
    let mut client = run_test_app(client_port).await;

    let server_port = 9003;
    let server = run_test_app(server_port).await;

    let server_enr = server.utp_listener.write().await.discovery.local_enr();

    let connection_id = 66;
    let payload = vec![6; 2000];

    client
        .utp_listener
        .write()
        .await
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

    let utp_listener = UtpListener::new(Arc::new(discovery));

    let test_app = TestApp {
        utp_listener: Arc::new(RwLock::new(utp_listener)),
    };

    test_app.process_utp_request().await;

    test_app
}
