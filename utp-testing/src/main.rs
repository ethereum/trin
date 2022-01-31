use discv5::{Discv5Event, TalkRequest};
use log::debug;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tokio;
use tokio::sync::{mpsc, RwLock};
use trin_core::portalnet::discovery::Discovery;
use trin_core::portalnet::types::messages::{PortalnetConfig, ProtocolId};
use trin_core::portalnet::Enr;
use trin_core::utp::stream::{ConnectionKey, UtpListener};
use trin_core::utp::trin_helpers::{UtpMessage, UtpMessageId, UtpStreamState};

pub struct TestApp {
    utp_listener: Arc<RwLock<UtpListener>>,
}

impl TestApp {
    async fn send_utp_request(&mut self, connection_id: u16, payload: Vec<u8>, enr: Enr) {
        let (tx, mut rx) = mpsc::unbounded_channel::<UtpStreamState>();

        self.utp_listener
            .write()
            .await
            .listening
            .insert(connection_id, UtpMessageId::OfferAcceptStream);
        self.utp_listener
            .write()
            .await
            .connect(connection_id, enr.node_id(), tx);

        let utp_list_arc = Arc::clone(&self.utp_listener);

        tokio::spawn(async move {
            while let Some(state) = rx.recv().await {
                if state == UtpStreamState::Connected {
                    if let Some(conn) =
                        utp_list_arc
                            .write()
                            .await
                            .utp_connections
                            .get_mut(&ConnectionKey {
                                node_id: enr.node_id(),
                                conn_id_recv: connection_id,
                            })
                    {
                        // send the content to the acceptor over a uTP stream
                        conn.send_to(&UtpMessage::new(payload.clone()).encode()[..]);
                    }
                } else if state == UtpStreamState::Finished {
                    debug!("State never finishes");
                    if let Some(conn) =
                        utp_list_arc
                            .write()
                            .await
                            .utp_connections
                            .get_mut(&ConnectionKey {
                                node_id: enr.node_id(),
                                conn_id_recv: connection_id,
                            })
                    {
                        conn.send_finalize();
                        return;
                    }
                }
            }
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
                    listener
                        .write()
                        .await
                        .process_utp_request(request.body(), request.node_id());
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

    async fn read_stream(&self, connection_id: u16) {}
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let discv5_port_1 = 9002;
    let mut app_1 = run_test_app(discv5_port_1).await;

    let discv5_port_2 = 9003;
    let app_2 = run_test_app(discv5_port_2).await;

    let server_enr = app_2.utp_listener.write().await.discovery.local_enr();

    let connection_id = 66;
    let payload = vec![1];

    app_1
        .utp_listener
        .write()
        .await
        .discovery
        .send_talk_req(server_enr.clone(), ProtocolId::History, vec![])
        .await
        .unwrap();

    app_2.prepare_to_receive(connection_id).await;

    app_1
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

    let utp_listener = UtpListener {
        discovery: Arc::new(discovery),
        utp_connections: HashMap::new(),
        listening: HashMap::new(),
    };

    let test_app = TestApp {
        utp_listener: Arc::new(RwLock::new(utp_listener)),
    };

    test_app.process_utp_request().await;

    test_app
}
