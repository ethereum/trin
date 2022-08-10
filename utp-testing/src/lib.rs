use discv5::{Discv5Event, TalkRequest};
use log::debug;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use trin_core::portalnet::discovery::Discovery;
use trin_core::portalnet::types::messages::{PortalnetConfig, ProtocolId};
use trin_core::portalnet::Enr;
use trin_core::utp::stream::{UtpListener, UtpListenerEvent, UtpListenerRequest, UtpStream};
use trin_core::utp::trin_helpers::{UtpMessage, UtpStreamId};

pub struct TestApp {
    pub discovery: Arc<Discovery>,
    pub utp_listener_tx: UnboundedSender<UtpListenerRequest>,
    pub utp_listener_rx: UnboundedReceiver<UtpListenerEvent>,
    pub utp_event_tx: UnboundedSender<TalkRequest>,
}

impl TestApp {
    pub async fn send_utp_request(&mut self, conn_id: u16, payload: Vec<u8>, enr: Enr) {
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

    pub async fn process_utp_request(&self) {
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

    pub async fn prepare_to_receive(&self, source: Enr, conn_id: u16) {
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

pub async fn run_test_app(discv5_port: u16, socket_addr: SocketAddr) -> TestApp {
    let config = PortalnetConfig {
        listen_port: discv5_port,
        external_addr: Some(socket_addr),
        ..Default::default()
    };

    let mut discovery = Discovery::new(config).unwrap();
    discovery.start().await.unwrap();
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

    test_app.process_utp_request().await;

    test_app
}
