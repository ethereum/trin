extern crate core;

pub mod cli;
pub mod rpc;

use crate::rpc::RpcServer;
use discv5::TalkRequest;
use jsonrpsee::core::{async_trait, RpcResult};
use jsonrpsee::http_server::{HttpServerBuilder, HttpServerHandle};
use jsonrpsee::proc_macros::rpc;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tracing::debug;
use trin_core::portalnet::discovery::Discovery;
use trin_core::portalnet::types::messages::{PortalnetConfig, ProtocolId};
use trin_core::utp::stream::{
    UtpListener, UtpListenerEvent, UtpListenerRequest, UtpPayload, UtpStream,
};
use trin_core::utp::trin_helpers::UtpStreamId;
use trin_types::enr::Enr;
use trin_utils::bytes::{hex_encode, hex_encode_upper};

/// uTP test app
pub struct TestApp {
    pub discovery: Arc<Discovery>,
    pub utp_listener_tx: mpsc::UnboundedSender<UtpListenerRequest>,
    pub utp_listener_rx: Arc<RwLock<mpsc::UnboundedReceiver<UtpListenerEvent>>>,
    pub utp_event_tx: mpsc::UnboundedSender<TalkRequest>,
    pub utp_payload: Arc<RwLock<Vec<UtpPayload>>>,
}

#[async_trait]
impl RpcServer for TestApp {
    fn local_enr(&self) -> RpcResult<String> {
        Ok(self.discovery.local_enr().to_base64())
    }

    async fn get_utp_payload(&self) -> RpcResult<String> {
        let utp_payload = self.utp_payload.read().await;
        let utp_payload = utp_payload.last();

        match utp_payload {
            Some(payload) => Ok(hex_encode(payload)),
            None => Ok("false".to_string()),
        }
    }

    async fn prepare_to_recv(&self, enr: String, conn_id: u16) -> RpcResult<String> {
        let enr = Enr::from_str(&enr).unwrap();
        self.prepare_to_receive(enr, conn_id).await;
        Ok("true".to_string())
    }

    async fn send_utp_payload(
        &self,
        enr: String,
        conn_id: u16,
        payload: Vec<u8>,
    ) -> RpcResult<String> {
        let enr = Enr::from_str(&enr).unwrap();
        self.send_utp_request(conn_id, payload, enr).await;
        Ok("true".to_string())
    }
}

impl TestApp {
    pub async fn send_utp_request(&self, conn_id: u16, payload: Vec<u8>, enr: Enr) {
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

        conn.send_to(&payload).await.unwrap();

        tokio::spawn(async move {
            let _ = conn.close().await;
            debug!("Connection state: {:?}", conn.state)
        });
    }

    pub async fn start(&self, mut talk_req_rx: mpsc::Receiver<TalkRequest>) {
        let utp_sender = self.utp_event_tx.clone();

        // Forward discv5 uTP packets to uTP socket
        tokio::spawn(async move {
            while let Some(request) = talk_req_rx.recv().await {
                let protocol_id =
                    ProtocolId::from_str(&hex_encode_upper(request.protocol())).unwrap();

                if let ProtocolId::Utp = protocol_id {
                    utp_sender.send(request).unwrap();
                };
            }
        });

        // Listen for uTP listener closed streams
        let utp_listener_rx = self.utp_listener_rx.clone();
        let utp_payload_store = self.utp_payload.clone();

        tokio::spawn(async move {
            while let Some(event) = utp_listener_rx.write().await.recv().await {
                if let UtpListenerEvent::ClosedStream(utp_payload, _, _) = event {
                    utp_payload_store.write().await.push(utp_payload)
                }
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

/// Main method to spawn uTP Test App
pub async fn run_test_app(
    udp_port: u16,
    socket_addr: SocketAddr,
    rpc_addr: String,
    rpc_port: u16,
) -> anyhow::Result<(SocketAddr, Enr, HttpServerHandle)> {
    let config = PortalnetConfig {
        listen_port: udp_port,
        external_addr: Some(socket_addr),
        ..Default::default()
    };

    let mut discovery = Discovery::new(config).unwrap();
    let talk_req_rx = discovery.start().await.unwrap();
    let enr = discovery.local_enr();
    let discovery = Arc::new(discovery);

    let (utp_event_sender, utp_listener_tx, utp_listener_rx, mut utp_listener) =
        UtpListener::new(Arc::clone(&discovery));
    tokio::spawn(async move { utp_listener.start().await });

    let test_app = TestApp {
        discovery,
        utp_listener_tx,
        utp_listener_rx: Arc::new(RwLock::new(utp_listener_rx)),
        utp_event_tx: utp_event_sender,
        utp_payload: Arc::new(RwLock::new(Vec::new())),
    };

    test_app.start(talk_req_rx).await;

    let rpc_addr = format!("{rpc_addr}:{rpc_port}");

    // Start HTTP json-rpc server
    let server = HttpServerBuilder::default()
        .build(rpc_addr.parse::<SocketAddr>()?)
        .await?;

    let addr = server.local_addr()?;
    let handle = server.start(test_app.into_rpc()).unwrap();

    Ok((addr, enr, handle))
}
