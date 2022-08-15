pub mod cli;

use discv5::{Discv5Event, TalkRequest};
use jsonrpsee::core::{async_trait, RpcResult};
use jsonrpsee::http_server::{HttpServerBuilder, HttpServerHandle};
use jsonrpsee::proc_macros::rpc;
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

#[rpc(server, client)]
pub trait Rpc {
    #[method(name = "local_enr")]
    fn local_enr(&self) -> RpcResult<String>;

    #[method(name = "talk_request")]
    async fn send_talk_req(&self, enr: String) -> RpcResult<String>;

    #[method(name = "prepare_to_recv")]
    async fn prepare_to_recv(&self, enr: String, conn_idj: u16) -> RpcResult<String>;

    #[method(name = "send_utp_payload")]
    async fn send_utp_payload(
        &self,
        enr: String,
        conn_id: u16,
        payload: Vec<u8>,
    ) -> RpcResult<String>;
}

pub struct TestApp {
    pub discovery: Arc<Discovery>,
    pub utp_listener_tx: UnboundedSender<UtpListenerRequest>,
    pub utp_listener_rx: UnboundedReceiver<UtpListenerEvent>,
    pub utp_event_tx: UnboundedSender<TalkRequest>,
}

#[async_trait]
impl RpcServer for TestApp {
    fn local_enr(&self) -> RpcResult<String> {
        Ok(self.discovery.local_enr().to_base64())
    }

    async fn send_talk_req(&self, enr: String) -> RpcResult<String> {
        let enr = Enr::from_str(&*enr).unwrap();

        self.discovery
            .send_talk_req(enr, ProtocolId::History, vec![])
            .await
            .unwrap();
        Ok("OK".to_owned())
    }

    async fn prepare_to_recv(&self, enr: String, conn_id: u16) -> RpcResult<String> {
        let enr = Enr::from_str(&*enr).unwrap();
        self.prepare_to_receive(enr, conn_id).await;
        Ok("OK".to_owned())
    }

    async fn send_utp_payload(
        &self,
        enr: String,
        conn_id: u16,
        payload: Vec<u8>,
    ) -> RpcResult<String> {
        let enr = Enr::from_str(&*enr).unwrap();
        self.send_utp_request(conn_id, payload, enr).await;
        Ok("OK".to_owned())
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
    discovery.start().await.unwrap();
    let enr = discovery.local_enr();
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

    let rpc_addr = format!("{rpc_addr}:{rpc_port}");

    // Start HTTP json-rpc server
    let server = HttpServerBuilder::default()
        .build(rpc_addr.parse::<SocketAddr>()?)
        .await?;

    let addr = server.local_addr()?;
    let handle = server.start(test_app.into_rpc()).unwrap();

    Ok((addr, enr, handle))
}
