#![warn(clippy::uninlined_format_args)]

extern crate core;

pub mod cli;
pub mod rpc;

use crate::rpc::RpcServer;
use discv5::TalkRequest;
use ethportal_api::{
    types::{
        enr::Enr,
        portal_wire::{ProtocolId, MAINNET},
    },
    utils::bytes::{hex_encode, hex_encode_upper},
};
use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
    server::{Server, ServerHandle},
};
use portalnet::{
    config::PortalnetConfig,
    discovery::{Discovery, UtpEnr},
    utils::db::setup_temp_dir,
};
use std::{io::ErrorKind, net::SocketAddr, str::FromStr, sync::Arc, time::Duration};
use tokio::sync::{
    mpsc::{self, Receiver},
    RwLock,
};
use utp_rs::{conn::ConnectionConfig, socket::UtpSocket};

/// uTP test app
pub struct TestApp {
    pub discovery: Arc<Discovery>,
    pub utp_socket: Arc<UtpSocket<UtpEnr>>,
    pub utp_talk_req_tx: mpsc::UnboundedSender<TalkRequest>,
    pub utp_payload: Arc<RwLock<Vec<Vec<u8>>>>,
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

    async fn prepare_to_recv(
        &self,
        src_enr: String,
        cid_send: u16,
        cid_recv: u16,
    ) -> RpcResult<String> {
        let src_enr = Enr::from_str(&src_enr).unwrap();
        let cid = utp_rs::cid::ConnectionId {
            send: cid_send,
            recv: cid_recv,
            peer: UtpEnr(src_enr.clone()),
        };
        self.discovery.add_enr(src_enr).unwrap();

        let utp = Arc::clone(&self.utp_socket);
        let payload_store = Arc::clone(&self.utp_payload);
        tokio::spawn(async move {
            let utp_config = ConnectionConfig {
                max_packet_size: 1024,
                max_conn_attempts: 3,
                max_idle_timeout: Duration::from_secs(16),
                initial_timeout: Duration::from_millis(1250),
                ..Default::default()
            };
            let mut conn = utp.accept_with_cid(cid, utp_config).await.unwrap();
            let mut data = vec![];
            let n = conn.read_to_eof(&mut data).await.unwrap();

            tracing::info!("read {n} bytes from uTP stream");

            // Since switching to one-way FIN-ACK, closing after reading is not allowed. We only
            // explicitly close after write() now, and close after reading should error.
            match conn.close().await {
                Ok(_) => panic!("Closing after reading should have errored, but succeeded"),
                Err(e) => {
                    // The stream will already be disconnected by the read_to_eof() call, so we
                    // expect a NotConnected error here.
                    assert_eq!(e.kind(), ErrorKind::NotConnected);
                }
            }

            payload_store.write().await.push(data);
        });

        Ok("true".to_string())
    }

    async fn send_utp_payload(
        &self,
        dst_enr: String,
        cid_send: u16,
        cid_recv: u16,
        payload: Vec<u8>,
    ) -> RpcResult<String> {
        let dst_enr = Enr::from_str(&dst_enr).unwrap();
        let cid = utp_rs::cid::ConnectionId {
            send: cid_send,
            recv: cid_recv,
            peer: UtpEnr(dst_enr.clone()),
        };
        self.discovery.add_enr(dst_enr).unwrap();

        let utp = Arc::clone(&self.utp_socket);
        let utp_config = ConnectionConfig {
            max_packet_size: 1024,
            max_conn_attempts: 3,
            max_idle_timeout: Duration::from_secs(16),
            initial_timeout: Duration::from_millis(1250),
            ..Default::default()
        };
        tokio::spawn(async move {
            let mut conn = utp.connect_with_cid(cid, utp_config).await.unwrap();

            conn.write(&payload).await.unwrap();

            conn.close().await.unwrap();
        });

        Ok("true".to_string())
    }
}

impl TestApp {
    pub async fn start(&self, mut talk_req_rx: Receiver<TalkRequest>) {
        let utp_talk_reqs_tx = self.utp_talk_req_tx.clone();

        // Forward discv5 uTP packets to uTP socket
        tokio::spawn(async move {
            while let Some(request) = talk_req_rx.recv().await {
                let protocol_id = MAINNET
                    .get_protocol_id_from_hex(&hex_encode_upper(request.protocol()))
                    .unwrap();

                if let ProtocolId::Utp = protocol_id {
                    utp_talk_reqs_tx.send(request).unwrap();
                };
            }
        });
    }
}

/// Main method to spawn uTP Test App
pub async fn run_test_app(
    udp_port: u16,
    socket_addr: SocketAddr,
    rpc_addr: String,
    rpc_port: u16,
) -> anyhow::Result<(SocketAddr, Enr, ServerHandle)> {
    let config = PortalnetConfig {
        listen_port: udp_port,
        external_addr: Some(socket_addr),
        ..Default::default()
    };

    let temp_dir = setup_temp_dir().unwrap().into_path();
    let mut discovery = Discovery::new(config, temp_dir, MAINNET.clone()).unwrap();
    let talk_req_rx = discovery.start().await.unwrap();
    let enr = discovery.local_enr();
    let discovery = Arc::new(discovery);

    let (utp_talk_req_tx, utp_talk_req_rx) = mpsc::unbounded_channel();
    let discv5_utp_socket =
        portalnet::discovery::Discv5UdpSocket::new(Arc::clone(&discovery), utp_talk_req_rx);
    let utp_socket = utp_rs::socket::UtpSocket::with_socket(discv5_utp_socket);
    let utp_socket = Arc::new(utp_socket);

    let test_app = TestApp {
        discovery,
        utp_socket,
        utp_talk_req_tx,
        utp_payload: Arc::new(RwLock::new(Vec::new())),
    };

    test_app.start(talk_req_rx).await;

    let rpc_addr = format!("{rpc_addr}:{rpc_port}");

    // Start HTTP json-rpc server
    let server = Server::builder()
        .build(rpc_addr.parse::<SocketAddr>()?)
        .await?;

    let addr = server.local_addr()?;
    let handle = server.start(test_app.into_rpc());

    Ok((addr, enr, handle))
}
