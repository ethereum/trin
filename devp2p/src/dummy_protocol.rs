use std::net::SocketAddr;
use std::sync::Arc;
use trin_core::portalnet::discovery::{Config as DiscoveryConfig, Discovery};
use trin_core::portalnet::protocol::PortalnetEvents;
use trin_core::portalnet::types::{Enr, FindContent, FindNodes, Message, Ping, Request};
use trin_core::portalnet::U256;
use trin_core::socket;
use trin_core::utils::get_data_dir;

use discv5::Discv5ConfigBuilder;
use rocksdb::{Options, DB};

const LISTEN_PORT: u16 = 9876;

#[derive(Clone)]
pub struct DummyProtocol {
    pub discovery: Arc<Discovery>,
    data_radius: U256,
}

impl DummyProtocol {
    pub async fn new() -> Result<(Self, PortalnetEvents), String> {
        let listen_all_ips = SocketAddr::new("0.0.0.0".parse().unwrap(), LISTEN_PORT);
        let external_addr = socket::default_local_address(LISTEN_PORT);

        let config = DiscoveryConfig {
            discv5_config: Discv5ConfigBuilder::default().build(),
            // This is for defining the ENR:
            listen_port: external_addr.port(),
            listen_address: external_addr.ip(),
            ..Default::default()
        };

        let mut discovery = Discovery::new(config).unwrap();
        discovery.start(listen_all_ips).await?;

        let protocol_receiver = discovery
            .discv5
            .event_stream()
            .await
            .map_err(|e| e.to_string())?;

        let discovery = Arc::new(discovery);
        let data_radius = U256::from(u64::MAX);

        let proto = Self {
            discovery: discovery.clone(),
            data_radius,
        };

        let data_path = get_data_dir();

        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        let db = DB::open(&db_opts, data_path).unwrap();

        let events = PortalnetEvents {
            data_radius,
            discovery,
            protocol_receiver,
            db,
        };

        Ok((proto, events))
    }

    pub async fn send_ping(&self, data_radius: U256, enr: Enr) -> Result<Vec<u8>, String> {
        let enr_seq = self.discovery.local_enr().seq();
        let msg = Ping {
            enr_seq,
            data_radius,
        };
        self.discovery
            .send_talkreq(enr, Message::Request(Request::Ping(msg)).to_bytes())
            .await
    }

    pub async fn send_find_nodes(&self, distances: Vec<u16>, enr: Enr) -> Result<Vec<u8>, String> {
        let msg = FindNodes { distances };
        self.discovery
            .send_talkreq(enr, Message::Request(Request::FindNodes(msg)).to_bytes())
            .await
    }

    pub async fn send_find_content(
        &self,
        content_key: Vec<u8>,
        enr: Enr,
    ) -> Result<Vec<u8>, String> {
        let msg = FindContent { content_key };
        self.discovery
            .send_talkreq(enr, Message::Request(Request::FindContent(msg)).to_bytes())
            .await
    }
}
