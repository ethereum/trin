#![allow(dead_code)]

use super::{
    types::messages::{HexData, PortalnetConfig, ProtocolId},
    Enr,
};
use crate::socket;
use discv5::{
    enr::{CombinedKey, EnrBuilder, NodeId},
    Discv5, Discv5Config, Discv5ConfigBuilder, Discv5Event, RequestError, TalkRequest,
};
use log::info;
use lru::LruCache;
use parking_lot::RwLock;
use serde_json::{json, Value};
use tokio::sync::mpsc;

use std::{
    convert::TryFrom,
    fmt,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

/// With even distribution assumptions, 2**17 is enough to put each node (estimating 100k nodes,
/// which is more than 10x the ethereum mainnet node count) into a unique bucket by the 17th bucket index.
const EXPECTED_NON_EMPTY_BUCKETS: usize = 17;

#[derive(Clone)]
pub struct Config {
    pub enr_address: Option<IpAddr>,
    pub listen_port: u16,
    pub discv5_config: Discv5Config,
    pub bootnode_enrs: Vec<Enr>,
    pub private_key: Option<HexData>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enr_address: None,
            listen_port: 4242,
            discv5_config: Discv5Config::default(),
            bootnode_enrs: vec![],
            private_key: None,
        }
    }
}

struct DiscoveryEvents {
    event_rx: mpsc::Receiver<Discv5Event>,
    enr_cache: Arc<RwLock<lru::LruCache<NodeId, (Enr, SocketAddr)>>>,
}

impl DiscoveryEvents {
    async fn start(
        mut event_rx: mpsc::Receiver<Discv5Event>,
        talk_req_tx: mpsc::Sender<TalkRequest>,
        enr_cache: Arc<RwLock<lru::LruCache<NodeId, (Enr, SocketAddr)>>>,
    ) {
        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                match event {
                    Discv5Event::TalkRequest(talk_req) => {
                        let _ = talk_req_tx.send(talk_req).await;
                    }
                    Discv5Event::SessionEstablished(enr, socket_addr) => {
                        enr_cache.write().put(enr.node_id(), (enr, socket_addr));
                    }
                    _ => {}
                }
            }
        });
    }
}

pub type ProtocolRequest = Vec<u8>;

/// Base Node Discovery Protocol v5 layer
pub struct Discovery {
    discv5: Discv5,
    enr_cache: Arc<RwLock<lru::LruCache<NodeId, (Enr, SocketAddr)>>>,
    /// Indicates if the discv5 service has been started
    pub started: bool,
    pub listen_socket: SocketAddr,
}

impl fmt::Debug for Discovery {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Discovery: ( enr: {}, started: {}, listen_socket: {} )",
            self.discv5.local_enr(),
            self.started,
            self.listen_socket
        )
    }
}

impl Discovery {
    pub fn new(portal_config: PortalnetConfig) -> Result<Self, String> {
        let listen_all_ips = SocketAddr::new("0.0.0.0".parse().unwrap(), portal_config.listen_port);

        let (ip_addr, ip_port) = if portal_config.no_stun {
            (None, portal_config.listen_port)
        } else {
            let known_external = portal_config
                .external_addr
                .or_else(|| socket::stun_for_external(&listen_all_ips));

            match known_external {
                Some(socket) => (Some(socket.ip()), socket.port()),
                None => (None, portal_config.listen_port),
            }
        };

        let config = Config {
            discv5_config: Discv5ConfigBuilder::default().build(),
            // This is for defining the ENR:
            enr_address: ip_addr,
            listen_port: ip_port,
            bootnode_enrs: portal_config.bootnode_enrs,
            private_key: portal_config.private_key,
            ..Default::default()
        };

        let enr_key = match config.private_key {
            Some(val) => CombinedKey::secp256k1_from_bytes(val.0.clone().as_mut_slice()).unwrap(),
            None => CombinedKey::generate_secp256k1(),
        };

        let enr = {
            let mut builder = EnrBuilder::new("v4");
            if let Some(ip_address) = config.enr_address {
                builder.ip(ip_address);
            }
            builder.udp4(config.listen_port);
            builder.build(&enr_key).unwrap()
        };

        info!(
            "Starting discv5 with local enr encoded={:?} decoded={}",
            enr, enr
        );

        let discv5 = Discv5::new(enr, enr_key, config.discv5_config)
            .map_err(|e| format!("Failed to create discv5 instance: {}", e))?;

        for enr in config.bootnode_enrs {
            info!("Adding bootnode {}", enr);
            discv5
                .add_enr(enr)
                .map_err(|e| format!("Failed to add enr: {}", e))?;
        }

        let enr_cache = LruCache::new(portal_config.enr_cache_capacity);
        let enr_cache = Arc::new(RwLock::new(enr_cache));

        Ok(Self {
            discv5,
            enr_cache,
            started: false,
            listen_socket: listen_all_ips,
        })
    }

    pub async fn start(&mut self) -> Result<mpsc::Receiver<TalkRequest>, String> {
        self.discv5.start(self.listen_socket).await.unwrap();

        let event_rx = self.discv5.event_stream().await.unwrap();

        // TODO: Make channel capacity configurable.
        let (talk_req_tx, talk_req_rx) = mpsc::channel(100);

        let enr_cache = Arc::clone(&self.enr_cache);

        DiscoveryEvents::start(event_rx, talk_req_tx, enr_cache).await;

        self.started = true;
        Ok(talk_req_rx)
    }

    /// Returns number of connected peers in the dht
    pub fn connected_peers_len(&self) -> usize {
        self.discv5.connected_peers()
    }

    /// Returns ENR and nodeId information of the local discv5 node
    pub fn node_info(&self) -> Value {
        json!({
            "enr":  self.discv5.local_enr().to_base64(),
            "nodeId":  self.discv5.local_enr().node_id().to_string(),
            "ip":  self.discv5.local_enr().ip4().map_or("None".to_owned(), |ip| ip.to_string())
        })
    }

    /// Returns vector of all ENR node IDs of nodes currently contained in the routing table mapped to JSON Value.
    pub fn routing_table_info(&self) -> Value {
        let buckets: Vec<(String, String, String)> = self
            .discv5
            .table_entries()
            .iter()
            .map(|(node_id, enr, node_status)| {
                (
                    node_id.to_string(),
                    enr.to_base64(),
                    format!("{:?}", node_status.state),
                )
            })
            .collect();

        json!(
            {
                "localKey": self.discv5.local_enr().node_id().to_string(),
                "buckets": buckets
            }
        )
    }

    pub fn connected_peers(&self) -> Vec<NodeId> {
        self.discv5.table_entries_id()
    }

    pub fn table_entries_enr(&self) -> Vec<Enr> {
        self.discv5.table_entries_enr()
    }

    pub fn local_enr(&self) -> Enr {
        self.discv5.local_enr()
    }

    pub fn find_enr(&self, node_id: &NodeId) -> Option<Enr> {
        self.discv5.find_enr(node_id)
    }

    /// Returns the cached ENR and observed socket address or `None` if not cached.
    pub fn cached_enr(&self, node_id: &NodeId) -> Option<(Enr, SocketAddr)> {
        match self.enr_cache.write().get(node_id) {
            Some(enr) => Some(enr.clone()),
            None => None,
        }
    }

    pub async fn send_talk_req(
        &self,
        enr: Enr,
        protocol: ProtocolId,
        request: ProtocolRequest,
    ) -> Result<Vec<u8>, RequestError> {
        // Send empty protocol id if unable to convert it to bytes
        let protocol = Vec::try_from(protocol).unwrap_or(vec![]);

        let response = self.discv5.talk_req(enr, protocol, request).await?;
        Ok(response)
    }
}
