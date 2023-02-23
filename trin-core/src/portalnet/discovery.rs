use super::{
    types::messages::{HexData, PortalnetConfig, ProtocolId},
    Enr,
};
use crate::utils::bytes::hex_encode;
use crate::{socket, TRIN_VERSION};

use async_trait::async_trait;
use discv5::{
    enr::{CombinedKey, EnrBuilder, NodeId},
    Discv5, Discv5Config, Discv5ConfigBuilder, Discv5Event, RequestError, TalkRequest,
};
use lru::LruCache;
use parking_lot::RwLock;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tracing::info;

use anyhow::anyhow;
use ethportal_api::types::discv5::{Enr as EthportalEnr, NodeId as EthportalNodeId, NodeInfo};
use std::str::FromStr;
use std::{
    convert::TryFrom,
    fmt,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

/// Size of the buffer of the Discv5 TALKREQ channel.
const TALKREQ_CHANNEL_BUFFER: usize = 100;

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

pub type ProtocolRequest = Vec<u8>;

/// The contact info for a remote node.
#[derive(Clone, Debug)]
pub struct NodeAddress {
    /// The node's ENR.
    pub enr: Enr,
    /// The node's observed socket address.
    pub socket_addr: SocketAddr,
}

/// Base Node Discovery Protocol v5 layer
pub struct Discovery {
    /// The inner Discv5 service.
    discv5: Discv5,
    /// A cache of the latest observed `NodeAddress` for a node ID.
    node_addr_cache: Arc<RwLock<LruCache<NodeId, NodeAddress>>>,
    /// Indicates if the Discv5 service has been started.
    pub started: bool,
    /// The socket address that the Discv5 service listens on.
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

            // Use "t" as short-hand for "Trin" to save bytes in ENR.
            let client_info = format!("t {}", TRIN_VERSION);
            // Use "c" as short-hand for "client".
            builder.add_value("c", client_info.as_bytes());
            builder.build(&enr_key).unwrap()
        };

        let discv5 = Discv5::new(enr, enr_key, config.discv5_config)
            .map_err(|e| format!("Failed to create discv5 instance: {}", e))?;

        for enr in config.bootnode_enrs {
            discv5
                .add_enr(enr)
                .map_err(|e| format!("Failed to add bootnode enr: {}", e))?;
        }

        let node_addr_cache = LruCache::new(portal_config.node_addr_cache_capacity);
        let node_addr_cache = Arc::new(RwLock::new(node_addr_cache));

        Ok(Self {
            discv5,
            node_addr_cache,
            started: false,
            listen_socket: listen_all_ips,
        })
    }

    pub async fn start(&mut self) -> Result<mpsc::Receiver<TalkRequest>, String> {
        info!(
            enr.encoded = ?self.local_enr(),
            enr.decoded = %self.local_enr(),
            "Starting discv5",
        );

        let _ = self
            .discv5
            .start(self.listen_socket)
            .await
            .map_err(|e| format!("Failed to start discv5 server: {:?}", e))?;
        self.started = true;

        let mut event_rx = self.discv5.event_stream().await.unwrap();

        let (talk_req_tx, talk_req_rx) = mpsc::channel(TALKREQ_CHANNEL_BUFFER);

        let node_addr_cache = Arc::clone(&self.node_addr_cache);

        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                match event {
                    Discv5Event::TalkRequest(talk_req) => {
                        // Forward all TALKREQ messages.
                        let _ = talk_req_tx.send(talk_req).await;
                    }
                    Discv5Event::SessionEstablished(enr, socket_addr) => {
                        node_addr_cache
                            .write()
                            .put(enr.node_id(), NodeAddress { enr, socket_addr });
                    }
                    _ => continue,
                }
            }
        });

        Ok(talk_req_rx)
    }

    /// Returns number of connected peers in the Discv5 routing table.
    pub fn connected_peers_len(&self) -> usize {
        self.discv5.connected_peers()
    }

    /// Returns the ENRs in the Discv5 routing table.
    pub fn table_entries_enr(&self) -> Vec<Enr> {
        self.discv5.table_entries_enr()
    }

    /// Returns ENR and nodeId information of the local Discv5 node.
    pub fn node_info(&self) -> anyhow::Result<NodeInfo> {
        Ok(NodeInfo {
            enr: EthportalEnr::from_str(&self.discv5.local_enr().to_base64())
                .map_err(|err| anyhow!("{err}"))?,
            node_id: EthportalNodeId::from(self.discv5.local_enr().node_id().raw()),
            ip: self
                .discv5
                .local_enr()
                .ip4()
                .map_or(Some("None".to_owned()), |ip| Some(ip.to_string())),
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
                    hex_encode(node_id.raw()),
                    enr.to_base64(),
                    format!("{:?}", node_status.state),
                )
            })
            .collect();

        json!(
            {
                "localNodeId": hex_encode(self.discv5.local_enr().node_id().raw()),
                "buckets": buckets
            }
        )
    }

    /// Returns the node IDs of connected peers in the Discv5 routing table.
    pub fn connected_peers(&self) -> Vec<NodeId> {
        self.discv5.table_entries_id()
    }

    /// Returns the ENR of the local node.
    pub fn local_enr(&self) -> Enr {
        self.discv5.local_enr()
    }

    /// Looks up the ENR for `node_id`.
    pub fn find_enr(&self, node_id: &NodeId) -> Option<Enr> {
        self.discv5.find_enr(node_id)
    }

    /// Returns the cached `NodeAddress` or `None` if not cached.
    pub fn cached_node_addr(&self, node_id: &NodeId) -> Option<NodeAddress> {
        match self.node_addr_cache.write().get(node_id) {
            Some(addr) => Some(addr.clone()),
            None => None,
        }
    }

    /// Sends a TALKREQ message to `enr`.
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

pub struct Discv5UdpSocket {
    // `RwLock` for interior mutability.
    // TODO: Figure out a better mechanism here. The socket is the only holder of the lock.
    talk_reqs: tokio::sync::RwLock<mpsc::UnboundedReceiver<TalkRequest>>,
    discv5: Arc<Discovery>,
}

impl Discv5UdpSocket {
    pub fn new(discv5: Arc<Discovery>, talk_reqs: mpsc::UnboundedReceiver<TalkRequest>) -> Self {
        Self {
            discv5,
            talk_reqs: tokio::sync::RwLock::new(talk_reqs),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UtpEnr(pub Enr);

impl UtpEnr {
    pub fn node_id(&self) -> NodeId {
        self.0.node_id()
    }
}

impl std::hash::Hash for UtpEnr {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.seq().hash(state);
        self.0.node_id().hash(state);
        // since the struct should always have a valid signature, we can hash the signature
        // directly, rather than hashing the content.
        self.0.signature().hash(state);
    }
}

impl utp::cid::ConnectionPeer for UtpEnr {}

#[async_trait]
impl utp::udp::AsyncUdpSocket<UtpEnr> for Discv5UdpSocket {
    async fn send_to(&self, buf: &[u8], target: &UtpEnr) -> std::io::Result<usize> {
        match self
            .discv5
            .send_talk_req(target.0.clone(), ProtocolId::Utp, buf.to_vec())
            .await
        {
            // We drop the talk response because it is ignored in the uTP protocol.
            Ok(..) => Ok(buf.len()),
            Err(err) => {
                tracing::error!(error = ?err, "error sending talk request");
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("{err}"),
                ))
            }
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, UtpEnr)> {
        let mut talk_reqs = self.talk_reqs.write().await;
        match talk_reqs.recv().await {
            Some(talk_req) => {
                let node_addr = self.discv5.cached_node_addr(talk_req.node_id()).unwrap();
                let enr = UtpEnr(node_addr.enr);
                let packet = talk_req.body();
                let n = std::cmp::min(buf.len(), packet.len());
                buf[..n].copy_from_slice(&packet[..n]);

                // when the talk request is dropped, an empty response is sent via the `Drop`
                // implementation for `TalkRequest`

                Ok((n, enr))
            }
            None => Err(std::io::Error::from(std::io::ErrorKind::NotConnected)),
        }
    }
}
