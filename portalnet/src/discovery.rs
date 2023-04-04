use anyhow::anyhow;
use async_trait::async_trait;
use discv5::{
    enr::{CombinedKey, EnrBuilder, NodeId},
    Discv5, Discv5Config, Discv5ConfigBuilder, Discv5Event, RequestError, TalkRequest,
};
use ethereum_types::H256;
use lru::LruCache;
use parking_lot::RwLock;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use utp_rs::{cid::ConnectionPeer, udp::AsyncUdpSocket};

use super::types::messages::{PortalnetConfig, ProtocolId};
use crate::socket;
use ethportal_api::types::discv5::{NodeId as EthportalNodeId, NodeInfo};
use std::str::FromStr;
use std::{
    convert::TryFrom,
    fmt, io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use trin_types::enr::Enr;
use trin_utils::bytes::hex_encode;
use trin_utils::version::get_trin_version;

/// Size of the buffer of the Discv5 TALKREQ channel.
const TALKREQ_CHANNEL_BUFFER: usize = 100;

/// ENR key for portal network client version.
const ENR_PORTAL_CLIENT_KEY: &str = "c";

#[derive(Clone)]
pub struct Config {
    pub enr_address: Option<IpAddr>,
    pub listen_port: u16,
    pub discv5_config: Discv5Config,
    pub bootnode_enrs: Vec<Enr>,
    pub private_key: Option<H256>,
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
        let listen_all_ips = SocketAddr::new(
            "0.0.0.0"
                .parse()
                .expect("Parsing static socket address to work"),
            portal_config.listen_port,
        );

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
        };

        let enr_key = match config.private_key {
            Some(val) => CombinedKey::secp256k1_from_bytes(val.0.clone().as_mut_slice())
                .map_err(|e| format!("When building servers key pair: {e:?}"))?,
            None => CombinedKey::generate_secp256k1(),
        };

        let enr = {
            let mut builder = EnrBuilder::new("v4");
            if let Some(ip_address) = config.enr_address {
                builder.ip(ip_address);
            }
            builder.udp4(config.listen_port);

            let trin_version = get_trin_version();
            // Use "t" as short-hand for "Trin" to save bytes in ENR.
            let client_info = format!("t {trin_version}");
            // Use "c" as short-hand for "client".
            builder.add_value(ENR_PORTAL_CLIENT_KEY, client_info.as_bytes());
            builder
                .build(&enr_key)
                .map_err(|e| format!("When adding key to servers ENR: {e:?}"))?
        };

        let discv5 = Discv5::new(enr, enr_key, config.discv5_config)
            .map_err(|e| format!("Failed to create discv5 instance: {e}"))?;

        for enr in config.bootnode_enrs {
            discv5
                .add_enr(enr)
                .map_err(|e| format!("Failed to add bootnode enr: {e}"))?;
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

        self.discv5
            .start(self.listen_socket)
            .await
            .map_err(|e| format!("Failed to start discv5 server: {e:?}"))?;
        self.started = true;

        let mut event_rx = self
            .discv5
            .event_stream()
            .await
            .map_err(|e| format!("When launching event stream in new discv5: {e:?}"))?;

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
                        if let Some(old) = node_addr_cache.write().put(
                            enr.node_id(),
                            NodeAddress {
                                enr: enr.clone(),
                                socket_addr,
                            },
                        ) {
                            tracing::debug!(
                                old = ?(old.enr, old.socket_addr),
                                new = ?(enr, socket_addr),
                                "cached node address updated"
                            );
                        } else {
                            tracing::debug!(addr = ?(enr, socket_addr), "node address cached");
                        }
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
            enr: Enr::from_str(&self.discv5.local_enr().to_base64())
                .map_err(|err| anyhow!("{err}"))?,
            node_id: EthportalNodeId(self.discv5.local_enr().node_id().raw().into()),
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

    /// Adds `enr` to the discv5 routing table.
    pub fn add_enr(&self, enr: Enr) -> Result<(), &'static str> {
        self.discv5.add_enr(enr)
    }

    /// Returns the cached `NodeAddress` or `None` if not cached.
    pub fn cached_node_addr(&self, node_id: &NodeId) -> Option<NodeAddress> {
        self.node_addr_cache.write().get(node_id).cloned()
    }

    /// Sends a TALKREQ message to `enr`.
    pub async fn send_talk_req(
        &self,
        enr: Enr,
        protocol: ProtocolId,
        request: ProtocolRequest,
    ) -> Result<Vec<u8>, RequestError> {
        // Send empty protocol id if unable to convert it to bytes
        let protocol = Vec::try_from(protocol).unwrap_or_default();

        let response = self.discv5.talk_req(enr, protocol, request).await?;
        Ok(response)
    }
}

pub struct Discv5UdpSocket {
    // `Mutex` for interior mutability.
    // TODO: Figure out a better mechanism here. The socket is the only holder of the lock.
    talk_reqs: tokio::sync::Mutex<mpsc::UnboundedReceiver<TalkRequest>>,
    discv5: Arc<Discovery>,
}

impl Discv5UdpSocket {
    pub fn new(discv5: Arc<Discovery>, talk_reqs: mpsc::UnboundedReceiver<TalkRequest>) -> Self {
        Self {
            discv5,
            talk_reqs: tokio::sync::Mutex::new(talk_reqs),
        }
    }
}

/// A wrapper around `Enr` that implements `ConnectionPeer`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct UtpEnr(pub Enr);

impl UtpEnr {
    pub fn node_id(&self) -> NodeId {
        self.0.node_id()
    }

    pub fn client(&self) -> Option<String> {
        self.0
            .get(ENR_PORTAL_CLIENT_KEY)
            .and_then(|v| String::from_utf8(v.to_vec()).ok())
    }
}

impl ConnectionPeer for UtpEnr {}

#[async_trait]
impl AsyncUdpSocket<UtpEnr> for Discv5UdpSocket {
    async fn send_to(&self, buf: &[u8], target: &UtpEnr) -> io::Result<usize> {
        let discv5 = Arc::clone(&self.discv5);
        let target = target.0.clone();
        let data = buf.to_vec();
        tokio::spawn(async move {
            match discv5.send_talk_req(target, ProtocolId::Utp, data).await {
                // We drop the talk response because it is ignored in the uTP protocol.
                Ok(..) => {}
                Err(err) => match err {
                    RequestError::Timeout => debug!("uTP talk request timed out"),
                    err => warn!(%err, "unable to send uTP talk request"),
                },
            }
        });

        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, UtpEnr)> {
        let mut talk_reqs = self.talk_reqs.lock().await;
        match talk_reqs.recv().await {
            Some(talk_req) => {
                let src_node_id = talk_req.node_id();
                let enr = match self.discv5.find_enr(src_node_id) {
                    Some(enr) => UtpEnr(enr),
                    None => {
                        let enr = match self.discv5.cached_node_addr(src_node_id) {
                            Some(node_addr) => Ok(node_addr.enr),
                            None => {
                                warn!(node_id = %src_node_id, "uTP packet from unknown source");
                                Err(io::Error::new(
                                    io::ErrorKind::Other,
                                    "ENR not found for talk req destination",
                                ))
                            }
                        }?;
                        UtpEnr(enr)
                    }
                };
                let packet = talk_req.body();
                let n = std::cmp::min(buf.len(), packet.len());
                buf[..n].copy_from_slice(&packet[..n]);

                // respond with empty talk response
                if let Err(err) = talk_req.respond(vec![]) {
                    warn!(%err, "failed to respond to uTP talk request");
                }

                Ok((n, enr))
            }
            None => Err(io::Error::from(io::ErrorKind::NotConnected)),
        }
    }
}
