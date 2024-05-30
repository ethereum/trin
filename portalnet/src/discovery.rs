use std::{
    fmt, fs,
    hash::{Hash, Hasher},
    io,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use anyhow::anyhow;
use async_trait::async_trait;
use discv5::{
    enr::{CombinedKey, Enr as Discv5Enr, NodeId},
    ConfigBuilder, Discv5, Event, ListenConfig, RequestError, TalkRequest,
};
use lru::LruCache;
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use utp_rs::{cid::ConnectionPeer, udp::AsyncUdpSocket};

use super::config::PortalnetConfig;
use crate::socket;
use ethportal_api::{
    types::{
        discv5::RoutingTableInfo,
        enr::Enr,
        portal_wire::{NetworkSpec, ProtocolId},
    },
    utils::bytes::{hex_decode, hex_encode},
    NodeInfo,
};
use trin_utils::version::get_trin_version;

/// Size of the buffer of the Discv5 TALKREQ channel.
const TALKREQ_CHANNEL_BUFFER: usize = 100;

/// ENR key for portal network client version.
const ENR_PORTAL_CLIENT_KEY: &str = "c";

/// ENR file name saving enr history to disk.
const ENR_FILE_NAME: &str = "trin.enr";

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
    /// The Portal Network to Protocal Id Map etc MAINNET, ANGELFOOD
    network_spec: Arc<NetworkSpec>,
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
    pub fn new(
        portal_config: PortalnetConfig,
        node_data_dir: PathBuf,
        network_spec: Arc<NetworkSpec>,
    ) -> Result<Self, String> {
        let listen_all_ips = SocketAddr::new(
            "0.0.0.0"
                .parse()
                .expect("Parsing static socket address to work"),
            portal_config.listen_port,
        );

        let (mut enr_address, mut enr_port) = if portal_config.no_stun {
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

        if !portal_config.no_upnp && !socket::is_local_addr(enr_address) {
            if let Some(socket) = socket::upnp_for_external(listen_all_ips) {
                if let Some(known_external) = enr_address {
                    if known_external != socket.ip() {
                        if portal_config.external_addr.is_some() {
                            return Err(format!(
                                "Mismatched known external address {} vs UPnP found address {}, consider disable --external-addr or --no-upnp",
                                known_external,
                                socket.ip()
                            ));
                        } else {
                            // STUN address is different from UPnP address. Use UPnP
                            warn!("overriding STUN address with known UPnP external address");
                        }
                    }
                };
                enr_address = Some(socket.ip());
                enr_port = socket.port();
            }
        };

        let enr_key =
            CombinedKey::secp256k1_from_bytes(portal_config.private_key.0.clone().as_mut_slice())
                .map_err(|e| format!("Unable to create enr key: {:?}", e.to_string()))?;

        let mut enr = {
            let mut builder = Discv5Enr::builder();
            if let Some(ip_address) = enr_address {
                builder.ip(ip_address);
            }
            builder.udp4(enr_port);

            let trin_version = get_trin_version();
            // Use "t" as short-hand for "Trin" to save bytes in ENR.
            let client_info = format!("t {trin_version}");
            // Use "c" as short-hand for "client".
            builder.add_value(ENR_PORTAL_CLIENT_KEY, &client_info.as_bytes());
            builder
                .build(&enr_key)
                .map_err(|e| format!("When adding key to servers ENR: {e:?}"))?
        };

        // Check if we have an old version of our Enr and if we do, increase our sequence number
        let trin_enr_path = node_data_dir.join(ENR_FILE_NAME);
        if trin_enr_path.is_file() {
            let data = fs::read_to_string(trin_enr_path.clone())
                .expect("Unable to read Trin Enr from file");
            let old_enr = Enr::from_str(&data).expect("Expected to read valid Trin Enr from file");
            enr.set_seq(old_enr.seq(), &enr_key)
                .expect("Unable to set Enr sequence number");

            // If the content is different then increase the sequence number
            if !enr.compare_content(&old_enr) {
                enr.set_seq(old_enr.seq() + 1, &enr_key)
                    .expect("Unable to increase Enr sequence number");
                fs::write(trin_enr_path, enr.to_base64())
                    .expect("Unable to update Trin Enr to file");
            } else {
                // the content is the same, we don't want to change signatures on restart
                // so set enr to old one to keep the same signature per sequence number
                enr = old_enr;
            }
        } else {
            // Write enr to disk
            fs::write(trin_enr_path, enr.to_base64()).expect("Unable to write Trin Enr to file");
        }

        let listen_config = ListenConfig::Ipv4 {
            ip: Ipv4Addr::UNSPECIFIED,
            port: portal_config.listen_port,
        };

        let discv5_config = ConfigBuilder::new(listen_config)
            .request_timeout(Duration::from_secs(3))
            .build();
        let discv5 = Discv5::new(enr, enr_key, discv5_config)
            .map_err(|e| format!("Failed to create discv5 instance: {e}"))?;

        let bootnode_enrs: Vec<Enr> = portal_config.bootnodes.into();
        for enr in bootnode_enrs {
            if enr.node_id() == discv5.local_enr().node_id() {
                warn!("Bootnode ENR is the same as the local ENR. Skipping.");
                continue;
            }
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
            network_spec,
        })
    }

    pub async fn start(&mut self) -> Result<mpsc::Receiver<TalkRequest>, String> {
        info!(enr = %self.local_enr(), "Starting discv5 with");
        debug!(enr = ?self.local_enr(), "Discv5 enr details");

        self.discv5
            .start()
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
                    Event::TalkRequest(talk_req) => {
                        // Forward all TALKREQ messages.
                        let _ = talk_req_tx.send(talk_req).await;
                    }
                    Event::SessionEstablished(enr, socket_addr) => {
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
            node_id: hex_encode(self.discv5.local_enr().node_id().raw()),
            ip: self
                .discv5
                .local_enr()
                .ip4()
                .map_or(Some("None".to_owned()), |ip| Some(ip.to_string())),
        })
    }

    /// Returns the local node-id and a nested array of node-ids contained in each of this node's
    /// k-buckets.
    pub fn routing_table_info(&self) -> RoutingTableInfo {
        RoutingTableInfo {
            local_node_id: hex_encode(self.discv5.local_enr().node_id().raw()),
            buckets: self.discv5.kbuckets().into(),
        }
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

    /// Put a `NodeAddress` into cache. If the key already exists in the cache, then it updates the
    /// key's value and returns the old value. Otherwise, `None` is returned.
    pub fn put_cached_node_addr(&self, node_addr: NodeAddress) -> Option<NodeAddress> {
        self.node_addr_cache
            .write()
            .put(node_addr.enr.node_id(), node_addr)
    }

    /// Sends a TALKREQ message to `enr`.
    pub async fn send_talk_req(
        &self,
        enr: Enr,
        protocol: ProtocolId,
        request: ProtocolRequest,
    ) -> Result<Vec<u8>, RequestError> {
        // Send empty protocol id if unable to convert it to bytes
        let protocol = match self.network_spec.get_protocol_hex_from_id(&protocol) {
            Ok(protocol_id) => hex_decode(&protocol_id).unwrap_or_default(),
            Err(err) => {
                unreachable!("send_talk_req() should never receive an invalid ProtocolId protocol: err={err}");
            }
        };

        let response = self.discv5.talk_req(enr, protocol, request).await?;
        Ok(response)
    }
}

pub struct Discv5UdpSocket {
    talk_reqs: mpsc::UnboundedReceiver<TalkRequest>,
    discv5: Arc<Discovery>,
}

impl Discv5UdpSocket {
    pub fn new(discv5: Arc<Discovery>, talk_reqs: mpsc::UnboundedReceiver<TalkRequest>) -> Self {
        Self { discv5, talk_reqs }
    }
}

/// A wrapper around `Enr` that implements `ConnectionPeer`.
#[derive(Clone, Debug)]
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

// Why are we implementing Hash, PartialEq, Eq for UtpEnr?
// UtpEnr is used as an element of the key for a Connections HashTable in our uTP library.
// Enr's can change and are not stable, so if we initiate a ``connect_with_cid`` we are inserting
// our known Enr for the peer, but if the peer has a more upto date Enr, values will be different
// and the Hash for the old Enr and New Enr will be different, along with equating the two structs
// will return false. This leads us to a situation where our peer sends us a uTP messages back and
// our code thinks the same peer is instead 2 different peers causing uTP to ignore the messages. We
// fixed this by implementing Eq and Hash only using the NodeId of the Enr as it is the only stable
// non-updatable field in the Enr.
impl Hash for UtpEnr {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.node_id().hash(state);
    }
}

impl PartialEq for UtpEnr {
    fn eq(&self, other: &Self) -> bool {
        self.0.node_id() == other.0.node_id()
    }
}

impl Eq for UtpEnr {}

impl ConnectionPeer for UtpEnr {}

#[async_trait]
impl AsyncUdpSocket<UtpEnr> for Discv5UdpSocket {
    async fn send_to(&mut self, buf: &[u8], target: &UtpEnr) -> io::Result<usize> {
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

    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, UtpEnr)> {
        match self.talk_reqs.recv().await {
            Some(talk_req) => {
                let src_node_id = talk_req.node_id();
                let enr = match self.discv5.find_enr(src_node_id) {
                    Some(enr) => UtpEnr(enr),
                    None => {
                        let enr = match self.discv5.cached_node_addr(src_node_id) {
                            Some(node_addr) => Ok(node_addr.enr),
                            None => {
                                debug!(node_id = %src_node_id, "uTP packet from unknown source");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::db::{configure_node_data_dir, configure_trin_data_dir};
    use ethportal_api::types::{bootnodes::Bootnodes, portal_wire::MAINNET};

    #[test]
    fn test_enr_file() {
        // Setup temp trin data directory if we're in ephemeral mode
        let trin_data_dir = configure_trin_data_dir(true).unwrap();

        // Configure node data dir based on the provided private key
        let (node_data_dir, private_key) =
            configure_node_data_dir(trin_data_dir, None, "test".to_string()).unwrap();

        let mut portalnet_config = PortalnetConfig {
            private_key,
            bootnodes: Bootnodes::None,
            ..Default::default()
        };

        // test file doesn't already exist
        let trin_enr_file_location = node_data_dir.join(ENR_FILE_NAME);
        assert!(!trin_enr_file_location.is_file());

        // test trin.enr is made on first run
        let discovery = Discovery::new(
            portalnet_config.clone(),
            node_data_dir.clone(),
            MAINNET.clone(),
        )
        .unwrap();
        let data = fs::read_to_string(trin_enr_file_location.clone()).unwrap();
        let old_enr = Enr::from_str(&data).unwrap();
        assert_eq!(discovery.local_enr(), old_enr);
        assert_eq!(old_enr.seq(), 1);

        // test if Enr changes the Enr sequence is increased and if it is written to disk
        portalnet_config.listen_port = 2424;
        let discovery = Discovery::new(
            portalnet_config.clone(),
            node_data_dir.clone(),
            MAINNET.clone(),
        )
        .unwrap();
        assert_ne!(discovery.local_enr(), old_enr);
        let data = fs::read_to_string(trin_enr_file_location.clone()).unwrap();
        let old_enr = Enr::from_str(&data).unwrap();
        assert_eq!(discovery.local_enr().seq(), 2);
        assert_eq!(old_enr.seq(), 2);
        assert_eq!(discovery.local_enr(), old_enr);

        // test if the enr isn't changed that it's sequence stays the same
        let discovery = Discovery::new(portalnet_config, node_data_dir, MAINNET.clone()).unwrap();
        assert_eq!(discovery.local_enr(), old_enr);
        let data = fs::read_to_string(trin_enr_file_location).unwrap();
        let old_enr = Enr::from_str(&data).unwrap();
        assert_eq!(discovery.local_enr().seq(), 2);
        assert_eq!(old_enr.seq(), 2);
        assert_eq!(discovery.local_enr(), old_enr);
    }
}
