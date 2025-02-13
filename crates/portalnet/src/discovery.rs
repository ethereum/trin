use std::{
    fmt, io,
    net::{Ipv4Addr, SocketAddr},
    ops::Deref,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use anyhow::anyhow;
use async_trait::async_trait;
use bytes::Bytes;
use discv5::{
    enr::{CombinedKey, Enr as Discv5Enr, NodeId},
    ConfigBuilder, Discv5, Event, IpMode, ListenConfig, RequestError, TalkRequest,
};
use ethportal_api::{
    types::{
        discv5::RoutingTableInfo, enr::Enr, network::Subnetwork, node_contact::NodeContact,
        portal_wire::NetworkSpec,
    },
    utils::bytes::hex_decode,
    version::get_trin_version,
    NodeInfo,
};
use lru::LruCache;
use parking_lot::RwLock;
use tokio::sync::{mpsc, RwLock as TokioRwLock};
use tracing::{debug, info, warn};
use trin_validation::oracle::HeaderOracle;
use utp_rs::{
    peer::{ConnectionPeer, Peer},
    udp::AsyncUdpSocket,
};

use super::config::PortalnetConfig;
use crate::socket;

/// Size of the buffer of the Discv5 TALKREQ channel.
const TALKREQ_CHANNEL_BUFFER: usize = 100;

/// ENR key for portal network client version.
pub const ENR_PORTAL_CLIENT_KEY: &str = "c";

pub type ProtocolRequest = Vec<u8>;

/// Base Node Discovery Protocol v5 layer
pub struct Discovery {
    /// The inner Discv5 service.
    pub discv5: Discv5,
    /// A cache of the latest observed `NodeAddress` for a node ID.
    node_contact_cache: Arc<RwLock<LruCache<NodeId, NodeContact>>>,
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

        let enr = {
            let mut builder = Discv5Enr::builder();
            if let Some(ip_address) = enr_address {
                builder.ip(ip_address);
            }
            builder.udp4(enr_port);

            // Set the ENR sequence number to the current timestamp this prevents other nodes from
            // storing outdated Trin Enr's
            let epoch_timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| format!("When getting current time: {e:?}"))?
                .as_secs();
            builder.seq(epoch_timestamp);

            let trin_version = get_trin_version();
            // Use "t" as short-hand for "Trin" to save bytes in ENR.
            let client_info = format!("t {trin_version}");
            // Use "c" as short-hand for "client".
            builder.add_value(ENR_PORTAL_CLIENT_KEY, &client_info.as_bytes());
            builder
                .build(&enr_key)
                .map_err(|e| format!("When adding key to servers ENR: {e:?}"))?
        };

        let listen_config = ListenConfig::Ipv4 {
            ip: Ipv4Addr::UNSPECIFIED,
            port: portal_config.listen_port,
        };

        let discv5_config = ConfigBuilder::new(listen_config)
            .request_timeout(Duration::from_secs(3))
            .build();
        let discv5 = Discv5::new(enr, enr_key, discv5_config)
            .map_err(|e| format!("Failed to create discv5 instance: {e}"))?;

        for enr in portal_config.bootnodes {
            if enr.node_id() == discv5.local_enr().node_id() {
                warn!("Bootnode ENR is the same as the local ENR. Skipping.");
                continue;
            }
            discv5
                .add_enr(enr)
                .map_err(|e| format!("Failed to add bootnode enr: {e}"))?;
        }

        let node_contact_cache = LruCache::new(portal_config.node_contact_cache_capacity);
        let node_contact_cache = Arc::new(RwLock::new(node_contact_cache));

        Ok(Self {
            discv5,
            node_contact_cache,
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

        let node_contact_cache = Arc::clone(&self.node_contact_cache);

        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                match event {
                    Event::TalkRequest(talk_req) => {
                        // Forward all TALKREQ messages.
                        let _ = talk_req_tx.send(talk_req).await;
                    }
                    Event::SessionEstablished(enr, socket_addr) => {
                        // TODO: this is a temporary fix to prevent caching of eth2 nodes
                        // and will be updated to a more stable solution as soon as it
                        // validates the theory of what is causing the issue on mainnet.
                        if enr.get_decodable::<String>(ENR_PORTAL_CLIENT_KEY).is_none() {
                            debug!(
                                enr = ?enr,
                                "discv5 session established with node that does not have a portal client key, not caching"
                            );
                            continue;
                        }
                        if let Some(old) = node_contact_cache.write().put(
                            enr.node_id(),
                            NodeContact {
                                public_key: enr.public_key(),
                                enr: enr.clone(),
                                socket_addr,
                            },
                        ) {
                            debug!(
                                old = ?(old.enr, old.socket_addr),
                                new = ?(enr, socket_addr),
                                "cached node address updated"
                            );
                        } else {
                            debug!(addr = ?(enr, socket_addr), "node address cached");
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
            node_id: self.discv5.local_enr().node_id(),
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
            local_node_id: self.discv5.local_enr().node_id(),
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

    pub fn try_node_contact_from_enr(&self, enr: Enr) -> anyhow::Result<NodeContact> {
        let socket_addr = match self.discv5.ip_mode().get_contactable_addr(&enr) {
            Some(socket_addr) => socket_addr,
            None => return Err(anyhow!("No contactable address in ENR")),
        };

        Ok(NodeContact {
            public_key: enr.public_key(),
            socket_addr,
            enr,
        })
    }

    pub fn ip_mode(&self) -> IpMode {
        self.discv5.ip_mode()
    }

    /// Returns the cached `NodeContact` or `None` if not cached.
    pub fn cached_node_contact(&self, node_id: &NodeId) -> Option<NodeContact> {
        self.node_contact_cache.write().get(node_id).cloned()
    }

    /// Put a `NodeContact` into cache. If the key already exists in the cache, then it updates the
    /// key's value and returns the old value. Otherwise, `None` is returned.
    pub fn put_cached_node_addr(&self, node_contact: NodeContact) -> Option<NodeContact> {
        self.node_contact_cache
            .write()
            .put(node_contact.enr.node_id(), node_contact)
    }

    /// Sends a TALKREQ message to `enr`.
    pub async fn send_talk_req(
        &self,
        node_contact: NodeContact,
        subnetwork: Subnetwork,
        request: ProtocolRequest,
    ) -> Result<Bytes, RequestError> {
        // Send empty protocol id if unable to convert it to bytes
        let protocol = match self
            .network_spec
            .get_protocol_identifier_from_subnetwork(&subnetwork)
        {
            Ok(protocol_id) => hex_decode(&protocol_id).unwrap_or_default(),
            Err(err) => {
                unreachable!(
                    "send_talk_req() should never receive an invalid Subnetwork: err={err}"
                );
            }
        };

        let response = self
            .discv5
            .talk_req(node_contact.into(), protocol, request)
            .await?;
        Ok(Bytes::from(response))
    }
}

pub struct Discv5UdpSocket {
    talk_request_receiver: mpsc::UnboundedReceiver<TalkRequest>,
    discv5: Arc<Discovery>,
    node_contact_cache: Arc<TokioRwLock<LruCache<NodeId, NodeContact>>>,
    header_oracle: Arc<TokioRwLock<HeaderOracle>>,
}

impl Discv5UdpSocket {
    pub fn new(
        discv5: Arc<Discovery>,
        talk_request_receiver: mpsc::UnboundedReceiver<TalkRequest>,
        header_oracle: Arc<TokioRwLock<HeaderOracle>>,
        node_contact_cache_capacity: usize,
    ) -> Self {
        let node_contact_cache = LruCache::new(node_contact_cache_capacity);
        let node_contact_cache = Arc::new(TokioRwLock::new(node_contact_cache));
        Self {
            discv5,
            talk_request_receiver,
            node_contact_cache,
            header_oracle,
        }
    }
}

/// A wrapper around `NodeContact` that implements `ConnectionPeer`.
#[derive(Clone)]
pub struct UtpPeer(pub NodeContact);

impl Deref for UtpPeer {
    type Target = NodeContact;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl UtpPeer {
    pub fn client(&self) -> Option<String> {
        self.enr
            .get_decodable::<String>(ENR_PORTAL_CLIENT_KEY)
            .and_then(|v| v.ok())
    }
}

impl std::fmt::Debug for UtpPeer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let peer_client_type = self.client().unwrap_or_else(|| "Unknown".to_string());
        f.debug_struct("UtpPeer")
            .field("enr", &self.0)
            .field("Peer Client Type", &peer_client_type)
            .finish()
    }
}

impl ConnectionPeer for UtpPeer {
    type Id = NodeId;

    fn id(&self) -> Self::Id {
        self.enr.node_id()
    }

    fn consolidate(a: Self, b: Self) -> Self {
        assert!(a.id() == b.id());
        if a.enr.seq() >= b.enr.seq() {
            a
        } else {
            b
        }
    }
}

#[async_trait]
impl AsyncUdpSocket<UtpPeer> for Discv5UdpSocket {
    async fn send_to(&mut self, buf: &[u8], peer: &Peer<UtpPeer>) -> io::Result<usize> {
        let peer_id = *peer.id();
        let peer_node_contact = peer.peer().cloned();
        let discv5 = Arc::clone(&self.discv5);
        let node_contact_cache = Arc::clone(&self.node_contact_cache);
        let header_oracle = Arc::clone(&self.header_oracle);
        let data = buf.to_vec();
        tokio::spawn(async move {
            let node_contact = match peer_node_contact {
                Some(node_contact) => node_contact.0,
                None => {
                    match find_node_contact(&peer_id, &discv5, node_contact_cache, header_oracle)
                        .await
                    {
                        Ok(node_contact) => node_contact,
                        Err(err) => {
                            warn!(%err, "unable to send uTP talk request, NodeContact not found");
                            return;
                        }
                    }
                }
            };
            match discv5
                .send_talk_req(node_contact, Subnetwork::Utp, data)
                .await
            {
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

    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, Peer<UtpPeer>)> {
        match self.talk_request_receiver.recv().await {
            Some(talk_req) => {
                let node_id = *talk_req.node_id();
                let packet = talk_req.body();
                let n = std::cmp::min(buf.len(), packet.len());
                buf[..n].copy_from_slice(&packet[..n]);

                // respond with empty talk response
                if let Err(err) = talk_req.respond(vec![]) {
                    warn!(%err, "failed to respond to uTP talk request");
                }

                Ok((n, Peer::new_id(node_id)))
            }
            None => Err(io::Error::from(io::ErrorKind::NotConnected)),
        }
    }
}

async fn find_node_contact(
    node_id: &NodeId,
    discv5: &Arc<Discovery>,
    node_contact_cache: Arc<TokioRwLock<LruCache<NodeId, NodeContact>>>,
    header_oracle: Arc<TokioRwLock<HeaderOracle>>,
) -> io::Result<NodeContact> {
    if let Some(cached_node_contact) = node_contact_cache.write().await.get(node_id).cloned() {
        return Ok(cached_node_contact);
    }

    if let Some(enr) = discv5.find_enr(node_id) {
        let node_contact = discv5.try_node_contact_from_enr(enr).map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Wasn't able to find a contactable address in the ENR: {err:?}"),
            )
        })?;
        node_contact_cache
            .write()
            .await
            .put(*node_id, node_contact.clone());
        return Ok(node_contact);
    }

    if let Some(node_contact) = discv5.cached_node_contact(node_id) {
        node_contact_cache
            .write()
            .await
            .put(*node_id, node_contact.clone());
        return Ok(node_contact);
    }

    let history_jsonrpc_tx = header_oracle.read().await.history_jsonrpc_tx();
    if let Ok(history_jsonrpc_tx) = history_jsonrpc_tx {
        if let Ok(enr) = HeaderOracle::history_get_enr(node_id, history_jsonrpc_tx).await {
            let node_contact = discv5.try_node_contact_from_enr(enr).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Wasn't able to find a contactable address in the ENR: {err:?}"),
                )
            })?;
            node_contact_cache
                .write()
                .await
                .put(*node_id, node_contact.clone());
            return Ok(node_contact);
        }
    }

    let state_jsonrpc_tx = header_oracle.read().await.state_jsonrpc_tx();
    if let Ok(state_jsonrpc_tx) = state_jsonrpc_tx {
        if let Ok(enr) = HeaderOracle::state_get_enr(node_id, state_jsonrpc_tx).await {
            let node_contact = discv5.try_node_contact_from_enr(enr).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Wasn't able to find a contactable address in the ENR: {err:?}"),
                )
            })?;
            node_contact_cache
                .write()
                .await
                .put(*node_id, node_contact.clone());
            return Ok(node_contact);
        }
    }

    let beacon_jsonrpc_tx = header_oracle.read().await.beacon_jsonrpc_tx();
    if let Ok(beacon_jsonrpc_tx) = beacon_jsonrpc_tx {
        if let Ok(enr) = HeaderOracle::beacon_get_enr(node_id, beacon_jsonrpc_tx).await {
            let node_contact = discv5.try_node_contact_from_enr(enr).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("Wasn't able to find a contactable address in the ENR: {err:?}"),
                )
            })?;
            node_contact_cache
                .write()
                .await
                .put(*node_id, node_contact.clone());
            return Ok(node_contact);
        }
    }

    debug!(node_id = %node_id, "uTP packet to unknown target");
    Err(io::Error::new(
        io::ErrorKind::Other,
        "NodeContact not found for talk req destination",
    ))
}
