#![allow(dead_code)]

use super::types::messages::{HexData, PortalnetConfig, ProtocolId};
use super::Enr;
use crate::socket;
use crate::utils::node_id::generate_random_node_id;
use discv5::enr::{CombinedKey, EnrBuilder, NodeId};
use discv5::{Discv5, Discv5Config, Discv5ConfigBuilder, RequestError};
use log::{debug, error, info, warn};
use rand::seq::SliceRandom;
use serde_json::{json, Value};
use std::convert::TryFrom;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// With even distribution assumptions, 2**17 is enough to put each node (estimating 100k nodes,
/// which is more than 10x the ethereum mainnet node count) into a unique bucket by the 17th bucket index.
const EXPECTED_NON_EMPTY_BUCKETS: usize = 17;

#[derive(Clone)]
pub struct Config {
    pub listen_address: IpAddr,
    pub listen_port: u16,
    pub discv5_config: Discv5Config,
    pub bootnode_enrs: Vec<Enr>,
    pub private_key: Option<HexData>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_address: "0.0.0.0".parse().expect("valid ip address"),
            listen_port: 4242,
            discv5_config: Discv5Config::default(),
            bootnode_enrs: vec![],
            private_key: None,
        }
    }
}

pub type ProtocolRequest = Vec<u8>;

/// Base Node Discovery Protocol v5 layer
pub struct Discovery {
    pub discv5: Discv5,
    /// Indicates if the discv5 service has been started
    pub started: bool,
    pub listen_socket: SocketAddr,
}

impl Discovery {
    pub fn new(portal_config: PortalnetConfig) -> Result<Self, String> {
        let listen_all_ips = SocketAddr::new("0.0.0.0".parse().unwrap(), portal_config.listen_port);

        let ip_addr = if portal_config.internal_ip {
            socket::default_local_address(portal_config.listen_port)
        } else {
            portal_config
                .external_addr
                .or_else(|| socket::stun_for_external(&listen_all_ips))
                .unwrap_or_else(|| socket::default_local_address(portal_config.listen_port))
        };

        let config = Config {
            discv5_config: Discv5ConfigBuilder::default().build(),
            // This is for defining the ENR:
            listen_port: ip_addr.port(),
            listen_address: ip_addr.ip(),
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
            builder.ip(config.listen_address);
            builder.udp(config.listen_port);
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

        Ok(Self {
            discv5,
            started: false,
            listen_socket: listen_all_ips,
        })
    }

    pub async fn start(&mut self) -> Result<(), String> {
        let _ = self
            .discv5
            .start(self.listen_socket)
            .await
            .map_err(|e| format!("Failed to start discv5 server: {:?}", e))?;
        self.started = true;
        Ok(())
    }

    /// Returns number of connected peers in the dht
    pub fn connected_peers_len(&self) -> usize {
        self.discv5.connected_peers()
    }

    /// Returns ENR and nodeId information of the local discv5 node
    pub fn node_info(&self) -> Value {
        json!({
            "enr":  self.discv5.local_enr().to_base64(),
            "nodeId":  self.discv5.local_enr().node_id().to_string()
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

    pub fn connected_peers(&mut self) -> Vec<NodeId> {
        self.discv5.table_entries_id()
    }

    pub fn local_enr(&self) -> Enr {
        self.discv5.local_enr()
    }

    /// Do a FindNode query and add the discovered peers to the dht
    pub async fn discover_nodes(&mut self) -> Result<(), String> {
        let random_node = NodeId::random();
        let nodes = self
            .discv5
            .find_node(random_node)
            .await
            .map_err(|e| format!("FindNode query failed: {:?}", e))?;

        info!("FindNode query found {} nodes", nodes.len());

        for node in nodes {
            self.discv5
                .add_enr(node)
                .map_err(|e| format!("Failed to add node to dht: {}", e))?;
        }
        Ok(())
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

    pub async fn bucket_refresh_lookup(self: Arc<Self>) {
        // construct a 30 second interval to search for new peers.
        let mut query_interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                _ = query_interval.tick() => {
                    // Look at local routing table and select the largest 17 buckets.
                    // We only need the 17 bits furthest from our own node ID, because the closest 239 bits of
                    // buckets are going to be empty-ish.
                    let buckets = self.discv5.kbuckets();
                    let buckets = buckets.buckets_iter().enumerate().collect::<Vec<_>>();
                    let buckets = &buckets[256 - EXPECTED_NON_EMPTY_BUCKETS..];
                    // Randomly pick one of these buckets.
                    let target_bucket = buckets.choose(&mut rand::thread_rng());

                     match target_bucket {
                         Some(bucket) => {
                             let target_bucket_idx = u8::try_from(bucket.0);
                             if let Ok(idx) = target_bucket_idx {
                                 // Randomly generate a NodeID that falls within the target bucket.
                                 let target_node_id = generate_random_node_id(idx, self.local_enr().node_id());
                                 // Do the random lookup on this node-id.
                                 match target_node_id {
                                     Ok(node_id) => {
                                        // get metrics
                                        let metrics = self.discv5.metrics();
                                        let connected_peers = self.discv5.connected_peers();
                                        debug!("Connected peers: {}, Active sessions: {}, Unsolicited requests/s: {:.2}", connected_peers, metrics.active_sessions, metrics.unsolicited_requests_per_second);
                                        debug!("Searching for discv5 peers...");
                                        // execute a FINDNODE query
                                        self.recursive_find_node(node_id).await;
                            },
                                     Err(msg) => warn!("{:?}", msg),
                                 }
                             } else {
                                 error!("Unable to downcast bucket index.")
                             }
                         }
                         None => error!("Failed to choose random bucket index"),
                     }
                }
            }
        }
    }

    /// Searching for discv5 peers with recursive FINDNODE
    async fn recursive_find_node(&self, node_id: NodeId) {
        match self.discv5.find_node(node_id).await {
            Err(e) => warn!("Find Node result failed: {:?}", e),
            Ok(v) => {
                // found a list of ENR's print their NodeIds
                let node_ids = v.iter().map(|enr| enr.node_id()).collect::<Vec<_>>();
                debug!("Nodes found: {}", node_ids.len());
                for node_id in node_ids {
                    debug!("Node: {}", node_id);
                }
            }
        }
    }
}
