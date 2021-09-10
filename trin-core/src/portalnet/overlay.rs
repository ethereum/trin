use crate::utils::{xor_two_values, setup_overlay_db};
use log::debug;

use discv5::enr::NodeId;
use discv5::kbucket::{Filter, KBucketsTable};
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::Duration;
use crate::portalnet::{Enr, U256};
use crate::portalnet::discovery::Discovery;
use crate::portalnet::protocol::{PortalnetConfig, PROTOCOL, PortalnetEvents};
use crate::portalnet::types::{
        FindContent, FindNodes, Message, Ping, Request, SszEnr,
    };

/// Maximum number of ENRs in response to FindNodes.
const FIND_NODES_MAX_NODES: usize = 32;
/// Maximum number of ENRs in response to FindContent.
const FIND_CONTENT_MAX_NODES: usize = 32;

#[derive(Clone)]
pub struct Node {
    enr: Enr,
    data_radius: U256,
}

impl Node {
    pub fn enr(&self) -> Enr {
        self.enr.clone()
    }

    pub fn data_radius(&self) -> U256 {
        self.data_radius.clone()
    }
}

impl std::cmp::Eq for Node {}

impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        self.enr == other.enr
    }
}

/// Configuration parameters for the overlay network.
#[derive(Clone)]
pub struct OverlayConfig {
    bucket_pending_timeout: Duration,
    max_incoming_per_bucket: usize,
    table_filter: Option<Box<dyn Filter<Node>>>,
    bucket_filter: Option<Box<dyn Filter<Node>>>,
}

impl Default for OverlayConfig {
    fn default() -> Self {
        Self {
            bucket_pending_timeout: Duration::from_secs(60),
            max_incoming_per_bucket: 16,
            table_filter: None,
            bucket_filter: None,
        }
    }
}

/// The node state for a node in an overlay network on top of Discovery v5.
#[derive(Clone)]
pub struct OverlayProtocol {
    discovery: Arc<Discovery>,
    // The data radius of the local node.
    data_radius: Arc<RwLock<U256>>,
    // The overlay routing table of the local node.
    kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
}

impl OverlayProtocol {
       /// Returns the local ENR of the node.
    pub fn local_enr(&self) -> Enr {
        self.discovery.discv5.local_enr()
    }

    // Returns the data radius of the node.
    pub fn data_radius(&self) -> U256 {
        self.data_radius.read().clone()
    }

    /// Returns a vector of the ENRs of the closest nodes by the given log2 distances.
    pub fn nodes_by_distance(&self, mut log2_distances: Vec<u64>) -> Vec<Enr> {
        let mut nodes_to_send = Vec::new();
        log2_distances.sort_unstable();
        log2_distances.dedup();

        let mut log2_distances = log2_distances.as_slice();
        if let Some(0) = log2_distances.first() {
            // If the distance is 0 send our local ENR.
            nodes_to_send.push(self.local_enr());
            log2_distances = &log2_distances[1..];
        }

        if !log2_distances.is_empty() {
            let mut kbuckets = self.kbuckets.write();
            for node in kbuckets
                .nodes_by_distances(&log2_distances, FIND_NODES_MAX_NODES)
                .into_iter()
                .map(|entry| entry.node.value.clone())
            {
                nodes_to_send.push(node.enr());
            }
        }
        nodes_to_send
    }

    /// Returns list of nodes closer to content than self, sorted by distance.
    pub fn find_nodes_close_to_content(&self, content_key: Vec<u8>) -> Vec<SszEnr> {
        let self_node_id = self.local_enr().node_id();
        let self_distance = xor_two_values(&content_key, &self_node_id.raw().to_vec());

        let mut nodes_with_distance: Vec<(Vec<u8>, Enr)> = self
            .table_entries_enr()
            .into_iter()
            .map(|enr| {
                (
                    xor_two_values(&content_key, &enr.node_id().raw().to_vec()),
                    enr,
                )
            })
            .collect();

        nodes_with_distance.sort_by(|a, b| a.0.cmp(&b.0));

        let closest_nodes = nodes_with_distance
            .into_iter()
            .take(FIND_CONTENT_MAX_NODES)
            .filter(|node_record| &node_record.0 < &self_distance)
            .map(|node_record| SszEnr::new(node_record.1))
            .collect();

        closest_nodes
    }

    /// Returns a vector of all ENR node IDs of nodes currently contained in the routing table.
    pub fn table_entries_id(&self) -> Vec<NodeId> {
        self.kbuckets
            .write()
            .iter()
            .map(|entry| *entry.node.key.preimage())
            .collect()
    }

    /// Returns a vector of all the ENRs of nodes currently contained in the routing table.
    pub fn table_entries_enr(&self) -> Vec<Enr> {
        self.kbuckets
            .write()
            .iter()
            .map(|entry| entry.node.value.enr().clone())
            .collect()
    }

    pub async fn send_ping(&self, data_radius: U256, enr: Enr) -> Result<Vec<u8>, String> {
        let enr_seq = self.discovery.local_enr().seq();
        let msg = Ping {
            enr_seq,
            data_radius,
        };
        self.discovery
            .send_talkreq(
                enr,
                PROTOCOL.to_string(),
                Message::Request(Request::Ping(msg)).to_bytes(),
            )
            .await
    }

    pub async fn send_find_nodes(&self, distances: Vec<u16>, enr: Enr) -> Result<Vec<u8>, String> {
        let msg = FindNodes { distances };
        self.discovery
            .send_talkreq(
                enr,
                PROTOCOL.to_string(),
                Message::Request(Request::FindNodes(msg)).to_bytes(),
            )
            .await
    }

    pub async fn send_find_content(
        &self,
        content_key: Vec<u8>,
        enr: Enr,
    ) -> Result<Vec<u8>, String> {
        let msg = FindContent { content_key };
        self.discovery
            .send_talkreq(
                enr,
                PROTOCOL.to_string(),
                Message::Request(Request::FindContent(msg)).to_bytes(),
            )
            .await
    }
}

#[derive(Clone)]
pub struct HistoryProtocol {
    overlay: Arc<OverlayProtocol>
}

impl HistoryProtocol {
    pub async fn new(mut discovery: Discovery, portal_config: PortalnetConfig) -> Result<(Self, PortalnetEvents), String>  {
        let config = OverlayConfig::default();
        let kbuckets = Arc::new(RwLock::new(KBucketsTable::new(
            discovery.local_enr().node_id().into(),
            config.bucket_pending_timeout,
            config.max_incoming_per_bucket,
            config.table_filter,
            config.bucket_filter,
        )));
        let data_radius = Arc::new(RwLock::new(portal_config.data_radius));

        let protocol_receiver = discovery
            .discv5
            .event_stream()
            .await
            .map_err(|e| e.to_string()).unwrap();

        let discovery = Arc::new(discovery);

        let overlay = OverlayProtocol {
            discovery: discovery.clone(),
            data_radius,
            kbuckets,
        };

        let overlay = Arc::new(overlay);
        let db = setup_overlay_db(discovery.local_enr());

        let events = PortalnetEvents {
            discovery: discovery.clone(),
            overlay: overlay.clone(),
            protocol_receiver,
            db,
        };

        let proto = Self {
            overlay: overlay.clone()
        };

        Ok((proto, events))
    }


    /// Convenience call for testing, quick way to ping bootnodes
    pub async fn ping_bootnodes(&mut self) -> Result<(), String> {
        // Trigger bonding with bootnodes, at both the base layer and portal overlay.
        // The overlay ping via talkreq will trigger a session at the base layer, then
        // a session on the (overlay) portal network.
        for enr in self.overlay.discovery.discv5.table_entries_enr() {
            debug!("Pinging {} on portal network", enr);
            let ping_result = self.overlay.send_ping(U256::from(u64::MAX), enr).await?;
            debug!("Portal network Ping result: {:?}", ping_result);
        }
        Ok(())
    }
}
