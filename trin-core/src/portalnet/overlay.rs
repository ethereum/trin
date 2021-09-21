use crate::utils::xor_two_values;

use super::{
    discovery::Discovery,
    types::{FindContent, FindNodes, Message, Ping, Request, SszEnr},
    Enr, U256,
};
use crate::portalnet::types::HexData;
use discv5::enr::NodeId;
use discv5::kbucket::{Filter, KBucketsTable};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

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

#[derive(Clone)]
pub struct PortalnetConfig {
    pub external_addr: Option<SocketAddr>,
    pub private_key: Option<HexData>,
    pub listen_port: u16,
    pub bootnode_enrs: Vec<Enr>,
    pub data_radius: U256,
}

impl Default for PortalnetConfig {
    fn default() -> Self {
        Self {
            external_addr: None,
            private_key: None,
            listen_port: 4242,
            bootnode_enrs: Vec::<Enr>::new(),
            data_radius: U256::from(u64::MAX), //TODO better data_radius default?
        }
    }
}

/// Configuration parameters for the overlay network.
#[derive(Clone)]
pub struct OverlayConfig {
    pub bucket_pending_timeout: Duration,
    pub max_incoming_per_bucket: usize,
    pub table_filter: Option<Box<dyn Filter<Node>>>,
    pub bucket_filter: Option<Box<dyn Filter<Node>>>,
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

/// Overlay protocol is a layer on top of discv5 that handles all requests from the overlay networks
/// (state, history etc.) and dispatch them to the discv5 protocol TalkReq. Each network should
/// implement the overlay protocol and the overlay protocol is where we can encapsulate the logic for
/// handling common network requests/responses.
#[derive(Clone)]
pub struct OverlayProtocol {
    pub discovery: Arc<RwLock<Discovery>>,
    // The data radius of the local node.
    pub data_radius: Arc<RwLock<U256>>,
    // The overlay routing table of the local node.
    pub kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
}

impl OverlayProtocol {
    /// Returns the local ENR of the node.
    pub async fn local_enr(&self) -> Enr {
        self.discovery.read().await.discv5.local_enr()
    }

    // Returns the data radius of the node.
    pub async fn data_radius(&self) -> U256 {
        self.data_radius.read().await.clone()
    }

    /// Returns a vector of the ENRs of the closest nodes by the given log2 distances.
    pub async fn nodes_by_distance(&self, mut log2_distances: Vec<u64>) -> Vec<Enr> {
        let mut nodes_to_send = Vec::new();
        log2_distances.sort_unstable();
        log2_distances.dedup();

        let mut log2_distances = log2_distances.as_slice();
        if let Some(0) = log2_distances.first() {
            // If the distance is 0 send our local ENR.
            nodes_to_send.push(self.local_enr().await);
            log2_distances = &log2_distances[1..];
        }

        if !log2_distances.is_empty() {
            let mut kbuckets = self.kbuckets.write().await;
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
    pub async fn find_nodes_close_to_content(&self, content_key: Vec<u8>) -> Vec<SszEnr> {
        let self_node_id = self.local_enr().await.node_id();
        let self_distance = xor_two_values(&content_key, &self_node_id.raw().to_vec());

        let mut nodes_with_distance: Vec<(Vec<u8>, Enr)> = self
            .table_entries_enr()
            .await
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
    pub async fn table_entries_id(&self) -> Vec<NodeId> {
        self.kbuckets
            .write()
            .await
            .iter()
            .map(|entry| *entry.node.key.preimage())
            .collect()
    }

    /// Returns a vector of all the ENRs of nodes currently contained in the routing table.
    pub async fn table_entries_enr(&self) -> Vec<Enr> {
        self.kbuckets
            .write()
            .await
            .iter()
            .map(|entry| entry.node.value.enr().clone())
            .collect()
    }

    pub async fn send_ping(
        &self,
        data_radius: U256,
        enr: Enr,
        protocol: String,
    ) -> Result<Vec<u8>, String> {
        let enr_seq = self.discovery.read().await.local_enr().seq();
        let msg = Ping {
            enr_seq,
            data_radius,
        };
        self.discovery
            .write()
            .await
            .send_talkreq(
                enr,
                protocol,
                Message::Request(Request::Ping(msg)).to_bytes(),
            )
            .await
    }

    pub async fn send_find_nodes(
        &self,
        distances: Vec<u16>,
        enr: Enr,
        protocol: String,
    ) -> Result<Vec<u8>, String> {
        let msg = FindNodes { distances };
        self.discovery
            .write()
            .await
            .send_talkreq(
                enr,
                protocol,
                Message::Request(Request::FindNodes(msg)).to_bytes(),
            )
            .await
    }

    pub async fn send_find_content(
        &self,
        content_key: Vec<u8>,
        enr: Enr,
        protocol: String,
    ) -> Result<Vec<u8>, String> {
        let msg = FindContent { content_key };
        self.discovery
            .write()
            .await
            .send_talkreq(
                enr,
                protocol,
                Message::Request(Request::FindContent(msg)).to_bytes(),
            )
            .await
    }
}
