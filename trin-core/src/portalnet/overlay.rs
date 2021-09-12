use crate::portalnet::types::SszEnr;
use crate::portalnet::{Enr, U256};
use crate::utils::xor_two_values;

use discv5::enr::NodeId;
use discv5::kbucket::{Filter, KBucketsTable};
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::Duration;

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
pub struct Config {
    bucket_pending_timeout: Duration,
    max_incoming_per_bucket: usize,
    table_filter: Option<Box<dyn Filter<Node>>>,
    bucket_filter: Option<Box<dyn Filter<Node>>>,
}

impl Default for Config {
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
pub struct Overlay {
    // The ENR of the local node.
    local_enr: Arc<RwLock<Enr>>,
    // The data radius of the local node.
    data_radius: Arc<RwLock<U256>>,
    // The routing table of the local node.
    kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
}

impl Overlay {
    pub fn new(local_enr: Enr, data_radius: U256, config: Config) -> Self {
        let kbuckets = Arc::new(RwLock::new(KBucketsTable::new(
            local_enr.node_id().into(),
            config.bucket_pending_timeout,
            config.max_incoming_per_bucket,
            config.table_filter,
            config.bucket_filter,
        )));
        let local_enr = Arc::new(RwLock::new(local_enr));
        let data_radius = Arc::new(RwLock::new(data_radius));

        Self {
            local_enr,
            data_radius,
            kbuckets,
        }
    }

    /// Returns the local ENR of the node.
    pub fn local_enr(&self) -> Enr {
        self.local_enr.read().clone()
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
}
