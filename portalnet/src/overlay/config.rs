#![allow(clippy::result_large_err)]

use std::time::Duration;

use discv5::kbucket::{Filter, MAX_NODES_PER_BUCKET};
use ethportal_api::types::enr::Enr;

use crate::{
    constants::{DEFAULT_QUERY_TIMEOUT, DEFAULT_UTP_TRANSFER_LIMIT},
    types::node::Node,
};

/// Configuration parameters for the overlay network.
#[derive(Clone)]
pub struct OverlayConfig {
    pub bootnode_enrs: Vec<Enr>,
    pub bucket_pending_timeout: Duration,
    pub max_incoming_per_bucket: usize,
    pub table_filter: Option<Box<dyn Filter<Node>>>,
    pub bucket_filter: Option<Box<dyn Filter<Node>>>,
    pub ping_queue_interval: Option<Duration>,
    pub query_parallelism: usize,
    pub query_timeout: Duration,
    pub query_peer_timeout: Duration,
    pub query_num_results: usize,
    pub findnodes_query_distances_per_peer: usize,
    pub disable_poke: bool,
    pub gossip_dropped: bool,
    pub utp_transfer_limit: usize,
}

impl Default for OverlayConfig {
    fn default() -> Self {
        Self {
            bootnode_enrs: vec![],
            bucket_pending_timeout: Duration::from_secs(60),
            max_incoming_per_bucket: 16,
            table_filter: None,
            bucket_filter: None,
            ping_queue_interval: None,
            query_parallelism: 3, // (recommended α from kademlia paper)
            query_peer_timeout: Duration::from_secs(2),
            query_timeout: DEFAULT_QUERY_TIMEOUT,
            query_num_results: MAX_NODES_PER_BUCKET,
            findnodes_query_distances_per_peer: 3,
            disable_poke: false,
            gossip_dropped: false,
            utp_transfer_limit: DEFAULT_UTP_TRANSFER_LIMIT,
        }
    }
}

/// A configuration used by a single query to find content.
#[derive(Debug, Default)]
pub struct FindContentConfig {
    /// Whether to trace the actions of each peer during the query
    ///
    /// This is useful for debugging and understanding the query process, but adds some overhead.
    pub is_trace: bool,

    /// Customize the timeout for the query.
    ///
    /// If set to None, the default timeout is used.
    pub timeout: Option<Duration>,
}
