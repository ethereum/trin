use crate::utils::xor_two_values;

use super::{
    discovery::Discovery,
    types::{
        FindContent, FindNodes, FoundContent, Message, Nodes, Ping, Pong, ProtocolKind, Request,
        Response, SszEnr,
    },
    Enr, U256,
};
use discv5::{
    enr::NodeId,
    kbucket::{Filter, KBucketsTable},
    TalkRequest,
};
use log::debug;
use rocksdb::DB;
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
    /// Reference to the underlying discv5 protocol
    pub discovery: Arc<RwLock<Discovery>>,
    // The data radius of the local node.
    pub data_radius: Arc<RwLock<U256>>,
    // The overlay routing table of the local node.
    pub kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
    // Reference to the database instance
    pub db: Arc<DB>,
}

impl OverlayProtocol {
    pub async fn new(
        config: OverlayConfig,
        discovery: Arc<RwLock<Discovery>>,
        db: Arc<DB>,
        data_radius: U256,
    ) -> Self {
        let kbuckets = Arc::new(RwLock::new(KBucketsTable::new(
            discovery.read().await.local_enr().node_id().into(),
            config.bucket_pending_timeout,
            config.max_incoming_per_bucket,
            config.table_filter,
            config.bucket_filter,
        )));

        Self {
            discovery,
            data_radius: Arc::new(RwLock::new(data_radius)),
            kbuckets,
            db,
        }
    }

    pub async fn process_one_request(
        &self,
        talk_request: &TalkRequest,
    ) -> Result<Response, String> {
        let request = match Message::from_bytes(talk_request.body()) {
            Ok(Message::Request(r)) => r,
            Ok(_) => return Err("Invalid message".to_owned()),
            Err(e) => return Err(format!("Invalid request: {}", e)),
        };

        let response = match request {
            Request::Ping(Ping { .. }) => {
                debug!("Got overlay ping request {:?}", request);
                let enr_seq = self.discovery.read().await.local_enr().seq();
                Response::Pong(Pong {
                    enr_seq,
                    data_radius: self.data_radius().await,
                })
            }
            Request::FindNodes(FindNodes { distances }) => {
                let distances64: Vec<u64> = distances.iter().map(|x| (*x).into()).collect();
                let enrs = self.nodes_by_distance(distances64).await;
                Response::Nodes(Nodes {
                    // from spec: total = The total number of Nodes response messages being sent.
                    // TODO: support returning multiple messages
                    total: 1_u8,
                    enrs,
                })
            }
            Request::FindContent(FindContent { content_key }) => match self.db.get(&content_key) {
                Ok(Some(value)) => {
                    let empty_enrs: Vec<SszEnr> = vec![];
                    Response::FoundContent(FoundContent {
                        enrs: empty_enrs,
                        payload: value,
                    })
                }
                Ok(None) => {
                    let enrs = self.find_nodes_close_to_content(content_key).await;
                    let empty_payload: Vec<u8> = vec![];
                    Response::FoundContent(FoundContent {
                        enrs,
                        payload: empty_payload,
                    })
                }
                Err(e) => panic!("Unable to respond to FindContent: {}", e),
            },
        };
        Ok(response)
    }

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
        protocol: ProtocolKind,
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
                protocol.to_string(),
                Message::Request(Request::Ping(msg)).to_bytes(),
            )
            .await
    }

    pub async fn send_find_nodes(
        &self,
        distances: Vec<u16>,
        enr: Enr,
        protocol: ProtocolKind,
    ) -> Result<Vec<u8>, String> {
        let msg = FindNodes { distances };
        self.discovery
            .write()
            .await
            .send_talkreq(
                enr,
                protocol.to_string(),
                Message::Request(Request::FindNodes(msg)).to_bytes(),
            )
            .await
    }

    pub async fn send_find_content(
        &self,
        content_key: Vec<u8>,
        enr: Enr,
        protocol: ProtocolKind,
    ) -> Result<Vec<u8>, String> {
        let msg = FindContent { content_key };
        self.discovery
            .write()
            .await
            .send_talkreq(
                enr,
                protocol.to_string(),
                Message::Request(Request::FindContent(msg)).to_bytes(),
            )
            .await
    }
}
