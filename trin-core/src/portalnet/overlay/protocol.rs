use crate::portalnet::{
    discovery::Discovery,
    types::{
        FindContent, FindNodes, FoundContent, Message, Nodes, Ping, Pong, ProtocolKind, Request,
        Response, SszEnr,
    },
    Enr, U256,
};
use crate::utils::xor_two_values;

use super::service::{
    Node, OverlayRequest, OverlayService, RequestDirection, FIND_CONTENT_MAX_NODES,
    FIND_NODES_MAX_NODES,
};

use discv5::{
    enr::NodeId,
    kbucket::{Filter, KBucketsTable},
    TalkRequest,
};
use futures::channel::oneshot;
use rocksdb::DB;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc::UnboundedSender, RwLock};

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
pub struct OverlayProtocol {
    /// Reference to the underlying discv5 protocol.
    pub discovery: Arc<RwLock<Discovery>>,
    /// Reference to the database instance.
    pub db: Arc<DB>,
    /// The data radius of the local node.
    data_radius: Arc<RwLock<U256>>,
    /// The overlay routing table of the local node.
    kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
    /// The subnetwork protocol of the overlay.
    protocol: ProtocolKind,
    /// A sender to send requests to the OverlayService.
    request_tx: UnboundedSender<OverlayRequest>,
}

impl OverlayProtocol {
    pub async fn new(
        config: OverlayConfig,
        discovery: Arc<RwLock<Discovery>>,
        db: Arc<DB>,
        data_radius: U256,
        protocol: ProtocolKind,
    ) -> Self {
        let local_enr = discovery.read().await.local_enr();
        let kbuckets = Arc::new(RwLock::new(KBucketsTable::new(
            local_enr.node_id().into(),
            config.bucket_pending_timeout,
            config.max_incoming_per_bucket,
            config.table_filter,
            config.bucket_filter,
        )));

        let data_radius = Arc::new(RwLock::new(data_radius));
        let request_tx = OverlayService::spawn(
            Arc::clone(&discovery),
            Arc::clone(&db),
            Arc::clone(&kbuckets),
            Arc::clone(&data_radius),
            protocol.clone(),
        )
        .await
        .unwrap();

        Self {
            discovery,
            data_radius: data_radius,
            kbuckets,
            db,
            protocol,
            request_tx,
        }
    }

    /// Returns the subnetwork protocol of the overlay protocol.
    pub fn protocol(&self) -> &ProtocolKind {
        &self.protocol
    }

    /// Processes a single TALK request destined for the overlay protocol.
    pub async fn process_one_request(
        &self,
        talk_request: &TalkRequest,
    ) -> Result<Response, String> {
        let request = match Message::from_bytes(talk_request.body()) {
            Ok(Message::Request(r)) => r,
            Ok(_) => return Err("Invalid message".to_owned()),
            Err(e) => return Err(format!("Invalid request: {}", e)),
        };

        // Send a request through the overlay service.
        let (tx, rx) = oneshot::channel();
        let overlay_request = OverlayRequest {
            request,
            direction: RequestDirection::Incoming {
                source: *talk_request.node_id(),
            },
            responder: Some(tx),
        };
        if let Err(_) = self.request_tx.send(overlay_request) {
            return Err("Receiver half of channel dropped, unable to submit request".to_owned());
        }
        // Wait on the response.
        match rx.await {
            Ok(result) => result,
            Err(oneshot::Canceled) => {
                Err("Sender half of the response channel was dropped".to_owned())
            }
        }
    }

    /// Returns the local ENR of the node.
    pub async fn local_enr(&self) -> Enr {
        self.discovery.read().await.discv5.local_enr()
    }

    /// Returns the data radius of the node.
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

    /// Sends a `Ping` request to `enr`.
    pub async fn send_ping(&self, enr: Enr) -> Result<Pong, String> {
        let enr_seq = self.discovery.read().await.local_enr().seq();
        let request = Ping {
            enr_seq,
            data_radius: self.data_radius().await,
        };

        // Send a request through the overlay service.
        let (tx, rx) = oneshot::channel();
        let overlay_request = OverlayRequest {
            request: Request::Ping(request),
            direction: RequestDirection::Outgoing { destination: enr },
            responder: Some(tx),
        };
        if let Err(_) = self.request_tx.send(overlay_request) {
            return Err("Receiver half of channel dropped, unable to submit request".to_owned());
        }

        // Wait on the response.
        match rx.await {
            Ok(Ok(Response::Pong(pong))) => Ok(pong),
            Ok(Ok(_)) => Err("Unexpected response to Ping request".to_owned()),
            Ok(Err(error)) => Err(error),
            Err(oneshot::Canceled) => {
                Err("Sender half of the response channel was dropped".to_owned())
            }
        }
    }

    pub async fn send_find_nodes(&self, distances: Vec<u16>, enr: Enr) -> Result<Nodes, String> {
        let request = FindNodes { distances };

        // Send a request through the overlay service.
        let (tx, rx) = oneshot::channel();
        let overlay_request = OverlayRequest {
            request: Request::FindNodes(request),
            direction: RequestDirection::Outgoing { destination: enr },
            responder: Some(tx),
        };
        if let Err(_) = self.request_tx.send(overlay_request) {
            return Err("Receiver half of channel dropped, unable to submit request".to_owned());
        }

        // Wait on the response.
        match rx.await {
            Ok(Ok(Response::Nodes(nodes))) => Ok(nodes),
            Ok(Ok(_)) => Err("Unexpected response to FindNodes request".to_owned()),
            Ok(Err(error)) => Err(error),
            Err(oneshot::Canceled) => {
                Err("Sender half of the response channel was dropped".to_owned())
            }
        }
    }

    pub async fn send_find_content(
        &self,
        content_key: Vec<u8>,
        enr: Enr,
    ) -> Result<FoundContent, String> {
        let request = FindContent { content_key };

        // Send a request through the overlay service.
        let (tx, rx) = oneshot::channel();
        let overlay_request = OverlayRequest {
            request: Request::FindContent(request),
            direction: RequestDirection::Outgoing { destination: enr },
            responder: Some(tx),
        };
        if let Err(_) = self.request_tx.send(overlay_request) {
            return Err("Receiver half of channel dropped, unable to submit request".to_owned());
        }

        // Wait on the response.
        match rx.await {
            Ok(Ok(Response::FoundContent(found_content))) => Ok(found_content),
            Ok(Ok(_)) => Err("Unexpected response to FindContent request".to_owned()),
            Ok(Err(error)) => Err(error),
            Err(oneshot::Canceled) => {
                Err("Sender half of the response channel was dropped".to_owned())
            }
        }
    }
}
