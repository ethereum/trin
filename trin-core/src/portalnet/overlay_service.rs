use std::fmt;
use std::sync::Arc;

use crate::{
    locks::RwLoggingExt,
    portalnet::{
        discovery::Discovery,
        types::{
            messages::{
                ByteList, Content, FindContent, FindNodes, Message, Nodes, Ping, Pong, ProtocolId,
                Request, Response, SszEnr,
            },
            uint::U256,
        },
        Enr,
    },
    utils::distance::xor_two_values,
};

use discv5::{enr::NodeId, kbucket::KBucketsTable};
use futures::channel::oneshot;
use log::{debug, info};
use rocksdb::DB;
use ssz::Encode;
use ssz_types::VariableList;
use thiserror::Error;
use tokio::sync::{
    mpsc::{self, UnboundedReceiver, UnboundedSender},
    RwLock,
};

/// Maximum number of ENRs in response to FindNodes.
pub const FIND_NODES_MAX_NODES: usize = 32;
/// Maximum number of ENRs in response to FindContent.
pub const FIND_CONTENT_MAX_NODES: usize = 32;

/// An incoming or outgoing request.
#[derive(Debug)]
pub enum RequestDirection {
    /// An incoming request from `source`.
    Incoming { source: NodeId },
    /// An outgoing request to `destination`.
    Outgoing { destination: Enr },
}

/// A request to pass through the overlay.
#[derive(Debug)]
pub struct OverlayRequest {
    /// The inner request.
    pub request: Request,
    /// The direction of the request.
    pub direction: RequestDirection,
    /// An optional responder to send a result of the request.
    /// The responder may be None if the request was initiated internally.
    pub responder: Option<oneshot::Sender<Result<Response, OverlayRequestError>>>,
}

/// An overlay request error.
#[derive(Error, Debug)]
pub enum OverlayRequestError {
    /// A failure to transmit or receive a message on a channel.
    #[error("Channel failure: {0}")]
    ChannelFailure(String),

    /// An invalid request was received.
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// An invalid response was received.
    #[error("Invalid response")]
    InvalidResponse,

    #[error("The request returned an empty response")]
    EmptyResponse,

    /// A failure to decode a message.
    #[error("The message was unable to be decoded")]
    DecodeError,

    /// The request timed out.
    #[error("The request timed out")]
    Timeout,

    /// The request was unable to be served.
    #[error("Failure to serve request: {0}")]
    Failure(String),

    /// The request  Discovery v5 request error.
    #[error("Internal Discovery v5 error: {0}")]
    Discv5Error(discv5::RequestError),
}

impl From<discv5::RequestError> for OverlayRequestError {
    fn from(err: discv5::RequestError) -> Self {
        match err {
            discv5::RequestError::Timeout => Self::Timeout,
            err => Self::Discv5Error(err),
        }
    }
}

/// A node in the overlay network routing table.
#[derive(Clone)]
pub struct Node {
    /// The node's ENR.
    enr: Enr,
    /// The node's data radius.
    data_radius: U256,
}

impl Node {
    /// Returns the ENR of the node.
    pub fn enr(&self) -> Enr {
        self.enr.clone()
    }

    /// Returns the data radius of the node.
    pub fn data_radius(&self) -> U256 {
        self.data_radius.clone()
    }

    /// Sets the ENR of the node.
    pub fn set_enr(&mut self, enr: Enr) {
        self.enr = enr;
    }

    /// Sets the data radius of the node.
    pub fn set_data_radius(&mut self, radius: U256) {
        self.data_radius = radius;
    }
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Node(node_id={}, radius={})",
            self.enr.node_id(),
            self.data_radius,
        )
    }
}

impl std::cmp::Eq for Node {}

impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        self.enr == other.enr
    }
}

/// The overlay service.
pub struct OverlayService {
    /// The underlying Discovery v5 protocol.
    discovery: Arc<Discovery>,
    /// The content database of the local node.
    db: Arc<DB>,
    /// The routing table of the local node.
    kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
    /// The data radius of the local node.
    data_radius: Arc<U256>,
    /// The protocol identifier.
    protocol: ProtocolId,
    // TODO: This should probably be a bounded channel.
    /// The receiver half of the service request channel.
    request_rx: UnboundedReceiver<OverlayRequest>,
}

impl OverlayService {
    /// Spawns the overlay network service.
    ///
    /// The state of the overlay network largely consists of its routing table. The routing table
    /// is updated according to incoming requests and responses as well as autonomous maintenance
    /// processes.
    pub async fn spawn(
        discovery: Arc<Discovery>,
        db: Arc<DB>,
        kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
        data_radius: Arc<U256>,
        protocol: ProtocolId,
    ) -> Result<UnboundedSender<OverlayRequest>, String> {
        let (request_tx, request_rx) = mpsc::unbounded_channel();
        let overlay_protocol = protocol.clone();

        tokio::spawn(async move {
            let mut service = Self {
                discovery,
                db,
                kbuckets,
                data_radius,
                protocol,
                request_rx,
            };

            info!("Starting {:?} overlay service", overlay_protocol);
            service.start().await;
        });

        Ok(request_tx)
    }

    async fn start(&mut self) {
        while let Some(request) = self.request_rx.recv().await {
            self.process_request(request).await;
        }
    }

    /// Returns the local ENR of the node.
    async fn local_enr(&self) -> Enr {
        self.discovery.discv5.local_enr()
    }

    /// Returns the data radius of the node.
    async fn data_radius(&self) -> U256 {
        *self.data_radius
    }

    /// Processes an overlay request.
    async fn process_request(&mut self, request: OverlayRequest) {
        // For incoming requests, handle the request, and then send the response over the channel.
        //
        // For outgoing requests, send the request via a TALK request over Discovery v5, and then
        // send the response over the channel.
        match request.direction {
            RequestDirection::Incoming { source } => {
                let response = self
                    .handle_request(request.request.clone(), source.clone())
                    .await;
                if let Some(responder) = request.responder {
                    let _ = responder.send(response);
                }
            }
            RequestDirection::Outgoing { destination } => {
                let response = self
                    .send_talk_req(request.request, destination.clone())
                    .await;
                if let Some(responder) = request.responder {
                    let _ = responder.send(response);
                }
            }
        }
    }

    /// Attempts to build a response for a request.
    async fn handle_request(
        &mut self,
        request: Request,
        source: NodeId,
    ) -> Result<Response, OverlayRequestError> {
        match request {
            Request::Ping(ping) => Ok(Response::Pong(self.handle_ping(ping, source).await)),
            Request::FindNodes(find_nodes) => {
                Ok(Response::Nodes(self.handle_find_nodes(find_nodes).await))
            }
            Request::FindContent(find_content) => Ok(Response::Content(
                self.handle_find_content(find_content).await?,
            )),
        }
    }

    /// Builds a `Pong` response for a `Ping` request.
    async fn handle_ping(&self, request: Ping, source: NodeId) -> Pong {
        debug!(
            "Handling {:?} ping request from node={}. Ping={:?}",
            self.protocol, source, request
        );
        let enr_seq = self.local_enr().await.seq();
        let data_radius = self.data_radius().await;
        let custom_payload = ByteList::from(data_radius.as_ssz_bytes());
        Pong {
            enr_seq,
            custom_payload,
        }
    }

    /// Builds a `Nodes` response for a `FindNodes` request.
    async fn handle_find_nodes(&self, request: FindNodes) -> Nodes {
        let distances64: Vec<u64> = request.distances.iter().map(|x| (*x).into()).collect();
        let enrs = self.nodes_by_distance(distances64).await;
        // `total` represents the total number of `Nodes` response messages being sent.
        // TODO: support returning multiple messages.
        Nodes { total: 1, enrs }
    }

    /// Attempts to build a `Content` response for a `FindContent` request.
    async fn handle_find_content(
        &self,
        request: FindContent,
    ) -> Result<Content, OverlayRequestError> {
        match self.db.get(&request.content_key) {
            Ok(Some(value)) => {
                let content = ByteList::from(VariableList::from(value));
                Ok(Content::Content(content))
            }
            Ok(None) => {
                let enrs = self.find_nodes_close_to_content(request.content_key).await;
                match enrs {
                    Ok(val) => Ok(Content::Enrs(val)),
                    Err(msg) => Err(OverlayRequestError::InvalidRequest(msg.to_string())),
                }
            }
            Err(msg) => Err(OverlayRequestError::Failure(format!(
                "Unable to respond to FindContent: {}",
                msg
            ))),
        }
    }

    /// Sends a TALK request via Discovery v5 to some destination node.
    async fn send_talk_req(
        &self,
        request: Request,
        destination: Enr,
    ) -> Result<Response, OverlayRequestError> {
        match self
            .discovery
            .send_talk_req(
                destination,
                self.protocol.clone(),
                Message::Request(request).to_bytes(),
            )
            .await
        {
            Ok(talk_resp) => match Message::from_bytes(&talk_resp) {
                Ok(Message::Response(response)) => Ok(response),
                Ok(_) => Err(OverlayRequestError::InvalidResponse),
                Err(_) => Err(OverlayRequestError::DecodeError),
            },
            Err(error) => Err(error.into()),
        }
    }

    /// Returns a vector of all the ENRs of nodes currently contained in the routing table.
    async fn table_entries_enr(&self) -> Vec<Enr> {
        self.kbuckets
            .write_with_warn()
            .await
            .iter()
            .map(|entry| entry.node.value.enr().clone())
            .collect()
    }

    /// Returns a vector of the ENRs of the closest nodes by the given log2 distances.
    async fn nodes_by_distance(&self, mut log2_distances: Vec<u64>) -> Vec<SszEnr> {
        let mut nodes_to_send = Vec::new();
        log2_distances.sort_unstable();
        log2_distances.dedup();

        let mut log2_distances = log2_distances.as_slice();
        if let Some(0) = log2_distances.first() {
            // If the distance is 0 send our local ENR.
            nodes_to_send.push(SszEnr::new(self.local_enr().await));
            log2_distances = &log2_distances[1..];
        }

        if !log2_distances.is_empty() {
            let mut kbuckets = self.kbuckets.write_with_warn().await;
            for node in kbuckets
                .nodes_by_distances(&log2_distances, FIND_NODES_MAX_NODES)
                .into_iter()
                .map(|entry| entry.node.value.clone())
            {
                nodes_to_send.push(SszEnr::new(node.enr()));
            }
        }
        nodes_to_send
    }

    /// Returns list of nodes closer to content than self, sorted by distance.
    async fn find_nodes_close_to_content(
        &self,
        content_key: Vec<u8>,
    ) -> Result<Vec<SszEnr>, OverlayRequestError> {
        let self_node_id = self.local_enr().await.node_id();
        let self_distance = match xor_two_values(&content_key, &self_node_id.raw().to_vec()) {
            Ok(val) => val,
            Err(msg) => {
                return Err(OverlayRequestError::InvalidRequest(format!(
                    "Could not find distance from node, because content key is malformed: {}",
                    msg
                )))
            }
        };

        let mut nodes_with_distance: Vec<(Vec<u8>, Enr)> = self
            .table_entries_enr()
            .await
            .into_iter()
            .map(|enr| {
                (
                    // naked unwrap since content key len has already been validated
                    xor_two_values(&content_key, &enr.node_id().raw().to_vec()).unwrap(),
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

        Ok(closest_nodes)
    }
}
