use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

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
    utils::{distance::xor_two_values, hash_delay_queue::HashDelayQueue},
};

use discv5::{
    enr::NodeId,
    kbucket::{
        self, ConnectionDirection, ConnectionState, FailureReason, InsertResult, KBucketsTable,
        NodeStatus, UpdateResult,
    },
    rpc::RequestId,
};
use futures::{channel::oneshot, stream::StreamExt};
use log::{debug, info, warn};
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

/// An overlay request error.
#[derive(Clone, Error, Debug)]
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

/// An incoming or outgoing request.
#[derive(Debug)]
pub enum RequestDirection {
    /// An incoming request from `source`.
    Incoming { id: RequestId, source: NodeId },
    /// An outgoing request to `destination`.
    Outgoing { destination: Enr },
}

/// An identifier for an overlay network request. The ID is used to track active outgoing requests.
// We only have visibility on the request IDs for incoming Discovery v5 talk requests. Here we use
// a separate identifier to track outgoing talk requests.
type OverlayRequestId = u128;

/// An overlay request response channel.
type OverlayResponder = oneshot::Sender<Result<Response, OverlayRequestError>>;

/// A request to pass through the overlay.
#[derive(Debug)]
pub struct OverlayRequest {
    /// The request identifier.
    pub id: OverlayRequestId,
    /// The inner request.
    pub request: Request,
    /// The direction of the request.
    pub direction: RequestDirection,
    /// An optional responder to send a result of the request.
    /// The responder may be None if the request was initiated internally.
    pub responder: Option<OverlayResponder>,
}

impl OverlayRequest {
    /// Creates a new overlay request.
    pub fn new(
        request: Request,
        direction: RequestDirection,
        responder: Option<OverlayResponder>,
    ) -> Self {
        OverlayRequest {
            id: rand::random(),
            request,
            direction,
            responder,
        }
    }
}

/// An active outgoing overlay request.
struct ActiveOverlayRequest {
    /// The ENR of the destination (target) node.
    pub destination: Enr,
    /// An optional responder to send the result of the associated request.
    pub responder: Option<OverlayResponder>,
}

/// A response for a particular overlay request.
struct OverlayResponse {
    /// The identifier of the associated request.
    pub request_id: OverlayRequestId,
    /// The result of the associated request.
    pub response: Result<Response, OverlayRequestError>,
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
    /// Creates a new node.
    pub fn new(enr: Enr, data_radius: U256) -> Node {
        Node { enr, data_radius }
    }

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
    /// A queue of peers that require regular ping to check connectivity.
    peers_to_ping: HashDelayQueue<NodeId>,
    // TODO: This should probably be a bounded channel.
    /// The receiver half of the service request channel.
    request_rx: UnboundedReceiver<OverlayRequest>,
    /// The sender half of a channel for service requests.
    /// This is used internally to submit requests (e.g. maintenance ping requests).
    request_tx: UnboundedSender<OverlayRequest>,
    /// A map of active outgoing requests.
    active_requests: Arc<RwLock<HashMap<OverlayRequestId, ActiveOverlayRequest>>>,
    /// The receiver half of a channel for responses to outgoing requests.
    response_rx: UnboundedReceiver<OverlayResponse>,
    /// The sender half of a channel for responses to outgoing requests.
    response_tx: UnboundedSender<OverlayResponse>,
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
        bootnode_enrs: Vec<Enr>,
        ping_queue_interval: Option<Duration>,
        data_radius: Arc<U256>,
        protocol: ProtocolId,
    ) -> Result<UnboundedSender<OverlayRequest>, String> {
        let (request_tx, request_rx) = mpsc::unbounded_channel();
        let internal_request_tx = request_tx.clone();

        let overlay_protocol = protocol.clone();

        let peers_to_ping = if let Some(interval) = ping_queue_interval {
            HashDelayQueue::new(interval)
        } else {
            HashDelayQueue::default()
        };

        let (response_tx, response_rx) = mpsc::unbounded_channel();

        tokio::spawn(async move {
            let mut service = Self {
                discovery,
                db,
                kbuckets,
                data_radius,
                protocol,
                peers_to_ping,
                request_rx,
                request_tx: internal_request_tx,
                active_requests: Arc::new(RwLock::new(HashMap::new())),
                response_rx,
                response_tx,
            };

            // Attempt to insert bootnodes into the routing table in a disconnected state.
            // If successful, then add the node to the ping queue. A subsequent successful ping
            // will mark the node as connected.
            //
            // TODO: Perform FindNode lookup for local node's own node ID and refresh all kbuckets
            // further away than closet neighbor (see Kademlia paper section 2.3).
            for enr in bootnode_enrs {
                let node_id = enr.node_id();
                // TODO: Decide default data radius, and define a constant. Or if there is an
                // associated database, then look for a radius value there.
                let node = Node::new(enr, U256::from(u64::MAX));
                let status = NodeStatus {
                    state: ConnectionState::Disconnected,
                    direction: ConnectionDirection::Outgoing,
                };

                // Attempt to insert the node into the routing table.
                match service.kbuckets.write_with_warn().await.insert_or_update(
                    &kbucket::Key::from(node_id.clone()),
                    node,
                    status,
                ) {
                    InsertResult::Failed(reason) => {
                        warn!(
                            "[{:?}] Failed to insert bootnode into overlay routing table. Node: {}, Reason {:?}",
                            service.protocol, node_id, reason
                        );
                    }
                    _ => {
                        debug!(
                            "[{:?}] Inserted bootnode into overlay routing table, adding to ping queue. Node {}",
                            service.protocol, node_id
                        );

                        // Queue the node in the ping queue.
                        service.peers_to_ping.insert(node_id);
                    }
                }
            }

            info!("[{:?}] Starting overlay service", overlay_protocol);
            service.start().await;
        });

        Ok(request_tx)
    }

    /// The main loop for the overlay service. The loop selects over different possible tasks to
    /// perform.
    ///
    /// Process request: Process an incoming or outgoing request through the overlay.
    ///
    /// Process response: Process a response to an outgoing request from the local node. Try to
    /// match this response to an active request, and send the response or error over the
    /// associated response channel. Update node state based on result of response.
    ///
    /// Ping queue: Ping a node in the routing table to perform a liveness check and to refresh
    /// information relevant to the overlay network.
    ///
    /// Bucket maintenance: Maintain the routing table (more info documented above function).
    async fn start(&mut self) {
        loop {
            tokio::select! {
                Some(request) = self.request_rx.recv() => self.process_request(request).await,
                Some(response) = self.response_rx.recv() => {
                    // Look up active request that corresponds to the response.
                    let optional_active_request = self.active_requests.write_with_warn().await.remove(&response.request_id);
                    if let Some(active_request) = optional_active_request {
                        // Send response to responder if present.
                        if let Some(responder) = active_request.responder {
                            let _ = responder.send(response.response.clone());
                        }

                        // Perform background processing.
                        match response.response {
                            Ok(response) => self.process_response(response, active_request.destination).await,
                            Err(error) => self.process_request_failure(response.request_id, active_request.destination, error).await,
                        }
                    } else {
                        warn!("No active request with id {} for response", response.request_id);
                    }
                }
                Some(Ok(node_id)) = self.peers_to_ping.next() => {
                    // If the node is in the routing table, then ping and re-queue the node.
                    let key = kbucket::Key::from(node_id);
                    let optional_enr = {
                        if let kbucket::Entry::Present(ref mut entry, _) = self.kbuckets.write_with_warn().await.entry(&key) {
                            // Re-queue the node.
                            self.peers_to_ping.insert(node_id);
                            Some(entry.value().enr())
                        } else { None }
                    };

                    if let Some(enr) = optional_enr {
                        self.ping_node(&enr).await;
                    }
                }
                _ = OverlayService::bucket_maintenance_poll(self.protocol.clone(), &self.kbuckets) => {}
            }
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

    /// Maintains the routing table.
    ///
    /// Consumes previously applied pending entries from the `KBucketsTable`. An `AppliedPending`
    /// result is recorded when a pending bucket entry replaces a disconnected entry in the
    /// respective bucket.
    async fn bucket_maintenance_poll(
        protocol: ProtocolId,
        kbuckets: &Arc<RwLock<KBucketsTable<NodeId, Node>>>,
    ) {
        // Drain applied pending entries from the routing table.
        if let Some(entry) = kbuckets.write_with_warn().await.take_applied_pending() {
            debug!(
                "[{:?}] Node {:?} inserted and node {:?} evicted",
                protocol,
                entry.inserted.into_preimage(),
                entry.evicted.map(|n| n.key.into_preimage())
            );
        }
    }

    /// Processes an overlay request.
    async fn process_request(&mut self, request: OverlayRequest) {
        // For incoming requests, handle the request, possibly send the response over the channel,
        // and then process the request.
        //
        // For outgoing requests, send the request via a TALK request over Discovery v5, send the
        // response over the channel, and then process the response. There may not be a response
        // channel if the request was initiated internally (e.g. for maintenance).
        match request.direction {
            RequestDirection::Incoming { id, source } => {
                let response = self
                    .handle_request(request.request.clone(), id.clone(), source.clone())
                    .await;
                // Send response to responder if present.
                if let Some(responder) = request.responder {
                    let _ = responder.send(response);
                }
                // Perform background processing.
                self.process_incoming_request(request.request, id, source)
                    .await;
            }
            RequestDirection::Outgoing { destination } => {
                self.active_requests.write_with_warn().await.insert(
                    request.id,
                    ActiveOverlayRequest {
                        destination: destination.clone(),
                        responder: request.responder,
                    },
                );
                self.send_talk_req(request.request, request.id, destination);
            }
        }
    }

    /// Attempts to build a response for a request.
    async fn handle_request(
        &mut self,
        request: Request,
        id: RequestId,
        source: NodeId,
    ) -> Result<Response, OverlayRequestError> {
        debug!("[{:?}] Handling request {}", self.protocol, id);
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
            "[{:?}] Handling ping request from node={}. Ping={:?}",
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
    fn send_talk_req(&self, request: Request, request_id: OverlayRequestId, destination: Enr) {
        let discovery = Arc::clone(&self.discovery);
        let protocol = self.protocol.clone();
        let response_tx = self.response_tx.clone();

        // Spawn a new thread to send end the TALK request. Otherwise we would delay processing of
        // other tasks until we receive the response. Send the response over the response channel,
        // which will be received in the main loop.
        tokio::spawn(async move {
            let response = match discovery
                .send_talk_req(destination, protocol, Message::Request(request).to_bytes())
                .await
            {
                Ok(talk_resp) => match Message::from_bytes(&talk_resp) {
                    Ok(Message::Response(response)) => Ok(response),
                    Ok(_) => Err(OverlayRequestError::InvalidResponse),
                    Err(_) => Err(OverlayRequestError::DecodeError),
                },
                Err(error) => Err(error.into()),
            };

            let _ = response_tx.send(OverlayResponse {
                request_id,
                response,
            });
        });
    }

    /// Processes an incoming request from some source node.
    async fn process_incoming_request(&mut self, request: Request, _id: RequestId, source: NodeId) {
        // Look up the node in the routing table.
        let key = kbucket::Key::from(source);
        let is_node_in_table = match self.kbuckets.write_with_warn().await.entry(&key) {
            kbucket::Entry::Present(_, _) => true,
            kbucket::Entry::Pending(_, _) => true,
            _ => false,
        };

        // If the node is in the routing table, then call update on the routing table in order to
        // update the node's position in the kbucket. If the node is not in the routing table, then
        // we cannot construct a new entry for sure, because we only have the node ID, not the ENR.
        if is_node_in_table {
            match self
                .update_node_connection_state(source, ConnectionState::Connected)
                .await
            {
                Ok(_) => {}
                Err(_) => {
                    // If the update fails, then remove the node from the ping queue.
                    self.peers_to_ping.remove(&source);
                }
            }
        } else {
            // The node is not in the overlay routing table, so look for the node's ENR
            // in the underlying Discovery v5 routing table. If an entry is found, then
            // attempt to insert the node as a connected peer.
            //
            // TODO: Remove this fallback logic. Request ENR via Discovery v5. If the
            // ENR sequence number has changed, then the node's address info may have
            // changed. The TalkRequest object does not contain the requester's ENR, only
            // its NodeAddress.
            if let Some(enr) = self.discovery.discv5.find_enr(&source) {
                // TODO: Decide default data radius, and define a constant.
                let node = Node {
                    enr,
                    data_radius: U256::from(u64::MAX),
                };
                self.connect_node(node, ConnectionDirection::Incoming).await;
            }
        }

        match request {
            Request::Ping(ping) => self.process_ping(ping, source).await,
            _ => {}
        }
    }

    /// Processes a ping request from some source node.
    async fn process_ping(&mut self, ping: Ping, source: NodeId) {
        // Look up the node in the routing table.
        let key = kbucket::Key::from(source);
        let optional_node = match self.kbuckets.write_with_warn().await.entry(&key) {
            kbucket::Entry::Present(ref mut entry, _) => Some(entry.value().clone()),
            kbucket::Entry::Pending(ref mut entry, _) => Some(entry.value().clone()),
            _ => None,
        };

        // If the node is in the routing table, then check if we need to update the node.
        if let Some(node) = optional_node {
            // TODO: How do we handle data in the custom payload? This is unique to each overlay
            // network, so there may need to be some way to parameterize the update for a
            // ping/pong.

            // If the ENR sequence number in pong is less than the ENR sequence number for the routing
            // table entry, then request the node.
            if node.enr().seq() < ping.enr_seq {
                self.request_node(&node.enr()).await;
            }
        }
    }

    /// Processes a failed request intended for some destination node.
    async fn process_request_failure(
        &mut self,
        request_id: OverlayRequestId,
        destination: Enr,
        error: OverlayRequestError,
    ) {
        debug!(
            "[{:?}] Request {} failed. Error: {}",
            self.protocol, request_id, error
        );

        // Attempt to mark the node as disconnected.
        let node_id = destination.node_id();
        let _ = self
            .update_node_connection_state(node_id, ConnectionState::Disconnected)
            .await;

        // Remove the node from the ping queue.
        self.peers_to_ping.remove(&node_id);
    }

    /// Processes a response to an outgoing request from some source node.
    async fn process_response(&mut self, response: Response, source: Enr) {
        // If the node is present in the routing table, but the node is not connected, then
        // use the existing entry's value and direction. Otherwise, build a new entry from
        // the source ENR and establish a connection in the outgoing direction, because this
        // node is responding to our request.
        let key = kbucket::Key::from(source.node_id());
        let (node, status) = match self.kbuckets.write_with_warn().await.entry(&key) {
            kbucket::Entry::Present(ref mut entry, status) => (entry.value().clone(), status),
            kbucket::Entry::Pending(ref mut entry, status) => (entry.value().clone(), status),
            _ => {
                // TODO: Decide default data radius, and define a constant.
                let node = Node {
                    enr: source.clone(),
                    data_radius: U256::from(u64::MAX),
                };
                let status = NodeStatus {
                    state: ConnectionState::Disconnected,
                    direction: ConnectionDirection::Outgoing,
                };
                (node, status)
            }
        };

        // If the node is not already connected, then attempt to mark the node as connected. If the
        // node is already connected, then call update on the routing table in order to update the
        // node's position in the kbucket.
        //
        // TODO: In what situation would a disconnected node respond to a request from the local
        // node? Handling this case might not be necessary, or it should be handled in a different
        // way.
        match status.state {
            ConnectionState::Disconnected => self.connect_node(node, status.direction).await,
            ConnectionState::Connected => {
                match self
                    .update_node_connection_state(source.node_id(), ConnectionState::Connected)
                    .await
                {
                    Ok(_) => {}
                    Err(_) => {
                        // If the update fails, then remove the node from the ping queue.
                        self.peers_to_ping.remove(&source.node_id());
                    }
                }
            }
        }

        match response {
            Response::Pong(pong) => self.process_pong(pong, source).await,
            Response::Nodes(nodes) => self.process_nodes(nodes, source).await,
            Response::Content(content) => self.process_content(content, source).await,
        }
    }

    /// Processes a Pong response.
    ///
    /// Refreshes the node if necessary. Attempts to mark the node as connected.
    async fn process_pong(&mut self, pong: Pong, source: Enr) {
        let node_id = source.node_id();
        debug!(
            "[{:?}] Processing Pong response from node. Node: {}",
            self.protocol, node_id
        );

        // If the ENR sequence number in pong is less than the ENR sequence number for the routing
        // table entry, then request the node.
        //
        // TODO: Perform update on non-ENR node entry state. See note in `process_ping`.
        let key = kbucket::Key::from(node_id);
        let optional_node = match self.kbuckets.write_with_warn().await.entry(&key) {
            kbucket::Entry::Present(ref mut entry, _) => Some(entry.value().clone()),
            kbucket::Entry::Pending(ref mut entry, _) => Some(entry.value().clone()),
            _ => None,
        };
        if let Some(node) = optional_node {
            if node.enr().seq() < pong.enr_seq {
                self.request_node(&node.enr()).await;
            }
        }
    }

    /// Processes a Nodes response.
    async fn process_nodes(&mut self, _nodes: Nodes, source: Enr) {
        debug!(
            "[{:?}] Processing Nodes response from node. Node: {}",
            self.protocol,
            source.node_id()
        );
        // TODO: Implement processing logic.
    }

    /// Processes a Content response.
    async fn process_content(&mut self, _content: Content, source: Enr) {
        debug!(
            "[{:?}] Processing Content response from node. Node: {}",
            self.protocol,
            source.node_id()
        );
        // TODO: Implement processing logic.
    }

    /// Submits a request to ping a destination (target) node.
    async fn ping_node(&self, destination: &Enr) {
        debug!(
            "[{:?}] Sending Ping request to node. Node: {}",
            self.protocol,
            destination.node_id()
        );

        let enr_seq = self.local_enr().await.seq();
        let data_radius = self.data_radius().await;
        let custom_payload = ByteList::from(data_radius.as_ssz_bytes());
        let ping = Request::Ping(Ping {
            enr_seq,
            custom_payload,
        });
        let request = OverlayRequest::new(
            ping,
            RequestDirection::Outgoing {
                destination: destination.clone(),
            },
            None,
        );
        let _ = self.request_tx.send(request);
    }

    /// Submits a request for the node info of a destination (target) node.
    async fn request_node(&self, destination: &Enr) {
        let find_nodes = Request::FindNodes(FindNodes { distances: vec![0] });
        let request = OverlayRequest::new(
            find_nodes,
            RequestDirection::Outgoing {
                destination: destination.clone(),
            },
            None,
        );
        let _ = self.request_tx.send(request);
    }

    /// Attempts to insert a newly connected node or update an existing node to connected.
    async fn connect_node(&mut self, node: Node, connection_direction: ConnectionDirection) {
        let node_id = node.enr().node_id();
        let key = kbucket::Key::from(node_id);
        let status = NodeStatus {
            state: ConnectionState::Connected,
            direction: connection_direction,
        };

        let mut node_to_ping = None;
        match self
            .kbuckets
            .write_with_warn()
            .await
            .insert_or_update(&key, node, status)
        {
            InsertResult::Inserted => {
                // The node was inserted into the routing table. Add the node to the ping queue.
                debug!(
                    "[{:?}] New connected node added to routing table. Node: {}",
                    self.protocol, node_id
                );
                self.peers_to_ping.insert(node_id);
            }
            InsertResult::Pending { disconnected } => {
                // The disconnected node is the least-recently connected entry that is
                // currently considered disconnected. This node should be pinged to check
                // for connectivity.
                node_to_ping = Some(disconnected);
            }
            InsertResult::StatusUpdated {
                promoted_to_connected,
            }
            | InsertResult::Updated {
                promoted_to_connected,
            } => {
                // The node existed in the routing table, and it was updated to connected.
                if promoted_to_connected {
                    debug!(
                        "[{:?}] Node promoted to connected. Node: {}",
                        self.protocol, node_id
                    );
                    self.peers_to_ping.insert(node_id);
                }
            }
            InsertResult::ValueUpdated | InsertResult::UpdatedPending => {}
            InsertResult::Failed(reason) => {
                self.peers_to_ping.remove(&node_id);
                debug!(
                    "[{:?}] Could not insert node. Node: {}, Reason: {:?}",
                    self.protocol, node_id, reason
                );
            }
        }

        // Ping node to check for connectivity. See comment above for reasoning.
        if let Some(key) = node_to_ping {
            match self.kbuckets.write_with_warn().await.entry(&key) {
                kbucket::Entry::Present(ref mut entry, _) => {
                    self.ping_node(&entry.value().enr()).await;
                }
                kbucket::Entry::Pending(ref mut entry, _) => {
                    self.ping_node(&entry.value().enr()).await;
                }
                _ => {}
            }
        }
    }

    /// Attempts to update the connection state of a node.
    async fn update_node_connection_state(
        &mut self,
        node_id: NodeId,
        state: ConnectionState,
    ) -> Result<(), FailureReason> {
        let key = kbucket::Key::from(node_id);
        match self
            .kbuckets
            .write_with_warn()
            .await
            .update_node_status(&key, state, None)
        {
            UpdateResult::Failed(reason) => match reason {
                FailureReason::KeyNonExistant => Err(FailureReason::KeyNonExistant),
                other => {
                    warn!(
                        "[{:?}] Could not update node to {:?}. Node: {}, Reason: {:?}",
                        self.protocol, state, node_id, other
                    );

                    Err(other)
                }
            },
            _ => {
                debug!(
                    "[{:?}] Node set to {:?}. Node: {}",
                    self.protocol, state, node_id
                );
                Ok(())
            }
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
