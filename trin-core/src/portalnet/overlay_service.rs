use std::collections::HashMap;
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use crate::locks::RwLoggingExt;
use crate::portalnet::types::messages::{Accept, Offer};
use crate::utp::stream::UtpListener;
use crate::utp::trin_helpers::UtpMessageId;
use crate::{
    portalnet::{
        discovery::Discovery,
        storage::PortalStorage,
        types::{
            content_key::OverlayContentKey,
            messages::{
                ByteList, Content, CustomPayload, FindContent, FindNodes, Message, Nodes, Ping,
                Pong, ProtocolId, Request, Response, SszEnr,
            },
            uint::U256,
        },
        Enr,
    },
    utils::{distance::xor, node_id},
};

use delay_map::HashSetDelay;
use discv5::{
    enr::NodeId,
    kbucket::{
        self, ConnectionDirection, ConnectionState, FailureReason, InsertResult, KBucketsTable,
        NodeStatus, UpdateResult,
    },
    rpc::RequestId,
};
use futures::{channel::oneshot, prelude::*};
use log::{debug, error, info, warn};
use parking_lot::RwLock;
use rand::seq::SliceRandom;
use ssz::Encode;
use ssz_types::BitList;
use ssz_types::VariableList;
use thiserror::Error;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::sync::RwLock as RwLockT;

/// Maximum number of ENRs in response to FindNodes.
pub const FIND_NODES_MAX_NODES: usize = 32;
/// Maximum number of ENRs in response to FindContent.
pub const FIND_CONTENT_MAX_NODES: usize = 32;
/// With even distribution assumptions, 2**17 is enough to put each node (estimating 100k nodes,
/// which is more than 10x the ethereum mainnet node count) into a unique bucket by the 17th bucket index.
const EXPECTED_NON_EMPTY_BUCKETS: usize = 17;

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

    /// Error types resulting from building ACCEPT message
    #[error("Error while building accept message")]
    AcceptError(ssz_types::Error),
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
#[derive(Debug, PartialEq)]
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
struct ActiveOutgoingRequest {
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
#[derive(Clone, Debug)]
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
pub struct OverlayService<TContentKey> {
    /// The underlying Discovery v5 protocol.
    discovery: Arc<Discovery>,
    /// The content database of the local node.
    storage: Arc<PortalStorage>,
    /// The routing table of the local node.
    kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
    /// The data radius of the local node.
    data_radius: Arc<U256>,
    /// The protocol identifier.
    protocol: ProtocolId,
    /// A queue of peers that require regular ping to check connectivity.
    /// Inserted entries expire after a fixed time. Nodes to be pinged are inserted with a timeout
    /// duration equal to some ping interval, and we continuously poll the queue to check for
    /// expired entries.
    peers_to_ping: HashSetDelay<NodeId>,
    // TODO: This should probably be a bounded channel.
    /// The receiver half of the service request channel.
    request_rx: UnboundedReceiver<OverlayRequest>,
    /// The sender half of a channel for service requests.
    /// This is used internally to submit requests (e.g. maintenance ping requests).
    request_tx: UnboundedSender<OverlayRequest>,
    /// A map of active outgoing requests.
    active_outgoing_requests: Arc<RwLock<HashMap<OverlayRequestId, ActiveOutgoingRequest>>>,
    /// The receiver half of a channel for responses to outgoing requests.
    response_rx: UnboundedReceiver<OverlayResponse>,
    /// The sender half of a channel for responses to outgoing requests.
    response_tx: UnboundedSender<OverlayResponse>,
    utp_listener: Arc<RwLockT<UtpListener>>,
    /// Phantom content key.
    phantom_content_key: PhantomData<TContentKey>,
}

impl<TContentKey: OverlayContentKey + Send> OverlayService<TContentKey> {
    /// Spawns the overlay network service.
    ///
    /// The state of the overlay network largely consists of its routing table. The routing table
    /// is updated according to incoming requests and responses as well as autonomous maintenance
    /// processes.
    pub async fn spawn(
        discovery: Arc<Discovery>,
        storage: Arc<PortalStorage>,
        kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
        bootnode_enrs: Vec<Enr>,
        ping_queue_interval: Option<Duration>,
        data_radius: Arc<U256>,
        protocol: ProtocolId,
        utp_listener: Arc<RwLockT<UtpListener>>,
    ) -> Result<UnboundedSender<OverlayRequest>, String> {
        let (request_tx, request_rx) = mpsc::unbounded_channel();
        let internal_request_tx = request_tx.clone();

        let overlay_protocol = protocol.clone();

        let peers_to_ping = if let Some(interval) = ping_queue_interval {
            HashSetDelay::new(interval)
        } else {
            HashSetDelay::default()
        };

        let (response_tx, response_rx) = mpsc::unbounded_channel();

        tokio::spawn(async move {
            let mut service = Self {
                discovery,
                storage,
                kbuckets,
                data_radius,
                protocol,
                peers_to_ping,
                request_rx,
                request_tx: internal_request_tx,
                active_outgoing_requests: Arc::new(RwLock::new(HashMap::new())),
                response_rx,
                response_tx,
                utp_listener,
                phantom_content_key: PhantomData,
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
                match service.kbuckets.write().insert_or_update(
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
        // Construct bucket refresh interval
        let mut bucket_refresh_interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                Some(request) = self.request_rx.recv() => self.process_request(request),
                Some(response) = self.response_rx.recv() => {
                    // Look up active request that corresponds to the response.
                    let optional_active_request = self.active_outgoing_requests.write().remove(&response.request_id);
                    if let Some(active_request) = optional_active_request {
                        // Send response to responder if present.
                        if let Some(responder) = active_request.responder {
                            let _ = responder.send(response.response.clone());
                        }

                        // Perform background processing.
                        match response.response {
                            Ok(response) => self.process_response(response, active_request.destination),
                            Err(error) => self.process_request_failure(response.request_id, active_request.destination, error),
                        }
                    } else {
                        warn!("No active request with id {} for response", response.request_id);
                    }
                }
                Some(Ok(node_id)) = self.peers_to_ping.next() => {
                    // If the node is in the routing table, then ping and re-queue the node.
                    let key = kbucket::Key::from(node_id);
                    if let kbucket::Entry::Present(ref mut entry, _) = self.kbuckets.write().entry(&key) {
                        self.ping_node(&entry.value().enr());
                        self.peers_to_ping.insert(node_id);
                    }
                }
                _ = OverlayService::<TContentKey>::bucket_maintenance_poll(self.protocol.clone(), &self.kbuckets) => {}
                _ = bucket_refresh_interval.tick() => {
                    debug!("[{:?}] Overlay bucket refresh lookup", self.protocol);
                    self.bucket_refresh_lookup();
                }
            }
        }
    }

    /// Main bucket refresh lookup logic
    fn bucket_refresh_lookup(&self) {
        // Look at local routing table and select the largest 17 buckets.
        // We only need the 17 bits furthest from our own node ID, because the closest 239 bits of
        // buckets are going to be empty-ish.
        let buckets = self.kbuckets.read();
        let buckets = buckets.buckets_iter().enumerate().collect::<Vec<_>>();
        let buckets = &buckets[256 - EXPECTED_NON_EMPTY_BUCKETS..];

        // Randomly pick one of these buckets.
        let target_bucket = buckets.choose(&mut rand::thread_rng());
        match target_bucket {
            Some(bucket) => {
                let target_bucket_idx = u8::try_from(bucket.0);
                if let Ok(idx) = target_bucket_idx {
                    // Randomly generate a NodeID that falls within the target bucket.
                    let target_node_id = self.generate_random_node_id(idx);
                    // Do the random lookup on this node-id.
                    match target_node_id {
                        Ok(node_id) => self.send_recursive_findnode(&node_id),
                        Err(msg) => warn!("{:?}", msg),
                    }
                } else {
                    error!("Unable to downcast bucket index.")
                }
            }
            None => error!("Failed to choose random bucket index"),
        }
    }

    /// Returns the local ENR of the node.
    fn local_enr(&self) -> Enr {
        self.discovery.discv5.local_enr()
    }

    /// Returns the data radius of the node.
    fn data_radius(&self) -> U256 {
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
        future::poll_fn(move |_cx| {
            // Drain applied pending entries from the routing table.
            if let Some(entry) = kbuckets.write().take_applied_pending() {
                debug!(
                    "[{:?}] Node {:?} inserted and node {:?} evicted",
                    protocol,
                    entry.inserted.into_preimage(),
                    entry.evicted.map(|n| n.key.into_preimage())
                );
                return Poll::Ready(());
            }
            Poll::Pending
        })
        .await
    }

    /// Processes an overlay request.
    fn process_request(&mut self, request: OverlayRequest) {
        // For incoming requests, handle the request, possibly send the response over the channel,
        // and then process the request.
        //
        // For outgoing requests, send the request via a TALK request over Discovery v5, send the
        // response over the channel, and then process the response. There may not be a response
        // channel if the request was initiated internally (e.g. for maintenance).
        match request.direction {
            RequestDirection::Incoming { id, source } => {
                let response =
                    self.handle_request(request.request.clone(), id.clone(), source.clone());
                // Send response to responder if present.
                if let Some(responder) = request.responder {
                    let _ = responder.send(response);
                }
                // Perform background processing.
                self.process_incoming_request(request.request, id, source);
            }
            RequestDirection::Outgoing { destination } => {
                self.active_outgoing_requests.write().insert(
                    request.id,
                    ActiveOutgoingRequest {
                        destination: destination.clone(),
                        responder: request.responder,
                    },
                );
                self.send_talk_req(request.request, request.id, destination);
            }
        }
    }

    /// Attempts to build a response for a request.
    fn handle_request(
        &mut self,
        request: Request,
        id: RequestId,
        source: NodeId,
    ) -> Result<Response, OverlayRequestError> {
        debug!("[{:?}] Handling request {}", self.protocol, id);
        match request {
            Request::Ping(ping) => Ok(Response::Pong(self.handle_ping(ping, source))),
            Request::FindNodes(find_nodes) => {
                Ok(Response::Nodes(self.handle_find_nodes(find_nodes)))
            }
            Request::FindContent(find_content) => {
                Ok(Response::Content(self.handle_find_content(find_content)?))
            }
            Request::Offer(offer) => Ok(Response::Accept(self.handle_offer(offer)?)),
        }
    }

    /// Builds a `Pong` response for a `Ping` request.
    fn handle_ping(&self, request: Ping, source: NodeId) -> Pong {
        debug!(
            "[{:?}] Handling ping request from node={}. Ping={:?}",
            self.protocol, source, request
        );
        let enr_seq = self.local_enr().seq();
        let data_radius = self.data_radius();
        let custom_payload = CustomPayload::from(data_radius.as_ssz_bytes());
        Pong {
            enr_seq,
            custom_payload,
        }
    }

    /// Builds a `Nodes` response for a `FindNodes` request.
    fn handle_find_nodes(&self, request: FindNodes) -> Nodes {
        let distances64: Vec<u64> = request.distances.iter().map(|x| (*x).into()).collect();
        let enrs = self.nodes_by_distance(distances64);
        // `total` represents the total number of `Nodes` response messages being sent.
        // TODO: support returning multiple messages.
        Nodes { total: 1, enrs }
    }

    /// Attempts to build a `Content` response for a `FindContent` request.
    fn handle_find_content(&self, request: FindContent) -> Result<Content, OverlayRequestError> {
        let content_key = match (TContentKey::try_from)(request.content_key) {
            Ok(key) => key,
            Err(_) => {
                return Err(OverlayRequestError::InvalidRequest(
                    "Invalid content key".to_string(),
                ))
            }
        };

        match self.storage.get(&content_key) {
            Ok(Some(value)) => {
                let content = ByteList::from(VariableList::from(value));
                Ok(Content::Content(content))
            }
            Ok(None) => {
                let enrs = self.find_nodes_close_to_content(content_key);
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

    /// Attempts to build a `Accept` response for a `Offer` request.
    fn handle_offer(&self, request: Offer) -> Result<Accept, OverlayRequestError> {
        let mut requested_keys = BitList::with_capacity(request.content_keys.len())
            .map_err(|e| OverlayRequestError::AcceptError(e))?;
        let connection_id: u16 = crate::utp::stream::rand();

        for (i, key) in request.content_keys.iter().enumerate() {
            // should_store is currently a dummy function
            // the actual function will take ContentKey type, so we'll  have to decode keys here
            requested_keys
                .set(i, should_store(key))
                .map_err(|e| OverlayRequestError::AcceptError(e))?;
        }

        let utp_listener = self.utp_listener.clone();
        tokio::spawn(async move {
            // listen for incoming connection request on conn_id, as part of utp handshake
            utp_listener
                .write_with_warn()
                .await
                .listening
                .insert(connection_id.clone(), UtpMessageId::OfferAcceptStream);

            // also listen on conn_id + 1 because this is the actual receive path for acceptor
            utp_listener
                .write_with_warn()
                .await
                .listening
                .insert(connection_id.clone() + 1, UtpMessageId::OfferAcceptStream);
        });

        let accept = Accept {
            connection_id,
            content_keys: requested_keys,
        };

        Ok(accept)
    }

    /// Sends a TALK request via Discovery v5 to some destination node.
    fn send_talk_req(&self, request: Request, request_id: OverlayRequestId, destination: Enr) {
        let discovery = Arc::clone(&self.discovery);
        let protocol = self.protocol.clone();
        let response_tx = self.response_tx.clone();

        // Spawn a new thread to send the TALK request. Otherwise we would delay processing of
        // other tasks until we receive the response. Send the response over the response channel,
        // which will be received in the main loop.
        tokio::spawn(async move {
            let response = match discovery
                .send_talk_req(destination, protocol, Message::from(request).into())
                .await
            {
                Ok(talk_resp) => match Message::try_from(talk_resp) {
                    Ok(message) => match Response::try_from(message) {
                        Ok(response) => Ok(response),
                        Err(_) => Err(OverlayRequestError::InvalidResponse),
                    },
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
    fn process_incoming_request(&mut self, request: Request, _id: RequestId, source: NodeId) {
        // Look up the node in the routing table.
        let key = kbucket::Key::from(source);
        let is_node_in_table = match self.kbuckets.write().entry(&key) {
            kbucket::Entry::Present(_, _) => true,
            kbucket::Entry::Pending(_, _) => true,
            _ => false,
        };

        // If the node is in the routing table, then call update on the routing table in order to
        // update the node's position in the kbucket. If the node is not in the routing table, then
        // we cannot construct a new entry for sure, because we only have the node ID, not the ENR.
        if is_node_in_table {
            match self.update_node_connection_state(source, ConnectionState::Connected) {
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
                self.connect_node(node, ConnectionDirection::Incoming);
            }
        }

        match request {
            Request::Ping(ping) => self.process_ping(ping, source),
            _ => {}
        }
    }

    /// Processes a ping request from some source node.
    fn process_ping(&mut self, ping: Ping, source: NodeId) {
        // Look up the node in the routing table.
        let key = kbucket::Key::from(source);
        let optional_node = match self.kbuckets.write().entry(&key) {
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
                self.request_node(&node.enr());
            }
        }
    }

    /// Processes a failed request intended for some destination node.
    fn process_request_failure(
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
        let _ = self.update_node_connection_state(node_id, ConnectionState::Disconnected);
        // Remove the node from the ping queue.
        self.peers_to_ping.remove(&node_id);
    }

    /// Processes a response to an outgoing request from some source node.
    fn process_response(&mut self, response: Response, source: Enr) {
        // If the node is present in the routing table, but the node is not connected, then
        // use the existing entry's value and direction. Otherwise, build a new entry from
        // the source ENR and establish a connection in the outgoing direction, because this
        // node is responding to our request.
        let key = kbucket::Key::from(source.node_id());
        let (node, status) = match self.kbuckets.write().entry(&key) {
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
            ConnectionState::Disconnected => self.connect_node(node, status.direction),
            ConnectionState::Connected => {
                match self
                    .update_node_connection_state(source.node_id(), ConnectionState::Connected)
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
            Response::Pong(pong) => self.process_pong(pong, source),
            Response::Nodes(nodes) => self.process_nodes(nodes, source),
            Response::Content(content) => self.process_content(content, source),
            _ => {}
        }
    }

    /// Processes a Pong response.
    ///
    /// Refreshes the node if necessary. Attempts to mark the node as connected.
    fn process_pong(&mut self, pong: Pong, source: Enr) {
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
        let optional_node = match self.kbuckets.write().entry(&key) {
            kbucket::Entry::Present(ref mut entry, _) => Some(entry.value().clone()),
            kbucket::Entry::Pending(ref mut entry, _) => Some(entry.value().clone()),
            _ => None,
        };
        if let Some(node) = optional_node {
            if node.enr().seq() < pong.enr_seq {
                self.request_node(&node.enr());
            }
        }
    }

    /// Processes a Nodes response.
    fn process_nodes(&mut self, nodes: Nodes, source: Enr) {
        debug!(
            "[{:?}] Processing Nodes response from node. Node: {}",
            self.protocol,
            source.node_id()
        );
        self.process_discovered_enrs(
            nodes
                .enrs
                .into_iter()
                .map(|ssz_enr| ssz_enr.into())
                .collect(),
        );
    }

    /// Processes a Content response.
    fn process_content(&mut self, content: Content, source: Enr) {
        debug!(
            "[{:?}] Processing Content response from node. Node: {}",
            self.protocol,
            source.node_id()
        );
        match content {
            Content::ConnectionId(id) => debug!(
                "[{:?}] Skipping processing for content connection ID {}",
                self.protocol, id
            ),
            Content::Content(_) => {
                debug!(
                    "[{:?}] Skipping processing for content bytes",
                    self.protocol
                )
            }
            Content::Enrs(enrs) => self
                .process_discovered_enrs(enrs.into_iter().map(|ssz_enr| ssz_enr.into()).collect()),
        }
    }

    /// Processes a collection of discovered nodes.
    fn process_discovered_enrs(&mut self, enrs: Vec<Enr>) {
        let local_node_id = self.local_enr().node_id();

        // Acquire write lock here so that we can perform node lookup and insert/update atomically.
        // Once we acquire the write lock for the routing table, there are no other locks that we
        // need to acquire, so we should not create a deadlock.
        let mut kbuckets = self.kbuckets.write();

        for enr in enrs {
            let node_id = enr.node_id();

            // Ignore ourself.
            if node_id == local_node_id {
                continue;
            }

            let key = kbucket::Key::from(node_id);
            let optional_node = match kbuckets.entry(&key) {
                kbucket::Entry::Present(entry, _) => Some(entry.value().clone()),
                kbucket::Entry::Pending(ref mut entry, _) => Some(entry.value().clone()),
                _ => None,
            };

            // If the node is in the routing table, then check to see if we should update its entry.
            // If the node is not in the routing table, then add the node in a disconnected state.
            // A subsequent ping will establish connectivity with the node. If the insertion succeeds,
            // then add the node to the ping queue. Ignore insertion failures.
            if let Some(node) = optional_node {
                if node.enr().seq() < enr.seq() {
                    let updated_node = Node {
                        enr,
                        data_radius: node.data_radius(),
                    };

                    // The update removed the node because it would violate the incoming peers condition
                    // or a bucket/table filter. Remove the node from the ping queue.
                    if let UpdateResult::Failed(reason) =
                        kbuckets.update_node(&key, updated_node, None)
                    {
                        self.peers_to_ping.remove(&node_id);
                        debug!(
                            "Failed to update discovered node. Node: {}, Reason: {:?}",
                            node_id, reason
                        );
                    }
                }
            } else {
                let node = Node {
                    enr,
                    data_radius: U256::from(u64::MAX),
                };
                let status = NodeStatus {
                    state: ConnectionState::Disconnected,
                    direction: ConnectionDirection::Outgoing,
                };
                match kbuckets.insert_or_update(&key, node, status) {
                    InsertResult::Inserted => {
                        debug!("Discovered node added to routing table. Node: {}", node_id);
                        self.peers_to_ping.insert(node_id);
                    }
                    InsertResult::Pending { disconnected } => {
                        // The disconnected node is the least-recently connected entry that is
                        // currently considered disconnected. This node should be pinged to check
                        // for connectivity.
                        //
                        // The discovered node was inserted as a pending entry that will be inserted
                        // after some timeout if the disconnected node is not updated.
                        if let kbucket::Entry::Present(node_to_ping, _) =
                            kbuckets.entry(&disconnected)
                        {
                            self.ping_node(&node_to_ping.value().enr());
                        }
                    }
                    _ => {
                        debug!(
                            "Discovered node not added to routing table. Node: {}",
                            node_id
                        );
                    }
                }
            }
        }
    }

    /// Submits a request to ping a destination (target) node.
    fn ping_node(&self, destination: &Enr) {
        debug!(
            "[{:?}] Sending Ping request to node. Node: {}",
            self.protocol,
            destination.node_id()
        );

        let enr_seq = self.local_enr().seq();
        let data_radius = self.data_radius();
        let custom_payload = CustomPayload::from(data_radius.as_ssz_bytes());
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
    fn request_node(&self, destination: &Enr) {
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
    fn connect_node(&mut self, node: Node, connection_direction: ConnectionDirection) {
        let node_id = node.enr().node_id();
        let key = kbucket::Key::from(node_id);
        let status = NodeStatus {
            state: ConnectionState::Connected,
            direction: connection_direction,
        };

        let mut node_to_ping = None;
        match self.kbuckets.write().insert_or_update(&key, node, status) {
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
            if let kbucket::Entry::Present(ref mut entry, _) = self.kbuckets.write().entry(&key) {
                self.ping_node(&entry.value().enr());
            }
        }
    }

    /// Attempts to update the connection state of a node.
    fn update_node_connection_state(
        &mut self,
        node_id: NodeId,
        state: ConnectionState,
    ) -> Result<(), FailureReason> {
        let key = kbucket::Key::from(node_id);
        match self.kbuckets.write().update_node_status(&key, state, None) {
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
    fn table_entries_enr(&self) -> Vec<Enr> {
        self.kbuckets
            .write()
            .iter()
            .map(|entry| entry.node.value.enr().clone())
            .collect()
    }

    /// Returns a vector of the ENRs of the closest nodes by the given log2 distances.
    fn nodes_by_distance(&self, mut log2_distances: Vec<u64>) -> Vec<SszEnr> {
        let mut nodes_to_send = Vec::new();
        log2_distances.sort_unstable();
        log2_distances.dedup();

        let mut log2_distances = log2_distances.as_slice();
        if let Some(0) = log2_distances.first() {
            // If the distance is 0 send our local ENR.
            nodes_to_send.push(SszEnr::new(self.local_enr()));
            log2_distances = &log2_distances[1..];
        }

        if !log2_distances.is_empty() {
            let mut kbuckets = self.kbuckets.write();
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
    fn find_nodes_close_to_content(
        &self,
        content_key: impl OverlayContentKey,
    ) -> Result<Vec<SszEnr>, OverlayRequestError> {
        let content_id = content_key.content_id();
        let self_node_id = self.local_enr().node_id();
        let self_distance = xor(&content_id, &self_node_id.raw());

        let mut nodes_with_distance: Vec<(U256, Enr)> = self
            .table_entries_enr()
            .into_iter()
            .map(|enr| (xor(&content_id, &enr.node_id().raw()), enr))
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

    fn send_recursive_findnode(&self, _target: &NodeId) {
        // TODO: Implement Recursive(iterative) FINDNODE. This is a stub.
    }

    fn generate_random_node_id(&self, target_bucket_idx: u8) -> anyhow::Result<NodeId> {
        node_id::generate_random_node_id(target_bucket_idx, self.local_enr().node_id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    use crate::{
        cli::DEFAULT_STORAGE_CAPACITY,
        portalnet::{
            discovery::Discovery, overlay::OverlayConfig, storage::PortalStorage,
            types::content_key::MockContentKey, types::messages::PortalnetConfig,
        },
        utils::node_id::generate_random_remote_enr,
    };

    use discv5::kbucket::Entry;
    use serial_test::serial;
    use tokio_test::{assert_pending, assert_ready, task};

    macro_rules! poll_request_rx {
        ($service:ident) => {
            $service.enter(|cx, mut service| service.request_rx.poll_recv(cx))
        };
    }

    fn build_service() -> OverlayService<MockContentKey> {
        let portal_config = PortalnetConfig {
            internal_ip: true,
            ..Default::default()
        };
        let discovery = Arc::new(Discovery::new(portal_config).unwrap());

        let utp_listener = Arc::new(RwLockT::new(UtpListener {
            discovery: Arc::clone(&discovery),
            utp_connections: HashMap::new(),
            listening: HashMap::new(),
        }));

        // Initialize DB config
        let storage_capacity: u32 = DEFAULT_STORAGE_CAPACITY.parse().unwrap();
        let node_id = discovery.local_enr().node_id();
        let storage_config = PortalStorage::setup_config(node_id, storage_capacity).unwrap();
        let storage = Arc::new(PortalStorage::new(storage_config).unwrap());

        let overlay_config = OverlayConfig::default();
        let kbuckets = Arc::new(RwLock::new(KBucketsTable::new(
            discovery.local_enr().node_id().into(),
            overlay_config.bucket_pending_timeout,
            overlay_config.max_incoming_per_bucket,
            overlay_config.table_filter,
            overlay_config.bucket_filter,
        )));

        let data_radius = Arc::new(U256::from(u64::MAX));
        let protocol = ProtocolId::History;
        let active_outgoing_requests = Arc::new(RwLock::new(HashMap::new()));
        let peers_to_ping = HashSetDelay::default();
        let (request_tx, request_rx) = mpsc::unbounded_channel();
        let (response_tx, response_rx) = mpsc::unbounded_channel();

        OverlayService {
            discovery,
            storage,
            kbuckets,
            data_radius,
            protocol,
            peers_to_ping,
            request_tx,
            request_rx,
            active_outgoing_requests,
            response_tx,
            response_rx,
            utp_listener,
            phantom_content_key: PhantomData,
        }
    }

    #[tokio::test]
    #[serial]
    async fn process_ping_source_in_table_higher_enr_seq() {
        let mut service = task::spawn(build_service());

        let (_, source) = generate_random_remote_enr();
        let node_id = source.node_id();
        let key = kbucket::Key::from(node_id);
        let status = NodeStatus {
            state: ConnectionState::Connected,
            direction: ConnectionDirection::Outgoing,
        };

        let data_radius = U256::from(u64::MAX);
        let node = Node {
            enr: source.clone(),
            data_radius,
        };

        let _ = service
            .kbuckets
            .write()
            .insert_or_update(&key, node, status);

        let ping = Ping {
            enr_seq: source.seq() + 1,
            custom_payload: CustomPayload::from(data_radius.as_ssz_bytes()),
        };

        service.process_ping(ping, node_id);

        let request = assert_ready!(poll_request_rx!(service));
        assert!(request.is_some());

        let request = request.unwrap();
        assert!(request.responder.is_none());

        assert_eq!(
            RequestDirection::Outgoing {
                destination: source
            },
            request.direction
        );

        assert!(matches!(request.request, Request::FindNodes { .. }));

        match request.request {
            Request::FindNodes(find_nodes) => {
                assert_eq!(vec![0], find_nodes.distances)
            }
            _ => panic!(),
        };
    }

    #[tokio::test]
    #[serial]
    async fn process_ping_source_not_in_table() {
        let mut service = task::spawn(build_service());

        let (_, source) = generate_random_remote_enr();
        let node_id = source.node_id();
        let data_radius = U256::from(u64::MAX);

        let ping = Ping {
            enr_seq: source.seq(),
            custom_payload: CustomPayload::from(data_radius.as_ssz_bytes()),
        };

        service.process_ping(ping, node_id);

        assert_pending!(poll_request_rx!(service));
    }

    #[tokio::test]
    #[serial]
    async fn process_request_failure() {
        let mut service = task::spawn(build_service());

        let (_, destination) = generate_random_remote_enr();
        let node_id = destination.node_id();
        let key = kbucket::Key::from(node_id);
        let status = NodeStatus {
            state: ConnectionState::Connected,
            direction: ConnectionDirection::Outgoing,
        };

        let node = Node {
            enr: destination.clone(),
            data_radius: U256::from(u64::MAX),
        };

        let _ = service
            .kbuckets
            .write()
            .insert_or_update(&key, node, status);
        service.peers_to_ping.insert(node_id);

        assert!(service.peers_to_ping.contains_key(&node_id));

        assert!(matches!(
            service.kbuckets.write().entry(&key),
            kbucket::Entry::Present { .. }
        ));

        let request_id = rand::random();
        let error = OverlayRequestError::Timeout;
        service.process_request_failure(request_id, destination.clone(), error);

        assert!(!service.peers_to_ping.contains_key(&node_id));

        match service.kbuckets.write().entry(&key) {
            kbucket::Entry::Present(_entry, status) => {
                assert_eq!(ConnectionState::Disconnected, status.state)
            }
            _ => panic!(),
        };
    }

    #[tokio::test]
    #[serial]
    async fn process_pong_source_in_table_higher_enr_seq() {
        let mut service = task::spawn(build_service());

        let (_, source) = generate_random_remote_enr();
        let node_id = source.node_id();
        let key = kbucket::Key::from(node_id);
        let status = NodeStatus {
            state: ConnectionState::Connected,
            direction: ConnectionDirection::Outgoing,
        };

        let data_radius = U256::from(u64::MAX);
        let node = Node {
            enr: source.clone(),
            data_radius,
        };

        let _ = service
            .kbuckets
            .write()
            .insert_or_update(&key, node, status);

        let pong = Pong {
            enr_seq: source.seq() + 1,
            custom_payload: CustomPayload::from(data_radius.as_ssz_bytes()),
        };

        service.process_pong(pong, source.clone());

        let request = assert_ready!(poll_request_rx!(service));
        assert!(request.is_some());

        let request = request.unwrap();
        assert!(request.responder.is_none());

        assert_eq!(
            RequestDirection::Outgoing {
                destination: source
            },
            request.direction
        );

        assert!(matches!(request.request, Request::FindNodes { .. }));

        match request.request {
            Request::FindNodes(find_nodes) => {
                assert_eq!(vec![0], find_nodes.distances)
            }
            _ => panic!(),
        };
    }

    #[tokio::test]
    #[serial]
    async fn process_pong_source_not_in_table() {
        let mut service = task::spawn(build_service());

        let (_, source) = generate_random_remote_enr();
        let data_radius = U256::from(u64::MAX);

        let pong = Pong {
            enr_seq: source.seq(),
            custom_payload: CustomPayload::from(data_radius.as_ssz_bytes()),
        };

        service.process_pong(pong, source);

        assert_pending!(poll_request_rx!(service));
    }

    #[tokio::test]
    #[serial]
    async fn process_discovered_enrs_local_enr() {
        let mut service = task::spawn(build_service());
        let local_enr = service.discovery.local_enr();
        service.process_discovered_enrs(vec![local_enr.clone()]);

        // Check routing table for local ENR.
        // Local node should not be present in the routing table.
        let local_key = kbucket::Key::from(local_enr.node_id());
        assert!(matches!(
            service.kbuckets.write().entry(&local_key),
            Entry::SelfEntry
        ));

        // Check ping queue for local ENR.
        // Ping queue should be empty.
        assert!(service.peers_to_ping.is_empty());
    }

    #[tokio::test]
    #[serial]
    async fn process_discovered_enrs_unknown_enrs() {
        let mut service = task::spawn(build_service());

        // Generate random ENRs to simulate.
        let (_, enr1) = generate_random_remote_enr();
        let (_, enr2) = generate_random_remote_enr();

        let mut enrs: Vec<Enr> = vec![];
        enrs.push(enr1.clone());
        enrs.push(enr2.clone());
        service.process_discovered_enrs(enrs);

        let key1 = kbucket::Key::from(enr1.node_id());
        let key2 = kbucket::Key::from(enr2.node_id());

        // Check routing table for first ENR.
        // Node should be present in a disconnected state in the outgoing direction.
        match service.kbuckets.write().entry(&key1) {
            kbucket::Entry::Present(_entry, status) => {
                assert_eq!(ConnectionState::Disconnected, status.state);
                assert_eq!(ConnectionDirection::Outgoing, status.direction);
            }
            _ => panic!(),
        };

        // Check routing table for second ENR.
        // Node should be present in a disconnected state in the outgoing direction.
        match service.kbuckets.write().entry(&key2) {
            kbucket::Entry::Present(_entry, status) => {
                assert_eq!(ConnectionState::Disconnected, status.state);
                assert_eq!(ConnectionDirection::Outgoing, status.direction);
            }
            _ => panic!(),
        };

        // Check ping queue for first ENR.
        // Key for node should be present.
        assert!(service.peers_to_ping.contains_key(&enr1.node_id()));

        // Check ping queue for second ENR.
        // Key for node should be present.
        assert!(service.peers_to_ping.contains_key(&enr2.node_id()));
    }

    #[tokio::test]
    #[serial]
    async fn process_discovered_enrs_known_enrs() {
        let mut service = task::spawn(build_service());

        // Generate random ENRs to simulate.
        let (sk1, mut enr1) = generate_random_remote_enr();
        let (_, enr2) = generate_random_remote_enr();

        let key1 = kbucket::Key::from(enr1.node_id());
        let key2 = kbucket::Key::from(enr2.node_id());

        let status = NodeStatus {
            state: ConnectionState::Connected,
            direction: ConnectionDirection::Outgoing,
        };
        let data_radius = U256::from(u64::MAX);

        let node1 = Node {
            enr: enr1.clone(),
            data_radius: data_radius.clone(),
        };
        let node2 = Node {
            enr: enr2.clone(),
            data_radius: data_radius.clone(),
        };

        // Insert nodes into routing table.
        let _ = service
            .kbuckets
            .write()
            .insert_or_update(&key1, node1, status);
        assert!(matches!(
            service.kbuckets.write().entry(&key1),
            kbucket::Entry::Present { .. }
        ));
        let _ = service
            .kbuckets
            .write()
            .insert_or_update(&key2, node2, status);
        assert!(matches!(
            service.kbuckets.write().entry(&key2),
            kbucket::Entry::Present { .. }
        ));

        // Modify first ENR to increment sequence number.
        let updated_udp: u16 = 9000;
        let _ = enr1.set_udp(updated_udp, &sk1);
        assert_ne!(1, enr1.seq());

        let mut enrs: Vec<Enr> = vec![];
        enrs.push(enr1.clone());
        enrs.push(enr2.clone());
        service.process_discovered_enrs(enrs);

        // Check routing table for first ENR.
        // Node should be present with ENR sequence number equal to 2.
        match service.kbuckets.write().entry(&key1) {
            kbucket::Entry::Present(entry, _status) => {
                assert_eq!(2, entry.value().enr.seq());
            }
            _ => panic!(),
        };

        // Check routing table for second ENR.
        // Node should be present with ENR sequence number equal to 1.
        match service.kbuckets.write().entry(&key2) {
            kbucket::Entry::Present(entry, _status) => {
                assert_eq!(1, entry.value().enr.seq());
            }
            _ => panic!(),
        };
    }

    #[tokio::test]
    #[serial]
    async fn request_node() {
        let mut service = task::spawn(build_service());

        let (_, destination) = generate_random_remote_enr();
        service.request_node(&destination);

        let request = assert_ready!(poll_request_rx!(service));
        assert!(request.is_some());

        let request = request.unwrap();
        assert!(request.responder.is_none());

        assert_eq!(
            RequestDirection::Outgoing { destination },
            request.direction
        );

        assert!(matches!(request.request, Request::FindNodes { .. }));

        match request.request {
            Request::FindNodes(find_nodes) => {
                assert_eq!(vec![0], find_nodes.distances)
            }
            _ => panic!(),
        };
    }

    #[tokio::test]
    #[serial]
    async fn ping_node() {
        let mut service = task::spawn(build_service());

        let (_, destination) = generate_random_remote_enr();
        service.ping_node(&destination);

        let request = assert_ready!(poll_request_rx!(service));
        assert!(request.is_some());

        let request = request.unwrap();
        assert!(request.responder.is_none());

        assert_eq!(
            RequestDirection::Outgoing { destination },
            request.direction
        );

        assert!(matches!(request.request, Request::Ping { .. }));
    }

    #[tokio::test]
    #[serial]
    async fn connect_node() {
        let mut service = task::spawn(build_service());

        let (_, enr) = generate_random_remote_enr();
        let node_id = enr.node_id();
        let key = kbucket::Key::from(node_id);

        let data_radius = U256::from(u64::MAX);
        let node = Node {
            enr: enr.clone(),
            data_radius,
        };
        let connection_direction = ConnectionDirection::Outgoing;

        assert!(!service.peers_to_ping.contains_key(&node_id));
        assert!(matches!(
            service.kbuckets.write().entry(&key),
            kbucket::Entry::Absent { .. }
        ));

        service.connect_node(node, connection_direction);

        assert!(service.peers_to_ping.contains_key(&node_id));

        match service.kbuckets.write().entry(&key) {
            kbucket::Entry::Present(_entry, status) => {
                assert_eq!(ConnectionState::Connected, status.state);
                assert_eq!(connection_direction, status.direction);
            }
            _ => panic!(),
        };
    }

    #[tokio::test]
    #[serial]
    async fn update_node_connection_state_disconnected_to_connected() {
        let mut service = task::spawn(build_service());

        let (_, enr) = generate_random_remote_enr();
        let node_id = enr.node_id();
        let key = kbucket::Key::from(node_id);

        let data_radius = U256::from(u64::MAX);
        let node = Node {
            enr: enr.clone(),
            data_radius,
        };

        let connection_direction = ConnectionDirection::Outgoing;
        let status = NodeStatus {
            state: ConnectionState::Disconnected,
            direction: connection_direction,
        };

        let _ = service
            .kbuckets
            .write()
            .insert_or_update(&key, node, status);

        match service.kbuckets.write().entry(&key) {
            kbucket::Entry::Present(_entry, status) => {
                assert_eq!(ConnectionState::Disconnected, status.state);
                assert_eq!(connection_direction, status.direction);
            }
            _ => panic!(),
        };

        let _ = service.update_node_connection_state(node_id, ConnectionState::Connected);

        match service.kbuckets.write().entry(&key) {
            kbucket::Entry::Present(_entry, status) => {
                assert_eq!(ConnectionState::Connected, status.state);
                assert_eq!(connection_direction, status.direction);
            }
            _ => panic!(),
        };
    }

    #[tokio::test]
    #[serial]
    async fn update_node_connection_state_connected_to_disconnected() {
        let mut service = task::spawn(build_service());

        let (_, enr) = generate_random_remote_enr();
        let node_id = enr.node_id();
        let key = kbucket::Key::from(node_id);

        let data_radius = U256::from(u64::MAX);
        let node = Node {
            enr: enr.clone(),
            data_radius,
        };

        let connection_direction = ConnectionDirection::Outgoing;
        let status = NodeStatus {
            state: ConnectionState::Connected,
            direction: connection_direction,
        };

        let _ = service
            .kbuckets
            .write()
            .insert_or_update(&key, node, status);

        match service.kbuckets.write().entry(&key) {
            kbucket::Entry::Present(_entry, status) => {
                assert_eq!(ConnectionState::Connected, status.state);
                assert_eq!(connection_direction, status.direction);
            }
            _ => panic!(),
        };

        let _ = service.update_node_connection_state(node_id, ConnectionState::Disconnected);

        match service.kbuckets.write().entry(&key) {
            kbucket::Entry::Present(_entry, status) => {
                assert_eq!(ConnectionState::Disconnected, status.state);
                assert_eq!(connection_direction, status.direction);
            }
            _ => panic!(),
        };
    }

    #[rstest]
    #[case(6)]
    #[case(0)]
    #[case(255)]
    #[serial]
    fn test_generate_random_node_id(#[case] target_bucket_idx: u8) {
        let service = task::spawn(build_service());
        let random_node_id = service.generate_random_node_id(target_bucket_idx).unwrap();
        let key = kbucket::Key::from(random_node_id);
        let bucket = service.kbuckets.read();
        let expected_index = bucket.get_index(&key).unwrap();
        assert_eq!(target_bucket_idx, expected_index as u8);
    }
}

fn should_store(_key: &Vec<u8>) -> bool {
    return true;
}
