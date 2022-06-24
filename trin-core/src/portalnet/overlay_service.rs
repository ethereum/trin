use anyhow::anyhow;
use std::{
    collections::HashMap,
    fmt,
    fmt::Debug,
    marker::{PhantomData, Sync},
    sync::Arc,
    task::Poll,
    time::Duration,
};

use crate::{
    portalnet::{
        discovery::Discovery,
        find::{
            iterators::{
                findnodes::FindNodeQuery,
                query::{Query, QueryConfig},
            },
            query_info::{QueryInfo, QueryType},
            query_pool::{QueryId, QueryPool, QueryPoolState, TargetKey},
        },
        metrics::OverlayMetrics,
        storage::PortalStorage,
        types::{
            content_key::OverlayContentKey,
            messages::{
                Accept, ByteList, Content, CustomPayload, FindContent, FindNodes, Message, Nodes,
                Offer, Ping, Pong, ProtocolId, Request, Response, SszEnr,
            },
            metric::Metric,
        },
        Enr,
    },
    types::validation::Validator,
    utils::node_id,
    utp::stream::UtpListenerRequest,
};

use crate::{
    portalnet::types::{content_key::RawContentKey, messages::ContentPayloadList},
    utp::{
        stream::{UtpStream, BUF_SIZE},
        trin_helpers::UtpStreamId,
    },
};
use delay_map::HashSetDelay;
use discv5::{
    enr::NodeId,
    kbucket::{
        self, ConnectionDirection, ConnectionState, FailureReason, InsertResult, KBucketsTable,
        Key, NodeStatus, UpdateResult,
    },
    rpc::RequestId,
};
use ethereum_types::U256;
use futures::{channel::oneshot, prelude::*};
use log::{debug, error, info, warn};
use parking_lot::RwLock;
use rand::seq::SliceRandom;
use smallvec::SmallVec;
use ssz::Encode;
use ssz_types::{BitList, VariableList};
use thiserror::Error;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

/// Maximum number of ENRs in response to FindNodes.
pub const FIND_NODES_MAX_NODES: usize = 32;
/// Maximum number of ENRs in response to FindContent.
pub const FIND_CONTENT_MAX_NODES: usize = 32;
/// With even distribution assumptions, 2**17 is enough to put each node (estimating 100k nodes,
/// which is more than 10x the ethereum mainnet node count) into a unique bucket by the 17th bucket index.
const EXPECTED_NON_EMPTY_BUCKETS: usize = 17;
/// Bucket refresh lookup interval in seconds
const BUCKET_REFRESH_INTERVAL_SECS: u64 = 60;

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
    #[error("Error while building accept message: {0}")]
    AcceptError(String),

    /// Error types resulting from building ACCEPT message
    #[error("Error while sending offer message: {0}")]
    OfferError(String),

    /// uTP request error
    #[error("uTP request error: {0}")]
    UtpError(String),
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
    /// Initialize a request from node.
    Initialize,
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
    /// ID of query that request's response will advance.
    /// Will be None for requests that are not associated with a query.
    pub query_id: Option<QueryId>,
}

impl OverlayRequest {
    /// Creates a new overlay request.
    pub fn new(
        request: Request,
        direction: RequestDirection,
        responder: Option<OverlayResponder>,
        query_id: Option<QueryId>,
    ) -> Self {
        OverlayRequest {
            id: rand::random(),
            request,
            direction,
            responder,
            query_id,
        }
    }
}

/// An active outgoing overlay request.
struct ActiveOutgoingRequest {
    /// The ENR of the destination (target) node.
    pub destination: Enr,
    /// An optional responder to send the result of the associated request.
    pub responder: Option<OverlayResponder>,
    pub request: Request,
    /// An optional QueryID for the query that this request is associated with.
    pub query_id: Option<QueryId>,
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
pub struct OverlayService<TContentKey, TMetric, TValidator> {
    /// The underlying Discovery v5 protocol.
    discovery: Arc<Discovery>,
    /// The content database of the local node.
    storage: Arc<RwLock<PortalStorage>>,
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
    /// All of the queries currently being performed.
    query_pool: QueryPool<NodeId, FindNodeQuery<NodeId>, TContentKey>,
    /// Timeout after which a peer in an ongoing query is marked unresponsive.
    query_peer_timeout: Duration,
    /// Number of peers to request data from in parallel for a single query.
    query_parallelism: usize,
    /// Number of new peers to discover before considering a FINDNODES query complete.
    query_num_results: usize,
    /// The number of buckets we simultaneously request from each peer in a FINDNODES query.
    findnodes_query_distances_per_peer: usize,
    /// The receiver half of a channel for responses to outgoing requests.
    response_rx: UnboundedReceiver<OverlayResponse>,
    /// The sender half of a channel for responses to outgoing requests.
    response_tx: UnboundedSender<OverlayResponse>,
    /// The sender half of a channel to send requests to uTP listener
    utp_listener_tx: UnboundedSender<UtpListenerRequest>,
    /// Phantom content key.
    phantom_content_key: PhantomData<TContentKey>,
    /// Phantom metric (distance function).
    phantom_metric: PhantomData<TMetric>,
    /// Metrics reporting component
    metrics: Option<OverlayMetrics>,
    /// Validator for overlay network content.
    validator: TValidator,
}

impl<
        TContentKey: OverlayContentKey + Send + Sync,
        TMetric: Metric + Send + Sync,
        TValidator: 'static + Validator<TContentKey> + Send + Sync,
    > OverlayService<TContentKey, TMetric, TValidator>
where
    <TContentKey as TryFrom<Vec<u8>>>::Error: Debug,
{
    /// Spawns the overlay network service.
    ///
    /// The state of the overlay network largely consists of its routing table. The routing table
    /// is updated according to incoming requests and responses as well as autonomous maintenance
    /// processes.
    pub async fn spawn(
        discovery: Arc<Discovery>,
        storage: Arc<RwLock<PortalStorage>>,
        kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
        bootnode_enrs: Vec<Enr>,
        ping_queue_interval: Option<Duration>,
        data_radius: Arc<U256>,
        protocol: ProtocolId,
        utp_listener_sender: UnboundedSender<UtpListenerRequest>,
        enable_metrics: bool,
        validator: TValidator,
        query_timeout: Duration,
        query_peer_timeout: Duration,
        query_parallelism: usize,
        query_num_results: usize,
        findnodes_query_distances_per_peer: usize,
    ) -> Result<UnboundedSender<OverlayRequest>, String>
    where
        <TContentKey as TryFrom<Vec<u8>>>::Error: Send,
    {
        let (request_tx, request_rx) = mpsc::unbounded_channel();
        let internal_request_tx = request_tx.clone();

        let overlay_protocol = protocol.clone();

        let peers_to_ping = if let Some(interval) = ping_queue_interval {
            HashSetDelay::new(interval)
        } else {
            HashSetDelay::default()
        };

        let (response_tx, response_rx) = mpsc::unbounded_channel();

        let metrics: Option<OverlayMetrics> =
            enable_metrics.then(|| OverlayMetrics::new(&protocol));

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
                query_pool: QueryPool::new(query_timeout),
                query_peer_timeout,
                query_parallelism,
                query_num_results,
                findnodes_query_distances_per_peer,
                response_rx,
                response_tx,
                utp_listener_tx: utp_listener_sender,
                phantom_content_key: PhantomData,
                phantom_metric: PhantomData,
                metrics,
                validator,
            };

            info!("[{:?}] Starting overlay service", overlay_protocol);
            service.initialize_routing_table(bootnode_enrs);
            service.start().await;
        });

        Ok(request_tx)
    }

    fn add_bootnodes(&mut self, bootnode_enrs: Vec<Enr>) {
        // Attempt to insert bootnodes into the routing table in a disconnected state.
        // If successful, then add the node to the ping queue. A subsequent successful ping
        // will mark the node as connected.

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
            match self.kbuckets.write().insert_or_update(
                &kbucket::Key::from(node_id.clone()),
                node,
                status,
            ) {
                InsertResult::Failed(reason) => {
                    warn!(
                        "[{:?}] Failed to insert bootnode into overlay routing table. Node: {}, Reason {:?}",
                        self.protocol, node_id, reason
                    );
                }
                _ => {
                    debug!(
                        "[{:?}] Inserted bootnode into overlay routing table, adding to ping queue. Node {}",
                        self.protocol, node_id
                    );

                    // Queue the node in the ping queue.
                    self.peers_to_ping.insert(node_id);
                }
            }
        }
    }

    /// Begins initial FINDNODES query to populate the routing table.
    fn initialize_routing_table(&mut self, bootnodes: Vec<Enr>) {
        self.add_bootnodes(bootnodes.clone());
        let node_id = self.local_enr().node_id();
        // Begin request for our local node ID.

        self.init_find_nodes_query_with_initial_enrs(&node_id, bootnodes);
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
        let mut bucket_refresh_interval =
            tokio::time::interval(Duration::from_secs(BUCKET_REFRESH_INTERVAL_SECS));

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
                            Ok(response) => self.process_response(response, active_request.destination, active_request.request, active_request.query_id).await,
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
                query_event = OverlayService::<TContentKey, TMetric, TValidator>::query_event_poll(&mut self.query_pool) => {
                    match query_event {
                        // Send a FINDNODES on behalf of the query.
                        FindNodeQueryEvent::Waiting(query_id, node_id, request) => {

                            // Look up the node's ENR.
                            if let Some(enr) = self.find_enr(&node_id) {

                                let request = OverlayRequest::new(
                                    request,
                                    RequestDirection::Outgoing {
                                        destination: enr
                                    },
                                    None,
                                    Some(query_id),
                                );
                                let _ = self.request_tx.send(request);

                            } else {
                                error!("[{:?}] Unable to send FINDNODES to unknown ENR with node ID {}",
                                         self.protocol, node_id);
                                if let Some((_, query)) = self.query_pool.get_mut(query_id) {
                                    query.on_failure(&node_id);
                                }
                            }

                        }
                        // Query has ended.
                        FindNodeQueryEvent::Finished(query_id, mut query_info, query) | FindNodeQueryEvent::TimedOut(query_id, mut query_info, query) => {
                            let result = query.into_result();
                            // Obtain the ENRs for the resulting nodes.
                            let mut found_enrs = Vec::new();
                            for node_id in result.into_iter() {
                                if let Some(position) = query_info.untrusted_enrs.iter().position(|enr| enr.node_id() == node_id) {
                                    let enr = query_info.untrusted_enrs.swap_remove(position);
                                    found_enrs.push(enr);
                                } else if let Some(enr) = self.find_enr(&node_id) {
                                    // look up from the routing table
                                    found_enrs.push(enr);
                                }
                                else {
                                    warn!("ENR not present in queries results.");
                                }
                            }
                            if let QueryType::FindNode { callback: Some(callback), .. } = query_info.query_type {
                                if let Err(_) = callback.send(found_enrs.clone()) {
                                    error!("Failed to send FindNode query {} results to callback", query_id);
                                }
                            }
                            debug!("[{:?}] Query {} complete, discovered {} ENRs", self.protocol, query_id, found_enrs.len());
                        }
                    }
                }
                _ = OverlayService::<TContentKey, TMetric, TValidator>::bucket_maintenance_poll(self.protocol.clone(), &self.kbuckets) => {}
                _ = bucket_refresh_interval.tick() => {
                    info!("[{:?}] Overlay bucket refresh lookup.", self.protocol);
                    self.bucket_refresh_lookup();
                }
            }
        }
    }

    /// Send request to UtpListener to add a uTP stream to the active connections
    fn add_utp_connection(
        &self,
        source: &NodeId,
        conn_id_recv: u16,
        stream_id: UtpStreamId,
    ) -> Result<(), OverlayRequestError> {
        if let Some(enr) = self.find_enr(source) {
            // Initialize active uTP stream with requesting node
            let utp_request = UtpListenerRequest::InitiateConnection(
                enr,
                self.protocol.clone(),
                stream_id,
                conn_id_recv,
            );
            if let Err(err) = self.utp_listener_tx.send(utp_request) {
                return Err(OverlayRequestError::UtpError(format!(
                    "Unable to send uTP AddActiveConnection request: {err}"
                )));
            }
            Ok(())
        } else {
            Err(OverlayRequestError::UtpError(
                "Can't find ENR in overlay routing table matching remote NodeId".to_string(),
            ))
        }
    }

    /// Main bucket refresh lookup logic
    fn bucket_refresh_lookup(&mut self) {
        // Look at local routing table and select the largest 17 buckets.
        // We only need the 17 bits furthest from our own node ID, because the closest 239 bits of
        // buckets are going to be empty-ish.
        let target_node_id = {
            let buckets = self.kbuckets.read();
            let buckets = buckets.buckets_iter().enumerate().collect::<Vec<_>>();
            let buckets = &buckets[256 - EXPECTED_NON_EMPTY_BUCKETS..];

            // Randomly pick one of these buckets.
            let target_bucket = buckets.choose(&mut rand::thread_rng());
            let random_node_id_in_bucket = match target_bucket {
                Some(bucket) => {
                    debug!("[{:?} Refreshing bucket {}", self.protocol, bucket.0);
                    match u8::try_from(bucket.0) {
                        Ok(idx) => self.generate_random_node_id(idx),
                        Err(err) => {
                            error!("Unable to downcast bucket index: {}", err);
                            return;
                        }
                    }
                }
                None => {
                    error!("Failed to choose random bucket index");
                    return;
                }
            };
            random_node_id_in_bucket
        };

        self.init_find_nodes_query(&target_node_id);
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

    /// Maintains the query pool.
    ///
    /// Returns a `FindNodeQueryEvent` when the `QueryPoolState` updates.
    /// This happens when a query needs to send a request to a node, when a query has completed,
    // or when a query has timed out.
    async fn query_event_poll(
        queries: &mut QueryPool<NodeId, FindNodeQuery<NodeId>, TContentKey>,
    ) -> FindNodeQueryEvent<TContentKey> {
        future::poll_fn(move |_cx| match queries.poll() {
            QueryPoolState::Finished(query_id, query_info, query) => {
                Poll::Ready(FindNodeQueryEvent::Finished(query_id, query_info, query))
            }
            QueryPoolState::Timeout(query_id, query_info, query) => {
                warn!("Query id: {:?} timed out", query_id);
                Poll::Ready(FindNodeQueryEvent::TimedOut(query_id, query_info, query))
            }
            QueryPoolState::Waiting(Some((query_id, query_info, query, return_peer))) => {
                let node_id = return_peer;

                let request_body = match query_info.rpc_request(return_peer) {
                    Ok(request_body) => request_body,
                    Err(_) => {
                        query.on_failure(&node_id);
                        return Poll::Pending;
                    }
                };

                Poll::Ready(FindNodeQueryEvent::Waiting(query_id, node_id, request_body))
            }

            QueryPoolState::Waiting(None) | QueryPoolState::Idle => Poll::Pending,
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
                let response = self.handle_request(request.request.clone(), id.clone(), &source);
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
                        request: request.request.clone(),
                        query_id: request.query_id,
                    },
                );
                self.send_talk_req(request.request, request.id, destination);
            }
            RequestDirection::Initialize => {
                let response = self.initialize_request(request.request.clone());
                // Send response to responder if present.
                if let Some(responder) = request.responder {
                    let _ = responder.send(response);
                }
            }
        }
    }

    /// Initializes a overlay service request from source node.
    fn initialize_request(&mut self, request: Request) -> Result<Response, OverlayRequestError> {
        debug!("[{:?}] Initializing request", self.protocol);
        match request {
            Request::FindContent(find_content) => Ok(Response::Content(
                self.handle_find_content(find_content, None)?,
            )),
            _ => Err(OverlayRequestError::InvalidRequest(
                "Initializing this overlay service request is not yet supported.".to_string(),
            )),
        }
    }

    /// Attempts to build a response for a request.
    fn handle_request(
        &mut self,
        request: Request,
        id: RequestId,
        source: &NodeId,
    ) -> Result<Response, OverlayRequestError> {
        debug!("[{:?}] Handling request {}", self.protocol, id);
        match request {
            Request::Ping(ping) => Ok(Response::Pong(self.handle_ping(ping, &source))),
            Request::FindNodes(find_nodes) => {
                Ok(Response::Nodes(self.handle_find_nodes(find_nodes)))
            }
            Request::FindContent(find_content) => Ok(Response::Content(
                self.handle_find_content(find_content, Some(&source))?,
            )),
            Request::Offer(offer) => Ok(Response::Accept(self.handle_offer(offer, source)?)),
        }
    }

    /// Builds a `Pong` response for a `Ping` request.
    fn handle_ping(&self, request: Ping, source: &NodeId) -> Pong {
        debug!(
            "[{:?}] Handling ping request from node={}. Ping={:?}",
            self.protocol, source, request
        );
        self.metrics
            .as_ref()
            .and_then(|m| Some(m.report_inbound_ping()));
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
        self.metrics
            .as_ref()
            .and_then(|m| Some(m.report_inbound_find_nodes()));
        let distances64: Vec<u64> = request.distances.iter().map(|x| (*x).into()).collect();
        let enrs = self.nodes_by_distance(distances64);

        // Limit the ENRs so that their summed sizes do not surpass the max TALKREQ packet size.
        let enrs = limit_enr_list_to_max_bytes(enrs, MAX_NODES_SIZE);

        Nodes { total: 1, enrs }
    }

    /// Attempts to build a `Content` response for a `FindContent` request.
    fn handle_find_content(
        &self,
        request: FindContent,
        source: Option<&NodeId>,
    ) -> Result<Content, OverlayRequestError> {
        self.metrics
            .as_ref()
            .and_then(|m| Some(m.report_inbound_find_content()));
        let content_key = match (TContentKey::try_from)(request.content_key) {
            Ok(key) => key,
            Err(_) => {
                return Err(OverlayRequestError::InvalidRequest(
                    "Invalid content key".to_string(),
                ))
            }
        };

        match self.storage.read().get(&content_key) {
            Ok(Some(value)) => {
                let content = ByteList::from(VariableList::from(value));

                // Check content size and initiate uTP connection if the size is over the threshold
                // TODO: Properly calculate max content size
                if content.len() < 1000 {
                    Ok(Content::Content(content))
                } else {
                    match source {
                        Some(source) => {
                            let conn_id: u16 = crate::utp::stream::rand();

                            // Listen for incoming uTP connection request on as part of uTP handshake and
                            // storing content data, so we can send it inside UtpListener right after we receive
                            // SYN packet from the requester
                            let conn_id_recv = conn_id.wrapping_add(1);

                            self.add_utp_connection(
                                source,
                                conn_id_recv,
                                UtpStreamId::ContentStream(content),
                            )?;

                            // Connection id is send as BE because uTP header values are stored also as BE
                            Ok(Content::ConnectionId(conn_id.to_be()))

                        },
                        None => {
                           return Err(OverlayRequestError::UtpError(
                               "Unable to start listening for uTP stream because source NodeID is not provided".to_string()))
                        }
                    }
                }
            }
            Ok(None) => {
                let enrs = self.find_nodes_close_to_content(content_key);
                match enrs {
                    Ok(val) => Ok(Content::Enrs(val)),
                    Err(msg) => Err(OverlayRequestError::InvalidRequest(msg.to_string())),
                }
            }
            Err(msg) => Err(OverlayRequestError::Failure(format!(
                "Unable to respond to FindContent: {msg}",
            ))),
        }
    }

    /// Attempts to build an `Accept` response for an `Offer` request.
    fn handle_offer(&self, request: Offer, source: &NodeId) -> Result<Accept, OverlayRequestError> {
        self.metrics
            .as_ref()
            .and_then(|m| Some(m.report_inbound_offer()));

        let mut requested_keys =
            BitList::with_capacity(request.content_keys.len()).map_err(|_| {
                OverlayRequestError::AcceptError(
                    "Unable to initialize bitlist for requested keys.".to_owned(),
                )
            })?;

        let accept_keys = request.content_keys.clone();

        for (i, key) in request.content_keys.into_iter().enumerate() {
            let key = (TContentKey::try_from)(key).map_err(|_| {
                OverlayRequestError::AcceptError(format!(
                    "Unable to build content key from OFFER request."
                ))
            })?;

            requested_keys
                .set(
                    i,
                    self.storage.read().should_store(&key).map_err(|err| {
                        OverlayRequestError::AcceptError(format!(
                            "Unable to check content availability: {err}"
                        ))
                    })?,
                )
                .map_err(|err| {
                    OverlayRequestError::AcceptError(format!(
                        "Unable to set requested keys bits: {err:?}"
                    ))
                })?;
        }

        // Listen for incoming connection request on conn_id, as part of utp handshake
        let conn_id: u16 = crate::utp::stream::rand();

        self.add_utp_connection(source, conn_id, UtpStreamId::AcceptStream(accept_keys))?;

        let accept = Accept {
            connection_id: conn_id.to_be(),
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
    async fn process_response(
        &mut self,
        response: Response,
        source: Enr,
        request: Request,
        query_id: Option<QueryId>,
    ) {
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
            Response::Nodes(nodes) => self.process_nodes(nodes, source, query_id),
            Response::Content(content) => {
                let find_content_request = match request {
                    Request::FindContent(find_content) => find_content,
                    _ => {
                        error!("Unable to process received content: Invalid request message.");
                        return;
                    }
                };
                self.process_content(content, source, find_content_request)
                    .await
            }
            Response::Accept(accept) => {
                let offer_request = match request {
                    Request::Offer(offer) => offer,
                    _ => {
                        error!("Unable to process received content: Invalid request message.");
                        return;
                    }
                };

                if let Err(err) = self
                    .process_accept(accept, source, offer_request.content_keys)
                    .await
                {
                    error!("Error processing ACCEPT response in overlay service: {err}")
                }
            }
        }
    }

    /// Process ACCEPT response
    pub async fn process_accept(
        &self,
        response: Accept,
        enr: Enr,
        content_keys: Vec<RawContentKey>,
    ) -> anyhow::Result<Accept> {
        let content_keys_offered: Result<Vec<TContentKey>, TContentKey::Error> = content_keys
            .into_iter()
            .map(|key| TContentKey::try_from(key))
            .collect();

        let content_keys_offered: Vec<TContentKey> = content_keys_offered
            .map_err(|_| anyhow!("Unable to decode our own offered content keys"))?;

        let conn_id = response.connection_id.to_be();

        // Do not initialize uTP stream if remote node doesn't have interest in the offered content keys
        if response.content_keys.is_zero() {
            return Ok(response);
        }

        // initiate the connection to the acceptor
        let (tx, rx) = tokio::sync::oneshot::channel::<UtpStream>();
        let utp_request = UtpListenerRequest::Connect(
            conn_id,
            enr,
            self.protocol.clone(),
            UtpStreamId::OfferStream,
            tx,
        );

        self.utp_listener_tx
            .send(utp_request).map_err(|err| anyhow!("Unable to send Connect request to UtpListener when processing ACCEPT message: {err}"))?;

        let mut conn = rx.await?;
        // Handle STATE packet for SYN
        let mut buf = [0; BUF_SIZE];
        conn.recv(&mut buf).await?;

        let content_items = self.provide_requested_content(&response, content_keys_offered)?;

        let content_payload = ContentPayloadList::new(content_items)
            .map_err(|err| anyhow!("Unable to build content payload: {err:?}"))?;

        tokio::spawn(async move {
            // send the content to the acceptor over a uTP stream
            if let Err(err) = conn.send_to(&content_payload.as_ssz_bytes()).await {
                warn!("Error sending content {err}");
            };
            // Close uTP connection
            if let Err(err) = conn.close().await {
                warn!("Unable to close uTP connection!: {err}")
            };
        });
        Ok(response)
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
    fn process_nodes(&mut self, nodes: Nodes, source: Enr, query_id: Option<QueryId>) {
        debug!(
            "[{:?}] Processing Nodes response from node. Node: {}",
            self.protocol,
            source.node_id()
        );

        let enrs: Vec<Enr> = nodes
            .enrs
            .into_iter()
            .map(|ssz_enr| ssz_enr.into())
            .collect();

        self.process_discovered_enrs(enrs.clone());
        if let Some(query_id) = query_id {
            self.advance_query(source, enrs, query_id);
        }
    }

    /// Processes a Content response.
    async fn process_content(&mut self, content: Content, source: Enr, request: FindContent) {
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
            Content::Content(content) => self.process_received_content(content, request).await,
            Content::Enrs(enrs) => self
                .process_discovered_enrs(enrs.into_iter().map(|ssz_enr| ssz_enr.into()).collect()),
        }
    }

    async fn process_received_content(&mut self, content: ByteList, request: FindContent) {
        let content_key = match TContentKey::try_from(request.content_key) {
            Ok(val) => val,
            Err(msg) => {
                error!("Unable to process received content: We sent a request with an invalid content key: {msg:?}");
                return;
            }
        };
        let should_store = self.storage.read().should_store(&content_key);
        match should_store {
            Ok(val) => {
                if val {
                    // validate content before storing
                    if let Err(err) = self
                        .validator
                        .validate_content(&content_key, &content)
                        .await
                    {
                        error!("Unable to validate received content: {err:?}");
                        return;
                    };

                    if let Err(err) = self.storage.write().store(&content_key, &content.into()) {
                        error!("Content received, but not stored: {err}")
                    }
                } else {
                    debug!(
                        "Content received, but not stored: Content is already stored or its distance falls outside current radius."
                    )
                }
            }
            Err(_) => {
                error!("Content received, but not stored: Error communicating with db.");
            }
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

    /// Provide the requested content key and content value for the acceptor
    fn provide_requested_content(
        &self,
        accept_message: &Accept,
        content_keys_offered: Vec<TContentKey>,
    ) -> anyhow::Result<Vec<ByteList>> {
        let mut content_items: Vec<ByteList> = Vec::new();

        for (i, key) in accept_message
            .content_keys
            .clone()
            .iter()
            .zip(content_keys_offered.iter())
        {
            if i == true {
                match self.storage.read().get(key) {
                    Ok(content) => match content {
                        Some(content) => content_items.push(content.into()),
                        None => return Err(anyhow!("Unable to read offered content!")),
                    },
                    Err(err) => {
                        return Err(anyhow!(
                            "Unable to get offered content from portal storage: {err}"
                        ))
                    }
                }
            }
        }
        Ok(content_items)
    }

    /// Advances a query (if one is active for the node) using the received ENRs.
    /// Does nothing if called with a node_id that does not have a corresponding active query request.
    fn advance_query(&mut self, source: Enr, enrs: Vec<Enr>, query_id: QueryId) {
        // Check whether this request was sent on behalf of a query.
        // If so, advance the query with the returned data.
        let local_node_id = self.local_enr().node_id();
        if let Some((query_info, query)) = self.query_pool.get_mut(query_id) {
            for enr_ref in enrs.iter() {
                if !query_info
                    .untrusted_enrs
                    .iter()
                    .any(|enr| enr.node_id() == enr_ref.node_id() && enr.node_id() != local_node_id)
                {
                    query_info.untrusted_enrs.push(enr_ref.clone());
                }
            }
            query.on_success(
                &source.node_id(),
                enrs.iter().map(|enr| enr.into()).collect(),
            );
        } else {
            debug!("Response returned for inactive query {:?}", query_id)
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
        let self_distance = TMetric::distance(&content_id, &self_node_id.raw());

        let mut nodes_with_distance: Vec<(U256, Enr)> = self
            .table_entries_enr()
            .into_iter()
            .map(|enr| (TMetric::distance(&content_id, &enr.node_id().raw()), enr))
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

    /// Starts a FindNode query to find nodes with IDs closest to target, starting with given enrs.
    fn init_find_nodes_query_with_initial_enrs(&mut self, target: &NodeId, enrs: Vec<Enr>) {
        let query_config = QueryConfig {
            parallelism: self.query_parallelism,
            num_results: self.query_num_results,
            peer_timeout: self.query_peer_timeout,
        };

        let query_info = QueryInfo {
            query_type: QueryType::FindNode {
                target: *target,
                distances_to_request: self.findnodes_query_distances_per_peer,
                callback: None,
            },
            untrusted_enrs: SmallVec::from_vec(enrs),
        };

        let known_closest_peers: Vec<Key<NodeId>> = query_info
            .untrusted_enrs
            .iter()
            .map(|enr| Key::from(enr.node_id()))
            .collect();

        if known_closest_peers.is_empty() {
            warn!(
                "FindNodes query initiated but no closest peers in routing table. Aborting query."
            );
        } else {
            let find_nodes_query =
                FindNodeQuery::with_config(query_config, query_info.key(), known_closest_peers);
            self.query_pool.add_query(query_info, find_nodes_query);
        }
    }

    /// Starts a FindNode query to find nodes with IDs closest to target.
    fn init_find_nodes_query(&mut self, target: &NodeId) {
        let target_key = Key::from(*target);
        let closest_enrs = self
            .kbuckets
            .write()
            .closest_values(&target_key)
            .map(|closest| closest.value.enr)
            .collect();

        self.init_find_nodes_query_with_initial_enrs(target, closest_enrs);
    }

    /// Returns an ENR if one is known for the given NodeId.
    pub fn find_enr(&self, node_id: &NodeId) -> Option<Enr> {
        // Check whether we know this node id in our routing table.
        let key = kbucket::Key::from(*node_id);
        if let kbucket::Entry::Present(entry, _) = self.kbuckets.write().entry(&key) {
            return Some(entry.value().clone().enr());
        }
        // Check the untrusted addresses for ongoing queries.
        for (query_info, _) in self.query_pool.iter() {
            if let Some(enr) = query_info
                .untrusted_enrs
                .iter()
                .find(|v| v.node_id() == *node_id)
            {
                return Some(enr.clone());
            }
        }
        None
    }

    fn generate_random_node_id(&self, target_bucket_idx: u8) -> NodeId {
        node_id::generate_random_node_id(target_bucket_idx, self.local_enr().node_id())
    }
}

/// The result of the `query_event_poll` indicating an action is required to further progress an
/// active query.
pub enum FindNodeQueryEvent<TContentKey> {
    /// The query is waiting for a peer to be contacted.
    Waiting(QueryId, NodeId, Request),
    /// The query has timed out, possible returning peers.
    TimedOut(QueryId, QueryInfo<TContentKey>, FindNodeQuery<NodeId>),
    /// The query has completed successfully.
    Finished(QueryId, QueryInfo<TContentKey>, FindNodeQuery<NodeId>),
}

const MAX_ENR_SIZE: usize = 300;
const MAX_DISCV5_PACKET_SIZE: usize = 1280;
const TALK_REQ_PACKET_OVERHEAD: usize = 16 + // IV
    55 + // Header
    1 + // Discv5 Message Type
    3 + // RLP Encoding of outer list
    9 + // Request ID, max 8 bytes + 1 for RLP encoding
    3 + // RLP Encoding of inner response
    16; // RLP HMAC
        // ENR SSZ overhead empirically observed to be double.
        // Todo: determine why this is. It seems too high.
const MAX_NODES_SIZE: usize = MAX_DISCV5_PACKET_SIZE - TALK_REQ_PACKET_OVERHEAD;
const NUM_MAX_SIZE_ENRS_IN_MAX_SIZE_PACKET: usize = MAX_NODES_SIZE / MAX_ENR_SIZE;

/// Limits a to a maximum packet size, including the discv5 header overhead.
fn limit_enr_list_to_max_bytes(enrs: Vec<SszEnr>, max_size: usize) -> Vec<SszEnr> {
    // If all ENRs would fit at max size, don't check individual sizes.
    if enrs.len() < NUM_MAX_SIZE_ENRS_IN_MAX_SIZE_PACKET {
        return enrs;
    }

    let mut total_size: usize = 0;
    enrs.into_iter()
        .take_while(|enr| {
            let enr_size = enr.ssz_bytes_len();
            total_size = total_size + enr_size;
            total_size < max_size
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    use crate::{
        cli::DEFAULT_STORAGE_CAPACITY,
        portalnet::{
            discovery::Discovery,
            overlay::OverlayConfig,
            storage::PortalStorage,
            types::{
                content_key::IdentityContentKey, messages::PortalnetConfig, metric::XorMetric,
            },
        },
        types::validation::MockValidator,
        utils::node_id::generate_random_remote_enr,
    };

    use discv5::kbucket::Entry;
    use serial_test::serial;
    use tokio::sync::mpsc::unbounded_channel;
    use tokio_test::{assert_pending, assert_ready, task};

    macro_rules! poll_request_rx {
        ($service:ident) => {
            $service.enter(|cx, mut service| service.request_rx.poll_recv(cx))
        };
    }

    fn build_service() -> OverlayService<IdentityContentKey, XorMetric, MockValidator> {
        let portal_config = PortalnetConfig {
            no_stun: true,
            ..Default::default()
        };
        let discovery = Arc::new(Discovery::new(portal_config).unwrap());

        let (utp_listener_tx, _) = unbounded_channel::<UtpListenerRequest>();

        // Initialize DB config
        let storage_capacity: u32 = DEFAULT_STORAGE_CAPACITY.parse().unwrap();
        let node_id = discovery.local_enr().node_id();
        let storage_config = PortalStorage::setup_config(node_id, storage_capacity).unwrap();
        let storage = Arc::new(RwLock::new(PortalStorage::new(storage_config).unwrap()));

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
        let metrics = None;
        let validator = MockValidator {};

        let service = OverlayService {
            discovery,
            storage,
            kbuckets,
            data_radius,
            protocol,
            peers_to_ping,
            request_tx,
            request_rx,
            active_outgoing_requests,
            query_pool: QueryPool::new(overlay_config.query_timeout),
            query_peer_timeout: overlay_config.query_peer_timeout,
            query_parallelism: overlay_config.query_parallelism,
            query_num_results: overlay_config.query_num_results,
            findnodes_query_distances_per_peer: overlay_config.findnodes_query_distances_per_peer,
            response_tx,
            response_rx,
            utp_listener_tx,
            phantom_content_key: PhantomData,
            phantom_metric: PhantomData,
            metrics,
            validator,
        };

        service
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
        let _ = enr1.set_udp4(updated_udp, &sk1);
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
        let random_node_id = service.generate_random_node_id(target_bucket_idx);
        let key = kbucket::Key::from(random_node_id);
        let bucket = service.kbuckets.read();
        let expected_index = bucket.get_index(&key).unwrap();
        assert_eq!(target_bucket_idx, expected_index as u8);
    }

    #[rstest]
    #[case(3, 3)]
    #[case(7, 7)]
    #[case(8, 8)]
    #[case(17, 8)]
    #[case(25, 8)]
    fn test_limit_nodes_response_size(
        #[case] original_nodes_size: usize,
        #[case] correct_limited_size: usize,
    ) {
        let mut enrs: Vec<SszEnr> = Vec::new();
        for _ in 0..original_nodes_size {
            // Generates an ENR of size 63 bytes.
            let (_, enr) = generate_random_remote_enr();
            enrs.push(SszEnr::new(enr));
        }

        let enrs_limited = limit_enr_list_to_max_bytes(enrs, MAX_NODES_SIZE);

        assert_eq!(enrs_limited.len(), correct_limited_size);
    }

    #[rstest]
    fn test_init_find_nodes_query() {
        let mut service = task::spawn(build_service());

        let (_, bootnode1) = generate_random_remote_enr();
        let (_, bootnode2) = generate_random_remote_enr();
        let bootnodes = vec![bootnode1.clone(), bootnode2.clone()];

        let (_, target_enr) = generate_random_remote_enr();
        let target_node_id = target_enr.node_id();

        assert_eq!(service.query_pool.iter().count(), 0);

        // Initialize the query and call `poll` so that it starts
        service.init_find_nodes_query_with_initial_enrs(&target_node_id, bootnodes);
        let _ = service.query_pool.poll();

        let (query_info, query) = service.query_pool.iter().next().unwrap();

        assert!(query_info.untrusted_enrs.contains(&bootnode1));
        assert!(query_info.untrusted_enrs.contains(&bootnode2));
        match query_info.query_type {
            QueryType::FindNode {
                target,
                distances_to_request,
                ..
            } => {
                assert_eq!(target, target_node_id);
                assert_eq!(
                    distances_to_request,
                    service.findnodes_query_distances_per_peer
                );
            }
            _ => panic!("Unexpected query type"),
        }

        assert!(query.started().is_some());
    }

    fn init_find_nodes_query_with_initial_enrs_and_config(
        service: &mut OverlayService<IdentityContentKey, XorMetric, MockValidator>,
        target: &NodeId,
        enrs: Vec<Enr>,
        query_config: QueryConfig,
    ) {
        let query_info = QueryInfo {
            query_type: QueryType::FindNode {
                target: *target,
                callback: None,
                distances_to_request: service.findnodes_query_distances_per_peer,
            },
            untrusted_enrs: SmallVec::from_vec(enrs),
        };

        let known_closest_peers: Vec<Key<NodeId>> = query_info
            .untrusted_enrs
            .iter()
            .map(|enr| Key::from(enr.node_id()))
            .collect();

        if known_closest_peers.is_empty() {
            warn!(
                "FindNodes query initiated but no closest peers in routing table. Aborting query."
            );
        } else {
            let find_nodes_query =
                FindNodeQuery::with_config(query_config, query_info.key(), known_closest_peers);
            service.query_pool.add_query(query_info, find_nodes_query);
        }
    }

    #[tokio::test]
    async fn test_advance_findnodes_query() {
        let mut service = build_service();

        let (_, bootnode) = generate_random_remote_enr();
        let bootnodes = vec![bootnode.clone()];
        let bootnode_node_id = bootnode.node_id();

        let (_, target_enr) = generate_random_remote_enr();
        let target_node_id = target_enr.node_id();

        let query_config = QueryConfig {
            parallelism: service.query_parallelism,
            num_results: 3,
            peer_timeout: service.query_peer_timeout,
        };

        init_find_nodes_query_with_initial_enrs_and_config(
            &mut service,
            &target_node_id,
            bootnodes,
            query_config,
        );

        // Test that the first query event contains a proper query ID and request to the bootnode
        let event =
            OverlayService::<IdentityContentKey, XorMetric, MockValidator>::query_event_poll(
                &mut service.query_pool,
            )
            .await;
        match event {
            FindNodeQueryEvent::Waiting(query_id, node_id, request) => {
                match request {
                    Request::FindNodes(find_nodes) => {
                        assert_eq!(
                            find_nodes.distances.len(),
                            service.findnodes_query_distances_per_peer
                        );
                    }
                    _ => panic!(),
                }
                assert_eq!(query_id, QueryId(0));
                assert_eq!(node_id, bootnode_node_id);
            }
            _ => panic!(),
        }

        // Create two ENRs to use as dummy responses to the query from the bootnode.
        let (_, enr1) = generate_random_remote_enr();
        let (_, enr2) = generate_random_remote_enr();
        let node_id_1 = enr1.node_id();
        let node_id_2 = enr2.node_id();

        service.advance_query(
            bootnode.clone(),
            vec![enr1.clone(), enr2.clone()],
            QueryId(0),
        );

        let event =
            OverlayService::<IdentityContentKey, XorMetric, MockValidator>::query_event_poll(
                &mut service.query_pool,
            )
            .await;

        // Check that the request is being sent to either node 1 or node 2. Keep track of which.
        let first_node_id: Option<NodeId>;
        match event {
            FindNodeQueryEvent::Waiting(_, node_id, _) => {
                assert!((node_id == node_id_1) || (node_id == node_id_2));
                first_node_id = Some(node_id);
            }
            _ => panic!(),
        }

        let event =
            OverlayService::<IdentityContentKey, XorMetric, MockValidator>::query_event_poll(
                &mut service.query_pool,
            )
            .await;

        // Check that a request is being sent to the other node.
        let second_node_id = if first_node_id.unwrap() == node_id_1 {
            node_id_2
        } else {
            node_id_1
        };
        match event {
            FindNodeQueryEvent::Waiting(_, node_id, _) => {
                assert_eq!(node_id, second_node_id);
            }
            _ => panic!(),
        };

        service.advance_query(enr1.clone(), vec![enr2.clone()], QueryId(0));
        service.advance_query(enr2.clone(), vec![enr1.clone()], QueryId(0));

        let event =
            OverlayService::<IdentityContentKey, XorMetric, MockValidator>::query_event_poll(
                &mut service.query_pool,
            )
            .await;

        match event {
            FindNodeQueryEvent::Finished(query_id, query_info, query) => {
                assert_eq!(query_id, QueryId(0));
                let results = query.into_result();

                assert_eq!(results.clone().len(), 3);

                assert!(results.contains(&node_id_1));
                assert!(results.contains(&node_id_2));
                assert!(results.contains(&bootnode_node_id));

                let untrusted_enrs = query_info.untrusted_enrs;
                assert!(untrusted_enrs.contains(&enr1));
                assert!(untrusted_enrs.contains(&enr2));
                assert!(untrusted_enrs.contains(&bootnode));
            }
            _ => panic!(),
        }
    }

    #[tokio::test]
    async fn test_find_enrs() {
        let mut service = task::spawn(build_service());

        let (_, bootnode) = generate_random_remote_enr();
        let bootnodes = vec![bootnode.clone()];
        let bootnode_node_id = bootnode.node_id();

        let (_, target_enr) = generate_random_remote_enr();
        let target_node_id = target_enr.node_id();

        service.init_find_nodes_query_with_initial_enrs(&target_node_id, bootnodes);

        let _event =
            OverlayService::<IdentityContentKey, XorMetric, MockValidator>::query_event_poll(
                &mut service.query_pool,
            )
            .await;

        let (_, enr1) = generate_random_remote_enr();
        let (_, enr2) = generate_random_remote_enr();
        let node_id_1 = enr1.node_id();
        let node_id_2 = enr2.node_id();

        service.advance_query(
            bootnode.clone(),
            vec![enr1.clone(), enr2.clone()],
            QueryId(0),
        );

        let found_bootnode_enr = service.find_enr(&bootnode_node_id).unwrap();
        assert_eq!(found_bootnode_enr, bootnode);

        let found_enr1 = service.find_enr(&node_id_1).unwrap();
        assert_eq!(found_enr1, enr1);

        let found_enr2 = service.find_enr(&node_id_2).unwrap();
        assert_eq!(found_enr2, enr2);
    }
}
