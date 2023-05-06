use std::{
    collections::HashMap,
    fmt::Debug,
    marker::{PhantomData, Sync},
    str::FromStr,
    sync::Arc,
    task::Poll,
    time::Duration,
};

use anyhow::anyhow;
use bytes::Bytes;
use delay_map::HashSetDelay;
use discv5::{
    enr::NodeId,
    kbucket::{
        self, ConnectionDirection, ConnectionState, FailureReason, InsertResult, KBucketsTable,
        Key, NodeStatus, UpdateResult,
    },
    rpc::RequestId,
};
use futures::{channel::oneshot, future::join_all, prelude::*};
use parking_lot::RwLock;
use rand::seq::{IteratorRandom, SliceRandom};
use smallvec::SmallVec;
use ssz::Encode;
use ssz_types::BitList;
use thiserror::Error;
use tokio::{
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};
use tracing::{debug, error, info, trace, warn};
use utp_rs::{conn::ConnectionConfig, socket::UtpSocket};

use crate::{
    discovery::Discovery,
    find::{
        iterators::{
            findcontent::{FindContentQuery, FindContentQueryResponse, FindContentQueryResult},
            findnodes::FindNodeQuery,
            query::{Query, QueryConfig},
        },
        query_info::{FindContentResult, QueryInfo, QueryType},
        query_pool::{QueryId, QueryPool, QueryPoolState, TargetKey},
    },
    metrics::OverlayMetrics,
    storage::ContentStore,
    types::{
        messages::{
            Accept, Content, CustomPayload, FindContent, FindNodes, Message, Nodes, Offer, Ping,
            Pong, PopulatedOffer, ProtocolId, Request, Response, MAX_PORTAL_CONTENT_PAYLOAD_SIZE,
            MAX_PORTAL_NODES_ENRS_SIZE,
        },
        node::Node,
    },
    utils::portal_wire,
};
use ethportal_api::trin_types::content_key::RawContentKey;
use ethportal_api::trin_types::distance::{Distance, Metric, XorMetric};
use ethportal_api::trin_types::enr::{Enr, SszEnr};
use ethportal_api::trin_types::node_id::NodeId as TrinNodeId;
use ethportal_api::trin_types::query_trace::QueryTrace;
use ethportal_api::OverlayContentKey;
use trin_utils::bytes::{hex_encode, hex_encode_compact};
use trin_validation::validator::Validator;

pub const FIND_NODES_MAX_NODES: usize = 32;

/// Maximum number of ENRs in response to FindContent.
pub const FIND_CONTENT_MAX_NODES: usize = 32;

/// With even distribution assumptions, 2**17 is enough to put each node (estimating 100k nodes,
/// which is more than 10x the ethereum mainnet node count) into a unique bucket by the 17th bucket index.
const EXPECTED_NON_EMPTY_BUCKETS: usize = 17;

/// Bucket refresh lookup interval in seconds
const BUCKET_REFRESH_INTERVAL_SECS: u64 = 60;

/// The default configuration to use for uTP connections.
pub const UTP_CONN_CFG: ConnectionConfig = ConnectionConfig {
    max_packet_size: 1024,
    max_conn_attempts: 3,
    max_idle_timeout: Duration::from_secs(32),
    initial_timeout: Duration::from_millis(1500),
    min_timeout: Duration::from_millis(500),
    target_delay: Duration::from_millis(250),
};

/// A network-based action that the overlay may perform.
///
/// The overlay performs network-based actions on behalf of the command issuer. The issuer may be
/// the overlay itself. The overlay manages network requests and responses and sends the result
/// back to the issuer upon completion.
#[derive(Debug)]
pub enum OverlayCommand<TContentKey> {
    /// Send a single portal request through the overlay.
    ///
    /// A `Request` corresponds to a single request message defined in the portal wire spec.
    Request(OverlayRequest),
    /// Perform a find content query through the overlay.
    ///
    /// A `FindContentQuery` issues multiple requests to find the content identified by `target`.
    /// The result is sent to the issuer over `callback`.
    FindContentQuery {
        /// The query target.
        target: TContentKey,
        /// A callback channel to transmit the result of the query.
        callback: oneshot::Sender<(Option<Vec<u8>>, Option<QueryTrace>)>,
        /// Whether or not a trace for the content query should be kept and returned.
        is_trace: bool,
    },
    FindNodeQuery {
        /// The query target.
        target: NodeId,
        /// A callback channel to transmit the result of the query.
        callback: oneshot::Sender<Vec<Enr>>,
    },
}

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

    /// Received content failed validation for a response.
    #[error("Response content failed validation: {0}")]
    FailedValidation(String),

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

    #[error("Received invalid remote discv5 packet")]
    InvalidRemoteDiscv5Packet,
}

impl From<discv5::RequestError> for OverlayRequestError {
    fn from(err: discv5::RequestError) -> Self {
        match err {
            discv5::RequestError::Timeout => Self::Timeout,
            discv5::RequestError::InvalidRemotePacket => Self::InvalidRemoteDiscv5Packet,
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

/// The overlay service.
pub struct OverlayService<TContentKey, TMetric, TValidator, TStore> {
    /// The underlying Discovery v5 protocol.
    discovery: Arc<Discovery>,
    /// The content database of the local node.
    store: Arc<RwLock<TStore>>,
    /// The routing table of the local node.
    kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
    /// The protocol identifier.
    protocol: ProtocolId,
    /// A queue of peers that require regular ping to check connectivity.
    /// Inserted entries expire after a fixed time. Nodes to be pinged are inserted with a timeout
    /// duration equal to some ping interval, and we continuously poll the queue to check for
    /// expired entries.
    peers_to_ping: HashSetDelay<NodeId>,
    // TODO: This should probably be a bounded channel.
    /// The receiver half of the service command channel.
    command_rx: UnboundedReceiver<OverlayCommand<TContentKey>>,
    /// The sender half of the service command channel.
    /// This is used internally to submit requests (e.g. maintenance ping requests).
    command_tx: UnboundedSender<OverlayCommand<TContentKey>>,
    /// A map of active outgoing requests.
    active_outgoing_requests: Arc<RwLock<HashMap<OverlayRequestId, ActiveOutgoingRequest>>>,
    /// A query pool that manages find node queries.
    find_node_query_pool: QueryPool<NodeId, FindNodeQuery<NodeId>, TContentKey>,
    /// A query pool that manages find content queries.
    find_content_query_pool: QueryPool<NodeId, FindContentQuery<NodeId>, TContentKey>,
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
    /// uTP socket.
    utp_socket: Arc<UtpSocket<crate::discovery::UtpEnr>>,
    /// Phantom content key.
    phantom_content_key: PhantomData<TContentKey>,
    /// Phantom metric (distance function).
    phantom_metric: PhantomData<TMetric>,
    /// Metrics reporting component
    metrics: Arc<OverlayMetrics>,
    /// Validator for overlay network content.
    validator: Arc<TValidator>,
}

impl<
        TContentKey: 'static + OverlayContentKey + Send + Sync,
        TMetric: Metric + Send + Sync,
        TValidator: 'static + Validator<TContentKey> + Send + Sync,
        TStore: 'static + ContentStore + Send + Sync,
    > OverlayService<TContentKey, TMetric, TValidator, TStore>
where
    <TContentKey as TryFrom<Vec<u8>>>::Error: Debug,
{
    /// Spawns the overlay network service.
    ///
    /// The state of the overlay network largely consists of its routing table. The routing table
    /// is updated according to incoming requests and responses as well as autonomous maintenance
    /// processes.
    #[allow(clippy::too_many_arguments)]
    pub async fn spawn(
        discovery: Arc<Discovery>,
        store: Arc<RwLock<TStore>>,
        kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
        bootnode_enrs: Vec<Enr>,
        ping_queue_interval: Option<Duration>,
        protocol: ProtocolId,
        utp_socket: Arc<UtpSocket<crate::discovery::UtpEnr>>,
        metrics: Arc<OverlayMetrics>,
        validator: Arc<TValidator>,
        query_timeout: Duration,
        query_peer_timeout: Duration,
        query_parallelism: usize,
        query_num_results: usize,
        findnodes_query_distances_per_peer: usize,
    ) -> UnboundedSender<OverlayCommand<TContentKey>>
    where
        <TContentKey as TryFrom<Vec<u8>>>::Error: Send,
    {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let internal_command_tx = command_tx.clone();

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
                store,
                kbuckets,
                protocol,
                peers_to_ping,
                command_rx,
                command_tx: internal_command_tx,
                active_outgoing_requests: Arc::new(RwLock::new(HashMap::new())),
                find_node_query_pool: QueryPool::new(query_timeout),
                find_content_query_pool: QueryPool::new(query_timeout),
                query_peer_timeout,
                query_parallelism,
                query_num_results,
                findnodes_query_distances_per_peer,
                response_rx,
                response_tx,
                utp_socket,
                phantom_content_key: PhantomData,
                phantom_metric: PhantomData,
                metrics,
                validator,
            };

            info!(protocol = %overlay_protocol, "Starting overlay service");
            service.initialize_routing_table(bootnode_enrs);
            service.start().await;
        });

        command_tx
    }

    fn add_bootnodes(&mut self, bootnode_enrs: Vec<Enr>) {
        // Attempt to insert bootnodes into the routing table in a disconnected state.
        // If successful, then add the node to the ping queue. A subsequent successful ping
        // will mark the node as connected.

        for enr in bootnode_enrs {
            let node_id = enr.node_id();

            // TODO: Decide default data radius, and define a constant. Or if there is an
            // associated database, then look for a radius value there.
            let node = Node::new(enr, Distance::MAX);
            let status = NodeStatus {
                state: ConnectionState::Disconnected,
                direction: ConnectionDirection::Outgoing,
            };

            // Attempt to insert the node into the routing table.
            match self
                .kbuckets
                .write()
                .insert_or_update(&kbucket::Key::from(node_id), node, status)
            {
                InsertResult::Failed(reason) => {
                    warn!(
                        protocol = %self.protocol,
                        bootnode = %node_id,
                        error = ?reason,
                        "Error inserting bootnode into routing table",
                    );
                }
                _ => {
                    debug!(
                        protocol = %self.protocol,
                        bootnode = %node_id,
                        "Inserted bootnode into routing table",
                    );

                    // Queue the node in the ping queue.
                    self.peers_to_ping.insert(node_id);
                }
            }
        }
    }

    /// Begins initial FINDNODES query to populate the routing table.
    fn initialize_routing_table(&mut self, bootnodes: Vec<Enr>) {
        self.add_bootnodes(bootnodes);
        let local_node_id = self.local_enr().node_id();

        // Begin request for our local node ID.
        self.init_find_nodes_query(&local_node_id, None);

        for bucket_index in (255 - EXPECTED_NON_EMPTY_BUCKETS as u8)..255 {
            let target_node_id =
                TrinNodeId::generate_random_node_id(bucket_index, self.local_enr().into());
            self.init_find_nodes_query(&target_node_id.into(), None);
        }
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
                Some(command) = self.command_rx.recv() => {
                    match command {
                        OverlayCommand::Request(request) => self.process_request(request),
                        OverlayCommand::FindContentQuery { target, callback, is_trace } => {
                            if let Some(query_id) = self.init_find_content_query(target.clone(), Some(callback), is_trace) {
                                trace!(
                                    query.id = %query_id,
                                    content.id = %hex_encode_compact(target.content_id()),
                                    content.key = %target,
                                    "FindContent query initialized"
                                );
                            }
                        }
                        OverlayCommand::FindNodeQuery { target, callback } => {
                            if let Some(query_id) = self.init_find_nodes_query(&target, Some(callback)) {
                                trace!(
                                    query.id = %query_id,
                                    node.id = %hex_encode_compact(target),
                                    "FindNode query initialized"
                                );
                            }
                        }
                    }
                }
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
                            Ok(response) => {
                                self.metrics.report_inbound_response(&self.protocol, &response);
                                self.process_response(response, active_request.destination, active_request.request, active_request.query_id)
                            }
                            Err(error) => self.process_request_failure(response.request_id, active_request.destination, error),
                        }

                    } else {
                        warn!(request.id = %hex_encode_compact(response.request_id.to_be_bytes()), "No request found for response");
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
                query_event = OverlayService::<TContentKey, TMetric, TValidator, TStore>::query_event_poll(&mut self.find_node_query_pool) => {
                    self.handle_find_nodes_query_event(query_event);
                }
                // Handle query events for queries in the find content query pool.
                query_event = OverlayService::<TContentKey, TMetric, TValidator, TStore>::query_event_poll(&mut self.find_content_query_pool) => {
                    self.handle_find_content_query_event(query_event);
                }
                _ = OverlayService::<TContentKey, TMetric, TValidator, TStore>::bucket_maintenance_poll(self.protocol.clone(), &self.kbuckets) => {}
                _ = bucket_refresh_interval.tick() => {
                    trace!(protocol = %self.protocol, "Routing table bucket refresh");
                    self.bucket_refresh_lookup();
                }
            }
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
            match target_bucket {
                Some(bucket) => {
                    trace!(protocol = %self.protocol, bucket = %bucket.0, "Refreshing routing table bucket");
                    match u8::try_from(bucket.0) {
                        Ok(idx) => {
                            TrinNodeId::generate_random_node_id(idx, self.local_enr().into())
                        }
                        Err(err) => {
                            error!(error = %err, "Error downcasting bucket index");
                            return;
                        }
                    }
                }
                None => {
                    error!("Error choosing random bucket index for refresh");
                    return;
                }
            }
        };

        self.init_find_nodes_query(&target_node_id.into(), None);
    }

    /// Returns the local ENR of the node.
    fn local_enr(&self) -> Enr {
        self.discovery.local_enr()
    }

    /// Returns the data radius of the node.
    fn data_radius(&self) -> Distance {
        self.store.read().radius()
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
                    %protocol,
                    inserted = %entry.inserted.into_preimage(),
                    evicted = ?entry.evicted.map(|n| n.key.into_preimage()),
                    "Pending node inserted",

                );
                return Poll::Ready(());
            }
            Poll::Pending
        })
        .await
    }

    /// Maintains the query pool.
    /// Returns a `QueryEvent` when the `QueryPoolState` updates.
    /// This happens when a query needs to send a request to a node, when a query has completed,
    // or when a query has timed out.
    async fn query_event_poll<TQuery: Query<NodeId>>(
        queries: &mut QueryPool<NodeId, TQuery, TContentKey>,
    ) -> QueryEvent<TQuery, TContentKey> {
        future::poll_fn(move |_cx| match queries.poll() {
            QueryPoolState::Finished(query_id, query_info, query) => {
                Poll::Ready(QueryEvent::Finished(query_id, query_info, query))
            }
            QueryPoolState::Timeout(query_id, query_info, query) => {
                warn!(query.id = %query_id, "Query timed out");
                Poll::Ready(QueryEvent::TimedOut(query_id, query_info, query))
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

                Poll::Ready(QueryEvent::Waiting(query_id, node_id, request_body))
            }

            QueryPoolState::Waiting(None) | QueryPoolState::Idle => Poll::Pending,
        })
        .await
    }

    /// Handles a `QueryEvent` from a poll on the find nodes query pool.
    fn handle_find_nodes_query_event(
        &mut self,
        query_event: QueryEvent<FindNodeQuery<NodeId>, TContentKey>,
    ) {
        match query_event {
            // Send a FINDNODES on behalf of the query.
            QueryEvent::Waiting(query_id, node_id, request) => {
                // Look up the node's ENR.
                if let Some(enr) = self.find_enr(&node_id) {
                    let request = OverlayRequest::new(
                        request,
                        RequestDirection::Outgoing { destination: enr },
                        None,
                        Some(query_id),
                    );
                    let _ = self.command_tx.send(OverlayCommand::Request(request));
                } else {
                    error!(
                        protocol = %self.protocol,
                        peer = %node_id,
                        query.id = %query_id,
                        "Cannot query peer with unknown ENR",
                    );
                    if let Some((_, query)) = self.find_node_query_pool.get_mut(query_id) {
                        query.on_failure(&node_id);
                    }
                }
            }
            // Query has ended.
            QueryEvent::Finished(query_id, mut query_info, query)
            | QueryEvent::TimedOut(query_id, mut query_info, query) => {
                let result = query.into_result();
                // Obtain the ENRs for the resulting nodes.
                let mut found_enrs = Vec::new();
                for node_id in result.into_iter() {
                    if let Some(position) = query_info
                        .untrusted_enrs
                        .iter()
                        .position(|enr| enr.node_id() == node_id)
                    {
                        let enr = query_info.untrusted_enrs.swap_remove(position);
                        found_enrs.push(enr);
                    } else if let Some(enr) = self.find_enr(&node_id) {
                        // look up from the routing table
                        found_enrs.push(enr);
                    } else {
                        warn!(
                            query.id = %query_id,
                            "ENR from FindNode query not present in query results"
                        );
                    }
                }
                if let QueryType::FindNode {
                    callback: Some(callback),
                    ..
                } = query_info.query_type
                {
                    if let Err(err) = callback.send(found_enrs.clone()) {
                        error!(
                            query.id = %query_id,
                            error = ?err,
                            "Error sending FindNode query result to callback",
                        );
                    }
                }
                trace!(
                    protocol = %self.protocol,
                    query.id = %query_id,
                    "Discovered {} ENRs via FindNode query",
                    found_enrs.len()
                );
            }
        }
    }

    /// Handles a `QueryEvent` from a poll on the find content query pool.
    fn handle_find_content_query_event(
        &mut self,
        query_event: QueryEvent<FindContentQuery<NodeId>, TContentKey>,
    ) {
        match query_event {
            QueryEvent::Waiting(query_id, node_id, request) => {
                if let Some(enr) = self.find_enr(&node_id) {
                    // If we find the node's ENR, then send the request on behalf of the
                    // query. No callback channel is necessary for the request, because the
                    // response will be incorporated into the query.
                    let request = OverlayRequest::new(
                        request,
                        RequestDirection::Outgoing { destination: enr },
                        None,
                        Some(query_id),
                    );
                    let _ = self.command_tx.send(OverlayCommand::Request(request));
                } else {
                    // If we cannot find the node's ENR, then we cannot contact the
                    // node, so fail the query for this node.
                    error!(
                        protocol = %self.protocol,
                        peer = %node_id,
                        query.id = %query_id,
                        "Cannot query peer with unknown ENR"
                    );
                    if let Some((_, query)) = self.find_node_query_pool.get_mut(query_id) {
                        query.on_failure(&node_id);
                    }
                }
            }
            QueryEvent::Finished(query_id, query_info, query)
            | QueryEvent::TimedOut(query_id, query_info, query) => {
                let result = query.into_result();
                let (content, closest_nodes) = match result {
                    FindContentQueryResult::ClosestNodes(closest_nodes) => (None, closest_nodes),
                    FindContentQueryResult::Content {
                        content,
                        closest_nodes,
                    } => (Some(content), closest_nodes),
                };

                if let QueryType::FindContent {
                    callback: Some(callback),
                    target: content_key,
                } = query_info.query_type
                {
                    let response = (content.clone(), query_info.trace);
                    // Send (possibly `None`) content on callback channel.
                    if let Err(err) = callback.send(response) {
                        error!(
                            query.id = %query_id,
                            error = ?err,
                            "Error sending FindContent query result to callback",
                        );
                    }

                    // If content was found, then offer the content to the closest nodes who did
                    // not possess the content.
                    if let Some(content) = content {
                        self.poke_content(content_key, content, closest_nodes);
                    }
                }
            }
        }
    }

    /// Submits outgoing requests to offer `content` to the closest known nodes whose radius
    /// contains `content_key`.
    fn poke_content(&self, content_key: TContentKey, content: Vec<u8>, closest_nodes: Vec<NodeId>) {
        let content_id = content_key.content_id();

        // Offer content to closest nodes with sufficient radius.
        for node_id in closest_nodes.iter() {
            // Look up node in the routing table. We need the ENR and the radius. If we can't find
            // the node, then move on to the next.
            let key = kbucket::Key::from(*node_id);
            let node = match self.kbuckets.write().entry(&key) {
                kbucket::Entry::Present(entry, _) => entry.value().clone(),
                kbucket::Entry::Pending(mut entry, _) => entry.value().clone(),
                _ => continue,
            };

            // If the content is within the node's radius, then offer the node the content.
            let is_within_radius =
                TMetric::distance(&node_id.raw(), &content_id) <= node.data_radius;
            if is_within_radius {
                let content_items = vec![(content_key.clone().into(), content.clone())];
                let offer_request = Request::PopulatedOffer(PopulatedOffer { content_items });

                let request = OverlayRequest::new(
                    offer_request,
                    RequestDirection::Outgoing {
                        destination: node.enr(),
                    },
                    None,
                    None,
                );

                if let Ok(..) = self.command_tx.send(OverlayCommand::Request(request)) {
                    trace!(
                        protocol = %self.protocol,
                        content.id = %hex_encode_compact(content_id),
                        content.key = %content_key,
                        peer.node_id = %node_id,
                        "Content poked"
                    );
                }
            }
        }
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
                self.register_node_activity(source);

                let response = self.handle_request(request.request.clone(), id.clone(), &source);
                // Send response to responder if present.
                if let Some(responder) = request.responder {
                    if let Ok(ref response) = response {
                        self.metrics
                            .report_outbound_response(&self.protocol, response);
                    }
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
                self.metrics
                    .report_outbound_request(&self.protocol, &request.request);
                self.send_talk_req(request.request, request.id, destination);
            }
        }
    }

    /// Attempts to build a response for a request.
    fn handle_request(
        &mut self,
        request: Request,
        id: RequestId,
        source: &NodeId,
    ) -> Result<Response, OverlayRequestError> {
        match request {
            Request::Ping(ping) => Ok(Response::Pong(self.handle_ping(ping, source, id))),
            Request::FindNodes(find_nodes) => Ok(Response::Nodes(
                self.handle_find_nodes(find_nodes, source, id),
            )),
            Request::FindContent(find_content) => Ok(Response::Content(self.handle_find_content(
                find_content,
                source,
                id,
            )?)),
            Request::Offer(offer) => Ok(Response::Accept(self.handle_offer(offer, source, id)?)),
            Request::PopulatedOffer(_) => Err(OverlayRequestError::InvalidRequest(
                "An offer with content attached is not a valid network message to receive"
                    .to_owned(),
            )),
        }
    }

    /// Builds a `Pong` response for a `Ping` request.
    fn handle_ping(&self, request: Ping, source: &NodeId, request_id: RequestId) -> Pong {
        trace!(
            protocol = %self.protocol,
            request.source = %source,
            request.discv5.id = %request_id,
            "Handling Ping message {}",
            request
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
    fn handle_find_nodes(
        &self,
        request: FindNodes,
        source: &NodeId,
        request_id: RequestId,
    ) -> Nodes {
        trace!(
            protocol = %self.protocol,
            request.source = %source,
            request.discv5.id = %request_id,
            "Handling FindNodes message",
        );

        let distances64: Vec<u64> = request.distances.iter().map(|x| (*x).into()).collect();
        let mut enrs = self.nodes_by_distance(distances64);

        // Limit the ENRs so that their summed sizes do not surpass the max TALKREQ packet size.
        pop_while_ssz_bytes_len_gt(&mut enrs, MAX_PORTAL_NODES_ENRS_SIZE);

        Nodes { total: 1, enrs }
    }

    /// Attempts to build a `Content` response for a `FindContent` request.
    fn handle_find_content(
        &self,
        request: FindContent,
        source: &NodeId,
        request_id: RequestId,
    ) -> Result<Content, OverlayRequestError> {
        trace!(
            protocol = %self.protocol,
            request.source = %source,
            request.discv5.id = %request_id,
            "Handling FindContent message",
        );

        let content_key = match (TContentKey::try_from)(request.content_key) {
            Ok(key) => key,
            Err(_) => {
                return Err(OverlayRequestError::InvalidRequest(
                    "Invalid content key".to_string(),
                ))
            }
        };
        match self.store.read().get(&content_key) {
            Ok(Some(content)) => {
                if content.len() <= MAX_PORTAL_CONTENT_PAYLOAD_SIZE {
                    Ok(Content::Content(content))
                } else {
                    // Generate a connection ID for the uTP connection.
                    let node_addr = self.discovery.cached_node_addr(source).ok_or_else(|| {
                        OverlayRequestError::AcceptError(
                            "unable to find ENR for NodeId".to_string(),
                        )
                    })?;
                    let enr = crate::discovery::UtpEnr(node_addr.enr);
                    let cid = self.utp_socket.cid(enr, false);
                    let cid_send = cid.send;

                    // Wait for an incoming connection with the given CID. Then, write the data
                    // over the uTP stream.
                    let utp = Arc::clone(&self.utp_socket);
                    tokio::spawn(async move {
                        let mut stream = match utp.accept_with_cid(cid.clone(), UTP_CONN_CFG).await
                        {
                            Ok(stream) => stream,
                            Err(err) => {
                                error!(
                                    %err,
                                    %cid.send,
                                    %cid.recv,
                                    peer = ?cid.peer.client(),
                                    "unable to accept uTP stream for CID"
                                );
                                return;
                            }
                        };

                        match stream.write(&content).await {
                            Ok(..) => {
                                debug!(
                                    %cid.send,
                                    %cid.recv,
                                    peer = ?cid.peer.client(),
                                    content_id = %hex_encode(content_key.content_id()),
                                    "wrote content to uTP stream"
                                );
                            }
                            Err(err) => {
                                error!(
                                    %cid.send,
                                    %cid.recv,
                                    peer = ?cid.peer.client(),
                                    %err,
                                    "error writing content to uTP stream"
                                );
                            }
                        }
                    });

                    // Connection id is send as BE because uTP header values are stored also as BE
                    Ok(Content::ConnectionId(cid_send.to_be()))
                }
            }
            Ok(None) => {
                let enrs = self.find_nodes_close_to_content(content_key);
                match enrs {
                    Ok(mut val) => {
                        pop_while_ssz_bytes_len_gt(&mut val, MAX_PORTAL_CONTENT_PAYLOAD_SIZE);
                        Ok(Content::Enrs(val))
                    }
                    Err(msg) => Err(OverlayRequestError::InvalidRequest(msg.to_string())),
                }
            }
            Err(msg) => Err(OverlayRequestError::Failure(format!(
                "Unable to respond to FindContent: {msg}",
            ))),
        }
    }

    /// Attempts to build an `Accept` response for an `Offer` request.
    fn handle_offer(
        &self,
        request: Offer,
        source: &NodeId,
        request_id: RequestId,
    ) -> Result<Accept, OverlayRequestError> {
        trace!(
            protocol = %self.protocol,
            request.source = %source,
            request.discv5.id = %request_id,
            "Handling Offer message",
        );

        let mut requested_keys =
            BitList::with_capacity(request.content_keys.len()).map_err(|_| {
                OverlayRequestError::AcceptError(
                    "Unable to initialize bitlist for requested keys.".to_owned(),
                )
            })?;

        let content_keys: Vec<TContentKey> = request
            .content_keys
            .into_iter()
            .map(|k| (TContentKey::try_from)(k))
            .collect::<Result<Vec<TContentKey>, _>>()
            .map_err(|_| {
                OverlayRequestError::AcceptError(
                    "Unable to build content key from OFFER request".to_owned(),
                )
            })?;

        for (i, key) in content_keys.iter().enumerate() {
            // Accept content if within radius and not already present in the data store.
            let accept = self
                .store
                .read()
                .is_key_within_radius_and_unavailable(key)
                .map_err(|err| {
                    OverlayRequestError::AcceptError(format!(
                        "Unable to check content availability {err}"
                    ))
                })?;
            requested_keys.set(i, accept).map_err(|err| {
                OverlayRequestError::AcceptError(format!(
                    "Unable to set requested keys bits: {err:?}"
                ))
            })?;
        }

        // If no content keys were accepted, then return an Accept with a connection ID value of
        // zero.
        if requested_keys.is_zero() {
            return Ok(Accept {
                connection_id: 0,
                content_keys: requested_keys,
            });
        }

        // Generate a connection ID for the uTP connection if there is data we would like to
        // accept.
        let node_addr = self.discovery.cached_node_addr(source).ok_or_else(|| {
            OverlayRequestError::AcceptError("unable to find ENR for NodeId".to_string())
        })?;
        let enr = crate::discovery::UtpEnr(node_addr.enr);
        let cid = self.utp_socket.cid(enr, false);
        let cid_send = cid.send;
        let validator = Arc::clone(&self.validator);
        let store = Arc::clone(&self.store);
        let kbuckets = Arc::clone(&self.kbuckets);
        let command_tx = self.command_tx.clone();
        let utp = Arc::clone(&self.utp_socket);

        tokio::spawn(async move {
            // Wait for an incoming connection with the given CID. Then, read the data from the uTP
            // stream.
            let mut stream = match utp.accept_with_cid(cid.clone(), UTP_CONN_CFG).await {
                Ok(stream) => stream,
                Err(err) => {
                    warn!(%err, cid.send, cid.recv, peer = ?cid.peer.client(), "unable to accept uTP stream");
                    return;
                }
            };

            let mut data = vec![];
            if let Err(err) = stream.read_to_eof(&mut data).await {
                error!(%err, cid.send, cid.recv, peer = ?cid.peer.client(), "error reading data from uTP stream");
                return;
            }

            if let Err(err) = Self::process_accept_utp_payload(
                validator,
                store,
                kbuckets,
                command_tx,
                content_keys,
                data,
            )
            .await
            {
                error!(%err, cid.send, cid.recv, peer = ?cid.peer.client(), "unable to process uTP payload");
            }
        });

        let accept = Accept {
            connection_id: cid_send.to_be(),
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
        self.metrics
            .report_inbound_request(&self.protocol, &request);
        if let Request::Ping(ping) = request {
            self.process_ping(ping, source);
        }
    }

    /// Register source NodeId activity in overlay routing table
    fn register_node_activity(&mut self, source: NodeId) {
        // Look up the node in the routing table.
        let key = kbucket::Key::from(source);
        let is_node_in_table = matches!(
            self.kbuckets.write().entry(&key),
            kbucket::Entry::Present(_, _) | kbucket::Entry::Pending(_, _)
        );

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
            // The node is not in the overlay routing table, so look for the node's ENR in the node
            // address cache. If an entry is found, then attempt to insert the node as a connected
            // peer.
            if let Some(node_addr) = self.discovery.cached_node_addr(&source) {
                // TODO: Decide default data radius, and define a constant.
                let node = Node {
                    enr: node_addr.enr,
                    data_radius: Distance::MAX,
                };
                self.connect_node(node, ConnectionDirection::Incoming);
            }
        }
    }

    /// Processes a ping request from some source node.
    fn process_ping(&self, ping: Ping, source: NodeId) {
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

            let data_radius: Distance = ping.custom_payload.into();
            if node.data_radius != data_radius {
                self.update_node_radius(node.enr(), data_radius);
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
            protocol = %self.protocol,
            request.id = %hex_encode_compact(request_id.to_be_bytes()),
            request.dest = %destination.node_id(),
            error = %error,
            "Request failed",
        );

        // Attempt to mark the node as disconnected.
        let node_id = destination.node_id();
        let _ = self.update_node_connection_state(node_id, ConnectionState::Disconnected);
        // Remove the node from the ping queue.
        self.peers_to_ping.remove(&node_id);
    }

    /// Processes a response to an outgoing request from some source node.
    fn process_response(
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
                let node = Node::new(source.clone(), Distance::MAX);
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
                        error!(
                            response.source = %source.node_id(),
                            "Content response associated with non-FindContent request"
                        );
                        return;
                    }
                };
                self.process_content(content, source, find_content_request, query_id)
            }
            Response::Accept(accept) => {
                if let Err(err) = self.process_accept(accept, source, request) {
                    error!(response.error = %err, "Error processing ACCEPT message")
                }
            }
        }
    }

    // Process ACCEPT response
    fn process_accept(&self, response: Accept, enr: Enr, offer: Request) -> anyhow::Result<Accept> {
        // Check that a valid triggering request was sent
        match &offer {
            Request::Offer(_) => {}
            Request::PopulatedOffer(_) => {}
            _ => {
                return Err(anyhow!("Invalid request message paired with ACCEPT"));
            }
        };

        // Do not initialize uTP stream if remote node doesn't have interest in the offered content keys
        if response.content_keys.is_zero() {
            return Ok(response);
        }

        // Build a connection ID based on the response.
        let conn_id = u16::from_be(response.connection_id);
        let cid = utp_rs::cid::ConnectionId {
            recv: conn_id,
            send: conn_id.wrapping_add(1),
            peer: crate::discovery::UtpEnr(enr),
        };

        let store = Arc::clone(&self.store);
        let response_clone = response.clone();

        let utp = Arc::clone(&self.utp_socket);
        tokio::spawn(async move {
            let mut stream = match utp.connect_with_cid(cid.clone(), UTP_CONN_CFG).await {
                Ok(stream) => stream,
                Err(err) => {
                    warn!(
                        %err,
                        cid.send,
                        cid.recv,
                        peer = ?cid.peer.client(),
                        "Unable to establish uTP conn based on Accept",
                    );
                    return;
                }
            };

            let content_items = match offer {
                Request::Offer(offer) => {
                    Self::provide_requested_content(store, &response_clone, offer.content_keys)
                }
                Request::PopulatedOffer(offer) => Ok(response_clone
                    .content_keys
                    .iter()
                    .zip(offer.content_items.into_iter())
                    .filter(|(is_accepted, _item)| *is_accepted)
                    .map(|(_is_accepted, (_key, val))| val)
                    .collect()),
                // Unreachable because of early return at top of method:
                _ => Err(anyhow!("Invalid request message paired with ACCEPT")),
            };

            let content_items: Vec<Bytes> = match content_items {
                Ok(items) => items
                    .into_iter()
                    .map(|item| Bytes::from(item.to_vec()))
                    .collect(),
                Err(err) => {
                    error!(
                        %err,
                        cid.send,
                        cid.recv,
                        peer = ?cid.peer.client(),
                        "Error decoding previously offered content items"
                    );
                    return;
                }
            };

            let content_payload = match portal_wire::encode_content_payload(&content_items) {
                Ok(payload) => payload,
                Err(err) => {
                    warn!(%err, "Unable to build content payload");
                    return;
                }
            };

            // send the content to the acceptor over a uTP stream
            if let Err(err) = stream.write(&content_payload).await {
                warn!(
                    %err,
                    cid.send,
                    cid.recv,
                    peer = ?cid.peer.client(),
                    "Error sending content over uTP connection"
                );
            }

            // close uTP connection
            if let Err(err) = stream.shutdown() {
                warn!(
                    %err,
                    cid.send,
                    cid.recv,
                    peer = ?cid.peer.client(),
                    "Error closing uTP connection"
                );
            };
        });

        Ok(response)
    }

    /// Process accepted uTP payload of the OFFER/ACCEPT stream
    async fn process_accept_utp_payload(
        validator: Arc<TValidator>,
        store: Arc<RwLock<TStore>>,
        kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
        command_tx: UnboundedSender<OverlayCommand<TContentKey>>,
        content_keys: Vec<TContentKey>,
        payload: Vec<u8>,
    ) -> anyhow::Result<()> {
        let content_values = portal_wire::decode_content_payload(payload)?;

        // Accepted content keys len should match content value len
        let keys_len = content_keys.len();
        let vals_len = content_values.len();
        if keys_len != vals_len {
            return Err(anyhow!(
                "Content keys len {keys_len} doesn't match content values len {vals_len}."
            ));
        }

        let handles: Vec<JoinHandle<_>> = content_keys
            .into_iter()
            .zip(content_values.to_vec())
            .map(|(key, content_value)| {
                // Spawn a task that...
                // - Validates accepted content (this step requires a dedicated task since it
                // might require non-blocking requests to this/other overlay networks)
                // - Checks if validated content should be stored, and stores it if true
                // - Propagate all validated content
                let validator = Arc::clone(&validator);
                let store = Arc::clone(&store);
                tokio::spawn(async move {
                    // Validated received content
                    if let Err(err) = validator
                        .validate_content(&key, &content_value.to_vec())
                        .await
                    {
                        // Skip storing & propagating content if it's not valid
                        warn!(
                            error = %err,
                            content.key = %key.to_hex(),
                            "Error validating accepted content"
                        );
                        return None;
                    }

                    // Check if data should be stored, and store if true.
                    let key_desired = store.read().is_key_within_radius_and_unavailable(&key);
                    match key_desired {
                        Ok(true) => {
                            if let Err(err) = store.write().put(key.clone(), &content_value) {
                                warn!(
                                    error = %err,
                                    content.key = %key.to_hex(),
                                    "Error storing accepted content"
                                );
                            }
                        }
                        Ok(false) => {
                            warn!(
                                content.key = %key.to_hex(),
                                "Accepted content outside radius or already stored"
                            );
                        }
                        Err(err) => {
                            warn!(
                                error = %err,
                                content.key = %key.to_hex(),
                                "Error checking data store for content key"
                            );
                        }
                    }
                    Some((key, content_value))
                })
            })
            .collect();
        let validated_content: Vec<(TContentKey, Vec<u8>)> = join_all(handles)
            .await
            .into_iter()
            // Whether the spawn fails or the content fails validation, we don't want it:
            .filter_map(|content| content.unwrap_or(None))
            .collect();
        // Propagate all validated content, whether or not it was stored.
        let validated_ids: Vec<String> = validated_content
            .iter()
            .map(|(k, _)| hex_encode_compact(k.content_id()))
            .collect();
        debug!(ids = ?validated_ids, "propagating validated content");
        propagate_gossip_cross_thread(validated_content, kbuckets, command_tx.clone());

        Ok(())
    }

    /// Processes a Pong response.
    ///
    /// Refreshes the node if necessary. Attempts to mark the node as connected.
    fn process_pong(&self, pong: Pong, source: Enr) {
        let node_id = source.node_id();
        trace!(
            protocol = %self.protocol,
            response.source = %node_id,
            "Processing Pong message {}", pong
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

            let data_radius: Distance = pong.custom_payload.into();
            if node.data_radius != data_radius {
                self.update_node_radius(source, data_radius);
            }
        }
    }

    /// Update the recorded radius of a node in our routing table.
    fn update_node_radius(&self, enr: Enr, data_radius: Distance) {
        let node_id = enr.node_id();
        let key = kbucket::Key::from(node_id);

        let updated_node = Node { enr, data_radius };

        if let UpdateResult::Failed(_) = self.kbuckets.write().update_node(&key, updated_node, None)
        {
            error!(
                "Failed to update radius of node {}",
                hex_encode_compact(node_id.raw())
            );
        };
    }

    /// Processes a Nodes response.
    fn process_nodes(&mut self, nodes: Nodes, source: Enr, query_id: Option<QueryId>) {
        trace!(
            protocol = %self.protocol,
            response.source = %source.node_id(),
            query.id = ?query_id,
            "Processing Nodes message",
        );

        let enrs: Vec<Enr> = nodes
            .enrs
            .into_iter()
            .map(|ssz_enr| ssz_enr.into())
            .collect();

        self.process_discovered_enrs(enrs.clone());
        if let Some(query_id) = query_id {
            self.advance_find_node_query(source, enrs, query_id);
        }
    }

    /// Processes a Content response.
    fn process_content(
        &mut self,
        content: Content,
        source: Enr,
        request: FindContent,
        query_id: Option<QueryId>,
    ) {
        trace!(
            protocol = %self.protocol,
            response.source = %source.node_id(),
            "Processing Content message",
        );
        match content {
            Content::ConnectionId(id) => debug!(
                protocol = %self.protocol,
                "Skipping processing for content connection ID {}",
                u16::from_be(id)
            ),
            Content::Content(content) => {
                self.process_received_content(content.clone(), request);
                // TODO: Should we only advance the query if the content has been validated?
                if let Some(query_id) = query_id {
                    self.advance_find_content_query_with_content(&query_id, source, content);
                }
            }
            Content::Enrs(enrs) => {
                let enrs: Vec<Enr> = enrs.into_iter().map(|ssz_enr| ssz_enr.into()).collect();
                self.process_discovered_enrs(enrs.clone());
                if let Some(query_id) = query_id {
                    self.advance_find_content_query_with_enrs(&query_id, source, enrs);
                }
            }
        }
    }

    fn process_received_content(&mut self, content: Vec<u8>, request: FindContent) {
        let content_key = match TContentKey::try_from(request.content_key) {
            Ok(val) => val,
            Err(msg) => {
                error!(
                    protocol = %self.protocol,
                    error = ?msg,
                    "Error decoding content key requested by local node"
                );
                return;
            }
        };
        let content_id = content_key.content_id();

        match self
            .store
            .read()
            .is_key_within_radius_and_unavailable(&content_key)
        {
            Ok(true) => {
                let validator = Arc::clone(&self.validator);
                let store = Arc::clone(&self.store);
                // Spawn task that validates content before storing.
                // Allows for non-blocking requests to this/other overlay services.
                tokio::spawn(async move {
                    if let Err(err) = validator.validate_content(&content_key, &content).await {
                        warn!(
                            error = ?err,
                            content.id = %hex_encode_compact(content_id),
                            content.key = %content_key,
                            "Error validating content"
                        );
                        return;
                    };

                    if let Err(err) = store.write().put(content_key.clone(), content) {
                        error!(
                            error = %err,
                            content.id = %hex_encode_compact(content_id),
                            content.key = %content_key,
                            "Error storing content"
                        );
                    }
                });
            }
            Ok(false) => {
                debug!(
                    content.id = %hex_encode_compact(content_id),
                    content.key = %content_key,
                    "Content not stored (key outside radius or already stored)"
                );
            }
            Err(err) => {
                error!(
                    error = %err,
                    content.id = %hex_encode_compact(content_id),
                    content.key = %content_key,
                    "Error storing content"
                );
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
                            peer = %node_id,
                            error = ?reason,
                            "Error updating entry for discovered node",
                        );
                    }
                }
            } else {
                let node = Node::new(enr, Distance::MAX);
                let status = NodeStatus {
                    state: ConnectionState::Disconnected,
                    direction: ConnectionDirection::Outgoing,
                };
                match kbuckets.insert_or_update(&key, node, status) {
                    InsertResult::Inserted => {
                        debug!(inserted = %node_id, "Inserted discovered node into routing table");
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
                    other => {
                        debug!(
                            peer = %node_id,
                            reason = ?other,
                            "Discovered node not inserted into routing table"
                        );
                    }
                }
            }
        }
    }

    /// Provide the requested content key and content value for the acceptor
    fn provide_requested_content(
        store: Arc<RwLock<TStore>>,
        accept_message: &Accept,
        content_keys_offered: Vec<RawContentKey>,
    ) -> anyhow::Result<Vec<Vec<u8>>> {
        let content_keys_offered: Result<Vec<TContentKey>, TContentKey::Error> =
            content_keys_offered
                .into_iter()
                .map(|key| TContentKey::try_from(key))
                .collect();

        let content_keys_offered: Vec<TContentKey> = content_keys_offered
            .map_err(|_| anyhow!("Unable to decode our own offered content keys"))?;

        let mut content_items: Vec<Vec<u8>> = Vec::new();

        for (i, key) in accept_message
            .content_keys
            .clone()
            .iter()
            .zip(content_keys_offered.iter())
        {
            if i {
                match store.read().get(key) {
                    Ok(content) => match content {
                        Some(content) => content_items.push(content),
                        None => return Err(anyhow!("Unable to read offered content!")),
                    },
                    Err(err) => {
                        return Err(anyhow!(
                            "Unable to get offered content from portal store: {err}"
                        ))
                    }
                }
            }
        }
        Ok(content_items)
    }

    /// Advances a find node query (if one is active for the node) using the received ENRs.
    /// Does nothing if called with a node_id that does not have a corresponding active query request.
    fn advance_find_node_query(&mut self, source: Enr, enrs: Vec<Enr>, query_id: QueryId) {
        // Check whether this request was sent on behalf of a query.
        // If so, advance the query with the returned data.
        let local_node_id = self.local_enr().node_id();
        if let Some((query_info, query)) = self.find_node_query_pool.get_mut(query_id) {
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
        }
    }

    /// Advances a find content query (if one exists for `query_id`) with ENRs close to content.
    fn advance_find_content_query_with_enrs(
        &mut self,
        query_id: &QueryId,
        source: Enr,
        enrs: Vec<Enr>,
    ) {
        let local_node_id = self.local_enr().node_id();
        if let Some((query_info, query)) = self.find_content_query_pool.get_mut(*query_id) {
            // If an ENR is not present in the query's untrusted ENRs, then add the ENR.
            // Ignore the local node's ENR.
            let mut new_enrs: Vec<&Enr> = vec![];
            for enr_ref in enrs.iter().filter(|enr| enr.node_id() != local_node_id) {
                if !query_info
                    .untrusted_enrs
                    .iter()
                    .any(|enr| enr.node_id() == enr_ref.node_id())
                {
                    query_info.untrusted_enrs.push(enr_ref.clone());

                    new_enrs.push(enr_ref);
                }
            }
            if let Some(trace) = &mut query_info.trace {
                trace.node_responded_with(&source, new_enrs);
            }
            let closest_nodes: Vec<NodeId> = enrs
                .iter()
                .filter(|enr| enr.node_id() != local_node_id)
                .map(|enr| enr.into())
                .collect();

            // Mark the query successful for the source of the response with the closest ENRs.
            query.on_success(
                &source.node_id(),
                FindContentQueryResponse::ClosestNodes(closest_nodes),
            );
        }
    }

    /// Advances a find content query (if one exists for `query_id`) with content.
    fn advance_find_content_query_with_content(
        &mut self,
        query_id: &QueryId,
        source: Enr,
        content: Vec<u8>,
    ) {
        if let Some((query_info, query)) = self.find_content_query_pool.get_mut(*query_id) {
            if let Some(trace) = &mut query_info.trace {
                trace.node_responded_with_content(&source);
            }
            // Mark the query successful for the source of the response with the content.
            query.on_success(
                &source.node_id(),
                FindContentQueryResponse::Content(content),
            );
        }
    }

    /// Submits a request to ping a destination (target) node.
    fn ping_node(&self, destination: &Enr) {
        trace!(
            protocol = %self.protocol,
            request.dest = %destination.node_id(),
            "Sending Ping message",
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
        let _ = self.command_tx.send(OverlayCommand::Request(request));
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
        let _ = self.command_tx.send(OverlayCommand::Request(request));
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
                    protocol = %self.protocol,
                    inserted = %node_id,
                    "Node inserted into routing table",
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
                        protocol = %self.protocol,
                        promoted = %node_id,
                        "Node promoted to connected",
                    );
                    self.peers_to_ping.insert(node_id);
                }
            }
            InsertResult::ValueUpdated | InsertResult::UpdatedPending => {}
            InsertResult::Failed(reason) => {
                self.peers_to_ping.remove(&node_id);
                debug!(
                    protocol = %self.protocol,
                    peer = %node_id,
                    error = ?reason,
                    "Error inserting/updating node into routing table",
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
                FailureReason::KeyNonExistent => Err(FailureReason::KeyNonExistent),
                other => {
                    warn!(
                        protocol = %self.protocol,
                        peer = %node_id,
                        error = ?other,
                        "Error updating node connection state",
                    );

                    Err(other)
                }
            },
            _ => {
                trace!(
                    protocol = %self.protocol,
                    updated = %node_id,
                    updated.conn_state = ?state,
                    "Node connection state updated",
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
            .map(|entry| entry.node.value.enr())
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
                .nodes_by_distances(log2_distances, FIND_NODES_MAX_NODES)
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

        let mut nodes_with_distance: Vec<(Distance, Enr)> = self
            .table_entries_enr()
            .into_iter()
            .map(|enr| (TMetric::distance(&content_id, &enr.node_id().raw()), enr))
            .collect();

        nodes_with_distance.sort_by(|a, b| a.0.cmp(&b.0));

        let closest_nodes = nodes_with_distance
            .into_iter()
            .take(FIND_CONTENT_MAX_NODES)
            .filter(|node_record| node_record.0 < self_distance)
            .map(|node_record| SszEnr::new(node_record.1))
            .collect();

        Ok(closest_nodes)
    }

    /// Starts a FindNode query to find nodes with IDs closest to `target`.
    fn init_find_nodes_query(
        &mut self,
        target: &NodeId,
        callback: Option<oneshot::Sender<Vec<Enr>>>,
    ) -> Option<QueryId> {
        let target_key = Key::from(*target);
        let mut closest_enrs: Vec<Enr> = self
            .kbuckets
            .write()
            .closest_values(&target_key)
            .map(|closest| closest.value.enr)
            .collect();

        // `closest_enrs` will be empty if `target` is our local node ID
        // due to the behavior of `closest_values`. In this case, set closest_enrs
        // to be all ENRs in routing table.
        if closest_enrs.is_empty() {
            let mut all_enrs: Vec<Enr> = self.table_entries_enr();
            closest_enrs.append(&mut all_enrs);
        }

        let query_config = QueryConfig {
            parallelism: self.query_parallelism,
            num_results: self.query_num_results,
            peer_timeout: self.query_peer_timeout,
        };

        let query_info = QueryInfo {
            query_type: QueryType::FindNode {
                target: *target,
                distances_to_request: self.findnodes_query_distances_per_peer,
                callback,
            },
            untrusted_enrs: SmallVec::from_vec(closest_enrs),
            trace: None,
        };

        let known_closest_peers: Vec<Key<NodeId>> = query_info
            .untrusted_enrs
            .iter()
            .map(|enr| Key::from(enr.node_id()))
            .collect();

        if known_closest_peers.is_empty() {
            warn!("Cannot initialize FindNode query (no known close peers)");
            None
        } else {
            let find_nodes_query =
                FindNodeQuery::with_config(query_config, query_info.key(), known_closest_peers);
            Some(
                self.find_node_query_pool
                    .add_query(query_info, find_nodes_query),
            )
        }
    }

    /// Starts a `FindContentQuery` for a target content key.
    fn init_find_content_query(
        &mut self,
        target: TContentKey,
        callback: Option<oneshot::Sender<FindContentResult>>,
        is_trace: bool,
    ) -> Option<QueryId> {
        info!("Starting query for content key: {}", target);

        // Represent the target content ID with a node ID.
        let target_node_id = NodeId::new(&target.content_id());
        let target_key = Key::from(target_node_id);

        let query_config = QueryConfig {
            parallelism: self.query_parallelism,
            num_results: self.query_num_results,
            peer_timeout: self.query_peer_timeout,
        };

        // Look up the closest ENRs to the target.
        // Limit the number of ENRs according to the query config.
        let closest_enrs: Vec<Enr> = self
            .kbuckets
            .write()
            .closest_values(&target_key)
            .map(|closest| closest.value.enr)
            .take(query_config.num_results)
            .collect();

        let trace: Option<QueryTrace> = {
            if is_trace {
                let mut trace = QueryTrace::new(&self.local_enr(), target_node_id.into());
                let local_enr = self.local_enr();
                trace.node_responded_with(&local_enr, closest_enrs.iter().collect());
                Some(trace)
            } else {
                None
            }
        };

        let query_info = QueryInfo {
            query_type: QueryType::FindContent { target, callback },
            untrusted_enrs: SmallVec::from_vec(closest_enrs),
            trace,
        };

        // Convert ENRs into k-bucket keys.
        let closest_enrs: Vec<Key<NodeId>> = query_info
            .untrusted_enrs
            .iter()
            .map(|enr| Key::from(enr.node_id()))
            .collect();

        // If the initial set of peers is non-empty, then add the query to the query pool.
        // Otherwise, there is no way for the query to progress, so drop it.
        if closest_enrs.is_empty() {
            warn!("Cannot initialize FindContent query (no known close peers)");
            None
        } else {
            let query = FindContentQuery::with_config(query_config, target_key, closest_enrs);
            Some(self.find_content_query_pool.add_query(query_info, query))
        }
    }

    /// Returns an ENR if one is known for the given NodeId.
    pub fn find_enr(&self, node_id: &NodeId) -> Option<Enr> {
        // Check whether we know this node id in our routing table.
        let key = kbucket::Key::from(*node_id);
        if let kbucket::Entry::Present(entry, _) = self.kbuckets.write().entry(&key) {
            return Some(entry.value().clone().enr());
        }

        // Check the existing find node queries for the ENR.
        for (query_info, _) in self.find_node_query_pool.iter() {
            if let Some(enr) = query_info
                .untrusted_enrs
                .iter()
                .find(|v| v.node_id() == *node_id)
            {
                return Some(enr.clone());
            }
        }

        // Check the existing find content queries for the ENR.
        for (query_info, _) in self.find_content_query_pool.iter() {
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
}

// Propagate gossip in a way that can be used across threads, without &self
pub fn propagate_gossip_cross_thread<TContentKey: OverlayContentKey>(
    content: Vec<(TContentKey, Vec<u8>)>,
    kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
    command_tx: mpsc::UnboundedSender<OverlayCommand<TContentKey>>,
) -> usize {
    // Get all connected nodes from overlay routing table
    let kbuckets = kbuckets.read();
    let all_nodes: Vec<&kbucket::Node<NodeId, Node>> = kbuckets
        .buckets_iter()
        .flat_map(|kbucket| {
            kbucket
                .iter()
                .filter(|node| node.status.is_connected())
                .collect::<Vec<&kbucket::Node<NodeId, Node>>>()
        })
        .collect();

    // HashMap to temporarily store all interested ENRs and the content.
    // Key is base64 string of node's ENR.
    let mut enrs_and_content: HashMap<String, Vec<(RawContentKey, Vec<u8>)>> = HashMap::new();

    // Filter all nodes from overlay routing table where XOR_distance(content_id, nodeId) < node radius
    for (content_key, content_value) in content {
        let mut interested_enrs: Vec<Enr> = all_nodes
            .clone()
            .into_iter()
            .filter(|node| {
                XorMetric::distance(&content_key.content_id(), &node.key.preimage().raw())
                    < node.value.data_radius()
            })
            .map(|node| node.value.enr())
            .collect();

        // Continue if no nodes are interested in the content
        if interested_enrs.is_empty() {
            debug!(
                content.id = %hex_encode(content_key.content_id()),
                kbuckets.len = all_nodes.len(),
                "No peers eligible for neighborhood gossip"
            );
            continue;
        }

        // Sort all eligible nodes by proximity to the content.
        interested_enrs.sort_by(|a, b| {
            let distance_a = XorMetric::distance(&content_key.content_id(), &a.node_id().raw());
            let distance_b = XorMetric::distance(&content_key.content_id(), &b.node_id().raw());
            distance_a.partial_cmp(&distance_b).unwrap_or_else(|| {
                warn!(a = %distance_a, b = %distance_b, "Error comparing two distances");
                std::cmp::Ordering::Less
            })
        });

        let gossip_recipients = select_gossip_recipients(interested_enrs);

        // Temporarily store all randomly selected nodes with the content of interest.
        // We want this so we can offer all the content to interested node in one request.
        let raw_item = (content_key.into(), content_value);
        for enr in gossip_recipients {
            enrs_and_content
                .entry(enr.to_base64())
                .or_default()
                .push(raw_item.clone());
        }
    }

    let num_propagated_peers = enrs_and_content.len();
    // Create and send OFFER overlay request to the interested nodes
    for (enr_string, interested_content) in enrs_and_content.into_iter() {
        let enr = match Enr::from_str(&enr_string) {
            Ok(enr) => enr,
            Err(err) => {
                error!(error = %err, enr.base64 = %enr_string, "Error decoding ENR from base-64");
                continue;
            }
        };

        let offer_request = Request::PopulatedOffer(PopulatedOffer {
            content_items: interested_content,
        });

        let overlay_request = OverlayRequest::new(
            offer_request,
            RequestDirection::Outgoing { destination: enr },
            None,
            None,
        );

        if let Err(err) = command_tx.send(OverlayCommand::Request(overlay_request)) {
            error!(error = %err, "Error sending OFFER message to service")
        }
    }

    num_propagated_peers
}

/// Randomly select `num_enrs` nodes from `enrs`.
fn select_random_enrs(num_enrs: usize, enrs: Vec<Enr>) -> Vec<Enr> {
    let random_enrs: Vec<Enr> = enrs
        .into_iter()
        .choose_multiple(&mut rand::thread_rng(), num_enrs);
    random_enrs
}

const NUM_CLOSEST_NODES: usize = 4;
const NUM_FARTHER_NODES: usize = 4;
/// Selects gossip recipients from a vec of sorted interested ENRs.
/// Returned vec is a concatenation of, at most:
/// 1. First `NUM_CLOSEST_NODES` elements of `interested_sorted_enrs`.
/// 2. `NUM_FARTHER_NODES` elements randomly selected from `interested_sorted_enrs[NUM_CLOSEST_NODES..]`
fn select_gossip_recipients(interested_sorted_enrs: Vec<Enr>) -> Vec<Enr> {
    let mut gossip_recipients: Vec<Enr> = vec![];

    // Get first n closest nodes
    gossip_recipients.extend(
        interested_sorted_enrs
            .clone()
            .into_iter()
            .take(NUM_CLOSEST_NODES),
    );
    if interested_sorted_enrs.len() > NUM_CLOSEST_NODES {
        let farther_enrs = interested_sorted_enrs[NUM_CLOSEST_NODES..].to_vec();
        // Get random non-close ENRs to gossip to.
        let random_farther_enrs = select_random_enrs(NUM_FARTHER_NODES, farther_enrs);
        gossip_recipients.extend(random_farther_enrs);
    }
    gossip_recipients
}

/// The result of the `query_event_poll` indicating an action is required to further progress an
/// active query.
pub enum QueryEvent<TQuery, TContentKey> {
    /// The query is waiting for a peer to be contacted.
    Waiting(QueryId, NodeId, Request),
    /// The query has timed out, possible returning peers.
    TimedOut(QueryId, QueryInfo<TContentKey>, TQuery),
    /// The query has completed successfully.
    Finished(QueryId, QueryInfo<TContentKey>, TQuery),
}

/// Limits a to a maximum packet size, including the discv5 header overhead.
fn pop_while_ssz_bytes_len_gt(enrs: &mut Vec<SszEnr>, max_size: usize) {
    while enrs.ssz_bytes_len() > max_size {
        enrs.pop();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    use std::time::Instant;

    use rstest::rstest;

    use crate::{
        discovery::Discovery,
        overlay::OverlayConfig,
        storage::{DistanceFunction, MemoryContentStore},
        types::messages::PortalnetConfig,
    };

    use ethportal_api::trin_types::content_key::IdentityContentKey;
    use ethportal_api::trin_types::distance::XorMetric;
    use ethportal_api::trin_types::enr::generate_random_remote_enr;
    use trin_validation::validator::MockValidator;

    use discv5::kbucket::Entry;
    use ethereum_types::U256;
    use serial_test::serial;
    use tokio::sync::mpsc::unbounded_channel;
    use tokio_test::{assert_pending, assert_ready, task};

    macro_rules! poll_command_rx {
        ($service:ident) => {
            $service.enter(|cx, mut service| service.command_rx.poll_recv(cx))
        };
    }

    fn build_service(
    ) -> OverlayService<IdentityContentKey, XorMetric, MockValidator, MemoryContentStore> {
        let portal_config = PortalnetConfig {
            no_stun: true,
            ..Default::default()
        };
        let discovery = Arc::new(Discovery::new(portal_config).unwrap());

        let (_utp_talk_req_tx, utp_talk_req_rx) = unbounded_channel();
        let discv5_utp =
            crate::discovery::Discv5UdpSocket::new(Arc::clone(&discovery), utp_talk_req_rx);
        let utp_socket = utp_rs::socket::UtpSocket::with_socket(discv5_utp);
        let utp_socket = Arc::new(utp_socket);

        let node_id = discovery.local_enr().node_id();
        let store = MemoryContentStore::new(node_id, DistanceFunction::Xor);
        let store = Arc::new(RwLock::new(store));

        let overlay_config = OverlayConfig::default();
        let kbuckets = Arc::new(RwLock::new(KBucketsTable::new(
            discovery.local_enr().node_id().into(),
            overlay_config.bucket_pending_timeout,
            overlay_config.max_incoming_per_bucket,
            overlay_config.table_filter,
            overlay_config.bucket_filter,
        )));

        let protocol = ProtocolId::History;
        let active_outgoing_requests = Arc::new(RwLock::new(HashMap::new()));
        let peers_to_ping = HashSetDelay::default();
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (response_tx, response_rx) = mpsc::unbounded_channel();
        let metrics = Arc::new(OverlayMetrics::new());
        let validator = Arc::new(MockValidator {});

        OverlayService {
            discovery,
            utp_socket,
            store,
            kbuckets,
            protocol,
            peers_to_ping,
            command_tx,
            command_rx,
            active_outgoing_requests,
            find_node_query_pool: QueryPool::new(overlay_config.query_timeout),
            find_content_query_pool: QueryPool::new(overlay_config.query_timeout),
            query_peer_timeout: overlay_config.query_peer_timeout,
            query_parallelism: overlay_config.query_parallelism,
            query_num_results: overlay_config.query_num_results,
            findnodes_query_distances_per_peer: overlay_config.findnodes_query_distances_per_peer,
            response_tx,
            response_rx,
            phantom_content_key: PhantomData,
            phantom_metric: PhantomData,
            metrics,
            validator,
        }
    }

    #[test_log::test(tokio::test)]
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

        let data_radius = Distance::MAX;
        let node = Node::new(source.clone(), data_radius);

        let _ = service
            .kbuckets
            .write()
            .insert_or_update(&key, node, status);

        let ping = Ping {
            enr_seq: source.seq() + 1,
            custom_payload: CustomPayload::from(data_radius.as_ssz_bytes()),
        };

        service.process_ping(ping, node_id);

        let command = assert_ready!(poll_command_rx!(service));
        assert!(command.is_some());

        let command = command.unwrap();
        let request = if let OverlayCommand::Request(request) = command {
            request
        } else {
            panic!("Unexpected overlay command variant");
        };

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

    #[test_log::test(tokio::test)]
    #[serial]
    async fn process_ping_source_not_in_table() {
        let mut service = task::spawn(build_service());

        let (_, source) = generate_random_remote_enr();
        let node_id = source.node_id();
        let data_radius = Distance::MAX;

        let ping = Ping {
            enr_seq: source.seq(),
            custom_payload: CustomPayload::from(data_radius.as_ssz_bytes()),
        };

        service.process_ping(ping, node_id);

        assert_pending!(poll_command_rx!(service));
    }

    #[test_log::test(tokio::test)]
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

        let node = Node::new(destination.clone(), Distance::MAX);

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
        service.process_request_failure(request_id, destination, error);

        assert!(!service.peers_to_ping.contains_key(&node_id));

        match service.kbuckets.write().entry(&key) {
            kbucket::Entry::Present(_entry, status) => {
                assert_eq!(ConnectionState::Disconnected, status.state)
            }
            _ => panic!(),
        };
    }

    #[test_log::test(tokio::test)]
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

        let data_radius = Distance::MAX;
        let node = Node::new(source.clone(), data_radius);

        let _ = service
            .kbuckets
            .write()
            .insert_or_update(&key, node, status);

        let pong = Pong {
            enr_seq: source.seq() + 1,
            custom_payload: CustomPayload::from(data_radius.as_ssz_bytes()),
        };

        service.process_pong(pong, source.clone());

        let command = assert_ready!(poll_command_rx!(service));
        assert!(command.is_some());

        let command = command.unwrap();
        let request = if let OverlayCommand::Request(request) = command {
            request
        } else {
            panic!("Unexpected overlay command variant");
        };

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

    #[test_log::test(tokio::test)]
    #[serial]
    async fn process_pong_source_not_in_table() {
        let mut service = task::spawn(build_service());

        let (_, source) = generate_random_remote_enr();
        let data_radius = Distance::MAX;

        let pong = Pong {
            enr_seq: source.seq(),
            custom_payload: CustomPayload::from(data_radius.as_ssz_bytes()),
        };

        service.process_pong(pong, source);

        assert_pending!(poll_command_rx!(service));
    }

    #[test_log::test(tokio::test)]
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

    #[test_log::test(tokio::test)]
    #[serial]
    async fn process_discovered_enrs_unknown_enrs() {
        let mut service = task::spawn(build_service());

        // Generate random ENRs to simulate.
        let (_, enr1) = generate_random_remote_enr();
        let (_, enr2) = generate_random_remote_enr();

        let enrs: Vec<Enr> = vec![enr1.clone(), enr2.clone()];
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

    #[test_log::test(tokio::test)]
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
        let data_radius = Distance::MAX;

        let node1 = Node::new(enr1.clone(), data_radius);
        let node2 = Node::new(enr2.clone(), data_radius);

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

        let enrs: Vec<Enr> = vec![enr1, enr2];
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

    #[test_log::test(tokio::test)]
    #[serial]
    async fn poke_content() {
        let mut service = task::spawn(build_service());

        let content_key = IdentityContentKey::new(service.local_enr().node_id().raw());
        let content = vec![0xef];

        let status = NodeStatus {
            state: ConnectionState::Connected,
            direction: ConnectionDirection::Outgoing,
        };

        let (_, enr) = generate_random_remote_enr();
        let key = kbucket::Key::from(enr.node_id());
        let peer = Node {
            enr,
            data_radius: Distance::MAX,
        };
        let _ = service
            .kbuckets
            .write()
            .insert_or_update(&key, peer.clone(), status);

        let peer_node_ids: Vec<NodeId> = vec![peer.enr.node_id()];

        // Node has maximum radius, so there should be one offer in the channel.
        service.poke_content(content_key, content, peer_node_ids);
        let cmd = assert_ready!(poll_command_rx!(service));
        let cmd = cmd.unwrap();
        if let OverlayCommand::Request(req) = cmd {
            assert!(matches!(req.request, Request::PopulatedOffer { .. }));
            assert_eq!(
                RequestDirection::Outgoing {
                    destination: peer.enr()
                },
                req.direction
            );
        } else {
            panic!("Unexpected overlay command variant");
        }
        assert_pending!(poll_command_rx!(service));
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn poke_content_unknown_peers() {
        let mut service = task::spawn(build_service());

        let content_key = IdentityContentKey::new(service.local_enr().node_id().raw());
        let content = vec![0xef];

        let (_, enr1) = generate_random_remote_enr();
        let (_, enr2) = generate_random_remote_enr();
        let peers = vec![enr1, enr2];
        let peer_node_ids: Vec<NodeId> = peers.iter().map(|p| p.node_id()).collect();

        // No nodes in the routing table, so no commands should be in the channel.
        service.poke_content(content_key, content, peer_node_ids);
        assert_pending!(poll_command_rx!(service));
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn poke_content_peers_with_sufficient_radius() {
        let mut service = task::spawn(build_service());

        let content_key = IdentityContentKey::new(service.local_enr().node_id().raw());
        let content = vec![0xef];

        let status = NodeStatus {
            state: ConnectionState::Connected,
            direction: ConnectionDirection::Outgoing,
        };

        // The first node has a maximum radius, so the content SHOULD be offered.
        let (_, enr1) = generate_random_remote_enr();
        let key1 = kbucket::Key::from(enr1.node_id());
        let peer1 = Node {
            enr: enr1,
            data_radius: Distance::MAX,
        };
        let _ = service
            .kbuckets
            .write()
            .insert_or_update(&key1, peer1.clone(), status);

        // The second node has a radius of zero, so the content SHOULD NOT not be offered.
        let (_, enr2) = generate_random_remote_enr();
        let key2 = kbucket::Key::from(enr2.node_id());
        let peer2 = Node {
            enr: enr2,
            data_radius: Distance::from(U256::zero()),
        };
        let _ = service
            .kbuckets
            .write()
            .insert_or_update(&key2, peer2.clone(), status);

        let peers = vec![peer1.clone(), peer2];
        let peer_node_ids: Vec<NodeId> = peers.iter().map(|p| p.enr.node_id()).collect();

        // One offer should be in the channel for the maximum radius node.
        service.poke_content(content_key, content, peer_node_ids);
        let cmd = assert_ready!(poll_command_rx!(service));
        let cmd = cmd.unwrap();
        if let OverlayCommand::Request(req) = cmd {
            assert!(matches!(req.request, Request::PopulatedOffer { .. }));
            assert_eq!(
                RequestDirection::Outgoing {
                    destination: peer1.enr()
                },
                req.direction
            );
        } else {
            panic!("Unexpected overlay command variant");
        }
        assert_pending!(poll_command_rx!(service));
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn request_node() {
        let mut service = task::spawn(build_service());

        let (_, destination) = generate_random_remote_enr();
        service.request_node(&destination);

        let command = assert_ready!(poll_command_rx!(service));
        assert!(command.is_some());

        let command = command.unwrap();
        let request = if let OverlayCommand::Request(request) = command {
            request
        } else {
            panic!("Unexpected overlay command variant");
        };

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

    #[test_log::test(tokio::test)]
    #[serial]
    async fn ping_node() {
        let mut service = task::spawn(build_service());

        let (_, destination) = generate_random_remote_enr();
        service.ping_node(&destination);

        let command = assert_ready!(poll_command_rx!(service));
        assert!(command.is_some());

        let command = command.unwrap();
        let request = if let OverlayCommand::Request(request) = command {
            request
        } else {
            panic!("Unexpected overlay command variant");
        };

        assert!(request.responder.is_none());

        assert_eq!(
            RequestDirection::Outgoing { destination },
            request.direction
        );

        assert!(matches!(request.request, Request::Ping { .. }));
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn connect_node() {
        let mut service = task::spawn(build_service());

        let (_, enr) = generate_random_remote_enr();
        let node_id = enr.node_id();
        let key = kbucket::Key::from(node_id);

        let data_radius = Distance::MAX;
        let node = Node::new(enr, data_radius);
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

    #[test_log::test(tokio::test)]
    #[serial]
    async fn update_node_connection_state_disconnected_to_connected() {
        let mut service = task::spawn(build_service());

        let (_, enr) = generate_random_remote_enr();
        let node_id = enr.node_id();
        let key = kbucket::Key::from(node_id);

        let data_radius = Distance::MAX;
        let node = Node::new(enr, data_radius);

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

    #[test_log::test(tokio::test)]
    #[serial]
    async fn update_node_connection_state_connected_to_disconnected() {
        let mut service = task::spawn(build_service());

        let (_, enr) = generate_random_remote_enr();
        let node_id = enr.node_id();
        let key = kbucket::Key::from(node_id);

        let data_radius = Distance::MAX;
        let node = Node::new(enr, data_radius);

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

        pop_while_ssz_bytes_len_gt(&mut enrs, MAX_PORTAL_NODES_ENRS_SIZE);

        assert_eq!(enrs.len(), correct_limited_size);
    }

    #[test_log::test(tokio::test)]
    async fn test_init_find_nodes_query() {
        let mut service = task::spawn(build_service());

        let (_, bootnode1) = generate_random_remote_enr();
        let (_, bootnode2) = generate_random_remote_enr();
        let bootnodes = vec![bootnode1.clone(), bootnode2.clone()];

        let (_, target_enr) = generate_random_remote_enr();
        let target_node_id = target_enr.node_id();

        assert_eq!(service.find_node_query_pool.iter().count(), 0);

        service.add_bootnodes(bootnodes);

        // Initialize the query and call `poll` so that it starts
        service.init_find_nodes_query(&target_node_id, None);
        let _ = service.find_node_query_pool.poll();

        let (query_info, query) = service.find_node_query_pool.iter().next().unwrap();

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

    #[test_log::test(tokio::test)]
    async fn test_advance_findnodes_query() {
        let mut service = build_service();

        let (_, bootnode) = generate_random_remote_enr();
        let bootnodes = vec![bootnode.clone()];
        let bootnode_node_id = bootnode.node_id();

        let (_, target_enr) = generate_random_remote_enr();
        let target_node_id = target_enr.node_id();

        service.add_bootnodes(bootnodes);
        service.query_num_results = 3;
        service.init_find_nodes_query(&target_node_id, None);

        // Test that the first query event contains a proper query ID and request to the bootnode
        let event = OverlayService::<
            IdentityContentKey,
            XorMetric,
            MockValidator,
            MemoryContentStore,
        >::query_event_poll(&mut service.find_node_query_pool)
        .await;
        match event {
            QueryEvent::Waiting(query_id, node_id, request) => {
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

        service.advance_find_node_query(
            bootnode.clone(),
            vec![enr1.clone(), enr2.clone()],
            QueryId(0),
        );

        let event = OverlayService::<
            IdentityContentKey,
            XorMetric,
            MockValidator,
            MemoryContentStore,
        >::query_event_poll(&mut service.find_node_query_pool)
        .await;

        // Check that the request is being sent to either node 1 or node 2. Keep track of which.
        let first_node_id: Option<NodeId> = match event {
            QueryEvent::Waiting(_, node_id, _) => {
                assert!((node_id == node_id_1) || (node_id == node_id_2));
                Some(node_id)
            }
            _ => panic!(),
        };

        let event = OverlayService::<
            IdentityContentKey,
            XorMetric,
            MockValidator,
            MemoryContentStore,
        >::query_event_poll(&mut service.find_node_query_pool)
        .await;

        // Check that a request is being sent to the other node.
        let second_node_id = if first_node_id.unwrap() == node_id_1 {
            node_id_2
        } else {
            node_id_1
        };
        match event {
            QueryEvent::Waiting(_, node_id, _) => {
                assert_eq!(node_id, second_node_id);
            }
            _ => panic!(),
        };

        service.advance_find_node_query(enr1.clone(), vec![enr2.clone()], QueryId(0));
        service.advance_find_node_query(enr2.clone(), vec![enr1.clone()], QueryId(0));

        let event = OverlayService::<
            IdentityContentKey,
            XorMetric,
            MockValidator,
            MemoryContentStore,
        >::query_event_poll(&mut service.find_node_query_pool)
        .await;

        match event {
            QueryEvent::Finished(query_id, query_info, query) => {
                assert_eq!(query_id, QueryId(0));
                let results = query.into_result();

                assert_eq!(results.len(), 3);

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

    #[test_log::test(tokio::test)]
    async fn test_find_enrs() {
        let mut service = task::spawn(build_service());

        let (_, bootnode) = generate_random_remote_enr();
        let bootnodes = vec![bootnode.clone()];
        let bootnode_node_id = bootnode.node_id();

        let (_, target_enr) = generate_random_remote_enr();
        let target_node_id = target_enr.node_id();

        service.add_bootnodes(bootnodes);

        service.init_find_nodes_query(&target_node_id, None);

        let _event = OverlayService::<
            IdentityContentKey,
            XorMetric,
            MockValidator,
            MemoryContentStore,
        >::query_event_poll(&mut service.find_node_query_pool)
        .await;

        let (_, enr1) = generate_random_remote_enr();
        let (_, enr2) = generate_random_remote_enr();
        let node_id_1 = enr1.node_id();
        let node_id_2 = enr2.node_id();

        service.advance_find_node_query(
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

    #[tokio::test]
    async fn init_find_content_query() {
        let mut service = task::spawn(build_service());

        let (_, bootnode_enr) = generate_random_remote_enr();
        let bootnode_node_id = bootnode_enr.node_id();
        let bootnode_key = kbucket::Key::from(bootnode_node_id);

        let data_radius = Distance::MAX;
        let bootnode = Node {
            enr: bootnode_enr.clone(),
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
            .insert_or_update(&bootnode_key, bootnode, status);

        let target_content = NodeId::random();
        let target_content_key = IdentityContentKey::new(target_content.raw());

        let query_id = service.init_find_content_query(target_content_key.clone(), None, false);
        let query_id = query_id.expect("Query ID for new find content query is `None`");

        let (query_info, query) = service
            .find_content_query_pool
            .get_mut(query_id)
            .expect("Query pool does not contain query");

        // Query info should contain the corresponding target content key.
        assert!(matches!(
            &query_info.query_type,
            QueryType::FindContent {
                target: _target_content_key,
                callback: None,
            }
        ));

        // Query target should be the key of the target content ID.
        let target_key = kbucket::Key::from(NodeId::new(&target_content_key.content_id()));
        assert_eq!(query.target(), target_key);

        // Query info should contain bootnode ENR. It is the only node in the routing table, so
        // it is among the "closest".
        assert!(query_info.untrusted_enrs.contains(&bootnode_enr));
    }

    #[tokio::test]
    async fn advance_find_content_query_with_enrs() {
        let mut service = task::spawn(build_service());

        let (_, bootnode_enr) = generate_random_remote_enr();
        let bootnode_node_id = bootnode_enr.node_id();
        let bootnode_key = kbucket::Key::from(bootnode_node_id);

        let data_radius = Distance::MAX;
        let bootnode = Node {
            enr: bootnode_enr.clone(),
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
            .insert_or_update(&bootnode_key, bootnode, status);

        let target_content = NodeId::random();
        let target_content_key = IdentityContentKey::new(target_content.raw());

        let query_id = service.init_find_content_query(target_content_key, None, false);
        let query_id = query_id.expect("Query ID for new find content query is `None`");

        let (_, query) = service
            .find_content_query_pool
            .get_mut(query_id)
            .expect("Query pool does not contain query");

        // Poll query to put into waiting state. Otherwise, `on_success` has no effect on the
        // query.
        query.poll(Instant::now());

        // Simulate a response from the bootnode.
        let (_, enr) = generate_random_remote_enr();
        service.advance_find_content_query_with_enrs(
            &query_id,
            bootnode_enr.clone(),
            vec![enr.clone()],
        );

        let (query_info, query) = service
            .find_content_query_pool
            .get_mut(query_id)
            .expect("Query pool does not contain query");

        // Query info should contain the "discovered" ENR.
        assert!(query_info.untrusted_enrs.contains(&enr));

        // Query result should contain bootnode who responded successfully.
        match query.clone().into_result() {
            FindContentQueryResult::ClosestNodes(closest_nodes) => {
                assert!(closest_nodes.contains(&bootnode_enr.node_id()));
            }
            _ => panic!("Unexpected find content query result"),
        }
    }

    #[tokio::test]
    async fn advance_find_content_query_with_content() {
        let mut service = task::spawn(build_service());

        let (_, bootnode_enr) = generate_random_remote_enr();
        let bootnode_node_id = bootnode_enr.node_id();
        let bootnode_key = kbucket::Key::from(bootnode_node_id);

        let data_radius = Distance::MAX;
        let bootnode = Node {
            enr: bootnode_enr.clone(),
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
            .insert_or_update(&bootnode_key, bootnode, status);

        let target_content = NodeId::random();
        let target_content_key = IdentityContentKey::new(target_content.raw());

        let query_id = service.init_find_content_query(target_content_key, None, false);
        let query_id = query_id.expect("Query ID for new find content query is `None`");

        let (_, query) = service
            .find_content_query_pool
            .get_mut(query_id)
            .expect("Query pool does not contain query");

        // Poll query to put into waiting state. Otherwise, `on_success` has no effect on the
        // query.
        query.poll(Instant::now());

        // Simulate a response from the bootnode.
        let content: Vec<u8> = vec![0, 1, 2, 3];
        service.advance_find_content_query_with_content(&query_id, bootnode_enr, content.clone());

        let (_, query) = service
            .find_content_query_pool
            .get_mut(query_id)
            .expect("Query pool does not contain query");

        // Query result should contain content.
        match query.clone().into_result() {
            FindContentQueryResult::Content {
                content: result_content,
                ..
            } => {
                assert_eq!(result_content, content);
            }
            _ => panic!("Unexpected find content query result"),
        }
    }

    #[tokio::test]
    async fn handle_find_content_query_event() {
        let mut service = task::spawn(build_service());

        let (_, bootnode_enr) = generate_random_remote_enr();
        let bootnode_node_id = bootnode_enr.node_id();
        let bootnode_key = kbucket::Key::from(bootnode_node_id);

        let data_radius = Distance::MAX;
        let bootnode = Node {
            enr: bootnode_enr.clone(),
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
            .insert_or_update(&bootnode_key, bootnode, status);

        let target_content = NodeId::random();
        let target_content_key = IdentityContentKey::new(target_content.raw());

        let (callback_tx, callback_rx) = oneshot::channel();
        let query_id =
            service.init_find_content_query(target_content_key.clone(), Some(callback_tx), false);
        let query_id = query_id.expect("Query ID for new find content query is `None`");

        let query_event =
            OverlayService::<_, XorMetric, MockValidator, MemoryContentStore>::query_event_poll(
                &mut service.find_content_query_pool,
            )
            .await;

        // Query event should be `Waiting` variant.
        assert!(matches!(query_event, QueryEvent::Waiting(_, _, _)));

        service.handle_find_content_query_event(query_event);

        // An outgoing request should be in the request channel.
        // Check that the fields of the request correspond to the query.
        let command = assert_ready!(poll_command_rx!(service));
        assert!(command.is_some());

        let command = command.unwrap();
        let request = if let OverlayCommand::Request(request) = command {
            request
        } else {
            panic!("Unexpected overlay command variant");
        };

        assert_eq!(
            request.direction,
            RequestDirection::Outgoing {
                destination: bootnode_enr.clone()
            }
        );
        assert_eq!(request.query_id, Some(query_id));

        // Simulate a response from the bootnode.
        let content: Vec<u8> = vec![0, 1, 2, 3];
        service.advance_find_content_query_with_content(
            &query_id,
            bootnode_enr.clone(),
            content.clone(),
        );

        let query_event =
            OverlayService::<_, XorMetric, MockValidator, MemoryContentStore>::query_event_poll(
                &mut service.find_content_query_pool,
            )
            .await;

        // Query event should be `Finished` variant.
        assert!(matches!(query_event, QueryEvent::Finished(_, _, _)));

        service.handle_find_content_query_event(query_event);

        match callback_rx
            .await
            .expect("Expected result on callback channel receiver")
        {
            (Some(result_content), _) => {
                assert_eq!(result_content, content);
            }
            _ => panic!("Unexpected find content query result type"),
        }
    }

    #[rstest]
    #[case(vec![generate_random_remote_enr().1; 0], 0)]
    #[case(vec![generate_random_remote_enr().1; NUM_CLOSEST_NODES - 1], NUM_CLOSEST_NODES - 1)]
    #[case(vec![generate_random_remote_enr().1; NUM_CLOSEST_NODES], NUM_CLOSEST_NODES)]
    #[case(vec![generate_random_remote_enr().1; NUM_CLOSEST_NODES + 1], NUM_CLOSEST_NODES + 1)]
    #[case(vec![generate_random_remote_enr().1; NUM_CLOSEST_NODES + NUM_FARTHER_NODES], NUM_CLOSEST_NODES + NUM_FARTHER_NODES)]
    #[case(vec![generate_random_remote_enr().1; 256], NUM_CLOSEST_NODES + NUM_FARTHER_NODES)]
    fn test_select_gossip_recipients_no_panic(
        #[case] all_nodes: Vec<Enr>,
        #[case] expected_size: usize,
    ) {
        let gossip_recipients = select_gossip_recipients(all_nodes);
        assert_eq!(gossip_recipients.len(), expected_size);
    }
}
