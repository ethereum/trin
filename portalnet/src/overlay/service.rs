use std::{
    collections::HashMap,
    fmt::Debug,
    marker::{PhantomData, Sync},
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
use itertools::Itertools;
use parking_lot::RwLock;
use rand::seq::SliceRandom;
use smallvec::SmallVec;
use ssz::Encode;
use ssz_types::BitList;
use tokio::{
    sync::{
        broadcast,
        mpsc::{self, UnboundedReceiver, UnboundedSender},
        OwnedSemaphorePermit,
    },
    task::JoinHandle,
};
use tracing::{debug, enabled, error, info, trace, warn, Level};
use utp_rs::cid::ConnectionId;

use crate::{
    accept_queue::AcceptQueue,
    discovery::{Discovery, UtpEnr},
    events::{EventEnvelope, OverlayEvent},
    find::{
        iterators::{
            findcontent::{FindContentQuery, FindContentQueryResponse, FindContentQueryResult},
            findnodes::FindNodeQuery,
            query::{Query, QueryConfig},
        },
        query_info::{QueryInfo, QueryType, RecursiveFindContentResult},
        query_pool::{QueryId, QueryPool, QueryPoolState, TargetKey},
    },
    gossip::propagate_gossip_cross_thread,
    overlay::{
        command::OverlayCommand,
        errors::OverlayRequestError,
        request::{
            ActiveOutgoingRequest, OverlayRequest, OverlayRequestId, OverlayResponse,
            RequestDirection,
        },
    },
    types::node::Node,
    utils::portal_wire,
    utp_controller::UtpController,
};
use ethportal_api::{
    generate_random_node_id,
    types::{
        distance::{Distance, Metric},
        enr::{Enr, SszEnr},
        portal_wire::{
            Accept, Content, CustomPayload, FindContent, FindNodes, Message, Nodes, Offer, Ping,
            Pong, PopulatedOffer, ProtocolId, Request, Response, MAX_PORTAL_CONTENT_PAYLOAD_SIZE,
            MAX_PORTAL_NODES_ENRS_SIZE,
        },
        query_trace::QueryTrace,
    },
    utils::bytes::hex_encode_compact,
    OverlayContentKey, RawContentKey,
};
use trin_metrics::overlay::OverlayMetricsReporter;
use trin_storage::{ContentStore, ShouldWeStoreContent};
use trin_validation::validator::{ValidationResult, Validator};

pub const FIND_NODES_MAX_NODES: usize = 32;

/// Maximum number of ENRs in response to FindContent.
pub const FIND_CONTENT_MAX_NODES: usize = 32;

/// With even distribution assumptions, 2**17 is enough to put each node (estimating 100k nodes,
/// which is more than 10x the ethereum mainnet node count) into a unique bucket by the 17th bucket
/// index.
const EXPECTED_NON_EMPTY_BUCKETS: usize = 17;

/// Bucket refresh lookup interval in seconds
const BUCKET_REFRESH_INTERVAL_SECS: u64 = 60;

/// The capacity of the event-stream's broadcast channel.
const EVENT_STREAM_CHANNEL_CAPACITY: usize = 10;

/// The overlay service.
pub struct OverlayService<TContentKey, TMetric, TValidator, TStore>
where
    TContentKey: OverlayContentKey,
{
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
    find_node_query_pool: Arc<RwLock<QueryPool<NodeId, FindNodeQuery<NodeId>, TContentKey>>>,
    /// A query pool that manages find content queries.
    find_content_query_pool: Arc<RwLock<QueryPool<NodeId, FindContentQuery<NodeId>, TContentKey>>>,
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
    /// uTP controller.
    utp_controller: Arc<UtpController>,
    /// Phantom content key.
    _phantom_content_key: PhantomData<TContentKey>,
    /// Phantom metric (distance function).
    _phantom_metric: PhantomData<TMetric>,
    /// Metrics reporting component
    metrics: OverlayMetricsReporter,
    /// Validator for overlay network content.
    validator: Arc<TValidator>,
    /// A channel that the overlay service emits events on.
    event_stream: broadcast::Sender<EventEnvelope>,
    /// Disable poke mechanism
    disable_poke: bool,
    /// Accept Queue for inbound content keys
    accept_queue: Arc<RwLock<AcceptQueue<TContentKey>>>,
}

impl<
        TContentKey: 'static + OverlayContentKey + Send + Sync,
        TMetric: Metric + Send + Sync,
        TValidator: 'static + Validator<TContentKey> + Send + Sync,
        TStore: 'static + ContentStore<Key = TContentKey> + Send + Sync,
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
        utp_controller: Arc<UtpController>,
        metrics: OverlayMetricsReporter,
        validator: Arc<TValidator>,
        query_timeout: Duration,
        query_peer_timeout: Duration,
        query_parallelism: usize,
        query_num_results: usize,
        findnodes_query_distances_per_peer: usize,
        disable_poke: bool,
    ) -> UnboundedSender<OverlayCommand<TContentKey>>
    where
        <TContentKey as TryFrom<Vec<u8>>>::Error: Send,
    {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let internal_command_tx = command_tx.clone();

        let peers_to_ping = if let Some(interval) = ping_queue_interval {
            HashSetDelay::new(interval)
        } else {
            HashSetDelay::default()
        };

        let (response_tx, response_rx) = mpsc::unbounded_channel();
        let (event_stream, _) = broadcast::channel(EVENT_STREAM_CHANNEL_CAPACITY);

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
                find_node_query_pool: Arc::new(RwLock::new(QueryPool::new(query_timeout))),
                find_content_query_pool: Arc::new(RwLock::new(QueryPool::new(query_timeout))),
                query_peer_timeout,
                query_parallelism,
                query_num_results,
                findnodes_query_distances_per_peer,
                response_rx,
                response_tx,
                utp_controller,
                _phantom_content_key: PhantomData,
                _phantom_metric: PhantomData,
                metrics,
                validator,
                event_stream,
                disable_poke,
                accept_queue: Arc::new(RwLock::new(AcceptQueue::default())),
            };

            info!(protocol = %protocol, "Starting overlay service");
            service.initialize_routing_table(bootnode_enrs);
            service.start().await;
        });

        command_tx
    }

    /// Insert a vector of enrs into the routing table
    /// set_connected: should only be true for tests, false for production code
    /// Tests that use this function are testing if adding to queues work, not if our connection
    /// code works.
    fn add_bootnodes(&mut self, bootnode_enrs: Vec<Enr>, set_connected: bool) {
        // Attempt to insert bootnodes into the routing table in a disconnected state.
        // If successful, then add the node to the ping queue. A subsequent successful ping
        // will mark the node as connected.

        for enr in bootnode_enrs {
            let node_id = enr.node_id();

            // TODO: Decide default data radius, and define a constant. Or if there is an
            // associated database, then look for a radius value there.
            let node = Node::new(enr, Distance::MAX);
            let state = if set_connected {
                ConnectionState::Connected
            } else {
                ConnectionState::Disconnected
            };
            let status = NodeStatus {
                state,
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
        self.add_bootnodes(bootnodes, false);
        let local_node_id = self.local_enr().node_id();

        // Begin request for our local node ID.
        self.init_find_nodes_query(&local_node_id, None);

        for bucket_index in (255 - EXPECTED_NON_EMPTY_BUCKETS as u8)..255 {
            let target_node_id = generate_random_node_id(bucket_index, self.local_enr().into());
            self.init_find_nodes_query(&target_node_id, None);
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
                        OverlayCommand::Event(event) => self.process_event(event),
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
                        OverlayCommand::RequestEventStream(callback) => {
                            if callback.send(self.event_stream.subscribe()).is_err() {
                                error!("Failed to return the event stream channel");
                            }
                        }
                    }
                }
                Some(response) = self.response_rx.recv() => {
                    // Look up active request that corresponds to the response.
                    let active_request = self.active_outgoing_requests.write().remove(&response.request_id);
                    if let Some(request) = active_request {

                        // Send response to responder if present.
                        if let Some(responder) = request.responder {
                            let _ = responder.send(response.response.clone());
                        }

                        // Perform background processing.
                        match response.response {
                            Ok(response) => {
                                self.metrics.report_inbound_response(&response);
                                self.process_response(response, request.destination, request.request, request.query_id, request.request_permit)
                            }
                            Err(error) => self.process_request_failure(response.request_id, request.destination, error),
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
                query_event = OverlayService::<TContentKey, TMetric, TValidator, TStore>::query_event_poll(self.find_node_query_pool.clone()) => {
                    self.handle_find_nodes_query_event(query_event);
                }
                // Handle query events for queries in the find content query pool.
                query_event = OverlayService::<TContentKey, TMetric, TValidator, TStore>::query_event_poll(self.find_content_query_pool.clone()) => {
                    self.handle_find_content_query_event(query_event);
                }
                _ = OverlayService::<TContentKey, TMetric, TValidator, TStore>::bucket_maintenance_poll(self.protocol, &self.kbuckets) => {}
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
                        Ok(idx) => generate_random_node_id(idx, self.local_enr().into()),
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

        self.init_find_nodes_query(&target_node_id, None);
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
    /// or when a query has timed out.
    async fn query_event_poll<TQuery: Query<NodeId>>(
        queries: Arc<RwLock<QueryPool<NodeId, TQuery, TContentKey>>>,
    ) -> QueryEvent<TQuery, TContentKey> {
        future::poll_fn(move |_cx| match queries.write().poll() {
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
                        None,
                    );
                    let _ = self.command_tx.send(OverlayCommand::Request(request));
                } else {
                    error!(
                        protocol = %self.protocol,
                        peer = %node_id,
                        query.id = %query_id,
                        "Cannot query peer with unknown ENR",
                    );
                    if let Some((_, query)) = self.find_node_query_pool.write().get_mut(query_id) {
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
                        None,
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
                    if let Some((_, query)) = self.find_node_query_pool.write().get_mut(query_id) {
                        query.on_failure(&node_id);
                    }
                }
            }
            QueryEvent::Finished(_, query_info, query)
            | QueryEvent::TimedOut(_, query_info, query) => {
                let (callback, content_key) = match query_info.query_type {
                    QueryType::FindContent { callback, target } => (callback, target),
                    _ => {
                        error!(
                            "Only FindContent queries trigger a Finished or TimedOut event, but this is a {:?}",
                            query_info.query_type
                        );
                        return;
                    }
                };

                match query.into_result() {
                    FindContentQueryResult::ClosestNodes(_closest_nodes) => {
                        if let Some(responder) = callback {
                            let _ = responder.send(Err(OverlayRequestError::ContentNotFound {
                                message: "Unable to locate content on the network".to_string(),
                                utp: false,
                                trace: query_info.trace,
                            }));
                        }
                    }
                    FindContentQueryResult::Content {
                        content,
                        nodes_to_poke,
                    } => {
                        let utp_processing = UtpProcessing::from(&*self);
                        tokio::spawn(async move {
                            Self::process_received_content(
                                content.clone(),
                                false,
                                content_key,
                                callback,
                                query_info.trace,
                                nodes_to_poke,
                                utp_processing,
                            )
                            .await;
                        });
                    }
                    FindContentQueryResult::Utp {
                        connection_id,
                        peer,
                        nodes_to_poke,
                    } => {
                        let source = match self.find_enr(&peer) {
                            Some(enr) => enr,
                            _ => {
                                debug!("Received uTP payload from unknown {peer}");
                                if let Some(responder) = callback {
                                    let _ =
                                        responder.send(Err(OverlayRequestError::ContentNotFound {
                                            message: "Unable to locate content on the network: received utp payload from unknown peer"
                                                .to_string(),
                                            utp: true,
                                            trace: query_info.trace,
                                        }));
                                };
                                return;
                            }
                        };
                        let utp_processing = UtpProcessing::from(&*self);
                        tokio::spawn(async move {
                            let trace = query_info.trace;
                            let cid = utp_rs::cid::ConnectionId {
                                recv: connection_id,
                                send: connection_id.wrapping_add(1),
                                peer: UtpEnr(source),
                            };
                            let data = match utp_processing
                                .utp_controller
                                .connect_inbound_stream(cid)
                                .await
                            {
                                Ok(data) => data,
                                Err(e) => {
                                    if let Some(responder) = callback {
                                        let _ = responder.send(Err(
                                            OverlayRequestError::ContentNotFound {
                                                message: format!(
                                                    "Unable to locate content on the network: {e}"
                                                ),
                                                utp: true,
                                                trace,
                                            },
                                        ));
                                    }
                                    return;
                                }
                            };
                            Self::process_received_content(
                                data,
                                true,
                                content_key,
                                callback,
                                trace,
                                nodes_to_poke,
                                utp_processing,
                            )
                            .await;
                        });
                    }
                };
            }
        }
    }

    /// Submits outgoing requests to offer `content` to the closest known nodes whose radius
    /// contains `content_key`.
    fn poke_content(
        kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
        command_tx: UnboundedSender<OverlayCommand<TContentKey>>,
        content_key: TContentKey,
        content: Vec<u8>,
        nodes_to_poke: Vec<NodeId>,
        utp_controller: Arc<UtpController>,
    ) {
        let content_id = content_key.content_id();

        // Offer content to closest nodes with sufficient radius.
        for node_id in nodes_to_poke.iter() {
            // Look up node in the routing table. We need the ENR and the radius. If we can't find
            // the node, then move on to the next.
            let key = kbucket::Key::from(*node_id);
            let node = match kbuckets.write().entry(&key) {
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

                // if we have met the max outbound utp transfer limit continue the loop as we aren't
                // allow to generate another utp stream
                let permit = match utp_controller.get_outbound_semaphore() {
                    Some(permit) => permit,
                    None => continue,
                };

                let request = OverlayRequest::new(
                    offer_request,
                    RequestDirection::Outgoing {
                        destination: node.enr(),
                    },
                    None,
                    None,
                    Some(permit),
                );

                match command_tx.send(OverlayCommand::Request(request)) {
                    Ok(_) => {
                        trace!(
                            content.id = %hex_encode_compact(content_id),
                            content.key = %content_key,
                            peer.node_id = %node_id,
                            "Content poked"
                        );
                    }
                    Err(err) => {
                        warn!(
                            content.id = %hex_encode_compact(content_id),
                            content.key = %content_key,
                            peer.node_id = %node_id,
                            %err,
                            "Failed to poke content to peer"
                        );
                    }
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
                        self.metrics.report_outbound_response(response);
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
                        request_permit: request.request_permit,
                    },
                );
                self.metrics.report_outbound_request(&request.request);
                self.send_talk_req(request.request, request.id, destination);
            }
        }
    }

    /// Process an event dispatched by another overlay on the discovery.
    fn process_event(&mut self, _event: EventEnvelope) {}

    /// Attempts to build a response for a request.
    #[allow(clippy::result_large_err)]
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
            Request::PopulatedOffer(_) | Request::PopulatedOfferWithResult(_) => {
                Err(OverlayRequestError::InvalidRequest(
                    "An offer with content attached is not a valid network message to receive"
                        .to_owned(),
                ))
            }
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
        let mut enrs = self
            .nodes_by_distance(distances64)
            .into_iter()
            .filter(|enr| {
                // Filter out the source node.
                &enr.node_id() != source
            })
            .collect();

        // Limit the ENRs so that their summed sizes do not surpass the max TALKREQ packet size.
        pop_while_ssz_bytes_len_gt(&mut enrs, MAX_PORTAL_NODES_ENRS_SIZE);

        Nodes { total: 1, enrs }
    }

    /// Attempts to build a `Content` response for a `FindContent` request.
    #[allow(clippy::result_large_err)]
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
        match (
            self.store.read().get(&content_key),
            self.utp_controller.get_outbound_semaphore(),
        ) {
            (Ok(Some(content)), Some(permit)) => {
                if content.len() <= MAX_PORTAL_CONTENT_PAYLOAD_SIZE {
                    Ok(Content::Content(content))
                } else {
                    // Generate a connection ID for the uTP connection.
                    let node_addr = self.discovery.cached_node_addr(source).ok_or_else(|| {
                        OverlayRequestError::AcceptError(
                            "unable to find ENR for NodeId".to_string(),
                        )
                    })?;
                    let enr = UtpEnr(node_addr.enr);
                    let cid = self.utp_controller.cid(enr, false);
                    let cid_send = cid.send;

                    // Wait for an incoming connection with the given CID. Then, write the data
                    // over the uTP stream.
                    let utp = Arc::clone(&self.utp_controller);
                    tokio::spawn(async move {
                        utp.accept_outbound_stream(cid, content).await;
                        drop(permit);
                    });

                    // Connection id is sent as BE because uTP header values are stored also as BE
                    Ok(Content::ConnectionId(cid_send.to_be()))
                }
            }
            // If we don't have data to send back or can't obtain a permit, send the requester a
            // list of closer ENRs.
            (Ok(Some(_)), _) | (Ok(None), _) => {
                let mut enrs = self.find_nodes_close_to_content(content_key);
                enrs.retain(|enr| source != &enr.node_id());
                pop_while_ssz_bytes_len_gt(&mut enrs, MAX_PORTAL_CONTENT_PAYLOAD_SIZE);
                Ok(Content::Enrs(enrs))
            }
            (Err(msg), _) => Err(OverlayRequestError::Failure(format!(
                "Unable to respond to FindContent: {msg}",
            ))),
        }
    }

    /// Attempts to build an `Accept` response for an `Offer` request.
    #[allow(clippy::result_large_err)]
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

        // Attempt to get semaphore permit if fails we return an empty accept.
        // `get_inbound_semaphore()` isn't blocking and will instantly return with
        // `None` if there isn't a permit available.
        // The reason we get the permit before checking if we can store it is because
        // * checking if a semaphore is available is basically free it doesn't block and will return
        //   instantly
        // * filling the `requested_keys` is expensive because it requires calls to disk which
        //   should be avoided.
        // so by trying to acquire the semaphore before the storage call we avoid unnecessary work
        // **Note:** if we are not accepting any content `requested_keys` should be empty
        let permit = match self.utp_controller.get_inbound_semaphore() {
            Some(permit) => permit,
            None => {
                return Ok(Accept {
                    connection_id: 0,
                    content_keys: requested_keys,
                });
            }
        };

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

        let mut accepted_keys: Vec<TContentKey> = Vec::default();

        // if we're unable to find the ENR for the source node we throw an error
        // since the enr is required for the accept queue, and it is expected to be present
        let node_addr = self.discovery.cached_node_addr(source).ok_or_else(|| {
            OverlayRequestError::AcceptError("unable to find ENR for NodeId".to_string())
        })?;
        for (i, key) in content_keys.iter().enumerate() {
            // Accept content if within radius and not already present in the data store.
            let mut accept = self
                .store
                .read()
                .is_key_within_radius_and_unavailable(key)
                .map(|value| matches!(value, ShouldWeStoreContent::Store))
                .map_err(|err| {
                    OverlayRequestError::AcceptError(format!(
                        "Unable to check content availability {err}"
                    ))
                })?;
            if accept {
                // accept all keys that are successfully added to the queue
                if self
                    .accept_queue
                    .write()
                    .add_key_to_queue(key, &node_addr.enr)
                {
                    accepted_keys.push(key.clone());
                } else {
                    accept = false;
                }
            }
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
        let enr = UtpEnr(node_addr.enr);
        let enr_str = if enabled!(Level::TRACE) {
            enr.0.to_base64()
        } else {
            String::with_capacity(0)
        };
        let cid: ConnectionId<UtpEnr> = self.utp_controller.cid(enr, false);
        let cid_send = cid.send;

        let content_keys_string: Vec<String> = content_keys
            .iter()
            .map(|content_key| content_key.to_hex())
            .collect();

        trace!(
            protocol = %self.protocol,
            request.source = %source,
            cid.send = cid.send,
            cid.recv = cid.recv,
            enr = enr_str,
            request.content_keys = ?content_keys_string,
            "Content keys handled by offer",
        );

        let utp_processing = UtpProcessing::from(self);
        tokio::spawn(async move {
            let data = match utp_processing
                .utp_controller
                .accept_inbound_stream(cid.clone())
                .await
            {
                Ok(data) => data,
                Err(err) => {
                    debug!(%err, cid.send, cid.recv, peer = ?cid.peer.client(), content_keys = ?content_keys_string, "unable to complete uTP transfer");
                    // Spawn a fallback FINDCONTENT task for each content key
                    // in a payload that failed to be received.
                    //
                    // We spawn these additional fallback FINDCONTENT tasks using
                    // the same semaphore permit that was initially acquired for
                    // the ACCEPT utp stream.
                    let handles: Vec<JoinHandle<_>> = content_keys
                        .into_iter()
                        .map(|content_key| {
                            let utp_processing = utp_processing.clone();
                            tokio::spawn(async move {
                                // We don't really care about the result from these fallbacks.
                                // If the fallback FINDCONTENT task fails, that's fine for now.
                                // In the future, we might want to cycle through all available
                                // fallback peers on an error.
                                let _ = Self::fallback_find_content(
                                    content_key.clone(),
                                    utp_processing,
                                )
                                .await;
                            })
                        })
                        .collect();
                    let _ = join_all(handles).await;
                    drop(permit);
                    return;
                }
            };

            // Spawn fallback FINDCONTENT tasks for each content key
            // in payloads that failed to be accepted.
            let content_values =
                match decode_and_validate_content_payload(&accepted_keys, data.clone()) {
                    Ok(content_values) => content_values,
                    Err(_) => {
                        let handles: Vec<JoinHandle<_>> = content_keys
                            .into_iter()
                            .map(|content_key| {
                                let utp_processing = utp_processing.clone();
                                tokio::spawn(async move {
                                    let _ = Self::fallback_find_content(
                                        content_key.clone(),
                                        utp_processing,
                                    )
                                    .await;
                                })
                            })
                            .collect();
                        let _ = join_all(handles).await;
                        drop(permit);
                        return;
                    }
                };

            let handles = accepted_keys
                .into_iter()
                .zip(content_values)
                .map(|(key, value)| {
                    let utp_processing = utp_processing.clone();
                    tokio::spawn(async move {
                        match Self::validate_and_store_content(
                            key.clone(),
                            value,
                            utp_processing.clone(),
                        )
                        .await
                        {
                            Some(validated_content) => {
                                utp_processing.accept_queue.write().remove_key(&key);
                                Some(validated_content)
                            }
                            None => {
                                // Spawn a fallback FINDCONTENT task for each content key
                                // that failed individual processing.
                                let _ = Self::fallback_find_content(key, utp_processing).await;
                                None
                            }
                        }
                    })
                })
                .collect::<Vec<_>>();
            let validated_content = join_all(handles)
                .await
                .into_iter()
                .enumerate()
                .filter_map(|(index, value)| {
                    value.unwrap_or_else(|err| {
                        let err = err.into_panic();
                        let err = if let Some(err) = err.downcast_ref::<&'static str>() {
                            err.to_string()
                        } else if let Some(err) = err.downcast_ref::<String>() {
                            err.clone()
                        } else {
                            format!("{err:?}")
                        };
                        debug!(err, content_key = ?content_keys_string[index], "Process uTP payload tokio task failed:");
                        // Do we want to fallback find content here?
                        None
                    })
                })
                .collect::<Vec<_>>();
            let _ = Self::propagate_validated_content(validated_content, utp_processing).await;
            // explicitly drop semaphore permit in thread so the permit is moved into the thread
            drop(permit);
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
        let response_tx = self.response_tx.clone();
        let protocol = self.protocol;

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
        self.metrics.report_inbound_request(&request);
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

            // If the ENR sequence number in pong is less than the ENR sequence number for the
            // routing table entry, then request the node.
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
        request_permit: Option<OwnedSemaphorePermit>,
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
            Response::Content(content) => self.process_content(content, source, query_id),
            Response::Accept(accept) => {
                if let Err(err) = self.process_accept(accept, source, request, request_permit) {
                    error!(response.error = %err, "Error processing ACCEPT message")
                }
            }
        }
    }

    // Process ACCEPT response
    fn process_accept(
        &self,
        response: Accept,
        enr: Enr,
        offer: Request,
        request_permit: Option<OwnedSemaphorePermit>,
    ) -> anyhow::Result<Accept> {
        // Check that a valid triggering request was sent
        let mut gossip_result_tx = None;
        match &offer {
            Request::Offer(_) => {}
            Request::PopulatedOffer(_) => {}
            Request::PopulatedOfferWithResult(req) => {
                gossip_result_tx = Some(req.result_tx.clone())
            }
            _ => {
                return Err(anyhow!("Invalid request message paired with ACCEPT"));
            }
        };

        // Do not initialize uTP stream if remote node doesn't have interest in the offered content
        // keys
        if response.content_keys.is_zero() {
            if let Some(tx) = gossip_result_tx {
                let _ = tx.send(false);
            }
            return Ok(response);
        }

        // Build a connection ID based on the response.
        let conn_id = u16::from_be(response.connection_id);
        let cid = utp_rs::cid::ConnectionId {
            recv: conn_id,
            send: conn_id.wrapping_add(1),
            peer: UtpEnr(enr),
        };
        let store = Arc::clone(&self.store);
        let response_clone = response.clone();

        let utp_controller = Arc::clone(&self.utp_controller);
        tokio::spawn(async move {
            let content_items = match offer {
                Request::Offer(offer) => {
                    Self::provide_requested_content(store, &response_clone, offer.content_keys)
                }
                Request::PopulatedOffer(offer) => Ok(response_clone
                    .content_keys
                    .iter()
                    .zip(offer.content_items)
                    .filter(|(is_accepted, _item)| *is_accepted)
                    .map(|(_is_accepted, (_key, val))| val)
                    .collect()),
                Request::PopulatedOfferWithResult(offer) => Ok(response_clone
                    .content_keys
                    .iter()
                    .zip(vec![offer.content_item])
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
                    if let Some(tx) = gossip_result_tx {
                        let _ = tx.send(false);
                    }
                    return;
                }
            };

            let content_payload = match portal_wire::encode_content_payload(&content_items) {
                Ok(payload) => payload,
                Err(err) => {
                    warn!(%err, "Unable to build content payload");
                    if let Some(tx) = gossip_result_tx {
                        let _ = tx.send(false);
                    }
                    return;
                }
            };
            let result = utp_controller
                .connect_outbound_stream(cid, content_payload.to_vec())
                .await;
            if let Some(tx) = gossip_result_tx {
                let _ = tx.send(result);
            }
            // explicitly drop permit in the thread so the permit is included in the thread
            if let Some(permit) = request_permit {
                drop(permit);
            }
        });

        Ok(response)
    }

    async fn propagate_validated_content(
        validated_content: Vec<(TContentKey, Vec<u8>, ValidationResult<TContentKey>)>,
        utp_processing: UtpProcessing<TValidator, TStore, TContentKey>,
    ) -> anyhow::Result<()> {
        // Propagate all validated content, whether or not it was stored.
        let content_to_propagate: Vec<(TContentKey, Vec<u8>)> = validated_content
            .into_iter()
            .flat_map(|(content_key, content_value, validation_result)| {
                match validation_result.additional_content_to_propagate {
                    Some(additional_content_to_propagate) => vec![
                        (content_key, content_value),
                        additional_content_to_propagate,
                    ],
                    None => vec![(content_key, content_value)],
                }
            })
            .unique_by(|(key, _)| key.content_id())
            .collect();

        let ids_to_propagate: Vec<String> = content_to_propagate
            .iter()
            .map(|(k, _)| hex_encode_compact(k.content_id()))
            .collect();
        debug!(ids = ?ids_to_propagate, "propagating validated content");
        propagate_gossip_cross_thread(
            content_to_propagate,
            utp_processing.kbuckets,
            utp_processing.command_tx.clone(),
            Some(utp_processing.utp_controller),
        );
        Ok(())
    }

    /// Validates & stores content value received from peer.
    /// Checks if validated content should be stored, and stores it if true
    // (this step requires a dedicated task since it might require
    // non-blocking requests to this/other overlay networks).
    async fn validate_and_store_content(
        key: TContentKey,
        content_value: Vec<u8>,
        utp_processing: UtpProcessing<TValidator, TStore, TContentKey>,
    ) -> Option<(TContentKey, Vec<u8>, ValidationResult<TContentKey>)> {
        // Validate received content
        let validation_result = utp_processing
            .validator
            .validate_content(&key, &content_value)
            .await;
        utp_processing
            .metrics
            .report_validation(validation_result.is_ok());

        let validation_result = match validation_result {
            Ok(validation_result) => validation_result,
            Err(err) => {
                // Skip storing & propagating content if it's not valid
                warn!(
                    error = %err,
                    content.key = %key.to_hex(),
                    "Error validating accepted content"
                );
                return None;
            }
        };

        if !validation_result.valid_for_storing {
            // Content received via Offer/Accept should be valid for storing.
            // If it isn't, don't store it and don't propagate it.
            warn!(
                content.key = %key.to_hex(),
                "Error validating accepted content - not valid for storing"
            );
            return None;
        }

        // Check if data should be stored, and store if it is within our radius and not
        // already stored.
        let key_desired = utp_processing
            .store
            .read()
            .is_key_within_radius_and_unavailable(&key);
        match key_desired {
            Ok(ShouldWeStoreContent::Store) => {
                if let Err(err) = utp_processing
                    .store
                    .write()
                    .put(key.clone(), &content_value)
                {
                    warn!(
                        error = %err,
                        content.key = %key.to_hex(),
                        "Error storing accepted content"
                    );
                }
            }
            Ok(ShouldWeStoreContent::NotWithinRadius) => {
                warn!(
                    content.key = %key.to_hex(),
                    "Accepted content outside radius"
                );
            }
            Ok(ShouldWeStoreContent::AlreadyStored) => {
                warn!(
                    content.key = %key.to_hex(),
                    "Accepted content already stored"
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
        Some((key, content_value, validation_result))
    }

    /// Attempts to send a single FINDCONTENT request to a fallback peer,
    /// if found in the accept queue. Then validate, store & propagate the content.
    async fn fallback_find_content(
        content_key: TContentKey,
        utp_processing: UtpProcessing<TValidator, TStore, TContentKey>,
    ) -> anyhow::Result<()> {
        let fallback_peer = match utp_processing
            .accept_queue
            .write()
            .process_failed_key(&content_key)
        {
            Some(peer) => peer,
            None => {
                debug!("No fallback peer found for content key");
                return Ok(());
            }
        };
        let request = Request::FindContent(FindContent {
            content_key: content_key.clone().into(),
        });
        let direction = RequestDirection::Outgoing {
            destination: fallback_peer.clone(),
        };
        let (tx, rx) = oneshot::channel();
        utp_processing
            .command_tx
            .send(OverlayCommand::Request(OverlayRequest::new(
                request,
                direction,
                Some(tx),
                None,
                None,
            )))?;
        let data: Vec<u8> = match rx.await? {
            Ok(Response::Content(found_content)) => {
                match found_content {
                    Content::Content(content) => content,
                    Content::Enrs(_) => return Err(anyhow!("expected content, got ENRs")),
                    // Init uTP stream if `connection_id` is received
                    Content::ConnectionId(conn_id) => {
                        let conn_id = u16::from_be(conn_id);
                        let cid = utp_rs::cid::ConnectionId {
                            recv: conn_id,
                            send: conn_id.wrapping_add(1),
                            peer: UtpEnr(fallback_peer.clone()),
                        };
                        utp_processing
                            .utp_controller
                            .connect_inbound_stream(cid)
                            .await?
                    }
                }
            }
            _ => return Err(anyhow!("invalid response")),
        };
        let validated_content = match Self::validate_and_store_content(
            content_key,
            data,
            utp_processing.clone(),
        )
        .await
        {
            Some(validated_content) => validated_content,
            None => {
                debug!("Fallback FINDCONTENT request to peer {fallback_peer} did not yield valid content");
                return Ok(());
            }
        };

        let _ = Self::propagate_validated_content(vec![validated_content], utp_processing).await;
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
            "Processing Pong message {pong}"
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
    fn process_content(&mut self, content: Content, source: Enr, query_id: Option<QueryId>) {
        trace!(
            protocol = %self.protocol,
            response.source = %source.node_id(),
            "Processing Content message",
        );
        match content {
            Content::ConnectionId(id) => {
                if let Some(query_id) = query_id {
                    self.advance_find_content_query_with_connection_id(&query_id, source, id);
                }
            }
            Content::Content(content) => {
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

    // This method should be used in a non-blocking thread to allow for
    // requests to this/other overlay services.
    #[allow(clippy::too_many_arguments)]
    async fn process_received_content(
        content: Vec<u8>,
        utp_transfer: bool,
        content_key: TContentKey,
        responder: Option<oneshot::Sender<RecursiveFindContentResult>>,
        trace: Option<QueryTrace>,
        nodes_to_poke: Vec<NodeId>,
        utp_processing: UtpProcessing<TValidator, TStore, TContentKey>,
    ) {
        let mut content = content;
        // Operate under assumption that all content in the store is valid
        let local_value = utp_processing.store.read().get(&content_key);
        if let Ok(Some(val)) = local_value {
            // todo validate & replace content value if different & punish bad peer
            content = val;
        } else {
            let content_id = content_key.content_id();
            let validation_result = utp_processing
                .validator
                .validate_content(&content_key, &content)
                .await;
            utp_processing
                .metrics
                .report_validation(validation_result.is_ok());

            let validation_result = match validation_result {
                Ok(validation_result) => validation_result,
                Err(err) => {
                    warn!(
                        error = ?err,
                        content.id = %hex_encode_compact(content_id),
                        content.key = %content_key,
                        "Error validating content"
                    );
                    if let Some(responder) = responder {
                        let _ = responder.send(Err(OverlayRequestError::ContentNotFound {
                            message:
                                "Unable to locate content on the network: error validating content"
                                    .to_string(),
                            utp: utp_transfer,
                            trace,
                        }));
                    }
                    return;
                }
            };

            // skip storing if content is not valid for storing, the content
            // is already stored or if there's an error reading the store
            let should_store = validation_result.valid_for_storing
                && utp_processing
                    .store
                    .read()
                    .is_key_within_radius_and_unavailable(&content_key)
                    .map_or_else(
                        |err| {
                            error!("Unable to read store: {err}");
                            false
                        },
                        |val| matches!(val, ShouldWeStoreContent::Store),
                    );
            if should_store {
                if let Err(err) = utp_processing
                    .store
                    .write()
                    .put(content_key.clone(), content.clone())
                {
                    error!(
                        error = %err,
                        content.id = %hex_encode_compact(content_id),
                        content.key = %content_key,
                        "Error storing content"
                    );
                }
            }
        }
        if let Some(responder) = responder {
            let _ = responder.send(Ok((content.clone(), utp_transfer, trace)));
        }

        if !utp_processing.disable_poke {
            Self::poke_content(
                utp_processing.kbuckets,
                utp_processing.command_tx,
                content_key,
                content,
                nodes_to_poke,
                utp_processing.utp_controller,
            );
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
            // A subsequent ping will establish connectivity with the node. If the insertion
            // succeeds, then add the node to the ping queue. Ignore insertion failures.
            if let Some(node) = optional_node {
                if node.enr().seq() < enr.seq() {
                    let updated_node = Node {
                        enr,
                        data_radius: node.data_radius(),
                    };

                    // The update removed the node because it would violate the incoming peers
                    // condition or a bucket/table filter. Remove the node from
                    // the ping queue.
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
    /// Does nothing if called with a node_id that does not have a corresponding active query
    /// request.
    fn advance_find_node_query(&mut self, source: Enr, enrs: Vec<Enr>, query_id: QueryId) {
        // Check whether this request was sent on behalf of a query.
        // If so, advance the query with the returned data.
        let local_node_id = self.local_enr().node_id();
        if let Some((query_info, query)) = self.find_node_query_pool.write().get_mut(query_id) {
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
        if let Some((query_info, query)) = self.find_content_query_pool.write().get_mut(*query_id) {
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
                trace.cancelled = query.pending_peers(source.node_id()).into_iter().collect();
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

    /// Advances a find content query (if one exists for `query_id`) with a connection id.
    fn advance_find_content_query_with_connection_id(
        &mut self,
        query_id: &QueryId,
        source: Enr,
        utp: u16,
    ) {
        if let Some((query_info, query)) = self.find_content_query_pool.write().get_mut(*query_id) {
            if let Some(trace) = &mut query_info.trace {
                trace.node_responded_with_content(&source);
                trace.cancelled = query.pending_peers(source.node_id()).into_iter().collect();
            }
            // Mark the query successful for the source of the response with the connection id.
            query.on_success(
                &source.node_id(),
                FindContentQueryResponse::ConnectionId(utp),
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
        let mut pool = self.find_content_query_pool.write();
        if let Some((query_info, query)) = pool.get_mut(*query_id) {
            if let Some(trace) = &mut query_info.trace {
                trace.node_responded_with_content(&source);
                trace.cancelled = query.pending_peers(source.node_id()).into_iter().collect();
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

    /// Returns a vector of all the ENRs of nodes currently contained in the routing table which are
    /// connected.
    fn table_entries_enr(&self) -> Vec<Enr> {
        self.kbuckets
            .write()
            .iter()
            .filter(|entry| {
                // Filter out disconnected nodes.
                entry.status.is_connected()
            })
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
                .filter(|entry| {
                    // Filter out disconnected nodes.
                    entry.status.is_connected()
                })
                .map(|entry| entry.node.value.clone())
            {
                nodes_to_send.push(SszEnr::new(node.enr()));
            }
        }
        nodes_to_send
    }

    /// Returns list of nodes closest to content, sorted by distance.
    fn find_nodes_close_to_content(&self, content_key: impl OverlayContentKey) -> Vec<SszEnr> {
        let content_id = content_key.content_id();

        let mut nodes_with_distance: Vec<(Distance, Enr)> = self
            .table_entries_enr()
            .into_iter()
            .map(|enr| (TMetric::distance(&content_id, &enr.node_id().raw()), enr))
            .collect();

        nodes_with_distance.sort_by(|a, b| a.0.cmp(&b.0));

        nodes_with_distance
            .into_iter()
            .take(FIND_CONTENT_MAX_NODES)
            .map(|node_record| SszEnr::new(node_record.1))
            .collect()
    }

    /// Returns a vector of ENRs of the `max_nodes` closest connected nodes to the target from our
    /// routing table.
    fn closest_connected_nodes(&self, target_key: &Key<NodeId>, max_nodes: usize) -> Vec<Enr> {
        // Filter out all disconnected nodes
        let kbuckets = self.kbuckets.read();
        let mut all_nodes: Vec<&kbucket::Node<NodeId, Node>> = kbuckets
            .buckets_iter()
            .flat_map(|kbucket| {
                kbucket
                    .iter()
                    .filter(|node| node.status.is_connected())
                    .collect::<Vec<&kbucket::Node<NodeId, Node>>>()
            })
            .collect();

        all_nodes.sort_by(|a, b| {
            let a_distance = a.key.distance(target_key);
            let b_distance = b.key.distance(target_key);
            a_distance.cmp(&b_distance)
        });

        all_nodes
            .iter()
            .take(max_nodes)
            .map(|closest| closest.value.enr.clone())
            .collect()
    }

    /// Starts a FindNode query to find nodes with IDs closest to `target`.
    fn init_find_nodes_query(
        &mut self,
        target: &NodeId,
        callback: Option<oneshot::Sender<Vec<Enr>>>,
    ) -> Option<QueryId> {
        let target_key = Key::from(*target);

        let closest_enrs = self.closest_connected_nodes(&target_key, self.query_num_results);
        if closest_enrs.is_empty() {
            // If there are no nodes whatsoever in the routing table the query cannot proceed.
            warn!("No nodes in routing table, find nodes query cannot proceed.");
            if let Some(callback) = callback {
                let _ = callback.send(vec![]);
            }
            return None;
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
                    .write()
                    .add_query(query_info, find_nodes_query),
            )
        }
    }

    /// Starts a `FindContentQuery` for a target content key.
    fn init_find_content_query(
        &mut self,
        target: TContentKey,
        callback: Option<oneshot::Sender<RecursiveFindContentResult>>,
        is_trace: bool,
    ) -> Option<QueryId> {
        debug!("Starting query for content key: {}", target);

        // Represent the target content ID with a node ID.
        let target_node_id = NodeId::new(&target.content_id());
        let target_key = Key::from(target_node_id);

        let query_config = QueryConfig {
            parallelism: self.query_parallelism,
            num_results: self.query_num_results,
            peer_timeout: self.query_peer_timeout,
        };

        let closest_enrs = self.closest_connected_nodes(&target_key, query_config.num_results);
        if closest_enrs.is_empty() {
            // If there are no connected nodes in the routing table the query cannot proceed.
            warn!("No connected nodes in routing table, find content query cannot proceed.");
            if let Some(callback) = callback {
                let _ = callback.send(Err(OverlayRequestError::ContentNotFound {
                    message: "Unable to locate content on the network: no connected nodes in the routing table"
                        .to_string(),
                    utp: false,
                    trace: None,
                }));
            }
            return None;
        }

        // Convert ENRs into k-bucket keys.
        let closest_nodes: Vec<Key<NodeId>> = closest_enrs
            .iter()
            .map(|enr| Key::from(enr.node_id()))
            .collect();

        let trace: Option<QueryTrace> = {
            if is_trace {
                let mut trace = QueryTrace::new(&self.local_enr(), target_node_id.raw());
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

        let query = FindContentQuery::with_config(query_config, target_key, closest_nodes);
        Some(
            self.find_content_query_pool
                .write()
                .add_query(query_info, query),
        )
    }

    /// Returns an ENR if one is known for the given NodeId.
    pub fn find_enr(&self, node_id: &NodeId) -> Option<Enr> {
        // Check whether we know this node id in our routing table.
        let key = kbucket::Key::from(*node_id);
        if let kbucket::Entry::Present(entry, _) = self.kbuckets.write().entry(&key) {
            return Some(entry.value().clone().enr());
        }

        // Check whether this node id is in our discovery ENR cache
        if let Some(node_addr) = self.discovery.cached_node_addr(node_id) {
            return Some(node_addr.enr);
        }

        // Check the existing find node queries for the ENR.
        for (query_info, _) in self.find_node_query_pool.read().iter() {
            if let Some(enr) = query_info
                .untrusted_enrs
                .iter()
                .find(|v| v.node_id() == *node_id)
            {
                return Some(enr.clone());
            }
        }

        // Check the existing find content queries for the ENR.
        for (query_info, _) in self.find_content_query_pool.read().iter() {
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

    /// Send `OverlayEvent` to the event stream.
    #[allow(dead_code)] // TODO: remove when used
    fn send_event(&self, event: OverlayEvent, to: Option<Vec<ProtocolId>>) {
        trace!(
            "Sending event={:?} to event-stream from protocol {}",
            event,
            self.protocol
        );
        let event = EventEnvelope::new(event, self.protocol, to);
        if let Err(err) = self.event_stream.send(event) {
            error!(
                error = %err,
                "Error sending event through event-stream"
            )
        }
    }
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

/// References to `OverlayService` components required for processing
/// a utp stream. This is basically a utility struct to avoid passing
/// around a large number of individual references.
struct UtpProcessing<TValidator, TStore, TContentKey>
where
    TContentKey: OverlayContentKey + Send + Sync,
    TValidator: Validator<TContentKey>,
    TStore: ContentStore<Key = TContentKey>,
{
    validator: Arc<TValidator>,
    store: Arc<RwLock<TStore>>,
    metrics: OverlayMetricsReporter,
    kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
    command_tx: UnboundedSender<OverlayCommand<TContentKey>>,
    utp_controller: Arc<UtpController>,
    accept_queue: Arc<RwLock<AcceptQueue<TContentKey>>>,
    disable_poke: bool,
}

impl<TContentKey, TMetric, TValidator, TStore>
    From<&OverlayService<TContentKey, TMetric, TValidator, TStore>>
    for UtpProcessing<TValidator, TStore, TContentKey>
where
    TContentKey: OverlayContentKey + Send + Sync,
    TValidator: Validator<TContentKey>,
    TStore: ContentStore<Key = TContentKey>,
{
    fn from(service: &OverlayService<TContentKey, TMetric, TValidator, TStore>) -> Self {
        Self {
            validator: Arc::clone(&service.validator),
            store: Arc::clone(&service.store),
            metrics: service.metrics.clone(),
            kbuckets: Arc::clone(&service.kbuckets),
            command_tx: service.command_tx.clone(),
            utp_controller: Arc::clone(&service.utp_controller),
            accept_queue: Arc::clone(&service.accept_queue),
            disable_poke: service.disable_poke,
        }
    }
}

impl<TValidator, TStore, TContentKey> Clone for UtpProcessing<TValidator, TStore, TContentKey>
where
    TContentKey: OverlayContentKey + Send + Sync,
    TValidator: Validator<TContentKey>,
    TStore: ContentStore<Key = TContentKey>,
{
    fn clone(&self) -> Self {
        Self {
            validator: Arc::clone(&self.validator),
            store: Arc::clone(&self.store),
            metrics: self.metrics.clone(),
            kbuckets: Arc::clone(&self.kbuckets),
            command_tx: self.command_tx.clone(),
            utp_controller: Arc::clone(&self.utp_controller),
            accept_queue: Arc::clone(&self.accept_queue),
            disable_poke: self.disable_poke,
        }
    }
}

fn decode_and_validate_content_payload<TContentKey>(
    accepted_keys: &[TContentKey],
    payload: Vec<u8>,
) -> anyhow::Result<Vec<Vec<u8>>> {
    let content_values = portal_wire::decode_content_payload(payload)?;
    // Accepted content keys len should match content value len
    let keys_len = accepted_keys.len();
    let vals_len = content_values.len();
    if keys_len != vals_len {
        return Err(anyhow!(
            "Accepted content keys len ({}) does not match content values len ({})",
            keys_len,
            vals_len
        ));
    }
    Ok(content_values)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    use std::{net::SocketAddr, time::Instant};

    use alloy_primitives::U256;
    use discv5::kbucket::Entry;
    use rstest::*;
    use serial_test::serial;
    use tokio::sync::mpsc::unbounded_channel;
    use tokio_test::{assert_pending, assert_ready, task};

    use crate::{
        config::PortalnetConfig,
        discovery::{Discovery, NodeAddress},
        overlay::config::OverlayConfig,
        utils::db::setup_temp_dir,
    };
    use ethportal_api::types::{
        cli::{DEFAULT_DISCOVERY_PORT, DEFAULT_UTP_TRANSFER_LIMIT},
        content_key::overlay::IdentityContentKey,
        distance::XorMetric,
        enr::generate_random_remote_enr,
        portal_wire::MAINNET,
    };
    use trin_metrics::portalnet::PORTALNET_METRICS;
    use trin_storage::{DistanceFunction, MemoryContentStore};
    use trin_validation::validator::MockValidator;

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
        let temp_dir = setup_temp_dir().unwrap().into_path();
        let discovery = Arc::new(Discovery::new(portal_config, temp_dir, MAINNET.clone()).unwrap());

        let (_utp_talk_req_tx, utp_talk_req_rx) = unbounded_channel();
        let discv5_utp =
            crate::discovery::Discv5UdpSocket::new(Arc::clone(&discovery), utp_talk_req_rx);
        let utp_socket = utp_rs::socket::UtpSocket::with_socket(discv5_utp);
        let metrics = OverlayMetricsReporter {
            overlay_metrics: PORTALNET_METRICS.overlay(),
            protocol: "test".to_string(),
        };
        let utp_controller = UtpController::new(
            DEFAULT_UTP_TRANSFER_LIMIT,
            Arc::new(utp_socket),
            metrics.clone(),
        );
        let utp_controller = Arc::new(utp_controller);

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
        let validator = Arc::new(MockValidator {});
        let accept_queue = Arc::new(RwLock::new(AcceptQueue::default()));

        OverlayService {
            discovery,
            utp_controller,
            store,
            kbuckets,
            protocol,
            peers_to_ping,
            command_tx,
            command_rx,
            active_outgoing_requests,
            find_node_query_pool: Arc::new(RwLock::new(QueryPool::new(
                overlay_config.query_timeout,
            ))),
            find_content_query_pool: Arc::new(RwLock::new(QueryPool::new(
                overlay_config.query_timeout,
            ))),
            query_peer_timeout: overlay_config.query_peer_timeout,
            query_parallelism: overlay_config.query_parallelism,
            query_num_results: overlay_config.query_num_results,
            findnodes_query_distances_per_peer: overlay_config.findnodes_query_distances_per_peer,
            response_tx,
            response_rx,
            _phantom_content_key: PhantomData,
            _phantom_metric: PhantomData,
            metrics,
            validator,
            event_stream: broadcast::channel(EVENT_STREAM_CHANNEL_CAPACITY).0,
            disable_poke: false,
            accept_queue,
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
        let updated_udp: u16 = DEFAULT_DISCOVERY_PORT;
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
        OverlayService::<IdentityContentKey, XorMetric, MockValidator, MemoryContentStore>::poke_content(
            service.kbuckets.clone(),
            service.command_tx.clone(),
            content_key,
            content,
            peer_node_ids,
            service.utp_controller.clone(),
        );
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
        let peers = [enr1, enr2];
        let peer_node_ids: Vec<NodeId> = peers.iter().map(|p| p.node_id()).collect();

        // No nodes in the routing table, so no commands should be in the channel.
        OverlayService::<IdentityContentKey, XorMetric, MockValidator, MemoryContentStore>::poke_content(
            service.kbuckets.clone(),
            service.command_tx.clone(),
            content_key,
            content,
            peer_node_ids,
            service.utp_controller.clone(),
        );
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
            data_radius: Distance::from(U256::ZERO),
        };
        let _ = service
            .kbuckets
            .write()
            .insert_or_update(&key2, peer2.clone(), status);

        let peers = vec![peer1.clone(), peer2];
        let peer_node_ids: Vec<NodeId> = peers.iter().map(|p| p.enr.node_id()).collect();

        // One offer should be in the channel for the maximum radius node.
        OverlayService::<IdentityContentKey, XorMetric, MockValidator, MemoryContentStore>::poke_content(
            service.kbuckets.clone(),
            service.command_tx.clone(),
            content_key,
            content,
            peer_node_ids,
            service.utp_controller.clone(),
        );
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

        assert_eq!(service.find_node_query_pool.read().iter().count(), 0);

        service.add_bootnodes(bootnodes, true);

        // Initialize the query and call `poll` so that it starts
        service.init_find_nodes_query(&target_node_id, None);
        let _ = service.find_node_query_pool.write().poll();

        let pool = service.find_node_query_pool.read();
        let (query_info, query) = pool.iter().next().unwrap();

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

        service.add_bootnodes(bootnodes, true);
        service.query_num_results = 3;
        service.init_find_nodes_query(&target_node_id, None);

        // Test that the first query event contains a proper query ID and request to the bootnode
        let event = OverlayService::<
            IdentityContentKey,
            XorMetric,
            MockValidator,
            MemoryContentStore,
        >::query_event_poll(service.find_node_query_pool.clone())
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
        >::query_event_poll(service.find_node_query_pool.clone())
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
        >::query_event_poll(service.find_node_query_pool.clone())
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
        >::query_event_poll(service.find_node_query_pool.clone())
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

        service.add_bootnodes(bootnodes, true);

        service.init_find_nodes_query(&target_node_id, None);

        let _event = OverlayService::<
            IdentityContentKey,
            XorMetric,
            MockValidator,
            MemoryContentStore,
        >::query_event_poll(service.find_node_query_pool.clone())
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

        // Test discovery node address cache
        let (_, enr3) = generate_random_remote_enr();
        let node_id_3 = enr3.node_id();

        let node_addr = NodeAddress {
            enr: enr3.clone(),
            socket_addr: SocketAddr::V4(enr3.udp4_socket().unwrap()),
        };

        service.discovery.put_cached_node_addr(node_addr);

        let found_enr3 = service.find_enr(&node_id_3).unwrap();
        assert_eq!(found_enr3, enr3);
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

        let pool = service.find_content_query_pool.clone();
        let mut pool = pool.write();
        let (query_info, query) = pool
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
    async fn test_find_content_no_nodes() {
        let mut service = task::spawn(build_service());

        let target_content = NodeId::random();
        let target_content_key = IdentityContentKey::new(target_content.raw());
        let (tx, rx) = oneshot::channel();
        let query_id = service.init_find_content_query(target_content_key.clone(), Some(tx), false);

        assert!(query_id.is_none());
        assert!(rx.await.unwrap().is_err());
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

        // update query in own span so mut ref is dropped after poll
        {
            let pool = service.find_content_query_pool.clone();
            let mut pool = pool.write();
            let (_, query) = pool
                .get_mut(query_id)
                .expect("Query pool does not contain query");
            // Poll query to put into waiting state. Otherwise, `on_success` has no effect on the
            // query.
            query.poll(Instant::now());
        }

        // Simulate a response from the bootnode.
        let (_, enr) = generate_random_remote_enr();
        service.advance_find_content_query_with_enrs(
            &query_id,
            bootnode_enr.clone(),
            vec![enr.clone()],
        );

        let mut pool = service.find_content_query_pool.write();
        let (query_info, query) = pool
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

        // update query in own span so mut ref is dropped after poll
        {
            let pool = service.find_content_query_pool.clone();
            let mut pool = pool.write();
            let (_, query) = pool
                .get_mut(query_id)
                .expect("Query pool does not contain query");

            // Poll query to put into waiting state. Otherwise, `on_success` has no effect on the
            // query.
            query.poll(Instant::now());
        }

        // Simulate a response from the bootnode.
        let content: Vec<u8> = vec![0, 1, 2, 3];
        service.advance_find_content_query_with_content(&query_id, bootnode_enr, content.clone());

        let mut pool = service.find_content_query_pool.write();
        let (_, query) = pool
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
    async fn advance_find_content_query_with_connection_id() {
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

        // update query in own span so mut ref is dropped after poll
        {
            let pool = service.find_content_query_pool.clone();
            let mut pool = pool.write();
            let (_, query) = pool
                .get_mut(query_id)
                .expect("Query pool does not contain query");
            // Poll query to put into waiting state. Otherwise, `on_success` has no effect on the
            // query.
            query.poll(Instant::now());
        }

        // Simulate a response from the bootnode.
        let actual_connection_id = 1;
        service.advance_find_content_query_with_connection_id(
            &query_id,
            bootnode_enr,
            actual_connection_id,
        );

        let mut pool = service.find_content_query_pool.write();
        let (_, query) = pool
            .get_mut(query_id)
            .expect("Query pool does not contain query");

        // Query result should contain content.
        match query.clone().into_result() {
            FindContentQueryResult::Utp { connection_id, .. } => {
                assert_eq!(u16::from_be(connection_id), actual_connection_id);
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
                service.find_content_query_pool.clone(),
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
                service.find_content_query_pool.clone(),
            )
            .await;

        // Query event should be `Finished` variant.
        assert!(matches!(query_event, QueryEvent::Finished(_, _, _)));

        service.handle_find_content_query_event(query_event);

        match callback_rx
            .await
            .expect("Expected result on callback channel receiver")
        {
            Ok((result_content, utp_transfer, _)) => {
                assert_eq!(result_content, content);
                assert!(!utp_transfer);
            }
            _ => panic!("Unexpected find content query result type"),
        }
    }

    #[tokio::test]
    async fn test_event_stream() {
        // Get overlay service event stream
        let mut service = task::spawn(build_service());
        let (sender, mut receiver) = broadcast::channel(1);
        service.event_stream = sender;
        // Emit LightClientUpdate event
        service.send_event(OverlayEvent::LightClientOptimisticUpdate, None);
        // Check that the event is received
        let event = receiver.recv().await.unwrap();
        assert_eq!(event.payload, OverlayEvent::LightClientOptimisticUpdate);
    }
}
