use std::{
    collections::HashMap,
    marker::{PhantomData, Sync},
    sync::Arc,
    task::Poll,
    time::Duration,
};

use delay_map::HashSetDelay;
use discv5::{
    enr::NodeId,
    kbucket::{
        ConnectionDirection, ConnectionState, FailureReason, InsertResult, NodeStatus, UpdateResult,
    },
    rpc::RequestId,
};
use ethportal_api::{
    generate_random_node_id,
    types::{
        distance::{Distance, Metric},
        enr::Enr,
        network::Subnetwork,
        portal_wire::{FindNodes, Message, Request, Response},
        query_trace::QueryFailureKind,
    },
    utils::bytes::hex_encode_compact,
    OverlayContentKey,
};
use futures::prelude::*;
use parking_lot::{Mutex, RwLock};
use rand::Rng;
use ssz::Encode;
use tokio::sync::{
    broadcast,
    mpsc::{self, UnboundedSender},
};
use tracing::{debug, error, info, trace, warn};
use trin_metrics::overlay::OverlayMetricsReporter;
use trin_storage::ContentStore;
use trin_validation::validator::Validator;

use super::OverlayService;
use crate::{
    accept_queue::AcceptQueue,
    discovery::Discovery,
    events::{EventEnvelope, OverlayEvent},
    find::{
        iterators::query::Query,
        query_info::{QueryInfo, QueryType},
        query_pool::{QueryId, QueryPool, QueryPoolState},
    },
    overlay::{
        command::OverlayCommand,
        errors::OverlayRequestError,
        ping_extensions::PingExtensions,
        request::{
            ActiveOutgoingRequest, OverlayRequest, OverlayRequestId, OverlayResponse,
            RequestDirection,
        },
    },
    types::{
        kbucket::{DiscoveredNodesUpdateResult, Entry, SharedKBucketsTable},
        node::Node,
    },
    utp::{controller::UtpController, timed_semaphore::OwnedTimedSemaphorePermit},
};

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

impl<
        TContentKey: 'static + OverlayContentKey + Send + Sync,
        TMetric: Metric + Send + Sync,
        TValidator: 'static + Validator<TContentKey> + Send + Sync,
        TStore: 'static + ContentStore<Key = TContentKey> + Send + Sync,
        TPingExtensions: 'static + PingExtensions + Send + Sync,
    > OverlayService<TContentKey, TMetric, TValidator, TStore, TPingExtensions>
{
    /// Spawns the overlay network service.
    ///
    /// The state of the overlay network largely consists of its routing table. The routing table
    /// is updated according to incoming requests and responses as well as autonomous maintenance
    /// processes.
    #[allow(clippy::too_many_arguments)]
    pub async fn spawn(
        discovery: Arc<Discovery>,
        store: Arc<Mutex<TStore>>,
        kbuckets: SharedKBucketsTable,
        bootnode_enrs: Vec<Enr>,
        ping_queue_interval: Option<Duration>,
        protocol: Subnetwork,
        utp_controller: Arc<UtpController>,
        metrics: OverlayMetricsReporter,
        validator: Arc<TValidator>,
        query_timeout: Duration,
        query_peer_timeout: Duration,
        query_parallelism: usize,
        query_num_results: usize,
        findnodes_query_distances_per_peer: usize,
        disable_poke: bool,
        gossip_dropped: bool,
        ping_extensions: Arc<TPingExtensions>,
    ) -> UnboundedSender<OverlayCommand<TContentKey>> {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let internal_command_tx = command_tx.clone();

        let peers_to_ping = if let Some(interval) = ping_queue_interval {
            HashSetDelay::new(interval)
        } else {
            HashSetDelay::default()
        };

        let (response_tx, response_rx) = mpsc::unbounded_channel();
        let (content_query_trace_events_tx, content_query_trace_events_rx) =
            mpsc::unbounded_channel();
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
                find_node_query_pool: QueryPool::new(),
                find_content_query_pool: QueryPool::new(),
                content_query_trace_events_tx,
                content_query_trace_events_rx,
                query_peer_timeout,
                query_timeout,
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
                gossip_dropped,
                accept_queue: Arc::new(RwLock::new(AcceptQueue::default())),
                ping_extensions,
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
            match self.kbuckets.insert_or_update(node, status) {
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
                        OverlayCommand::FindContentQuery { target, callback, config } => {
                            self.init_find_content_query(target.clone(), callback, config);
                        }
                        OverlayCommand::FindNodeQuery { target, callback } => {
                            self.init_find_nodes_query(&target, Some(callback));
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
                    if let Some(node) = self.kbuckets.entry(node_id).present() {
                        self.ping_node(node);
                        self.peers_to_ping.insert(node_id);
                    }
                }
                query_event = OverlayService::<TContentKey, TMetric, TValidator, TStore, TPingExtensions>::query_event_poll(&mut self.find_node_query_pool) => {
                    self.handle_find_nodes_query_event(query_event);
                }
                // Handle query events for queries in the find content query pool.
                query_event = OverlayService::<TContentKey, TMetric, TValidator, TStore, TPingExtensions>::query_event_poll(&mut self.find_content_query_pool) => {
                    self.handle_find_content_query_event(query_event);
                }
                _ = OverlayService::<TContentKey, TMetric, TValidator, TStore, TPingExtensions>::bucket_maintenance_poll(self.protocol, &self.kbuckets) => {}
                Some(trace_event) = self.content_query_trace_events_rx.recv() => {
                    self.track_content_query_trace_event(trace_event);
                }
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
            // This should be 256
            let buckets_count = self.kbuckets.buckets_count();
            // Randomly pick one of the buckets.
            let bucket = rand::thread_rng()
                .gen_range(buckets_count - EXPECTED_NON_EMPTY_BUCKETS..buckets_count);

            trace!(protocol = %self.protocol, bucket = %bucket, "Refreshing routing table bucket");
            match u8::try_from(bucket) {
                Ok(idx) => generate_random_node_id(idx, self.local_enr().into()),
                Err(err) => {
                    error!(error = %err, "Error downcasting bucket index");
                    return;
                }
            }
        };

        self.init_find_nodes_query(&target_node_id, None);
    }

    /// Returns the local ENR of the node.
    pub(super) fn local_enr(&self) -> Enr {
        self.discovery.local_enr()
    }

    /// Returns the data radius of the node.
    ///
    /// This requires store lock and can block the thread, so it shouldn't be called other lock is
    /// already held.
    pub(super) fn data_radius(&self) -> Distance {
        self.store.lock().radius()
    }

    /// Maintains the routing table.
    ///
    /// Consumes previously applied pending entries from the `KBucketsTable`. An `AppliedPending`
    /// result is recorded when a pending bucket entry replaces a disconnected entry in the
    /// respective bucket.
    async fn bucket_maintenance_poll(protocol: Subnetwork, kbuckets: &SharedKBucketsTable) {
        future::poll_fn(move |_cx| {
            // Drain applied pending entries from the routing table.
            if let Some(entry) = kbuckets.take_applied_pending() {
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
        queries: &mut QueryPool<NodeId, TQuery, TContentKey>,
    ) -> QueryEvent<TQuery, TContentKey> {
        future::poll_fn(move |_cx| match queries.poll() {
            QueryPoolState::Validating(query_id, query_info, query, sending_peer) => {
                // This only happens during a FindContent query.
                let content_key = match &query_info.query_type {
                    QueryType::FindContent { target, .. } => target.clone(),
                    _ => {
                        error!(
                            "Received wrong QueryType when handling new content during FindContent. This is a: {:?}",
                            query_info.query_type
                        );
                        return Poll::Pending;
                    }
                };
                let is_tracing = query_info.trace.is_some();
                // Generate the query result here instead of in handle_find_content_query_event,
                // because the query is only borrowed, and can't be moved to the query event.
                let query_result = query.pending_validation_result(sending_peer);
                Poll::Ready(QueryEvent::Validating(query_id, is_tracing, content_key, query_result))
            }
            // Note that some query pools skip over Validating, straight to Finished (like the
            // FindNode query pool)
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
        }).await
    }

    /// Handles a queued event, used to trace the progress of a content query.
    /// These events can be issued from spawned tasks, such as when processing received content.
    fn track_content_query_trace_event(&mut self, trace_event: QueryTraceEvent) {
        match trace_event {
            QueryTraceEvent::Failure(query_id, node_id, fail_kind) => {
                debug!(
                    protocol = %self.protocol,
                    query.id = %query_id,
                    node_id = %node_id,
                    failure = ?fail_kind,
                    "Peer failed during content query"
                );
                if let Some((query_info, _)) = self.find_content_query_pool.get_mut(query_id) {
                    if let Some(trace) = &mut query_info.trace {
                        trace.node_failed(node_id, fail_kind);
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
                .send_talk_req(destination, protocol, Message::from(request).as_ssz_bytes())
                .await
            {
                Ok(talk_resp) => match Message::try_from(talk_resp.to_vec()) {
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
        let is_node_in_table = self.kbuckets.entry(source).present_or_pending().is_some();

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
                let node = Node::new(node_addr.enr, Distance::MAX);
                self.connect_node(node, ConnectionDirection::Incoming);
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
        request_permit: Option<OwnedTimedSemaphorePermit>,
    ) {
        // If the node is present in the routing table, but the node is not connected, then
        // use the existing entry's value and direction. Otherwise, build a new entry from
        // the source ENR and establish a connection in the outgoing direction, because this
        // node is responding to our request.
        let (node, status) = match self.kbuckets.entry(source.node_id()) {
            Entry::Present(node, node_status) => (node, node_status),
            Entry::Pending(node, node_status) => (node, node_status),
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

    /// Update the recorded radius of a node in our routing table.
    pub(super) fn update_node(&self, node: Node) {
        let node_id = node.enr.node_id();

        if let UpdateResult::Failed(_) = self.kbuckets.update_node(node, None) {
            error!(
                "Failed to update radius of node {}",
                hex_encode_compact(node_id.raw())
            );
        };
    }

    /// Processes a collection of discovered nodes.
    pub(super) fn process_discovered_enrs(&mut self, enrs: Vec<Enr>) {
        let local_node_id = self.local_enr().node_id();

        // Ignore outself
        let enrs = enrs
            .into_iter()
            .filter(|enr| enr.node_id() != local_node_id);

        let DiscoveredNodesUpdateResult {
            inserted_nodes,
            removed_nodes,
        } = self.kbuckets.insert_or_update_discovered_nodes(enrs);

        for node_id in inserted_nodes {
            self.peers_to_ping.insert(node_id);
        }
        for node_id in removed_nodes {
            self.peers_to_ping.remove(&node_id);
        }
    }

    /// Submits a request for the node info of a destination (target) node.
    pub(super) fn request_node(&self, destination: &Enr) {
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
        let node_id = node.enr.node_id();
        let status = NodeStatus {
            state: ConnectionState::Connected,
            direction: connection_direction,
        };

        match self.kbuckets.insert_or_update(node, status) {
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
                if let Some(node) = self.kbuckets.entry(disconnected.into_preimage()).present() {
                    self.ping_node(node);
                }
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
    }

    /// Attempts to update the connection state of a node.
    fn update_node_connection_state(
        &mut self,
        node_id: NodeId,
        state: ConnectionState,
    ) -> Result<(), FailureReason> {
        match self.kbuckets.update_node_status(node_id, state, None) {
            UpdateResult::Failed(reason) => {
                if reason != FailureReason::KeyNonExistent {
                    warn!(
                        protocol = %self.protocol,
                        peer = %node_id,
                        error = ?reason,
                        "Error updating node connection state",
                    );
                }
                Err(reason)
            }
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

    /// Returns an ENR if one is known for the given NodeId.
    pub fn find_enr(&self, node_id: &NodeId) -> Option<Enr> {
        // Check whether this node id is in our enr_session_cache or discv5 routing table
        if let Some(enr) = self.discovery.find_enr(node_id) {
            return Some(enr);
        }

        // Check whether we know this node id in our X's Portal Network's routing table.
        if let Some(node) = self.kbuckets.entry(*node_id).present_or_pending() {
            return Some(node.enr);
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

    /// Send `OverlayEvent` to the event stream.
    #[allow(dead_code)] // TODO: remove when used
    fn send_event(&self, event: OverlayEvent, to: Option<Vec<Subnetwork>>) {
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
pub enum QueryEvent<TQuery: Query<NodeId>, TContentKey> {
    /// The query is waiting for a peer to be contacted.
    Waiting(QueryId, NodeId, Request),
    /// The query has timed out, possible returning peers.
    TimedOut(QueryId, QueryInfo<TContentKey>, TQuery),
    /// The query is working to validate the response.
    /// The bool argument indicates whether this query traces events.
    Validating(QueryId, bool, TContentKey, TQuery::PendingValidationResult),
    /// The query has completed successfully.
    Finished(QueryId, QueryInfo<TContentKey>, TQuery),
}

pub enum QueryTraceEvent {
    /// The interaction with a particular node had a fatal failure
    Failure(QueryId, NodeId, QueryFailureKind),
}

/// References to `OverlayService` components required for processing
/// a utp stream. This is basically a utility struct to avoid passing
/// around a large number of individual references.
pub(super) struct UtpProcessing<TValidator, TStore, TContentKey>
where
    TContentKey: OverlayContentKey + Send + Sync,
    TValidator: Validator<TContentKey>,
    TStore: ContentStore<Key = TContentKey>,
{
    pub validator: Arc<TValidator>,
    pub store: Arc<Mutex<TStore>>,
    pub metrics: OverlayMetricsReporter,
    pub kbuckets: SharedKBucketsTable,
    pub command_tx: UnboundedSender<OverlayCommand<TContentKey>>,
    pub utp_controller: Arc<UtpController>,
    pub accept_queue: Arc<RwLock<AcceptQueue<TContentKey>>>,
    pub disable_poke: bool,
    pub gossip_dropped: bool,
}

impl<TContentKey, TMetric, TValidator, TStore, TPingExtensions>
    From<&OverlayService<TContentKey, TMetric, TValidator, TStore, TPingExtensions>>
    for UtpProcessing<TValidator, TStore, TContentKey>
where
    TContentKey: OverlayContentKey + Send + Sync,
    TValidator: Validator<TContentKey>,
    TStore: ContentStore<Key = TContentKey>,
    TPingExtensions: PingExtensions,
{
    fn from(
        service: &OverlayService<TContentKey, TMetric, TValidator, TStore, TPingExtensions>,
    ) -> Self {
        Self {
            validator: Arc::clone(&service.validator),
            store: Arc::clone(&service.store),
            metrics: service.metrics.clone(),
            kbuckets: service.kbuckets.clone(),
            command_tx: service.command_tx.clone(),
            utp_controller: Arc::clone(&service.utp_controller),
            accept_queue: Arc::clone(&service.accept_queue),
            disable_poke: service.disable_poke,
            gossip_dropped: service.gossip_dropped,
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
            kbuckets: self.kbuckets.clone(),
            command_tx: self.command_tx.clone(),
            utp_controller: Arc::clone(&self.utp_controller),
            accept_queue: Arc::clone(&self.accept_queue),
            disable_poke: self.disable_poke,
            gossip_dropped: self.gossip_dropped,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::{net::SocketAddr, str::FromStr, time::Instant};

    use alloy::primitives::U256;
    use discv5::kbucket;
    use ethportal_api::{
        types::{
            content_key::overlay::IdentityContentKey,
            distance::XorMetric,
            enr::generate_random_remote_enr,
            ping_extensions::{
                extension_types::PingExtensionType,
                extensions::type_0::ClientInfoRadiusCapabilities,
            },
            portal_wire::{Ping, Pong},
        },
        RawContentValue,
    };
    use futures::channel::oneshot;
    use kbucket::KBucketsTable;
    use parking_lot::lock_api::Mutex;
    use rstest::*;
    use serial_test::serial;
    use tokio::{sync::mpsc::unbounded_channel, time::timeout};
    use tokio_test::{assert_pending, assert_ready, task};
    use trin_metrics::portalnet::PORTALNET_METRICS;
    use trin_storage::{DistanceFunction, MemoryContentStore};
    use trin_validation::validator::MockValidator;

    use super::*;
    use crate::{
        config::PortalnetConfig,
        constants::{DEFAULT_DISCOVERY_PORT, DEFAULT_UTP_TRANSFER_LIMIT},
        discovery::{Discovery, NodeAddress},
        find::iterators::findcontent::{FindContentQueryPending, FindContentQueryResult},
        overlay::{
            config::{FindContentConfig, OverlayConfig},
            ping_extensions::MockPingExtension,
        },
    };

    macro_rules! poll_command_rx {
        ($service:ident) => {
            $service.enter(|cx, mut service| service.command_rx.poll_recv(cx))
        };
    }

    fn build_service() -> OverlayService<
        IdentityContentKey,
        XorMetric,
        MockValidator,
        MemoryContentStore,
        MockPingExtension,
    > {
        let portal_config = PortalnetConfig {
            no_stun: true,
            no_upnp: true,
            ..Default::default()
        };
        let discovery = Arc::new(Discovery::new(portal_config).unwrap());

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
        let store = Arc::new(Mutex::new(store));

        let overlay_config = OverlayConfig::default();
        let kbuckets = SharedKBucketsTable::new(KBucketsTable::new(
            node_id.into(),
            overlay_config.bucket_pending_timeout,
            overlay_config.max_incoming_per_bucket,
            overlay_config.table_filter,
            overlay_config.bucket_filter,
        ));

        let protocol = Subnetwork::History;
        let active_outgoing_requests = Arc::new(RwLock::new(HashMap::new()));
        let peers_to_ping = HashSetDelay::default();
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (response_tx, response_rx) = mpsc::unbounded_channel();
        let (content_query_trace_events_tx, content_query_trace_events_rx) =
            mpsc::unbounded_channel();
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
            find_node_query_pool: QueryPool::new(),
            find_content_query_pool: QueryPool::new(),
            content_query_trace_events_tx,
            content_query_trace_events_rx,
            query_peer_timeout: overlay_config.query_peer_timeout,
            query_timeout: overlay_config.query_timeout,
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
            gossip_dropped: false,
            accept_queue,
            ping_extensions: Arc::new(MockPingExtension {}),
        }
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn process_ping_source_in_table_higher_enr_seq() {
        let mut service = task::spawn(build_service());

        let (_, source) = generate_random_remote_enr();
        let node_id = source.node_id();
        let status = NodeStatus {
            state: ConnectionState::Connected,
            direction: ConnectionDirection::Outgoing,
        };

        let data_radius = Distance::MAX;
        let node = Node::new(source.clone(), data_radius);

        let _ = service.kbuckets.insert_or_update(node, status);

        let ping = Ping {
            enr_seq: source.seq() + 1,
            payload_type: PingExtensionType::Capabilities,
            payload: ClientInfoRadiusCapabilities::new(
                data_radius,
                service.ping_extensions.supported_extensions().to_vec(),
            )
            .into(),
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
            payload_type: PingExtensionType::Capabilities,
            payload: ClientInfoRadiusCapabilities::new(
                data_radius,
                service.ping_extensions.supported_extensions().to_vec(),
            )
            .into(),
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
        let status = NodeStatus {
            state: ConnectionState::Connected,
            direction: ConnectionDirection::Outgoing,
        };

        let node = Node::new(destination.clone(), Distance::MAX);

        let _ = service.kbuckets.insert_or_update(node, status);
        service.peers_to_ping.insert(node_id);

        assert!(service.peers_to_ping.contains_key(&node_id));

        assert!(service.kbuckets.entry(node_id).present().is_some());

        let request_id = rand::random();
        let error = OverlayRequestError::Timeout;
        service.process_request_failure(request_id, destination, error);

        assert!(!service.peers_to_ping.contains_key(&node_id));

        match service.kbuckets.entry(node_id) {
            Entry::Present(_, status) => {
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
        let status = NodeStatus {
            state: ConnectionState::Connected,
            direction: ConnectionDirection::Outgoing,
        };

        let data_radius = Distance::MAX;
        let node = Node::new(source.clone(), data_radius);

        let _ = service.kbuckets.insert_or_update(node, status);

        let pong = Pong {
            enr_seq: source.seq() + 1,
            payload_type: PingExtensionType::Capabilities,
            payload: ClientInfoRadiusCapabilities::new(
                data_radius,
                service.ping_extensions.supported_extensions().to_vec(),
            )
            .into(),
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
            payload_type: PingExtensionType::Capabilities,
            payload: ClientInfoRadiusCapabilities::new(
                data_radius,
                service.ping_extensions.supported_extensions().to_vec(),
            )
            .into(),
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
        assert!(matches!(
            service.kbuckets.entry(local_enr.node_id()),
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

        // Check routing table for first ENR.
        // Node should be present in a disconnected state in the outgoing direction.
        match service.kbuckets.entry(enr1.node_id()) {
            Entry::Present(_node, status) => {
                assert_eq!(ConnectionState::Disconnected, status.state);
                assert_eq!(ConnectionDirection::Outgoing, status.direction);
            }
            _ => panic!(),
        };

        // Check routing table for second ENR.
        // Node should be present in a disconnected state in the outgoing direction.
        match service.kbuckets.entry(enr2.node_id()) {
            Entry::Present(_node, status) => {
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

        let node_id_1 = enr1.node_id();
        let node_id_2 = enr2.node_id();

        let status = NodeStatus {
            state: ConnectionState::Connected,
            direction: ConnectionDirection::Outgoing,
        };
        let data_radius = Distance::MAX;

        let node1 = Node::new(enr1.clone(), data_radius);
        let node2 = Node::new(enr2.clone(), data_radius);

        // Insert nodes into routing table.
        let _ = service.kbuckets.insert_or_update(node1, status);
        assert!(service.kbuckets.entry(node_id_1).present().is_some(),);
        let _ = service.kbuckets.insert_or_update(node2, status);
        assert!(service.kbuckets.entry(node_id_2).present().is_some());

        // Modify first ENR to increment sequence number.
        let updated_udp: u16 = DEFAULT_DISCOVERY_PORT;
        let _ = enr1.set_udp4(updated_udp, &sk1);
        assert_ne!(1, enr1.seq());

        let enrs: Vec<Enr> = vec![enr1, enr2];
        service.process_discovered_enrs(enrs);

        // Check routing table for first ENR.
        // Node should be present with ENR sequence number equal to 2.
        match service.kbuckets.entry(node_id_1).present() {
            Some(node) => assert_eq!(2, node.enr.seq()),
            _ => panic!(),
        };

        // Check routing table for second ENR.
        // Node should be present with ENR sequence number equal to 1.
        match service.kbuckets.entry(node_id_2).present() {
            Some(node) => assert_eq!(1, node.enr.seq()),
            _ => panic!(),
        };
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn poke_content() {
        let mut service = task::spawn(build_service());

        let content_key = IdentityContentKey::new(service.local_enr().node_id().raw());
        let content = RawContentValue::from_str("0xef").unwrap();

        let status = NodeStatus {
            state: ConnectionState::Connected,
            direction: ConnectionDirection::Outgoing,
        };

        let (_, enr) = generate_random_remote_enr();
        let peer = Node::new(enr.clone(), Distance::MAX);
        let _ = service.kbuckets.insert_or_update(peer.clone(), status);

        let peer_node_ids: Vec<NodeId> = vec![peer.enr.node_id()];

        // Node has maximum radius, so there should be one offer in the channel.
        OverlayService::<
            IdentityContentKey,
            XorMetric,
            MockValidator,
            MemoryContentStore,
            MockPingExtension,
        >::poke_content(
            &service.kbuckets,
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
        let content = RawContentValue::from_str("0xef").unwrap();

        let (_, enr1) = generate_random_remote_enr();
        let (_, enr2) = generate_random_remote_enr();
        let peers = [enr1, enr2];
        let peer_node_ids: Vec<NodeId> = peers.iter().map(|p| p.node_id()).collect();

        // No nodes in the routing table, so no commands should be in the channel.
        OverlayService::<
            IdentityContentKey,
            XorMetric,
            MockValidator,
            MemoryContentStore,
            MockPingExtension,
        >::poke_content(
            &service.kbuckets,
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
        let content = RawContentValue::from_str("0xef").unwrap();

        let status = NodeStatus {
            state: ConnectionState::Connected,
            direction: ConnectionDirection::Outgoing,
        };

        // The first node has a maximum radius, so the content SHOULD be offered.
        let (_, enr1) = generate_random_remote_enr();
        let peer1 = Node::new(enr1.clone(), Distance::MAX);
        let _ = service.kbuckets.insert_or_update(peer1.clone(), status);

        // The second node has a radius of zero, so the content SHOULD NOT not be offered.
        let (_, enr2) = generate_random_remote_enr();
        let peer2 = Node::new(enr2.clone(), Distance::from(U256::ZERO));
        let _ = service.kbuckets.insert_or_update(peer2.clone(), status);

        let peers = vec![peer1.clone(), peer2];
        let peer_node_ids: Vec<NodeId> = peers.iter().map(|p| p.enr.node_id()).collect();

        // One offer should be in the channel for the maximum radius node.
        OverlayService::<
            IdentityContentKey,
            XorMetric,
            MockValidator,
            MemoryContentStore,
            MockPingExtension,
        >::poke_content(
            &service.kbuckets,
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
        service.ping_node(Node::new(destination.clone(), Distance::MAX));

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

        let data_radius = Distance::MAX;
        let node = Node::new(enr, data_radius);
        let connection_direction = ConnectionDirection::Outgoing;

        assert!(!service.peers_to_ping.contains_key(&node_id));
        assert!(matches!(service.kbuckets.entry(node_id), Entry::Absent));

        service.connect_node(node, connection_direction);

        assert!(service.peers_to_ping.contains_key(&node_id));

        match service.kbuckets.entry(node_id) {
            Entry::Present(_node, status) => {
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

        let data_radius = Distance::MAX;
        let node = Node::new(enr, data_radius);

        let connection_direction = ConnectionDirection::Outgoing;
        let status = NodeStatus {
            state: ConnectionState::Disconnected,
            direction: connection_direction,
        };

        let _ = service.kbuckets.insert_or_update(node, status);

        match service.kbuckets.entry(node_id) {
            Entry::Present(_node, status) => {
                assert_eq!(ConnectionState::Disconnected, status.state);
                assert_eq!(connection_direction, status.direction);
            }
            _ => panic!(),
        };

        let _ = service.update_node_connection_state(node_id, ConnectionState::Connected);

        match service.kbuckets.entry(node_id) {
            Entry::Present(_node, status) => {
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

        let data_radius = Distance::MAX;
        let node = Node::new(enr, data_radius);

        let connection_direction = ConnectionDirection::Outgoing;
        let status = NodeStatus {
            state: ConnectionState::Connected,
            direction: connection_direction,
        };

        let _ = service.kbuckets.insert_or_update(node, status);

        match service.kbuckets.entry(node_id) {
            Entry::Present(_node, status) => {
                assert_eq!(ConnectionState::Connected, status.state);
                assert_eq!(connection_direction, status.direction);
            }
            _ => panic!(),
        };

        let _ = service.update_node_connection_state(node_id, ConnectionState::Disconnected);

        match service.kbuckets.entry(node_id) {
            Entry::Present(_node, status) => {
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
        use ethportal_api::{types::portal_wire::MAX_PORTAL_NODES_ENRS_SIZE, SszEnr};

        use crate::overlay::service::utils::pop_while_ssz_bytes_len_gt;

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

        service.add_bootnodes(bootnodes, true);

        // Initialize the query and call `poll` so that it starts
        service.init_find_nodes_query(&target_node_id, None);
        let _ = service.find_node_query_pool.poll();

        let expected_distances_per_peer = service.findnodes_query_distances_per_peer;
        let pool = &mut service.find_node_query_pool;
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
                assert_eq!(distances_to_request, expected_distances_per_peer);
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
            MockPingExtension,
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
            MockPingExtension,
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
            MockPingExtension,
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
            MockPingExtension,
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

        service.add_bootnodes(bootnodes, true);

        service.init_find_nodes_query(&target_node_id, None);

        let _event = OverlayService::<
            IdentityContentKey,
            XorMetric,
            MockValidator,
            MemoryContentStore,
            MockPingExtension,
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

        let data_radius = Distance::MAX;
        let bootnode = Node::new(bootnode_enr.clone(), data_radius);

        let connection_direction = ConnectionDirection::Outgoing;
        let status = NodeStatus {
            state: ConnectionState::Connected,
            direction: connection_direction,
        };

        let _ = service.kbuckets.insert_or_update(bootnode, status);

        let target_content = NodeId::random();
        let target_content_key = IdentityContentKey::new(target_content.raw());

        let (tx, _rx) = oneshot::channel();
        service.init_find_content_query(
            target_content_key.clone(),
            tx,
            FindContentConfig::default(),
        );
        let query_id = QueryId(0); // default query id for all initial queries

        let pool = &mut service.find_content_query_pool;
        let (query_info, query) = pool
            .get_mut(query_id)
            .expect("Query pool does not contain query");

        // Query info should contain the corresponding target content key.
        assert!(matches!(
            &query_info.query_type,
            QueryType::FindContent {
                target: _target_content_key,
                callback: _callback,
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
        service.init_find_content_query(
            target_content_key.clone(),
            tx,
            FindContentConfig::default(),
        );

        let query = service.find_content_query_pool.iter().next();
        assert!(query.is_none());
        assert!(rx.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn advance_find_content_query_with_enrs() {
        let mut service = task::spawn(build_service());

        let (_, bootnode_enr) = generate_random_remote_enr();

        let data_radius = Distance::MAX;
        let bootnode = Node::new(bootnode_enr.clone(), data_radius);

        let connection_direction = ConnectionDirection::Outgoing;
        let status = NodeStatus {
            state: ConnectionState::Connected,
            direction: connection_direction,
        };

        let _ = service.kbuckets.insert_or_update(bootnode, status);

        let target_content = NodeId::random();
        let target_content_key = IdentityContentKey::new(target_content.raw());

        let (tx, _rx) = oneshot::channel();
        service.init_find_content_query(target_content_key, tx, FindContentConfig::default());
        let query_id = QueryId(0); // default query id for all initial queries

        // update query in own span so mut ref is dropped after poll
        {
            let pool = &mut service.find_content_query_pool;
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

        let pool = &mut service.find_content_query_pool;
        let (query_info, query) = pool
            .get_mut(query_id)
            .expect("Query pool does not contain query");

        // Query info should contain the "discovered" ENR.
        assert!(query_info.untrusted_enrs.contains(&enr));

        match query.clone().into_result() {
            FindContentQueryResult::NoneFound => {}
            _ => panic!("Unexpected find content query result"),
        }
    }

    #[tokio::test]
    async fn advance_find_content_query_with_content() {
        let mut service = task::spawn(build_service());

        let (_, bootnode_enr) = generate_random_remote_enr();
        let bootnode_node_id = bootnode_enr.node_id();

        let data_radius = Distance::MAX;
        let bootnode = Node::new(bootnode_enr.clone(), data_radius);

        let connection_direction = ConnectionDirection::Outgoing;
        let status = NodeStatus {
            state: ConnectionState::Connected,
            direction: connection_direction,
        };

        let _ = service.kbuckets.insert_or_update(bootnode, status);

        let target_content = NodeId::random();
        let target_content_key = IdentityContentKey::new(target_content.raw());

        let (tx, _rx) = oneshot::channel();
        service.init_find_content_query(target_content_key, tx, FindContentConfig::default());
        let query_id = QueryId(0); // default query id for all initial queries

        // update query in own span so mut ref is dropped after poll
        {
            let pool = &mut service.find_content_query_pool;
            let (_, query) = pool
                .get_mut(query_id)
                .expect("Query pool does not contain query");

            // Poll query to put into waiting state. Otherwise, `on_success` has no effect on the
            // query.
            query.poll(Instant::now());
        }

        // Simulate a response from the bootnode.
        let content = RawContentValue::from_str("0x00010203").unwrap();
        service.advance_find_content_query_with_content(&query_id, bootnode_enr, content.clone());

        let pool = &mut service.find_content_query_pool;
        let (_, query) = pool
            .get_mut(query_id)
            .expect("Query pool does not contain query");

        // Query result should contain content.
        match query.pending_validation_result(bootnode_node_id) {
            FindContentQueryPending::PendingContent {
                content: pending_content,
                peer,
                ..
            } => {
                assert_eq!(pending_content, content);
                assert_eq!(peer, bootnode_node_id);
            }
            result => panic!("Unexpected find content query result: {result:?}"),
        }
    }

    #[tokio::test]
    async fn advance_find_content_query_with_connection_id() {
        let mut service = task::spawn(build_service());

        let (_, bootnode_enr) = generate_random_remote_enr();
        let bootnode_node_id = bootnode_enr.node_id();

        let data_radius = Distance::MAX;
        let bootnode = Node::new(bootnode_enr.clone(), data_radius);

        let connection_direction = ConnectionDirection::Outgoing;
        let status = NodeStatus {
            state: ConnectionState::Connected,
            direction: connection_direction,
        };

        let _ = service.kbuckets.insert_or_update(bootnode, status);

        let target_content = NodeId::random();
        let target_content_key = IdentityContentKey::new(target_content.raw());

        let (tx, _rx) = oneshot::channel();
        service.init_find_content_query(target_content_key, tx, FindContentConfig::default());
        let query_id = QueryId(0); // default query id for all initial queries

        // update query in own span so mut ref is dropped after poll
        {
            let pool = &mut service.find_content_query_pool;
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

        let pool = &mut service.find_content_query_pool;
        let (_, query) = pool
            .get_mut(query_id)
            .expect("Query pool does not contain query");

        // Query result should contain connection ID
        match query.pending_validation_result(bootnode_node_id) {
            FindContentQueryPending::Utp {
                connection_id,
                peer,
                ..
            } => {
                assert_eq!(connection_id, actual_connection_id);
                assert_eq!(peer, bootnode_node_id);
            }
            result => panic!("Unexpected find content query result: {result:?}"),
        }
    }

    #[test_log::test(tokio::test)]
    async fn handle_find_content_query_event() {
        let mut service = task::spawn(build_service());

        let (_, bootnode_enr) = generate_random_remote_enr();

        let data_radius = Distance::MAX;
        let bootnode = Node::new(bootnode_enr.clone(), data_radius);

        let connection_direction = ConnectionDirection::Outgoing;
        let status = NodeStatus {
            state: ConnectionState::Connected,
            direction: connection_direction,
        };

        let _ = service.kbuckets.insert_or_update(bootnode, status);

        let target_content = NodeId::random();
        let target_content_key = IdentityContentKey::new(target_content.raw());

        let (callback_tx, callback_rx) = oneshot::channel();
        service.init_find_content_query(
            target_content_key.clone(),
            callback_tx,
            FindContentConfig::default(),
        );
        let query_id = QueryId(0); // default query id for all initial queries

        let query_event = OverlayService::<
            _,
            XorMetric,
            MockValidator,
            MemoryContentStore,
            MockPingExtension,
        >::query_event_poll(&mut service.find_content_query_pool)
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
        let content = RawContentValue::from_str("0x00010203").unwrap();
        service.advance_find_content_query_with_content(
            &query_id,
            bootnode_enr.clone(),
            content.clone(),
        );

        let query_event = OverlayService::<
            _,
            XorMetric,
            MockValidator,
            MemoryContentStore,
            MockPingExtension,
        >::query_event_poll(&mut service.find_content_query_pool)
        .await;

        // Query event should be `Validating` variant.
        assert!(matches!(query_event, QueryEvent::Validating(..)));

        service.handle_find_content_query_event(query_event);

        // Poll until content is validated
        let mut attempts_left = 5;
        let query_event = loop {
            let polled =
                timeout(
                    Duration::from_millis(10),
                    OverlayService::<
                        _,
                        XorMetric,
                        MockValidator,
                        MemoryContentStore,
                        MockPingExtension,
                    >::query_event_poll(&mut service.find_content_query_pool),
                )
                .await;
            if let Ok(query_event) = polled {
                break query_event;
            }
            attempts_left -= 1;
            if attempts_left == 0 {
                panic!("Timeout waiting for Finished query event, after validation");
            }
        };

        // Query event should be `Finished` variant.
        assert!(matches!(query_event, QueryEvent::Finished(..)));

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
