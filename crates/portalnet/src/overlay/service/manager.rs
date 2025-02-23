use std::{
    collections::HashMap,
    marker::{PhantomData, Sync},
    sync::Arc,
    task::Poll,
    time::Duration,
};

use anyhow::anyhow;
use bytes::Bytes;
use crossbeam_channel::Sender;
use delay_map::HashSetDelay;
use discv5::{
    enr::NodeId,
    kbucket::{
        ConnectionDirection, ConnectionState, FailureReason, InsertResult, Key, NodeStatus,
        UpdateResult,
    },
    rpc::RequestId,
};
use ethportal_api::{
    generate_random_node_id,
    types::{
        distance::{Distance, Metric},
        enr::{Enr, SszEnr},
        network::Subnetwork,
        portal_wire::{
            Accept, Content, FindContent, FindNodes, Message, Nodes, Offer, OfferTrace,
            PopulatedOffer, Request, Response, MAX_PORTAL_CONTENT_PAYLOAD_SIZE,
            MAX_PORTAL_NODES_ENRS_SIZE,
        },
        query_trace::{QueryFailureKind, QueryTrace},
    },
    utils::bytes::hex_encode_compact,
    OverlayContentKey, RawContentKey, RawContentValue,
};
use futures::{channel::oneshot, future::join_all, prelude::*};
use parking_lot::{Mutex, RwLock};
use rand::Rng;
use smallvec::SmallVec;
use ssz::Encode;
use ssz_types::BitList;
use tokio::{
    sync::{
        broadcast,
        mpsc::{self, UnboundedSender},
    },
    task::JoinHandle,
};
use tracing::{debug, enabled, error, info, trace, warn, Level};
use trin_metrics::overlay::OverlayMetricsReporter;
use trin_storage::{ContentStore, ShouldWeStoreContent};
use trin_validation::validator::Validator;
use utp_rs::cid::ConnectionId;

use super::OverlayService;
use crate::{
    accept_queue::AcceptQueue,
    discovery::{Discovery, UtpPeer},
    events::{EventEnvelope, OverlayEvent},
    find::{
        iterators::{
            findcontent::{
                FindContentQuery, FindContentQueryPending, FindContentQueryResponse,
                FindContentQueryResult, ValidatedContent,
            },
            findnodes::FindNodeQuery,
            query::{Query, QueryConfig},
        },
        query_info::{QueryInfo, QueryType, RecursiveFindContentResult},
        query_pool::{QueryId, QueryPool, QueryPoolState, TargetKey},
    },
    overlay::{
        command::OverlayCommand,
        config::FindContentConfig,
        errors::OverlayRequestError,
        ping_extensions::PingExtension,
        request::{
            ActiveOutgoingRequest, OverlayRequest, OverlayRequestId, OverlayResponse,
            RequestDirection,
        },
    },
    put_content::propagate_put_content_cross_thread,
    types::{
        kbucket::{DiscoveredNodesUpdateResult, Entry, SharedKBucketsTable},
        node::Node,
    },
    utils::portal_wire,
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
        TPingExtensions: 'static + PingExtension + Send + Sync,
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
                    if let Some((_, query)) = self.find_node_query_pool.get_mut(query_id) {
                        query.on_failure(&node_id);
                    }
                }
            }
            QueryEvent::Validating(..) => {
                // This should be an unreachable path
                unimplemented!("A FindNode query unexpectedly tried to validate content");
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
                    if let Some((_, query)) = self.find_node_query_pool.get_mut(query_id) {
                        query.on_failure(&node_id);
                    }
                }
            }
            QueryEvent::Validating(query_id, is_tracing, content_key, query_result) => {
                let query_trace_events_tx = if is_tracing {
                    Some(self.content_query_trace_events_tx.clone())
                } else {
                    None
                };
                match query_result {
                    FindContentQueryPending::NonePending => {
                        // This should be an unreachable path
                        error!("A FindContent query claimed to have some new data to validate, but none was available");
                    }
                    FindContentQueryPending::PendingContent {
                        content,
                        nodes_to_poke,
                        peer,
                        valid_content_tx,
                    } => {
                        let utp_processing = UtpProcessing::from(&*self);
                        tokio::spawn(async move {
                            Self::process_received_content(
                                content,
                                false,
                                content_key,
                                nodes_to_poke,
                                utp_processing,
                                peer,
                                valid_content_tx,
                                query_id,
                                query_trace_events_tx,
                            )
                            .await;
                        });
                    }
                    FindContentQueryPending::Utp {
                        connection_id,
                        peer,
                        nodes_to_poke,
                        valid_content_tx,
                    } => {
                        let source = match self.find_enr(&peer) {
                            Some(enr) => enr,
                            _ => {
                                debug!("Received uTP payload from unknown {peer}");
                                return;
                            }
                        };
                        let utp_processing = UtpProcessing::from(&*self);
                        tokio::spawn(async move {
                            let cid = utp_rs::cid::ConnectionId {
                                recv: connection_id,
                                send: connection_id.wrapping_add(1),
                                peer_id: source.node_id(),
                            };
                            let data = match utp_processing
                                .utp_controller
                                .connect_inbound_stream(cid, UtpPeer(source))
                                .await
                            {
                                Ok(data) => RawContentValue::from(data),
                                Err(e) => {
                                    debug!(
                                        %e,
                                        "Failed to connect to inbound uTP stream for FindContent"
                                    );
                                    // Indicate to the query that the content is invalid
                                    let _ = valid_content_tx.send(None);
                                    if let Some(query_trace_events_tx) = query_trace_events_tx {
                                        let _ =
                                            query_trace_events_tx.send(QueryTraceEvent::Failure(
                                                query_id,
                                                peer,
                                                QueryFailureKind::UtpTransferFailed,
                                            ));
                                    }
                                    return;
                                }
                            };
                            Self::process_received_content(
                                data,
                                true,
                                content_key,
                                nodes_to_poke,
                                utp_processing,
                                peer,
                                valid_content_tx,
                                query_id,
                                query_trace_events_tx,
                            )
                            .await;
                        });
                    }
                };
            }
            QueryEvent::Finished(_, query_info, query)
            | QueryEvent::TimedOut(_, query_info, query) => {
                let callback = match query_info.query_type {
                    QueryType::FindContent { callback, .. } => callback,
                    _ => {
                        error!(
                            "Received wrong QueryType when handling a FindContent Timeout. This is a: {:?}",
                            query_info.query_type
                        );
                        return;
                    }
                };
                match query.into_result() {
                    FindContentQueryResult::ValidContent(valid_content, cancelled_peers) => {
                        let ValidatedContent {
                            content,
                            was_utp_transfer,
                            sending_peer,
                        } = valid_content;

                        let trace = if let Some(mut trace) = query_info.trace {
                            trace.content_validated(sending_peer);
                            trace.cancelled = cancelled_peers;
                            Some(trace)
                        } else {
                            None
                        };

                        if callback
                            .send(Ok((content, was_utp_transfer, trace)))
                            .is_err()
                        {
                            error!(
                                "Failed to send RecursiveFindContent result to the initiator of the query"
                            );
                        }
                    }
                    FindContentQueryResult::NoneFound => {
                        let _ = callback.send(Err(OverlayRequestError::ContentNotFound {
                            message: "Unable to locate content on the network before timeout"
                                .to_string(),
                            utp: false,
                            trace: query_info.trace,
                        }));
                    }
                }
            }
        }
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

    /// Submits outgoing requests to offer `content` to the closest known nodes whose radius
    /// contains `content_key`.
    fn poke_content(
        kbuckets: &SharedKBucketsTable,
        command_tx: UnboundedSender<OverlayCommand<TContentKey>>,
        content_key: TContentKey,
        content: RawContentValue,
        nodes_to_poke: Vec<NodeId>,
        utp_controller: Arc<UtpController>,
    ) {
        let content_id = content_key.content_id();

        let raw_content_key = content_key.to_bytes();

        // Offer content to closest nodes with sufficient radius.
        for node_id in nodes_to_poke.iter() {
            // Look up node in the routing table. We need the ENR and the radius. If we can't find
            // the node, then move on to the next.
            let Some(node) = kbuckets.entry(*node_id).present_or_pending() else {
                continue;
            };

            // If the content is within the node's radius, then offer the node the content.
            let is_within_radius =
                TMetric::distance(&node_id.raw(), &content_id) <= node.data_radius;
            if is_within_radius {
                let content_items: Vec<(RawContentKey, RawContentValue)> =
                    vec![(raw_content_key.clone(), content.clone())];
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

        let mut enrs = self
            .kbuckets
            .nodes_by_distances(self.local_enr(), &request.distances, FIND_NODES_MAX_NODES)
            .into_iter()
            .filter(|enr| {
                // Filter out the source node.
                &enr.node_id() != source
            })
            .map(SszEnr)
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
        let content_key = match TContentKey::try_from_bytes(&request.content_key) {
            Ok(key) => key,
            Err(_) => {
                return Err(OverlayRequestError::InvalidRequest(
                    "Invalid content key".to_string(),
                ))
            }
        };
        match (
            self.store.lock().get(&content_key),
            self.utp_controller.get_outbound_semaphore(),
        ) {
            (Ok(Some(content)), Some(permit)) => {
                if content.len() <= MAX_PORTAL_CONTENT_PAYLOAD_SIZE {
                    Ok(Content::Content(content))
                } else {
                    // Generate a connection ID for the uTP connection.
                    let enr = self.find_enr(source).ok_or_else(|| {
                        OverlayRequestError::AcceptError(
                            "handle_find_content: unable to find ENR for NodeId".to_string(),
                        )
                    })?;
                    let cid = self.utp_controller.cid(enr.node_id(), false);
                    let cid_send = cid.send;

                    // Wait for an incoming connection with the given CID. Then, write the data
                    // over the uTP stream.
                    let utp = Arc::clone(&self.utp_controller);
                    tokio::spawn(async move {
                        utp.accept_outbound_stream(cid, UtpPeer(enr), &content)
                            .await;
                        permit.drop();
                    });

                    // Connection id is sent as BE because uTP header values are stored also as BE
                    Ok(Content::ConnectionId(cid_send.to_be()))
                }
            }
            // If we can't obtain a permit or don't have data to send back, send the requester a
            // list of closer ENRs.
            (Ok(_), None) | (Ok(None), _) => {
                let mut enrs = self
                    .kbuckets
                    .closest_to_content_id::<TMetric>(
                        &content_key.content_id(),
                        FIND_CONTENT_MAX_NODES,
                    )
                    .into_iter()
                    .filter(|enr| &enr.node_id() != source)
                    .map(SszEnr)
                    .collect::<Vec<_>>();
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
            .iter()
            .map(TContentKey::try_from_bytes)
            .collect::<Result<Vec<TContentKey>, _>>()
            .map_err(|_| {
                OverlayRequestError::AcceptError(
                    "Unable to build content key from OFFER request".to_owned(),
                )
            })?;

        let mut accepted_keys: Vec<TContentKey> = Vec::default();

        // if we're unable to find the ENR for the source node we throw an error
        // since the enr is required for the accept queue, and it is expected to be present
        let enr = self.find_enr(source).ok_or_else(|| {
            OverlayRequestError::AcceptError(
                "handle_offer: unable to find ENR for NodeId".to_string(),
            )
        })?;
        for (i, key) in content_keys.iter().enumerate() {
            // Accept content if within radius and not already present in the data store.
            let mut accept = self
                .store
                .lock()
                .is_key_within_radius_and_unavailable(key)
                .map(|value| matches!(value, ShouldWeStoreContent::Store))
                .map_err(|err| {
                    OverlayRequestError::AcceptError(format!(
                        "Unable to check content availability {err}"
                    ))
                })?;
            if accept {
                // accept all keys that are successfully added to the queue
                if self.accept_queue.write().add_key_to_queue(key, &enr) {
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
        let enr_str = if enabled!(Level::TRACE) {
            enr.to_base64()
        } else {
            String::with_capacity(0)
        };
        let cid: ConnectionId<NodeId> = self.utp_controller.cid(enr.node_id(), false);
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
            let peer = UtpPeer(enr);
            let peer_client = peer.client();
            let data = match utp_processing
                .utp_controller
                .accept_inbound_stream(cid, peer)
                .await
            {
                Ok(data) => data,
                Err(err) => {
                    debug!(%err, cid.send, cid.recv, peer = ?peer_client, content_keys = ?content_keys_string, "unable to complete uTP transfer");
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
                    permit.drop();
                    return;
                }
            };

            // Spawn fallback FINDCONTENT tasks for each content key
            // in payloads that failed to be accepted.
            let content_values = match decode_and_validate_content_payload(&accepted_keys, data) {
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
                    permit.drop();
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
            let validated_content: Vec<(TContentKey, RawContentValue)> = join_all(handles)
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
                .flatten()
                .collect();
            propagate_put_content_cross_thread::<_, TMetric>(
                validated_content,
                &utp_processing.kbuckets,
                utp_processing.command_tx.clone(),
                Some(utp_processing.utp_controller),
            );
            // explicitly drop semaphore permit in thread so the permit is moved into the thread
            permit.drop();
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

    // Process ACCEPT response
    fn process_accept(
        &self,
        response: Accept,
        enr: Enr,
        offer: Request,
        request_permit: Option<OwnedTimedSemaphorePermit>,
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
                let _ = tx.send(OfferTrace::Declined);
            }
            return Ok(response);
        }

        // Build a connection ID based on the response.
        let conn_id = u16::from_be(response.connection_id);
        let cid = utp_rs::cid::ConnectionId {
            recv: conn_id,
            send: conn_id.wrapping_add(1),
            peer_id: enr.node_id(),
        };
        let store = Arc::clone(&self.store);
        let response_clone = response.clone();

        let utp_controller = Arc::clone(&self.utp_controller);
        tokio::spawn(async move {
            let peer = UtpPeer(enr);
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
                        peer = ?peer.client(),
                        "Error decoding previously offered content items"
                    );
                    if let Some(tx) = gossip_result_tx {
                        let _ = tx.send(OfferTrace::Failed);
                    }
                    return;
                }
            };

            let content_payload = match portal_wire::encode_content_payload(&content_items) {
                Ok(payload) => payload,
                Err(err) => {
                    warn!(%err, "Unable to build content payload");
                    if let Some(tx) = gossip_result_tx {
                        let _ = tx.send(OfferTrace::Failed);
                    }
                    return;
                }
            };
            let result = utp_controller
                .connect_outbound_stream(cid, peer, &content_payload)
                .await;
            if let Some(tx) = gossip_result_tx {
                if result {
                    let _ = tx.send(OfferTrace::Success(response_clone.content_keys));
                } else {
                    let _ = tx.send(OfferTrace::Failed);
                }
            }
            // explicitly drop permit in the thread so the permit is included in the thread
            if let Some(permit) = request_permit {
                permit.drop();
            }
        });

        Ok(response)
    }

    /// Validates & stores content value received from peer.
    /// Checks if validated content should be stored, and stores it if true
    /// Returns validated content/content dropped from storage to
    /// propagate to other peers.
    // (this step requires a dedicated task since it might require
    // non-blocking requests to this/other overlay networks).
    async fn validate_and_store_content(
        key: TContentKey,
        content_value: RawContentValue,
        utp_processing: UtpProcessing<TValidator, TStore, TContentKey>,
    ) -> Option<Vec<(TContentKey, RawContentValue)>> {
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

        // Collect all content to propagate
        let mut content_to_propagate = vec![(key.clone(), content_value.clone())];
        if let Some(additional_content_to_propagate) =
            validation_result.additional_content_to_propagate
        {
            content_to_propagate.push(additional_content_to_propagate);
        }

        // Check if data should be stored, and store if it is within our radius and not
        // already stored.
        let key_desired = utp_processing
            .store
            .lock()
            .is_key_within_radius_and_unavailable(&key);
        match key_desired {
            Ok(ShouldWeStoreContent::Store) => {
                match utp_processing.store.lock().put(key.clone(), &content_value) {
                    Ok(dropped_content) => {
                        if !dropped_content.is_empty() && utp_processing.gossip_dropped {
                            // add dropped content to validation result, so it will be propagated
                            debug!("Dropped {:?} pieces of content after inserting new content, propagating them back into the network.", dropped_content.len());
                            content_to_propagate.extend(dropped_content.clone());
                        }
                    }
                    Err(err) => warn!(
                        error = %err,
                        content.key = %key.to_hex(),
                        "Error storing accepted content"
                    ),
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
        };
        Some(content_to_propagate)
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
            content_key: content_key.to_bytes(),
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
        let data: RawContentValue = match rx.await? {
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
                            peer_id: fallback_peer.node_id(),
                        };
                        utp_processing
                            .utp_controller
                            .connect_inbound_stream(cid, UtpPeer(fallback_peer.clone()))
                            .await?
                            .into()
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

        propagate_put_content_cross_thread::<_, TMetric>(
            validated_content,
            &utp_processing.kbuckets,
            utp_processing.command_tx.clone(),
            Some(utp_processing.utp_controller),
        );
        Ok(())
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
                    let id = u16::from_be(id);
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
        content: RawContentValue,
        utp_transfer: bool,
        content_key: TContentKey,
        nodes_to_poke: Vec<NodeId>,
        utp_processing: UtpProcessing<TValidator, TStore, TContentKey>,
        sending_peer: NodeId,
        valid_content_callback: Sender<Option<ValidatedContent<NodeId>>>,
        query_id: QueryId,
        query_trace_events_tx: Option<UnboundedSender<QueryTraceEvent>>,
    ) {
        let mut content = content;
        // Operate under assumption that all content in the store is valid
        let local_value = utp_processing.store.lock().get(&content_key);
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
                    // Indicate to the query that the content is invalid
                    let _ = valid_content_callback.send(None);
                    if let Some(query_trace_events_tx) = query_trace_events_tx {
                        let _ = query_trace_events_tx.send(QueryTraceEvent::Failure(
                            query_id,
                            sending_peer,
                            QueryFailureKind::InvalidContent,
                        ));
                    }
                    return;
                }
            };

            // skip storing if content is not valid for storing, the content
            // is already stored or if there's an error reading the store
            let should_store = validation_result.valid_for_storing
                && utp_processing
                    .store
                    .lock()
                    .is_key_within_radius_and_unavailable(&content_key)
                    .map_or_else(
                        |err| {
                            error!("Unable to read store: {err}");
                            false
                        },
                        |val| matches!(val, ShouldWeStoreContent::Store),
                    );
            if should_store {
                match utp_processing
                    .store
                    .lock()
                    .put(content_key.clone(), content.clone())
                {
                    Ok(dropped_content) => {
                        let mut content_to_propagate = vec![(content_key.clone(), content.clone())];
                        if let Some(additional_content_to_propagate) =
                            validation_result.additional_content_to_propagate
                        {
                            content_to_propagate.push(additional_content_to_propagate);
                        }
                        if !dropped_content.is_empty() && utp_processing.gossip_dropped {
                            debug!(
                                "Dropped {:?} pieces of content after inserting new content, propagating them back into the network.",
                                dropped_content.len(),
                            );
                            content_to_propagate.extend(dropped_content.clone());
                        }
                        propagate_put_content_cross_thread::<_, TMetric>(
                            content_to_propagate,
                            &utp_processing.kbuckets,
                            utp_processing.command_tx.clone(),
                            Some(utp_processing.utp_controller.clone()),
                        );
                    }
                    Err(err) => error!(
                        error = %err,
                        content.id = %hex_encode_compact(content_id),
                        content.key = %content_key,
                        "Error storing content"
                    ),
                }
            }
        }

        if valid_content_callback
            .send(Some(ValidatedContent {
                content: content.clone(),
                was_utp_transfer: utp_transfer,
                sending_peer,
            }))
            .is_err()
        {
            warn!("The content query has exited before the returned content could be marked as valid. Perhaps a timeout, or a parallel copy of the content was validated first.");
        }

        if !utp_processing.disable_poke {
            Self::poke_content(
                &utp_processing.kbuckets,
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

    /// Provide the requested content key and content value for the acceptor
    fn provide_requested_content(
        store: Arc<Mutex<TStore>>,
        accept_message: &Accept,
        content_keys_offered: Vec<RawContentKey>,
    ) -> anyhow::Result<Vec<RawContentValue>> {
        let content_keys_offered = content_keys_offered
            .iter()
            .map(TContentKey::try_from_bytes)
            .collect::<Result<Vec<_>, _>>();

        let content_keys_offered: Vec<TContentKey> = content_keys_offered
            .map_err(|_| anyhow!("Unable to decode our own offered content keys"))?;

        let mut content_items: Vec<RawContentValue> = Vec::new();

        for (i, key) in accept_message
            .content_keys
            .clone()
            .iter()
            .zip(content_keys_offered.iter())
        {
            if i {
                match store.lock().get(key) {
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
        if let Some((query_info, query)) = self.find_content_query_pool.get_mut(*query_id) {
            if let Some(trace) = &mut query_info.trace {
                trace.node_responded_with_content(&source);
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
        content: RawContentValue,
    ) {
        let pool = &mut self.find_content_query_pool;
        if let Some((query_info, query)) = pool.get_mut(*query_id) {
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

    /// Starts a FindNode query to find nodes with IDs closest to `target`.
    fn init_find_nodes_query(
        &mut self,
        target: &NodeId,
        callback: Option<oneshot::Sender<Vec<Enr>>>,
    ) {
        let closest_enrs = self
            .kbuckets
            .closest_to_node_id(*target, self.query_num_results);
        if closest_enrs.is_empty() {
            // If there are no nodes whatsoever in the routing table the query cannot proceed.
            warn!("No nodes in routing table, find nodes query cannot proceed.");
            if let Some(callback) = callback {
                let _ = callback.send(vec![]);
            }
            return;
        }

        let query_config = QueryConfig {
            parallelism: self.query_parallelism,
            num_results: self.query_num_results,
            peer_timeout: self.query_peer_timeout,
            overall_timeout: self.query_timeout,
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
        } else {
            let find_nodes_query =
                FindNodeQuery::with_config(query_config, query_info.key(), known_closest_peers);
            let query_id = self
                .find_node_query_pool
                .add_query(query_info, find_nodes_query);
            trace!(
                query.id = %query_id,
                node.id = %hex_encode_compact(target),
                "FindNode query initialized"
            );
        }
    }

    /// Starts a `FindContentQuery` for a target content key.
    fn init_find_content_query(
        &mut self,
        target: TContentKey,
        callback: oneshot::Sender<RecursiveFindContentResult>,
        config: FindContentConfig,
    ) {
        debug!("Starting query for content key: {}", target);

        // Lookup content locally before querying the network.
        if let Ok(Some(content)) = self.store.lock().get(&target) {
            let local_enr = self.local_enr();
            let mut query_trace = QueryTrace::new(&local_enr, target.content_id().into());
            query_trace.node_responded_with_content(&local_enr);
            query_trace.content_validated(local_enr.into());
            let _ = callback.send(Ok((
                RawContentValue::from(content),
                false,
                Some(query_trace),
            )));
            return;
        }

        // Represent the target content ID with a node ID.
        let target_node_id = NodeId::new(&target.content_id());
        let target_key = Key::from(target_node_id);

        let query_config = QueryConfig {
            parallelism: self.query_parallelism,
            num_results: self.query_num_results,
            peer_timeout: self.query_peer_timeout,
            overall_timeout: config.timeout.unwrap_or(self.query_timeout),
        };

        let closest_enrs = self
            .kbuckets
            .closest_to_content_id::<TMetric>(&target.content_id(), query_config.num_results);
        if closest_enrs.is_empty() {
            // If there are no connected nodes in the routing table the query cannot proceed.
            warn!("No connected nodes in routing table, find content query cannot proceed.");
            let _ = callback.send(Err(OverlayRequestError::ContentNotFound {
                message: "Unable to locate content on the network: no connected nodes in the routing table"
                    .to_string(),
                utp: false,
                trace: None,
            }));
            return;
        }

        // Convert ENRs into k-bucket keys.
        let closest_nodes: Vec<Key<NodeId>> = closest_enrs
            .iter()
            .map(|enr| Key::from(enr.node_id()))
            .collect();

        let trace: Option<QueryTrace> = {
            if config.is_trace {
                let mut trace = QueryTrace::new(&self.local_enr(), target_node_id.raw().into());
                let local_enr = self.local_enr();
                trace.node_responded_with(&local_enr, closest_enrs.iter().collect());
                Some(trace)
            } else {
                None
            }
        };

        let query_info = QueryInfo {
            query_type: QueryType::FindContent {
                target: target.clone(),
                callback,
            },
            untrusted_enrs: SmallVec::from_vec(closest_enrs),
            trace,
        };

        let query = FindContentQuery::with_config(query_config, target_key, closest_nodes);
        let query_id = self.find_content_query_pool.add_query(query_info, query);
        trace!(
            query.id = %query_id,
            content.id = %hex_encode_compact(target.content_id()),
            content.key = %target,
            "FindContent query initialized"
        );
    }

    /// Returns an ENR if one is known for the given NodeId.
    pub fn find_enr(&self, node_id: &NodeId) -> Option<Enr> {
        // Check whether we know this node id in our X's Portal Network's routing table.
        if let Some(node) = self.kbuckets.entry(*node_id).present_or_pending() {
            return Some(node.enr);
        }

        // Check whether this node id is in our discv5 routing table
        if let Some(enr) = self.discovery.find_enr(node_id) {
            return Some(enr);
        }

        // Check whether this node id is in our discovery ENR cache
        if let Some(node_addr) = self.discovery.cached_node_addr(node_id) {
            return Some(node_addr.enr);
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
    store: Arc<Mutex<TStore>>,
    metrics: OverlayMetricsReporter,
    kbuckets: SharedKBucketsTable,
    command_tx: UnboundedSender<OverlayCommand<TContentKey>>,
    utp_controller: Arc<UtpController>,
    accept_queue: Arc<RwLock<AcceptQueue<TContentKey>>>,
    disable_poke: bool,
    gossip_dropped: bool,
}

impl<TContentKey, TMetric, TValidator, TStore, TPingExtensions>
    From<&OverlayService<TContentKey, TMetric, TValidator, TStore, TPingExtensions>>
    for UtpProcessing<TValidator, TStore, TContentKey>
where
    TContentKey: OverlayContentKey + Send + Sync,
    TValidator: Validator<TContentKey>,
    TStore: ContentStore<Key = TContentKey>,
    TPingExtensions: PingExtension,
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

fn decode_and_validate_content_payload<TContentKey>(
    accepted_keys: &[TContentKey],
    payload: Bytes,
) -> anyhow::Result<Vec<RawContentValue>> {
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
    Ok(content_values
        .into_iter()
        .map(RawContentValue::from)
        .collect())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::{net::SocketAddr, str::FromStr, time::Instant};

    use alloy::primitives::U256;
    use discv5::kbucket;
    use ethportal_api::types::{
        content_key::overlay::IdentityContentKey,
        distance::XorMetric,
        enr::generate_random_remote_enr,
        ping_extensions::extensions::type_0::ClientInfoRadiusCapabilities,
        portal_wire::{Ping, Pong, MAINNET},
    };
    use kbucket::KBucketsTable;
    use parking_lot::lock_api::Mutex;
    use rstest::*;
    use serial_test::serial;
    use tokio::{
        sync::{mpsc::unbounded_channel, RwLock as TokioRwLock},
        time::timeout,
    };
    use tokio_test::{assert_pending, assert_ready, task};
    use trin_metrics::portalnet::PORTALNET_METRICS;
    use trin_storage::{DistanceFunction, MemoryContentStore};
    use trin_validation::{oracle::HeaderOracle, validator::MockValidator};

    use super::*;
    use crate::{
        config::PortalnetConfig,
        constants::{DEFAULT_DISCOVERY_PORT, DEFAULT_UTP_TRANSFER_LIMIT},
        discovery::{Discovery, NodeAddress},
        overlay::{config::OverlayConfig, ping_extensions::MockPingExtension},
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
        let discovery = Arc::new(Discovery::new(portal_config, MAINNET.clone()).unwrap());

        let header_oracle = HeaderOracle::default();
        let header_oracle = Arc::new(TokioRwLock::new(header_oracle));
        let (_utp_talk_req_tx, utp_talk_req_rx) = unbounded_channel();
        let discv5_utp = crate::discovery::Discv5UdpSocket::new(
            Arc::clone(&discovery),
            utp_talk_req_rx,
            header_oracle,
            50,
        );
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
            payload_type: 0,
            payload: ClientInfoRadiusCapabilities::new(
                data_radius,
                service.ping_extensions.raw_extensions(),
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
            payload_type: 0,
            payload: ClientInfoRadiusCapabilities::new(
                data_radius,
                service.ping_extensions.raw_extensions(),
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
            payload_type: 0,
            payload: ClientInfoRadiusCapabilities::new(
                data_radius,
                service.ping_extensions.raw_extensions(),
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
            payload_type: 0,
            payload: ClientInfoRadiusCapabilities::new(
                data_radius,
                service.ping_extensions.raw_extensions(),
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
