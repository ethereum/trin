pub mod manager;
pub mod ping;

use std::{collections::HashMap, marker::PhantomData, sync::Arc, time::Duration};

use delay_map::HashSetDelay;
use discv5::enr::NodeId;
use ethportal_api::{types::network::Subnetwork, OverlayContentKey};
use manager::QueryTraceEvent;
use parking_lot::{Mutex, RwLock};
use tokio::sync::{
    broadcast,
    mpsc::{UnboundedReceiver, UnboundedSender},
};
use trin_metrics::overlay::OverlayMetricsReporter;

use crate::{
    accept_queue::AcceptQueue,
    discovery::Discovery,
    events::EventEnvelope,
    find::{
        iterators::{findcontent::FindContentQuery, findnodes::FindNodeQuery},
        query_pool::QueryPool,
    },
    overlay::{
        command::OverlayCommand,
        request::{ActiveOutgoingRequest, OverlayRequestId, OverlayResponse},
    },
    types::kbucket::SharedKBucketsTable,
    utp::controller::UtpController,
};

/// The overlay service.
pub struct OverlayService<TContentKey, TMetric, TValidator, TStore, TPingExtensions>
where
    TContentKey: OverlayContentKey,
{
    /// The underlying Discovery v5 protocol.
    discovery: Arc<Discovery>,
    /// The content database of the local node.
    store: Arc<Mutex<TStore>>,

    /// The routing table of the local node.
    kbuckets: SharedKBucketsTable,
    /// The protocol identifier.
    protocol: Subnetwork,
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
    /// A channel for recording events related to content queries.
    content_query_trace_events_tx: UnboundedSender<QueryTraceEvent>,
    content_query_trace_events_rx: UnboundedReceiver<QueryTraceEvent>,
    /// Timeout after which a peer in an ongoing query is marked unresponsive.
    query_peer_timeout: Duration,
    /// Timeout for each complete query
    query_timeout: Duration,
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
    /// Gossip content as it gets dropped from local storage
    gossip_dropped: bool,
    /// Accept Queue for inbound content keys
    accept_queue: Arc<RwLock<AcceptQueue<TContentKey>>>,
    /// Ping extensions for the overlay network.
    ping_extensions: Arc<TPingExtensions>,
}
