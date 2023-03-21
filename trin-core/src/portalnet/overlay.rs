use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::{Debug, Display},
    marker::{PhantomData, Sync},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use anyhow::anyhow;
use discv5::{
    enr::NodeId,
    kbucket,
    kbucket::{Filter, KBucketsTable, NodeStatus, MAX_NODES_PER_BUCKET},
    TalkRequest,
};
use futures::{channel::oneshot, future::join_all};
use parking_lot::RwLock;
use rand::seq::IteratorRandom;
use ssz::Encode;
use tokio::{sync::mpsc::UnboundedSender, task::JoinHandle};
use tracing::{debug, error, info, warn};

use crate::{
    portalnet::{
        discovery::Discovery,
        overlay_service::{
            OverlayCommand, OverlayRequest, OverlayRequestError, OverlayService, RequestDirection,
        },
        storage::ContentStore,
        types::{
            messages::{
                Accept, Content, CustomPayload, FindContent, FindNodes, Message, Nodes, Offer,
                Ping, Pong, PopulatedOffer, ProtocolId, Request, Response,
            },
            node::Node,
        },
    },
    utils::portal_wire,
    utp::{
        stream::{UtpListenerEvent, UtpListenerRequest, UtpPayload, UtpStream, BUF_SIZE},
        trin_helpers::UtpStreamId,
    },
};
use ethportal_api::types::content_key::{OverlayContentKey, RawContentKey};
use trin_types::distance::{Distance, Metric, XorMetric};
use trin_types::enr::Enr;
use trin_utils::bytes::hex_encode;
use trin_validation::validator::Validator;

/// Configuration parameters for the overlay network.
#[derive(Clone)]
pub struct OverlayConfig {
    pub bootnode_enrs: Vec<Enr>,
    pub bucket_pending_timeout: Duration,
    pub max_incoming_per_bucket: usize,
    pub table_filter: Option<Box<dyn Filter<Node>>>,
    pub bucket_filter: Option<Box<dyn Filter<Node>>>,
    pub ping_queue_interval: Option<Duration>,
    pub enable_metrics: bool,
    pub query_parallelism: usize,
    pub query_timeout: Duration,
    pub query_peer_timeout: Duration,
    pub query_num_results: usize,
    pub findnodes_query_distances_per_peer: usize,
}

impl Default for OverlayConfig {
    fn default() -> Self {
        Self {
            bootnode_enrs: vec![],
            bucket_pending_timeout: Duration::from_secs(60),
            max_incoming_per_bucket: 16,
            table_filter: None,
            bucket_filter: None,
            ping_queue_interval: None,
            enable_metrics: false,
            query_parallelism: 3, // (recommended α from kademlia paper)
            query_peer_timeout: Duration::from_secs(10),
            query_timeout: Duration::from_secs(60),
            query_num_results: MAX_NODES_PER_BUCKET,
            findnodes_query_distances_per_peer: 3,
        }
    }
}

/// Overlay protocol is a layer on top of discv5 that handles all requests from the overlay networks
/// (state, history etc.) and dispatch them to the discv5 protocol TalkReq. Each network should
/// implement the overlay protocol and the overlay protocol is where we can encapsulate the logic for
/// handling common network requests/responses.
#[derive(Clone)]
pub struct OverlayProtocol<TContentKey, TMetric, TValidator, TStore> {
    /// Reference to the underlying discv5 protocol
    pub discovery: Arc<Discovery>,
    /// The data store.
    pub store: Arc<RwLock<TStore>>,
    /// The data radius of the local node.
    pub data_radius: Arc<Distance>,
    /// The overlay routing table of the local node.
    kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
    /// The subnetwork protocol of the overlay.
    protocol: ProtocolId,
    /// A sender to send commands to the OverlayService.
    command_tx: UnboundedSender<OverlayCommand<TContentKey>>,
    /// A sender to send request to UtpListener
    utp_listener_tx: UnboundedSender<UtpListenerRequest>,
    /// Declare the allowed content key types for a given overlay network.
    /// Use a phantom, because we don't store any keys in this struct.
    /// For example, this type is used when decoding a content key received over the network.
    phantom_content_key: PhantomData<TContentKey>,
    /// Associate a metric with the overlay network.
    phantom_metric: PhantomData<TMetric>,
    /// Accepted content validator that makes requests to this/other overlay networks (or trusted
    /// http server)
    validator: Arc<TValidator>,
}

impl<
        TContentKey: 'static + OverlayContentKey + Send + Sync,
        TMetric: Metric + Send + Sync,
        TValidator: 'static + Validator<TContentKey> + Send + Sync,
        TStore: 'static + ContentStore + Send + Sync,
    > OverlayProtocol<TContentKey, TMetric, TValidator, TStore>
where
    <TContentKey as TryFrom<Vec<u8>>>::Error: Debug + Display + Send,
{
    pub async fn new(
        config: OverlayConfig,
        discovery: Arc<Discovery>,
        utp_listener_tx: UnboundedSender<UtpListenerRequest>,
        store: Arc<RwLock<TStore>>,
        data_radius: Distance,
        protocol: ProtocolId,
        validator: Arc<TValidator>,
    ) -> Self {
        let kbuckets = Arc::new(RwLock::new(KBucketsTable::new(
            discovery.local_enr().node_id().into(),
            config.bucket_pending_timeout,
            config.max_incoming_per_bucket,
            config.table_filter,
            config.bucket_filter,
        )));

        let data_radius = Arc::new(data_radius);
        let command_tx = OverlayService::<TContentKey, TMetric, TValidator, TStore>::spawn(
            Arc::clone(&discovery),
            Arc::clone(&store),
            Arc::clone(&kbuckets),
            config.bootnode_enrs,
            config.ping_queue_interval,
            Arc::clone(&data_radius),
            protocol.clone(),
            utp_listener_tx.clone(),
            config.enable_metrics,
            Arc::clone(&validator),
            config.query_timeout,
            config.query_peer_timeout,
            config.query_parallelism,
            config.query_num_results,
            config.findnodes_query_distances_per_peer,
        )
        .await;

        Self {
            discovery,
            data_radius,
            kbuckets,
            store,
            protocol,
            command_tx,
            utp_listener_tx,
            phantom_content_key: PhantomData,
            phantom_metric: PhantomData,
            validator,
        }
    }

    /// Returns the subnetwork protocol of the overlay protocol.
    pub fn protocol(&self) -> &ProtocolId {
        &self.protocol
    }

    /// Returns the ENR of the local node.
    pub fn local_enr(&self) -> Enr {
        self.discovery.local_enr()
    }

    /// Returns the data radius of the local node.
    pub fn data_radius(&self) -> Distance {
        *self.data_radius
    }

    /// Processes a single Discovery v5 TALKREQ message.
    pub async fn process_one_request(
        &self,
        talk_request: &TalkRequest,
    ) -> Result<Response, OverlayRequestError> {
        let request = match Message::try_from(Vec::<u8>::from(talk_request.body())) {
            Ok(message) => match Request::try_from(message) {
                Ok(request) => request,
                Err(err) => return Err(OverlayRequestError::InvalidRequest(err.to_string())),
            },
            Err(_) => return Err(OverlayRequestError::DecodeError),
        };
        let direction = RequestDirection::Incoming {
            id: talk_request.id().clone(),
            source: *talk_request.node_id(),
        };

        // Send the request and wait on the response.
        self.send_overlay_request(request, direction).await
    }

    /// Process overlay uTP listener event
    pub fn process_utp_event(&self, event: UtpListenerEvent) -> anyhow::Result<()> {
        match event {
            UtpListenerEvent::ClosedStream(utp_payload, _, stream_id) => {
                // Handle all closed uTP streams, currently we process only AcceptStream here.
                // FindContent payload is processed explicitly when we send FindContent request.
                // We don't expect to process a payload for ContentStream and OfferStream.
                match stream_id {
                    UtpStreamId::AcceptStream(content_keys) => {
                        self.process_accept_utp_payload(content_keys, utp_payload)?
                    }
                    UtpStreamId::ContentStream(_) => {}
                    UtpStreamId::FindContentStream => {}
                    UtpStreamId::OfferStream => {}
                }
            }
            UtpListenerEvent::ResetStream(..) => {}
        }
        Ok(())
    }

    /// Process accepted uTP payload of the OFFER/ACCEPT stream
    fn process_accept_utp_payload(
        &self,
        content_keys: Vec<RawContentKey>,
        payload: UtpPayload,
    ) -> anyhow::Result<()> {
        let content_values = portal_wire::decode_content_payload(payload)?;

        // Accepted content keys len should match content value len
        if content_keys.len() != content_values.len() {
            return Err(anyhow!(
                "Content keys len doesn't match content values len."
            ));
        }

        let validator = Arc::clone(&self.validator);
        let store = Arc::clone(&self.store);
        let kbuckets = Arc::clone(&self.kbuckets);
        let command_tx = self.command_tx.clone();

        // Spawn a task that spawns a validation task for each piece of content,
        // collects validated content and propagates it via gossip.
        tokio::spawn(async move {
            let handles: Vec<JoinHandle<_>> = content_keys
                .into_iter()
                .zip(content_values.to_vec())
                .filter_map(
                    |(raw_key, content_value)| match TContentKey::try_from(raw_key) {
                        Ok(content_key) => Some((content_key, content_value)),
                        Err(err) => {
                            warn!(error = %err, "Error decoding overlay content key");
                            None
                        }
                    },
                )
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
                                content.id = %hex_encode(key.content_id()),
                                "Error validating accepted content"
                            );
                            return None;
                        }

                        // Check if data should be stored, and store if true.
                        let key_desired = store.read().is_key_within_radius_and_unavailable(&key);
                        match key_desired {
                            Ok(true) => {
                                if let Err(err) =
                                    store.write().put(key.clone(), &content_value.to_vec())
                                {
                                    warn!(
                                        error = %err,
                                        content.id = %hex_encode(key.content_id()),
                                        "Error storing accepted content"
                                    );
                                }
                            }
                            Ok(false) => {
                                warn!(
                                    content.id = %hex_encode(key.content_id()),
                                    "Accepted content outside radius or already stored"
                                );
                            }
                            Err(err) => {
                                warn!(
                                    error = %err,
                                    content.id = %hex_encode(key.content_id()),
                                    "Error checking data store for content key"
                                );
                            }
                        }
                        Some((key, content_value))
                    })
                })
                .collect();
            let validated_content = join_all(handles)
                .await
                .into_iter()
                // Whether the spawn fails or the content fails validation, we don't want it:
                .filter_map(|content| content.unwrap_or(None))
                .collect();
            // Propagate all validated content, whether or not it was stored.
            Self::propagate_gossip_cross_thread(validated_content, kbuckets, command_tx);
        });
        Ok(())
    }

    /// Propagate gossip accepted content via OFFER/ACCEPT, return number of peers propagated
    pub fn propagate_gossip(&self, content: Vec<(TContentKey, Vec<u8>)>) -> usize {
        let kbuckets = Arc::clone(&self.kbuckets);
        let command_tx = self.command_tx.clone();
        Self::propagate_gossip_cross_thread(content, kbuckets, command_tx)
    }

    // Propagate gossip in a way that can be used across threads, without &self
    fn propagate_gossip_cross_thread(
        content: Vec<(TContentKey, Vec<u8>)>,
        kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
        command_tx: UnboundedSender<OverlayCommand<TContentKey>>,
    ) -> usize {
        // Get all connected nodes from overlay routing table
        let kbuckets = kbuckets.read();
        let all_nodes: Vec<&kbucket::Node<NodeId, Node>> = kbuckets
            .buckets_iter()
            .map(|kbucket| {
                kbucket
                    .iter()
                    .filter(|node| node.status.is_connected())
                    .collect::<Vec<&kbucket::Node<NodeId, Node>>>()
            })
            .flatten()
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

    /// Returns a vector of all ENR node IDs of nodes currently contained in the routing table.
    pub fn table_entries_id(&self) -> Vec<NodeId> {
        self.kbuckets
            .write()
            .iter()
            .map(|entry| *entry.node.key.preimage())
            .collect()
    }

    /// Returns a vector of all the ENRs of nodes currently contained in the routing table.
    pub fn table_entries_enr(&self) -> Vec<Enr> {
        self.kbuckets
            .write()
            .iter()
            .map(|entry| entry.node.value.enr().clone())
            .collect()
    }

    /// Returns a map (BTree for its ordering guarantees) with:
    ///     key: usize representing bucket index
    ///     value: Vec of tuples, each tuple represents a node
    pub fn bucket_entries(
        &self,
    ) -> BTreeMap<usize, Vec<(NodeId, Enr, NodeStatus, Distance, Option<String>)>> {
        self.kbuckets
            .read()
            .buckets_iter()
            .enumerate()
            .filter(|(_, bucket)| bucket.num_entries() > 0)
            .map(|(index, bucket)| {
                (
                    index,
                    bucket
                        .iter()
                        .map(|node| {
                            // "c" is used as short-hand for "client" within the ENR's key-values.
                            let client_info: Option<String> = match node.value.enr().clone().get("c") {
                                Some(slice) => {
                                    match std::str::from_utf8(slice) {
                                        Ok(client_string) => Some(client_string.to_string()),
                                        Err(err) => {
                                            error!("Failed to parse remote client info from ENR: {err:?}");
                                            None
                                        }
                                    }
                                }
                                None => None
                            };
                            (
                                *node.key.preimage(),
                                node.value.enr().clone(),
                                node.status,
                                node.value.data_radius(),
                                client_info,
                            )
                        })
                        .collect(),
                )
            })
            .collect()
    }

    /// Sends a `Ping` request to `enr`.
    pub async fn send_ping(&self, enr: Enr) -> Result<Pong, OverlayRequestError> {
        // Construct the request.
        let enr_seq = self.discovery.local_enr().seq();
        let data_radius = self.data_radius();
        let custom_payload = CustomPayload::from(data_radius.as_ssz_bytes());
        let request = Ping {
            enr_seq,
            custom_payload,
        };

        let direction = RequestDirection::Outgoing { destination: enr };

        // Send the request and wait on the response.
        match self
            .send_overlay_request(Request::Ping(request), direction)
            .await
        {
            Ok(Response::Pong(pong)) => Ok(pong),
            Ok(_) => Err(OverlayRequestError::InvalidResponse),
            Err(error) => Err(error),
        }
    }

    /// Sends a `FindNodes` request to `enr`.
    pub async fn send_find_nodes(
        &self,
        enr: Enr,
        distances: Vec<u16>,
    ) -> Result<Nodes, OverlayRequestError> {
        // Construct the request.
        validate_find_nodes_distances(&distances)?;
        let request = FindNodes { distances };
        let direction = RequestDirection::Outgoing { destination: enr };

        // Send the request and wait on the response.
        match self
            .send_overlay_request(Request::FindNodes(request), direction)
            .await
        {
            Ok(Response::Nodes(nodes)) => Ok(nodes),
            Ok(_) => Err(OverlayRequestError::InvalidResponse),
            Err(error) => Err(error),
        }
    }

    /// Sends a `FindContent` request for `content_key` to `enr`.
    pub async fn send_find_content(
        &self,
        enr: Enr,
        content_key: Vec<u8>,
    ) -> Result<Content, OverlayRequestError> {
        // Construct the request.
        let request = FindContent {
            content_key: content_key.clone(),
        };
        let direction = RequestDirection::Outgoing {
            destination: enr.clone(),
        };

        // Send the request and wait on the response.
        match self
            .send_overlay_request(Request::FindContent(request), direction)
            .await
        {
            Ok(Response::Content(found_content)) => {
                match found_content {
                    Content::Content(_) => Ok(found_content),
                    Content::Enrs(_) => Ok(found_content),
                    // Init uTP stream if `connection_id`is received
                    Content::ConnectionId(conn_id) => {
                        let conn_id = u16::from_be(conn_id);
                        let content = self.init_find_content_stream(enr, conn_id).await?;
                        let content_key = TContentKey::try_from(content_key).map_err(|err| {
                            OverlayRequestError::FailedValidation(format!(
                                "Error decoding content key for received utp content: {err}"
                            ))
                        })?;
                        match self
                            .validator
                            .validate_content(&content_key, &content)
                            .await
                        {
                            Ok(_) => Ok(Content::Content(content)),
                            Err(msg) => Err(OverlayRequestError::FailedValidation(format!(
                                "Network: {:?}, Reason: {:?}",
                                self.protocol, msg
                            ))),
                        }
                    }
                }
            }
            Ok(_) => Err(OverlayRequestError::InvalidResponse),
            Err(error) => Err(error),
        }
    }

    /// Initialize FindContent uTP stream with remote node
    async fn init_find_content_stream(
        &self,
        enr: Enr,
        conn_id: u16,
    ) -> Result<Vec<u8>, OverlayRequestError> {
        // initiate the connection to the acceptor
        let (tx, rx) = tokio::sync::oneshot::channel::<UtpStream>();
        let utp_request = UtpListenerRequest::Connect(
            conn_id,
            enr,
            self.protocol.clone(),
            UtpStreamId::FindContentStream,
            tx,
        );

        self.utp_listener_tx.send(utp_request).map_err(|err| {
            OverlayRequestError::UtpError(format!(
                "Unable to send Connect request with FindContent stream to UtpListener: {err}"
            ))
        })?;

        match rx.await {
            Ok(mut conn) => {
                let mut result = Vec::new();
                // Loop and receive all DATA packets, similar to `read_to_end`
                loop {
                    let mut buf = [0; BUF_SIZE];
                    match conn.recv_from(&mut buf).await {
                        Ok((0, _)) => {
                            break;
                        }
                        Ok((bytes, _)) => {
                            result.extend_from_slice(&mut buf[..bytes]);
                        }
                        Err(err) => {
                            warn!(
                                error = %err,
                                utp.conn_id = %conn_id,
                                utp.peer = %conn.connected_to,
                                "Error receiving content from uTP conn"
                            );
                            return Err(OverlayRequestError::UtpError(err.to_string()));
                        }
                    }
                }
                Ok(result)
            }
            Err(err) => {
                warn!(error = %err, "Error receiving content from uTP listener");
                Err(OverlayRequestError::UtpError(err.to_string()))
            }
        }
    }

    /// Offer is sent in order to store content to k nodes with radii that contain content-id
    /// Offer is also sent to nodes after FindContent (POKE)
    pub async fn send_offer(
        &self,
        content_keys: Vec<RawContentKey>,
        enr: Enr,
    ) -> Result<Accept, OverlayRequestError> {
        // Construct the request.
        let request = Offer {
            content_keys: content_keys.clone(),
        };
        let direction = RequestDirection::Outgoing {
            destination: enr.clone(),
        };

        // Send the request and wait on the response.
        match self
            .send_overlay_request(Request::Offer(request), direction)
            .await
        {
            Ok(Response::Accept(accept)) => Ok(accept),
            Ok(_) => Err(OverlayRequestError::InvalidResponse),
            Err(error) => Err(error),
        }
    }

    /// Send Offer request without storing the content into db
    pub async fn send_populated_offer(
        &self,
        enr: Enr,
        content_key: RawContentKey,
        content_value: Vec<u8>,
    ) -> Result<Accept, OverlayRequestError> {
        // Construct the request.
        let request = Request::PopulatedOffer(PopulatedOffer {
            content_items: vec![(content_key, content_value)],
        });

        let direction = RequestDirection::Outgoing {
            destination: enr.clone(),
        };

        // Send the request and wait on the response.
        match self.send_overlay_request(request, direction).await {
            Ok(Response::Accept(accept)) => Ok(accept),
            Ok(_) => Err(OverlayRequestError::InvalidResponse),
            Err(error) => Err(error),
        }
    }

    /// Performs a content lookup for `target`.
    /// Returns the target content along with the peers traversed during content lookup.
    pub async fn lookup_content(&self, target: TContentKey) -> (Option<Vec<u8>>, Vec<NodeId>) {
        let (tx, rx) = oneshot::channel();
        let content_id = target.content_id();

        if let Err(err) = self.command_tx.send(OverlayCommand::FindContentQuery {
            target,
            callback: tx,
        }) {
            warn!(
                protocol = %self.protocol,
                error = %err,
                content.id = %hex_encode(content_id),
                "Error submitting FindContent query to service"
            );
            return (None, vec![]);
        }

        match rx.await {
            Ok(result) => result,
            Err(err) => {
                warn!(
                    protocol = %self.protocol,
                    error = %err,
                    content.id = %hex_encode(content_id),
                    "Error receiving content from service",
                );
                (None, vec![])
            }
        }
    }

    /// Sends a request through the overlay service.
    async fn send_overlay_request(
        &self,
        request: Request,
        direction: RequestDirection,
    ) -> Result<Response, OverlayRequestError> {
        let (tx, rx) = oneshot::channel();
        let overlay_request = OverlayRequest::new(request, direction, Some(tx), None);
        if let Err(error) = self
            .command_tx
            .send(OverlayCommand::Request(overlay_request))
        {
            warn!(
                protocol = %self.protocol,
                error = %error,
                "Error submitting request to service",
            );
            return Err(OverlayRequestError::ChannelFailure(error.to_string()));
        }

        // Wait on the response.
        match rx.await {
            Ok(result) => result,
            Err(error) => Err(OverlayRequestError::ChannelFailure(error.to_string())),
        }
    }

    pub async fn ping_bootnodes(&self) {
        // Trigger bonding with bootnodes, at both the base layer and portal overlay.
        // The overlay ping via talkreq will trigger a session at the base layer, then
        // a session on the (overlay) portal network.
        let mut successfully_bonded_bootnode = false;
        let enrs = self.discovery.table_entries_enr();
        if enrs.is_empty() {
            error!(
                protocol = %self.protocol,
                "No bootnodes provided to join portal network",
            );
            return;
        }
        for enr in enrs {
            debug!(bootnode.enr = %enr, "Attempting to bond with bootnode");
            let ping_result = self.send_ping(enr.clone()).await;

            match ping_result {
                Ok(_) => {
                    info!(bootnode.enr = %enr, "Bonded with bootnode");
                    successfully_bonded_bootnode = true;
                }
                Err(err) => {
                    error!(
                        protocol = %self.protocol,
                        error = %err,
                        bootnode.enr = %enr,
                        "Error bonding with bootnode",
                    );
                }
            }
        }
        if !successfully_bonded_bootnode {
            error!(
                protocol = %self.protocol,
                "Failed to bond with any bootnodes",
            );
        }
    }
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

fn validate_find_nodes_distances(distances: &Vec<u16>) -> Result<(), OverlayRequestError> {
    if distances.len() == 0 {
        return Err(OverlayRequestError::InvalidRequest(
            "Invalid distances: Empty list".to_string(),
        ));
    }
    if distances.len() > 256 {
        return Err(OverlayRequestError::InvalidRequest(
            "Invalid distances: More than 256 elements".to_string(),
        ));
    }
    let invalid_distances: Vec<&u16> = distances.iter().filter(|val| val > &&256u16).collect();
    if invalid_distances.len() > 0 {
        return Err(OverlayRequestError::InvalidRequest(format!(
            "Invalid distances: Distances greater than 256 are not allowed. Found: {:?}",
            invalid_distances
        )));
    }
    let unique: HashSet<u16> = HashSet::from_iter(distances.iter().cloned());
    if unique.len() != distances.len() {
        return Err(OverlayRequestError::InvalidRequest(
            "Invalid distances: Duplicate elements detected".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use crate::utils::node_id::generate_random_remote_enr;
    use rstest::rstest;

    #[rstest]
    #[case(vec![0u16])]
    #[case(vec![256u16])]
    #[case((0u16..256u16).collect())]
    fn test_nodes_validator_accepts_valid_input(#[case] input: Vec<u16>) {
        let result = validate_find_nodes_distances(&input);
        match result {
            Ok(val) => assert_eq!(val, ()),
            Err(_) => panic!("Valid test case fails"),
        }
    }

    #[rstest]
    #[case(vec![], "Empty list")]
    #[case((0u16..257u16).collect(), "More than 256")]
    #[case(vec![257u16], "Distances greater than")]
    #[case(vec![0u16, 0u16, 1u16], "Duplicate elements detected")]
    fn test_nodes_validator_rejects_invalid_input(#[case] input: Vec<u16>, #[case] msg: String) {
        let result = validate_find_nodes_distances(&input);
        match result {
            Ok(_) => panic!("Invalid test case passed"),
            Err(err) => assert!(err.to_string().contains(&msg)),
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
