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
use ethereum_types::U256;
use futures::{channel::oneshot, future::join_all};
use log::error;
use parking_lot::RwLock;
use rand::seq::IteratorRandom;
use ssz::Encode;
use ssz_types::VariableList;
use tokio::{sync::mpsc::UnboundedSender, task::JoinHandle};
use tracing::{debug, warn};

use crate::{
    portalnet::{
        discovery::Discovery,
        overlay_service::{
            OverlayCommand, OverlayRequest, OverlayRequestError, OverlayService, RequestDirection,
        },
        storage::ContentStore,
        types::{
            content_key::{OverlayContentKey, RawContentKey},
            messages::{
                Accept, ByteList, Content, CustomPayload, FindContent, FindNodes, Message, Nodes,
                Offer, Ping, Pong, PopulatedOffer, ProtocolId, Request, Response,
            },
            metric::{Metric, XorMetric},
            node::Node,
        },
        Enr,
    },
    types::validation::Validator,
    utils::{bytes::hex_encode, portal_wire},
    utp::{
        stream::{UtpListenerEvent, UtpListenerRequest, UtpPayload, UtpStream, BUF_SIZE},
        trin_helpers::UtpStreamId,
    },
};

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
    pub data_radius: Arc<U256>,
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
    /// Accepted content validator that makes requests to this/other overlay networks (or infura)
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
        data_radius: U256,
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
        .await
        .unwrap();

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
        self.discovery.discv5.local_enr()
    }

    /// Returns the data radius of the local node.
    pub fn data_radius(&self) -> U256 {
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
                .map(
                    |(content_key, content_value)| match TContentKey::try_from(content_key) {
                        Ok(key) => {
                            // Spawn a task that...
                            // - Validates accepted content (this step requires a dedicated task since it
                            // might require non-blocking requests to this/other overlay networks)
                            // - Checks if validated content should be stored, and stores it if true
                            // - Propagate all validated content
                            let validator = Arc::clone(&validator);
                            let store = Arc::clone(&store);
                            Some(tokio::spawn(async move {
                                // Validated received content
                                validator
                                    .validate_content(&key, &content_value.to_vec())
                                    .await
                                    // Skip storing & propagating content if it's not valid
                                    .expect("Unable to validate received content: {err:?}");

                                // Ignore error since all validated content is propagated.
                                if store
                                    .read()
                                    .is_key_within_radius_and_unavailable(&key)
                                    .expect("unable to check data store for content")
                                {
                                    let _ = store.write().put(key.clone(), &content_value.to_vec());
                                }

                                (key, content_value)
                            }))
                        }
                        Err(err) => {
                            warn!("Unexpected error while decoding overlay content key: {err}");
                            None
                        }
                    },
                )
                .flatten()
                .collect();
            let validated_content = join_all(handles)
                .await
                .into_iter()
                .filter_map(|content| content.ok())
                .collect();
            // Propagate all validated content, whether or not it was stored.
            Self::propagate_gossip(validated_content, kbuckets, command_tx);
        });
        Ok(())
    }

    /// Propagate gossip accepted content via OFFER/ACCEPT:
    fn propagate_gossip(
        content: Vec<(TContentKey, ByteList)>,
        kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
        command_tx: UnboundedSender<OverlayCommand<TContentKey>>,
    ) {
        // Get all nodes from overlay routing table
        let kbuckets = kbuckets.read();
        let all_nodes: Vec<&kbucket::Node<NodeId, Node>> = kbuckets
            .buckets_iter()
            .map(|kbucket| {
                kbucket
                    .iter()
                    .collect::<Vec<&kbucket::Node<NodeId, Node>>>()
            })
            .flatten()
            .collect();

        // HashMap to temporarily store all interested ENRs and the content.
        // Key is base64 string of node's ENR.
        let mut enrs_and_content: HashMap<String, Vec<(RawContentKey, ByteList)>> = HashMap::new();

        // Filter all nodes from overlay routing table where XOR_distance(content_id, nodeId) < node radius
        for (content_key, content_value) in content {
            let interested_enrs: Vec<Enr> = all_nodes
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
                debug!("No nodes interested in neighborhood gossip: content_key={} num_nodes_checked={}",
                    hex_encode(content_key.into()), all_nodes.len());
                continue;
            }

            // Get log2 random ENRs to gossip
            let random_enrs = match log2_random_enrs(interested_enrs) {
                Ok(val) => val,
                Err(msg) => {
                    debug!("Error calculating log2 random enrs for gossip propagation: {msg}");
                    return;
                }
            };

            // Temporarily store all randomly selected nodes with the content of interest.
            // We want this so we can offer all the content to interested node in one request.
            let raw_item = (content_key.into(), content_value);
            for enr in random_enrs {
                enrs_and_content
                    .entry(enr.to_base64())
                    .or_default()
                    .push(raw_item.clone());
            }
        }

        // Create and send OFFER overlay request to the interested nodes
        for (enr_string, interested_content) in enrs_and_content.into_iter() {
            let enr = match Enr::from_str(&enr_string) {
                Ok(enr) => enr,
                Err(err) => {
                    error!("Error creating ENR from base_64 encoded string: {err}");
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
                error!("Unable to send OFFER request to overlay: {err}.")
            }
        }
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
    pub fn bucket_entries(&self) -> BTreeMap<usize, Vec<(NodeId, Enr, NodeStatus, U256)>> {
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
                            (
                                *node.key.preimage(),
                                node.value.enr().clone(),
                                node.status,
                                node.value.data_radius(),
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

        let node_id = enr.node_id();
        let direction = RequestDirection::Outgoing { destination: enr };

        // Send the request and wait on the response.
        debug!("Sending {} dest={}", request, node_id);
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
                            Ok(_) => Ok(Content::Content(VariableList::from(content))),
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

    /// Initialize FIndContent uTP stream with remote node
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
                            warn!("Unable to receive content via uTP: {err}");
                            return Err(OverlayRequestError::UtpError(err.to_string()));
                        }
                    }
                }
                Ok(result)
            }
            Err(err) => {
                warn!("Unable to receive from uTP listener channel: {err}");
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

    /// Public method for initiating a network request through the overlay service.
    pub async fn initiate_overlay_request(
        &self,
        request: Request,
    ) -> Result<Response, OverlayRequestError> {
        let direction = RequestDirection::Initialize;
        self.send_overlay_request(request, direction).await
    }

    /// Performs a content lookup for `target`.
    pub async fn lookup_content(&self, target: TContentKey) -> Option<Vec<u8>> {
        let (tx, rx) = oneshot::channel();

        if let Err(_) = self.command_tx.send(OverlayCommand::FindContentQuery {
            target,
            callback: tx,
        }) {
            warn!(
                "Failure sending query over {:?} service channel",
                self.protocol
            );
            return None;
        }

        match rx.await {
            Ok(result) => result,
            Err(_) => {
                warn!(
                    "Unable to receive content over {:?} service channel",
                    self.protocol
                );
                None
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
                "Failure sending request over {:?} service channel",
                self.protocol
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
        let enrs = self.discovery.discv5.table_entries_enr();
        if enrs.is_empty() {
            error!(
                "No bootnodes provided, cannot join Portal {:?} Network.",
                self.protocol
            );
            return;
        }
        for enr in enrs {
            debug!("Attempting to bond with bootnode: {}", enr);
            let ping_result = self.send_ping(enr.clone()).await;

            match ping_result {
                Ok(_) => {
                    debug!("Successfully bonded with bootnode: {}", enr);
                    successfully_bonded_bootnode = true;
                }
                Err(err) => {
                    error!(
                        "{err} while pinging {:?} network bootnode: {enr:?}",
                        self.protocol
                    );
                }
            }
        }
        if !successfully_bonded_bootnode {
            error!(
                "Failed to bond with any bootnodes, cannot join Portal {:?} Network.",
                self.protocol
            );
        }
    }
}

/// Randomly select log2 nodes. log2() is stable only for floats, that's why we cast it first to f32
fn log2_random_enrs(enrs: Vec<Enr>) -> anyhow::Result<Vec<Enr>> {
    if enrs.is_empty() {
        return Err(anyhow!("Expected non-empty vector of ENRs"));
    }
    // log2(1) is zero but we want to propagate to at least one node
    if enrs.len() == 1 {
        return Ok(enrs);
    }

    // Greedy gossip by ceiling the log2 value
    let log2_value = (enrs.len() as f32).log2().ceil();

    let random_enrs: Vec<Enr> = enrs
        .into_iter()
        .choose_multiple(&mut rand::thread_rng(), log2_value as usize);
    Ok(random_enrs)
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
    #[case(vec![generate_random_remote_enr().1; 8], 3)]
    #[case(vec![generate_random_remote_enr().1; 1], 1)]
    #[case(vec![generate_random_remote_enr().1; 9], 4)]
    fn test_log2_random_enrs(#[case] all_nodes: Vec<Enr>, #[case] expected_log2: usize) {
        let log2_random_nodes = log2_random_enrs(all_nodes).unwrap();
        assert_eq!(log2_random_nodes.len(), expected_log2);
    }

    #[test_log::test]
    #[should_panic]
    fn test_log2_random_enrs_empty_input() {
        let all_nodes = vec![];
        log2_random_enrs(all_nodes).unwrap();
    }
}
