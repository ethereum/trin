#![allow(clippy::result_large_err)]

use std::{
    collections::{BTreeMap, HashSet},
    fmt::{Debug, Display},
    future::Future,
    marker::{PhantomData, Sync},
    sync::Arc,
};

use anyhow::anyhow;
use discv5::{
    enr::NodeId,
    kbucket::{Entry, FailureReason, InsertResult, KBucketsTable, Key, NodeStatus},
    ConnectionDirection, ConnectionState, TalkRequest,
};
use futures::channel::oneshot;
use parking_lot::RwLock;
use ssz::Encode;
use tokio::sync::{broadcast, mpsc::UnboundedSender};
use tracing::{debug, error, info, warn};
use utp_rs::socket::UtpSocket;

use crate::{
    discovery::{Discovery, UtpEnr},
    find::query_info::{FindContentResult, RecursiveFindContentResult},
    gossip::{propagate_gossip_cross_thread, trace_propagate_gossip_cross_thread, GossipResult},
    overlay::{
        command::OverlayCommand,
        config::OverlayConfig,
        errors::OverlayRequestError,
        request::{OverlayRequest, RequestDirection},
        service::OverlayService,
    },
    types::node::Node,
    utp_controller::UtpController,
};
use ethportal_api::{
    types::{
        bootnodes::Bootnode,
        discv5::RoutingTableInfo,
        distance::{Distance, Metric},
        enr::Enr,
        portal_wire::{
            Accept, Content, CustomPayload, FindContent, FindNodes, Message, Nodes, Offer, Ping,
            Pong, PopulatedOffer, ProtocolId, Request, Response,
        },
    },
    utils::bytes::hex_encode,
    OverlayContentKey, RawContentKey,
};
use trin_metrics::{overlay::OverlayMetricsReporter, portalnet::PORTALNET_METRICS};
use trin_storage::ContentStore;
use trin_validation::validator::{ValidationResult, Validator};

use crate::events::EventEnvelope;

type BucketEntry = (NodeId, Enr, NodeStatus, Distance, Option<String>);

/// Overlay protocol is a layer on top of discv5 that handles all requests from the overlay networks
/// (state, history etc.) and dispatch them to the discv5 protocol TalkReq. Each network should
/// implement the overlay protocol and the overlay protocol is where we can encapsulate the logic
/// for handling common network requests/responses.
#[derive(Clone)]
pub struct OverlayProtocol<TContentKey, TMetric, TValidator, TStore> {
    /// Reference to the underlying discv5 protocol
    pub discovery: Arc<Discovery>,
    /// The data store.
    pub store: Arc<RwLock<TStore>>,
    /// The overlay routing table of the local node.
    kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
    /// The subnetwork protocol of the overlay.
    protocol: ProtocolId,
    /// A sender to send commands to the OverlayService.
    pub command_tx: UnboundedSender<OverlayCommand<TContentKey>>,
    /// uTP controller.
    utp_controller: Arc<UtpController>,
    /// Declare the allowed content key types for a given overlay network.
    /// Use a phantom, because we don't store any keys in this struct.
    /// For example, this type is used when decoding a content key received over the network.
    _phantom_content_key: PhantomData<TContentKey>,
    /// Associate a distance metric with the overlay network.
    _phantom_metric: PhantomData<TMetric>,
    /// Accepted content validator that makes requests to this/other overlay networks
    validator: Arc<TValidator>,
    /// Runtime telemetry metrics for the overlay network.
    metrics: OverlayMetricsReporter,
}

impl<
        TContentKey: 'static + OverlayContentKey + Send + Sync,
        TMetric: Metric + Send + Sync,
        TValidator: 'static + Validator<TContentKey> + Send + Sync,
        TStore: 'static + ContentStore<Key = TContentKey> + Send + Sync,
    > OverlayProtocol<TContentKey, TMetric, TValidator, TStore>
where
    <TContentKey as TryFrom<Vec<u8>>>::Error: Debug + Display + Send,
{
    pub async fn new(
        config: OverlayConfig,
        discovery: Arc<Discovery>,
        utp_socket: Arc<UtpSocket<UtpEnr>>,
        store: Arc<RwLock<TStore>>,
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
        // Initialize metrics, keep a reference in order to build metrics summaries for logging
        let metrics = OverlayMetricsReporter {
            overlay_metrics: PORTALNET_METRICS.overlay(),
            protocol: protocol.to_string(),
        };
        let utp_controller = Arc::new(UtpController::new(
            config.utp_transfer_limit,
            utp_socket,
            metrics.clone(),
        ));
        let command_tx = OverlayService::<TContentKey, TMetric, TValidator, TStore>::spawn(
            Arc::clone(&discovery),
            Arc::clone(&store),
            Arc::clone(&kbuckets),
            config.bootnode_enrs,
            config.ping_queue_interval,
            protocol,
            Arc::clone(&utp_controller),
            metrics.clone(),
            Arc::clone(&validator),
            config.query_timeout,
            config.query_peer_timeout,
            config.query_parallelism,
            config.query_num_results,
            config.findnodes_query_distances_per_peer,
            config.disable_poke,
        )
        .await;

        Self {
            discovery,
            kbuckets,
            store,
            protocol,
            command_tx,
            utp_controller,
            _phantom_content_key: PhantomData,
            _phantom_metric: PhantomData,
            validator,
            metrics,
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
        self.store.read().radius()
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

    /// Processes a single EventEnvelope from an overlay.
    pub async fn process_one_event(&self, event: EventEnvelope) -> Result<(), OverlayRequestError> {
        if let Err(err) = self.command_tx.send(OverlayCommand::Event(event)) {
            warn!(
                protocol = %self.protocol,
                error = %err,
                "Error submitting event to service",
            );
            return Err(OverlayRequestError::ChannelFailure(err.to_string()));
        }
        Ok(())
    }

    /// Propagate gossip accepted content via OFFER/ACCEPT, return number of peers propagated
    pub fn propagate_gossip(&self, content: Vec<(TContentKey, Vec<u8>)>) -> usize {
        let kbuckets = Arc::clone(&self.kbuckets);
        propagate_gossip_cross_thread(content, kbuckets, self.command_tx.clone(), None)
    }

    /// Propagate gossip accepted content via OFFER/ACCEPT, returns trace detailing outcome of
    /// gossip
    pub async fn propagate_gossip_trace(
        &self,
        content_key: TContentKey,
        data: Vec<u8>,
    ) -> GossipResult {
        let kbuckets = Arc::clone(&self.kbuckets);
        trace_propagate_gossip_cross_thread(content_key, data, kbuckets, self.command_tx.clone())
            .await
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
            .map(|entry| entry.node.value.enr())
            .collect()
    }

    /// Returns the node-id and a nested array of node-ids to represent this node's k-buckets table.
    pub fn routing_table_info(&self) -> RoutingTableInfo {
        RoutingTableInfo {
            local_node_id: hex_encode(self.local_enr().node_id().raw()),
            buckets: self.kbuckets.read().clone().into(),
        }
    }

    /// Returns a map (BTree for its ordering guarantees) with:
    ///     key: usize representing bucket index
    ///     value: Vec of tuples, each tuple represents a node
    pub fn bucket_entries(&self) -> BTreeMap<usize, Vec<BucketEntry>> {
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
                            let client_info: Option<String> = match node.value.enr().get("c") {
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
                                node.value.enr(),
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

    /// `AddEnr` adds requested `enr` to our kbucket.
    pub fn add_enr(&self, enr: Enr) -> Result<(), OverlayRequestError> {
        let key = Key::from(enr.node_id());
        match self.kbuckets.write().insert_or_update(
            &key,
            Node {
                enr,
                data_radius: Distance::MAX,
            },
            NodeStatus {
                state: ConnectionState::Connected,
                direction: ConnectionDirection::Incoming,
            },
        ) {
            InsertResult::Inserted
            | InsertResult::Pending { .. }
            | InsertResult::StatusUpdated { .. }
            | InsertResult::ValueUpdated
            | InsertResult::Updated { .. }
            | InsertResult::UpdatedPending => Ok(()),
            InsertResult::Failed(FailureReason::BucketFull) => {
                Err(OverlayRequestError::Failure("The bucket was full.".into()))
            }
            InsertResult::Failed(FailureReason::BucketFilter) => Err(OverlayRequestError::Failure(
                "The node didn't pass the bucket filter.".into(),
            )),
            InsertResult::Failed(FailureReason::TableFilter) => Err(OverlayRequestError::Failure(
                "The node didn't pass the table filter.".into(),
            )),
            InsertResult::Failed(FailureReason::InvalidSelfUpdate) => {
                Err(OverlayRequestError::Failure("Cannot update self.".into()))
            }
            InsertResult::Failed(_) => {
                Err(OverlayRequestError::Failure("Failed to insert ENR".into()))
            }
        }
    }

    /// `GetEnr` gets requested `enr` from our kbucket.
    pub fn get_enr(&self, node_id: NodeId) -> Result<Enr, OverlayRequestError> {
        if node_id == self.local_enr().node_id() {
            return Ok(self.local_enr());
        }
        let key = Key::from(node_id);
        if let Entry::Present(entry, _) = self.kbuckets.write().entry(&key) {
            return Ok(entry.value().enr());
        }
        Err(OverlayRequestError::Failure("Couldn't get ENR".into()))
    }

    /// `DeleteEnr` deletes requested `enr` from our kbucket.
    pub fn delete_enr(&self, node_id: NodeId) -> bool {
        let key = &Key::from(node_id);
        self.kbuckets.write().remove(key)
    }

    /// `LookupEnr` finds requested `enr` from our kbucket, FindNode, and RecursiveFindNode.
    pub async fn lookup_enr(&self, node_id: NodeId) -> Result<Enr, OverlayRequestError> {
        if node_id == self.local_enr().node_id() {
            return Ok(self.local_enr());
        }

        let enr = self.get_enr(node_id);

        // try to find more up to date enr
        if let Ok(enr) = enr.clone() {
            if let Ok(nodes) = self.send_find_nodes(enr, vec![0]).await {
                let enr_highest_seq = nodes.enrs.into_iter().max_by(|a, b| a.seq().cmp(&b.seq()));

                if let Some(enr_highest_seq) = enr_highest_seq {
                    return Ok(enr_highest_seq.into());
                }
            }
        }

        let lookup_node_enr = self.lookup_node(node_id).await;
        let lookup_node_enr = lookup_node_enr
            .into_iter()
            .max_by(|a, b| a.seq().cmp(&b.seq()));
        if let Some(lookup_node_enr) = lookup_node_enr {
            let mut enr_seq = 0;
            if let Ok(enr) = enr.clone() {
                enr_seq = enr.seq();
            }
            if lookup_node_enr.seq() > enr_seq {
                return Ok(lookup_node_enr);
            }
        }

        enr
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
    ) -> Result<FindContentResult, OverlayRequestError> {
        // Construct the request.
        let request = FindContent {
            content_key: content_key.clone(),
        };
        let direction = RequestDirection::Outgoing {
            destination: enr.clone(),
        };
        let content_key = TContentKey::try_from(content_key).map_err(|err| {
            OverlayRequestError::FailedValidation(format!(
                "Error decoding content key for received utp content: {err}"
            ))
        })?;

        // Send the request and wait on the response.
        match self
            .send_overlay_request(Request::FindContent(request), direction)
            .await
        {
            Ok(Response::Content(found_content)) => {
                match found_content {
                    Content::Content(content) => {
                        match self.validate_content(&content_key, &content).await {
                            Ok(_) => Ok((Content::Content(content), false)),
                            Err(msg) => Err(OverlayRequestError::FailedValidation(format!(
                                "Network: {:?}, Reason: {msg:?}",
                                self.protocol
                            ))),
                        }
                    }
                    Content::Enrs(_) => Ok((found_content, false)),
                    // Init uTP stream if `connection_id` is received
                    Content::ConnectionId(conn_id) => {
                        let conn_id = u16::from_be(conn_id);
                        let content = self.init_find_content_stream(enr, conn_id).await?;
                        match self.validate_content(&content_key, &content).await {
                            Ok(_) => Ok((Content::Content(content), true)),
                            Err(msg) => Err(OverlayRequestError::FailedValidation(format!(
                                "Network: {:?}, Reason: {msg:?}",
                                self.protocol
                            ))),
                        }
                    }
                }
            }
            Ok(_) => Err(OverlayRequestError::InvalidResponse),
            Err(error) => Err(error),
        }
    }

    async fn validate_content(
        &self,
        content_key: &TContentKey,
        content: &[u8],
    ) -> anyhow::Result<ValidationResult<TContentKey>> {
        let validation_result = self.validator.validate_content(content_key, content).await;
        self.metrics.report_validation(validation_result.is_ok());

        validation_result.map_err(|err| {
            anyhow!("Content validation failed for content key {content_key:?} with error: {err:?}")
        })
    }

    /// Initialize FindContent uTP stream with remote node
    async fn init_find_content_stream(
        &self,
        enr: Enr,
        conn_id: u16,
    ) -> Result<Vec<u8>, OverlayRequestError> {
        let cid = utp_rs::cid::ConnectionId {
            recv: conn_id,
            send: conn_id.wrapping_add(1),
            peer: UtpEnr(enr),
        };
        self.utp_controller
            .connect_inbound_stream(cid)
            .await
            .map_err(|err| OverlayRequestError::ContentNotFound {
                message: format!("Unable to locate content on the network: {err:?}"),
                utp: true,
                trace: None,
            })
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

        // Validate that the content keys are available in the local store, before sending the
        // offer
        for content_key in content_keys.into_iter() {
            let content_key = TContentKey::try_from(content_key.clone()).map_err(|err| {
                OverlayRequestError::ContentNotFound {
                    message: format!(
                        "Error decoding content key for content key: {content_key:02X?} - {err}"
                    ),
                    utp: false,
                    trace: None,
                }
            })?;
            match self.store.read().get(&content_key) {
                Ok(Some(_)) => {}
                _ => {
                    return Err(OverlayRequestError::ContentNotFound {
                        message: format!(
                            "Content key not found in local store: {content_key:02X?}"
                        ),
                        utp: false,
                        trace: None,
                    });
                }
            }
        }

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

    pub async fn lookup_node(&self, target: NodeId) -> Vec<Enr> {
        if target == self.local_enr().node_id() {
            return vec![self.local_enr()];
        }
        let connected_peer = self
            .kbuckets
            .write()
            .iter()
            .filter(|entry| entry.status.is_connected())
            .map(|entry| *entry.node.key.preimage())
            .find(|node_id| node_id == &target);
        if let Some(entry) = connected_peer {
            match self.discovery.find_enr(&entry) {
                Some(enr) => return vec![enr],
                None => {
                    warn!(
                        protocol = %self.protocol,
                        "Error finding ENR for node expected to exist in local routing table",
                    );
                    return vec![];
                }
            }
        };
        let (tx, rx) = oneshot::channel();
        if let Err(err) = self.command_tx.send(OverlayCommand::FindNodeQuery {
            target,
            callback: tx,
        }) {
            warn!(
                protocol = %self.protocol,
                error = %err,
                "Error submitting FindNode query to service"
            );
            return vec![];
        }
        rx.await.unwrap_or_else(|err| {
            warn!(
                protocol = %self.protocol,
                error = %err,
                "Error receiving FindNode query response"
            );
            vec![]
        })
    }

    /// Performs a content lookup for `target`.
    /// Returns the target content along with the peers traversed during content lookup.
    pub async fn lookup_content(
        &self,
        target: TContentKey,
        is_trace: bool,
    ) -> Result<RecursiveFindContentResult, OverlayRequestError> {
        let (tx, rx) = oneshot::channel();
        let content_id = target.content_id();

        if let Err(err) = self.command_tx.send(OverlayCommand::FindContentQuery {
            target,
            callback: tx,
            is_trace,
        }) {
            warn!(
                protocol = %self.protocol,
                error = %err,
                content.id = %hex_encode(content_id),
                "Error submitting FindContent query to service"
            );
            return Err(OverlayRequestError::ChannelFailure(err.to_string()));
        }

        // Wait on the response.
        rx.await.map_err(|err| {
            warn!(
                protocol = %self.protocol,
                error = %err,
                content.id = %hex_encode(content_id),
                "Error receiving FindContent query response"
            );
            OverlayRequestError::ChannelFailure(err.to_string())
        })
    }

    /// Sends a request through the overlay service.
    async fn send_overlay_request(
        &self,
        request: Request,
        direction: RequestDirection,
    ) -> Result<Response, OverlayRequestError> {
        let (tx, rx) = oneshot::channel();
        let overlay_request = OverlayRequest::new(request, direction, Some(tx), None, None);
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
        rx.await
            .unwrap_or_else(|err| Err(OverlayRequestError::ChannelFailure(err.to_string())))
    }

    pub async fn ping_bootnodes(&self) {
        // Trigger bonding with bootnodes, at both the base layer and portal overlay.
        // The overlay ping via talkreq will trigger a session at the base layer, then
        // a session on the (overlay) portal network.
        let mut successfully_bonded_bootnode = false;
        let enrs = self.discovery.table_entries_enr();
        if enrs.is_empty() {
            info!(
                protocol = %self.protocol,
                "No bootnodes provided to join portal network",
            );
            return;
        }
        // Convert raw enrs to bootnode type to get alias
        let bootnodes: Vec<Bootnode> = enrs
            .into_iter()
            .map(|enr| {
                let enr: ethportal_api::types::enr::Enr = enr;
                enr.into()
            })
            .collect();
        for bootnode in bootnodes {
            debug!(alias = %bootnode.alias, protocol = %self.protocol, "Attempting to bond with bootnode");
            let ping_result = self.send_ping(bootnode.enr.clone()).await;

            match ping_result {
                Ok(_) => {
                    info!(alias = %bootnode.alias, protocol = %self.protocol, "Bonded with bootnode");
                    successfully_bonded_bootnode = true;
                }
                Err(err) => {
                    error!(
                        alias = %bootnode.alias,
                        protocol = %self.protocol,
                        error = %err,
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

    pub fn get_message_summary(&self) -> String {
        self.metrics.get_message_summary()
    }

    pub fn get_utp_summary(&self) -> String {
        self.metrics.get_utp_summary()
    }

    /// Creates an event stream channel which can be polled to receive overlay events.
    pub fn event_stream(
        &self,
    ) -> impl Future<Output = anyhow::Result<broadcast::Receiver<EventEnvelope>>> + 'static {
        let channel = self.command_tx.clone();

        async move {
            let (callback_send, callback_recv) = oneshot::channel();

            let command = OverlayCommand::RequestEventStream(callback_send);
            channel
                .send(command)
                .map_err(|_| anyhow!("The Overlay Service channel has been closed early."))?;

            callback_recv
                .await
                .map_err(|_| anyhow!("The Overlay Service callback channel has been closed early."))
        }
    }
}

fn validate_find_nodes_distances(distances: &[u16]) -> Result<(), OverlayRequestError> {
    if distances.is_empty() {
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
    if !invalid_distances.is_empty() {
        return Err(OverlayRequestError::InvalidRequest(format!(
            "Invalid distances: Distances greater than 256 are not allowed. Found: {invalid_distances:?}",
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
    use rstest::rstest;

    #[rstest]
    #[case(vec![0u16])]
    #[case(vec![256u16])]
    #[case((0u16..256u16).collect())]
    fn test_nodes_validator_accepts_valid_input(#[case] input: Vec<u16>) {
        let result = validate_find_nodes_distances(&input);
        assert!(result.is_ok());
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
}
