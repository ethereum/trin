#![allow(clippy::result_large_err)]

use std::{
    collections::HashSet,
    future::Future,
    marker::{PhantomData, Sync},
    sync::Arc,
};

use anyhow::anyhow;
use bytes::Bytes;
use discv5::{
    enr::NodeId,
    kbucket::{FailureReason, InsertResult, KBucketsTable, NodeStatus},
    ConnectionDirection, ConnectionState, TalkRequest,
};
use ethportal_api::{
    types::{
        discv5::RoutingTableInfo,
        distance::{Distance, Metric},
        enr::Enr,
        network::Subnetwork,
        ping_extensions::extensions::type_0::ClientInfoRadiusCapabilities,
        portal::PutContentInfo,
        portal_wire::{
            Accept, Content, FindContent, FindNodes, Message, Nodes, OfferTrace, Ping, Pong,
            PopulatedOffer, PopulatedOfferWithResult, Request, Response,
        },
    },
    utils::bytes::hex_encode,
    OverlayContentKey, RawContentKey, RawContentValue,
};
use futures::channel::oneshot;
use parking_lot::Mutex;
use tokio::sync::{broadcast, mpsc::UnboundedSender};
use tracing::{debug, error, info, warn};
use trin_metrics::{overlay::OverlayMetricsReporter, portalnet::PORTALNET_METRICS};
use trin_storage::{ContentStore, ShouldWeStoreContent};
use trin_validation::validator::{ValidationResult, Validator};
use utp_rs::socket::UtpSocket;

use super::{ping_extensions::PingExtension, service::OverlayService};
use crate::{
    bootnodes::Bootnode,
    discovery::{Discovery, UtpPeer},
    events::EventEnvelope,
    find::query_info::{FindContentResult, RecursiveFindContentResult},
    overlay::{
        command::OverlayCommand,
        config::{FindContentConfig, OverlayConfig},
        errors::OverlayRequestError,
        request::{OverlayRequest, RequestDirection},
    },
    put_content::{
        propagate_put_content_cross_thread, trace_propagate_put_content_cross_thread,
        PutContentResult,
    },
    types::{
        kbucket::{Entry, SharedKBucketsTable},
        node::Node,
    },
    utp::controller::UtpController,
};

/// Overlay protocol is a layer on top of discv5 that handles all requests from the overlay networks
/// (state, history etc.) and dispatch them to the discv5 protocol TalkReq. Each network should
/// implement the overlay protocol and the overlay protocol is where we can encapsulate the logic
/// for handling common network requests/responses.
#[derive(Clone)]
pub struct OverlayProtocol<TContentKey, TMetric, TValidator, TStore, TPingExtensions> {
    /// Reference to the underlying discv5 protocol
    pub discovery: Arc<Discovery>,
    /// The data store.
    pub store: Arc<Mutex<TStore>>,
    /// The overlay routing table of the local node.
    kbuckets: SharedKBucketsTable,
    /// The subnetwork protocol of the overlay.
    protocol: Subnetwork,
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
    /// Ping extensions for the overlay network.
    ping_extensions: Arc<TPingExtensions>,
}

impl<
        TContentKey: 'static + OverlayContentKey + Send + Sync,
        TMetric: Metric + Send + Sync,
        TValidator: 'static + Validator<TContentKey> + Send + Sync,
        TStore: 'static + ContentStore<Key = TContentKey> + Send + Sync,
        TPingExtensions: 'static + PingExtension + Send + Sync,
    > OverlayProtocol<TContentKey, TMetric, TValidator, TStore, TPingExtensions>
{
    pub async fn new(
        config: OverlayConfig,
        discovery: Arc<Discovery>,
        utp_socket: Arc<UtpSocket<UtpPeer>>,
        store: Arc<Mutex<TStore>>,
        protocol: Subnetwork,
        validator: Arc<TValidator>,
        ping_extensions: Arc<TPingExtensions>,
    ) -> Self {
        let local_node_id = discovery.local_enr().node_id();
        let kbuckets = SharedKBucketsTable::new(KBucketsTable::new(
            local_node_id.into(),
            config.bucket_pending_timeout,
            config.max_incoming_per_bucket,
            config.table_filter,
            config.bucket_filter,
        ));
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
        let command_tx =
            OverlayService::<TContentKey, TMetric, TValidator, TStore, TPingExtensions>::spawn(
                Arc::clone(&discovery),
                Arc::clone(&store),
                kbuckets.clone(),
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
                config.gossip_dropped,
                Arc::clone(&ping_extensions),
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
            ping_extensions,
        }
    }

    /// Returns the subnetwork protocol of the overlay protocol.
    pub fn protocol(&self) -> &Subnetwork {
        &self.protocol
    }

    /// Returns the ENR of the local node.
    pub fn local_enr(&self) -> Enr {
        self.discovery.local_enr()
    }

    /// Returns the data radius of the local node.
    pub fn data_radius(&self) -> Distance {
        self.store.lock().radius()
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

    /// Propagate put_content accepted content via OFFER/ACCEPT, return number of peers propagated
    pub fn propagate_put_content(
        &self,
        content_key: TContentKey,
        content_value: RawContentValue,
    ) -> PutContentInfo {
        let should_we_store = match self
            .store
            .lock()
            .is_key_within_radius_and_unavailable(&content_key)
        {
            Ok(should_we_store) => matches!(should_we_store, ShouldWeStoreContent::Store),
            Err(err) => {
                warn!(
                    protocol = %self.protocol,
                    error = %err,
                    "Error checking if content key is within radius and unavailable",
                );
                false
            }
        };

        if should_we_store {
            let _ = self
                .store
                .lock()
                .put(content_key.clone(), content_value.clone());
        }

        PutContentInfo {
            peer_count: propagate_put_content_cross_thread::<_, TMetric>(
                vec![(content_key, content_value)],
                &self.kbuckets,
                self.command_tx.clone(),
                None,
            ) as u32,
            stored_locally: should_we_store,
        }
    }

    /// Propagate put content accepted content via OFFER/ACCEPT, returns trace detailing outcome of
    /// put content
    pub async fn propagate_put_content_trace(
        &self,
        content_key: TContentKey,
        data: RawContentValue,
    ) -> PutContentResult {
        trace_propagate_put_content_cross_thread::<_, TMetric>(
            content_key,
            data,
            &self.kbuckets,
            self.command_tx.clone(),
        )
        .await
    }

    /// Returns a vector of all the ENRs of nodes currently contained in the routing table.
    pub fn table_entries_enr(&self) -> Vec<Enr> {
        self.kbuckets.enrs()
    }

    /// Returns the node-id and a nested array of node-ids to represent this node's k-buckets table.
    pub fn routing_table_info(&self) -> RoutingTableInfo {
        RoutingTableInfo {
            local_node_id: self.local_enr().node_id(),
            buckets: ethportal_api::KBucketsTable::from(&self.kbuckets),
        }
    }

    /// `AddEnr` adds requested `enr` to our kbucket.
    pub fn add_enr(&self, enr: Enr) -> Result<(), OverlayRequestError> {
        match self.kbuckets.insert_or_update(
            Node::new(enr.clone(), Distance::MAX),
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
        self.kbuckets
            .entry(node_id)
            .present()
            .map(|node| node.enr)
            .ok_or_else(|| OverlayRequestError::Failure("Couldn't get ENR".to_string()))
    }

    /// `DeleteEnr` deletes requested `enr` from our kbucket.
    pub fn delete_enr(&self, node_id: NodeId) -> bool {
        self.kbuckets.remove(node_id)
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
        let payload =
            ClientInfoRadiusCapabilities::new(data_radius, self.ping_extensions.raw_extensions())
                .into();
        let request = Ping {
            enr_seq,
            payload_type: 0,
            payload,
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
        content_key: RawContentKey,
    ) -> Result<FindContentResult, OverlayRequestError> {
        // Construct the request.
        let request = FindContent {
            content_key: content_key.clone(),
        };
        let direction = RequestDirection::Outgoing {
            destination: enr.clone(),
        };
        let content_key = TContentKey::try_from_bytes(&content_key).map_err(|err| {
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
                        let content = RawContentValue::from(
                            self.init_find_content_stream(enr, conn_id).await?,
                        );
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
    ) -> Result<Bytes, OverlayRequestError> {
        let cid = utp_rs::cid::ConnectionId {
            recv: conn_id,
            send: conn_id.wrapping_add(1),
            peer_id: enr.node_id(),
        };
        self.utp_controller
            .connect_inbound_stream(cid, UtpPeer(enr))
            .await
            .map_err(|err| OverlayRequestError::ContentNotFound {
                message: format!("Unable to locate content on the network: {err:?}"),
                utp: true,
                trace: None,
            })
    }

    /// Send Offer request without storing the content into db
    pub async fn send_offer(
        &self,
        enr: Enr,
        content_items: Vec<(RawContentKey, RawContentValue)>,
    ) -> Result<Accept, OverlayRequestError> {
        // Construct the request.
        let request = Request::PopulatedOffer(PopulatedOffer { content_items });

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

    /// Send Offer request with trace, without storing the content into db
    pub async fn send_offer_trace(
        &self,
        enr: Enr,
        content_key: RawContentKey,
        content_value: RawContentValue,
    ) -> Result<OfferTrace, OverlayRequestError> {
        // Construct the request.
        let (result_tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let request = Request::PopulatedOfferWithResult(PopulatedOfferWithResult {
            content_item: (content_key, content_value),
            result_tx,
        });

        let direction = RequestDirection::Outgoing {
            destination: enr.clone(),
        };

        // Send the offer request and wait on the response.
        // Ignore the accept message, since we only care about the trace.
        self.send_overlay_request(request, direction).await?;

        // Wait for the trace response.
        match rx.recv().await {
            Some(accept) => Ok(accept),
            None => {
                warn!(
                    protocol = %self.protocol,
                    "Error receiving TraceOffer query response"
                );
                Err(OverlayRequestError::ChannelFailure(
                    "Error receiving TraceOffer query response".to_string(),
                ))
            }
        }
    }

    pub async fn lookup_node(&self, target: NodeId) -> Vec<Enr> {
        if target == self.local_enr().node_id() {
            return vec![self.local_enr()];
        }
        let is_connected = match self.kbuckets.entry(target) {
            Entry::Present(_, node_status) => node_status.is_connected(),
            _ => false,
        };
        if is_connected {
            match self.discovery.find_enr(&target) {
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
        config: FindContentConfig,
    ) -> Result<RecursiveFindContentResult, OverlayRequestError> {
        let (tx, rx) = oneshot::channel();
        let content_id = target.content_id();

        if let Err(err) = self.command_tx.send(OverlayCommand::FindContentQuery {
            target,
            callback: tx,
            config,
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
                    warn!(
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
                "Failed to bond with any bootnodes, unable to connect to subnetwork.",
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
    use rstest::rstest;

    use super::*;

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
