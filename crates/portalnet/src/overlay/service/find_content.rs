use std::{marker::Sync, sync::Arc};

use crossbeam_channel::Sender;
use discv5::{enr::NodeId, rpc::RequestId, Key};
use ethportal_api::{
    types::{
        distance::Metric,
        enr::{Enr, SszEnr},
        network_spec::network_spec,
        portal_wire::{
            Content, FindContent, PopulatedOffer, Request, MAX_PORTAL_CONTENT_PAYLOAD_SIZE,
        },
        query_trace::{QueryFailureKind, QueryTrace},
    },
    utils::bytes::hex_encode_compact,
    OverlayContentKey, RawContentKey, RawContentValue,
};
use futures::channel::oneshot;
use smallvec::SmallVec;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, error, trace, warn};
use trin_storage::{ContentStore, ShouldWeStoreContent};
use trin_validation::validator::Validator;

use super::{
    manager::{QueryEvent, UtpProcessing},
    OverlayService,
};
use crate::{
    discovery::UtpPeer,
    find::{
        iterators::{
            findcontent::{
                FindContentQuery, FindContentQueryPending, FindContentQueryResponse,
                FindContentQueryResult, ValidatedContent,
            },
            query::{Query, QueryConfig},
        },
        query_info::{QueryInfo, QueryType, RecursiveFindContentResult},
        query_pool::QueryId,
    },
    overlay::{
        command::OverlayCommand,
        config::FindContentConfig,
        errors::OverlayRequestError,
        ping_extensions::PingExtensions,
        request::{OverlayRequest, RequestDirection},
        service::{
            manager::{QueryTraceEvent, FIND_CONTENT_MAX_NODES},
            utils::pop_while_ssz_bytes_len_gt,
        },
    },
    put_content::propagate_put_content_cross_thread,
    types::kbucket::SharedKBucketsTable,
    utils::portal_wire::{decode_single_content_payload, encode_content_payload},
    utp::controller::UtpController,
};

/// Implementation of the `OverlayService` for handling FindContent and Content.
impl<
        TContentKey: 'static + OverlayContentKey + Send + Sync,
        TMetric: Metric + Send + Sync,
        TValidator: 'static + Validator<TContentKey> + Send + Sync,
        TStore: 'static + ContentStore<Key = TContentKey> + Send + Sync,
        TPingExtensions: 'static + PingExtensions + Send + Sync,
    > OverlayService<TContentKey, TMetric, TValidator, TStore, TPingExtensions>
{
    /// Attempts to build a `Content` response for a `FindContent` request.
    #[allow(clippy::result_large_err)]
    pub(super) fn handle_find_content(
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

                    let content = match network_spec().latest_common_protocol_version(&enr) {
                        Ok(protocol_version) if protocol_version.is_v1_enabled() => {
                            encode_content_payload(&[content])
                                .map_err(|err| {
                                    OverlayRequestError::AcceptError(format!(
                                        "Unable to encode content payload: {err}"
                                    ))
                                })?
                                .freeze()
                                .into()
                        }
                        Ok(_) => content,
                        Err(err) => {
                            // TODO: descore or ban this peer as they shouldn't be sending us
                            // requests unless they know we have a common protocol version.
                            return Err(OverlayRequestError::AcceptError(format!(
                                "Unable to get latest common protocol version: {err:?}"
                            )));
                        }
                    };

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

    /// Processes a Content response.
    pub(super) fn process_content(
        &mut self,
        content: Content,
        source: Enr,
        query_id: Option<QueryId>,
    ) {
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

    /// Advances a find content query (if one exists for `query_id`) with a connection id.
    pub(super) fn advance_find_content_query_with_connection_id(
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

    /// Advances a find content query (if one exists for `query_id`) with ENRs close to content.
    pub(super) fn advance_find_content_query_with_enrs(
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

    /// Advances a find content query (if one exists for `query_id`) with content.
    pub(super) fn advance_find_content_query_with_content(
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

    /// Handles a `QueryEvent` from a poll on the find content query pool.
    pub(super) fn handle_find_content_query_event(
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
                        let protocol = self.protocol;
                        tokio::spawn(async move {
                            let cid = utp_rs::cid::ConnectionId {
                                recv: connection_id,
                                send: connection_id.wrapping_add(1),
                                peer_id: source.node_id(),
                            };

                            let protocol_version = match network_spec()
                                .latest_common_protocol_version(&source)
                            {
                                Ok(protocol_version) => protocol_version,
                                Err(err) => {
                                    debug!(?err, "Unable to get latest common protocol version");
                                    return;
                                }
                            };

                            let data = match utp_processing
                                .utp_controller
                                .connect_inbound_stream(cid, UtpPeer(source))
                                .await
                            {
                                Ok(data) => {
                                    match protocol_version.is_v1_enabled() {
                                        true => match decode_single_content_payload(data) {
                                            Ok(data) => data,
                                            Err(err) => {
                                                debug!(
                                                    protocol = %protocol,
                                                    peer = %peer,
                                                    error = %err,
                                                    "Failed to decode FindContent v1 uTP payload"
                                                );
                                                // Indicate to the query that the content is invalid
                                                let _ = valid_content_tx.send(None);
                                                if let Some(query_trace_events_tx) =
                                                    query_trace_events_tx
                                                {
                                                    let _ = query_trace_events_tx.send(
                                                        QueryTraceEvent::Failure(
                                                            query_id,
                                                            peer,
                                                            QueryFailureKind::InvalidContent,
                                                        ),
                                                    );
                                                }
                                                return;
                                            }
                                        },
                                        false => data,
                                    }
                                }
                                Err(err) => {
                                    debug!(
                                        %err,
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

    /// Submits outgoing requests to offer `content` to the closest known nodes whose radius
    /// contains `content_key`.
    pub(super) fn poke_content(
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

    /// Starts a `FindContentQuery` for a target content key.
    pub(super) fn init_find_content_query(
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
}
