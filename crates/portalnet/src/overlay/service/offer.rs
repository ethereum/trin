use std::{marker::Sync, sync::Arc};

use alloy::primitives::Bytes;
use anyhow::{anyhow, bail};
use discv5::{enr::NodeId, rpc::RequestId};
use ethportal_api::{
    types::{
        accept_code::{AcceptCode, AcceptCodeList},
        distance::Metric,
        enr::Enr,
        network_spec::network_spec,
        portal_wire::{
            Accept, Content, FindContent, Offer, OfferTraceMultipleItems, Request, Response,
        },
        protocol_versions::ProtocolVersion,
    },
    OverlayContentKey, RawContentKey, RawContentValue,
};
use futures::{channel::oneshot, future::join_all};
use parking_lot::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, enabled, error, trace, warn, Level};
use trin_storage::{ContentStore, ShouldWeStoreContent};
use trin_validation::validator::Validator;
use utp_rs::cid::ConnectionId;

use super::{manager::UtpProcessing, OverlayService};
use crate::{
    discovery::UtpPeer,
    overlay::{
        command::OverlayCommand,
        errors::OverlayRequestError,
        ping_extensions::PingExtensions,
        request::{OverlayRequest, RequestDirection},
    },
    put_content::propagate_put_content_cross_thread,
    utils::portal_wire::{self, decode_single_content_payload},
    utp::timed_semaphore::OwnedTimedSemaphorePermit,
};

/// Implementation of the `OverlayService` for handling FindNodes/Nodes.
impl<
        TContentKey: 'static + OverlayContentKey + Send + Sync,
        TMetric: Metric + Send + Sync,
        TValidator: 'static + Validator<TContentKey> + Send + Sync,
        TStore: 'static + ContentStore<Key = TContentKey> + Send + Sync,
        TPingExtensions: 'static + PingExtensions + Send + Sync,
    > OverlayService<TContentKey, TMetric, TValidator, TStore, TPingExtensions>
{
    /// Attempts to build an `Accept` response for an `Offer` request.
    #[allow(clippy::result_large_err)]
    pub(super) fn handle_offer(
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

        let mut requested_keys = AcceptCodeList::new(request.content_keys.len()).map_err(|_| {
            OverlayRequestError::AcceptError(
                "Unable to initialize bitlist for requested keys.".to_owned(),
            )
        })?;

        // if we're unable to find the ENR for the source node we throw an error
        // since the enr is required for the accept queue, and it is expected to be present
        let enr = self.find_enr(source).ok_or_else(|| {
            OverlayRequestError::AcceptError(format!(
                "handle_offer: unable to find ENR for NodeId: source={source:?}"
            ))
        })?;

        let protocol_version = match network_spec().latest_common_protocol_version(&enr) {
            Ok(protocol_version) => protocol_version,
            Err(err) => {
                return Err(OverlayRequestError::AcceptError(format!(
                    "Unable to get latest common protocol version: {err:?}"
                )));
            }
        };

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
                requested_keys
                    .iter_mut()
                    .for_each(|accept_code| *accept_code = AcceptCode::RateLimited);
                return Ok(Accept::new(protocol_version, 0, requested_keys));
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

        for (i, key) in content_keys.iter().enumerate() {
            // Accept content if within radius and not already present in the data store.
            let accept = self
                .store
                .lock()
                .is_key_within_radius_and_unavailable(key)
                .map_err(|err| {
                    OverlayRequestError::AcceptError(format!(
                        "Unable to check content availability {err}"
                    ))
                })?;
            let accept_code = match accept {
                ShouldWeStoreContent::Store => {
                    // accept all keys that are successfully added to the queue
                    if self.accept_queue.write().add_key_to_queue(key, &enr) {
                        accepted_keys.push(key.clone());
                        AcceptCode::Accepted
                    } else {
                        AcceptCode::InboundTransferInProgress
                    }
                }
                ShouldWeStoreContent::NotWithinRadius => AcceptCode::NotWithinRadius,
                ShouldWeStoreContent::AlreadyStored => AcceptCode::AlreadyStored,
            };

            requested_keys.set(i, accept_code);
        }

        // If no content keys were accepted, then return an Accept with a connection ID value of
        // zero.
        if requested_keys.all_declined() {
            return Ok(Accept::new(protocol_version, 0, requested_keys));
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
                                if let Err(err) = Self::fallback_find_content(
                                    content_key.clone(),
                                    utp_processing,
                                    protocol_version
                                )
                                .await {
                                    debug!(%err, ?content_key, "Fallback FINDCONTENT task failed, after uTP transfer failed");
                                }
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
                Err(err) => {
                    debug!(%err, ?content_keys_string, "Decoding and validating content payload failed");
                    let handles: Vec<JoinHandle<_>> = content_keys
                        .into_iter()
                        .map(|content_key| {
                            let utp_processing = utp_processing.clone();
                            tokio::spawn(async move {
                                if let Err(err) = Self::fallback_find_content(
                                    content_key.clone(),
                                    utp_processing,
                                    protocol_version
                                )
                                .await {
                                    debug!(%err, ?content_key, "Fallback FINDCONTENT task failed, decoding and validating content payload failed");
                                }
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
                                if let Err(err) = Self::fallback_find_content(
                                    key.clone(),
                                    utp_processing,
                                    protocol_version
                                )
                                .await {
                                    debug!(%err, ?key, "Fallback FINDCONTENT task failed, after validating and storing content failed");
                                }
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

        Ok(Accept::new(
            protocol_version,
            cid_send.to_be(),
            requested_keys,
        ))
    }

    // Process ACCEPT response
    pub(super) fn process_accept(
        &self,
        response: Accept,
        enr: Enr,
        offer: Request,
        request_permit: Option<OwnedTimedSemaphorePermit>,
    ) -> anyhow::Result<()> {
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

        let protocol_version = match network_spec().latest_common_protocol_version(&enr) {
            Ok(protocol_version) => protocol_version,
            Err(err) => {
                bail!("Unable to get latest common protocol version with peer: {err:?}");
            }
        };

        let content_keys = AcceptCodeList::decode(protocol_version, response.content_keys)
            .map_err(|err| {
                OverlayRequestError::AcceptError(format!(
                    "Unable to decode ACCEPT response payload: {err:?}"
                ))
            })?;

        // Do not initialize uTP stream if remote node doesn't have interest in the offered content
        // keys
        if content_keys.all_declined() {
            if let Some(tx) = gossip_result_tx {
                if let Err(err) = tx.send(OfferTraceMultipleItems::Success(content_keys)) {
                    warn!(%err, "Unable to send OfferTrace result all keys declined");
                }
            }
            return Ok(());
        }

        // Build a connection ID based on the response.
        let conn_id = u16::from_be(response.connection_id);
        let cid = utp_rs::cid::ConnectionId {
            recv: conn_id,
            send: conn_id.wrapping_add(1),
            peer_id: enr.node_id(),
        };
        let store = Arc::clone(&self.store);
        let utp_controller = Arc::clone(&self.utp_controller);
        tokio::spawn(async move {
            let peer = UtpPeer(enr);
            let content_items = match offer {
                Request::Offer(offer) => {
                    Self::provide_requested_content(store, &content_keys, offer.content_keys)
                }
                Request::PopulatedOffer(offer) => Ok(content_keys
                    .iter()
                    .zip(offer.content_items)
                    .filter(|(is_accepted, _item)| **is_accepted == AcceptCode::Accepted)
                    .map(|(_is_accepted, (_key, val))| val)
                    .collect()),
                Request::PopulatedOfferWithResult(offer) => Ok(content_keys
                    .iter()
                    .zip(offer.content_items)
                    .filter(|(is_accepted, _item)| **is_accepted == AcceptCode::Accepted)
                    .map(|(_is_accepted, (_key, val))| val)
                    .collect()),
                // Unreachable because of early return at top of method:
                _ => Err(anyhow!("Invalid request message paired with ACCEPT")),
            };

            let content_items: Vec<Bytes> = match content_items {
                Ok(items) => items,
                Err(err) => {
                    error!(
                        %err,
                        cid.send,
                        cid.recv,
                        peer = ?peer.client(),
                        "Error decoding previously offered content items"
                    );
                    if let Some(tx) = gossip_result_tx {
                        if let Err(err) = tx.send(OfferTraceMultipleItems::Failed) {
                            warn!(%err, "Unable to send OfferTrace Failed result for decoding offered content items");
                        }
                    }
                    return;
                }
            };

            let content_payload = match portal_wire::encode_content_payload(&content_items) {
                Ok(payload) => payload,
                Err(err) => {
                    warn!(%err, "Unable to build content payload");
                    if let Some(tx) = gossip_result_tx {
                        if let Err(err) = tx.send(OfferTraceMultipleItems::Failed) {
                            warn!(%err, "Unable to send OfferTrace Failed result failed to build content payload");
                        }
                    }
                    return;
                }
            };
            let result = utp_controller
                .connect_outbound_stream(cid, peer, &content_payload)
                .await;
            if let Some(tx) = gossip_result_tx {
                let result = if result {
                    OfferTraceMultipleItems::Success(content_keys)
                } else {
                    OfferTraceMultipleItems::Failed
                };
                if let Err(err) = tx.send(result) {
                    warn!(%err, "Unable to send OfferTrace result");
                }
            }
            // explicitly drop permit in the thread so the permit is included in the thread
            if let Some(permit) = request_permit {
                permit.drop();
            }
        });

        Ok(())
    }

    /// Attempts to send a single FINDCONTENT request to a fallback peer,
    /// if found in the accept queue. Then validate, store & propagate the content.
    async fn fallback_find_content(
        content_key: TContentKey,
        utp_processing: UtpProcessing<TValidator, TStore, TContentKey>,
        protocol_version: ProtocolVersion,
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
                        let bytes = utp_processing
                            .utp_controller
                            .connect_inbound_stream(cid, UtpPeer(fallback_peer.clone()))
                            .await?;

                        match protocol_version.is_v1_enabled() {
                            true => match decode_single_content_payload(bytes) {
                                Ok(bytes) => bytes,
                                Err(err) => bail!(
                                    "Unable to decode content payload from FINDCONTENT v1 response {err:?}",
                                ),
                            },
                            false => bytes,
                        }
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

    /// Provide the requested content key and content value for the acceptor
    fn provide_requested_content(
        store: Arc<Mutex<TStore>>,
        accept_code_list: &AcceptCodeList,
        content_keys_offered: Vec<RawContentKey>,
    ) -> anyhow::Result<Vec<RawContentValue>> {
        let content_keys_offered = content_keys_offered
            .iter()
            .map(TContentKey::try_from_bytes)
            .collect::<Result<Vec<_>, _>>();

        let content_keys_offered: Vec<TContentKey> = content_keys_offered
            .map_err(|_| anyhow!("Unable to decode our own offered content keys"))?;

        let mut content_items: Vec<RawContentValue> = Vec::new();

        for (accept_code, key) in accept_code_list
            .clone()
            .iter()
            .zip(content_keys_offered.iter())
        {
            if *accept_code == AcceptCode::Accepted {
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
    Ok(content_values)
}
