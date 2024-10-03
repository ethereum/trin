use std::{collections::HashMap, sync::Arc};

use futures::channel::oneshot;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, error, trace, warn};

use crate::{
    overlay::{
        command::OverlayCommand,
        request::{OverlayRequest, RequestDirection},
    },
    types::kbucket::SharedKBucketsTable,
    utp_controller::UtpController,
};
use ethportal_api::{
    types::{
        distance::Metric,
        enr::Enr,
        portal::MAX_CONTENT_KEYS_PER_OFFER,
        portal_wire::{OfferTrace, PopulatedOffer, PopulatedOfferWithResult, Request, Response},
    },
    utils::bytes::{hex_encode, hex_encode_compact},
    OverlayContentKey, RawContentValue,
};

/// Datatype to store the result of a gossip request.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Default)]
pub struct GossipResult {
    /// List of all ENRs that were offered the content
    pub offered: Vec<Enr>,
    /// List of all ENRs that accepted the offer
    pub accepted: Vec<Enr>,
    /// List of all ENRs to whom the content was successfully transferred
    pub transferred: Vec<Enr>,
}

/// Propagate gossip in a way that can be used across threads, without &self.
/// Doesn't trace gossip results
pub fn propagate_gossip_cross_thread<TContentKey: OverlayContentKey, TMetric: Metric>(
    content: Vec<(TContentKey, RawContentValue)>,
    kbuckets: &SharedKBucketsTable,
    command_tx: mpsc::UnboundedSender<OverlayCommand<TContentKey>>,
    utp_controller: Option<Arc<UtpController>>,
) -> usize {
    // Precalculate content ids
    let content = content
        .into_iter()
        .map(|(content_key, content_value)| {
            (content_key.content_id(), (content_key, content_value))
        })
        .collect::<HashMap<_, _>>();

    let content_ids = content.keys().collect::<Vec<_>>();
    debug!(
        ids = ?content_ids.iter().map(hex_encode_compact),
        "propagating validated content",
    );

    // Map from content_ids to interested ENRs
    let mut content_id_to_interested_enrs = kbuckets.batch_interested_enrs::<TMetric>(&content_ids);

    // Map from ENRs to content they will gossip
    let mut enrs_and_content: HashMap<Enr, Vec<&(TContentKey, RawContentValue)>> = HashMap::new();
    for (content_id, content_key_value) in &content {
        let interested_enrs = content_id_to_interested_enrs.remove(content_id).unwrap_or_else(|| {
            error!("interested_enrs should contain all content ids, even if there are no interested ENRs");
            vec![]
        });
        if interested_enrs.is_empty() {
            debug!(
                content.id = %hex_encode(content_id),
                "No peers eligible for neighborhood gossip"
            );
            continue;
        };

        // Select gossip recipients
        for enr in select_gossip_recipients::<TMetric>(content_id, interested_enrs) {
            enrs_and_content
                .entry(enr)
                .or_default()
                .push(content_key_value);
        }
    }

    let num_propagated_peers = enrs_and_content.len();

    // Create and send OFFER overlay request to the interested nodes
    for (enr, mut interested_content) in enrs_and_content {
        let permit = match utp_controller {
            Some(ref utp_controller) => match utp_controller.get_outbound_semaphore() {
                Some(permit) => Some(permit),
                None => {
                    trace!("Permit for gossip not acquired! Skipping gossiping to enr: {enr}");
                    continue;
                }
            },
            None => None,
        };

        // offer messages are limited to 64 content keys
        if interested_content.len() > MAX_CONTENT_KEYS_PER_OFFER {
            warn!(
                enr = %enr,
                content.len = interested_content.len(),
                "Too many content items to offer to a single peer, dropping {}.",
                interested_content.len() - MAX_CONTENT_KEYS_PER_OFFER
            );
            // sort content keys by distance to the node
            interested_content.sort_by_cached_key(|(key, _)| {
                TMetric::distance(&key.content_id(), &enr.node_id().raw())
            });
            // take 64 closest content keys
            interested_content.truncate(MAX_CONTENT_KEYS_PER_OFFER);
        }
        // change content keys to raw content keys
        let interested_content = interested_content
            .into_iter()
            .map(|(key, value)| (key.to_bytes(), value.clone().into()))
            .collect();
        let offer_request = Request::PopulatedOffer(PopulatedOffer {
            content_items: interested_content,
        });

        let overlay_request = OverlayRequest::new(
            offer_request,
            RequestDirection::Outgoing { destination: enr },
            None,
            None,
            permit,
        );

        if let Err(err) = command_tx.send(OverlayCommand::Request(overlay_request)) {
            error!(error = %err, "Error sending OFFER message to service")
        }
    }

    num_propagated_peers
}

/// Propagate gossip in a way that can be used across threads, without &self.
/// This function is designed to be used via the JSON-RPC API. Since it is blocking, it should not
/// be used internally in the offer/accept flow.
/// Returns a trace detailing the outcome of the gossip.
pub async fn trace_propagate_gossip_cross_thread<
    TContentKey: OverlayContentKey,
    TMetric: Metric,
>(
    content_key: TContentKey,
    data: RawContentValue,
    kbuckets: &SharedKBucketsTable,
    command_tx: mpsc::UnboundedSender<OverlayCommand<TContentKey>>,
) -> GossipResult {
    let mut gossip_result = GossipResult::default();

    let content_id = content_key.content_id();

    let interested_enrs = kbuckets.interested_enrs::<TMetric>(&content_id);
    if interested_enrs.is_empty() {
        debug!(content.id = %hex_encode(content_id), "No peers eligible for trace gossip");
        return gossip_result;
    };

    // Select ENRs to gossip to, create and send OFFER overlay request to the interested nodes
    for enr in select_gossip_recipients::<TMetric>(&content_id, interested_enrs) {
        let (result_tx, mut result_rx) = tokio::sync::mpsc::unbounded_channel();
        let offer_request = Request::PopulatedOfferWithResult(PopulatedOfferWithResult {
            content_item: (content_key.clone().to_bytes(), data.clone().into()),
            result_tx,
        });

        let (tx, rx) = oneshot::channel();
        let responder = Some(tx);
        let overlay_request = OverlayRequest::new(
            offer_request,
            RequestDirection::Outgoing {
                destination: enr.clone(),
            },
            responder,
            None,
            None,
        );
        if let Err(err) = command_tx.send(OverlayCommand::Request(overlay_request)) {
            error!(error = %err, "Error sending OFFER message to service");
            continue;
        }
        // update gossip result with peer marked as being offered the content
        gossip_result.offered.push(enr.clone());
        match rx.await {
            Ok(res) => {
                if let Ok(Response::Accept(accept)) = res {
                    if !accept.content_keys.is_zero() {
                        // update gossip result with peer marked as accepting the content
                        gossip_result.accepted.push(enr.clone());
                    }
                } else {
                    // continue to next peer if no content was accepted
                    continue;
                }
            }
            // continue to next peer if err while waiting for response
            Err(_) => continue,
        }
        if let Some(OfferTrace::Success(_)) = result_rx.recv().await {
            // update gossip result with peer marked as successfully transferring the content
            gossip_result.transferred.push(enr);
        }
    }
    gossip_result
}

const NUM_CLOSEST_NODES: usize = 4;
const NUM_FARTHER_NODES: usize = 4;

/// Selects gossip recipients from a vec of interested ENRs.
///
/// If number of ENRs is at most `NUM_CLOSEST_NODES + NUM_FARTHER_NODES`, then all are returned.
/// Otherwise, ENRs are sorted by distance from `content_id` and then:
///
/// 1. Closest `NUM_CLOSEST_NODES` ENRs are selected
/// 2. Random `NUM_FARTHER_NODES` ENRs are selected from the rest
fn select_gossip_recipients<TMetric: Metric>(
    content_id: &[u8; 32],
    mut enrs: Vec<Enr>,
) -> Vec<Enr> {
    // Check if we need to do any selection
    if enrs.len() <= NUM_CLOSEST_NODES + NUM_FARTHER_NODES {
        return enrs;
    }

    // Sort enrs by distance
    enrs.sort_by_cached_key(|enr| TMetric::distance(content_id, &enr.node_id().raw()));

    // Split of at NUM_CLOSEST_NODES
    let mut farther_enrs = enrs.split_off(NUM_CLOSEST_NODES);

    // Select random NUM_FARTHER_NODES
    let mut rng = rand::thread_rng();
    for _ in 0..NUM_FARTHER_NODES {
        let enr = farther_enrs.swap_remove(rng.gen_range(0..farther_enrs.len()));
        enrs.push(enr);
    }

    enrs
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    use rand::random;
    use rstest::rstest;

    use ethportal_api::types::{distance::XorMetric, enr::generate_random_remote_enr};

    #[allow(clippy::zero_repeat_side_effects)]
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
        let gossip_recipients = select_gossip_recipients::<XorMetric>(&random(), all_nodes);
        assert_eq!(gossip_recipients.len(), expected_size);
    }
}
