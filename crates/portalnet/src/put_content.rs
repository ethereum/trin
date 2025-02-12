use std::{collections::HashMap, sync::Arc};

use ethportal_api::{
    types::{
        distance::Metric,
        enr::Enr,
        node_contact::NodeContact,
        portal::MAX_CONTENT_KEYS_PER_OFFER,
        portal_wire::{OfferTrace, PopulatedOffer, PopulatedOfferWithResult, Request, Response},
    },
    utils::bytes::{hex_encode, hex_encode_compact},
    OverlayContentKey, RawContentValue,
};
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
    utp::controller::UtpController,
};

/// Datatype to store the result of a put content request.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize, Default)]
pub struct PutContentResult {
    /// List of all ENRs that were offered the content
    pub offered: Vec<Enr>,
    /// List of all ENRs that accepted the offer
    pub accepted: Vec<Enr>,
    /// List of all ENRs to whom the content was successfully transferred
    pub transferred: Vec<Enr>,
}

/// Propagate put content in a way that can be used across threads, without &self.
/// Doesn't trace put content results
pub fn propagate_put_content_cross_thread<TContentKey: OverlayContentKey, TMetric: Metric>(
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
    let mut content_id_to_interested_node_contacts =
        kbuckets.batch_interested_node_contacts::<TMetric>(&content_ids);

    // Map from ENRs to content they will put content
    let mut node_contacts_and_content: HashMap<NodeContact, Vec<&(TContentKey, RawContentValue)>> =
        HashMap::new();
    for (content_id, content_key_value) in &content {
        let interested_node_contacts = content_id_to_interested_node_contacts.remove(content_id).unwrap_or_else(|| {
            error!("interested_node_contacts should contain all content ids, even if there are no interested ENRs");
            vec![]
        });
        if interested_node_contacts.is_empty() {
            debug!(
                content.id = %hex_encode(content_id),
                "No peers eligible for neighborhood gossip"
            );
            continue;
        };

        // Select put content recipients
        for node_contact in
            select_put_content_recipients::<TMetric>(content_id, interested_node_contacts)
        {
            node_contacts_and_content
                .entry(node_contact)
                .or_default()
                .push(content_key_value);
        }
    }

    let num_propagated_peers = node_contacts_and_content.len();

    // Create and send OFFER overlay request to the interested nodes
    for (node_contact, mut interested_content) in node_contacts_and_content {
        let permit = match utp_controller {
            Some(ref utp_controller) => match utp_controller.get_outbound_semaphore() {
                Some(permit) => Some(permit),
                None => {
                    trace!("Permit for put content not acquired! Skipping offering to node_contact: {}", node_contact.enr);
                    continue;
                }
            },
            None => None,
        };

        // offer messages are limited to 64 content keys
        if interested_content.len() > MAX_CONTENT_KEYS_PER_OFFER {
            warn!(
                enr = %node_contact.enr,
                content.len = interested_content.len(),
                "Too many content items to offer to a single peer, dropping {}.",
                interested_content.len() - MAX_CONTENT_KEYS_PER_OFFER
            );
            // sort content keys by distance to the node
            interested_content.sort_by_cached_key(|(key, _)| {
                TMetric::distance(&key.content_id(), &node_contact.enr.node_id().raw())
            });
            // take 64 closest content keys
            interested_content.truncate(MAX_CONTENT_KEYS_PER_OFFER);
        }
        // change content keys to raw content keys
        let interested_content = interested_content
            .into_iter()
            .map(|(key, value)| (key.to_bytes(), value.clone()))
            .collect();
        let offer_request = Request::PopulatedOffer(PopulatedOffer {
            content_items: interested_content,
        });

        let overlay_request = OverlayRequest::new(
            offer_request,
            RequestDirection::Outgoing {
                destination: node_contact,
            },
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

/// Propagate put content in a way that can be used across threads, without &self.
/// This function is designed to be used via the JSON-RPC API. Since it is blocking, it should not
/// be used internally in the offer/accept flow.
/// Returns a trace detailing the outcome of the put content.
pub async fn trace_propagate_put_content_cross_thread<
    TContentKey: OverlayContentKey,
    TMetric: Metric,
>(
    content_key: TContentKey,
    data: RawContentValue,
    kbuckets: &SharedKBucketsTable,
    command_tx: mpsc::UnboundedSender<OverlayCommand<TContentKey>>,
) -> PutContentResult {
    let mut put_content_result = PutContentResult::default();

    let content_id = content_key.content_id();

    let interested_node_contacts = kbuckets.interested_node_contacts::<TMetric>(&content_id);
    if interested_node_contacts.is_empty() {
        debug!(content.id = %hex_encode(content_id), "No peers eligible for trace put content");
        return put_content_result;
    };

    // Select ENRs to put content to, create and send OFFER overlay request to the interested nodes
    for node_contact in
        select_put_content_recipients::<TMetric>(&content_id, interested_node_contacts)
    {
        let (result_tx, mut result_rx) = tokio::sync::mpsc::unbounded_channel();
        let offer_request = Request::PopulatedOfferWithResult(PopulatedOfferWithResult {
            content_item: (content_key.clone().to_bytes(), data.clone()),
            result_tx,
        });

        let (tx, rx) = oneshot::channel();
        let responder = Some(tx);
        let overlay_request = OverlayRequest::new(
            offer_request,
            RequestDirection::Outgoing {
                destination: node_contact.clone(),
            },
            responder,
            None,
            None,
        );
        if let Err(err) = command_tx.send(OverlayCommand::Request(overlay_request)) {
            error!(error = %err, "Error sending OFFER message to service");
            continue;
        }
        // update put content result with peer marked as being offered the content
        put_content_result.offered.push(node_contact.enr.clone());
        match rx.await {
            Ok(res) => {
                if let Ok(Response::Accept(accept)) = res {
                    if !accept.content_keys.is_zero() {
                        // update put content result with peer marked as accepting the content
                        put_content_result.accepted.push(node_contact.enr.clone());
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
            // update put content result with peer marked as successfully transferring the content
            put_content_result.transferred.push(node_contact.enr);
        }
    }
    put_content_result
}

const NUM_CLOSEST_NODES: usize = 4;
const NUM_FARTHER_NODES: usize = 4;

/// Selects put content recipients from a vec of interested ENRs.
///
/// If number of NodeContacts is at most `NUM_CLOSEST_NODES + NUM_FARTHER_NODES`, then all are returned.
/// Otherwise, NodeContacts are sorted by distance from `content_id` and then:
///
/// 1. Closest `NUM_CLOSEST_NODES` NodeContacts are selected
/// 2. Random `NUM_FARTHER_NODES` NodeContacts are selected from the rest
fn select_put_content_recipients<TMetric: Metric>(
    content_id: &[u8; 32],
    mut node_contacts: Vec<NodeContact>,
) -> Vec<NodeContact> {
    // Check if we need to do any selection
    if node_contacts.len() <= NUM_CLOSEST_NODES + NUM_FARTHER_NODES {
        return node_contacts;
    }

    // Sort enrs by distance
    node_contacts.sort_by_cached_key(|node_contact| {
        TMetric::distance(content_id, &node_contact.enr.node_id().raw())
    });

    // Split of at NUM_CLOSEST_NODES
    let mut farther_node_contacts = node_contacts.split_off(NUM_CLOSEST_NODES);

    // Select random NUM_FARTHER_NODES
    let mut rng = rand::thread_rng();
    for _ in 0..NUM_FARTHER_NODES {
        let node_contact =
            farther_node_contacts.swap_remove(rng.gen_range(0..farther_node_contacts.len()));
        node_contacts.push(node_contact);
    }

    node_contacts
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use ethportal_api::types::{
        distance::XorMetric, node_contact::generate_random_remote_node_contact,
    };
    use rand::random;
    use rstest::rstest;

    use super::*;

    #[allow(clippy::zero_repeat_side_effects)]
    #[rstest]
    #[case(vec![generate_random_remote_node_contact().1; 0], 0)]
    #[case(vec![generate_random_remote_node_contact().1; NUM_CLOSEST_NODES - 1], NUM_CLOSEST_NODES - 1)]
    #[case(vec![generate_random_remote_node_contact().1; NUM_CLOSEST_NODES], NUM_CLOSEST_NODES)]
    #[case(vec![generate_random_remote_node_contact().1; NUM_CLOSEST_NODES + 1], NUM_CLOSEST_NODES + 1)]
    #[case(vec![generate_random_remote_node_contact().1; NUM_CLOSEST_NODES + NUM_FARTHER_NODES], NUM_CLOSEST_NODES + NUM_FARTHER_NODES)]
    #[case(vec![generate_random_remote_node_contact().1; 256], NUM_CLOSEST_NODES + NUM_FARTHER_NODES)]
    fn test_select_put_content_recipients_no_panic(
        #[case] all_nodes: Vec<NodeContact>,
        #[case] expected_size: usize,
    ) {
        let put_content_recipients =
            select_put_content_recipients::<XorMetric>(&random(), all_nodes);
        assert_eq!(put_content_recipients.len(), expected_size);
    }
}
