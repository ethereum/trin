use std::{collections::HashMap, str::FromStr, sync::Arc};

use discv5::{
    enr::NodeId,
    kbucket::{self, KBucketsTable},
};
use futures::channel::oneshot;
use parking_lot::RwLock;
use rand::{seq::SliceRandom, thread_rng};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use crate::{
    overlay::{
        command::OverlayCommand,
        request::{OverlayRequest, RequestDirection},
    },
    types::node::Node,
    utp_controller::UtpController,
};
use ethportal_api::{
    types::{
        distance::{Metric, XorMetric},
        enr::Enr,
        portal_wire::{PopulatedOffer, PopulatedOfferWithResult, Request, Response},
    },
    utils::bytes::hex_encode,
    OverlayContentKey, RawContentKey,
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

fn get_local_nodes(
    kbuckets: &Arc<RwLock<KBucketsTable<NodeId, Node>>>,
) -> Vec<kbucket::Node<NodeId, Node>> {
    kbuckets
        .read()
        .buckets_iter()
        .flat_map(|kbucket| {
            kbucket
                .iter()
                .filter(|node| node.status.is_connected())
                .map(|node| node.to_owned())
                .collect::<Vec<kbucket::Node<NodeId, Node>>>()
        })
        .collect()
}

/// Propagate gossip in a way that can be used across threads, without &self.
/// Doesn't trace gossip results
pub async fn propagate_gossip_cross_thread<TContentKey: OverlayContentKey>(
    content: Vec<(TContentKey, Vec<u8>)>,
    kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
    command_tx: mpsc::UnboundedSender<OverlayCommand<TContentKey>>,
    utp_controller: Option<Arc<UtpController>>,
) -> usize {
    // Get all connected nodes from overlay routing table
    let local_nodes = get_local_nodes(&kbuckets);

    // HashMap to temporarily store all interested ENRs and the content.
    // Key is base64 string of node's ENR.
    let mut enrs_and_content: HashMap<String, Vec<(RawContentKey, Vec<u8>)>> = HashMap::new();

    for (content_key, content_value) in content {
        let (tx, rx) = oneshot::channel();
        let target = discv5::enr::NodeId::from(content_key.content_id());
        if let Err(msg) = command_tx.send(OverlayCommand::FindNodeQuery {
            target,
            callback: tx,
        }) {
            error!(error = %msg, "Error sending FIND_NODE message to service during RFN gossip lookup");
        };
        let mut rfn_nodes = rx.await.unwrap_or_else(|_| {
            error!("Failed to get RFN nodes for content key gossip");
            vec![]
        });
        let interested_enrs = calculate_interested_enrs(&content_key, &local_nodes, &mut rfn_nodes);

        // Temporarily store all randomly selected nodes with the content of interest.
        // We want this so we can offer all the content to an interested node in one request.
        let raw_item = (content_key.into(), content_value);
        for enr in interested_enrs {
            enrs_and_content
                .entry(enr.to_base64())
                .or_default()
                .push(raw_item.clone());
        }
    }

    let num_propagated_peers = enrs_and_content.len();
    // Create and send OFFER overlay request to the interested nodes
    for (enr_string, interested_content) in enrs_and_content.into_iter() {
        let permit = match utp_controller {
            Some(ref utp_controller) => match utp_controller.get_outbound_semaphore() {
                Some(permit) => Some(permit),
                None => continue,
            },
            None => None,
        };

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
pub async fn trace_propagate_gossip_cross_thread<TContentKey: OverlayContentKey>(
    content_key: TContentKey,
    data: Vec<u8>,
    kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
    command_tx: mpsc::UnboundedSender<OverlayCommand<TContentKey>>,
) -> GossipResult {
    let mut gossip_result = GossipResult::default();
    // Get all connected nodes from overlay routing table
    let interested_enrs = {
        let local_nodes = get_local_nodes(&kbuckets);
        let local_nodes: Vec<kbucket::Node<NodeId, Node>> = local_nodes
            .into_iter()
            .map(|node| node.to_owned())
            .collect();
        let (tx, rx) = oneshot::channel();
        let target = discv5::enr::NodeId::from(content_key.content_id());
        if let Err(msg) = command_tx.send(OverlayCommand::FindNodeQuery {
            target,
            callback: tx,
        }) {
            error!(error = %msg, "Error sending FIND_NODE message to service during RFN gossip lookup");
        };
        let mut rfn_nodes = rx.await.unwrap_or_else(|_| {
            error!("Failed to get RFN nodes for content key gossip");
            vec![]
        });
        calculate_interested_enrs(&content_key, &local_nodes, &mut rfn_nodes)
    };
    if interested_enrs.is_empty() {
        return gossip_result;
    };

    // Create and send OFFER overlay request to the interested nodes
    for enr in interested_enrs.into_iter() {
        let (result_tx, mut result_rx) = tokio::sync::mpsc::unbounded_channel();
        let offer_request = Request::PopulatedOfferWithResult(PopulatedOfferWithResult {
            content_item: (content_key.clone().into(), data.clone()),
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
        if let Some(result) = result_rx.recv().await {
            if result {
                // update gossip result with peer marked as successfully transferring the content
                gossip_result.transferred.push(enr);
            }
        }
    }
    gossip_result
}

/// Filter all nodes from overlay routing table where XOR_distance(content_id, nodeId) < node radius
fn calculate_interested_enrs<TContentKey: OverlayContentKey>(
    content_key: &TContentKey,
    local_nodes: &[kbucket::Node<NodeId, Node>],
    rfn_nodes: &mut Vec<Enr>,
) -> Vec<Enr> {
    // HashMap to temporarily store all interested ENRs and the content.
    // Key is base64 string of node's ENR.

    // Filter all nodes from overlay routing table where XOR_distance(content_id, nodeId) < node
    // radius
    let mut interested_enrs: Vec<Enr> = local_nodes
        .iter()
        .filter(|node| {
            XorMetric::distance(&content_key.content_id(), &node.key.preimage().raw())
                < node.value.data_radius()
        })
        .map(|node| node.value.enr())
        .collect();

    // Continue if no nodes are interested in the content
    if interested_enrs.is_empty() && rfn_nodes.is_empty() {
        debug!(
            content.id = %hex_encode(content_key.content_id()),
            kbuckets.len = local_nodes.len(),
            "No peers eligible for neighborhood gossip"
        );
        return vec![];
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
    select_gossip_recipients(interested_enrs, rfn_nodes)
}

const NUM_CLOSEST_NODES: usize = 4;
const NUM_RFN_NODES: usize = 4;
const MAX_NODES: usize = 8;
/// Selects gossip recipients from a vec of sorted interested ENRs.
/// Returned vec is a concatenation of, at most:
/// 1. First `NUM_CLOSEST_NODES` elements of `interested_sorted_enrs`.
/// 2. `NUM_FARTHER_NODES` elements randomly selected from
///    `interested_sorted_enrs[NUM_CLOSEST_NODES..]`
fn select_gossip_recipients(
    interested_sorted_enrs: Vec<Enr>,
    rfn_nodes: &mut Vec<Enr>,
) -> Vec<Enr> {
    let mut gossip_recipients: Vec<Enr> = vec![];
    let rfn_node_ids: Vec<NodeId> = rfn_nodes.iter().map(|enr| enr.node_id()).collect();

    // Filter out all duplicates
    let mut interested_sorted_enrs: Vec<Enr> = interested_sorted_enrs
        .into_iter()
        .filter(|enr| !rfn_node_ids.contains(&enr.node_id()))
        .collect();

    // Get first n rfn nodes
    while gossip_recipients.len() < NUM_RFN_NODES {
        match rfn_nodes.pop() {
            Some(enr) => gossip_recipients.push(enr),
            None => break,
        }
    }

    // Append first n closest nodes
    let rfn_count = gossip_recipients.len();
    while gossip_recipients.len() < rfn_count + NUM_CLOSEST_NODES {
        match interested_sorted_enrs.pop() {
            Some(enr) => gossip_recipients.push(enr),
            None => break,
        }
    }

    // Fill remaining slots with random nodes from interested_sorted_enrs
    interested_sorted_enrs.shuffle(&mut thread_rng());
    while gossip_recipients.len() < MAX_NODES {
        match interested_sorted_enrs.pop() {
            Some(enr) => gossip_recipients.push(enr),
            None => break,
        }
    }
    gossip_recipients
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    use rstest::rstest;

    use ethportal_api::types::enr::generate_random_remote_enr;

    #[rstest]
    #[case(0, 0, 0)]
    #[case(0, 3, 3)]
    #[case(3, 0, 3)]
    #[case(7, 0, 7)]
    #[case(2, 2, 4)]
    #[case(5, 5, MAX_NODES)]
    #[case(7, 2, MAX_NODES)]
    #[case(2, 7, 6)]
    #[case(7, 7, MAX_NODES)]
    #[case(12, 0, MAX_NODES)]
    #[case(0, 12, NUM_RFN_NODES)]
    fn test_select_gossip_recipients(
        #[case] local_nodes: usize,
        #[case] rfn_nodes: usize,
        #[case] expected_size: usize,
    ) {
        let mut rfn_nodes = (0..rfn_nodes)
            .map(|_| generate_random_remote_enr().1)
            .collect();
        let local_nodes = (0..local_nodes)
            .map(|_| generate_random_remote_enr().1)
            .collect();
        let gossip_recipients = select_gossip_recipients(local_nodes, &mut rfn_nodes);
        assert_eq!(gossip_recipients.len(), expected_size);
    }

    #[test]
    fn test_select_gossip_recipients_filters_duplicates() {
        let local_nodes: Vec<Enr> = (0..4).map(|_| generate_random_remote_enr().1).collect();
        let mut rfn_nodes: Vec<Enr> = (0..4).map(|_| generate_random_remote_enr().1).collect();
        rfn_nodes[0] = local_nodes[0].clone();
        let gossip_recipients = select_gossip_recipients(local_nodes, &mut rfn_nodes);
        assert_eq!(gossip_recipients.len(), 7);
    }
}
