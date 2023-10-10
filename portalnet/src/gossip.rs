use std::{collections::HashMap, str::FromStr, sync::Arc};

use discv5::{
    enr::NodeId,
    kbucket::{self, KBucketsTable},
};
use parking_lot::RwLock;
use rand::seq::IteratorRandom;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use crate::overlay_service::{OverlayCommand, OverlayRequest, RequestDirection};
use crate::types::{
    messages::{PopulatedOffer, Request},
    node::Node,
};
use ethportal_api::types::distance::{Metric, XorMetric};
use ethportal_api::types::enr::Enr;
use ethportal_api::utils::bytes::hex_encode;
use ethportal_api::OverlayContentKey;
use ethportal_api::RawContentKey;

// Propagate gossip in a way that can be used across threads, without &self
pub fn propagate_gossip_cross_thread<TContentKey: OverlayContentKey>(
    content: Vec<(TContentKey, Vec<u8>)>,
    kbuckets: Arc<RwLock<KBucketsTable<NodeId, Node>>>,
    command_tx: mpsc::UnboundedSender<OverlayCommand<TContentKey>>,
) -> usize {
    // Get all connected nodes from overlay routing table
    let kbuckets = kbuckets.read();
    let mut all_nodes: Vec<&kbucket::Node<NodeId, Node>> = kbuckets
        .buckets_iter()
        .flat_map(|kbucket| {
            kbucket
                .iter()
                .filter(|node| node.status.is_connected())
                .collect::<Vec<&kbucket::Node<NodeId, Node>>>()
        })
        .collect();

    if all_nodes.is_empty() {
        warn!("No connected nodes, using disconnected nodes for gossip.");
        all_nodes = kbuckets
            .buckets_iter()
            .flat_map(|kbucket| {
                kbucket
                    .iter()
                    .collect::<Vec<&kbucket::Node<NodeId, Node>>>()
            })
            .collect();
    }

    if all_nodes.is_empty() {
        // If there are no nodes whatsoever in the routing table the gossip cannot proceed.
        warn!("No nodes in routing table, gossip cannot proceed.");
        return 0;
    }

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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    use rstest::rstest;

    use ethportal_api::types::enr::generate_random_remote_enr;

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
