use std::collections::HashMap;

use alloy::hex::ToHexExt;
use discv5::Enr;
use ethportal_api::{types::distance::Metric, OverlayContentKey};
use rand::{rng, seq::IteratorRandom};
use tracing::{debug, error};

use crate::types::kbucket::SharedKBucketsTable;

pub fn gossip_recipients<'c, TContentKey: OverlayContentKey, TMetric: Metric>(
    content: Vec<(&'c [u8; 32], &TContentKey)>,
    kbuckets: &SharedKBucketsTable,
) -> HashMap<Enr, Vec<&'c [u8; 32]>> {
    if content.is_empty() {
        return HashMap::new();
    }

    let content_ids = content
        .iter()
        .map(|(content_id, _content_key)| *content_id)
        .collect::<Vec<_>>();

    // Map from content_ids to interested ENRs
    let mut content_id_to_interested_enrs = kbuckets.batch_interested_enrs::<TMetric>(&content_ids);

    // Map from ENRs to content they will put content
    let mut enrs_and_content: HashMap<Enr, Vec<&'c [u8; 32]>> = HashMap::new();
    for (content_id, content_key) in content {
        let interested_enrs = content_id_to_interested_enrs.remove(content_id).unwrap_or_else(|| {
            error!("interested_enrs should contain all content ids, even if there are no interested ENRs");
            vec![]
        });
        if interested_enrs.is_empty() {
            debug!(
                content.id = content_id.encode_hex_with_prefix(),
                content.key = %content_key.to_bytes(),
                "No peers eligible for neighborhood gossip"
            );
            continue;
        };

        // Select content recipients
        for enr in select_content_recipients::<TMetric>(content_id, interested_enrs) {
            enrs_and_content.entry(enr).or_default().push(content_id);
        }
    }
    enrs_and_content
}

const NUM_CLOSEST_PEERS: usize = 4;
const NUM_FARTHER_PEERS: usize = 4;

/// Selects put content recipients from a vec of interested peers.
///
/// If number of peers is at most `NUM_CLOSEST_PEERS + NUM_FARTHER_PEERS`, then all are returned.
/// Otherwise, peers are sorted by distance from `content_id` and then:
///
/// 1. Closest `NUM_CLOSEST_PEERS` ENRs are selected
/// 2. Random `NUM_FARTHER_PEERS` ENRs are selected from the rest
fn select_content_recipients<TMetric: Metric>(
    content_id: &[u8; 32],
    mut peers: Vec<Enr>,
) -> Vec<Enr> {
    // Check if we need to do any selection
    if peers.len() <= NUM_CLOSEST_PEERS + NUM_FARTHER_PEERS {
        return peers;
    }

    // Sort peers by distance
    peers.sort_by_cached_key(|peer| TMetric::distance(content_id, &peer.node_id().raw()));

    // Split of at NUM_CLOSEST_PEERS
    let farther_peers = peers.split_off(NUM_CLOSEST_PEERS);

    // Select random NUM_FARTHER_PEERS
    peers.extend(
        farther_peers
            .into_iter()
            .choose_multiple(&mut rng(), NUM_FARTHER_PEERS),
    );

    peers
}

#[cfg(test)]
mod tests {
    use std::iter;

    use discv5::enr::NodeId;
    use ethportal_api::{
        types::{
            distance::{Distance, XorMetric},
            enr::generate_random_remote_enr,
        },
        IdentityContentKey,
    };
    use rand::random;
    use rstest::rstest;

    use super::*;

    #[test]
    fn empty() {
        let kbuckets = SharedKBucketsTable::new_for_tests(NodeId::random());

        for _ in 0..NUM_CLOSEST_PEERS {
            let (_, peer) = generate_random_remote_enr();
            let _ = kbuckets.insert_or_update_disconnected(&peer, Distance::MAX);
        }

        assert!(gossip_recipients::<IdentityContentKey, XorMetric>(vec![], &kbuckets).is_empty());
    }

    mod select_content_recipients {
        use std::ops::RangeBounds;

        use itertools::chain;

        use super::*;

        fn create_peers_with_distance(
            count: usize,
            content_id: &[u8; 32],
            log2_distances: impl RangeBounds<usize>,
        ) -> Vec<Enr> {
            iter::repeat_with(|| generate_random_remote_enr().1)
                .filter(|peer| {
                    log2_distances.contains(
                        &XorMetric::distance(content_id, &peer.node_id().raw())
                            .log2()
                            .unwrap(),
                    )
                })
                .take(count)
                .collect()
        }

        #[rstest]
        #[case(0, 0)]
        #[case(NUM_CLOSEST_PEERS - 1, NUM_CLOSEST_PEERS - 1)]
        #[case(NUM_CLOSEST_PEERS, NUM_CLOSEST_PEERS)]
        #[case(NUM_CLOSEST_PEERS + 1, NUM_CLOSEST_PEERS + 1)]
        #[case(NUM_CLOSEST_PEERS + NUM_FARTHER_PEERS, NUM_CLOSEST_PEERS + NUM_FARTHER_PEERS)]
        #[case(NUM_CLOSEST_PEERS + NUM_FARTHER_PEERS + 1, NUM_CLOSEST_PEERS + NUM_FARTHER_PEERS)]
        #[case(256, NUM_CLOSEST_PEERS + NUM_FARTHER_PEERS)]
        fn count(#[case] peers_count: usize, #[case] expected_content_recipients_count: usize) {
            let content_id = random();
            let peers = create_peers_with_distance(peers_count, &content_id, ..);
            assert_eq!(
                select_content_recipients::<XorMetric>(&content_id, peers).len(),
                expected_content_recipients_count
            );
        }

        #[test]
        fn closest() {
            let content_id = random();

            const CLOSE_PEER_LOG2_DISTANCE: usize = 253;

            // Create NUM_CLOSEST_PEERS peers with log2 distance less than CLOSE_PEER_LOG2_DISTANCE
            let close_peers = create_peers_with_distance(
                NUM_CLOSEST_PEERS,
                &content_id,
                ..CLOSE_PEER_LOG2_DISTANCE,
            );

            // Create 1000 peers with log2 distance at least CLOSE_PEER_LOG2_DISTANCE
            let far_peers =
                create_peers_with_distance(1000, &content_id, CLOSE_PEER_LOG2_DISTANCE..);

            let recipients = select_content_recipients::<XorMetric>(
                &content_id,
                chain!(close_peers.clone(), far_peers).collect(),
            );

            // Verify that `NUM_CLOSEST_PEERS + NUM_FARTHER_PEERS` peers selected
            assert_eq!(recipients.len(), NUM_CLOSEST_PEERS + NUM_FARTHER_PEERS);

            // Verify that all close peers are selected
            for close_peer in close_peers {
                assert!(recipients.contains(&close_peer));
            }
        }

        #[test]
        fn closest_far_peer_is_not_selected() {
            let content_id = random();
            const TARGET_PEER_DISTANCE: usize = 253;

            // Create NUM_CLOSEST_PEERS peers with log2 distance less than TARGET_PEER_DISTANCE
            let close_peers =
                create_peers_with_distance(NUM_CLOSEST_PEERS, &content_id, ..TARGET_PEER_DISTANCE);

            // Create 1 peer with log2 distance exactly TARGET_PEER_DISTANCE
            let target_peer = create_peers_with_distance(
                1,
                &content_id,
                TARGET_PEER_DISTANCE..=TARGET_PEER_DISTANCE,
            )
            .remove(0);

            // Create 1000 peers with log2 distance more than TARGET_PEER_DISTANCE
            let far_peers =
                create_peers_with_distance(1000, &content_id, TARGET_PEER_DISTANCE + 1..);

            let all_peers =
                chain!(close_peers, [target_peer.clone()], far_peers).collect::<Vec<_>>();

            // We want to test that "target_peer" isn't selected.
            // However, because far peers are selected randomly, there is a small chance of being
            // selected anyway (0.4%). But we will just repeat the test up to 10 times, as it is
            // extremely unlikely to be selected all 10 times.
            let target_peer_is_not_selected = || {
                !select_content_recipients::<XorMetric>(&content_id, all_peers.clone())
                    .contains(&target_peer)
            };
            assert!((0..10).any(|_| target_peer_is_not_selected()));
        }
    }
}
