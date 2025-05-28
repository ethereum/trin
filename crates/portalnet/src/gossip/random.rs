use std::collections::HashMap;

use discv5::Enr;
use ethportal_api::OverlayContentKey;

use crate::types::kbucket::SharedKBucketsTable;

const NUM_PEERS: usize = 8;

pub fn gossip_recipients<'c, TContentKey: OverlayContentKey>(
    content: Vec<(&'c [u8; 32], &TContentKey)>,
    kbuckets: &SharedKBucketsTable,
) -> HashMap<Enr, Vec<&'c [u8; 32]>> {
    if content.is_empty() {
        return HashMap::new();
    }

    let content_ids = content
        .into_iter()
        .map(|(content_id, _content_key)| content_id)
        .collect::<Vec<_>>();
    kbuckets
        .random_peers(NUM_PEERS)
        .into_iter()
        .map(|peer| (peer, content_ids.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::iter;

    use discv5::enr::NodeId;
    use ethportal_api::{
        generate_random_remote_enr, types::distance::Distance, IdentityContentKey,
    };

    use super::*;

    fn assert_gossip_recipients(
        content: impl IntoIterator<Item = IdentityContentKey>,
        kbuckets: &SharedKBucketsTable,
        expected_recipients_count: usize,
    ) {
        let (ids, keys): (Vec<_>, Vec<_>) = content
            .into_iter()
            .map(|key| (key.content_id(), key))
            .unzip();
        let recipients = gossip_recipients(iter::zip(&ids, &keys).collect(), kbuckets);
        assert_eq!(recipients.len(), expected_recipients_count);
        for (_peer, content) in recipients {
            assert_eq!(content, ids.iter().collect::<Vec<_>>());
        }
    }

    #[test]
    fn empty() {
        let kbuckets = SharedKBucketsTable::new_for_tests(NodeId::random());

        for _ in 0..NUM_PEERS {
            let (_, peer) = generate_random_remote_enr();
            let _ = kbuckets.insert_or_update_disconnected(&peer, Distance::MAX);
        }

        assert!(gossip_recipients::<IdentityContentKey>(vec![], &kbuckets).is_empty());
    }

    #[test]
    fn zero_distance() {
        let kbuckets = SharedKBucketsTable::new_for_tests(NodeId::random());
        let (_, peer) = generate_random_remote_enr();
        let _ = kbuckets.insert_or_update_connected(&peer, Distance::ZERO);

        assert_gossip_recipients(
            iter::repeat_with(IdentityContentKey::random).take(5),
            &kbuckets,
            1,
        );
    }

    #[test]
    fn max_peers() {
        let kbuckets = SharedKBucketsTable::new_for_tests(NodeId::random());

        let mut peers = vec![];
        for _ in 0..(NUM_PEERS * 2) {
            let (_, peer) = generate_random_remote_enr();
            let _ = kbuckets.insert_or_update_connected(&peer, Distance::MAX);
            peers.push(peer);
        }

        assert_gossip_recipients(
            iter::repeat_with(IdentityContentKey::random).take(5),
            &kbuckets,
            NUM_PEERS,
        );
    }
}
