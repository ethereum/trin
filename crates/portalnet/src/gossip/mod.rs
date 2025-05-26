use std::collections::HashMap;

use discv5::Enr;
use ethportal_api::{
    types::{distance::Metric, portal::MAX_CONTENT_KEYS_PER_OFFER},
    utils::bytes::hex_encode_compact,
    OverlayContentKey, RawContentKey, RawContentValue,
};
use itertools::{chain, Itertools};
use tracing::{debug, warn};

use crate::types::kbucket::SharedKBucketsTable;

mod neighborhood;
mod random;

/// Selects peers and content that should be gossiped to them.
///
/// Every peer will have at least 1 and at most `MAX_CONTENT_KEYS_PER_OFFER` content assigned to
/// them. If more than `MAX_CONTENT_KEYS_PER_OFFER` is passed as an argument, it's possible that
/// no peers will be selected to propagate that content (even if they exist). The order of content
/// in the returned collection will be the same as the one that is passed (this might be important
/// for some content types).
///
/// This function is designed such that either all content is affected by radius (in which case we
/// use "neighborhood gossip" strategy) or not (in which case we use "random gossip" strategy).
/// If content contains the mix of the two types, then content is split and each gossip strategy is
/// applied to respective part. This can lead to suboptimal result when we select more peers than
/// it is needed.
pub fn gossip_recipients<TContentKey: OverlayContentKey, TMetric: Metric>(
    content: Vec<(TContentKey, RawContentValue)>,
    kbuckets: &SharedKBucketsTable,
) -> HashMap<Enr, Vec<(RawContentKey, RawContentValue)>> {
    // Precalculate "content_id" and "raw_content_key" and use references going forward
    let content = content
        .into_iter()
        .map(|(key, raw_value)| {
            let id = key.content_id();
            let raw_key = key.to_bytes();
            (id, key, raw_key, raw_value)
        })
        .collect::<Vec<_>>();

    debug!(
        ids = ?content.iter().map(|(id, _, _, _)| hex_encode_compact(id)),
        "selecing gossip recipients"
    );

    // Split content id+key depending on whether they are affected by radius
    let (content_for_neighborhood_gossip, content_for_random_gossip) = content
        .iter()
        .map(|(id, key, _raw_key, _raw_value)| (id, key))
        .partition::<Vec<_>, _>(|(_content_id, content_key)| content_key.affected_by_radius());
    if !content_for_neighborhood_gossip.is_empty() && !content_for_random_gossip.is_empty() {
        warn!("Expected to gossip content with both neighborhood_gossip and random_gossip");
    }

    // Combine results of "neighborhood gossip" and "random gossip".
    let peer_to_content_ids = chain!(
        neighborhood::gossip_recipients::<_, TMetric>(content_for_neighborhood_gossip, kbuckets),
        random::gossip_recipients(content_for_random_gossip, kbuckets)
    )
    .into_grouping_map()
    .reduce(|mut all_content_to_gossip, _enr, content_ids| {
        all_content_to_gossip.extend(content_ids);
        all_content_to_gossip
    });

    // Extract raw content key/value in hash map for easier lookup.
    let raw_content = content
        .iter()
        .map(|(id, _key, raw_key, raw_value)| (id, (raw_key, raw_value)))
        .collect::<HashMap<_, _>>();

    peer_to_content_ids
        .into_iter()
        .map(|(enr, content_ids)| {
            let raw_content_key_value = content_ids
                .into_iter()
                // Select at most `MAX_CONTENT_KEYS_PER_OFFER`
                .take(MAX_CONTENT_KEYS_PER_OFFER)
                .map(|content_id| {
                    let (raw_content_key, raw_content_value) = raw_content[content_id];
                    (raw_content_key.clone(), raw_content_value.clone())
                })
                .collect();
            (enr, raw_content_key_value)
        })
        .collect()
}
