use std::{collections::HashMap, time::Duration};

use ethportal_api::{
    types::{accept_code::AcceptCode, portal_wire::OfferTrace},
    OverlayContentKey,
};
use itertools::Itertools;
use rand::{rng, seq::IndexedRandom};

use super::peer::{Peer, PeerInfo};

/// A trait for calculating peer's weight.
pub trait Weight: Send + Sync {
    fn weight(
        &self,
        content_key: Option<&impl OverlayContentKey>,
        content_id: &Option<[u8; 32]>,
        peer: &Peer,
    ) -> u32;

    fn weight_all<'a>(
        &self,
        content_key: Option<&impl OverlayContentKey>,
        peers: impl IntoIterator<Item = &'a Peer>,
    ) -> impl Iterator<Item = (&'a Peer, u32)> {
        let content_id = content_key
            .as_ref()
            .map(|key| Some(key.content_id()))
            .unwrap_or(None);
        peers
            .into_iter()
            .map(move |peer| (peer, self.weight(content_key, &content_id, peer)))
    }
}

/// Calculates peer's weight by adding/subtracting weights of recent events.
///
/// Weight is calculated using following rules:
/// 1. If peer is not interested in content, `0` is returned
/// 2. Weight's starting value is `starting_weight`
/// 3. All recent events (based on `timeframe` parameter) are scored separately:
///     - successful events increase weight by `success_weight`
///     - failed events decrease weight by `failure_weight`
/// 4. Final weight is restricted to `[0, maximum_weight]` range.
#[derive(Debug, Clone)]
pub struct AdditiveWeight {
    pub timeframe: Duration,
    pub starting_weight: u32,
    pub maximum_weight: u32,
    pub success_weight: i32,
    pub accept_code_weights: HashMap<AcceptCode, i32>,
    pub failure_weight: i32,
}

impl Default for AdditiveWeight {
    fn default() -> Self {
        let accept_code_weights = HashMap::from([
            (AcceptCode::Accepted, 5),
            (AcceptCode::AlreadyStored, 0),
            // Rate limited and inbound transfer in progress are treated the same. We don't
            // want to overload the node.
            (AcceptCode::RateLimited, -2),
            (AcceptCode::InboundTransferInProgress, -2),
            // The peer doesn't properly support decline codes, we should avoid using them
            // as we can't get good data from them, they will still get the content through
            // neighbors, but they are a lower priority for the bridge as we have limited
            // resources.
            (AcceptCode::Declined, -5),
            (AcceptCode::Unspecified, -5),
            // If we got a NotWithinRadius code, we either have a bug, they do, or the node
            // is malicious.
            (AcceptCode::NotWithinRadius, -10),
        ]);

        Self {
            timeframe: Duration::from_secs(15 * 60), // 15 min
            starting_weight: 200,
            maximum_weight: 400,
            success_weight: 5,
            accept_code_weights,
            failure_weight: -10,
        }
    }
}

impl Weight for AdditiveWeight {
    fn weight(
        &self,
        content_key: Option<&impl OverlayContentKey>,
        content_id: &Option<[u8; 32]>,
        peer: &Peer,
    ) -> u32 {
        if let (Some(content_key), Some(content_id)) = (content_key, content_id) {
            if !peer.is_interested_in_content(content_key, content_id) {
                return 0;
            }
        }

        let liveness_weight = peer
            .iter_liveness_checks()
            .filter(|liveness_check| liveness_check.timestamp.elapsed() <= self.timeframe)
            .map(|liveness_check| {
                if liveness_check.success {
                    self.success_weight
                } else {
                    self.failure_weight
                }
            })
            .sum::<i32>();

        let offer_weight = peer
            .iter_offer_events()
            .filter(|offer_event| offer_event.timestamp.elapsed() <= self.timeframe)
            .map(|offer_event| match &offer_event.offer_trace {
                OfferTrace::Success(accept_code) => *self
                    .accept_code_weights
                    .get(accept_code)
                    // We don't know how to handle this accept code, so we might as well prioritize
                    // nodes we do know how to deal with
                    .unwrap_or(&self.failure_weight),
                OfferTrace::Failed => self.failure_weight,
            })
            .sum::<i32>();

        let weight = self.starting_weight as i32 + liveness_weight + offer_weight;
        weight.clamp(0, self.maximum_weight as i32) as u32
    }
}

/// Selects peers based on their weight provided by [Weight] trait.
///
/// Selection is done using [SliceRandom::choose_multiple_weighted]. Peers are ranked so that
/// probability of peer A being ranked higher than peer B is proportional to their weights.
/// The top ranked peers are then selected and returned.
#[derive(Debug, Clone)]
pub struct PeerSelector<W: Weight> {
    weight: W,
    /// The maximum number of peers to select
    limit: usize,
}

impl<W: Weight> PeerSelector<W> {
    pub fn new(rank: W, limit: usize) -> Self {
        Self {
            weight: rank,
            limit,
        }
    }

    /// Selects up to `self.limit` peers based on their weights.
    pub fn select_peers<'a>(
        &self,
        content_key: Option<&impl OverlayContentKey>,
        peers: impl IntoIterator<Item = &'a Peer>,
    ) -> Vec<PeerInfo> {
        let weighted_peers = self
            .weight
            .weight_all(content_key, peers)
            .filter(|(_peer, weight)| *weight > 0)
            .collect_vec();

        weighted_peers
            .choose_multiple_weighted(&mut rng(), self.limit, |(_peer, weight)| *weight)
            .expect("choosing random sample shouldn't fail")
            .map(|(peer, _weight)| peer.peer_info())
            .collect()
    }
}
