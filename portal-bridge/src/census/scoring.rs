use std::time::Duration;

use ethportal_api::Enr;
use itertools::Itertools;
use rand::{seq::SliceRandom, thread_rng};

use super::peer::Peer;

/// A trait for calculating peer's weight.
pub trait Weight: Send + Sync {
    fn weight(&self, content_id: &[u8; 32], peer: &Peer) -> u32;

    fn weight_all<'a>(
        &self,
        content_id: &[u8; 32],
        peers: impl IntoIterator<Item = &'a Peer>,
    ) -> impl Iterator<Item = (&'a Peer, u32)> {
        peers
            .into_iter()
            .map(|peer| (peer, self.weight(content_id, peer)))
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
    pub failure_weight: i32,
}

impl Default for AdditiveWeight {
    fn default() -> Self {
        Self {
            timeframe: Duration::from_secs(15 * 60), // 15 min
            starting_weight: 200,
            maximum_weight: 400,
            success_weight: 5,
            failure_weight: -10,
        }
    }
}

impl Weight for AdditiveWeight {
    fn weight(&self, content_id: &[u8; 32], peer: &Peer) -> u32 {
        if !peer.is_interested_in_content(content_id) {
            return 0;
        }
        let weight = self.starting_weight as i32
            + Iterator::chain(
                peer.iter_liveness_checks()
                    .map(|liveness_check| (liveness_check.success, liveness_check.timestamp)),
                peer.iter_offer_events()
                    .map(|offer_event| (offer_event.success, offer_event.timestamp)),
            )
            .map(|(success, timestamp)| {
                if timestamp.elapsed() > self.timeframe {
                    return 0;
                }
                if success {
                    self.success_weight
                } else {
                    self.failure_weight
                }
            })
            .sum::<i32>();
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
        content_id: &[u8; 32],
        peers: impl IntoIterator<Item = &'a Peer>,
    ) -> Vec<Enr> {
        let weighted_peers = self.weight.weight_all(content_id, peers).collect_vec();

        weighted_peers
            .choose_multiple_weighted(&mut thread_rng(), self.limit, |(_peer, weight)| *weight)
            .expect("choosing random sample shouldn't fail")
            .map(|(peer, _weight)| peer.enr())
            .collect()
    }
}
