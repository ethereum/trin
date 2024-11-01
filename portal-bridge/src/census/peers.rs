use std::{
    collections::HashMap,
    pin::Pin,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
    task::{Context, Poll},
    time::Duration,
};

use delay_map::HashSetDelay;
use discv5::enr::NodeId;
use ethportal_api::{types::distance::Distance, Enr};
use futures::Stream;
use rand::seq::IteratorRandom;
use tokio::time::Instant;
use tracing::error;

use super::peer::Peer;

/// How frequently liveness check should be done.
///
/// Five minutes is chosen arbitrarily.
const LIVENESS_CHECK_DELAY: Duration = Duration::from_secs(300);

/// Stores peers and when they should be checked for liveness.
///
/// Convinient structure for holding both objects behind single [RwLock].
#[derive(Debug)]
struct PeersWithLivenessChecks {
    /// Stores peers and their info
    peers: HashMap<NodeId, Peer>,
    /// Stores when peers should be checked for liveness using [HashSetDelay].
    liveness_checks: HashSetDelay<NodeId>,
}

/// Contains all discovered peers on the network.
///
/// It provides thread safe access to peers and is responsible for deciding when they should be
/// pinged for liveness.
#[derive(Clone, Debug)]
pub(super) struct Peers {
    peers: Arc<RwLock<PeersWithLivenessChecks>>,
}

impl Default for Peers {
    fn default() -> Self {
        Self::new()
    }
}

impl Peers {
    pub fn new() -> Self {
        Self {
            peers: Arc::new(RwLock::new(PeersWithLivenessChecks {
                peers: HashMap::new(),
                liveness_checks: HashSetDelay::new(LIVENESS_CHECK_DELAY),
            })),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.read().peers.is_empty()
    }

    pub fn len(&self) -> usize {
        self.read().peers.len()
    }

    pub fn next_liveness_check(&self, node_id: &NodeId) -> Option<Instant> {
        self.read().liveness_checks.deadline(node_id)
    }

    pub fn record_successful_liveness_check(&self, enr: Enr, radius: Distance) {
        let node_id = enr.node_id();
        let mut guard = self.write();
        guard
            .peers
            .entry(node_id)
            .or_insert_with(|| Peer::new(enr.clone()))
            .record_successful_liveness_check(enr, radius);
        guard.liveness_checks.insert(node_id);
    }

    pub fn record_failed_liveness_check(&self, enr: Enr) {
        let node_id = enr.node_id();

        let mut guard = self.write();

        let Some(peer) = guard.peers.get_mut(&node_id) else {
            error!("record_failed_liveness_check: unknown peer: {node_id}");
            guard.liveness_checks.remove(&node_id);
            return;
        };

        peer.record_failed_liveness_check();

        if peer.is_obsolete() {
            guard.peers.remove(&node_id);
            guard.liveness_checks.remove(&node_id);
        } else {
            guard.liveness_checks.insert(node_id);
        }
    }

    /// Selects random `limit` peers that should be interested in content.
    pub fn get_interested_enrs(&self, content_id: &[u8; 32], limit: usize) -> Vec<Enr> {
        self.read()
            .peers
            .values()
            .filter(|peer| peer.is_interested_in_content(content_id))
            .map(Peer::enr)
            .choose_multiple(&mut rand::thread_rng(), limit)
    }

    fn read(&self) -> RwLockReadGuard<'_, PeersWithLivenessChecks> {
        self.peers.read().expect("to get peers lock")
    }

    fn write(&self) -> RwLockWriteGuard<'_, PeersWithLivenessChecks> {
        self.peers.write().expect("to get peers lock")
    }
}

impl Stream for Peers {
    type Item = Enr;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut guard = self.write();

        // Poll expired until non-error is returned.
        // Error can happen only if there is some race condition, which shouldn't happen because
        // of the RwLock.
        loop {
            match guard.liveness_checks.poll_expired(cx) {
                Poll::Ready(Some(Ok(node_id))) => match guard.peers.get(&node_id) {
                    Some(peer) => break Poll::Ready(Some(peer.enr())),
                    None => {
                        error!("poll_next: unknown peer: {node_id}");
                    }
                },
                Poll::Ready(Some(Err(err))) => {
                    error!("poll_next: error getting peer - err: {err}");
                }
                Poll::Ready(None) => break Poll::Ready(None),
                Poll::Pending => break Poll::Pending,
            }
        }
    }
}
