use std::{
    collections::HashMap,
    pin::Pin,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
    task::{Context, Poll},
    time::Duration,
};

use delay_map::HashSetDelay;
use discv5::enr::NodeId;
use ethportal_api::{
    types::{client_type::ClientType, distance::Distance, portal_wire::OfferTrace},
    Enr, OverlayContentKey,
};
use futures::Stream;
use tokio::time::Instant;
use tracing::error;

use super::{
    peer::{Peer, PeerInfo},
    scoring::{PeerSelector, Weight},
};

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
pub(super) struct Peers<W: Weight> {
    peers: Arc<RwLock<PeersWithLivenessChecks>>,
    selector: PeerSelector<W>,
}

impl<W: Weight> Peers<W> {
    pub fn new(selector: PeerSelector<W>) -> Self {
        Self {
            peers: Arc::new(RwLock::new(PeersWithLivenessChecks {
                peers: HashMap::new(),
                liveness_checks: HashSetDelay::new(LIVENESS_CHECK_DELAY),
            })),
            selector,
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

    pub fn record_successful_liveness_check(
        &self,
        enr: Enr,
        client_type: ClientType,
        radius: Distance,
    ) {
        let node_id = enr.node_id();
        let mut guard = self.write();
        guard
            .peers
            .entry(node_id)
            .or_insert_with(|| Peer::new(enr.clone()))
            .record_successful_liveness_check(enr, client_type, radius);
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

    pub fn record_offer_result(
        &self,
        node_id: NodeId,
        content_value_size: usize,
        duration: Duration,
        offer_trace: &OfferTrace,
    ) {
        match self.write().peers.get_mut(&node_id) {
            Some(peer) => {
                peer.record_offer_result(offer_trace.clone(), content_value_size, duration)
            }
            None => error!("record_offer_result: unknown peer: {node_id}"),
        }
    }

    /// Selects peers to receive content.
    pub fn select_peers(&self, content_key: Option<&impl OverlayContentKey>) -> Vec<PeerInfo> {
        self.selector
            .select_peers(content_key, self.read().peers.values())
    }

    fn read(&self) -> RwLockReadGuard<'_, PeersWithLivenessChecks> {
        self.peers.read().expect("to get peers lock")
    }

    fn write(&self) -> RwLockWriteGuard<'_, PeersWithLivenessChecks> {
        self.peers.write().expect("to get peers lock")
    }
}

impl<W: Weight> Stream for Peers<W> {
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
