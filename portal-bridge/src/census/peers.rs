use std::{
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
    time::Duration,
};

use delay_map::HashMapDelay;
use ethportal_api::{
    types::{
        distance::{Distance, Metric, XorMetric},
        portal::PongInfo,
    },
    Enr,
};
use futures::Stream;
use rand::seq::IteratorRandom;
use tokio::time::Instant;

/// How frequently liveness check should be done.
///
/// Five minutes is chosen arbitrarily.
const LIVENESS_CHECK_DELAY: Duration = Duration::from_secs(300);

type PeersHashMapDelay = HashMapDelay<[u8; 32], (Enr, Distance)>;

/// Contains all discovered peers on the network.
///
/// It provides thread safe access to peers and is responsible for deciding when they should be
/// pinged for liveness.
#[derive(Clone, Debug)]
pub(super) struct Peers {
    peers: Arc<RwLock<PeersHashMapDelay>>,
}

impl Peers {
    pub fn new() -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMapDelay::new(LIVENESS_CHECK_DELAY))),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.peers.read().expect("to get peers lock").is_empty()
    }

    pub fn len(&self) -> usize {
        self.peers.read().expect("to get peers lock").len()
    }

    pub fn deadline(&self, enr: &Enr) -> Option<Instant> {
        self.peers
            .read()
            .expect("to get peers lock")
            .deadline(&enr.node_id().raw())
    }

    pub fn process_ping_response(&self, enr: Enr, ping_response: anyhow::Result<PongInfo>) -> bool {
        let mut peers = self.peers.write().expect("to get peers lock");
        match ping_response {
            Ok(pong_info) => {
                let data_radius = Distance::from(pong_info.data_radius);
                peers.insert(enr.node_id().raw(), (enr, data_radius));
                true
            }
            Err(_) => {
                peers.remove(&enr.node_id().raw());
                false
            }
        }
    }

    /// Selects random `limit` peers that should be interested in content.
    pub fn get_interested_enrs(&self, content_id: &[u8; 32], limit: usize) -> Vec<Enr> {
        self.peers
            .read()
            .expect("to get peers lock")
            .iter()
            .filter_map(|(node_id, (enr, data_radius))| {
                let distance = XorMetric::distance(node_id, content_id);
                if data_radius >= &distance {
                    Some(enr.clone())
                } else {
                    None
                }
            })
            .choose_multiple(&mut rand::thread_rng(), limit)
    }
}

impl Stream for Peers {
    type Item = Result<Enr, String>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.peers
            .write()
            .expect("to get peers lock")
            .poll_expired(cx)
            .map_ok(|(_node_id, (enr, _distance))| enr)
    }
}

impl Default for Peers {
    fn default() -> Self {
        Self::new()
    }
}
