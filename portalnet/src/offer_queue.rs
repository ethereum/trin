use crate::overlay::{
    command::OverlayCommand,
    request::{OverlayRequest, RequestDirection},
};
use delay_map::HashMapDelay;
use ethportal_api::{
    types::{
        enr::Enr,
        portal_wire::{FindContent, Request},
    },
    OverlayContentKey,
};
use futures::prelude::*;
use rand::{seq::SliceRandom, thread_rng};
use tokio::{sync::mpsc::UnboundedSender, time::Duration};
use tracing::{debug, warn};

struct SeenPeers {
    origin: Enr,
    fallback: Vec<Enr>,
}

/// In-memory queue of content keys that have been accepted, and are
/// currently being processed.
/// This queue is designed for content keys that have already
/// been checked with storage that they are within radius.
// It's possible that some content keys evade tracking through the entire processing
// cycle, due to error handling inside the OverlayService (eg process_accept_utp_payload()).
// On top of this, we could also have threads panic / deadlocking. The use of a delay
// map is useful to remove content keys which have been in the queue for too long or
// might be stuck, and avoid infinitely-growing queues / indefinitely prevent
// previously seen content keys from being accepted.
pub struct OfferQueue<TContentKey>
where
    TContentKey: OverlayContentKey,
{
    // a map of content keys actively being transferred / processed
    // pointing to seen peers that have offered them the content
    content_key_map: HashMapDelay<TContentKey, SeenPeers>,
    command_tx: UnboundedSender<OverlayCommand<TContentKey>>,
}

const OFFER_QUEUE_TIMEOUT: Duration = Duration::from_secs(120);

impl<TContentKey> OfferQueue<TContentKey>
where
    TContentKey: OverlayContentKey,
{
    pub fn new(command_tx: UnboundedSender<OverlayCommand<TContentKey>>) -> Self {
        Self {
            content_key_map: HashMapDelay::new(OFFER_QUEUE_TIMEOUT),
            command_tx,
        }
    }

    // Checks if we should accept the given content key based on the queue state.
    // - Polls for expired items, which will remove them from the queue.
    // - If the key is not in the queue, it is added to the queue and returns true.
    // - If the key is in the queue, the seen peer is stored, and it returns false.
    pub fn should_accept(&mut self, content_key: &TContentKey, peer: &Enr) -> bool {
        // poll for expired items, which will remove them from the queue
        let _ = future::poll_fn(|cx| self.content_key_map.poll_expired(cx)).now_or_never();
        if let Some(mut node_ids) = self.content_key_map.remove(content_key) {
            if node_ids.origin == *peer || node_ids.fallback.contains(peer) {
                warn!(
                    "Received multiple offers containing the same content key: {} from peer: {}",
                    content_key,
                    peer.node_id(),
                );
                self.content_key_map.insert(content_key.clone(), node_ids);
                return false;
            }
            if !node_ids.fallback.contains(peer) {
                debug!(
                    "Content key: {} already in offer queue, adding peer to fallback list: {}",
                    content_key,
                    peer.node_id()
                );
                node_ids.fallback.push(peer.clone());
            }
            self.content_key_map.insert(content_key.clone(), node_ids);
            return false;
        }
        self.content_key_map.insert(
            content_key.clone(),
            SeenPeers {
                origin: peer.clone(),
                fallback: vec![],
            },
        );
        true
    }

    pub fn successful_processing(&mut self, content_key: &TContentKey) {
        debug!("Content key: {content_key} successfully processed");
        self.content_key_map.remove(content_key);
    }

    pub fn failed_to_accept(&mut self, content_keys: &Vec<TContentKey>) {
        for content_key in content_keys {
            self.failed_to_process(content_key);
        }
    }

    pub fn failed_to_process(&mut self, content_key: &TContentKey) {
        if let Some(mut node_ids) = self.content_key_map.remove(content_key) {
            if node_ids.fallback.is_empty() {
                debug!(
                    "Failed to process content key: {content_key}, but no fallback peers found."
                );
                return;
            }
            // choose a random seen peer as the fallback peer
            // and send a FINDCONTENT request to them
            node_ids.fallback.shuffle(&mut thread_rng());
            let fallback_peer = node_ids.fallback.remove(0);
            let request = Request::FindContent(FindContent {
                content_key: content_key.to_bytes(),
            });
            debug!(
                "Failed to process content key: {}, sending fallback FINDCONTENT to {}",
                content_key,
                fallback_peer.node_id()
            );
            let direction = RequestDirection::Outgoing {
                destination: fallback_peer.clone(),
            };
            if let Err(err) = self
                .command_tx
                .send(OverlayCommand::Request(OverlayRequest::new(
                    request, direction, None, None, None,
                )))
            {
                warn!(
                    "Failed to send FINDCONTENT request from offer queue to fallback peer: {}, error: {}",
                    fallback_peer.node_id(),
                    err
                );
            }
        } else {
            warn!(
                "Failed to process content key: {content_key}, but a corresponding OfferQueue record was not found"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethportal_api::{types::enr::generate_random_remote_enr, IdentityContentKey};
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_successful_processing() {
        let (command_tx, _command_rx) = mpsc::unbounded_channel();
        let mut offer_queue = OfferQueue::new(command_tx);
        let content_key = IdentityContentKey::random();
        let (_, peer) = generate_random_remote_enr();
        assert!(offer_queue.should_accept(&content_key, &peer));
        assert!(!offer_queue.should_accept(&content_key, &peer));
        offer_queue.successful_processing(&content_key);
        assert!(offer_queue.should_accept(&content_key, &peer));
    }

    #[tokio::test]
    async fn test_multiple_peers() {
        let (command_tx, _command_rx) = mpsc::unbounded_channel();
        let mut offer_queue = OfferQueue::new(command_tx);
        let content_key = IdentityContentKey::random();
        let (_, peer1) = generate_random_remote_enr();
        let (_, peer2) = generate_random_remote_enr();
        assert!(offer_queue.should_accept(&content_key, &peer1));
        assert!(!offer_queue.should_accept(&content_key, &peer2));
        assert!(!offer_queue.should_accept(&content_key, &peer1));
        offer_queue.successful_processing(&content_key);
        assert!(offer_queue.should_accept(&content_key, &peer1));
    }

    #[tokio::test]
    async fn test_queue_keeps_record_after_duplicate_offers_from_same_peer() {
        let (command_tx, mut command_rx) = mpsc::unbounded_channel();
        let mut offer_queue = OfferQueue::new(command_tx);
        let content_key = IdentityContentKey::random();
        let (_, peer1) = generate_random_remote_enr();
        let (_, peer2) = generate_random_remote_enr();
        assert!(offer_queue.should_accept(&content_key, &peer1));
        assert!(!offer_queue.should_accept(&content_key, &peer2));
        // peer1 offers the same content key again
        assert!(!offer_queue.should_accept(&content_key, &peer1));
        offer_queue.failed_to_process(&content_key);
        let fallback = command_rx.recv().await;
        match fallback.unwrap() {
            OverlayCommand::Request(OverlayRequest {
                request, direction, ..
            }) => {
                match request {
                    Request::FindContent(FindContent {
                        content_key: target,
                    }) => {
                        assert_eq!(target, content_key.to_bytes());
                    }
                    _ => panic!("unexpected request"),
                }
                match direction {
                    RequestDirection::Outgoing { destination } => {
                        assert_eq!(destination, peer2);
                    }
                    _ => panic!("unexpected direction"),
                }
            }
            _ => panic!("unexpected command"),
        }
    }

    #[tokio::test]
    async fn test_failed_to_process() {
        let (command_tx, mut command_rx) = mpsc::unbounded_channel();
        let mut offer_queue = OfferQueue::new(command_tx);
        let content_key = IdentityContentKey::random();
        let (_, original_peer) = generate_random_remote_enr();
        let (_, fallback_peer) = generate_random_remote_enr();
        assert!(offer_queue.should_accept(&content_key, &original_peer));
        assert!(!offer_queue.should_accept(&content_key, &fallback_peer));
        offer_queue.failed_to_process(&content_key);
        let fallback = command_rx.recv().await;
        match fallback.unwrap() {
            OverlayCommand::Request(OverlayRequest {
                request, direction, ..
            }) => {
                match request {
                    Request::FindContent(FindContent {
                        content_key: target,
                    }) => {
                        assert_eq!(target, content_key.to_bytes());
                    }
                    _ => panic!("unexpected request"),
                }
                match direction {
                    RequestDirection::Outgoing { destination } => {
                        assert_eq!(destination, fallback_peer);
                    }
                    _ => panic!("unexpected direction"),
                }
            }
            _ => panic!("unexpected command"),
        }
    }

    #[tokio::test]
    async fn test_failed_to_process_with_multiple_records() {
        let (command_tx, mut command_rx) = mpsc::unbounded_channel();
        let mut offer_queue = OfferQueue::new(command_tx);
        let content_key1 = IdentityContentKey::random();
        let content_key2 = IdentityContentKey::random();
        let content_key3 = IdentityContentKey::random();
        let (_, peer1) = generate_random_remote_enr();
        let (_, peer2) = generate_random_remote_enr();
        let (_, peer3) = generate_random_remote_enr();
        assert!(offer_queue.should_accept(&content_key1, &peer1));
        // peer2 is fallback peer for content_key1
        assert!(!offer_queue.should_accept(&content_key1, &peer2));
        assert!(offer_queue.should_accept(&content_key2, &peer1));
        // peer3 is fallback peer for content_key2
        assert!(!offer_queue.should_accept(&content_key2, &peer3));
        assert!(offer_queue.should_accept(&content_key3, &peer2));
        offer_queue.failed_to_process(&content_key1);
        let fallback = command_rx.recv().await;
        match fallback.unwrap() {
            OverlayCommand::Request(OverlayRequest {
                request, direction, ..
            }) => {
                match request {
                    Request::FindContent(FindContent {
                        content_key: target,
                    }) => {
                        assert_eq!(target, content_key1.to_bytes());
                    }
                    _ => panic!("unexpected request"),
                }
                match direction {
                    RequestDirection::Outgoing { destination } => {
                        assert_eq!(destination, peer2);
                    }
                    _ => panic!("unexpected direction"),
                }
            }
            _ => panic!("unexpected command"),
        }
        // test that content_key3 is still in the queue
        assert!(!offer_queue.should_accept(&content_key3, &peer1));
        // test that content_key1 is no longer in the queue
        assert!(offer_queue.should_accept(&content_key1, &peer1));
        offer_queue.failed_to_process(&content_key2);
        let fallback = command_rx.recv().await;
        match fallback.unwrap() {
            OverlayCommand::Request(OverlayRequest {
                request, direction, ..
            }) => {
                match request {
                    Request::FindContent(FindContent {
                        content_key: target,
                    }) => {
                        assert_eq!(target, content_key2.to_bytes());
                    }
                    _ => panic!("unexpected request"),
                }
                match direction {
                    RequestDirection::Outgoing { destination } => {
                        assert_eq!(destination, peer3);
                    }
                    _ => panic!("unexpected direction"),
                }
            }
            _ => panic!("unexpected command"),
        }
        // test that content_key3 is still in the queue
        assert!(!offer_queue.should_accept(&content_key3, &peer1));
        // test that content_key2 is no longer in the queue
        assert!(offer_queue.should_accept(&content_key2, &peer1));
    }

    #[tokio::test]
    async fn test_failed_to_accept() {
        let (command_tx, _command_rx) = mpsc::unbounded_channel();
        let mut offer_queue = OfferQueue::new(command_tx);
        let content_key1 = IdentityContentKey::random();
        let content_key2 = IdentityContentKey::random();
        let (_, peer1) = generate_random_remote_enr();
        assert!(offer_queue.should_accept(&content_key1, &peer1));
        assert!(offer_queue.should_accept(&content_key2, &peer1));
        offer_queue.failed_to_accept(&vec![content_key1.clone(), content_key2.clone()]);
        // validate that keys are no longer in queue
        assert!(offer_queue.should_accept(&content_key1, &peer1));
        assert!(offer_queue.should_accept(&content_key2, &peer1));
    }

    #[tokio::test]
    async fn test_queue_timeout() {
        let (command_tx, _command_rx) = mpsc::unbounded_channel();
        let mut offer_queue = OfferQueue::new(command_tx);
        offer_queue.content_key_map = HashMapDelay::new(Duration::from_secs(1));
        let content_key = IdentityContentKey::random();
        let (_, peer) = generate_random_remote_enr();
        assert!(offer_queue.should_accept(&content_key, &peer));
        tokio::time::sleep(Duration::from_secs(3)).await;
        // validate that the content key has been removed from the queue
        assert!(offer_queue.should_accept(&content_key, &peer));
    }
}
