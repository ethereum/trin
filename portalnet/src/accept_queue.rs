use delay_map::HashMapDelay;
use ethportal_api::{types::enr::Enr, OverlayContentKey};
use futures::prelude::*;
use rand::{seq::SliceRandom, thread_rng};
use tokio::time::Duration;
use tracing::{debug, warn};

const OFFER_QUEUE_TIMEOUT: Duration = Duration::from_secs(120);

/// A record of peers that have offered a content key.
struct SeenPeers {
    /// The peer that originally offered the content key.
    origin: Enr,
    /// A list of subsequent peers that have also offered the content key.
    fallback: Vec<Enr>,
}

/// In-memory queue of content keys that have been accepted, and are
/// currently being processed.
/// This queue is designed for content keys that have already
/// been checked with storage that they are within radius.
// It's possible that some content keys evade tracking through the entire processing
// cycle, due to error handling inside the OverlayService, or threads
// panicking / deadlocking. The use of a delay
// map will remove content keys which have been in the queue for too long or
// might be stuck, and avoid infinitely-growing queues / indefinitely preventing
// previously seen content keys from being accepted.
pub struct AcceptQueue<TContentKey>
where
    TContentKey: OverlayContentKey,
{
    // a map of content keys actively being transferred / processed
    // pointing to seen peers that have offered them the content
    content_key_map: HashMapDelay<TContentKey, SeenPeers>,
}

impl<TContentKey> Default for AcceptQueue<TContentKey>
where
    TContentKey: OverlayContentKey,
{
    fn default() -> Self {
        Self {
            content_key_map: HashMapDelay::new(OFFER_QUEUE_TIMEOUT),
        }
    }
}

impl<TContentKey> AcceptQueue<TContentKey>
where
    TContentKey: OverlayContentKey,
{
    /// Tries to add a content key to the queue.
    /// If the key is not in the queue, it is added to the queue and returns true.
    /// If the key is in the queue, the seen peer is stored as a fallback, and it returns false.
    /// Also polls for expired items, which will remove them from the queue.
    pub fn add_key_to_queue(&mut self, content_key: &TContentKey, peer: &Enr) -> bool {
        // poll for expired items, which will remove them from the queue
        let _ = future::poll_fn(|cx| self.content_key_map.poll_expired(cx)).now_or_never();
        if let Some(mut seen_peers) = self.content_key_map.remove(content_key) {
            if seen_peers.origin == *peer || seen_peers.fallback.contains(peer) {
                debug!(
                    "Received multiple offers containing the same content key: {content_key} from peer: {peer}"
                );
            } else {
                debug!(
                    "Content key: {content_key} already in accept queue, adding peer to fallback list: {peer}"
                );
                seen_peers.fallback.push(peer.clone());
            }
            self.content_key_map.insert(content_key.clone(), seen_peers);
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

    /// Removes a content key from the queue.
    pub fn remove_key(&mut self, content_key: &TContentKey) {
        self.content_key_map.remove(content_key);
    }

    /// Removes a failed content key, and returns a randomly selected
    /// fallback peer to send a fallback FINDCONTENT request.
    /// If no fallback peer is found, it returns None.
    pub fn process_failed_key(&mut self, content_key: &TContentKey) -> Option<Enr> {
        if let Some(mut seen_peers) = self.content_key_map.remove(content_key) {
            if seen_peers.fallback.is_empty() {
                debug!("Failed to process content key: {content_key}, no fallback peers found.");
                return None;
            }
            // randomly choose a seen peer as the fallback peer
            seen_peers.fallback.shuffle(&mut thread_rng());
            Some(seen_peers.fallback.remove(0))
        } else {
            warn!(
                "Failed to process content key: {content_key}, but a corresponding AcceptQueue record was not found"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethportal_api::{types::enr::generate_random_remote_enr, IdentityContentKey};

    #[tokio::test]
    async fn test_remove_key() {
        let mut accept_queue = AcceptQueue::default();
        let content_key = IdentityContentKey::random();
        let (_, peer) = generate_random_remote_enr();
        assert!(accept_queue.add_key_to_queue(&content_key, &peer));
        assert!(!accept_queue.add_key_to_queue(&content_key, &peer));
        accept_queue.remove_key(&content_key);
        assert!(accept_queue.add_key_to_queue(&content_key, &peer));
    }

    #[tokio::test]
    async fn test_multiple_peers() {
        let mut accept_queue = AcceptQueue::default();
        let content_key = IdentityContentKey::random();
        let (_, peer1) = generate_random_remote_enr();
        let (_, peer2) = generate_random_remote_enr();
        assert!(accept_queue.add_key_to_queue(&content_key, &peer1));
        assert!(!accept_queue.add_key_to_queue(&content_key, &peer2));
        assert!(!accept_queue.add_key_to_queue(&content_key, &peer1));
        accept_queue.remove_key(&content_key);
        assert!(accept_queue.add_key_to_queue(&content_key, &peer1));
    }

    #[tokio::test]
    async fn test_queue_keeps_record_after_duplicate_offers_from_same_peer() {
        let mut accept_queue = AcceptQueue::default();
        let content_key = IdentityContentKey::random();
        let (_, peer1) = generate_random_remote_enr();
        let (_, peer2) = generate_random_remote_enr();
        assert!(accept_queue.add_key_to_queue(&content_key, &peer1));
        assert!(!accept_queue.add_key_to_queue(&content_key, &peer2));
        // peer1 offers the same content key again
        assert!(!accept_queue.add_key_to_queue(&content_key, &peer1));
        let actual_fallback = accept_queue.process_failed_key(&content_key);
        assert_eq!(actual_fallback, Some(peer2));
    }

    #[tokio::test]
    async fn test_process_failed_key() {
        let mut accept_queue = AcceptQueue::default();
        let content_key = IdentityContentKey::random();
        let (_, original_peer) = generate_random_remote_enr();
        let (_, fallback_peer) = generate_random_remote_enr();
        assert!(accept_queue.add_key_to_queue(&content_key, &original_peer));
        assert!(!accept_queue.add_key_to_queue(&content_key, &fallback_peer));
        let actual_fallback = accept_queue.process_failed_key(&content_key);
        assert_eq!(actual_fallback, Some(fallback_peer));
    }

    #[tokio::test]
    async fn test_process_failed_key_with_multiple_records() {
        let mut accept_queue = AcceptQueue::default();
        let content_key1 = IdentityContentKey::random();
        let content_key2 = IdentityContentKey::random();
        let content_key3 = IdentityContentKey::random();
        let (_, peer1) = generate_random_remote_enr();
        let (_, peer2) = generate_random_remote_enr();
        let (_, peer3) = generate_random_remote_enr();
        assert!(accept_queue.add_key_to_queue(&content_key1, &peer1));
        // peer2 is fallback peer for content_key1
        assert!(!accept_queue.add_key_to_queue(&content_key1, &peer2));
        assert!(accept_queue.add_key_to_queue(&content_key2, &peer1));
        // peer3 is fallback peer for content_key2
        assert!(!accept_queue.add_key_to_queue(&content_key2, &peer3));
        assert!(accept_queue.add_key_to_queue(&content_key3, &peer2));
        let actual_fallback1 = accept_queue.process_failed_key(&content_key1);
        assert_eq!(actual_fallback1, Some(peer2));
        // test that content_key3 is still in the queue
        assert!(!accept_queue.add_key_to_queue(&content_key3, &peer1));
        // test that content_key1 is no longer in the queue
        assert!(accept_queue.add_key_to_queue(&content_key1, &peer1));
        let actual_fallback2 = accept_queue.process_failed_key(&content_key2);
        assert_eq!(actual_fallback2, Some(peer3));
        // test that content_key3 is still in the queue
        assert!(!accept_queue.add_key_to_queue(&content_key3, &peer1));
        // test that content_key2 is no longer in the queue
        assert!(accept_queue.add_key_to_queue(&content_key2, &peer1));
    }

    #[tokio::test]
    async fn test_queue_timeout() {
        let mut accept_queue = AcceptQueue::<IdentityContentKey> {
            content_key_map: HashMapDelay::new(Duration::from_secs(1)),
        };
        let content_key = IdentityContentKey::random();
        let (_, peer) = generate_random_remote_enr();
        assert!(accept_queue.add_key_to_queue(&content_key, &peer));
        tokio::time::sleep(Duration::from_secs(3)).await;
        // validate that the content key has been removed from the queue
        assert!(accept_queue.add_key_to_queue(&content_key, &peer));
    }
}
