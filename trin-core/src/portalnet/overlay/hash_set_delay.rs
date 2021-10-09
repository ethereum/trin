//! A simple hashset object coupled with a `delay_queue` which has entries that expire after a
//! fixed time.
//!
//! A `HashSetDelay` implements `Stream` which removes expired items from the map.
//!
//! Based on implementation by Sigma Prime: https://github.com/sigp/discv5/blob/master/src/service/hashset_delay.rs.

/// The default delay for entries, in seconds. This is only used when `insert()` is used to add
/// entries.
const DEFAULT_DELAY: u64 = 30;

use futures::prelude::*;
use std::{
    collections::HashMap,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio_util::time::delay_queue::{self, DelayQueue};

pub struct HashSetDelay<K>
where
    K: std::cmp::Eq + std::hash::Hash + std::clone::Clone + Unpin,
{
    /// The given entries.
    entries: HashMap<K, delay_queue::Key>,
    /// A queue holding the timeouts of each entry.
    expirations: DelayQueue<K>,
    /// The default expiration timeout of an entry.
    default_entry_timeout: Duration,
}

impl<K> Default for HashSetDelay<K>
where
    K: std::cmp::Eq + std::hash::Hash + std::clone::Clone + Unpin,
{
    fn default() -> Self {
        HashSetDelay::new(Duration::from_secs(DEFAULT_DELAY))
    }
}

impl<K> HashSetDelay<K>
where
    K: std::cmp::Eq + std::hash::Hash + std::clone::Clone + Unpin,
{
    /// Creates a new instance of `HashSetDelay`.
    pub fn new(default_entry_timeout: Duration) -> Self {
        HashSetDelay {
            entries: HashMap::new(),
            expirations: DelayQueue::new(),
            default_entry_timeout,
        }
    }

    /// Insert an entry into the mapping. Entries will expire after the `default_entry_timeout`.
    pub fn insert(&mut self, key: K) {
        self.insert_at(key, self.default_entry_timeout);
    }

    /// Inserts an entry that will expire at a given instant.
    pub fn insert_at(&mut self, key: K, entry_duration: Duration) {
        if self.contains_key(&key) {
            // update the timeout
            self.update_timeout(&key, entry_duration);
        } else {
            let delay_key = self.expirations.insert(key.clone(), entry_duration);
            self.entries.insert(key, delay_key);
        }
    }

    /// Updates the timeout for a given key. Returns true if the key existed, false otherwise.
    ///
    /// Panics if the duration is too far in the future.
    pub fn update_timeout(&mut self, key: &K, timeout: Duration) -> bool {
        if let Some(delay_key) = self.entries.get_mut(key) {
            self.expirations.reset(delay_key, timeout);
            true
        } else {
            false
        }
    }

    /// Returns true if the key exists, false otherwise.
    pub fn contains_key(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }

    /// Returns the length of the mapping.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Removes a key from the map returning the value associated with the key that was in the map.
    ///
    /// Return None if the key was not in the map.
    pub fn remove(&mut self, key: &K) -> bool {
        if let Some(delay_key) = self.entries.remove(key) {
            self.expirations.remove(&delay_key);
            true
        } else {
            false
        }
    }

    /// Removes all entries from the map.
    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.entries.clear();
        self.expirations.clear();
    }
}

impl<K> Stream for HashSetDelay<K>
where
    K: std::cmp::Eq + std::hash::Hash + std::clone::Clone + Unpin,
{
    type Item = Result<K, String>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.expirations.poll_expired(cx) {
            Poll::Ready(Some(Ok(key))) => match self.entries.remove(key.get_ref()) {
                Some(_delay_key) => Poll::Ready(Some(Ok(key.into_inner()))),
                None => Poll::Ready(Some(Err("Value no longer exists in expirations".into()))),
            },
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Some(Err(format!("delay queue error: {:?}", e))))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}
