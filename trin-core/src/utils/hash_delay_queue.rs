//! A `DelayQueue` with keyed entries implemented with a `HashMap`.
//!
//! A `HashDelayQueue` implements `Stream` which removes expired items from the map.

/// The default delay for entries, in seconds. This is only used when `insert()` is used to add
/// entries.
const DEFAULT_DELAY: Duration = Duration::from_secs(30);

use futures::prelude::*;
use std::{
    collections::HashMap,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio_util::time::delay_queue::{self, DelayQueue};

pub struct HashDelayQueue<K>
where
    K: std::cmp::Eq + std::hash::Hash + std::clone::Clone + Unpin,
{
    /// The given entries.
    entries: HashMap<K, delay_queue::Key>,
    /// A queue holding the timeouts of each entry.
    expirations: DelayQueue<K>,
    /// The default expiration timeout of an entry.
    default_expiration_timeout: Duration,
}

impl<K> Default for HashDelayQueue<K>
where
    K: std::cmp::Eq + std::hash::Hash + std::clone::Clone + Unpin,
{
    fn default() -> Self {
        HashDelayQueue::new(DEFAULT_DELAY)
    }
}

impl<K> HashDelayQueue<K>
where
    K: std::cmp::Eq + std::hash::Hash + std::clone::Clone + Unpin,
{
    /// Creates a new, empty `HashDelayQueue` with a default expiration timeout.
    pub fn new(default_expiration_timeout: Duration) -> Self {
        HashDelayQueue {
            entries: HashMap::new(),
            expirations: DelayQueue::new(),
            default_expiration_timeout,
        }
    }

    /// Inserts an entry that expires after the default expiration timeout.
    pub fn insert(&mut self, key: K) {
        self.insert_with_timeout(key, self.default_expiration_timeout);
    }

    /// Inserts an entry that will expire after a given duration.
    ///
    /// If the key was not present, then a new entry is inserted.
    /// If the key was present, then the existing entry is updated.
    ///
    /// # Panics
    ///
    /// This function panics if `timeout` is greater than the maximum duration supported by the
    /// timer in the current `Runtime`.
    pub fn insert_with_timeout(&mut self, key: K, timeout: Duration) {
        if self.contains_key(&key) {
            // Update the timeout.
            self.reset_timeout(&key, timeout);
        } else {
            let delay_key = self.expirations.insert(key.clone(), timeout);
            self.entries.insert(key, delay_key);
        }
    }

    /// Resets the expiration timeout of an entry for `key`. Returns `true` if the key existed,
    /// `false` otherwise.
    ///
    /// # Panics
    ///
    /// This function panics if `timeout` is greater than the maximum duration supported by the
    /// timer in the current `Runtime`.
    pub fn reset_timeout(&mut self, key: &K, timeout: Duration) -> bool {
        if let Some(delay_key) = self.entries.get_mut(key) {
            self.expirations.reset(delay_key, timeout);
            true
        } else {
            false
        }
    }

    /// Returns `true` if the queue contains an entry for `key`, `false` otherwise.
    pub fn contains_key(&self, key: &K) -> bool {
        self.entries.contains_key(key)
    }

    /// Returns the length of the queue.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the queue is empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.len() == 0
    }

    /// Removes the entry associated with the `key`. Returns `true` if there was an entry
    /// associated with `key`, `false` otherwise.
    pub fn remove(&mut self, key: &K) -> bool {
        if let Some(delay_key) = self.entries.remove(key) {
            self.expirations.remove(&delay_key);
            true
        } else {
            false
        }
    }

    /// Clears the queue, removing all entries.
    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.entries.clear();
        self.expirations.clear();
    }
}

impl<K> Stream for HashDelayQueue<K>
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

#[cfg(test)]
mod test {
    use super::*;

    use std::collections::HashSet;

    use tokio::time::{self, sleep, Duration};
    use tokio_test::{assert_ok, assert_pending, assert_ready, task};

    macro_rules! poll {
        ($queue:ident) => {
            $queue.enter(|cx, queue| queue.poll_next(cx))
        };
    }

    macro_rules! assert_ready_ok_some {
        ($e:expr) => {{
            assert_ok!(match assert_ready!($e) {
                Some(v) => v,
                None => panic!("None"),
            })
        }};
    }

    const DELAY: Duration = Duration::from_millis(5);

    #[tokio::test]
    async fn insert_zero_delay() {
        time::pause();

        let mut queue = task::spawn(HashDelayQueue::<String>::new(DELAY));
        let key = "foo".to_string();

        queue.insert_with_timeout(key.clone(), Duration::ZERO);

        sleep(Duration::from_millis(1)).await;

        let entry = assert_ready_ok_some!(poll!(queue));
        assert_eq!(key, entry);

        let entry = assert_ready!(poll!(queue));
        assert!(entry.is_none());
    }

    #[tokio::test]
    async fn multi_insert_zero_delay() {
        time::pause();

        let mut queue = task::spawn(HashDelayQueue::<String>::new(DELAY));

        let mut keys = HashSet::new();
        keys.insert("1".to_string());
        keys.insert("2".to_string());
        keys.insert("3".to_string());

        for key in keys.iter() {
            queue.insert_with_timeout(key.clone(), Duration::ZERO);
        }

        sleep(Duration::from_millis(1)).await;

        let mut entries = vec![];
        while entries.len() < keys.len() {
            let entry = assert_ready_ok_some!(poll!(queue));
            entries.push(entry);
        }

        let entry = assert_ready!(poll!(queue));
        assert!(entry.is_none());

        for entry in entries {
            assert!(keys.remove(&entry));
        }
        assert_eq!(0, keys.len());
    }

    #[tokio::test]
    async fn insert_short_delay() {
        time::pause();

        let mut queue = task::spawn(HashDelayQueue::<String>::new(DELAY));
        let key = "foo".to_string();

        queue.insert_with_timeout(key.clone(), Duration::from_millis(5));

        sleep(Duration::from_millis(1)).await;

        assert_pending!(poll!(queue));

        sleep(Duration::from_millis(5)).await;

        let entry = assert_ready_ok_some!(poll!(queue));
        assert_eq!(key, entry);

        let entry = assert_ready!(poll!(queue));
        assert!(entry.is_none());
    }

    #[tokio::test]
    async fn reset() {
        time::pause();

        let mut queue = task::spawn(HashDelayQueue::<String>::new(DELAY));
        let key = "foo".to_string();

        queue.insert_with_timeout(key.clone(), Duration::from_millis(5));

        assert_pending!(poll!(queue));

        sleep(Duration::from_millis(1)).await;

        queue.reset_timeout(&key, Duration::from_millis(10));

        assert_pending!(poll!(queue));

        sleep(Duration::from_millis(5)).await;

        assert_pending!(poll!(queue));

        sleep(Duration::from_millis(5)).await;

        let entry = assert_ready_ok_some!(poll!(queue));
        assert_eq!(key, entry);

        let entry = assert_ready!(poll!(queue));
        assert!(entry.is_none());
    }

    #[tokio::test]
    async fn multi_reset() {
        time::pause();

        let mut queue = task::spawn(HashDelayQueue::<String>::new(DELAY));
        let key = "foo".to_string();

        queue.insert_with_timeout(key.clone(), Duration::from_millis(50));

        assert_pending!(poll!(queue));

        queue.reset_timeout(&key, Duration::from_millis(10));

        assert_pending!(poll!(queue));

        sleep(Duration::from_millis(5)).await;

        assert_pending!(poll!(queue));

        queue.reset_timeout(&key, Duration::from_millis(10));

        sleep(Duration::from_millis(5)).await;

        assert_pending!(poll!(queue));

        sleep(Duration::from_millis(5)).await;

        let entry = assert_ready_ok_some!(poll!(queue));
        assert_eq!(key, entry);

        let entry = assert_ready!(poll!(queue));
        assert!(entry.is_none());
    }

    #[tokio::test]
    async fn reset_expired_entry() {
        time::pause();

        let mut queue = task::spawn(HashDelayQueue::<String>::new(DELAY));
        let key = "foo".to_string();

        queue.insert_with_timeout(key.clone(), Duration::ZERO);
        queue.reset_timeout(&key, Duration::from_millis(10));

        assert_pending!(poll!(queue));

        sleep(Duration::from_millis(10)).await;

        let entry = assert_ready_ok_some!(poll!(queue));
        assert_eq!(key, entry);

        let entry = assert_ready!(poll!(queue));
        assert!(entry.is_none());
    }

    #[tokio::test]
    async fn remove_existing() {
        time::pause();

        let mut queue = task::spawn(HashDelayQueue::<String>::new(DELAY));
        let key = "foo".to_string();

        queue.insert_with_timeout(key.clone(), Duration::from_millis(1));

        assert_pending!(poll!(queue));

        let removed = queue.remove(&key);
        assert!(removed);

        sleep(Duration::from_millis(5)).await;

        let entry = assert_ready!(poll!(queue));
        assert!(entry.is_none());
    }

    #[tokio::test]
    async fn remove_nonexisting() {
        time::pause();

        let mut queue = task::spawn(HashDelayQueue::<String>::new(DELAY));
        let key = "foo".to_string();

        let removed = queue.remove(&key);
        assert!(!removed);
    }

    #[tokio::test]
    async fn clear() {
        time::pause();

        let mut queue = task::spawn(HashDelayQueue::<String>::new(DELAY));

        let mut keys = HashSet::new();
        keys.insert("1".to_string());
        keys.insert("2".to_string());
        keys.insert("3".to_string());

        for key in keys.iter() {
            queue.insert_with_timeout(key.clone(), Duration::ZERO);
        }

        assert_eq!(keys.len(), queue.len());

        queue.clear();

        assert_eq!(0, queue.len());

        let entry = assert_ready!(poll!(queue));
        assert!(entry.is_none());
    }

    #[tokio::test]
    async fn len() {
        time::pause();

        let mut queue = task::spawn(HashDelayQueue::<String>::new(DELAY));

        let mut keys = HashSet::new();
        keys.insert("1".to_string());
        keys.insert("2".to_string());
        keys.insert("3".to_string());

        for key in keys.iter() {
            queue.insert_with_timeout(key.clone(), Duration::ZERO);
        }

        sleep(Duration::from_millis(1)).await;

        assert_eq!(keys.len(), queue.len());

        for _ in 0..queue.len() {
            let _ = assert_ready_ok_some!(poll!(queue));
        }

        assert_eq!(0, queue.len());

        let entry = assert_ready!(poll!(queue));
        assert!(entry.is_none());
    }
}
