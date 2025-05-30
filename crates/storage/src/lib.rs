pub mod config;
pub mod error;
pub mod sql;
pub mod test_utils;
pub mod utils;
pub mod versioned;

use std::{marker::PhantomData, ops::Deref, str::FromStr};

use alloy::primitives::{Bytes, B256};
pub use config::{PortalStorageConfig, PortalStorageConfigFactory};
use discv5::enr::NodeId;
use error::ContentStoreError;
use ethportal_api::{
    types::{
        content_key::overlay::{IdentityContentKey, OverlayContentKey},
        distance::{Distance, Metric, XorMetric},
    },
    RawContentValue,
};
use rusqlite::types::{FromSql, FromSqlError, ValueRef};

pub const DATABASE_NAME: &str = "trin.sqlite";

/// An enum which tells us if we should store or not store content, and if not why for better
/// errors.
#[derive(Debug, PartialEq)]
pub enum ShouldWeStoreContent {
    Store,
    NotWithinRadius,
    AlreadyStored,
}

/// A data store for Portal Network content (data).
pub trait ContentStore {
    type Key;

    /// Looks up a piece of content by `key`.
    fn get(&self, key: &Self::Key) -> Result<Option<RawContentValue>, ContentStoreError>;

    /// Puts a piece of content into the store.
    ///
    /// Returns a list of keys that were evicted from the store, which should be gossiped into the
    /// network. In the future this might be updated to a separate table that stores a queue
    /// of content keys to be gossiped and gossips them in a background task.
    #[allow(clippy::type_complexity)]
    fn put<V: AsRef<[u8]>>(
        &mut self,
        key: Self::Key,
        value: V,
    ) -> Result<Vec<(Self::Key, RawContentValue)>, ContentStoreError>;

    /// Returns whether the content denoted by `key` is within the radius of the data store and not
    /// already stored within the data store.
    fn should_we_store(&self, key: &Self::Key) -> Result<ShouldWeStoreContent, ContentStoreError>;

    /// Performs [ContentStore::should_we_store] for multiple content keys.
    ///
    /// The default implementation calls `self.should_we_store` for each key.
    fn should_we_store_batch(
        &self,
        keys: &[Self::Key],
    ) -> Result<Vec<ShouldWeStoreContent>, ContentStoreError> {
        keys.iter().map(|key| self.should_we_store(key)).collect()
    }

    /// Returns the radius of the data store.
    fn radius(&self) -> Distance;
}

/// An in-memory `ContentStore`.
pub struct MemoryContentStore<TMetric: Metric = XorMetric> {
    /// The content store.
    store: std::collections::HashMap<Vec<u8>, RawContentValue>,
    /// The `NodeId` of the local node.
    node_id: NodeId,
    /// The radius of the store.
    radius: Distance,
    /// Phantom metric
    _metric: PhantomData<TMetric>,
}

impl<TMetric: Metric> MemoryContentStore<TMetric> {
    /// Constructs a new `MemoryPortalContentStore`.
    pub fn new(node_id: NodeId) -> Self {
        Self {
            store: std::collections::HashMap::new(),
            node_id,
            radius: Distance::MAX,
            _metric: PhantomData,
        }
    }

    /// Sets the radius of the store to `radius`.
    pub fn set_radius(&mut self, radius: Distance) {
        self.radius = radius;
    }

    /// Returns the distance to `key` from the local `NodeId` according to the distance function.
    fn distance_to_key<K: OverlayContentKey>(&self, key: &K) -> Distance {
        TMetric::distance(&self.node_id.raw(), &key.content_id())
    }

    /// Returns `true` if the content store contains data for `key`.
    fn contains_key<K: OverlayContentKey>(&self, key: &K) -> bool {
        let key = key.content_id().to_vec();
        self.store.contains_key(&key)
    }
}

impl<TMetric: Metric> ContentStore for MemoryContentStore<TMetric> {
    type Key = IdentityContentKey;

    fn get(&self, key: &Self::Key) -> Result<Option<RawContentValue>, ContentStoreError> {
        let key = key.content_id();
        let val = self.store.get(key.as_slice()).cloned();
        Ok(val)
    }

    fn put<V: AsRef<[u8]>>(
        &mut self,
        key: Self::Key,
        value: V,
    ) -> Result<Vec<(Self::Key, RawContentValue)>, ContentStoreError> {
        let content_id = key.content_id();
        let value: &[u8] = value.as_ref();
        self.store
            .insert(content_id.to_vec(), Bytes::copy_from_slice(value));

        Ok(vec![])
    }

    fn should_we_store(&self, key: &Self::Key) -> Result<ShouldWeStoreContent, ContentStoreError> {
        if key.affected_by_radius() && self.distance_to_key(key) > self.radius {
            return Ok(ShouldWeStoreContent::NotWithinRadius);
        }
        if self.contains_key(key) {
            return Ok(ShouldWeStoreContent::AlreadyStored);
        }
        Ok(ShouldWeStoreContent::Store)
    }

    fn radius(&self) -> Distance {
        self.radius
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentId(B256);

impl<T: Into<B256>> From<T> for ContentId {
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl FromSql for ContentId {
    fn column_result(value: ValueRef<'_>) -> Result<Self, FromSqlError> {
        match value {
            ValueRef::Blob(bytes) => {
                if bytes.len() == B256::len_bytes() {
                    Ok(ContentId(B256::from_slice(bytes)))
                } else {
                    Err(FromSqlError::Other(
                        format!(
                            "ContentId is not possible from a blob of length {}",
                            bytes.len()
                        )
                        .into(),
                    ))
                }
            }
            ValueRef::Text(_) => {
                let hex_text = value.as_str()?;
                B256::from_str(hex_text)
                    .map(ContentId)
                    .map_err(|err| FromSqlError::Other(err.into()))
            }
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

impl Deref for ContentId {
    type Target = B256;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct DataSize {
    pub num_bytes: f64,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub mod test {
    use alloy::primitives::{bytes, B512};
    use ethportal_api::{types::distance::XorMetric, IdentityContentKey};

    use super::*;

    #[test]
    fn memory_store_contains_key() {
        let node_id = NodeId::random();
        let mut store = MemoryContentStore::<XorMetric>::new(node_id);

        let val = vec![0xef];

        // Arbitrary key not available.
        let arb_key = IdentityContentKey::new(node_id.raw());
        assert!(!store.contains_key(&arb_key));

        // Arbitrary key available.
        let _ = store.put(arb_key.clone(), val);
        assert!(store.contains_key(&arb_key));
    }

    #[test]
    fn memory_store_get() {
        let node_id = NodeId::random();
        let mut store = MemoryContentStore::<XorMetric>::new(node_id);

        let val = bytes!("ef");

        // Arbitrary key not available.
        let arb_key = IdentityContentKey::new(node_id.raw());
        assert!(store.get(&arb_key).unwrap().is_none());

        // Arbitrary key available and equal to assigned value.
        let _ = store.put(arb_key.clone(), val.clone());
        assert_eq!(store.get(&arb_key).unwrap(), Some(val));
    }

    #[test]
    fn memory_store_put() {
        let node_id = NodeId::random();
        let mut store = MemoryContentStore::<XorMetric>::new(node_id);

        let val = bytes!("ef");

        // Store content
        let arb_key = IdentityContentKey::new(node_id.raw());
        let _ = store.put(arb_key.clone(), val.clone());
        assert_eq!(store.get(&arb_key).unwrap(), Some(val));
    }

    #[test]
    fn memory_store_is_within_radius_and_unavailable() {
        let node_id = NodeId::random();
        let mut store = MemoryContentStore::<XorMetric>::new(node_id);

        let val = bytes!("ef");

        // Arbitrary key within radius and unavailable.
        let arb_key = IdentityContentKey::new(node_id.raw());
        assert_eq!(
            store.should_we_store(&arb_key).unwrap(),
            ShouldWeStoreContent::Store
        );

        // Arbitrary key available.
        let _ = store.put(arb_key.clone(), val);
        assert_eq!(
            store.should_we_store(&arb_key).unwrap(),
            ShouldWeStoreContent::AlreadyStored
        );
    }

    #[test]
    fn content_id_from_blob() {
        let content_id = ContentId(B256::random());
        let sql_value = ValueRef::from(content_id.as_slice());
        assert_eq!(ContentId::column_result(sql_value), Ok(content_id));
    }

    #[test]
    #[should_panic(expected = "ContentId is not possible from a blob of length 31")]
    fn content_id_from_blob_less_bytes() {
        let bytes = B256::random().0;
        ContentId::column_result(ValueRef::from(&bytes[..31])).unwrap();
    }

    #[test]
    #[should_panic(expected = "ContentId is not possible from a blob of length 33")]
    fn content_id_from_blob_more_bytes() {
        let bytes = B512::random().0;
        ContentId::column_result(ValueRef::from(&bytes[..33])).unwrap();
    }

    #[test]
    fn content_id_from_text() {
        let content_id_str = "0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF";
        let content_id = ContentId(B256::from_str(content_id_str).unwrap());
        let sql_value = ValueRef::from(content_id_str);
        assert_eq!(ContentId::column_result(sql_value), Ok(content_id));
    }

    #[test]
    fn content_id_from_text_with_0x_prefix() {
        let content_id_str = "0x0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF";
        let content_id = ContentId(B256::from_str(content_id_str).unwrap());
        let sql_value = ValueRef::from(content_id_str);
        assert_eq!(ContentId::column_result(sql_value), Ok(content_id));
    }
}
