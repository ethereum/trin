pub mod error;
pub mod sql;
pub mod utils;

use crate::utils::setup_sql;
use discv5::enr::NodeId;
use error::ContentStoreError;
use ethportal_api::types::{
    content_key::overlay::OverlayContentKey,
    distance::{Distance, Metric, XorMetric},
};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use std::path::PathBuf;

pub const BYTES_IN_MB_U64: u64 = 1000 * 1000;

// TODO: Replace enum with generic type parameter. This will require that we have a way to
// associate a "find farthest" query with the generic Metric.
#[derive(Copy, Clone, Debug)]
pub enum DistanceFunction {
    Xor,
}

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
    /// Looks up a piece of content by `key`.
    fn get<K: OverlayContentKey>(&self, key: &K) -> Result<Option<Vec<u8>>, ContentStoreError>;

    /// Puts a piece of content into the store.
    fn put<K: OverlayContentKey, V: AsRef<[u8]>>(
        &mut self,
        key: K,
        value: V,
    ) -> Result<(), ContentStoreError>;

    /// Returns whether the content denoted by `key` is within the radius of the data store and not
    /// already stored within the data store.
    fn is_key_within_radius_and_unavailable<K: OverlayContentKey>(
        &self,
        key: &K,
    ) -> Result<ShouldWeStoreContent, ContentStoreError>;

    /// Returns the radius of the data store.
    fn radius(&self) -> Distance;
}

/// An in-memory `ContentStore`.
pub struct MemoryContentStore {
    /// The content store.
    store: std::collections::HashMap<Vec<u8>, Vec<u8>>,
    /// The `NodeId` of the local node.
    node_id: NodeId,
    /// The distance function used by the store to compute distances.
    distance_fn: DistanceFunction,
    /// The radius of the store.
    radius: Distance,
}

impl MemoryContentStore {
    /// Constructs a new `MemoryPortalContentStore`.
    pub fn new(node_id: NodeId, distance_fn: DistanceFunction) -> Self {
        Self {
            store: std::collections::HashMap::new(),
            node_id,
            distance_fn,
            radius: Distance::MAX,
        }
    }

    /// Sets the radius of the store to `radius`.
    pub fn set_radius(&mut self, radius: Distance) {
        self.radius = radius;
    }

    /// Returns the distance to `key` from the local `NodeId` according to the distance function.
    fn distance_to_key<K: OverlayContentKey>(&self, key: &K) -> Distance {
        match self.distance_fn {
            DistanceFunction::Xor => XorMetric::distance(&key.content_id(), &self.node_id.raw()),
        }
    }

    /// Returns `true` if the content store contains data for `key`.
    fn contains_key<K: OverlayContentKey>(&self, key: &K) -> bool {
        let key = key.content_id().to_vec();
        self.store.contains_key(&key)
    }
}

impl ContentStore for MemoryContentStore {
    fn get<K: OverlayContentKey>(&self, key: &K) -> Result<Option<Vec<u8>>, ContentStoreError> {
        let key = key.content_id();
        let val = self.store.get(&key.to_vec()).cloned();
        Ok(val)
    }

    fn put<K: OverlayContentKey, V: AsRef<[u8]>>(
        &mut self,
        key: K,
        value: V,
    ) -> Result<(), ContentStoreError> {
        let content_id = key.content_id();
        let value: &[u8] = value.as_ref();
        self.store.insert(content_id.to_vec(), value.to_vec());

        Ok(())
    }

    fn is_key_within_radius_and_unavailable<K: OverlayContentKey>(
        &self,
        key: &K,
    ) -> Result<ShouldWeStoreContent, ContentStoreError> {
        let distance = self.distance_to_key(key);
        if distance > self.radius {
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

/// Struct for configuring a `PortalStorage` instance.
#[derive(Clone)]
pub struct PortalStorageConfig {
    pub storage_capacity_mb: u64,
    pub node_id: NodeId,
    pub node_data_dir: PathBuf,
    pub distance_fn: DistanceFunction,
    pub sql_connection_pool: Pool<SqliteConnectionManager>,
}

impl PortalStorageConfig {
    pub fn new(
        storage_capacity_mb: u64,
        node_data_dir: PathBuf,
        node_id: NodeId,
    ) -> anyhow::Result<Self> {
        let sql_connection_pool = setup_sql(&node_data_dir)?;
        Ok(Self {
            storage_capacity_mb,
            node_id,
            node_data_dir,
            distance_fn: DistanceFunction::Xor,
            sql_connection_pool,
        })
    }
}

// SQLite Result Containers
pub struct ContentId {
    pub id_long: Vec<u8>,
}

pub struct DataSize {
    pub num_bytes: f64,
}

pub struct EntryCount(pub u64);

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub mod test {
    use super::*;
    use ethportal_api::IdentityContentKey;

    #[test]
    fn memory_store_contains_key() {
        let node_id = NodeId::random();
        let mut store = MemoryContentStore::new(node_id, DistanceFunction::Xor);

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
        let mut store = MemoryContentStore::new(node_id, DistanceFunction::Xor);

        let val = vec![0xef];

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
        let mut store = MemoryContentStore::new(node_id, DistanceFunction::Xor);

        let val = vec![0xef];

        // Store content
        let arb_key = IdentityContentKey::new(node_id.raw());
        let _ = store.put(arb_key.clone(), val.clone());
        assert_eq!(store.get(&arb_key).unwrap(), Some(val));
    }

    #[test]
    fn memory_store_is_within_radius_and_unavailable() {
        let node_id = NodeId::random();
        let mut store = MemoryContentStore::new(node_id, DistanceFunction::Xor);

        let val = vec![0xef];

        // Arbitrary key within radius and unavailable.
        let arb_key = IdentityContentKey::new(node_id.raw());
        assert_eq!(
            store
                .is_key_within_radius_and_unavailable(&arb_key)
                .unwrap(),
            ShouldWeStoreContent::Store
        );

        // Arbitrary key available.
        let _ = store.put(arb_key.clone(), val);
        assert_eq!(
            store
                .is_key_within_radius_and_unavailable(&arb_key)
                .unwrap(),
            ShouldWeStoreContent::AlreadyStored
        );
    }
}
