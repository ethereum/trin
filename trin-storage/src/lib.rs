pub mod error;
pub mod sql;
pub mod test_utils;
pub mod utils;
pub mod versioned;

use crate::utils::setup_sql;
use discv5::enr::NodeId;
use error::ContentStoreError;
use ethereum_types::H256;
use ethportal_api::types::{
    content_key::overlay::OverlayContentKey,
    distance::{Distance, Metric, XorMetric},
};
use sqlx::{sqlite::SqliteValueRef, Database, Decode, Sqlite, SqlitePool, Type};
use std::{error::Error, ops::Deref, path::PathBuf};

pub const DATABASE_NAME: &str = "trin.sqlite";
pub const BYTES_IN_MB_U64: u64 = 1000 * 1000;

// TODO: Replace enum with generic type parameter. This will require that we have a way to
// associate a "find farthest" query with the generic Metric.
#[derive(Copy, Clone, Debug)]
pub enum DistanceFunction {
    Xor,
}

impl DistanceFunction {
    pub fn distance(&self, node_id: &NodeId, other: &[u8; 32]) -> Distance {
        match self {
            DistanceFunction::Xor => XorMetric::distance(&node_id.raw(), other),
        }
    }
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
    fn get<K: OverlayContentKey>(
        &self,
        key: &K,
    ) -> impl std::future::Future<Output = Result<Option<Vec<u8>>, ContentStoreError>> + Send;

    /// Puts a piece of content into the store.
    fn put<K: OverlayContentKey>(
        &mut self,
        key: K,
        value: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<(), ContentStoreError>> + Send;

    /// Returns whether the content denoted by `key` is within the radius of the data store and not
    /// already stored within the data store.
    fn is_key_within_radius_and_unavailable<K: OverlayContentKey>(
        &self,
        key: &K,
    ) -> impl std::future::Future<Output = Result<ShouldWeStoreContent, ContentStoreError>> + Send;

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
        self.distance_fn.distance(&self.node_id, &key.content_id())
    }

    /// Returns `true` if the content store contains data for `key`.
    fn contains_key<K: OverlayContentKey>(&self, key: &K) -> bool {
        let key = key.content_id().to_vec();
        self.store.contains_key(&key)
    }
}

impl ContentStore for MemoryContentStore {
    async fn get<K: OverlayContentKey>(
        &self,
        key: &K,
    ) -> Result<Option<Vec<u8>>, ContentStoreError> {
        let key = key.content_id();
        let val = self.store.get(&key.to_vec()).cloned();
        Ok(val)
    }

    async fn put<K: OverlayContentKey>(
        &mut self,
        key: K,
        value: Vec<u8>,
    ) -> Result<(), ContentStoreError> {
        let content_id = key.content_id();
        self.store.insert(content_id.to_vec(), value);

        Ok(())
    }

    async fn is_key_within_radius_and_unavailable<K: OverlayContentKey>(
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
    pub sql_connection_pool: SqlitePool,
}

impl PortalStorageConfig {
    pub async fn new(
        storage_capacity_mb: u64,
        node_data_dir: PathBuf,
        node_id: NodeId,
    ) -> Result<Self, ContentStoreError> {
        let sql_connection_pool = setup_sql(&node_data_dir).await?;
        Ok(Self {
            storage_capacity_mb,
            node_id,
            node_data_dir,
            distance_fn: DistanceFunction::Xor,
            sql_connection_pool,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentId(H256);

impl Type<Sqlite> for ContentId {
    fn type_info() -> <Sqlite as Database>::TypeInfo {
        <Vec<u8> as Type<Sqlite>>::type_info()
    }
}

impl<'r> Decode<'r, Sqlite> for ContentId {
    fn decode(
        value: SqliteValueRef<'r>,
    ) -> Result<ContentId, Box<dyn Error + 'static + Send + Sync>> {
        let bytes: &[u8] = Decode::<Sqlite>::decode(value)?;

        if bytes.len() == H256::len_bytes() {
            Ok(ContentId(H256::from_slice(bytes)))
        } else {
            Err(format!(
                "ContentId is not possible from a blob of length {}",
                bytes.len()
            )
            .into())
        }
    }
}

impl<T: Into<H256>> From<T> for ContentId {
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl Deref for ContentId {
    type Target = H256;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct EntryCount(pub i64);

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub mod test {
    use super::*;
    use ethportal_api::{jsonrpsee::tokio, IdentityContentKey};

    #[tokio::test]
    async fn memory_store_contains_key() {
        let node_id = NodeId::random();
        let mut store = MemoryContentStore::new(node_id, DistanceFunction::Xor);

        let val = vec![0xef];

        // Arbitrary key not available.
        let arb_key = IdentityContentKey::new(node_id.raw());
        assert!(!store.contains_key(&arb_key));

        // Arbitrary key available.
        let _ = store.put(arb_key.clone(), val).await;
        assert!(store.contains_key(&arb_key));
    }

    #[tokio::test]
    async fn memory_store_get() {
        let node_id = NodeId::random();
        let mut store = MemoryContentStore::new(node_id, DistanceFunction::Xor);

        let val = vec![0xef];

        // Arbitrary key not available.
        let arb_key = IdentityContentKey::new(node_id.raw());
        assert!(store.get(&arb_key).await.unwrap().is_none());
        assert!(store.get(&arb_key).await.unwrap().is_none());

        // Arbitrary key available and equal to assigned value.
        let _ = store.put(arb_key.clone(), val.clone()).await;
        assert_eq!(store.get(&arb_key).await.unwrap(), Some(val));
    }

    #[tokio::test]
    async fn memory_store_put() {
        let node_id = NodeId::random();
        let mut store = MemoryContentStore::new(node_id, DistanceFunction::Xor);

        let val = vec![0xef];

        // Store content
        let arb_key = IdentityContentKey::new(node_id.raw());
        let _ = store.put(arb_key.clone(), val.clone()).await;
        assert_eq!(store.get(&arb_key).await.unwrap(), Some(val));
    }

    #[tokio::test]
    async fn memory_store_is_within_radius_and_unavailable() {
        let node_id = NodeId::random();
        let mut store = MemoryContentStore::new(node_id, DistanceFunction::Xor);

        let val = vec![0xef];

        // Arbitrary key within radius and unavailable.
        let arb_key = IdentityContentKey::new(node_id.raw());
        assert_eq!(
            store
                .is_key_within_radius_and_unavailable(&arb_key)
                .await
                .unwrap(),
            ShouldWeStoreContent::Store
        );

        // Arbitrary key available.
        let _ = store.put(arb_key.clone(), val).await;
        assert_eq!(
            store
                .is_key_within_radius_and_unavailable(&arb_key)
                .await
                .unwrap(),
            ShouldWeStoreContent::AlreadyStored
        );
    }
}
