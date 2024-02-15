use std::collections::HashMap;

use discv5::enr::NodeId;
use ethportal_api::{types::distance::Distance, OverlayContentKey};
use trin_metrics::storage::StorageMetricsReporter;

use crate::{error::ContentStoreError, ContentId, DistanceFunction, PortalStorageConfig};

use super::{store::VersionedContentStore, ContentType, StoreVersion};

struct KeyValuePair {
    key: Vec<u8>,
    value: Vec<u8>,
}

/// In-memory content store
pub struct MemoryContentStore {
    /// The content store.
    store: HashMap<ContentId, KeyValuePair>,
    /// The `NodeId` of the local node.
    node_id: NodeId,
    /// The distance function used by the store to compute distances.
    distance_fn: DistanceFunction,
    /// The radius of the store.
    radius: Distance,
    /// The Metrics reporter
    metrics: StorageMetricsReporter,
}

impl MemoryContentStore {
    pub fn set_radius(&mut self, radius: Distance) {
        self.radius = radius;
    }
}

impl VersionedContentStore for MemoryContentStore {
    fn version() -> StoreVersion {
        StoreVersion::InMemory
    }

    fn migrate_from(
        _content_type: ContentType,
        _old_version: StoreVersion,
        _config: &PortalStorageConfig,
    ) -> Result<(), ContentStoreError> {
        Err(ContentStoreError::Database(
            "Migration to MemoryContentStore not supported!".into(),
        ))
    }

    fn create(
        _content_type: ContentType,
        config: PortalStorageConfig,
        metrics: StorageMetricsReporter,
    ) -> Result<Self, ContentStoreError> {
        metrics.report_radius(Distance::MAX);
        Ok(Self {
            store: HashMap::new(),
            node_id: config.node_id,
            distance_fn: config.distance_fn,
            radius: Distance::MAX,
            metrics,
        })
    }

    fn radius(&self) -> Distance {
        self.radius
    }

    fn distance_to_content_id(&self, content_id: &ContentId) -> Distance {
        self.distance_fn
            .distance(&self.node_id, content_id.as_fixed_bytes())
    }

    fn insert<K: OverlayContentKey>(
        &mut self,
        content_key: &K,
        content_value: Vec<u8>,
    ) -> Result<(), ContentStoreError> {
        let content_id = content_key.content_id().into();
        if !self.should_store_content_id(&content_id) {
            return Err(ContentStoreError::InsufficientRadius {
                radius: self.radius(),
                distance: self.distance_to_content_id(&content_id),
            });
        }

        self.store.insert(
            content_key.content_id().into(),
            KeyValuePair {
                key: content_key.to_bytes(),
                value: content_value,
            },
        );
        self.metrics.increase_entry_count();
        Ok(())
    }

    fn delete(&mut self, content_id: &ContentId) -> Result<(), ContentStoreError> {
        self.store.remove(content_id);
        self.metrics.decrease_entry_count();
        Ok(())
    }

    fn prune(&mut self) -> Result<(), ContentStoreError> {
        let to_delete: Vec<ContentId> = self
            .store
            .keys()
            .filter(|content_id| !self.should_store_content_id(content_id))
            .cloned()
            .collect();

        for content_id in to_delete {
            self.delete(&content_id)?;
        }

        Ok(())
    }

    fn has_content(&self, content_id: &ContentId) -> Result<bool, ContentStoreError> {
        Ok(self.store.contains_key(content_id))
    }

    fn lookup_content_key<K: OverlayContentKey>(
        &self,
        content_id: &ContentId,
    ) -> Result<Option<K>, ContentStoreError> {
        match self.store.get(content_id) {
            None => Ok(None),
            Some(key_value) => Ok(Some(K::try_from(key_value.key.clone())?)),
        }
    }

    fn lookup_content_value(
        &self,
        content_id: &ContentId,
    ) -> Result<Option<Vec<u8>>, ContentStoreError> {
        Ok(self
            .store
            .get(content_id)
            .map(|key_value| key_value.value.clone()))
    }

    fn get_summary_info(&self) -> String {
        self.metrics.get_summary()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub mod test {
    use std::{ops::Sub, path::PathBuf};

    use anyhow::Result;
    use ethereum_types::U256;
    use ethportal_api::{types::portal_wire::ProtocolId, IdentityContentKey};
    use r2d2::Pool;
    use r2d2_sqlite::SqliteConnectionManager;
    use trin_metrics::portalnet::PORTALNET_METRICS;

    use super::*;

    fn setup_store(node_id: &NodeId) -> MemoryContentStore {
        let config = PortalStorageConfig {
            node_id: *node_id,
            node_data_dir: PathBuf::new(),
            storage_capacity_mb: 0,
            distance_fn: DistanceFunction::Xor,
            sql_connection_pool: Pool::new(SqliteConnectionManager::memory()).unwrap(),
        };
        let metrics = StorageMetricsReporter {
            protocol: ProtocolId::History.to_string(),
            storage_metrics: PORTALNET_METRICS.storage(),
        };
        MemoryContentStore::create(ContentType::History, config, metrics).unwrap()
    }

    #[test]
    fn insert() -> Result<()> {
        let node_id = NodeId::random();
        let mut store = setup_store(&node_id);

        let key = IdentityContentKey::new(node_id.raw());
        let id = key.content_id().into();

        assert!(!store.has_content(&id)?, "shouldn't have content");

        store.insert(&key, vec![0xca, 0xfe])?;
        assert!(store.has_content(&id)?, "should have content");

        Ok(())
    }

    #[test]
    fn delete() -> Result<()> {
        let node_id = NodeId::random();
        let mut store = setup_store(&node_id);

        let key = IdentityContentKey::new(node_id.raw());
        let id = key.content_id().into();

        let value = vec![0xca, 0xfe];
        store.insert(&key, value)?;

        assert!(store.has_content(&id)?, "should have content");

        store.delete(&id)?;
        assert!(!store.has_content(&id)?, "should no longer have content");

        Ok(())
    }

    #[test]
    fn lookup() -> Result<()> {
        let node_id = NodeId::random();
        let mut store = setup_store(&node_id);

        let key = IdentityContentKey::new(node_id.raw());
        let id = key.content_id().into();

        let value = vec![0xca, 0xfe];
        store.insert(&key, value.clone())?;

        assert_eq!(
            store.lookup_content_key(&id)?,
            Some(key),
            "content key should match"
        );
        assert_eq!(
            store.lookup_content_value(&id)?,
            Some(value),
            "content value should match"
        );

        Ok(())
    }

    #[test]
    fn radius() -> Result<()> {
        let node_id = NodeId::random();
        let mut store = setup_store(&node_id);

        // pick completely opposite key from node_id (the biggest distance)
        let far_key = IdentityContentKey::new(node_id.raw().map(|b| !b));
        let value = vec![0xca, 0xfe];

        store.insert(&far_key, value)?;

        assert_eq!(store.radius(), Distance::MAX, "radius should be MAX");
        assert!(
            store.has_content(&far_key.content_id().into())?,
            "should have content"
        );

        Ok(())
    }

    #[test]
    #[should_panic = "InsufficientRadius"]
    fn radius_too_big() {
        let node_id = NodeId::random();
        let mut store = setup_store(&node_id);

        // pick completely opposite key from node_id (the biggest distance)
        let far_key = IdentityContentKey::new(node_id.raw().map(|b| !b));
        let value = vec![0xca, 0xfe];

        store.set_radius(store.radius().sub(U256::from(1)).into());

        // should panic
        store.insert(&far_key, value).unwrap();
    }

    #[test]
    fn prune() -> Result<()> {
        let node_id = NodeId::random();
        let mut store = setup_store(&node_id);

        let close_key = IdentityContentKey::new(node_id.raw());
        let far_key = IdentityContentKey::new(node_id.raw().map(|b| !b));

        // insert both and verify they are present
        store.insert(&close_key, vec![0xca])?;
        store.insert(&far_key, vec![0xfe])?;
        assert!(store.has_content(&close_key.content_id().into())?);
        assert!(store.has_content(&far_key.content_id().into())?);

        // lower the radius and prune
        store.set_radius(store.radius().sub(U256::from(1)).into());
        store.prune()?;

        // check that only close key is present
        assert!(
            store.has_content(&close_key.content_id().into())?,
            "should have close key"
        );
        assert!(
            !store.has_content(&far_key.content_id().into())?,
            "shouldn't have far key"
        );

        Ok(())
    }
}
