use ethportal_api::{
    types::{distance::Distance, history::PaginateLocalContentInfo},
    OverlayContentKey,
};
use trin_storage::{
    error::ContentStoreError,
    versioned::{create_store, ContentType, LegacyHistoryStore},
    ContentStore, PortalStorageConfig, ShouldWeStoreContent,
};

/// Storage layer for the history network. Encapsulates history network specific data and logic.
#[derive(Debug)]
pub struct HistoryStorage {
    store: LegacyHistoryStore,
}

impl ContentStore for HistoryStorage {
    fn get<K: OverlayContentKey>(&self, key: &K) -> Result<Option<Vec<u8>>, ContentStoreError> {
        self.store
            .lookup_content_value(key.content_id())
            .map_err(|err| {
                ContentStoreError::Database(format!("Error looking up content value: {err:?}"))
            })
    }

    fn put<K: OverlayContentKey, V: AsRef<[u8]>>(
        &mut self,
        key: K,
        value: V,
    ) -> Result<(), ContentStoreError> {
        self.store.store(&key, &value.as_ref().to_vec())
    }

    fn is_key_within_radius_and_unavailable<K: OverlayContentKey>(
        &self,
        key: &K,
    ) -> Result<ShouldWeStoreContent, ContentStoreError> {
        let content_id = key.content_id();
        if self.store.distance_to_content_id(&content_id) > self.store.radius() {
            return Ok(ShouldWeStoreContent::NotWithinRadius);
        }

        match self.store.lookup_content_key(content_id).map_err(|err| {
            ContentStoreError::Database(format!("Error looking up content key: {err:?}"))
        })? {
            Some(_) => Ok(ShouldWeStoreContent::AlreadyStored),
            None => Ok(ShouldWeStoreContent::Store),
        }
    }

    fn radius(&self) -> Distance {
        self.store.radius()
    }
}

impl HistoryStorage {
    pub fn new(config: PortalStorageConfig) -> Result<Self, ContentStoreError> {
        let sql_connection_pool = config.sql_connection_pool.clone();
        Ok(Self {
            store: create_store(ContentType::History, config, sql_connection_pool)?,
        })
    }

    /// Get a summary of the current state of storage
    pub fn get_summary_info(&self) -> String {
        self.store.get_summary_info()
    }

    /// Returns a paginated list of all available content keys from local storage (from any
    /// subnetwork) according to the provided offset and limit.
    pub fn paginate(
        &self,
        offset: u64,
        limit: u64,
    ) -> Result<PaginateLocalContentInfo, ContentStoreError> {
        self.store.paginate(&offset, &limit)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub mod test {
    use std::path::PathBuf;

    use discv5::enr::{CombinedKey, Enr as Discv5Enr, NodeId};
    use ethportal_api::{BlockHeaderKey, HistoryContentKey, IdentityContentKey};
    use portalnet::utils::db::{configure_node_data_dir, setup_temp_dir};
    use quickcheck::{QuickCheck, TestResult};
    use rand::RngCore;
    use serial_test::serial;

    use super::*;

    const CAPACITY_MB: u64 = 2;

    fn get_active_node_id(temp_dir: PathBuf) -> NodeId {
        let (_, mut pk) = configure_node_data_dir(temp_dir, None, "test".to_string()).unwrap();
        let pk = CombinedKey::secp256k1_from_bytes(pk.0.as_mut_slice()).unwrap();
        Discv5Enr::empty(&pk).unwrap().node_id()
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_store() {
        fn test_store_random_bytes() -> TestResult {
            let temp_dir = setup_temp_dir().unwrap();
            let node_id = get_active_node_id(temp_dir.path().to_path_buf());
            let storage_config =
                PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id)
                    .unwrap();
            let mut storage = HistoryStorage::new(storage_config).unwrap();
            let content_key = IdentityContentKey::random();
            let mut value = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut value);
            storage.put(content_key, value).unwrap();

            std::mem::drop(storage);
            temp_dir.close().unwrap();

            TestResult::passed()
        }
        QuickCheck::new()
            .tests(10)
            .quickcheck(test_store_random_bytes as fn() -> _);
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_get_data() -> Result<(), ContentStoreError> {
        let temp_dir = setup_temp_dir().unwrap();
        let node_id = get_active_node_id(temp_dir.path().to_path_buf());
        let storage_config =
            PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id).unwrap();
        let mut storage = HistoryStorage::new(storage_config)?;
        let content_key = HistoryContentKey::BlockHeaderWithProof(BlockHeaderKey::default());
        let value: Vec<u8> = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".into();
        storage.put(content_key.clone(), &value)?;

        let result = storage.get(&content_key).unwrap().unwrap();

        assert_eq!(result, value);

        drop(storage);
        temp_dir.close()?;
        Ok(())
    }
}
