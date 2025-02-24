use ethportal_api::{
    types::{distance::Distance, network::Subnetwork, portal::PaginateLocalContentInfo},
    HistoryContentKey, OverlayContentKey, RawContentValue,
};
use trin_storage::{
    error::ContentStoreError,
    versioned::{create_store, ContentType, IdIndexedV1Store, IdIndexedV1StoreConfig},
    ContentId, ContentStore, PortalStorageConfig, ShouldWeStoreContent,
};

use crate::storage_migration::maybe_migrate;

/// Storage layer for the history network. Encapsulates history network specific data and logic.
#[derive(Debug)]
pub struct HistoryStorage {
    store: IdIndexedV1Store<HistoryContentKey>,
    disable_history_storage: bool,
}

impl ContentStore for HistoryStorage {
    type Key = HistoryContentKey;

    fn get(&self, key: &HistoryContentKey) -> Result<Option<RawContentValue>, ContentStoreError> {
        self.store.lookup_content_value(&key.content_id().into())
    }

    fn put<V: AsRef<[u8]>>(
        &mut self,
        key: HistoryContentKey,
        value: V,
    ) -> Result<Vec<(HistoryContentKey, RawContentValue)>, ContentStoreError> {
        self.store
            .insert(&key, RawContentValue::copy_from_slice(value.as_ref()))
    }

    fn is_key_within_radius_and_unavailable(
        &self,
        key: &HistoryContentKey,
    ) -> Result<ShouldWeStoreContent, ContentStoreError> {
        let content_id = ContentId::from(key.content_id());
        // temporarily disable storing all history network
        if self.disable_history_storage {
            return Ok(ShouldWeStoreContent::NotWithinRadius);
        }
        if self.store.distance_to_content_id(&content_id) > self.store.radius() {
            Ok(ShouldWeStoreContent::NotWithinRadius)
        } else if self.store.has_content(&content_id)? {
            Ok(ShouldWeStoreContent::AlreadyStored)
        } else {
            Ok(ShouldWeStoreContent::Store)
        }
    }

    fn radius(&self) -> Distance {
        self.store.radius()
    }
}

impl HistoryStorage {
    pub fn new(
        config: PortalStorageConfig,
        disable_history_storage: bool,
    ) -> Result<Self, ContentStoreError> {
        maybe_migrate(&config)?;
        let sql_connection_pool = config.sql_connection_pool.clone();
        let config =
            IdIndexedV1StoreConfig::new(ContentType::HistoryEternal, Subnetwork::History, config);
        Ok(Self {
            store: create_store(ContentType::HistoryEternal, config, sql_connection_pool)?,
            disable_history_storage,
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
    ) -> Result<PaginateLocalContentInfo<HistoryContentKey>, ContentStoreError> {
        let paginate_result = self.store.paginate(offset, limit)?;
        Ok(PaginateLocalContentInfo {
            content_keys: paginate_result.content_keys,
            total_entries: paginate_result.entry_count,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub mod test {
    use ethportal_api::{types::content_key::history::BlockHeaderByHashKey, HistoryContentKey};
    use quickcheck::{QuickCheck, TestResult};
    use rand::RngCore;
    use serial_test::serial;
    use trin_storage::test_utils::create_test_portal_storage_config_with_capacity;

    use super::*;

    const CAPACITY_MB: u32 = 2;

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_store() {
        fn test_store_random_bytes() -> TestResult {
            let (temp_dir, storage_config) =
                create_test_portal_storage_config_with_capacity(CAPACITY_MB).unwrap();
            let mut storage = HistoryStorage::new(storage_config, false).unwrap();
            let content_key = HistoryContentKey::random().unwrap();
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
        let (temp_dir, storage_config) =
            create_test_portal_storage_config_with_capacity(CAPACITY_MB).unwrap();
        let mut storage = HistoryStorage::new(storage_config, false)?;
        let content_key = HistoryContentKey::BlockHeaderByHash(BlockHeaderByHashKey::default());
        let value: Vec<u8> = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".into();
        storage.put(content_key.clone(), &value)?;

        let result = storage.get(&content_key).unwrap().unwrap();

        assert_eq!(result, value);

        drop(storage);
        temp_dir.close()?;
        Ok(())
    }
}
