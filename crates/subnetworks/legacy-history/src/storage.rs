use ethportal_api::{
    types::{
        distance::{Distance, XorMetric},
        network::Subnetwork,
        portal::PaginateLocalContentInfo,
    },
    LegacyHistoryContentKey, OverlayContentKey, RawContentValue,
};
use trin_storage::{
    error::ContentStoreError,
    versioned::{create_store, ContentType, IdIndexedV1Store, IdIndexedV1StoreConfig},
    ContentId, ContentStore, PortalStorageConfig, ShouldWeStoreContent,
};

/// Storage layer for the legacy history network. Encapsulates legacy history network specific data
/// and logic.
#[derive(Debug)]
pub struct LegacyHistoryStorage {
    store: IdIndexedV1Store<LegacyHistoryContentKey, XorMetric>,
}

impl ContentStore for LegacyHistoryStorage {
    type Key = LegacyHistoryContentKey;

    fn get(
        &self,
        key: &LegacyHistoryContentKey,
    ) -> Result<Option<RawContentValue>, ContentStoreError> {
        self.store.lookup_content_value(&key.content_id().into())
    }

    fn put<V: AsRef<[u8]>>(
        &mut self,
        key: LegacyHistoryContentKey,
        value: V,
    ) -> Result<Vec<(LegacyHistoryContentKey, RawContentValue)>, ContentStoreError> {
        self.store
            .insert(&key, RawContentValue::copy_from_slice(value.as_ref()))
    }

    fn should_we_store(
        &self,
        key: &LegacyHistoryContentKey,
    ) -> Result<ShouldWeStoreContent, ContentStoreError> {
        let content_id = ContentId::from(key.content_id());
        if key.affected_by_radius()
            && self.store.distance_to_content_id(&content_id) > self.store.radius()
        {
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

impl LegacyHistoryStorage {
    pub fn new(config: PortalStorageConfig) -> Result<Self, ContentStoreError> {
        let sql_connection_pool = config.sql_connection_pool.clone();
        let config = IdIndexedV1StoreConfig::new(
            ContentType::LegacyHistoryEternal,
            Subnetwork::LegacyHistory,
            config,
        );
        Ok(Self {
            store: create_store(
                ContentType::LegacyHistoryEternal,
                config,
                sql_connection_pool,
            )?,
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
    ) -> Result<PaginateLocalContentInfo<LegacyHistoryContentKey>, ContentStoreError> {
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
    use ethportal_api::{
        types::content_key::legacy_history::BlockHeaderByHashKey, LegacyHistoryContentKey,
    };
    use quickcheck::{QuickCheck, TestResult};
    use rand::{rng, RngCore};
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
            let mut storage = LegacyHistoryStorage::new(storage_config).unwrap();
            let content_key = LegacyHistoryContentKey::random().unwrap();
            let mut value = [0u8; 32];
            rng().fill_bytes(&mut value);
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
        let mut storage = LegacyHistoryStorage::new(storage_config)?;
        let content_key =
            LegacyHistoryContentKey::BlockHeaderByHash(BlockHeaderByHashKey::default());
        let value: Vec<u8> = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".into();
        storage.put(content_key.clone(), &value)?;

        let result = storage.get(&content_key).unwrap().unwrap();

        assert_eq!(result, value);

        drop(storage);
        temp_dir.close()?;
        Ok(())
    }
}
