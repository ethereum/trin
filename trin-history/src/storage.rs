use discv5::enr::NodeId;
use ethportal_api::{
    types::{distance::Distance, history::PaginateLocalContentInfo, portal_wire::ProtocolId},
    utils::bytes::hex_encode,
    HistoryContentKey, OverlayContentKey,
};
use sqlx::{query, sqlite::SqliteRow, Row, SqlitePool};
use std::path::PathBuf;
use tracing::debug;
use trin_metrics::storage::StorageMetricsReporter;
use trin_storage::{
    error::ContentStoreError,
    sql::{
        CONTENT_KEY_LOOKUP_QUERY_HISTORY, CONTENT_SIZE_LOOKUP_QUERY_HISTORY,
        CONTENT_VALUE_LOOKUP_QUERY_HISTORY, DELETE_QUERY_HISTORY, INSERT_QUERY_HISTORY,
        PAGINATE_QUERY_HISTORY, TOTAL_DATA_SIZE_QUERY_HISTORY, TOTAL_ENTRY_COUNT_QUERY_HISTORY,
        XOR_FIND_FARTHEST_QUERY_HISTORY,
    },
    utils::get_total_size_of_directory_in_bytes,
    ContentId, ContentStore, DistanceFunction, EntryCount, PortalStorageConfig,
    ShouldWeStoreContent, BYTES_IN_MB_U64,
};

// The length of content_id and content_key
const CONTENT_ID_AND_KEY_LENGTH: usize = 64;

/// Storage layer for the history network. Encapsulates history network specific data and logic.
#[derive(Debug)]
pub struct HistoryStorage {
    node_id: NodeId,
    node_data_dir: PathBuf,
    storage_capacity_in_bytes: u64,
    storage_occupied_in_bytes: u64,
    radius: Distance,
    sql_connection_pool: SqlitePool,
    distance_fn: DistanceFunction,
    metrics: StorageMetricsReporter,
}

impl ContentStore for HistoryStorage {
    async fn get<K: OverlayContentKey>(
        &self,
        key: &K,
    ) -> Result<Option<Vec<u8>>, ContentStoreError> {
        let content_id = key.content_id();
        self.lookup_content_value(content_id).await.map_err(|err| {
            ContentStoreError::Database(format!("Error looking up content value: {err:?}"))
        })
    }

    async fn put<K: OverlayContentKey>(
        &mut self,
        key: K,
        value: Vec<u8>,
    ) -> Result<(), ContentStoreError> {
        self.store(&key, &value).await
    }

    async fn is_key_within_radius_and_unavailable<K: OverlayContentKey>(
        &self,
        key: &K,
    ) -> Result<ShouldWeStoreContent, ContentStoreError> {
        let distance = self.distance_to_content_id(&key.content_id());
        if distance > self.radius {
            return Ok(ShouldWeStoreContent::NotWithinRadius);
        }

        let key = key.content_id();
        let is_key_available = self
            .lookup_content_key(key)
            .await
            .map_err(|err| {
                ContentStoreError::Database(format!("Error looking up content key: {err:?}"))
            })?
            .is_some();
        if is_key_available {
            return Ok(ShouldWeStoreContent::AlreadyStored);
        }
        Ok(ShouldWeStoreContent::Store)
    }

    fn radius(&self) -> Distance {
        self.radius
    }
}

impl HistoryStorage {
    /// Public constructor for building a `HistoryStorage` object.
    /// Checks whether a populated database already exists vs a fresh instance.
    pub async fn new(
        config: PortalStorageConfig,
        protocol: ProtocolId,
    ) -> Result<Self, ContentStoreError> {
        let mut storage = Self {
            node_id: config.node_id,
            node_data_dir: config.node_data_dir,
            storage_capacity_in_bytes: config.storage_capacity_mb * BYTES_IN_MB_U64,
            radius: Distance::MAX,
            sql_connection_pool: config.sql_connection_pool,
            distance_fn: config.distance_fn,
            metrics: StorageMetricsReporter::new(protocol),
            storage_occupied_in_bytes: 0,
        };

        // Set the metrics to the default radius, to start
        storage.metrics.report_radius(storage.radius);

        // Set the network content storage used at start
        storage.storage_occupied_in_bytes = storage
            .get_total_storage_usage_in_bytes_from_network()
            .await?;

        // Check whether we already have data, and use it to set radius
        match storage.total_entry_count().await? {
            0 => {
                // Default radius is left in place, unless user selected 0mb capacity
                if storage.storage_capacity_in_bytes == 0 {
                    storage.set_radius(Distance::ZERO);
                }
            }
            // Only prunes data when at capacity. (eg. user changed it via mb flag)
            entry_count => {
                storage.metrics.report_entry_count(entry_count);

                let _ = storage.prune_db().await?;
            }
        }

        // Report current storage capacity.
        storage
            .metrics
            .report_storage_capacity_bytes(storage.storage_capacity_in_bytes as f64);

        // Report current total storage usage.
        let total_storage_usage = storage.get_total_storage_usage_in_bytes_on_disk()?;
        storage
            .metrics
            .report_total_storage_usage_bytes(total_storage_usage as f64);

        Ok(storage)
    }

    /// Sets the radius of the store to `radius`.
    fn set_radius(&mut self, radius: Distance) {
        self.radius = radius;
        self.metrics.report_radius(radius);
    }

    /// Returns a paginated list of all available content keys from local storage (from any
    /// subnetwork) according to the provided offset and limit.
    pub async fn paginate(
        &self,
        offset: u64,
        limit: u64,
    ) -> Result<PaginateLocalContentInfo, ContentStoreError> {
        let content_keys = query(PAGINATE_QUERY_HISTORY)
            .bind(limit as i64)
            .bind(offset as i64)
            .map(|row: SqliteRow| {
                let row: Vec<u8> = row.get(0);
                row
            })
            .fetch_all(&self.sql_connection_pool)
            .await?;

        let content_keys: Result<Vec<HistoryContentKey>, ContentStoreError> = content_keys
            .into_iter()
            .map(|bytes| HistoryContentKey::try_from(bytes).map_err(ContentStoreError::ContentKey))
            .collect();

        Ok(PaginateLocalContentInfo {
            content_keys: content_keys?,
            total_entries: self.total_entry_count().await?,
        })
    }

    async fn total_entry_count(&self) -> Result<u64, ContentStoreError> {
        let timer = self.metrics.start_process_timer("total_entry_count");
        let result = query(TOTAL_ENTRY_COUNT_QUERY_HISTORY)
            .map(|row: SqliteRow| EntryCount(row.get(0)))
            .fetch_one(&self.sql_connection_pool)
            .await?;
        self.metrics.stop_process_timer(timer);
        Ok(result.0 as u64)
    }

    /// Method for storing a given value for a given content-key.
    async fn store(
        &mut self,
        key: &impl OverlayContentKey,
        value: &Vec<u8>,
    ) -> Result<(), ContentStoreError> {
        let store_timer = self.metrics.start_process_timer("store");
        let content_id = key.content_id();
        let distance_to_content_id = self.distance_to_content_id(&content_id);

        if distance_to_content_id > self.radius {
            // Return Err if content is outside radius
            debug!("Not storing: {:02X?}", key.clone().into());
            return Err(ContentStoreError::InsufficientRadius {
                radius: self.radius,
                distance: distance_to_content_id,
            });
        }

        // Store the data in db
        let content_key: Vec<u8> = key.clone().into();
        let value_size = value.len();
        match self.db_insert(&content_id, &content_key, value).await {
            Ok(result) => {
                // Insertion successful, increase total network storage count
                if result == 1 {
                    // adding 32 bytes for content_id and 32 for content_key
                    self.storage_occupied_in_bytes +=
                        (value_size + CONTENT_ID_AND_KEY_LENGTH) as u64;
                    self.metrics
                        .report_content_data_storage_bytes(self.storage_occupied_in_bytes as f64);
                    self.metrics.increase_entry_count();
                }
            }
            Err(err) => {
                debug!("Error writing content ID {content_id:?} to db: {err:?}");
                return Err(err);
            }
        }
        self.metrics.stop_process_timer(store_timer);
        self.prune_db().await?;
        let total_bytes_on_disk = self.get_total_storage_usage_in_bytes_on_disk()?;
        self.metrics
            .report_total_storage_usage_bytes(total_bytes_on_disk as f64);

        Ok(())
    }

    /// Internal method for pruning any data that falls outside of the radius of the store.
    /// Resets the data radius if it prunes any data. Does nothing if the store is empty.
    /// Returns the number of items removed during pruning
    async fn prune_db(&mut self) -> Result<usize, ContentStoreError> {
        let timer = self.metrics.start_process_timer("prune_db");
        let mut farthest_content_id: Option<[u8; 32]> = self.find_farthest_content_id().await?;
        let mut num_removed_items = 0;
        // Delete furthest data until our data usage is less than capacity.
        while self.capacity_reached() {
            // If the database were empty, then `capacity_reached()` would be false, because the
            // amount of content (zero) would not be greater than capacity.
            let id_to_remove =
                farthest_content_id.expect("Capacity reached, but no farthest id found!");
            // Test if removing the item would put us under capacity
            let bytes_to_remove = self.get_content_size(&id_to_remove).await?;
            if self.storage_occupied_in_bytes - bytes_to_remove < self.storage_capacity_in_bytes {
                // If so, we're done pruning
                debug!(
                    "Removing item would drop us below capacity. We target slight overfilling. {}",
                    hex_encode(id_to_remove)
                );
                self.set_radius(self.distance_to_content_id(&id_to_remove));
                break;
            }
            debug!(
                "Capacity reached, deleting farthest: {}",
                hex_encode(id_to_remove)
            );
            if let Err(err) = self.db_remove(&id_to_remove).await {
                debug!("Error removing content ID {id_to_remove:?} from db: {err:?}");
            } else {
                // Eviction successful, decrease total network storage count
                self.storage_occupied_in_bytes -= bytes_to_remove;
                self.metrics
                    .report_content_data_storage_bytes(self.storage_occupied_in_bytes as f64);
                num_removed_items += 1;
            }
            // Calculate new farthest_content_id and reset radius
            match self.find_farthest_content_id().await? {
                None => {
                    // We get here if the entire db has been pruned,
                    // eg. user selected 0mb capacity for storage
                    self.set_radius(Distance::ZERO);
                }
                Some(farthest) => {
                    debug!("Found new farthest: {}", hex_encode(farthest));
                    self.set_radius(self.distance_to_content_id(&farthest));
                    farthest_content_id = Some(farthest);
                }
            }
        }
        self.metrics.stop_process_timer(timer);
        Ok(num_removed_items)
    }

    /// Internal method for getting the size of a content item in bytes.
    /// Returns the size of the content item in bytes.
    /// Raises an error if there is a problem accessing the database.
    async fn get_content_size(&self, id: &[u8; 32]) -> Result<u64, ContentStoreError> {
        let timer = self.metrics.start_process_timer("get_content_size");
        let result = query(CONTENT_SIZE_LOOKUP_QUERY_HISTORY)
            .bind(id.as_slice())
            .map(|row: SqliteRow| {
                let num_bytes: i64 = row.get(0);
                num_bytes
            })
            .fetch_optional(&self.sql_connection_pool)
            .await?;
        let byte_size = match result {
            Some(data_size) => data_size,
            None => {
                // Build error message with hex encoded content id
                let err = format!("Unable to determine size of item {}", hex_encode(id));
                return Err(ContentStoreError::Database(err));
            }
        };
        self.metrics.stop_process_timer(timer);
        Ok(byte_size as u64)
    }

    /// Internal method for looking up a content key by its content id
    async fn lookup_content_key(&self, id: [u8; 32]) -> anyhow::Result<Option<Vec<u8>>> {
        let timer = self.metrics.start_process_timer("lookup_content_key");
        let result = query(CONTENT_KEY_LOOKUP_QUERY_HISTORY)
            .bind(id.as_slice())
            .map(|row: SqliteRow| {
                let row: Vec<u8> = row.get(0);
                row
            })
            .fetch_optional(&self.sql_connection_pool)
            .await?;
        let key = match result {
            Some(bytes) => match HistoryContentKey::try_from(bytes) {
                Ok(key) => Ok(Some(key.into())),
                Err(err) => Err(ContentStoreError::ContentKey(err)),
            },
            None => Ok(None),
        };
        self.metrics.stop_process_timer(timer);
        Ok(key?)
    }

    /// Internal method for looking up a content value by its content id
    async fn lookup_content_value(&self, id: [u8; 32]) -> anyhow::Result<Option<Vec<u8>>> {
        let timer = self.metrics.start_process_timer("lookup_content_value");
        let result = query(CONTENT_VALUE_LOOKUP_QUERY_HISTORY)
            .bind(id.as_slice())
            .map(|row: SqliteRow| {
                let bytes: Vec<u8> = row.get(0);
                bytes
            })
            .fetch_optional(&self.sql_connection_pool)
            .await?;
        self.metrics.stop_process_timer(timer);
        Ok(result)
    }

    /// Public method for retrieving the node's current radius.
    pub fn radius(&self) -> Distance {
        self.radius
    }

    /// Internal Method for determining how much actual disk space is being used to store this
    /// node's Portal Network data. Intended for analysis purposes. PortalStorage's capacity
    /// decision-making is not based off of this method.
    fn get_total_storage_usage_in_bytes_on_disk(&self) -> Result<u64, ContentStoreError> {
        let timer = self
            .metrics
            .start_process_timer("get_total_storage_usage_in_bytes_on_disk");
        let storage_usage = get_total_size_of_directory_in_bytes(&self.node_data_dir)?;
        self.metrics.stop_process_timer(timer);
        Ok(storage_usage)
    }

    /// Internal method for inserting data into the db.
    async fn db_insert(
        &self,
        content_id: &[u8; 32],
        content_key: &Vec<u8>,
        value: &Vec<u8>,
    ) -> Result<u64, ContentStoreError> {
        let timer = self.metrics.start_process_timer("db_insert");
        let result = query(INSERT_QUERY_HISTORY)
            .bind(content_id.as_slice())
            .bind(content_key)
            .bind(value)
            .bind(self.distance_to_content_id(content_id).big_endian_u32())
            .bind((CONTENT_ID_AND_KEY_LENGTH + value.len()) as i64)
            .execute(&self.sql_connection_pool)
            .await?
            .rows_affected();
        self.metrics.stop_process_timer(timer);
        Ok(result)
    }

    /// Internal method for removing a given content-id from the db.
    async fn db_remove(&self, content_id: &[u8; 32]) -> Result<(), ContentStoreError> {
        let timer = self.metrics.start_process_timer("db_remove");
        query(DELETE_QUERY_HISTORY)
            .bind(content_id.as_slice())
            .execute(&self.sql_connection_pool)
            .await?;
        self.metrics.stop_process_timer(timer);
        self.metrics.decrease_entry_count();
        Ok(())
    }

    /// Internal method for determining whether the node is over-capacity.
    fn capacity_reached(&self) -> bool {
        self.storage_occupied_in_bytes > self.storage_capacity_in_bytes
    }

    /// Internal method for measuring the total amount of requestable data that the node is storing.
    async fn get_total_storage_usage_in_bytes_from_network(
        &self,
    ) -> Result<u64, ContentStoreError> {
        let timer = self
            .metrics
            .start_process_timer("get_total_storage_usage_in_bytes_from_network");
        let result = query(TOTAL_DATA_SIZE_QUERY_HISTORY)
            .map(|row: SqliteRow| {
                let num_bytes: f32 = row.get(0);
                num_bytes
            })
            .fetch_optional(&self.sql_connection_pool)
            .await?;
        let sum = match result {
            Some(total) => total,
            None => {
                let err = "Unable to compute sum over content item sizes".to_string();
                return Err(ContentStoreError::Database(err));
            }
        };

        self.metrics.report_content_data_storage_bytes(sum as f64);
        self.metrics.stop_process_timer(timer);
        Ok(sum as u64)
    }

    /// Internal method for finding the piece of stored data that has the farthest content id from
    /// our node id, according to xor distance. Used to determine which data to drop when at a
    /// capacity.
    async fn find_farthest_content_id(&self) -> Result<Option<[u8; 32]>, ContentStoreError> {
        let timer = self.metrics.start_process_timer("find_farthest_content_id");
        let result = match self.distance_fn {
            DistanceFunction::Xor => {
                query(XOR_FIND_FARTHEST_QUERY_HISTORY)
                    .map(|row: SqliteRow| {
                        let content_id: ContentId = row.get(0);
                        content_id.to_fixed_bytes()
                    })
                    .fetch_optional(&self.sql_connection_pool)
                    .await?
            }
        };

        self.metrics.stop_process_timer(timer);
        Ok(result)
    }

    /// Method that returns the distance between our node ID and a given content ID.
    fn distance_to_content_id(&self, content_id: &[u8; 32]) -> Distance {
        self.distance_fn.distance(&self.node_id, content_id)
    }

    /// Get a summary of the current state of storage
    pub fn get_summary_info(&self) -> String {
        self.metrics.get_summary()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub mod test {
    use super::*;
    use discv5::enr::{CombinedKey, Enr as Discv5Enr};
    use ethportal_api::{
        types::{distance::Distance, portal_wire::ProtocolId},
        BlockHeaderKey, HistoryContentKey, IdentityContentKey,
    };
    use portalnet::utils::db::{configure_node_data_dir, setup_temp_dir};
    use rand::RngCore;
    use serial_test::serial;

    const CAPACITY_MB: u64 = 2;

    fn get_active_node_id(temp_dir: PathBuf) -> NodeId {
        let (_, mut pk) = configure_node_data_dir(temp_dir, None).unwrap();
        let pk = CombinedKey::secp256k1_from_bytes(pk.0.as_mut_slice()).unwrap();
        Discv5Enr::empty(&pk).unwrap().node_id()
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_new() -> Result<(), ContentStoreError> {
        let temp_dir = setup_temp_dir().unwrap();
        let node_id = get_active_node_id(temp_dir.path().to_path_buf());

        let storage_config =
            PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id)
                .await
                .unwrap();
        let storage = HistoryStorage::new(storage_config, ProtocolId::History).await?;

        // Assert that configs match the storage object's fields
        assert_eq!(storage.node_id, node_id);
        assert_eq!(
            storage.storage_capacity_in_bytes,
            CAPACITY_MB * BYTES_IN_MB_U64
        );
        assert_eq!(storage.radius, Distance::MAX);

        std::mem::drop(storage);
        temp_dir.close()?;
        Ok(())
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_store() -> anyhow::Result<()> {
        for _ in 0..=10 {
            let temp_dir = setup_temp_dir().unwrap();
            let node_id = get_active_node_id(temp_dir.path().to_path_buf());
            let storage_config =
                PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id)
                    .await
                    .unwrap();
            let mut storage = HistoryStorage::new(storage_config, ProtocolId::History)
                .await
                .unwrap();
            let content_key = IdentityContentKey::random();
            let mut value = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut value);
            storage.store(&content_key, &value.to_vec()).await.unwrap();

            std::mem::drop(storage);
            temp_dir.close().unwrap();
        }
        Ok(())
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_get_data() -> Result<(), ContentStoreError> {
        let temp_dir = setup_temp_dir().unwrap();
        let node_id = get_active_node_id(temp_dir.path().to_path_buf());
        let storage_config =
            PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id)
                .await
                .unwrap();
        let mut storage = HistoryStorage::new(storage_config, ProtocolId::History).await?;
        let content_key = HistoryContentKey::BlockHeaderWithProof(BlockHeaderKey::default());
        let value: Vec<u8> = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".into();
        storage.store(&content_key, &value).await?;

        let result = storage.get(&content_key).await.unwrap().unwrap();

        assert_eq!(result, value);

        drop(storage);
        temp_dir.close()?;
        Ok(())
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_get_total_storage() -> Result<(), ContentStoreError> {
        let temp_dir = setup_temp_dir().unwrap();
        let node_id = get_active_node_id(temp_dir.path().to_path_buf());
        let storage_config =
            PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id)
                .await
                .unwrap();
        let mut storage = HistoryStorage::new(storage_config, ProtocolId::History).await?;

        let content_key = IdentityContentKey::random();
        let value: Vec<u8> = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".into();
        storage.store(&content_key, &value).await?;

        let bytes = storage
            .get_total_storage_usage_in_bytes_from_network()
            .await?;

        assert_eq!(96, bytes);

        std::mem::drop(storage);
        temp_dir.close()?;
        Ok(())
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_restarting_storage_with_decreased_capacity() -> Result<(), ContentStoreError> {
        let temp_dir = setup_temp_dir().unwrap();
        let node_id = get_active_node_id(temp_dir.path().to_path_buf());
        let storage_config =
            PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id)
                .await
                .unwrap();
        let mut storage = HistoryStorage::new(storage_config, ProtocolId::History).await?;

        for _ in 0..50 {
            let content_key = IdentityContentKey::random();
            let value: Vec<u8> = vec![0; 32000];
            storage.store(&content_key, &value).await?;
            assert_eq!(
                storage.storage_occupied_in_bytes,
                storage
                    .get_total_storage_usage_in_bytes_from_network()
                    .await?
            );
        }

        let bytes = storage
            .get_total_storage_usage_in_bytes_from_network()
            .await?;
        assert_eq!(1603200, bytes); // (32kb + CONTENT_ID_AND_KEY_LENGTH) * 50
        assert_eq!(storage.radius, Distance::MAX);
        std::mem::drop(storage);

        // test with 1mb capacity
        let new_storage_config =
            PortalStorageConfig::new(1, temp_dir.path().to_path_buf(), node_id)
                .await
                .unwrap();
        let new_storage = HistoryStorage::new(new_storage_config, ProtocolId::History).await?;

        // test that previously set value has been pruned
        let bytes = new_storage
            .get_total_storage_usage_in_bytes_from_network()
            .await?;
        assert_eq!(1026048, bytes);
        assert_eq!(32, new_storage.total_entry_count().await.unwrap());
        assert_eq!(new_storage.storage_capacity_in_bytes, BYTES_IN_MB_U64);
        // test that radius has decreased now that we're at capacity
        assert!(new_storage.radius < Distance::MAX);
        std::mem::drop(new_storage);

        // test with 0mb capacity
        let new_storage_config =
            PortalStorageConfig::new(0, temp_dir.path().to_path_buf(), node_id)
                .await
                .unwrap();
        let new_storage = HistoryStorage::new(new_storage_config, ProtocolId::History).await?;

        // test that previously set value has been pruned
        assert_eq!(new_storage.storage_capacity_in_bytes, 0);
        assert_eq!(new_storage.radius, Distance::ZERO);
        std::mem::drop(new_storage);

        temp_dir.close()?;
        Ok(())
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_inserting_same_key() -> Result<(), ContentStoreError> {
        let temp_dir = setup_temp_dir().unwrap();
        let node_id = get_active_node_id(temp_dir.path().to_path_buf());
        let storage_config =
            PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id)
                .await
                .unwrap();
        let mut storage = HistoryStorage::new(storage_config, ProtocolId::History).await?;

        let content_key = IdentityContentKey::random();
        let value: Vec<u8> = vec![0; 32000];
        storage.store(&content_key, &value).await?;
        assert_eq!(
            storage.storage_occupied_in_bytes,
            storage
                .get_total_storage_usage_in_bytes_from_network()
                .await?
        );

        storage.store(&content_key, &value).await?;
        assert_eq!(
            storage.storage_occupied_in_bytes,
            storage
                .get_total_storage_usage_in_bytes_from_network()
                .await?
        );

        std::mem::drop(storage);
        Ok(())
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_evict_content_keys_and_check_we_track_the_right_number(
    ) -> Result<(), ContentStoreError> {
        let temp_dir = setup_temp_dir().unwrap();
        let node_id = get_active_node_id(temp_dir.path().to_path_buf());
        let storage_config =
            PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id)
                .await
                .unwrap();
        let mut storage = HistoryStorage::new(storage_config, ProtocolId::History).await?;

        for _ in 0..50 {
            let content_key = IdentityContentKey::random();
            let value: Vec<u8> = vec![0; 32000];
            storage.store(&content_key, &value).await?;
            assert_eq!(
                storage.storage_occupied_in_bytes,
                storage
                    .get_total_storage_usage_in_bytes_from_network()
                    .await?
            );
        }

        storage.storage_capacity_in_bytes = 1;
        let num_removed_items = storage.prune_db().await.unwrap();
        assert_eq!(49, num_removed_items);

        let bytes = storage
            .get_total_storage_usage_in_bytes_from_network()
            .await?;
        assert_eq!(32064, storage.storage_occupied_in_bytes);
        assert_eq!(32064, bytes);

        storage.storage_capacity_in_bytes = 0;
        let num_removed_items = storage.prune_db().await.unwrap();
        assert_eq!(1, num_removed_items);

        let bytes = storage
            .get_total_storage_usage_in_bytes_from_network()
            .await?;
        assert_eq!(0, storage.storage_occupied_in_bytes);
        assert_eq!(0, bytes);
        std::mem::drop(storage);
        temp_dir.close()?;
        Ok(())
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_restarting_full_storage_with_same_capacity() -> Result<(), ContentStoreError> {
        // test a node that gets full and then restarts with the same capacity
        let temp_dir = setup_temp_dir().unwrap();
        let node_id = get_active_node_id(temp_dir.path().to_path_buf());

        let min_capacity = 1;
        // Use a tiny storage capacity, to fill up as quickly as possible
        let storage_config =
            PortalStorageConfig::new(min_capacity, temp_dir.path().to_path_buf(), node_id)
                .await
                .unwrap();
        let mut storage = HistoryStorage::new(storage_config.clone(), ProtocolId::History).await?;

        // Fill up the storage.
        for _ in 0..32 {
            let content_key = IdentityContentKey::random();
            let value: Vec<u8> = vec![0; 32000];
            storage.store(&content_key, &value).await?;
            assert_eq!(
                storage.storage_occupied_in_bytes,
                storage
                    .get_total_storage_usage_in_bytes_from_network()
                    .await?
            );
            // Speed up the test by ending the loop as soon as possible
            if storage.capacity_reached() {
                break;
            }
        }
        assert!(storage.capacity_reached());

        // Save the number of items, to compare with the restarted storage
        let total_entry_count = storage.total_entry_count().await.unwrap();
        // Save the radius, to compare with the restarted storage
        let radius = storage.radius;
        assert!(radius < Distance::MAX);

        // Restart a filled-up store with the same capacity
        let new_storage = HistoryStorage::new(storage_config, ProtocolId::History).await?;

        // The restarted store should have the same number of items
        assert_eq!(
            total_entry_count,
            new_storage.total_entry_count().await.unwrap()
        );
        // The restarted store should be full
        assert!(new_storage.capacity_reached());
        // The restarted store should have the same radius as the original
        assert_eq!(radius, new_storage.radius);

        drop(storage);
        drop(new_storage);
        temp_dir.close()?;
        Ok(())
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_restarting_storage_with_increased_capacity() -> Result<(), ContentStoreError> {
        let temp_dir = setup_temp_dir().unwrap();
        let (node_data_dir, mut private_key) =
            configure_node_data_dir(temp_dir.path().to_path_buf(), None).unwrap();
        let private_key = CombinedKey::secp256k1_from_bytes(private_key.0.as_mut_slice()).unwrap();
        let node_id = Discv5Enr::empty(&private_key).unwrap().node_id();
        let storage_config = PortalStorageConfig::new(CAPACITY_MB, node_data_dir.clone(), node_id)
            .await
            .unwrap();
        let mut storage = HistoryStorage::new(storage_config, ProtocolId::History).await?;

        for _ in 0..50 {
            let content_key = IdentityContentKey::random();
            let value: Vec<u8> = vec![0; 32000];
            storage.store(&content_key, &value).await?;
        }

        let bytes = storage
            .get_total_storage_usage_in_bytes_from_network()
            .await?;
        assert_eq!(1603200, bytes); // (32kb + CONTENT_ID_AND_KEY_LENGTH) * 50
        assert_eq!(storage.radius, Distance::MAX);
        // Save the number of items, to compare with the restarted storage
        let total_entry_count = storage.total_entry_count().await.unwrap();
        std::mem::drop(storage);

        // test with increased capacity
        let new_storage_config = PortalStorageConfig::new(2 * CAPACITY_MB, node_data_dir, node_id)
            .await
            .unwrap();
        let new_storage = HistoryStorage::new(new_storage_config, ProtocolId::History).await?;

        // test that previously set value has not been pruned
        let bytes = new_storage
            .get_total_storage_usage_in_bytes_from_network()
            .await?;
        assert_eq!(1603200, bytes);
        assert_eq!(
            new_storage.total_entry_count().await.unwrap(),
            total_entry_count
        );
        assert_eq!(
            new_storage.storage_capacity_in_bytes,
            2 * CAPACITY_MB * BYTES_IN_MB_U64
        );
        // test that radius is at max
        assert_eq!(new_storage.radius, Distance::MAX);
        std::mem::drop(new_storage);

        temp_dir.close()?;
        Ok(())
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_new_storage_with_zero_capacity() -> Result<(), ContentStoreError> {
        let temp_dir = setup_temp_dir().unwrap();
        let node_id = get_active_node_id(temp_dir.path().to_path_buf());
        let storage_config = PortalStorageConfig::new(0, temp_dir.path().to_path_buf(), node_id)
            .await
            .unwrap();
        let mut storage = HistoryStorage::new(storage_config, ProtocolId::History).await?;

        let content_key = IdentityContentKey::random();
        let value: Vec<u8> = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".into();
        assert!(storage.store(&content_key, &value).await.is_err());

        let bytes = storage
            .get_total_storage_usage_in_bytes_from_network()
            .await?;

        assert_eq!(0, bytes);
        assert_eq!(storage.radius, Distance::ZERO);

        std::mem::drop(storage);
        temp_dir.close()?;
        Ok(())
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_find_farthest_empty_db() -> Result<(), ContentStoreError> {
        let temp_dir = setup_temp_dir().unwrap();
        let node_id = get_active_node_id(temp_dir.path().to_path_buf());
        let storage_config =
            PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id)
                .await
                .unwrap();
        let storage = HistoryStorage::new(storage_config, ProtocolId::History).await?;
        let result = storage.find_farthest_content_id().await?;
        assert!(result.is_none());

        std::mem::drop(storage);
        temp_dir.close()?;
        Ok(())
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_find_farthest() -> anyhow::Result<()> {
        for _ in 0..=10 {
            let x = IdentityContentKey::random();
            let y = IdentityContentKey::random();
            let temp_dir = setup_temp_dir().unwrap();
            let node_id = get_active_node_id(temp_dir.path().to_path_buf());

            let val = vec![0x00, 0x01, 0x02, 0x03, 0x04];
            let storage_config =
                PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id)
                    .await
                    .unwrap();
            let mut storage = HistoryStorage::new(storage_config, ProtocolId::History)
                .await
                .unwrap();
            storage.store(&x, &val).await.unwrap();
            storage.store(&y, &val).await.unwrap();

            let expected_farthest = if storage.distance_to_content_id(&x.content_id())
                > storage.distance_to_content_id(&y.content_id())
            {
                x.content_id()
            } else {
                y.content_id()
            };

            let farthest = storage.find_farthest_content_id().await;

            std::mem::drop(storage);
            temp_dir.close().unwrap();

            assert_eq!(farthest.unwrap().unwrap(), expected_farthest);
        }
        Ok(())
    }
}
