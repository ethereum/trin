use discv5::enr::NodeId;
use ethportal_api::{
    types::{distance::Distance, history::PaginateLocalContentInfo, portal_wire::ProtocolId},
    utils::bytes::hex_encode,
    HistoryContentKey, OverlayContentKey,
};
use r2d2::Pool;
use r2d2_sqlite::{rusqlite, SqliteConnectionManager};
use rusqlite::params;
use std::path::PathBuf;
use tracing::debug;
use trin_metrics::storage::StorageMetricsReporter;

use crate::{
    error::ContentStoreError,
    utils::get_total_size_of_directory_in_bytes,
    versioned::{ContentType, StoreVersion, VersionedContentStore},
    ContentId, DataSize, DistanceFunction, EntryCount, PortalStorageConfig, BYTES_IN_MB_U64,
};

use super::sql::{
    CONTENT_KEY_LOOKUP_QUERY_HISTORY, CONTENT_SIZE_LOOKUP_QUERY_HISTORY,
    CONTENT_VALUE_LOOKUP_QUERY_HISTORY, CREATE_QUERY_DB_HISTORY, DELETE_QUERY_HISTORY,
    INSERT_QUERY_HISTORY, PAGINATE_QUERY_HISTORY, TOTAL_DATA_SIZE_QUERY_HISTORY,
    TOTAL_ENTRY_COUNT_QUERY_HISTORY, XOR_FIND_FARTHEST_QUERY_HISTORY,
};

// The length of content_id and content_key
const CONTENT_ID_AND_KEY_LENGTH: usize = 64;

/// Storage layer for the history network. Encapsulates history network specific data and logic.
#[derive(Debug)]
pub struct LegacyHistoryStore {
    node_id: NodeId,
    node_data_dir: PathBuf,
    storage_capacity_in_bytes: u64,
    storage_occupied_in_bytes: u64,
    radius: Distance,
    sql_connection_pool: Pool<SqliteConnectionManager>,
    distance_fn: DistanceFunction,
    metrics: StorageMetricsReporter,
}

impl VersionedContentStore for LegacyHistoryStore {
    type Config = PortalStorageConfig;

    fn version() -> StoreVersion {
        StoreVersion::LegacyHistory
    }

    fn migrate_from(
        _content_type: &ContentType,
        old_version: StoreVersion,
        _config: &Self::Config,
    ) -> Result<(), ContentStoreError> {
        Err(ContentStoreError::UnsupportedStoreMigration {
            old_version,
            new_version: Self::version(),
        })
    }

    fn create(content_type: ContentType, config: Self::Config) -> Result<Self, ContentStoreError> {
        if content_type != ContentType::History {
            panic!("LegacyHistoryStore only supports History content type");
        }
        Self::new(config)
    }
}

impl LegacyHistoryStore {
    /// Public constructor for building a `HistoryStorage` object.
    /// Checks whether a populated database already exists vs a fresh instance.
    pub fn new(config: PortalStorageConfig) -> Result<Self, ContentStoreError> {
        let conn = config.sql_connection_pool.get()?;
        conn.execute_batch(CREATE_QUERY_DB_HISTORY)?;

        let mut storage = Self {
            node_id: config.node_id,
            node_data_dir: config.node_data_dir,
            storage_capacity_in_bytes: config.storage_capacity_mb * BYTES_IN_MB_U64,
            radius: Distance::MAX,
            sql_connection_pool: config.sql_connection_pool,
            distance_fn: config.distance_fn,
            metrics: StorageMetricsReporter::new(ProtocolId::History),
            storage_occupied_in_bytes: 0,
        };

        // Set the metrics to the default radius, to start
        storage.metrics.report_radius(storage.radius);

        // Set the network content storage used at start
        storage.storage_occupied_in_bytes =
            storage.get_total_storage_usage_in_bytes_from_network()?;

        // Check whether we already have data, and use it to set radius
        match storage.total_entry_count()? {
            0 => {
                // Default radius is left in place, unless user selected 0mb capacity
                if storage.storage_capacity_in_bytes == 0 {
                    storage.set_radius(Distance::ZERO);
                }
            }
            // Only prunes data when at capacity. (eg. user changed it via mb flag)
            entry_count => {
                storage.metrics.report_entry_count(entry_count);

                let _ = storage.prune_db()?;
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
    pub fn paginate(
        &self,
        offset: &u64,
        limit: &u64,
    ) -> Result<PaginateLocalContentInfo, ContentStoreError> {
        let conn = self.sql_connection_pool.get()?;
        let mut query = conn.prepare(PAGINATE_QUERY_HISTORY)?;

        let content_keys: Result<Vec<HistoryContentKey>, ContentStoreError> = query
            .query_map([limit, offset], |row| {
                let row: Vec<u8> = row.get(0)?;
                Ok(row)
            })?
            .map(|row| HistoryContentKey::try_from(row?).map_err(ContentStoreError::ContentKey))
            .collect();
        Ok(PaginateLocalContentInfo {
            content_keys: content_keys?,
            total_entries: self.total_entry_count()?,
        })
    }

    fn total_entry_count(&self) -> Result<u64, ContentStoreError> {
        let timer = self.metrics.start_process_timer("total_entry_count");
        let conn = self.sql_connection_pool.get()?;
        let mut query = conn.prepare(TOTAL_ENTRY_COUNT_QUERY_HISTORY)?;
        let result: Result<Vec<EntryCount>, rusqlite::Error> = query
            .query_map([], |row| Ok(EntryCount(row.get(0)?)))?
            .collect();
        self.metrics.stop_process_timer(timer);
        match result?.first() {
            Some(val) => Ok(val.0),
            None => Err(ContentStoreError::InvalidData {
                message: "Invalid total entries count returned from sql query.".to_string(),
            }),
        }
    }

    /// Method for storing a given value for a given content-key.
    pub fn store(
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
        match self.db_insert(&content_id, &content_key, value) {
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
        self.prune_db()?;
        let total_bytes_on_disk = self.get_total_storage_usage_in_bytes_on_disk()?;
        self.metrics
            .report_total_storage_usage_bytes(total_bytes_on_disk as f64);

        Ok(())
    }

    /// Internal method for pruning any data that falls outside of the radius of the store.
    /// Resets the data radius if it prunes any data. Does nothing if the store is empty.
    /// Returns the number of items removed during pruning
    fn prune_db(&mut self) -> Result<usize, ContentStoreError> {
        let timer = self.metrics.start_process_timer("prune_db");
        let mut farthest_content_id: Option<[u8; 32]> = self.find_farthest_content_id()?;
        let mut num_removed_items = 0;
        // Delete furthest data until our data usage is less than capacity.
        while self.capacity_reached() {
            // If the database were empty, then `capacity_reached()` would be false, because the
            // amount of content (zero) would not be greater than capacity.
            let id_to_remove =
                farthest_content_id.expect("Capacity reached, but no farthest id found!");
            // Test if removing the item would put us under capacity
            let bytes_to_remove = self.get_content_size(&id_to_remove)?;
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
            if let Err(err) = self.db_remove(&id_to_remove) {
                debug!("Error removing content ID {id_to_remove:?} from db: {err:?}");
            } else {
                // Eviction successful, decrease total network storage count
                self.storage_occupied_in_bytes -= bytes_to_remove;
                self.metrics
                    .report_content_data_storage_bytes(self.storage_occupied_in_bytes as f64);
                num_removed_items += 1;
            }
            // Calculate new farthest_content_id and reset radius
            match self.find_farthest_content_id()? {
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
    fn get_content_size(&self, id: &[u8; 32]) -> Result<u64, ContentStoreError> {
        let timer = self.metrics.start_process_timer("get_content_size");
        let conn = self.sql_connection_pool.get()?;
        let mut query = conn.prepare(CONTENT_SIZE_LOOKUP_QUERY_HISTORY)?;
        let id_vec = id.to_vec();
        let result = query.query_map([id_vec], |row| {
            Ok(DataSize {
                num_bytes: row.get(0)?,
            })
        });
        let byte_size = match result?.next() {
            Some(data_size) => data_size,
            None => {
                // Build error message with hex encoded content id
                let err = format!("Unable to determine size of item {}", hex_encode(id));
                return Err(ContentStoreError::Database(err));
            }
        }?
        .num_bytes;
        self.metrics.stop_process_timer(timer);
        Ok(byte_size as u64)
    }

    /// Internal method for looking up a content key by its content id
    pub fn lookup_content_key(&self, id: [u8; 32]) -> anyhow::Result<Option<Vec<u8>>> {
        let timer = self.metrics.start_process_timer("lookup_content_key");
        let conn = self.sql_connection_pool.get()?;
        let mut query = conn.prepare(CONTENT_KEY_LOOKUP_QUERY_HISTORY)?;
        let result: Result<Vec<HistoryContentKey>, ContentStoreError> = query
            .query_map([id.as_slice()], |row| {
                let row: Vec<u8> = row.get(0)?;
                Ok(row)
            })?
            .map(|row| HistoryContentKey::try_from(row?).map_err(ContentStoreError::ContentKey))
            .collect();
        self.metrics.stop_process_timer(timer);
        match result?.first() {
            Some(val) => Ok(Some(val.into())),
            None => Ok(None),
        }
    }

    /// Internal method for looking up a content value by its content id
    pub fn lookup_content_value(&self, id: [u8; 32]) -> anyhow::Result<Option<Vec<u8>>> {
        let timer = self.metrics.start_process_timer("lookup_content_value");
        let conn = self.sql_connection_pool.get()?;
        let mut query = conn.prepare(CONTENT_VALUE_LOOKUP_QUERY_HISTORY)?;
        let result: Result<Vec<Vec<u8>>, ContentStoreError> = query
            .query_map([id.as_slice()], |row| {
                let row: Vec<u8> = row.get(0)?;
                Ok(row)
            })?
            .map(|row| row.map_err(ContentStoreError::Rusqlite))
            .collect();

        let result = result?.first().map(|val| val.to_vec());
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
    fn db_insert(
        &self,
        content_id: &[u8; 32],
        content_key: &Vec<u8>,
        value: &Vec<u8>,
    ) -> Result<usize, ContentStoreError> {
        let timer = self.metrics.start_process_timer("db_insert");
        let conn = self.sql_connection_pool.get()?;
        let result = conn.execute(
            INSERT_QUERY_HISTORY,
            params![
                content_id.as_slice(),
                content_key,
                value,
                self.distance_to_content_id(content_id).big_endian_u32(),
                CONTENT_ID_AND_KEY_LENGTH + value.len()
            ],
        )?;
        self.metrics.stop_process_timer(timer);
        Ok(result)
    }

    /// Internal method for removing a given content-id from the db.
    fn db_remove(&self, content_id: &[u8; 32]) -> Result<(), ContentStoreError> {
        let timer = self.metrics.start_process_timer("db_remove");
        self.sql_connection_pool
            .get()?
            .execute(DELETE_QUERY_HISTORY, [content_id.as_slice()])?;
        self.metrics.stop_process_timer(timer);
        self.metrics.decrease_entry_count();
        Ok(())
    }

    /// Internal method for determining whether the node is over-capacity.
    fn capacity_reached(&self) -> bool {
        self.storage_occupied_in_bytes > self.storage_capacity_in_bytes
    }

    /// Internal method for measuring the total amount of requestable data that the node is storing.
    fn get_total_storage_usage_in_bytes_from_network(&self) -> Result<u64, ContentStoreError> {
        let timer = self
            .metrics
            .start_process_timer("get_total_storage_usage_in_bytes_from_network");
        let conn = self.sql_connection_pool.get()?;
        let mut query = conn.prepare(TOTAL_DATA_SIZE_QUERY_HISTORY)?;

        let result = query.query_map([], |row| {
            Ok(DataSize {
                num_bytes: row.get(0)?,
            })
        });

        let sum = match result?.next() {
            Some(total) => total,
            None => {
                let err = "Unable to compute sum over content item sizes".to_string();
                return Err(ContentStoreError::Database(err));
            }
        }?
        .num_bytes;

        self.metrics.report_content_data_storage_bytes(sum);
        self.metrics.stop_process_timer(timer);
        Ok(sum as u64)
    }

    /// Internal method for finding the piece of stored data that has the farthest content id from
    /// our node id, according to xor distance. Used to determine which data to drop when at a
    /// capacity.
    fn find_farthest_content_id(&self) -> Result<Option<[u8; 32]>, ContentStoreError> {
        let timer = self.metrics.start_process_timer("find_farthest_content_id");
        let result = match self.distance_fn {
            DistanceFunction::Xor => {
                let conn = self.sql_connection_pool.get()?;
                let mut query = conn.prepare(XOR_FIND_FARTHEST_QUERY_HISTORY)?;

                let mut result = query.query_map([], |row| {
                    let content_id: ContentId = row.get(0)?;
                    Ok(content_id)
                })?;

                let result = match result.next() {
                    Some(row) => row,
                    None => {
                        return Ok(None);
                    }
                };
                result?.to_fixed_bytes()
            }
        };

        self.metrics.stop_process_timer(timer);
        Ok(Some(result))
    }

    /// Method that returns the distance between our node ID and a given content ID.
    pub fn distance_to_content_id(&self, content_id: &[u8; 32]) -> Distance {
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
    use ethportal_api::{
        types::distance::Distance, BlockHeaderKey, HistoryContentKey, IdentityContentKey,
    };
    use quickcheck::{quickcheck, QuickCheck, TestResult};
    use rand::RngCore;
    use tempfile::TempDir;

    const CAPACITY_MB: u64 = 2;

    #[test]
    fn test_new() -> Result<(), ContentStoreError> {
        let temp_dir = TempDir::new()?;
        let node_id = NodeId::random();

        let storage_config =
            PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id).unwrap();
        let storage = LegacyHistoryStore::new(storage_config)?;

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

    #[test]
    fn test_store() {
        fn test_store_random_bytes() -> TestResult {
            let temp_dir = TempDir::new().unwrap();
            let node_id = NodeId::random();
            let storage_config =
                PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id)
                    .unwrap();
            let mut storage = LegacyHistoryStore::new(storage_config).unwrap();
            let content_key = IdentityContentKey::random();
            let mut value = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut value);
            storage.store(&content_key, &value.to_vec()).unwrap();

            std::mem::drop(storage);
            temp_dir.close().unwrap();

            TestResult::passed()
        }
        QuickCheck::new()
            .tests(10)
            .quickcheck(test_store_random_bytes as fn() -> _);
    }

    #[test]
    fn test_get_data() -> Result<(), ContentStoreError> {
        let temp_dir = TempDir::new()?;
        let node_id = NodeId::random();
        let storage_config =
            PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id).unwrap();
        let mut storage = LegacyHistoryStore::new(storage_config)?;
        let content_key = HistoryContentKey::BlockHeaderWithProof(BlockHeaderKey::default());
        let value: Vec<u8> = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".into();
        storage.store(&content_key, &value)?;

        let result = storage
            .lookup_content_value(content_key.content_id())
            .unwrap()
            .unwrap();

        assert_eq!(result, value);

        drop(storage);
        temp_dir.close()?;
        Ok(())
    }

    #[test]
    fn test_get_total_storage() -> Result<(), ContentStoreError> {
        let temp_dir = TempDir::new()?;
        let node_id = NodeId::random();
        let storage_config =
            PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id).unwrap();
        let mut storage = LegacyHistoryStore::new(storage_config)?;

        let content_key = IdentityContentKey::random();
        let value: Vec<u8> = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".into();
        storage.store(&content_key, &value)?;

        let bytes = storage.get_total_storage_usage_in_bytes_from_network()?;

        assert_eq!(96, bytes);

        std::mem::drop(storage);
        temp_dir.close()?;
        Ok(())
    }

    #[test]
    fn test_restarting_storage_with_decreased_capacity() -> Result<(), ContentStoreError> {
        let temp_dir = TempDir::new()?;
        let node_id = NodeId::random();
        let storage_config =
            PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id).unwrap();
        let mut storage = LegacyHistoryStore::new(storage_config)?;

        for _ in 0..50 {
            let content_key = IdentityContentKey::random();
            let value: Vec<u8> = vec![0; 32000];
            storage.store(&content_key, &value)?;
            assert_eq!(
                storage.storage_occupied_in_bytes,
                storage.get_total_storage_usage_in_bytes_from_network()?
            );
        }

        let bytes = storage.get_total_storage_usage_in_bytes_from_network()?;
        assert_eq!(1603200, bytes); // (32kb + CONTENT_ID_AND_KEY_LENGTH) * 50
        assert_eq!(storage.radius, Distance::MAX);
        std::mem::drop(storage);

        // test with 1mb capacity
        let new_storage_config =
            PortalStorageConfig::new(1, temp_dir.path().to_path_buf(), node_id).unwrap();
        let new_storage = LegacyHistoryStore::new(new_storage_config)?;

        // test that previously set value has been pruned
        let bytes = new_storage.get_total_storage_usage_in_bytes_from_network()?;
        assert_eq!(1026048, bytes);
        assert_eq!(32, new_storage.total_entry_count().unwrap());
        assert_eq!(new_storage.storage_capacity_in_bytes, BYTES_IN_MB_U64);
        // test that radius has decreased now that we're at capacity
        assert!(new_storage.radius < Distance::MAX);
        std::mem::drop(new_storage);

        // test with 0mb capacity
        let new_storage_config =
            PortalStorageConfig::new(0, temp_dir.path().to_path_buf(), node_id).unwrap();
        let new_storage = LegacyHistoryStore::new(new_storage_config)?;

        // test that previously set value has been pruned
        assert_eq!(new_storage.storage_capacity_in_bytes, 0);
        assert_eq!(new_storage.radius, Distance::ZERO);
        std::mem::drop(new_storage);

        temp_dir.close()?;
        Ok(())
    }

    #[test]
    fn test_inserting_same_key() -> Result<(), ContentStoreError> {
        let temp_dir = TempDir::new()?;
        let node_id = NodeId::random();
        let storage_config =
            PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id).unwrap();
        let mut storage = LegacyHistoryStore::new(storage_config)?;

        let content_key = IdentityContentKey::random();
        let value: Vec<u8> = vec![0; 32000];
        storage.store(&content_key, &value)?;
        assert_eq!(
            storage.storage_occupied_in_bytes,
            storage.get_total_storage_usage_in_bytes_from_network()?
        );

        storage.store(&content_key, &value)?;
        assert_eq!(
            storage.storage_occupied_in_bytes,
            storage.get_total_storage_usage_in_bytes_from_network()?
        );

        std::mem::drop(storage);
        Ok(())
    }

    #[test]
    fn test_evict_content_keys_and_check_we_track_the_right_number() -> Result<(), ContentStoreError>
    {
        let temp_dir = TempDir::new()?;
        let node_id = NodeId::random();
        let storage_config =
            PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id).unwrap();
        let mut storage = LegacyHistoryStore::new(storage_config)?;

        for _ in 0..50 {
            let content_key = IdentityContentKey::random();
            let value: Vec<u8> = vec![0; 32000];
            storage.store(&content_key, &value)?;
            assert_eq!(
                storage.storage_occupied_in_bytes,
                storage.get_total_storage_usage_in_bytes_from_network()?
            );
        }

        storage.storage_capacity_in_bytes = 1;
        let num_removed_items = storage.prune_db().unwrap();
        assert_eq!(49, num_removed_items);

        let bytes = storage.get_total_storage_usage_in_bytes_from_network()?;
        assert_eq!(32064, storage.storage_occupied_in_bytes);
        assert_eq!(32064, bytes);

        storage.storage_capacity_in_bytes = 0;
        let num_removed_items = storage.prune_db().unwrap();
        assert_eq!(1, num_removed_items);

        let bytes = storage.get_total_storage_usage_in_bytes_from_network()?;
        assert_eq!(0, storage.storage_occupied_in_bytes);
        assert_eq!(0, bytes);
        std::mem::drop(storage);
        temp_dir.close()?;
        Ok(())
    }

    #[test]
    fn test_restarting_full_storage_with_same_capacity() -> Result<(), ContentStoreError> {
        // test a node that gets full and then restarts with the same capacity
        let temp_dir = TempDir::new()?;
        let node_id = NodeId::random();

        let min_capacity = 1;
        // Use a tiny storage capacity, to fill up as quickly as possible
        let storage_config =
            PortalStorageConfig::new(min_capacity, temp_dir.path().to_path_buf(), node_id).unwrap();
        let mut storage = LegacyHistoryStore::new(storage_config.clone())?;

        // Fill up the storage.
        for _ in 0..32 {
            let content_key = IdentityContentKey::random();
            let value: Vec<u8> = vec![0; 32000];
            storage.store(&content_key, &value)?;
            assert_eq!(
                storage.storage_occupied_in_bytes,
                storage.get_total_storage_usage_in_bytes_from_network()?
            );
            // Speed up the test by ending the loop as soon as possible
            if storage.capacity_reached() {
                break;
            }
        }
        assert!(storage.capacity_reached());

        // Save the number of items, to compare with the restarted storage
        let total_entry_count = storage.total_entry_count().unwrap();
        // Save the radius, to compare with the restarted storage
        let radius = storage.radius;
        assert!(radius < Distance::MAX);

        // Restart a filled-up store with the same capacity
        let new_storage = LegacyHistoryStore::new(storage_config)?;

        // The restarted store should have the same number of items
        assert_eq!(total_entry_count, new_storage.total_entry_count().unwrap());
        // The restarted store should be full
        assert!(new_storage.capacity_reached());
        // The restarted store should have the same radius as the original
        assert_eq!(radius, new_storage.radius);

        drop(storage);
        drop(new_storage);
        temp_dir.close()?;
        Ok(())
    }

    #[test]
    fn test_restarting_storage_with_increased_capacity() -> Result<(), ContentStoreError> {
        let temp_dir = TempDir::new()?;
        let node_id = NodeId::random();

        let storage_config =
            PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id).unwrap();
        let mut storage = LegacyHistoryStore::new(storage_config)?;

        for _ in 0..50 {
            let content_key = IdentityContentKey::random();
            let value: Vec<u8> = vec![0; 32000];
            storage.store(&content_key, &value)?;
        }

        let bytes = storage.get_total_storage_usage_in_bytes_from_network()?;
        assert_eq!(1603200, bytes); // (32kb + CONTENT_ID_AND_KEY_LENGTH) * 50
        assert_eq!(storage.radius, Distance::MAX);
        // Save the number of items, to compare with the restarted storage
        let total_entry_count = storage.total_entry_count().unwrap();
        std::mem::drop(storage);

        // test with increased capacity
        let new_storage_config =
            PortalStorageConfig::new(2 * CAPACITY_MB, temp_dir.path().to_path_buf(), node_id)
                .unwrap();
        let new_storage = LegacyHistoryStore::new(new_storage_config)?;

        // test that previously set value has not been pruned
        let bytes = new_storage.get_total_storage_usage_in_bytes_from_network()?;
        assert_eq!(1603200, bytes);
        assert_eq!(new_storage.total_entry_count().unwrap(), total_entry_count);
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

    #[test]
    fn test_new_storage_with_zero_capacity() -> Result<(), ContentStoreError> {
        let temp_dir = TempDir::new()?;
        let node_id = NodeId::random();
        let storage_config =
            PortalStorageConfig::new(0, temp_dir.path().to_path_buf(), node_id).unwrap();
        let mut storage = LegacyHistoryStore::new(storage_config)?;

        let content_key = IdentityContentKey::random();
        let value: Vec<u8> = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".into();
        assert!(storage.store(&content_key, &value).is_err());

        let bytes = storage.get_total_storage_usage_in_bytes_from_network()?;

        assert_eq!(0, bytes);
        assert_eq!(storage.radius, Distance::ZERO);

        std::mem::drop(storage);
        temp_dir.close()?;
        Ok(())
    }

    #[test]
    fn test_find_farthest_empty_db() -> Result<(), ContentStoreError> {
        let temp_dir = TempDir::new()?;
        let node_id = NodeId::random();
        let storage_config =
            PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id).unwrap();
        let storage = LegacyHistoryStore::new(storage_config)?;

        let result = storage.find_farthest_content_id()?;
        assert!(result.is_none());

        std::mem::drop(storage);
        temp_dir.close()?;
        Ok(())
    }

    #[test]
    fn test_find_farthest() {
        fn prop(x: IdentityContentKey, y: IdentityContentKey) -> TestResult {
            let temp_dir = TempDir::new().unwrap();
            let node_id = NodeId::random();

            let val = vec![0x00, 0x01, 0x02, 0x03, 0x04];
            let storage_config =
                PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id)
                    .unwrap();
            let mut storage = LegacyHistoryStore::new(storage_config).unwrap();
            storage.store(&x, &val).unwrap();
            storage.store(&y, &val).unwrap();

            let expected_farthest = if storage.distance_to_content_id(&x.content_id())
                > storage.distance_to_content_id(&y.content_id())
            {
                x.content_id()
            } else {
                y.content_id()
            };

            let farthest = storage.find_farthest_content_id();

            std::mem::drop(storage);
            temp_dir.close().unwrap();

            TestResult::from_bool(farthest.unwrap().unwrap() == expected_farthest)
        }

        quickcheck(prop as fn(IdentityContentKey, IdentityContentKey) -> TestResult);
    }
}
