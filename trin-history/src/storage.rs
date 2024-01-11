use discv5::enr::NodeId;
use ethportal_api::{
    types::{
        distance::{Distance, Metric, XorMetric},
        history::PaginateLocalContentInfo,
        portal_wire::ProtocolId,
    },
    utils::bytes::{hex_decode, hex_encode},
    HistoryContentKey, OverlayContentKey,
};
use r2d2::Pool;
use r2d2_sqlite::{rusqlite, SqliteConnectionManager};
use std::path::PathBuf;
use tracing::debug;
use trin_metrics::{portalnet::PORTALNET_METRICS, storage::StorageMetricsReporter};
use trin_storage::{
    error::ContentStoreError,
    sql::{
        CONTENT_KEY_LOOKUP_QUERY_DB, CONTENT_SIZE_LOOKUP_QUERY_DB, DELETE_QUERY_DB,
        PAGINATE_QUERY_DB, TOTAL_DATA_SIZE_QUERY_DB, TOTAL_ENTRY_COUNT_QUERY_NETWORK,
        XOR_FIND_FARTHEST_QUERY_NETWORK,
    },
    utils::{
        byte_vector_to_u32, get_total_size_of_directory_in_bytes, insert_value,
        lookup_content_value,
    },
    ContentId, ContentStore, DataSize, DistanceFunction, EntryCount, PortalStorageConfig,
    ShouldWeStoreContent, BYTES_IN_MB_U64,
};

/// Storage layer for the history network. Encapsulates history network specific data and logic.
#[derive(Debug)]
pub struct HistoryStorage {
    node_id: NodeId,
    node_data_dir: PathBuf,
    storage_capacity_in_bytes: u64,
    radius: Distance,
    sql_connection_pool: Pool<SqliteConnectionManager>,
    distance_fn: DistanceFunction,
    metrics: StorageMetricsReporter,
    network: ProtocolId,
}

impl ContentStore for HistoryStorage {
    fn get<K: OverlayContentKey>(&self, key: &K) -> Result<Option<Vec<u8>>, ContentStoreError> {
        let content_id = key.content_id();
        self.lookup_content_value(content_id).map_err(|err| {
            ContentStoreError::Database(format!("Error looking up content value: {err:?}"))
        })
    }

    fn put<K: OverlayContentKey, V: AsRef<[u8]>>(
        &mut self,
        key: K,
        value: V,
    ) -> Result<(), ContentStoreError> {
        self.store(&key, &value.as_ref().to_vec())
    }

    fn is_key_within_radius_and_unavailable<K: OverlayContentKey>(
        &self,
        key: &K,
    ) -> Result<ShouldWeStoreContent, ContentStoreError> {
        let distance = self.distance_to_key(key);
        if distance > self.radius {
            return Ok(ShouldWeStoreContent::NotWithinRadius);
        }

        let key = key.content_id();
        let is_key_available = self
            .lookup_content_key(key)
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
    pub fn new(
        config: PortalStorageConfig,
        protocol: ProtocolId,
    ) -> Result<Self, ContentStoreError> {
        // Initialize the instance
        let metrics = StorageMetricsReporter {
            storage_metrics: PORTALNET_METRICS.storage(),
            protocol: protocol.to_string(),
        };
        let mut storage = Self {
            node_id: config.node_id,
            node_data_dir: config.node_data_dir,
            storage_capacity_in_bytes: config.storage_capacity_mb * BYTES_IN_MB_U64,
            radius: Distance::MAX,
            sql_connection_pool: config.sql_connection_pool,
            distance_fn: config.distance_fn,
            metrics,
            network: protocol,
        };

        // Set the metrics to the default radius, to start
        storage.metrics.report_radius(storage.radius);

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

        // Report total storage used by network content.
        let network_content_storage_usage =
            storage.get_total_storage_usage_in_bytes_from_network()?;
        storage
            .metrics
            .report_content_data_storage_bytes(network_content_storage_usage as f64);

        Ok(storage)
    }

    /// Sets the radius of the store to `radius`.
    pub fn set_radius(&mut self, radius: Distance) {
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
        let mut query = conn.prepare(PAGINATE_QUERY_DB)?;

        let content_keys: Result<Vec<HistoryContentKey>, ContentStoreError> = query
            .query_map(
                &[
                    (":offset", offset.to_string().as_str()),
                    (":limit", limit.to_string().as_str()),
                ],
                |row| {
                    let row: String = row.get(0)?;
                    Ok(row)
                },
            )?
            .map(|row| {
                // value is stored without 0x prefix, so we must add it
                let bytes: Vec<u8> = hex_decode(&format!("0x{}", row?))
                    .map_err(ContentStoreError::ByteUtilsError)?;
                HistoryContentKey::try_from(bytes).map_err(ContentStoreError::ContentKey)
            })
            .collect();
        Ok(PaginateLocalContentInfo {
            content_keys: content_keys?,
            total_entries: self.total_entry_count()?,
        })
    }

    fn total_entry_count(&self) -> Result<u64, ContentStoreError> {
        let conn = self.sql_connection_pool.get()?;
        let mut query = conn.prepare(TOTAL_ENTRY_COUNT_QUERY_NETWORK)?;
        let result: Result<Vec<EntryCount>, rusqlite::Error> = query
            .query_map([u8::from(self.network)], |row| Ok(EntryCount(row.get(0)?)))?
            .collect();
        match result?.first() {
            Some(val) => Ok(val.0),
            None => Err(ContentStoreError::InvalidData {
                message: "Invalid total entries count returned from sql query.".to_string(),
            }),
        }
    }

    /// Returns the distance to `key` from the local `NodeId` according to the distance function.
    fn distance_to_key<K: OverlayContentKey>(&self, key: &K) -> Distance {
        match self.distance_fn {
            DistanceFunction::Xor => XorMetric::distance(&key.content_id(), &self.node_id.raw()),
        }
    }

    /// Method for storing a given value for a given content-key.
    fn store(
        &mut self,
        key: &impl OverlayContentKey,
        value: &Vec<u8>,
    ) -> Result<(), ContentStoreError> {
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
        // store content key w/o the 0x prefix
        let content_key = hex_encode(content_key).trim_start_matches("0x").to_string();
        if let Err(err) = self.db_insert(&content_id, &content_key, value) {
            debug!("Error writing content ID {content_id:?} to db: {err:?}");
            return Err(err);
        } else {
            self.metrics.increase_entry_count();
        }
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
        let mut farthest_content_id: Option<[u8; 32]> = self.find_farthest_content_id()?;
        let mut num_removed_items = 0;
        // Delete furthest data until our data usage is less than capacity.
        while self.capacity_reached()? {
            // If the database were empty, then `capacity_reached()` would be false, because the
            // amount of content (zero) would not be greater than capacity.
            let id_to_remove =
                farthest_content_id.expect("Capacity reached, but no farthest id found!");
            // Test if removing the item would put us under capacity
            if self.does_eviction_cause_under_capacity(&id_to_remove)? {
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
            if let Err(err) = self.evict(id_to_remove) {
                debug!("Error writing content ID {id_to_remove:?} to db: {err:?}",);
            } else {
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
        Ok(num_removed_items)
    }

    /// Internal method for testing if an eviction would cause the store to fall under capacity.
    /// Returns true if the store would fall under capacity, false otherwise.
    /// Raises an error if there is a problem accessing the database.
    fn does_eviction_cause_under_capacity(&self, id: &[u8; 32]) -> Result<bool, ContentStoreError> {
        let total_bytes_on_disk = self.get_total_storage_usage_in_bytes_from_network()?;
        // Get the size of the content we're about to remove
        let bytes_to_remove = self.get_content_size(id)?;
        Ok(total_bytes_on_disk - bytes_to_remove < self.storage_capacity_in_bytes)
    }

    /// Internal method for getting the size of a content item in bytes.
    /// Returns the size of the content item in bytes.
    /// Raises an error if there is a problem accessing the database.
    fn get_content_size(&self, id: &[u8; 32]) -> Result<u64, ContentStoreError> {
        let conn = self.sql_connection_pool.get()?;
        let mut query = conn.prepare(CONTENT_SIZE_LOOKUP_QUERY_DB)?;
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

        Ok(byte_size as u64)
    }

    /// Public method for evicting a certain content id.
    pub fn evict(&self, id: [u8; 32]) -> anyhow::Result<()> {
        self.db_remove(&id)?;
        self.metrics.decrease_entry_count();
        Ok(())
    }

    /// Public method for looking up a content key by its content id
    pub fn lookup_content_key(&self, id: [u8; 32]) -> anyhow::Result<Option<Vec<u8>>> {
        let conn = self.sql_connection_pool.get()?;
        let mut query = conn.prepare(CONTENT_KEY_LOOKUP_QUERY_DB)?;
        let id = id.to_vec();
        let result: Result<Vec<HistoryContentKey>, ContentStoreError> = query
            .query_map([id], |row| {
                let row: String = row.get(0)?;
                Ok(row)
            })?
            .map(|row| {
                // value is stored without 0x prefix, so we must add it
                let bytes: Vec<u8> = hex_decode(&format!("0x{}", row?))?;
                HistoryContentKey::try_from(bytes).map_err(ContentStoreError::ContentKey)
            })
            .collect();

        match result?.first() {
            Some(val) => Ok(Some(val.into())),
            None => Ok(None),
        }
    }

    /// Public method for looking up a content value by its content id
    pub fn lookup_content_value(&self, id: [u8; 32]) -> anyhow::Result<Option<Vec<u8>>> {
        let conn = self.sql_connection_pool.get()?;

        lookup_content_value(id, conn)?
    }

    /// Public method for retrieving the node's current radius.
    pub fn radius(&self) -> Distance {
        self.radius
    }

    /// Public method for determining how much actual disk space is being used to store this node's
    /// Portal Network data. Intended for analysis purposes. PortalStorage's capacity
    /// decision-making is not based off of this method.
    pub fn get_total_storage_usage_in_bytes_on_disk(&self) -> Result<u64, ContentStoreError> {
        let storage_usage = get_total_size_of_directory_in_bytes(&self.node_data_dir)?;
        Ok(storage_usage)
    }

    /// Internal method for inserting data into the db.
    fn db_insert(
        &self,
        content_id: &[u8; 32],
        content_key: &String,
        value: &Vec<u8>,
    ) -> Result<(), ContentStoreError> {
        let conn = self.sql_connection_pool.get()?;
        insert_value(conn, content_id, content_key, value, u8::from(self.network))
    }

    /// Internal method for removing a given content-id from the db.
    fn db_remove(&self, content_id: &[u8; 32]) -> Result<(), ContentStoreError> {
        self.sql_connection_pool
            .get()?
            .execute(DELETE_QUERY_DB, [content_id.to_vec()])?;
        Ok(())
    }

    /// Internal method for determining whether the node is over-capacity.
    fn capacity_reached(&self) -> Result<bool, ContentStoreError> {
        let storage_usage = self.get_total_storage_usage_in_bytes_from_network()?;
        Ok(storage_usage > self.storage_capacity_in_bytes)
    }

    /// Internal method for measuring the total amount of requestable data that the node is storing.
    fn get_total_storage_usage_in_bytes_from_network(&self) -> Result<u64, ContentStoreError> {
        let conn = self.sql_connection_pool.get()?;
        let mut query = conn.prepare(TOTAL_DATA_SIZE_QUERY_DB)?;

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

        Ok(sum as u64)
    }

    /// Internal method for finding the piece of stored data that has the farthest content id from
    /// our node id, according to xor distance. Used to determine which data to drop when at a
    /// capacity.
    fn find_farthest_content_id(&self) -> Result<Option<[u8; 32]>, ContentStoreError> {
        let result = match self.distance_fn {
            DistanceFunction::Xor => {
                let node_id_u32 = byte_vector_to_u32(self.node_id.raw().to_vec());

                let conn = self.sql_connection_pool.get()?;
                let mut query = conn.prepare(XOR_FIND_FARTHEST_QUERY_NETWORK)?;

                let mut result =
                    query.query_map([node_id_u32, u8::from(self.network).into()], |row| {
                        Ok(ContentId {
                            id_long: row.get(0)?,
                        })
                    })?;

                let result = match result.next() {
                    Some(row) => row,
                    None => {
                        return Ok(None);
                    }
                };
                let result = result?.id_long;
                let result_vec: [u8; 32] = match result.len() {
                    // If exact data size, safe to expect conversion.
                    32 => result.try_into().expect(
                        "Unexpectedly failed to convert 32 element vec to 32 element array.",
                    ),
                    // Received data of size other than 32 bytes.
                    length => {
                        let err = format!("content ID of length {length} != 32");
                        return Err(ContentStoreError::InvalidData { message: err });
                    }
                };
                result_vec
            }
        };

        Ok(Some(result))
    }

    /// Method that returns the distance between our node ID and a given content ID.
    pub fn distance_to_content_id(&self, content_id: &[u8; 32]) -> Distance {
        match self.distance_fn {
            DistanceFunction::Xor => XorMetric::distance(content_id, &self.node_id.raw()),
        }
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
    use quickcheck::{quickcheck, QuickCheck, TestResult};
    use rand::RngCore;
    use serial_test::serial;

    const CAPACITY_MB: u64 = 2;

    fn generate_random_content_key() -> IdentityContentKey {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        IdentityContentKey::new(key)
    }

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
            PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id).unwrap();
        let storage = HistoryStorage::new(storage_config, ProtocolId::History)?;

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
    async fn test_store() {
        fn test_store_random_bytes() -> TestResult {
            let temp_dir = setup_temp_dir().unwrap();
            let node_id = get_active_node_id(temp_dir.path().to_path_buf());
            let storage_config =
                PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id)
                    .unwrap();
            let mut storage = HistoryStorage::new(storage_config, ProtocolId::History).unwrap();
            let content_key = generate_random_content_key();
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

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_get_data() -> Result<(), ContentStoreError> {
        let temp_dir = setup_temp_dir().unwrap();
        let node_id = get_active_node_id(temp_dir.path().to_path_buf());
        let storage_config =
            PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id).unwrap();
        let mut storage = HistoryStorage::new(storage_config, ProtocolId::History)?;
        let content_key = HistoryContentKey::BlockHeaderWithProof(BlockHeaderKey::default());
        let value: Vec<u8> = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".into();
        storage.store(&content_key, &value)?;

        let result = storage.get(&content_key).unwrap().unwrap();

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
            PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id).unwrap();
        let mut storage = HistoryStorage::new(storage_config, ProtocolId::History)?;

        let content_key = generate_random_content_key();
        let value: Vec<u8> = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".into();
        storage.store(&content_key, &value)?;

        let bytes = storage.get_total_storage_usage_in_bytes_from_network()?;

        assert_eq!(32, bytes);

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
            PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id).unwrap();
        let mut storage = HistoryStorage::new(storage_config, ProtocolId::History)?;

        for _ in 0..50 {
            let content_key = generate_random_content_key();
            let value: Vec<u8> = vec![0; 32000];
            storage.store(&content_key, &value)?;
        }

        let bytes = storage.get_total_storage_usage_in_bytes_from_network()?;
        assert_eq!(1600000, bytes); // 32kb * 50
        assert_eq!(storage.radius, Distance::MAX);
        std::mem::drop(storage);

        // test with 1mb capacity
        let new_storage_config =
            PortalStorageConfig::new(1, temp_dir.path().to_path_buf(), node_id).unwrap();
        let new_storage = HistoryStorage::new(new_storage_config, ProtocolId::History)?;

        // test that previously set value has been pruned
        let bytes = new_storage.get_total_storage_usage_in_bytes_from_network()?;
        assert_eq!(1024000, bytes);
        assert_eq!(32, new_storage.total_entry_count().unwrap());
        assert_eq!(new_storage.storage_capacity_in_bytes, BYTES_IN_MB_U64);
        // test that radius has decreased now that we're at capacity
        assert!(new_storage.radius < Distance::MAX);
        std::mem::drop(new_storage);

        // test with 0mb capacity
        let new_storage_config =
            PortalStorageConfig::new(0, temp_dir.path().to_path_buf(), node_id).unwrap();
        let new_storage = HistoryStorage::new(new_storage_config, ProtocolId::History)?;

        // test that previously set value has been pruned
        assert_eq!(new_storage.storage_capacity_in_bytes, 0);
        assert_eq!(new_storage.radius, Distance::ZERO);
        std::mem::drop(new_storage);

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
            PortalStorageConfig::new(min_capacity, temp_dir.path().to_path_buf(), node_id).unwrap();
        let mut storage = HistoryStorage::new(storage_config.clone(), ProtocolId::History)?;

        // Fill up the storage.
        for _ in 0..32 {
            let content_key = generate_random_content_key();
            let value: Vec<u8> = vec![0; 32000];
            storage.store(&content_key, &value)?;
            // Speed up the test by ending the loop as soon as possible
            if storage.capacity_reached()? {
                break;
            }
        }
        assert!(storage.capacity_reached()?);

        // Save the number of items, to compare with the restarted storage
        let total_entry_count = storage.total_entry_count().unwrap();
        // Save the radius, to compare with the restarted storage
        let radius = storage.radius;
        assert!(radius < Distance::MAX);

        // Restart a filled-up store with the same capacity
        let new_storage = HistoryStorage::new(storage_config, ProtocolId::History)?;

        // The restarted store should have the same number of items
        assert_eq!(total_entry_count, new_storage.total_entry_count().unwrap());
        // The restarted store should be full
        assert!(new_storage.capacity_reached()?);
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
        let storage_config =
            PortalStorageConfig::new(CAPACITY_MB, node_data_dir.clone(), node_id).unwrap();
        let mut storage = HistoryStorage::new(storage_config, ProtocolId::History)?;

        for _ in 0..50 {
            let content_key = generate_random_content_key();
            let value: Vec<u8> = vec![0; 32000];
            storage.store(&content_key, &value)?;
        }

        let bytes = storage.get_total_storage_usage_in_bytes_from_network()?;
        assert_eq!(1600000, bytes); // 32kb * 50
        assert_eq!(storage.radius, Distance::MAX);
        // Save the number of items, to compare with the restarted storage
        let total_entry_count = storage.total_entry_count().unwrap();
        std::mem::drop(storage);

        // test with increased capacity
        let new_storage_config =
            PortalStorageConfig::new(2 * CAPACITY_MB, node_data_dir, node_id).unwrap();
        let new_storage = HistoryStorage::new(new_storage_config, ProtocolId::History)?;

        // test that previously set value has not been pruned
        let bytes = new_storage.get_total_storage_usage_in_bytes_from_network()?;
        assert_eq!(1600000, bytes);
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

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_new_storage_with_zero_capacity() -> Result<(), ContentStoreError> {
        let temp_dir = setup_temp_dir().unwrap();
        let node_id = get_active_node_id(temp_dir.path().to_path_buf());
        let storage_config =
            PortalStorageConfig::new(0, temp_dir.path().to_path_buf(), node_id).unwrap();
        let mut storage = HistoryStorage::new(storage_config, ProtocolId::History)?;

        let content_key = generate_random_content_key();
        let value: Vec<u8> = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".into();
        assert!(storage.store(&content_key, &value).is_err());

        let bytes = storage.get_total_storage_usage_in_bytes_from_network()?;

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
            PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id).unwrap();
        let storage = HistoryStorage::new(storage_config, ProtocolId::History)?;

        let result = storage.find_farthest_content_id()?;
        assert!(result.is_none());

        std::mem::drop(storage);
        temp_dir.close()?;
        Ok(())
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_find_farthest() {
        fn prop(x: IdentityContentKey, y: IdentityContentKey) -> TestResult {
            let temp_dir = setup_temp_dir().unwrap();
            let node_id = get_active_node_id(temp_dir.path().to_path_buf());

            let val = vec![0x00, 0x01, 0x02, 0x03, 0x04];
            let storage_config =
                PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id)
                    .unwrap();
            let mut storage = HistoryStorage::new(storage_config, ProtocolId::History).unwrap();
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
