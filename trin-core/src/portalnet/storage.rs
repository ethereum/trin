use std::path::{Path, PathBuf};
use std::{convert::TryInto, fs, sync::Arc};

use discv5::enr::NodeId;
use hex;
use log::{debug, error, info};
use lru::LruCache;
use parking_lot::RwLock;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rocksdb::{Options, DB};
use rusqlite::params;
use thiserror::Error;

use super::types::{
    content_key::OverlayContentKey,
    metric::{Distance, Metric, XorMetric},
};
use crate::utils::db::get_data_dir;

// Assuming large 15kB content values, 5k elements consume 75MB of data
const CACHE_NUM_ELEMENTS_MAX: usize = 5000;

// TODO: Replace enum with generic type parameter. This will require that we have a way to
// associate a "find farthest" query with the generic Metric.
#[derive(Copy, Clone)]
pub enum DistanceFunction {
    Xor,
}

/// Struct for configuring a PortalStorage instance.
#[derive(Clone)]
pub struct PortalStorageConfig {
    pub storage_capacity_kb: u64,
    pub node_id: NodeId,
    pub distance_function: DistanceFunction,
    pub db: Arc<rocksdb::DB>,
    pub sql_connection_pool: Pool<SqliteConnectionManager>,
}

/// Struct whose public methods abstract away Kademlia-based storage behavior.
pub struct PortalStorage {
    node_id: NodeId,
    storage_capacity_in_bytes: u64,
    // pub to allow for tests in trin-history/src/content_key.rs
    pub data_radius: Distance,
    farthest_content_id: Option<[u8; 32]>,
    db: Arc<rocksdb::DB>,
    cache: RwLock<LruCache<[u8; 32], Vec<u8>>>,
    sql_connection_pool: Pool<SqliteConnectionManager>,
    distance_function: DistanceFunction,
}

/// Error type returned in a Result by any failable public PortalStorage methods.
#[derive(Debug, Error)]
pub enum PortalStorageError {
    #[error("RocksDB Error")]
    RocksDB(#[from] rocksdb::Error),

    #[error("Sqlite Error")]
    Sqlite(#[from] rusqlite::Error),

    #[error("Sqlite Connection Pool Error")]
    SqliteConnectionPool(#[from] r2d2::Error),

    #[error("IO Error")]
    IOError(#[from] std::io::Error),

    #[error("Sum data size error: received None from SQLite")]
    SumError(),

    #[error("While {doing:?}, expected to receive data of size {expected:?} but found data of size {actual:?}")]
    DataSizeError {
        doing: String,
        expected: usize,
        actual: usize,
    },

    #[error("String error value returned from {function_name:?}: {error:?}")]
    StringError {
        function_name: String,
        error: std::ffi::OsString,
    },

    #[error("Content can not be stored since it falls outside our radius")]
    OutsideDistanceError,

    #[error("Unable to insert content id into meta db: {content_id:?}")]
    InsertError { content_id: Vec<u8> },

    #[error("Unable to remove content id from meta db: {content_id:?}")]
    RemoveError { content_id: Vec<u8> },
}

impl PortalStorage {
    /// Public constructor for building a PortalStorage object.
    /// Checks whether a populated database already exists vs a fresh instance.
    pub fn new(config: PortalStorageConfig) -> Result<Self, PortalStorageError> {
        // Initialize the instance
        let mut storage = Self {
            node_id: config.node_id,
            storage_capacity_in_bytes: config.storage_capacity_kb * 1000,
            data_radius: Distance::MAX,
            db: config.db,
            cache: RwLock::new(LruCache::new(CACHE_NUM_ELEMENTS_MAX)),
            farthest_content_id: None,
            sql_connection_pool: config.sql_connection_pool,
            distance_function: config.distance_function,
        };

        // Check whether we already have data, and if so
        // use it to set the farthest_key and data_radius fields
        match storage.find_farthest_content_id()? {
            Some(content_id) => {
                storage.farthest_content_id = Some(content_id.clone());
                if storage.capacity_reached()? {
                    storage.data_radius = storage.distance_to_content_id(&content_id);
                }
            }
            // No farthest key found, carry on with blank slate settings
            None => (),
        }

        Ok(storage)
    }

    /// Public method for determining whether a given content key should be stored by the node.
    /// Takes into account our data radius and whether we are already storing the data.
    pub fn should_store(&self, key: &impl OverlayContentKey) -> Result<bool, PortalStorageError> {
        let content_id = key.content_id();
        // Don't store if we already have the data
        match self.db.get_pinned(&content_id) {
            Ok(Some(_)) => return Ok(false),
            Err(e) => return Err(PortalStorageError::RocksDB(e)),
            _ => (),
        }

        // Don't store if it's outside our radius
        if self.data_radius < Distance::MAX {
            Ok(self.distance_to_content_id(&content_id) < self.data_radius)
        } else {
            Ok(true)
        }
    }

    /// Public method for storing a given value for a given content-key.
    pub fn store(
        &mut self,
        key: &impl OverlayContentKey,
        value: &Vec<u8>,
    ) -> Result<(), PortalStorageError> {
        match self.durable_store(key, value) {
            Ok(()) => Ok(()),
            Err(e) => {
                // When the data cannot be stored locally, save it to an LRU. This supports
                // a few use cases, like:
                // - offering all portal_historyStore content to peers, ignoring radius
                // - serving hotspots in network, outside of radius
                self.cache.write().put(key.content_id(), value.clone());
                Err(e)
            }
        }
    }

    fn durable_store(
        &mut self,
        key: &impl OverlayContentKey,
        value: &Vec<u8>,
    ) -> Result<(), PortalStorageError> {
        let content_id = key.content_id();
        let distance_to_content_id = self.distance_to_content_id(&content_id);

        // Check whether data is outside our radius.
        if distance_to_content_id > self.data_radius {
            debug!("Not storing: {:02X?}", key.clone().into());
            return Err(PortalStorageError::OutsideDistanceError);
        }

        // Store the data.
        self.db_insert(&content_id, value)?;
        // Revert rocks db action if there's an error with writing to metadata db
        if let Err(msg) = self.meta_db_insert(&content_id, &key.clone().into(), value) {
            debug!(
                "Error writing content ID {:?} to meta db. Reverting: {:?}",
                content_id, msg
            );
            self.db.delete(&content_id)?;
            return Err(PortalStorageError::InsertError {
                content_id: content_id.to_vec(),
            });
        }

        // Update the farthest key if this key is either 1.) the first key ever or 2.) farther than the current farthest.
        match self.farthest_content_id.as_ref() {
            None => {
                self.farthest_content_id = Some(content_id);
            }
            Some(farthest) => {
                // if self.distance_to_content_id(&content_id) > self.distance_to_content_id(&farthest)
                if distance_to_content_id > self.distance_to_content_id(&farthest) {
                    self.farthest_content_id = Some(content_id.clone());
                }
            }
        }

        // Delete furthest data until our data usage is less than capacity.
        while self.capacity_reached()? {
            // Unwrap because this was set in the block before this loop.
            let id_to_remove = self.farthest_content_id.clone().unwrap();

            debug!(
                "Capacity reached, deleting farthest: {}",
                hex::encode(&id_to_remove)
            );

            let deleted_value = self.db.get(&id_to_remove)?;
            self.db.delete(&id_to_remove)?;
            // Revert rocksdb action if there's an error with writing to metadata db
            if let Err(msg) = self.meta_db_remove(&id_to_remove) {
                debug!(
                    "Error writing content ID {:?} to meta db. Reverting: {:?}",
                    content_id, msg
                );
                if let Some(value) = deleted_value {
                    self.db_insert(&content_id, &value)?;
                }
                return Err(PortalStorageError::RemoveError {
                    content_id: content_id.to_vec(),
                });
            };

            match self.find_farthest_content_id()? {
                None => {
                    error!("Database is over-capacity, but could not find find entry to delete!");
                    self.farthest_content_id = None;
                    // stop attempting to delete to avoid infinite loop
                    break;
                }
                Some(farthest) => {
                    debug!("Found new farthest: {}", hex::encode(&farthest));
                    self.farthest_content_id = Some(farthest.clone());
                    self.data_radius = self.distance_to_content_id(&farthest);
                }
            }
        }

        Ok(())
    }

    /// Public method for retrieving the stored value for a given content-key.
    /// If no value exists for the given content-key, Result<None> is returned.
    pub fn get(&self, key: &impl OverlayContentKey) -> Result<Option<Vec<u8>>, PortalStorageError> {
        let content_id = key.content_id();
        let result = self.db.get(content_id);
        if let Ok(Some(val)) = result {
            Ok(Some(val))
        } else if let Some(cached) = self.cache.write().get(&content_id) {
            // When database doesn't return Some value, try to return cached value
            Ok(Some(cached.clone()))
        } else {
            Ok(result?)
        }
    }

    /// Public method for retrieving the node's current radius.
    pub fn radius(&self) -> Distance {
        self.data_radius
    }

    /// Public method for determining how much actual disk space is being used to store this node's Portal Network data.
    /// Intended for analysis purposes. PortalStorage's capacity decision-making is not based off of this method.
    pub fn get_total_storage_usage_in_bytes_on_disk(&self) -> Result<u64, PortalStorageError> {
        Ok(self.get_total_size_of_directory_in_bytes(get_data_dir(self.node_id))?)
    }

    /// Internal method for inserting data into the db.
    fn db_insert(&self, content_id: &[u8; 32], value: &Vec<u8>) -> Result<(), PortalStorageError> {
        self.db.put(&content_id, value)?;
        Ok(())
    }

    /// Internal method for inserting data into the meta db.
    fn meta_db_insert(
        &self,
        content_id: &[u8; 32],
        content_key: &Vec<u8>,
        value: &Vec<u8>,
    ) -> Result<(), PortalStorageError> {
        let content_id_as_u32: u32 = PortalStorage::byte_vector_to_u32(content_id.to_vec());
        let value_size = value.len();
        let content_key = hex::encode(content_key);
        match self.sql_connection_pool.get()?.execute(
            INSERT_QUERY,
            params![
                content_id.to_vec(),
                content_id_as_u32,
                content_key,
                value_size
            ],
        ) {
            Ok(_) => Ok(()),
            Err(e) => Err(PortalStorageError::Sqlite(e)),
        }
    }

    /// Internal method for removing a given content-id from the meta db.
    fn meta_db_remove(&self, content_id: &[u8; 32]) -> Result<(), PortalStorageError> {
        self.sql_connection_pool
            .get()?
            .execute(DELETE_QUERY, [content_id.to_vec()])?;
        Ok(())
    }

    /// Internal method for determining whether the node is over-capacity.
    fn capacity_reached(&self) -> Result<bool, PortalStorageError> {
        let storage_usage = self.get_total_storage_usage_in_bytes_from_network()?;
        Ok(storage_usage > self.storage_capacity_in_bytes)
    }

    /// Internal method for measuring the total amount of requestable data that the node is storing.
    fn get_total_storage_usage_in_bytes_from_network(&self) -> Result<u64, PortalStorageError> {
        let conn = self.sql_connection_pool.get()?;
        let mut query = conn.prepare(TOTAL_DATA_SIZE_QUERY)?;

        let result = query.query_map([], |row| Ok(DataSizeSum { sum: row.get(0)? }));

        let sum = match result?.next() {
            Some(x) => x,
            None => {
                return Err(PortalStorageError::SumError());
            }
        }?
        .sum;

        Ok(sum)
    }

    /// Internal method for finding the piece of stored data that has the farthest content id from our
    /// node id, according to xor distance. Used to determine which data to drop when at a capacity.
    fn find_farthest_content_id(&self) -> Result<Option<[u8; 32]>, PortalStorageError> {
        let result = match self.distance_function {
            DistanceFunction::Xor => {
                let node_id_u32 = PortalStorage::byte_vector_to_u32(self.node_id.raw().to_vec());

                let conn = self.sql_connection_pool.get()?;
                let mut query = conn.prepare(XOR_FIND_FARTHEST_QUERY)?;

                let mut result = query.query_map([node_id_u32], |row| {
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
                        return Err(PortalStorageError::DataSizeError {
                            doing: "finding farthest content id".to_string(),
                            expected: 32,
                            actual: length,
                        });
                    }
                };
                result_vec
            }
        };

        Ok(Some(result))
    }

    /// Internal method used to measure on-disk storage usage.
    fn get_total_size_of_directory_in_bytes(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<u64, PortalStorageError> {
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => {
                return Ok(0);
            }
        };
        let mut size = metadata.len();

        if metadata.is_dir() {
            for entry in fs::read_dir(&path)? {
                let dir = entry?;
                let path_string = match dir.path().into_os_string().into_string() {
                    Ok(string) => string,
                    Err(error_string) => {
                        return Err(PortalStorageError::StringError {
                            function_name: "get_total_size_of_directory_in_bytes".to_string(),
                            error: error_string,
                        });
                    }
                };
                size += self.get_total_size_of_directory_in_bytes(path_string)?;
            }
        }

        Ok(size)
    }

    /// Method that returns the distance between our node ID and a given content ID.
    pub fn distance_to_content_id(&self, content_id: &[u8; 32]) -> Distance {
        match self.distance_function {
            DistanceFunction::Xor => XorMetric::distance(content_id, &self.node_id.raw()),
        }
    }

    /// Converts most significant 4 bytes of a vector to a u32.
    fn byte_vector_to_u32(vec: Vec<u8>) -> u32 {
        if vec.len() < 4 {
            debug!("Error: XOR returned less than 4 bytes.");
            return 0;
        }

        let mut array: [u8; 4] = [0, 0, 0, 0];
        for (index, byte) in vec.iter().take(4).enumerate() {
            array[index] = byte.clone();
        }

        u32::from_be_bytes(array)
    }

    pub fn setup_config(
        node_id: NodeId,
        storage_capacity_kb: u32,
    ) -> Result<PortalStorageConfig, PortalStorageError> {
        let rocks_db = PortalStorage::setup_rocksdb(node_id)?;
        let sql_connection_pool = PortalStorage::setup_sql(node_id)?;
        Ok(PortalStorageConfig {
            // Arbitrarily set capacity at a quarter of what we're storing.
            // todo: make this ratio configurable
            storage_capacity_kb: (storage_capacity_kb / 4) as u64,
            node_id,
            distance_function: DistanceFunction::Xor,
            db: Arc::new(rocks_db),
            sql_connection_pool,
        })
    }

    /// Helper function for opening a SQLite connection.
    /// Used for testing.
    pub fn setup_rocksdb(node_id: NodeId) -> Result<rocksdb::DB, PortalStorageError> {
        let mut data_path: PathBuf = get_data_dir(node_id);
        data_path.push("rocksdb");
        debug!("Setting up RocksDB at path: {:?}", data_path);

        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        Ok(DB::open(&db_opts, data_path)?)
    }

    /// Helper function for opening a SQLite connection.
    /// Used for testing.
    pub fn setup_sql(node_id: NodeId) -> Result<Pool<SqliteConnectionManager>, PortalStorageError> {
        let mut data_path: PathBuf = get_data_dir(node_id);
        data_path.push("trin.sqlite");
        info!("Setting up SqliteDB at path: {:?}", data_path);

        let manager = SqliteConnectionManager::file(data_path);
        let pool = Pool::new(manager)?;
        pool.get()?.execute(CREATE_QUERY, params![])?;
        Ok(pool)
    }
}

// SQLite Statements
const CREATE_QUERY: &str = "create table if not exists content_metadata (
                                content_id_long TEXT PRIMARY KEY,
                                content_id_short INTEGER NOT NULL,
                                content_key TEXT NOT NULL,
                                content_size INTEGER
                            )";

const INSERT_QUERY: &str =
    "INSERT OR IGNORE INTO content_metadata (content_id_long, content_id_short, content_key, content_size)
                            VALUES (?1, ?2, ?3, ?4)";

const DELETE_QUERY: &str = "DELETE FROM content_metadata
                            WHERE content_id_long = (?1)";

const XOR_FIND_FARTHEST_QUERY: &str = "SELECT
                                    content_id_long
                                    FROM content_metadata
                                    ORDER BY ((?1 | content_id_short) - (?1 & content_id_short)) DESC";

const TOTAL_DATA_SIZE_QUERY: &str = "SELECT SUM(content_size) FROM content_metadata";

// SQLite Result Containers
struct ContentId {
    id_long: Vec<u8>,
}

struct DataSizeSum {
    sum: u64,
}

#[cfg(test)]
pub mod test {

    use super::*;
    use crate::portalnet::types::content_key::IdentityContentKey;

    use crate::utils::db::setup_temp_dir;
    use quickcheck::{quickcheck, Arbitrary, Gen, QuickCheck, TestResult};
    use rand::RngCore;
    use serial_test::serial;

    fn generate_random_content_key() -> IdentityContentKey {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        IdentityContentKey::new(key)
    }

    impl Arbitrary for IdentityContentKey {
        fn arbitrary(g: &mut Gen) -> Self {
            let mut value = [0; 32];
            for byte in value.iter_mut() {
                *byte = u8::arbitrary(g);
            }
            Self::new(value)
        }
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_new() -> Result<(), PortalStorageError> {
        let temp_dir = setup_temp_dir();

        let node_id = NodeId::random();

        let db = Arc::new(PortalStorage::setup_rocksdb(node_id)?);
        let sql_connection_pool = PortalStorage::setup_sql(node_id)?;

        const CAPACITY: u64 = 100;

        let storage_config = PortalStorageConfig {
            storage_capacity_kb: CAPACITY,
            node_id,
            distance_function: DistanceFunction::Xor,
            db,
            sql_connection_pool,
        };
        let storage = PortalStorage::new(storage_config)?;

        // Assert that configs match the storage object's fields
        assert_eq!(storage.node_id, node_id);
        assert_eq!(storage.storage_capacity_in_bytes, CAPACITY * 1000);

        temp_dir.close()?;
        Ok(())
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_store() -> Result<(), PortalStorageError> {
        fn test_store_random_bytes() {
            let temp_dir = setup_temp_dir();

            let node_id = NodeId::random();

            let db = Arc::new(PortalStorage::setup_rocksdb(node_id).unwrap());
            let sql_connection_pool = PortalStorage::setup_sql(node_id).unwrap();

            let storage_config = PortalStorageConfig {
                storage_capacity_kb: 100,
                node_id,
                distance_function: DistanceFunction::Xor,
                db,
                sql_connection_pool,
            };

            let mut storage = PortalStorage::new(storage_config).unwrap();
            let content_key = generate_random_content_key();
            let mut value = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut value);
            storage.store(&content_key, &value.to_vec()).unwrap();
            temp_dir.close().unwrap();
        }
        QuickCheck::new()
            .tests(10)
            .quickcheck(test_store_random_bytes as fn() -> _);
        Ok(())
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_get_data() -> Result<(), PortalStorageError> {
        let temp_dir = setup_temp_dir();

        let node_id = NodeId::random();

        let db = Arc::new(PortalStorage::setup_rocksdb(node_id)?);
        let sql_connection_pool = PortalStorage::setup_sql(node_id)?;

        let storage_config = PortalStorageConfig {
            storage_capacity_kb: 100,
            node_id,
            distance_function: DistanceFunction::Xor,
            db,
            sql_connection_pool,
        };
        let mut storage = PortalStorage::new(storage_config)?;
        let content_key = generate_random_content_key();
        let value: Vec<u8> = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".into();
        storage.store(&content_key, &value)?;

        let result = storage.get(&content_key).unwrap().unwrap();

        assert_eq!(result, value);

        temp_dir.close()?;
        Ok(())
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_get_total_storage() -> Result<(), PortalStorageError> {
        let temp_dir = setup_temp_dir();

        let node_id = NodeId::random();

        let db = Arc::new(PortalStorage::setup_rocksdb(node_id)?);
        let sql_connection_pool = PortalStorage::setup_sql(node_id)?;

        let storage_config = PortalStorageConfig {
            storage_capacity_kb: 100,
            node_id,
            distance_function: DistanceFunction::Xor,
            db,
            sql_connection_pool,
        };
        let mut storage = PortalStorage::new(storage_config)?;

        let content_key = generate_random_content_key();
        let value: Vec<u8> = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".into();
        storage.store(&content_key, &value)?;

        let bytes = storage.get_total_storage_usage_in_bytes_from_network()?;

        assert_eq!(32, bytes);

        temp_dir.close()?;
        Ok(())
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_find_farthest_empty_db() -> Result<(), PortalStorageError> {
        let temp_dir = setup_temp_dir();

        let node_id = NodeId::random();

        let db = Arc::new(PortalStorage::setup_rocksdb(node_id)?);
        let sql_connection_pool = PortalStorage::setup_sql(node_id)?;

        let storage_config = PortalStorageConfig {
            storage_capacity_kb: 100,
            node_id,
            distance_function: DistanceFunction::Xor,
            db,
            sql_connection_pool,
        };

        let storage = PortalStorage::new(storage_config)?;

        let result = storage.find_farthest_content_id()?;
        assert!(result.is_none());

        temp_dir.close()?;
        Ok(())
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_find_farthest() {
        fn prop(x: IdentityContentKey, y: IdentityContentKey) -> TestResult {
            let temp_dir = setup_temp_dir();

            let node_id = NodeId::random();
            let val = vec![0x00, 0x01, 0x02, 0x03, 0x04];

            let db = Arc::new(PortalStorage::setup_rocksdb(node_id).unwrap());
            let sql_connection_pool = PortalStorage::setup_sql(node_id).unwrap();

            let storage_config = PortalStorageConfig {
                storage_capacity_kb: 100,
                node_id,
                distance_function: DistanceFunction::Xor,
                db,
                sql_connection_pool,
            };

            let mut storage = PortalStorage::new(storage_config).unwrap();
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

            temp_dir.close().unwrap();

            TestResult::from_bool(farthest.unwrap().unwrap() == expected_farthest)
        }

        quickcheck(prop as fn(IdentityContentKey, IdentityContentKey) -> TestResult);
    }
}
