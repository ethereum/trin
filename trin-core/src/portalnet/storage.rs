use std::convert::TryInto;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use discv5::enr::NodeId;
use ethereum_types::U256;
use hex;
use log::{debug, error, info};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rocksdb::{Options, DB};
use rusqlite::params;

use super::types::{
    content_key::OverlayContentKey,
    metric::{Metric, XorMetric},
};
use crate::utils::db::get_data_dir;

// TODO: Replace enum with generic type parameter. This will require that we have a way to
// associate a "find farthest" query with the generic Metric.
#[derive(Copy, Clone)]
pub enum DistanceFunction {
    Xor,
}

/// An error from an operation on a `PortalContentStore`.
#[derive(Debug)]
pub enum PortalContentStoreError {
    /// An error from the underlying database.
    Database(String),
    /// An IO error.
    Io(std::io::Error),
    /// Unable to store content because it does not fall within the store's radius.
    InsufficientRadius { radius: U256, distance: U256 },
    /// Unable to store or retrieve data because it is invalid.
    InvalidData(String),
}

impl fmt::Display for PortalContentStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Database(err) => format!("database error {}", err),
            Self::Io(err) => format!("IO error {}", err),
            Self::InsufficientRadius { radius, distance } => format!(
                "radius {} insufficient to store content at distance {}",
                radius, distance
            ),
            Self::InvalidData(err) => format!("data invalid {}", err),
        };

        write!(f, "{}", message)
    }
}

impl std::error::Error for PortalContentStoreError {}

impl From<rocksdb::Error> for PortalContentStoreError {
    fn from(err: rocksdb::Error) -> Self {
        Self::Database(format!("(rocksdb) {}", err.to_string()))
    }
}

impl From<rusqlite::Error> for PortalContentStoreError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Database(format!("(sqlite) {}", err.to_string()))
    }
}

impl From<r2d2::Error> for PortalContentStoreError {
    fn from(err: r2d2::Error) -> Self {
        Self::Database(format!("(r2d2) {}", err.to_string()))
    }
}

impl From<std::io::Error> for PortalContentStoreError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// A data store for Portal Network content (data).
pub trait PortalContentStore {
    /// Looks up a piece of content by `key`.
    fn get<K: OverlayContentKey>(
        &self,
        key: &K,
    ) -> Result<Option<Vec<u8>>, PortalContentStoreError>;
    /// Puts a piece of content into the store.
    fn put<K: OverlayContentKey, V: AsRef<[u8]>>(
        &mut self,
        key: K,
        value: V,
    ) -> Result<(), PortalContentStoreError>;
    /// Returns whether the content denoted by `key` is within the radius of the data store.
    fn is_key_within_radius<K: OverlayContentKey>(&self, key: &K) -> bool;
    /// Returns the radius of the data store.
    fn radius(&self) -> U256;
    /// Returns the distance function used by the data store to compute distances.
    fn distance_fn(&self) -> DistanceFunction;
}

/// An in-memory `PortalContentStore`.
pub struct MemoryPortalContentStore {
    /// The content store.
    store: std::collections::HashMap<Vec<u8>, Vec<u8>>,
    /// The `NodeId` of the local node.
    node_id: NodeId,
    /// The distance function used by the store to compute distances.
    distance_fn: DistanceFunction,
    /// The radius of the store.
    radius: U256,
}

impl MemoryPortalContentStore {
    /// Constructs a new `MemoryPortalContentStore`.
    pub fn new(node_id: NodeId, distance_fn: DistanceFunction) -> Self {
        Self {
            store: std::collections::HashMap::new(),
            node_id,
            distance_fn,
            radius: U256::MAX,
        }
    }

    /// Returns the distance to `key` from the local `NodeId` according to the distance function.
    fn distance_to_key<K: OverlayContentKey>(&self, key: &K) -> U256 {
        match self.distance_fn {
            DistanceFunction::Xor => XorMetric::distance(&key.content_id(), &self.node_id.raw()),
        }
    }
}

impl PortalContentStore for MemoryPortalContentStore {
    fn get<K: OverlayContentKey>(
        &self,
        key: &K,
    ) -> Result<Option<Vec<u8>>, PortalContentStoreError> {
        let key = key.content_id();
        let val = self.store.get(&key.to_vec()).map(|val| val.clone());
        Ok(val)
    }

    fn put<K: OverlayContentKey, V: AsRef<[u8]>>(
        &mut self,
        key: K,
        value: V,
    ) -> Result<(), PortalContentStoreError> {
        let content_id = key.content_id();

        // Check whether `value` falls outside the radius.
        let distance = match self.distance_fn {
            DistanceFunction::Xor => XorMetric::distance(&content_id, &self.node_id.raw()),
        };
        if distance > self.radius {
            return Err(PortalContentStoreError::InsufficientRadius {
                radius: self.radius,
                distance,
            });
        }

        let value: &[u8] = value.as_ref();
        self.store.insert(content_id.to_vec(), value.to_vec());

        Ok(())
    }

    fn is_key_within_radius<K: OverlayContentKey>(&self, key: &K) -> bool {
        let distance = self.distance_to_key(key);
        distance <= self.radius
    }

    fn radius(&self) -> U256 {
        self.radius
    }

    fn distance_fn(&self) -> DistanceFunction {
        self.distance_fn
    }
}

/// Struct for configuring a `PortalStore` instance.
#[derive(Clone)]
pub struct PortalStoreConfig {
    pub storage_capacity_kb: u64,
    pub node_id: NodeId,
    pub distance_fn: DistanceFunction,
    pub db: Arc<rocksdb::DB>,
    pub sql_connection_pool: Pool<SqliteConnectionManager>,
}

/// Struct whose public methods abstract away Kademlia-based store behavior.
pub struct PortalStore {
    node_id: NodeId,
    storage_capacity_in_bytes: u64,
    radius: U256,
    farthest_content_id: Option<[u8; 32]>,
    db: Arc<rocksdb::DB>,
    sql_connection_pool: Pool<SqliteConnectionManager>,
    distance_fn: DistanceFunction,
}

impl PortalContentStore for PortalStore {
    fn get<K: OverlayContentKey>(
        &self,
        key: &K,
    ) -> Result<Option<Vec<u8>>, PortalContentStoreError> {
        let key = key.content_id();
        let value = self.db.get(key)?;
        Ok(value)
    }

    fn put<K: OverlayContentKey, V: AsRef<[u8]>>(
        &mut self,
        key: K,
        value: V,
    ) -> Result<(), PortalContentStoreError> {
        self.store(&key, &value.as_ref().to_vec())
    }

    fn is_key_within_radius<K: OverlayContentKey>(&self, key: &K) -> bool {
        let distance = self.distance_to_key(key);
        distance <= self.radius
    }

    fn radius(&self) -> U256 {
        self.radius
    }

    fn distance_fn(&self) -> DistanceFunction {
        self.distance_fn
    }
}

impl PortalStore {
    /// Public constructor for building a `PortalStore` object.
    /// Checks whether a populated database already exists vs a fresh instance.
    pub fn new(config: PortalStoreConfig) -> Result<Self, PortalContentStoreError> {
        // Initialize the instance
        let mut store = Self {
            node_id: config.node_id,
            storage_capacity_in_bytes: config.storage_capacity_kb * 1000,
            radius: U256::MAX,
            db: config.db,
            farthest_content_id: None,
            sql_connection_pool: config.sql_connection_pool,
            distance_fn: config.distance_fn,
        };

        // Check whether we already have data, and if so
        // use it to set the farthest_key and data_radius fields
        match store.find_farthest_content_id()? {
            Some(content_id) => {
                store.farthest_content_id = Some(content_id.clone());
                if store.capacity_reached()? {
                    store.radius = store.distance_to_content_id(&content_id);
                }
            }
            // No farthest key found, carry on with blank slate settings
            None => (),
        }

        Ok(store)
    }

    /// Returns the distance to `key` from the local `NodeId` according to the distance function.
    fn distance_to_key<K: OverlayContentKey>(&self, key: &K) -> U256 {
        match self.distance_fn {
            DistanceFunction::Xor => XorMetric::distance(&key.content_id(), &self.node_id.raw()),
        }
    }

    /// Method for storing a given value for a given content-key.
    fn store(
        &mut self,
        key: &impl OverlayContentKey,
        value: &Vec<u8>,
    ) -> Result<(), PortalContentStoreError> {
        let content_id = key.content_id();
        let distance_to_content_id = self.distance_to_content_id(&content_id);

        // Check whether data is outside our radius.
        if distance_to_content_id > self.radius {
            debug!("Not storing: {:02X?}", key.clone().into());
            return Err(PortalContentStoreError::InsufficientRadius {
                radius: self.radius,
                distance: distance_to_content_id,
            });
        }

        // Store the data.
        self.db_insert(&content_id, value)?;
        // Revert rocks db action if there's an error with writing to metadata db
        if let Err(err) = self.meta_db_insert(&content_id, &key.clone().into(), value) {
            debug!(
                "Error writing content ID {:?} to meta db. Reverting: {:?}",
                content_id, err
            );
            self.db.delete(&content_id)?;
            return Err(err.into());
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
            if let Err(err) = self.meta_db_remove(&id_to_remove) {
                debug!(
                    "Error writing content ID {:?} to meta db. Reverting: {:?}",
                    content_id, err
                );
                if let Some(value) = deleted_value {
                    self.db_insert(&content_id, &value)?;
                }

                let err = format!("failed deletion {}", err);
                return Err(PortalContentStoreError::Database(err));
            }

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
                    self.radius = self.distance_to_content_id(&farthest);
                }
            }
        }

        Ok(())
    }

    /// Public method for determining how much actual disk space is being used to store this node's Portal Network data.
    /// Intended for analysis purposes. PortalStorage's capacity decision-making is not based off of this method.
    pub fn get_total_store_usage_in_bytes_on_disk(&self) -> Result<u64, PortalContentStoreError> {
        Ok(self.get_total_size_of_directory_in_bytes(get_data_dir(self.node_id))?)
    }

    /// Internal method for inserting data into the db.
    fn db_insert(
        &self,
        content_id: &[u8; 32],
        value: &Vec<u8>,
    ) -> Result<(), PortalContentStoreError> {
        self.db.put(&content_id, value)?;
        Ok(())
    }

    /// Internal method for inserting data into the meta db.
    fn meta_db_insert(
        &self,
        content_id: &[u8; 32],
        content_key: &Vec<u8>,
        value: &Vec<u8>,
    ) -> Result<(), PortalContentStoreError> {
        let content_id_as_u32: u32 = Self::byte_vector_to_u32(content_id.to_vec());
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
            Err(err) => Err(err.into()),
        }
    }

    /// Internal method for removing a given content-id from the meta db.
    fn meta_db_remove(&self, content_id: &[u8; 32]) -> Result<(), PortalContentStoreError> {
        self.sql_connection_pool
            .get()?
            .execute(DELETE_QUERY, [content_id.to_vec()])?;
        Ok(())
    }

    /// Internal method for determining whether the node is over-capacity.
    fn capacity_reached(&self) -> Result<bool, PortalContentStoreError> {
        let store_usage = self.get_total_storage_usage_in_bytes_from_network()?;
        Ok(store_usage > self.storage_capacity_in_bytes)
    }

    /// Internal method for measuring the total amount of requestable data that the node is storing.
    fn get_total_storage_usage_in_bytes_from_network(
        &self,
    ) -> Result<u64, PortalContentStoreError> {
        let conn = self.sql_connection_pool.get()?;
        let mut query = conn.prepare(TOTAL_DATA_SIZE_QUERY)?;

        let result = query.query_map([], |row| Ok(DataSizeSum { sum: row.get(0)? }));

        let sum = match result?.next() {
            Some(x) => x,
            None => {
                let err = format!("unable to compute sum over content item sizes");
                return Err(PortalContentStoreError::Database(err));
            }
        }?
        .sum;

        Ok(sum)
    }

    /// Internal method for finding the piece of stored data that has the farthest content id from our
    /// node id, according to xor distance. Used to determine which data to drop when at a capacity.
    fn find_farthest_content_id(&self) -> Result<Option<[u8; 32]>, PortalContentStoreError> {
        let result = match self.distance_fn {
            DistanceFunction::Xor => {
                let node_id_u32 = Self::byte_vector_to_u32(self.node_id.raw().to_vec());

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
                        let err = format!("content ID of length {} != 32", length);
                        return Err(PortalContentStoreError::InvalidData(err));
                    }
                };
                result_vec
            }
        };

        Ok(Some(result))
    }

    /// Internal method used to measure on-disk store usage.
    fn get_total_size_of_directory_in_bytes(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<u64, PortalContentStoreError> {
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
                    Ok(path_string) => path_string,
                    Err(err) => {
                        let err = format!(
                            "unable to convert path {:?} into string {:?}",
                            path.as_ref(),
                            err
                        );
                        return Err(PortalContentStoreError::Database(err));
                    }
                };
                size += self.get_total_size_of_directory_in_bytes(path_string)?;
            }
        }

        Ok(size)
    }

    /// Method that returns the distance between our node ID and a given content ID.
    pub fn distance_to_content_id(&self, content_id: &[u8; 32]) -> U256 {
        match self.distance_fn {
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
    ) -> Result<PortalStoreConfig, PortalContentStoreError> {
        let rocks_db = Self::setup_rocksdb(node_id)?;
        let sql_connection_pool = Self::setup_sql(node_id)?;
        Ok(PortalStoreConfig {
            // Arbitrarily set capacity at a quarter of what we're storing.
            // todo: make this ratio configurable
            storage_capacity_kb: (storage_capacity_kb / 4) as u64,
            node_id,
            distance_fn: DistanceFunction::Xor,
            db: Arc::new(rocks_db),
            sql_connection_pool,
        })
    }

    /// Helper function for opening a SQLite connection.
    /// Used for testing.
    pub fn setup_rocksdb(node_id: NodeId) -> Result<rocksdb::DB, PortalContentStoreError> {
        let mut data_path: PathBuf = get_data_dir(node_id);
        data_path.push("rocksdb");
        debug!("Setting up RocksDB at path: {:?}", data_path);

        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        Ok(DB::open(&db_opts, data_path)?)
    }

    /// Helper function for opening a SQLite connection.
    /// Used for testing.
    pub fn setup_sql(
        node_id: NodeId,
    ) -> Result<Pool<SqliteConnectionManager>, PortalContentStoreError> {
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
    async fn test_new() -> Result<(), PortalContentStoreError> {
        let temp_dir = setup_temp_dir();

        let node_id = NodeId::random();

        let db = Arc::new(PortalStore::setup_rocksdb(node_id)?);
        let sql_connection_pool = PortalStore::setup_sql(node_id)?;

        const CAPACITY: u64 = 100;

        let store_config = PortalStoreConfig {
            storage_capacity_kb: CAPACITY,
            node_id,
            distance_fn: DistanceFunction::Xor,
            db,
            sql_connection_pool,
        };
        let store = PortalStore::new(store_config)?;

        // Assert that configs match the store object's fields
        assert_eq!(store.node_id, node_id);
        assert_eq!(store.storage_capacity_in_bytes, CAPACITY * 1000);

        temp_dir.close()?;
        Ok(())
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_store() -> Result<(), PortalContentStoreError> {
        fn test_store_random_bytes() {
            let temp_dir = setup_temp_dir();

            let node_id = NodeId::random();

            let db = Arc::new(PortalStore::setup_rocksdb(node_id).unwrap());
            let sql_connection_pool = PortalStore::setup_sql(node_id).unwrap();

            let store_config = PortalStoreConfig {
                storage_capacity_kb: 100,
                node_id,
                distance_fn: DistanceFunction::Xor,
                db,
                sql_connection_pool,
            };

            let mut store = PortalStore::new(store_config).unwrap();
            let content_key = generate_random_content_key();
            let mut value = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut value);
            store.store(&content_key, &value.to_vec()).unwrap();
            temp_dir.close().unwrap();
        }
        QuickCheck::new()
            .tests(10)
            .quickcheck(test_store_random_bytes as fn() -> _);
        Ok(())
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_get_data() -> Result<(), PortalContentStoreError> {
        let temp_dir = setup_temp_dir();

        let node_id = NodeId::random();

        let db = Arc::new(PortalStore::setup_rocksdb(node_id)?);
        let sql_connection_pool = PortalStore::setup_sql(node_id)?;

        let store_config = PortalStoreConfig {
            storage_capacity_kb: 100,
            node_id,
            distance_fn: DistanceFunction::Xor,
            db,
            sql_connection_pool,
        };
        let mut store = PortalStore::new(store_config)?;
        let content_key = generate_random_content_key();
        let value: Vec<u8> = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".into();
        store.store(&content_key, &value)?;

        let result = store.get(&content_key).unwrap().unwrap();

        assert_eq!(result, value);

        temp_dir.close()?;
        Ok(())
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_get_total_store() -> Result<(), PortalContentStoreError> {
        let temp_dir = setup_temp_dir();

        let node_id = NodeId::random();

        let db = Arc::new(PortalStore::setup_rocksdb(node_id)?);
        let sql_connection_pool = PortalStore::setup_sql(node_id)?;

        let store_config = PortalStoreConfig {
            storage_capacity_kb: 100,
            node_id,
            distance_fn: DistanceFunction::Xor,
            db,
            sql_connection_pool,
        };
        let mut store = PortalStore::new(store_config)?;

        let content_key = generate_random_content_key();
        let value: Vec<u8> = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".into();
        store.store(&content_key, &value)?;

        let bytes = store.get_total_storage_usage_in_bytes_from_network()?;

        assert_eq!(32, bytes);

        temp_dir.close()?;
        Ok(())
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_find_farthest_empty_db() -> Result<(), PortalContentStoreError> {
        let temp_dir = setup_temp_dir();

        let node_id = NodeId::random();

        let db = Arc::new(PortalStore::setup_rocksdb(node_id)?);
        let sql_connection_pool = PortalStore::setup_sql(node_id)?;

        let store_config = PortalStoreConfig {
            storage_capacity_kb: 100,
            node_id,
            distance_fn: DistanceFunction::Xor,
            db,
            sql_connection_pool,
        };

        let store = PortalStore::new(store_config)?;

        let result = store.find_farthest_content_id()?;
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

            let db = Arc::new(PortalStore::setup_rocksdb(node_id).unwrap());
            let sql_connection_pool = PortalStore::setup_sql(node_id).unwrap();

            let store_config = PortalStoreConfig {
                storage_capacity_kb: 100,
                node_id,
                distance_fn: DistanceFunction::Xor,
                db,
                sql_connection_pool,
            };

            let mut store = PortalStore::new(store_config).unwrap();
            store.store(&x, &val).unwrap();
            store.store(&y, &val).unwrap();

            let expected_farthest = if store.distance_to_content_id(&x.content_id())
                > store.distance_to_content_id(&y.content_id())
            {
                x.content_id()
            } else {
                y.content_id()
            };

            let farthest = store.find_farthest_content_id();

            temp_dir.close().unwrap();

            TestResult::from_bool(farthest.unwrap().unwrap() == expected_farthest)
        }

        quickcheck(prop as fn(IdentityContentKey, IdentityContentKey) -> TestResult);
    }
}
