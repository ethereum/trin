use std::{
    convert::TryInto,
    fmt, fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::anyhow;
use discv5::enr::NodeId;
use ethportal_api::types::portal::PaginateLocalContentInfo;
use prometheus_exporter::{
    self,
    prometheus::{register_gauge, Gauge},
};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rocksdb::{Options, DB};
use rusqlite::params;
use tracing::{debug, info};

use crate::{portalnet::types::messages::ProtocolId, utils::db::get_data_dir};
use ethportal_api::types::content_key::{HistoryContentKey, OverlayContentKey};
use trin_types::distance::{Distance, Metric, XorMetric};
use trin_utils::bytes::{hex_decode, hex_encode};

// TODO: Replace enum with generic type parameter. This will require that we have a way to
// associate a "find farthest" query with the generic Metric.
#[derive(Copy, Clone, Debug)]
pub enum DistanceFunction {
    Xor,
}

/// An error from an operation on a `ContentStore`.
#[derive(Debug)]
pub enum ContentStoreError {
    /// An error from the underlying database.
    Database(String),
    /// An IO error.
    Io(std::io::Error),
    /// Unable to store content because it does not fall within the store's radius.
    InsufficientRadius {
        radius: Distance,
        distance: Distance,
    },
    /// Unable to store or retrieve data because it is invalid.
    InvalidData(String),
}

impl fmt::Display for ContentStoreError {
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

impl std::error::Error for ContentStoreError {}

impl From<rocksdb::Error> for ContentStoreError {
    fn from(err: rocksdb::Error) -> Self {
        Self::Database(format!("(rocksdb) {}", err.to_string()))
    }
}

impl From<rusqlite::Error> for ContentStoreError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Database(format!("(sqlite) {}", err.to_string()))
    }
}

impl From<r2d2::Error> for ContentStoreError {
    fn from(err: r2d2::Error) -> Self {
        Self::Database(format!("(r2d2) {}", err.to_string()))
    }
}

impl From<std::io::Error> for ContentStoreError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// A data store for Portal Network content (data).
pub trait ContentStore {
    /// Looks up a piece of content by `key`.
    fn get<K: OverlayContentKey>(&self, key: &K) -> Result<Option<Vec<u8>>, ContentStoreError>;

    /// Puts a piece of content into the store.
    fn put<K: OverlayContentKey, V: AsRef<[u8]>>(
        &mut self,
        key: K,
        value: V,
    ) -> Result<(), ContentStoreError>;

    /// Returns whether the content denoted by `key` is within the radius of the data store and not
    /// already stored within the data store.
    fn is_key_within_radius_and_unavailable<K: OverlayContentKey>(
        &self,
        key: &K,
    ) -> Result<bool, ContentStoreError>;

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
        match self.distance_fn {
            DistanceFunction::Xor => XorMetric::distance(&key.content_id(), &self.node_id.raw()),
        }
    }

    /// Returns `true` if the content store contains data for `key`.
    fn contains_key<K: OverlayContentKey>(&self, key: &K) -> bool {
        let key = key.content_id().to_vec();
        self.store.contains_key(&key)
    }
}

impl ContentStore for MemoryContentStore {
    fn get<K: OverlayContentKey>(&self, key: &K) -> Result<Option<Vec<u8>>, ContentStoreError> {
        let key = key.content_id();
        let val = self.store.get(&key.to_vec()).map(|val| val.clone());
        Ok(val)
    }

    fn put<K: OverlayContentKey, V: AsRef<[u8]>>(
        &mut self,
        key: K,
        value: V,
    ) -> Result<(), ContentStoreError> {
        let content_id = key.content_id();
        let value: &[u8] = value.as_ref();
        self.store.insert(content_id.to_vec(), value.to_vec());

        Ok(())
    }

    fn is_key_within_radius_and_unavailable<K: OverlayContentKey>(
        &self,
        key: &K,
    ) -> Result<bool, ContentStoreError> {
        let distance = self.distance_to_key(key);
        if distance > self.radius {
            return Ok(false);
        }

        Ok(!self.contains_key(key))
    }

    fn radius(&self) -> Distance {
        self.radius
    }
}

/// Struct for configuring a `PortalStorage` instance.
#[derive(Clone)]
pub struct PortalStorageConfig {
    pub storage_capacity_kb: u64,
    pub node_id: NodeId,
    pub distance_fn: DistanceFunction,
    pub db: Arc<rocksdb::DB>,
    pub sql_connection_pool: Pool<SqliteConnectionManager>,
    pub metrics_enabled: bool,
}

impl PortalStorageConfig {
    pub fn new(
        storage_capacity_kb: u64,
        node_id: NodeId,
        metrics_enabled: bool,
    ) -> anyhow::Result<Self> {
        let db = Arc::new(PortalStorage::setup_rocksdb(node_id)?);
        let sql_connection_pool = PortalStorage::setup_sql(node_id)?;
        Ok(Self {
            storage_capacity_kb,
            node_id,
            distance_fn: DistanceFunction::Xor,
            db,
            sql_connection_pool,
            metrics_enabled,
        })
    }
}

/// Struct whose public methods abstract away Kademlia-based store behavior.
#[derive(Debug)]
pub struct PortalStorage {
    node_id: NodeId,
    storage_capacity_in_bytes: u64,
    radius: Distance,
    db: Arc<rocksdb::DB>,
    sql_connection_pool: Pool<SqliteConnectionManager>,
    distance_fn: DistanceFunction,
    metrics: Option<StorageMetrics>,
    protocol: ProtocolId,
}

impl ContentStore for PortalStorage {
    fn get<K: OverlayContentKey>(&self, key: &K) -> Result<Option<Vec<u8>>, ContentStoreError> {
        let content_id = key.content_id();
        Ok(self.db.get(content_id)?)
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
    ) -> Result<bool, ContentStoreError> {
        let distance = self.distance_to_key(key);
        if distance > self.radius {
            return Ok(false);
        }

        let key = key.content_id();
        let is_key_available = self.db.get_pinned(&key)?.is_some();
        Ok(!is_key_available)
    }

    fn radius(&self) -> Distance {
        self.radius
    }
}

impl PortalStorage {
    /// Public constructor for building a `PortalStorage` object.
    /// Checks whether a populated database already exists vs a fresh instance.
    pub fn new(
        config: PortalStorageConfig,
        protocol: ProtocolId,
    ) -> Result<Self, ContentStoreError> {
        // Initialize the instance
        let mut storage = Self {
            node_id: config.node_id,
            storage_capacity_in_bytes: config.storage_capacity_kb * 1000,
            radius: Distance::MAX,
            db: config.db,
            sql_connection_pool: config.sql_connection_pool,
            distance_fn: config.distance_fn,
            metrics: None,
            protocol,
        };

        // Check whether we already have data, and use it to set radius
        match storage.total_entry_count()? {
            0 => {
                // Default radius is left in place, unless user selected 0kb capacity
                if storage.storage_capacity_in_bytes == 0 {
                    storage.radius = Distance::ZERO;
                }
            }
            // Only prunes data when at capacity. (eg. user changed it via kb flag)
            _ => storage.prune_db()?,
        }

        if config.metrics_enabled {
            let metrics = StorageMetrics::new(&storage.protocol);
            storage.metrics = Some(metrics);

            // Report current storage capacity.
            storage.metrics.as_ref().and_then(|metrics| {
                Some(
                    metrics
                        .report_storage_capacity(storage.storage_capacity_in_bytes as f64 / 1000.0),
                )
            });

            // Report current total storage usage.
            let total_storage_usage = storage.get_total_storage_usage_in_bytes_on_disk()?;
            storage.metrics.as_ref().and_then(|metrics| {
                Some(metrics.report_total_storage_usage(total_storage_usage as f64 / 1000.0))
            });

            // Report total storage used by network content.
            let network_content_storage_usage =
                storage.get_total_storage_usage_in_bytes_from_network()?;
            storage.metrics.as_ref().and_then(|metrics| {
                Some(
                    metrics
                        .report_content_data_storage(network_content_storage_usage as f64 / 1000.0),
                )
            });
        }

        Ok(storage)
    }

    /// Returns a paginated list of all available content keys from local storage (from any
    /// subnetwork) according to the provided offset and limit.
    pub fn paginate(&self, offset: &u64, limit: &u64) -> anyhow::Result<PaginateLocalContentInfo> {
        let conn = self.sql_connection_pool.get()?;
        let mut query = conn.prepare(PAGINATE_QUERY)?;

        let content_keys: Result<Vec<HistoryContentKey>, rusqlite::Error> = query
            .query_map(
                &[
                    (":offset", offset.to_string().as_str()),
                    (":limit", limit.to_string().as_str()),
                ],
                |row| {
                    Ok({
                        let row: String = row.get(0)?;
                        // value is stored without 0x prefix, so we must add it
                        let row = format!("0x{}", row);
                        let bytes: Vec<u8> = hex_decode(&row).map_err(|err|
                            // TODO: This is a hack to get around the fact that rusqlite doesn't
                            // support returning a custom error type. We should fix this.
                            rusqlite::Error::InvalidParameterName(err.to_string()))?;
                        HistoryContentKey::from(bytes)
                    })
                },
            )?
            .collect();
        Ok(PaginateLocalContentInfo {
            content_keys: content_keys?,
            total_entries: self.total_entry_count()?,
        })
    }

    fn total_entry_count(&self) -> Result<u64, ContentStoreError> {
        let conn = self.sql_connection_pool.get()?;
        let mut query = conn.prepare(TOTAL_ENTRY_COUNT_QUERY)?;
        let result: Result<Vec<EntryCount>, rusqlite::Error> = query
            .query_map([], |row| Ok(EntryCount(row.get(0)?)))?
            .collect();
        match result?.first() {
            Some(val) => Ok(val.0),
            None => Err(ContentStoreError::InvalidData(
                "Invalid total entries count returned from sql query.".to_string(),
            )),
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

        // Store the data in radius db
        self.db_insert(&content_id, value)?;
        let content_key: Vec<u8> = key.clone().into();
        // store content key w/o the 0x prefix
        let content_key = hex_encode(content_key).trim_start_matches("0x").to_string();
        // Revert rocks db action if there's an error with writing to metadata db
        if let Err(err) = self.meta_db_insert(&content_id, &content_key, value) {
            debug!(
                "Error writing content ID {:?} to meta db. Reverting: {:?}",
                content_id, err
            );
            self.db.delete(&content_id)?;
            return Err(err.into());
        }
        self.prune_db()?;
        if let Some(metrics) = &self.metrics {
            let total_bytes_on_disk = self.get_total_storage_usage_in_bytes_on_disk()?;
            metrics.report_total_storage_usage(total_bytes_on_disk as f64 / 1000.0)
        }

        Ok(())
    }

    /// Internal method for pruning any data that falls outside of the radius of the store.
    /// Resets the data radius if it prunes any data. Does nothing if the store is empty.
    fn prune_db(&mut self) -> Result<(), ContentStoreError> {
        let mut farthest_content_id: Option<[u8; 32]> = self.find_farthest_content_id()?;
        // Delete furthest data until our data usage is less than capacity.
        while self.capacity_reached()? {
            let id_to_remove =
                // Always expect a content id if capacity_reached(), even at 0kb capacity
                farthest_content_id.expect("Capacity reached, but no farthest id found!");
            debug!(
                "Capacity reached, deleting farthest: {}",
                hex_encode(&id_to_remove)
            );
            if let Err(err) = self.evict(id_to_remove) {
                debug!("Error writing content ID {id_to_remove:?} to meta db. Reverted: {err:?}",);
            }
            // Calculate new farthest_content_id and reset radius
            match self.find_farthest_content_id()? {
                None => {
                    // We get here if the entire db has been pruned,
                    // eg. user selected 0kb capacity for storage
                    self.radius = Distance::ZERO;
                }
                Some(farthest) => {
                    debug!("Found new farthest: {}", hex_encode(&farthest));
                    self.radius = self.distance_to_content_id(&farthest);
                    farthest_content_id = Some(farthest);
                }
            }
        }
        Ok(())
    }

    /// Public method for evicting a certain content id. Will revert RocksDB deletion if meta_db
    /// deletion fails.
    pub fn evict(&self, id: [u8; 32]) -> anyhow::Result<()> {
        let deleted_value = self.db.get(&id)?;
        self.db.delete(&id)?;
        // Revert rocksdb action if there's an error with writing to metadata db
        if let Err(err) = self.meta_db_remove(&id) {
            if let Some(value) = deleted_value {
                self.db_insert(&id, &value)?;
            }
            return Err(anyhow!("failed deletion {err}"));
        }
        Ok(())
    }

    /// Public method for looking up a content key by its content id
    pub fn lookup_content_key(&self, id: [u8; 32]) -> anyhow::Result<Option<Vec<u8>>> {
        let conn = self.sql_connection_pool.get()?;
        let mut query = conn.prepare(CONTENT_KEY_LOOKUP_QUERY)?;
        let id = id.to_vec();
        let result: Result<Vec<HistoryContentKey>, rusqlite::Error> = query
            .query_map([id], |row| {
                let row: String = row.get(0)?;
                // value is stored without 0x prefix, so we must add it
                let row = format!("0x{}", row);
                let bytes: Vec<u8> = hex_decode(&row).map_err(|err|
                    // TODO: This is a hack to get around the fact that rusqlite doesn't
                    // support returning a custom error type. We should fix this.
                    rusqlite::Error::InvalidParameterName(err.to_string()))?;
                Ok(HistoryContentKey::from(bytes))
            })?
            .collect();

        match result?.first() {
            Some(val) => Ok(Some(val.into())),
            None => Ok(None),
        }
    }

    /// Public method for retrieving the node's current radius.
    pub fn radius(&self) -> Distance {
        self.radius
    }

    /// Public method for determining how much actual disk space is being used to store this node's Portal Network data.
    /// Intended for analysis purposes. PortalStorage's capacity decision-making is not based off of this method.
    pub fn get_total_storage_usage_in_bytes_on_disk(&self) -> Result<u64, ContentStoreError> {
        let data_dir: PathBuf = get_data_dir(self.node_id).map_err(|err| {
            ContentStoreError::Database(format!(
                "Unable to get data dir when calculating total storage usage: {err:?}"
            ))
        })?;
        let storage_usage = self.get_total_size_of_directory_in_bytes(data_dir)?;
        self.metrics.as_ref().and_then(|metrics| {
            Some(metrics.report_total_storage_usage(storage_usage as f64 / 1000.0))
        });
        Ok(storage_usage)
    }

    /// Internal method for inserting data into the db.
    fn db_insert(&self, content_id: &[u8; 32], value: &Vec<u8>) -> Result<(), ContentStoreError> {
        self.db.put(&content_id, value)?;
        Ok(())
    }

    /// Internal method for inserting data into the meta db.
    fn meta_db_insert(
        &self,
        content_id: &[u8; 32],
        content_key: &String,
        value: &Vec<u8>,
    ) -> Result<(), ContentStoreError> {
        let content_id_as_u32: u32 = Self::byte_vector_to_u32(content_id.to_vec());
        let value_size = value.len();
        if content_key.starts_with("0x") {
            return Err(ContentStoreError::InvalidData(
                "Content key should not start with 0x".to_string(),
            ));
        }
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
    fn meta_db_remove(&self, content_id: &[u8; 32]) -> Result<(), ContentStoreError> {
        self.sql_connection_pool
            .get()?
            .execute(DELETE_QUERY, [content_id.to_vec()])?;
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
        let mut query = conn.prepare(TOTAL_DATA_SIZE_QUERY)?;

        let result = query.query_map([], |row| Ok(DataSizeSum { sum: row.get(0)? }));

        let sum = match result?.next() {
            Some(total) => total,
            None => {
                let err = format!("Unable to compute sum over content item sizes");
                return Err(ContentStoreError::Database(err));
            }
        }?
        .sum;

        self.metrics
            .as_ref()
            .and_then(|metrics| Some(metrics.report_content_data_storage(sum as f64 / 1000.0)));

        Ok(sum as u64)
    }

    /// Internal method for finding the piece of stored data that has the farthest content id from our
    /// node id, according to xor distance. Used to determine which data to drop when at a capacity.
    fn find_farthest_content_id(&self) -> Result<Option<[u8; 32]>, ContentStoreError> {
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
                        return Err(ContentStoreError::InvalidData(err));
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
    ) -> Result<u64, ContentStoreError> {
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
                            "Unable to convert path {:?} into string {:?}",
                            path.as_ref(),
                            err
                        );
                        return Err(ContentStoreError::Database(err));
                    }
                };
                size += self.get_total_size_of_directory_in_bytes(path_string)?;
            }
        }

        Ok(size)
    }

    /// Method that returns the distance between our node ID and a given content ID.
    pub fn distance_to_content_id(&self, content_id: &[u8; 32]) -> Distance {
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

    /// Helper function for opening a RocksDB connection for the radius-constrained db.
    pub fn setup_rocksdb(node_id: NodeId) -> Result<rocksdb::DB, ContentStoreError> {
        let mut data_path: PathBuf = get_data_dir(node_id).map_err(|err| {
            ContentStoreError::Database(format!("Unable to get data dir for rocksdb: {err:?}"))
        })?;
        data_path.push("rocksdb");
        info!(path = %data_path.display(), "Setting up RocksDB");

        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        Ok(DB::open(&db_opts, data_path)?)
    }

    /// Helper function for opening a SQLite connection.
    pub fn setup_sql(node_id: NodeId) -> Result<Pool<SqliteConnectionManager>, ContentStoreError> {
        let mut data_path: PathBuf = get_data_dir(node_id).map_err(|err| {
            ContentStoreError::Database(format!("Unable to get data dir for sql: {err:?}"))
        })?;
        data_path.push("trin.sqlite");
        info!(path = %data_path.display(), "Setting up SqliteDB");

        let manager = SqliteConnectionManager::file(data_path);
        let pool = Pool::new(manager)?;
        pool.get()?.execute(CREATE_QUERY, params![])?;
        Ok(pool)
    }
}

#[derive(Debug)]
struct StorageMetrics {
    content_storage_usage_kb: Gauge,
    total_storage_usage_kb: Gauge,
    storage_capacity_kb: Gauge,
}

impl StorageMetrics {
    pub fn new(protocol: &ProtocolId) -> Self {
        let content_storage_usage_kb = register_gauge!(
            format!("trin_content_storage_usage_kb_{:?}", protocol),
            "help"
        )
        .unwrap();
        let total_storage_usage_kb = register_gauge!(
            format!("trin_total_storage_usage_kb_{:?}", protocol),
            "help"
        )
        .unwrap();
        let storage_capacity_kb =
            register_gauge!(format!("trin_storage_capacity_kb_{:?}", protocol), "help").unwrap();

        Self {
            content_storage_usage_kb,
            total_storage_usage_kb,
            storage_capacity_kb,
        }
    }

    pub fn report_content_data_storage(&self, kb: f64) {
        self.content_storage_usage_kb.set(kb);
    }

    pub fn report_total_storage_usage(&self, kb: f64) {
        self.total_storage_usage_kb.set(kb);
    }

    pub fn report_storage_capacity(&self, kb: f64) {
        self.storage_capacity_kb.set(kb);
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

const CONTENT_KEY_LOOKUP_QUERY: &str =
    "SELECT content_key FROM content_metadata WHERE content_id_long = (?1)";

const TOTAL_DATA_SIZE_QUERY: &str = "SELECT TOTAL(content_size) FROM content_metadata";

const TOTAL_ENTRY_COUNT_QUERY: &str = "SELECT COUNT(content_id_long) FROM content_metadata";

const PAGINATE_QUERY: &str =
    "SELECT content_key FROM content_metadata ORDER BY content_key LIMIT :limit OFFSET :offset";

// SQLite Result Containers
struct ContentId {
    id_long: Vec<u8>,
}

struct DataSizeSum {
    sum: f64,
}

struct EntryCount(u64);

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub mod test {

    use super::*;

    use quickcheck::{quickcheck, QuickCheck, TestResult};
    use rand::RngCore;
    use serial_test::serial;

    use crate::utils::db::setup_temp_dir;
    use trin_types::content_key::IdentityContentKey;

    const CAPACITY: u64 = 100;

    fn generate_random_content_key() -> IdentityContentKey {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        IdentityContentKey::new(key)
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_new() -> Result<(), ContentStoreError> {
        let temp_dir = setup_temp_dir().unwrap();

        let node_id = NodeId::random();

        let storage_config = PortalStorageConfig::new(CAPACITY, node_id, false).unwrap();
        let storage = PortalStorage::new(storage_config, ProtocolId::History)?;

        // Assert that configs match the storage object's fields
        assert_eq!(storage.node_id, node_id);
        assert_eq!(storage.storage_capacity_in_bytes, CAPACITY * 1000);
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

            let node_id = NodeId::random();
            let storage_config = PortalStorageConfig::new(CAPACITY, node_id, false).unwrap();
            let mut storage = PortalStorage::new(storage_config, ProtocolId::History).unwrap();
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

        let node_id = NodeId::random();
        let storage_config = PortalStorageConfig::new(CAPACITY, node_id, false).unwrap();
        let mut storage = PortalStorage::new(storage_config, ProtocolId::History)?;
        let content_key = generate_random_content_key();
        let value: Vec<u8> = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".into();
        storage.store(&content_key, &value)?;

        let result = storage.get(&content_key).unwrap().unwrap();

        assert_eq!(result, value);

        std::mem::drop(storage);
        temp_dir.close()?;
        Ok(())
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_get_total_storage() -> Result<(), ContentStoreError> {
        let temp_dir = setup_temp_dir().unwrap();

        let node_id = NodeId::random();
        let storage_config = PortalStorageConfig::new(CAPACITY, node_id, false).unwrap();
        let mut storage = PortalStorage::new(storage_config, ProtocolId::History)?;

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

        let node_id = NodeId::random();
        let storage_config = PortalStorageConfig::new(CAPACITY, node_id, false).unwrap();
        let mut storage = PortalStorage::new(storage_config, ProtocolId::History)?;

        for _ in 0..50 {
            let content_key = generate_random_content_key();
            let value: Vec<u8> = "OGFWs179fWnqmjvHQFGHszXloc3Wzdb4".into();
            storage.store(&content_key, &value)?;
        }

        let bytes = storage.get_total_storage_usage_in_bytes_from_network()?;
        assert_eq!(1600, bytes); // 32bytes * 50
        assert_eq!(storage.radius, Distance::MAX);
        std::mem::drop(storage);

        // test with 1kb capacity
        let new_storage_config = PortalStorageConfig::new(1, node_id, false).unwrap();
        let new_storage = PortalStorage::new(new_storage_config, ProtocolId::History)?;

        // test that previously set value has been pruned
        let bytes = new_storage.get_total_storage_usage_in_bytes_from_network()?;
        assert_eq!(992, bytes);
        assert_eq!(31, new_storage.total_entry_count().unwrap());
        assert_eq!(new_storage.storage_capacity_in_bytes, 1000);
        // test that radius has decreased now that we're at capacity
        assert!(new_storage.radius < Distance::MAX);
        std::mem::drop(new_storage);

        // test with 0kb capacity
        let new_storage_config = PortalStorageConfig::new(0, node_id, false).unwrap();
        let new_storage = PortalStorage::new(new_storage_config, ProtocolId::History)?;

        // test that previously set value has been pruned
        assert_eq!(new_storage.storage_capacity_in_bytes, 0);
        assert_eq!(new_storage.radius, Distance::ZERO);
        //assert_eq!(31, new_storage.total_entry_count().unwrap());
        std::mem::drop(new_storage);

        temp_dir.close()?;
        Ok(())
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_new_storage_with_zero_capacity() -> Result<(), ContentStoreError> {
        let temp_dir = setup_temp_dir().unwrap();

        let node_id = NodeId::random();
        let storage_config = PortalStorageConfig::new(0, node_id, false).unwrap();
        let mut storage = PortalStorage::new(storage_config, ProtocolId::History)?;

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

        let node_id = NodeId::random();
        let storage_config = PortalStorageConfig::new(CAPACITY, node_id, false).unwrap();
        let storage = PortalStorage::new(storage_config, ProtocolId::History)?;

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

            let node_id = NodeId::random();
            let val = vec![0x00, 0x01, 0x02, 0x03, 0x04];
            let storage_config = PortalStorageConfig::new(CAPACITY, node_id, false).unwrap();
            let mut storage = PortalStorage::new(storage_config, ProtocolId::History).unwrap();
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

    #[test]
    fn memory_store_contains_key() {
        let node_id = NodeId::random();
        let mut store = MemoryContentStore::new(node_id, DistanceFunction::Xor);

        let val = vec![0xef];

        // Arbitrary key not available.
        let arb_key = IdentityContentKey::new(node_id.raw());
        assert!(!store.contains_key(&arb_key));

        // Arbitrary key available.
        let _ = store.put(arb_key.clone(), val);
        assert!(store.contains_key(&arb_key));
    }

    #[test]
    fn memory_store_get() {
        let node_id = NodeId::random();
        let mut store = MemoryContentStore::new(node_id, DistanceFunction::Xor);

        let val = vec![0xef];

        // Arbitrary key not available.
        let arb_key = IdentityContentKey::new(node_id.raw());
        assert!(store.get(&arb_key).unwrap().is_none());

        // Arbitrary key available and equal to assigned value.
        let _ = store.put(arb_key.clone(), val.clone());
        assert_eq!(store.get(&arb_key).unwrap(), Some(val));
    }

    #[test]
    fn memory_store_put() {
        let node_id = NodeId::random();
        let mut store = MemoryContentStore::new(node_id, DistanceFunction::Xor);

        let val = vec![0xef];

        // Store content
        let arb_key = IdentityContentKey::new(node_id.raw());
        let _ = store.put(arb_key.clone(), val.clone());
        assert_eq!(store.get(&arb_key).unwrap(), Some(val));
    }

    #[test]
    fn memory_store_is_within_radius_and_unavailable() {
        let node_id = NodeId::random();
        let mut store = MemoryContentStore::new(node_id, DistanceFunction::Xor);

        let val = vec![0xef];

        // Arbitrary key within radius and unavailable.
        let arb_key = IdentityContentKey::new(node_id.raw());
        assert!(store
            .is_key_within_radius_and_unavailable(&arb_key)
            .unwrap());

        // Arbitrary key available.
        let _ = store.put(arb_key.clone(), val.clone());
        assert!(!store
            .is_key_within_radius_and_unavailable(&arb_key)
            .unwrap());
    }
}
