use anyhow::Error;
use discv5::enr::k256::elliptic_curve::consts::U128;
use std::{
    convert::TryInto,
    fs,
    path::{Path, PathBuf},
};

use discv5::enr::NodeId;
use ethportal_api::types::history::PaginateLocalContentInfo;
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use ssz::{Decode, Encode};
use ssz_types::VariableList;
use thiserror::Error;
use tracing::{debug, error, info};

use ethportal_api::{
    types::{
        content_key::beacon::{
            LIGHT_CLIENT_BOOTSTRAP_KEY_PREFIX, LIGHT_CLIENT_FINALITY_UPDATE_KEY_PREFIX,
            LIGHT_CLIENT_OPTIMISTIC_UPDATE_KEY_PREFIX, LIGHT_CLIENT_UPDATES_BY_RANGE_KEY_PREFIX,
        },
        content_value::beacon::{
            ForkVersionedLightClientFinalityUpdate, ForkVersionedLightClientOptimisticUpdate,
            ForkVersionedLightClientUpdate, LightClientUpdatesByRange,
        },
        distance::{Distance, Metric, XorMetric},
        portal_wire::ProtocolId,
    },
    utils::bytes::{hex_decode, hex_encode, ByteUtilsError},
    BeaconContentKey, ContentKeyError, HistoryContentKey, OverlayContentKey,
};
use trin_metrics::{portalnet::PORTALNET_METRICS, storage::StorageMetricsReporter};

const BYTES_IN_MB_U64: u64 = 1000 * 1000;

// TODO: Replace enum with generic type parameter. This will require that we have a way to
// associate a "find farthest" query with the generic Metric.
#[derive(Copy, Clone, Debug)]
pub enum DistanceFunction {
    Xor,
}

/// An error from an operation on a `ContentStore`.
#[derive(Debug, Error)]
pub enum ContentStoreError {
    #[error("An error from the underlying database: {0:?}")]
    Database(String),

    #[error("IO error: {0:?}")]
    Io(#[from] std::io::Error),

    /// Unable to store content because it does not fall within the store's radius.
    #[error("radius {radius} insufficient to store content at distance {distance}")]
    InsufficientRadius {
        radius: Distance,
        distance: Distance,
    },

    /// Unable to store or retrieve data because it is invalid.
    #[error("data invalid {message}")]
    InvalidData { message: String },

    #[error("rusqlite error {0}")]
    Rusqlite(#[from] rusqlite::Error),

    #[error("r2d2 error {0}")]
    R2D2(#[from] r2d2::Error),

    #[error("unable to use byte utils {0}")]
    ByteUtilsError(#[from] ByteUtilsError),

    #[error("unable to use content key {0}")]
    ContentKey(#[from] ContentKeyError),
}

/// An enum which tells us if we should store or not store content, and if not why for better
/// errors.
#[derive(Debug, PartialEq)]
pub enum ShouldWeStoreContent {
    Store,
    NotWithinRadius,
    AlreadyStored,
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
    ) -> Result<ShouldWeStoreContent, ContentStoreError>;

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
        let val = self.store.get(&key.to_vec()).cloned();
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
    ) -> Result<ShouldWeStoreContent, ContentStoreError> {
        let distance = self.distance_to_key(key);
        if distance > self.radius {
            return Ok(ShouldWeStoreContent::NotWithinRadius);
        }
        if self.contains_key(key) {
            return Ok(ShouldWeStoreContent::AlreadyStored);
        }
        Ok(ShouldWeStoreContent::Store)
    }

    fn radius(&self) -> Distance {
        self.radius
    }
}

/// Struct for configuring a `PortalStorage` instance.
#[derive(Clone)]
pub struct PortalStorageConfig {
    pub storage_capacity_mb: u64,
    pub node_id: NodeId,
    pub node_data_dir: PathBuf,
    pub distance_fn: DistanceFunction,
    pub sql_connection_pool: Pool<SqliteConnectionManager>,
}

impl PortalStorageConfig {
    pub fn new(
        storage_capacity_mb: u64,
        node_data_dir: PathBuf,
        node_id: NodeId,
    ) -> anyhow::Result<Self> {
        let sql_connection_pool = HistoryStorage::setup_sql(&node_data_dir)?;
        Ok(Self {
            storage_capacity_mb,
            node_id,
            node_data_dir,
            distance_fn: DistanceFunction::Xor,
            sql_connection_pool,
        })
    }
}

/// Struct whose public methods abstract away Kademlia-based store behavior.
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
    /// Public constructor for building a `PortalStorage` object.
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
        let mut query = conn.prepare(PAGINATE_QUERY)?;

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
        let mut query = conn.prepare(TOTAL_ENTRY_COUNT_QUERY)?;
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
        let mut query = conn.prepare(CONTENT_SIZE_LOOKUP_QUERY)?;
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
        let mut query = conn.prepare(CONTENT_KEY_LOOKUP_QUERY)?;
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
                let mut query = conn.prepare(XOR_FIND_FARTHEST_QUERY)?;

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

    /// Helper function for opening a SQLite connection.
    pub fn setup_sql(
        node_data_dir: &Path,
    ) -> Result<Pool<SqliteConnectionManager>, ContentStoreError> {
        let sql_path = node_data_dir.join("trin.sqlite");
        info!(path = %sql_path.display(), "Setting up SqliteDB");

        let manager = SqliteConnectionManager::file(sql_path);
        let pool = Pool::new(manager)?;
        pool.get()?.execute(CREATE_QUERY, params![])?;
        pool.get()?.execute(CREATE_LC_UPDATE_TABLE, params![])?;
        Ok(pool)
    }

    /// Get a summary of the current state of storage
    pub fn get_summary_info(&self) -> String {
        self.metrics.get_summary()
    }
}

/// Store ephemeral light client data in memory
#[derive(Debug)]
pub struct BeaconStorageCache {
    optimistic_update: Option<ForkVersionedLightClientOptimisticUpdate>,
    finality_update: Option<ForkVersionedLightClientFinalityUpdate>,
}

impl Default for BeaconStorageCache {
    fn default() -> Self {
        Self::new()
    }
}

impl BeaconStorageCache {
    pub fn new() -> Self {
        Self {
            optimistic_update: None,
            finality_update: None,
        }
    }

    /// Returns the optimistic update if it exists and matches the given signature slot.
    pub fn get_optimistic_update(
        &self,
        signature_slot: u64,
    ) -> Option<ForkVersionedLightClientOptimisticUpdate> {
        if self.optimistic_update.is_some() {
            let optimistic_update = self.optimistic_update.clone().expect("Can't be None");
            if optimistic_update.update.signature_slot() == &signature_slot {
                return Some(optimistic_update);
            }
        };

        None
    }

    /// Returns the finality update if it exists and matches the given finalized slot.
    pub fn get_finality_update(
        &self,
        finalized_slot: u64,
    ) -> Option<ForkVersionedLightClientFinalityUpdate> {
        if self.finality_update.is_some() {
            let finality_update = self.finality_update.clone().expect("Can't be None");
            // Returns the current finality update if it's finality slot is bigger or equal to the
            // requested slot.
            if finality_update
                .update
                .finalized_header_capella()
                .ok()?
                .beacon
                .slot
                >= finalized_slot
            {
                return Some(finality_update);
            }
        };

        None
    }

    /// Sets the light client optimistic update
    pub fn set_optimistic_update(
        &mut self,
        optimistic_update: ForkVersionedLightClientOptimisticUpdate,
    ) {
        self.optimistic_update = Some(optimistic_update);
    }

    /// Sets the light client finality update
    pub fn set_finality_update(&mut self, finality_update: ForkVersionedLightClientFinalityUpdate) {
        self.finality_update = Some(finality_update);
    }
}

/// A data store for Beacon Network content.
#[derive(Debug)]
pub struct BeaconStorage {
    node_data_dir: PathBuf,
    sql_connection_pool: Pool<SqliteConnectionManager>,
    storage_capacity_in_bytes: u64,
    metrics: StorageMetricsReporter,
    network: ProtocolId,
    cache: BeaconStorageCache,
}

impl ContentStore for BeaconStorage {
    fn get<K: OverlayContentKey>(&self, key: &K) -> Result<Option<Vec<u8>>, ContentStoreError> {
        let content_key: Vec<u8> = key.clone().into();
        let beacon_content_key =
            BeaconContentKey::from_ssz_bytes(content_key.as_slice()).map_err(|err| {
                ContentStoreError::InvalidData {
                    message: format!("Error deserializing BeaconContentKey value: {err:?}"),
                }
            })?;

        match beacon_content_key {
            BeaconContentKey::LightClientBootstrap(_) => {
                let content_id = key.content_id();
                self.lookup_content_value(content_id).map_err(|err| {
                    ContentStoreError::Database(format!(
                        "Error looking up LightClientBootstrap content value: {err:?}"
                    ))
                })
            }
            BeaconContentKey::LightClientUpdatesByRange(content_key) => {
                let periods =
                    content_key.start_period..(content_key.start_period + content_key.count);

                let mut content: Vec<ForkVersionedLightClientUpdate> = Vec::new();

                for period in periods {
                    let result = self.lookup_lc_update_value(period).map_err(|err| {
                        ContentStoreError::Database(format!(
                            "Error looking up LightClientUpdate content value: {err:?}"
                        ))
                    })?;

                    match result {
                        Some(result) => content.push(
                            ForkVersionedLightClientUpdate::from_ssz_bytes(result.as_slice())
                                .map_err(|err| {
                                    ContentStoreError::Database(format!(
                                    "Error ssz decode ForkVersionedLightClientUpdate value: {err:?}"
                                ))
                                })?,
                        ),
                        None => return Ok(None),
                    }
                }

                let result = VariableList::<ForkVersionedLightClientUpdate, U128>::new(content)
                    .map_err(|err| ContentStoreError::Database(
                        format!(
                            "Error building VariableList from ForkVersionedLightClientUpdate data: {err:?}"
                        ),
                    ))?;

                Ok(Some(result.as_ssz_bytes()))
            }
            BeaconContentKey::LightClientFinalityUpdate(content_key) => {
                match self.cache.get_finality_update(content_key.finalized_slot) {
                    Some(finality_update) => Ok(Some(finality_update.as_ssz_bytes())),
                    None => Ok(None),
                }
            }
            BeaconContentKey::LightClientOptimisticUpdate(content_key) => {
                match self.cache.get_optimistic_update(content_key.signature_slot) {
                    Some(optimistic_update) => Ok(Some(optimistic_update.as_ssz_bytes())),
                    None => Ok(None),
                }
            }
        }
    }

    fn put<K: OverlayContentKey, V: AsRef<[u8]>>(
        &mut self,
        key: K,
        value: V,
    ) -> Result<(), ContentStoreError> {
        self.store(&key, &value.as_ref().to_vec())
    }

    /// The "radius: concept is not applicable for Beacon network
    fn is_key_within_radius_and_unavailable<K: OverlayContentKey>(
        &self,
        key: &K,
    ) -> Result<ShouldWeStoreContent, ContentStoreError> {
        let content_key: Vec<u8> = key.clone().into();
        let beacon_content_key =
            BeaconContentKey::from_ssz_bytes(content_key.as_slice()).map_err(|err| {
                ContentStoreError::InvalidData {
                    message: format!("Error deserializing BeaconContentKey value: {err:?}"),
                }
            })?;

        match beacon_content_key {
            BeaconContentKey::LightClientBootstrap(_) => {
                let key = key.content_id();
                let is_key_available = self
                    .lookup_content_key(key)
                    .map_err(|err| {
                        ContentStoreError::Database(format!(
                            "Error looking up content key: {err:?}"
                        ))
                    })?
                    .is_some();
                if is_key_available {
                    return Ok(ShouldWeStoreContent::AlreadyStored);
                }
                Ok(ShouldWeStoreContent::Store)
            }
            BeaconContentKey::LightClientUpdatesByRange(content_key) => {
                // Check if any of the periods are available, return AlreadyStored if so otherwise
                // Store
                let periods =
                    content_key.start_period..(content_key.start_period + content_key.count);

                for period in periods {
                    let is_period_available = self
                        .lookup_lc_update_period(period)
                        .map_err(|err| {
                            ContentStoreError::Database(format!(
                                "Error looking up lc update period: {err:?}"
                            ))
                        })?
                        .is_some();
                    if is_period_available {
                        return Ok(ShouldWeStoreContent::AlreadyStored);
                    }
                }
                Ok(ShouldWeStoreContent::Store)
            }
            BeaconContentKey::LightClientFinalityUpdate(content_key) => {
                match self.cache.get_finality_update(content_key.finalized_slot) {
                    Some(_) => Ok(ShouldWeStoreContent::AlreadyStored),
                    None => Ok(ShouldWeStoreContent::Store),
                }
            }
            BeaconContentKey::LightClientOptimisticUpdate(content_key) => {
                match self.cache.get_optimistic_update(content_key.signature_slot) {
                    Some(_) => Ok(ShouldWeStoreContent::AlreadyStored),
                    None => Ok(ShouldWeStoreContent::Store),
                }
            }
        }
    }

    /// The "radius: concept is not applicable for Beacon network, this is why we always return the
    /// max radius.
    fn radius(&self) -> Distance {
        Distance::MAX
    }
}

impl BeaconStorage {
    pub fn new(config: PortalStorageConfig) -> Result<Self, ContentStoreError> {
        let metrics = StorageMetricsReporter {
            storage_metrics: PORTALNET_METRICS.storage(),
            protocol: ProtocolId::Beacon.to_string(),
        };
        let storage = Self {
            node_data_dir: config.node_data_dir,
            sql_connection_pool: config.sql_connection_pool,
            storage_capacity_in_bytes: config.storage_capacity_mb * BYTES_IN_MB_U64,
            metrics,
            network: ProtocolId::Beacon,
            cache: BeaconStorageCache::new(),
        };

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

    fn db_insert(
        &self,
        content_id: &[u8; 32],
        content_key: &String,
        value: &Vec<u8>,
    ) -> Result<(), ContentStoreError> {
        let conn = self.sql_connection_pool.get()?;
        insert_value(conn, content_id, content_key, value, u8::from(self.network))
    }

    fn db_insert_lc_update(&self, period: &u64, value: &Vec<u8>) -> Result<(), ContentStoreError> {
        let conn = self.sql_connection_pool.get()?;
        let value_size = value.len();

        match conn.execute(
            INSERT_LC_UPDATE_QUERY,
            params![period, value, 0, value_size],
        ) {
            Ok(_) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    pub fn store(
        &mut self,
        key: &impl OverlayContentKey,
        value: &Vec<u8>,
    ) -> Result<(), ContentStoreError> {
        let content_id = key.content_id();
        let content_key: Vec<u8> = key.clone().into();

        match content_key.first() {
            Some(&LIGHT_CLIENT_BOOTSTRAP_KEY_PREFIX) => {
                // store content key w/o the 0x prefix
                let content_key = hex_encode(content_key).trim_start_matches("0x").to_string();
                if let Err(err) = self.db_insert(&content_id, &content_key, value) {
                    debug!("Error writing light client bootstrap content ID {content_id:?} to beacon network db: {err:?}");
                    return Err(err);
                } else {
                    self.metrics.increase_entry_count();
                }
            }
            Some(&LIGHT_CLIENT_UPDATES_BY_RANGE_KEY_PREFIX) => {
                if let Ok(update) = BeaconContentKey::from_ssz_bytes(content_key.as_slice()) {
                    match update {
                        BeaconContentKey::LightClientUpdatesByRange(update) => {
                            // Build a range of values starting with update.start_period and len
                            // update.count
                            let periods = update.start_period..(update.start_period + update.count);
                            let update_values = LightClientUpdatesByRange::from_ssz_bytes(
                                value.as_slice(),
                            )
                            .map_err(|err| {
                                ContentStoreError::InvalidData {
                                    message: format!(
                                        "Error deserializing LightClientUpdatesByRange value: {err:?}"
                                    ),
                                }
                            })?;

                            for (period, value) in periods.zip(update_values.as_ref()) {
                                if let Err(err) = self.db_insert_lc_update(&period, &value.encode())
                                {
                                    debug!("Error writing light client update by range content ID {content_id:?} to beacon network db: {err:?}");
                                } else {
                                    self.metrics.increase_entry_count();
                                }
                            }
                        }
                        _ => {
                            // Unknown content type
                            return Err(ContentStoreError::InvalidData {
                                message: "Unexpected LightClientUpdatesByRange content key"
                                    .to_string(),
                            });
                        }
                    }
                }
            }
            Some(&LIGHT_CLIENT_FINALITY_UPDATE_KEY_PREFIX) => {
                self.cache.set_finality_update(
                    ForkVersionedLightClientFinalityUpdate::from_ssz_bytes(value.as_slice())
                        .map_err(|err| ContentStoreError::InvalidData {
                            message: format!(
                                "Error deserializing ForkVersionedLightClientFinalityUpdate value: {err:?}"
                            ),
                        })?,
                );
            }
            Some(&LIGHT_CLIENT_OPTIMISTIC_UPDATE_KEY_PREFIX) => {
                self.cache.set_optimistic_update(
                    ForkVersionedLightClientOptimisticUpdate::from_ssz_bytes(value.as_slice()).map_err(
                        |err| ContentStoreError::InvalidData {
                            message: format!(
                                "Error deserializing ForkVersionedLightClientOptimisticUpdate value: {err:?}"
                            ),
                        },
                    )?,
                );
            }
            _ => {
                // Unknown content type
                return Err(ContentStoreError::InvalidData {
                    message: "Unknown beacon content key".to_string(),
                });
            }
        }

        let total_bytes_on_disk = self.get_total_storage_usage_in_bytes_on_disk()?;
        self.metrics
            .report_total_storage_usage_bytes(total_bytes_on_disk as f64);

        Ok(())
    }

    pub fn paginate(
        &self,
        _offset: &u64,
        _limit: &u64,
    ) -> Result<ethportal_api::types::beacon::PaginateLocalContentInfo, ContentStoreError> {
        Err(ContentStoreError::Database(
            "Paginate not implemented for Beacon storage".to_string(),
        ))
    }

    /// Public method for determining how much actual disk space is being used to store this node's
    /// Portal Network data. Intended for analysis purposes. PortalStorage's capacity
    /// decision-making is not based off of this method.
    pub fn get_total_storage_usage_in_bytes_on_disk(&self) -> Result<u64, ContentStoreError> {
        let storage_usage = get_total_size_of_directory_in_bytes(&self.node_data_dir)?;
        Ok(storage_usage)
    }

    /// Internal method for measuring the total amount of requestable data that the node is storing.
    fn get_total_storage_usage_in_bytes_from_network(&self) -> Result<u64, ContentStoreError> {
        let conn = self.sql_connection_pool.get()?;
        let mut query = conn.prepare(TOTAL_DATA_SIZE_QUERY)?;

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

    /// Public method for looking up a content key by its content id
    pub fn lookup_content_key(&self, id: [u8; 32]) -> anyhow::Result<Option<Vec<u8>>> {
        let conn = self.sql_connection_pool.get()?;
        let mut query = conn.prepare(CONTENT_KEY_LOOKUP_QUERY)?;
        let id = id.to_vec();
        let result: Result<Vec<BeaconContentKey>, ContentStoreError> = query
            .query_map([id], |row| {
                let row: String = row.get(0)?;
                Ok(row)
            })?
            .map(|row| {
                // value is stored without 0x prefix, so we must add it
                let bytes: Vec<u8> = hex_decode(&format!("0x{}", row?))?;
                BeaconContentKey::try_from(bytes).map_err(ContentStoreError::ContentKey)
            })
            .collect();

        match result?.first() {
            Some(val) => Ok(Some(val.into())),
            None => Ok(None),
        }
    }

    /// Public method for looking up a light client update by period number
    pub fn lookup_lc_update_period(&self, period: u64) -> anyhow::Result<Option<u64>> {
        let conn = self.sql_connection_pool.get()?;
        let mut query = conn.prepare(LC_UPDATE_PERIOD_LOOKUP_QUERY)?;

        let rows: Result<Vec<u64>, rusqlite::Error> = query
            .query_map([period], |row| {
                let row: u64 = row.get(0)?;
                Ok(row)
            })?
            .collect();

        match rows?.first() {
            Some(val) => Ok(Some(*val)),
            None => Ok(None),
        }
    }

    /// Public method for looking up a content value by its content id
    pub fn lookup_content_value(&self, id: [u8; 32]) -> anyhow::Result<Option<Vec<u8>>> {
        let conn = self.sql_connection_pool.get()?;
        lookup_content_value(id, conn)?
    }

    /// Public method for looking up a  light client update value by period number
    pub fn lookup_lc_update_value(&self, period: u64) -> anyhow::Result<Option<Vec<u8>>> {
        let conn = self.sql_connection_pool.get()?;
        let mut query = conn.prepare(LC_UPDATE_LOOKUP_QUERY)?;

        let rows: Result<Vec<Vec<u8>>, rusqlite::Error> = query
            .query_map([period], |row| {
                let row: Vec<u8> = row.get(0)?;
                Ok(row)
            })?
            .collect();

        match rows?.first() {
            Some(val) => Ok(Some(val.to_vec())),
            None => Ok(None),
        }
    }

    /// Get a summary of the current state of storage
    pub fn get_summary_info(&self) -> String {
        self.metrics.get_summary()
    }
}

/// Internal method used to measure on-disk storage usage.
fn get_total_size_of_directory_in_bytes(path: impl AsRef<Path>) -> Result<u64, ContentStoreError> {
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
            size += get_total_size_of_directory_in_bytes(path_string)?;
        }
    }

    Ok(size)
}

/// Internal method for looking up a content value by its content id
fn lookup_content_value(
    id: [u8; 32],
    conn: PooledConnection<SqliteConnectionManager>,
) -> Result<Result<Option<Vec<u8>>, Error>, Error> {
    let mut query = conn.prepare(CONTENT_VALUE_LOOKUP_QUERY)?;
    let id = id.to_vec();
    let result: Result<Vec<Vec<u8>>, ContentStoreError> = query
        .query_map([id], |row| {
            let row: String = row.get(0)?;
            Ok(row)
        })?
        .map(|row| hex_decode(row?.as_str()).map_err(ContentStoreError::ByteUtilsError))
        .collect();

    Ok(match result?.first() {
        Some(val) => Ok(Some(val.to_vec())),
        None => Ok(None),
    })
}

/// Converts most significant 4 bytes of a vector to a u32.
fn byte_vector_to_u32(vec: Vec<u8>) -> u32 {
    if vec.len() < 4 {
        debug!("Error: XOR returned less than 4 bytes.");
        return 0;
    }

    let mut array: [u8; 4] = [0, 0, 0, 0];
    for (index, byte) in vec.iter().take(4).enumerate() {
        array[index] = *byte;
    }

    u32::from_be_bytes(array)
}

/// Inserts a content  into the database.
fn insert_value(
    conn: PooledConnection<SqliteConnectionManager>,
    content_id: &[u8; 32],
    content_key: &String,
    value: &Vec<u8>,
    network_id: u8,
) -> Result<(), ContentStoreError> {
    let content_id_as_u32: u32 = byte_vector_to_u32(content_id.to_vec());
    let value_size = value.len();
    if content_key.starts_with("0x") {
        return Err(ContentStoreError::InvalidData {
            message: "Content key should not start with 0x".to_string(),
        });
    }
    match conn.execute(
        INSERT_QUERY,
        params![
            content_id.to_vec(),
            content_id_as_u32,
            content_key,
            hex_encode(value),
            network_id,
            value_size
        ],
    ) {
        Ok(_) => Ok(()),
        Err(err) => Err(err.into()),
    }
}

// SQLite Statements
const CREATE_QUERY: &str = "CREATE TABLE IF NOT EXISTS content_data (
                                content_id_long TEXT PRIMARY KEY,
                                content_id_short INTEGER NOT NULL,
                                content_key TEXT NOT NULL,
                                content_value TEXT NOT NULL,
                                network INTEGER NOT NULL DEFAULT 0,
                                content_size INTEGER
                            );
                            CREATE INDEX content_size_idx ON content_data(content_size);
                            CREATE INDEX content_id_short_idx ON content_data(content_id_short);
                            CREATE INDEX content_id_long_idx ON content_data(content_id_long);
                            CREATE INDEX network_idx ON content_data(network);";

const INSERT_QUERY: &str =
    "INSERT OR IGNORE INTO content_data (content_id_long, content_id_short, content_key, content_value, network, content_size)
                            VALUES (?1, ?2, ?3, ?4, ?5, ?6)";

const INSERT_LC_UPDATE_QUERY: &str =
    "INSERT OR IGNORE INTO lc_update (period, value, score, update_size)
                            VALUES (?1, ?2, ?3, ?4)";

const DELETE_QUERY: &str = "DELETE FROM content_data
                            WHERE content_id_long = (?1)";

const XOR_FIND_FARTHEST_QUERY: &str = "SELECT
                                    content_id_long
                                    FROM content_data
                                    WHERE network = (?2)
                                    ORDER BY ((?1 | content_id_short) - (?1 & content_id_short)) DESC";

const CONTENT_KEY_LOOKUP_QUERY: &str =
    "SELECT content_key FROM content_data WHERE content_id_long = (?1) LIMIT 1";

const CONTENT_VALUE_LOOKUP_QUERY: &str =
    "SELECT content_value FROM content_data WHERE content_id_long = (?1) LIMIT 1";

const TOTAL_DATA_SIZE_QUERY: &str = "SELECT TOTAL(content_size) FROM content_data";

const TOTAL_ENTRY_COUNT_QUERY: &str =
    "SELECT COUNT(content_id_long) FROM content_data WHERE network = (?1)";

const PAGINATE_QUERY: &str =
    "SELECT content_key FROM content_data ORDER BY content_key LIMIT :limit OFFSET :offset";

const CONTENT_SIZE_LOOKUP_QUERY: &str =
    "SELECT content_size FROM content_data WHERE content_id_long = (?1)";

const CREATE_LC_UPDATE_TABLE: &str = "CREATE TABLE IF NOT EXISTS lc_update (
                                          period INTEGER PRIMARY KEY,
                                          value BLOB NOT NULL,
                                          score INTEGER NOT NULL,
                                          update_size INTEGER
                                      );
                                     CREATE INDEX update_size_idx ON lc_update(update_size);
                                     CREATE INDEX period_idx ON lc_update(period);";

const LC_UPDATE_LOOKUP_QUERY: &str = "SELECT value FROM lc_update WHERE period = (?1) LIMIT 1";

const LC_UPDATE_PERIOD_LOOKUP_QUERY: &str =
    "SELECT period FROM lc_update WHERE period = (?1) LIMIT 1";

// SQLite Result Containers
struct ContentId {
    id_long: Vec<u8>,
}

struct DataSize {
    num_bytes: f64,
}

struct EntryCount(u64);

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub mod test {

    use super::*;

    use discv5::enr::{CombinedKey, Enr as Discv5Enr};
    use quickcheck::{quickcheck, QuickCheck, TestResult};
    use rand::RngCore;
    use serial_test::serial;

    use crate::utils::db::{configure_node_data_dir, setup_temp_dir};
    use ethportal_api::{types::content_key::overlay::IdentityContentKey, BlockHeaderKey};

    const CAPACITY_MB: u64 = 2;

    fn generate_random_content_key() -> IdentityContentKey {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        IdentityContentKey::new(key)
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
        assert_eq!(
            store
                .is_key_within_radius_and_unavailable(&arb_key)
                .unwrap(),
            ShouldWeStoreContent::Store
        );

        // Arbitrary key available.
        let _ = store.put(arb_key.clone(), val);
        assert_eq!(
            store
                .is_key_within_radius_and_unavailable(&arb_key)
                .unwrap(),
            ShouldWeStoreContent::AlreadyStored
        );
    }

    #[test]
    fn test_precision_for_percentage() {
        fn formatted_percent(ratio: f64) -> String {
            let precision = StorageMetricsReporter::precision_for_percentage(ratio * 100.0);
            format!("{:.*}%", precision, ratio * 100.0)
        }
        assert_eq!(formatted_percent(1.0), "100%");
        assert_eq!(formatted_percent(0.9999), "100%");
        assert_eq!(formatted_percent(0.9949), "99%");

        assert_eq!(formatted_percent(0.10001), "10%");
        assert_eq!(formatted_percent(0.1), "10%");
        assert_eq!(formatted_percent(0.09949), "9.9%");

        assert_eq!(formatted_percent(0.010001), "1.0%");
        assert_eq!(formatted_percent(0.01), "1.0%");
        assert_eq!(formatted_percent(0.009949), "0.99%");

        assert_eq!(formatted_percent(0.0010001), "0.10%");
        assert_eq!(formatted_percent(0.001), "0.10%");
        assert_eq!(formatted_percent(0.0009949), "0.099%");

        assert_eq!(formatted_percent(0.00010001), "0.010%");
        assert_eq!(formatted_percent(0.0001), "0.010%");
        assert_eq!(formatted_percent(0.00009949), "0.0099%");

        assert_eq!(formatted_percent(0.000010001), "0.0010%");
        assert_eq!(formatted_percent(0.00001), "0.0010%");
        assert_eq!(formatted_percent(0.0000095), "0.0010%");
        assert_eq!(formatted_percent(0.00000949), "0.0009%");

        assert_eq!(formatted_percent(0.0000010001), "0.0001%");
        assert_eq!(formatted_percent(0.000001), "0.0001%");
        assert_eq!(formatted_percent(0.0000009949), "0.0001%");
        assert_eq!(formatted_percent(0.0000005001), "0.0001%");
        assert_eq!(formatted_percent(0.0000004999), "0.0000%");
        assert_eq!(formatted_percent(0.0), "0.0000%");

        // We mostly care that values outside of [0.0, 1.0] do not crash, but
        // for now we also check that they pin to 0 or 4.
        assert_eq!(StorageMetricsReporter::precision_for_percentage(101.0), 0);
        assert_eq!(StorageMetricsReporter::precision_for_percentage(-0.001), 4);
        assert_eq!(StorageMetricsReporter::precision_for_percentage(-1000.0), 4);
    }

    fn get_active_node_id(temp_dir: PathBuf) -> NodeId {
        let (_, mut pk) = configure_node_data_dir(temp_dir, None).unwrap();
        let pk = CombinedKey::secp256k1_from_bytes(pk.0.as_mut_slice()).unwrap();
        Discv5Enr::empty(&pk).unwrap().node_id()
    }
}
