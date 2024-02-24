use ethportal_api::types::distance::Distance;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{named_params, types::Type, OptionalExtension};
use tracing::{debug, error, warn};
use trin_metrics::storage::StorageMetricsReporter;

use super::{sql, usage_stats::UsageStats, IdIndexedV1StoreConfig};
use crate::{
    error::ContentStoreError,
    utils::get_total_size_of_directory_in_bytes,
    versioned::{ContentType, StoreVersion, VersionedContentStore},
    ContentId,
};

struct FarthestQueryResult {
    content_id: ContentId,
    distance_u32: u32,
}

/// The store for storing content key/value pairs.
///
/// Different SQL table is created for each `ContentType`, with content-id as a primary key.
/// It has a configurable capacity and it will prune data that is farthest from the `NodeId` once
/// it's close to that capacity.
#[derive(Debug)]
pub struct IdIndexedV1Store {
    /// The config.
    config: IdIndexedV1StoreConfig,
    /// Estimated number of new inserts required for pruning.
    inserts_until_pruning: u64,
    /// The maximum distance between `NodeId` and content id that store should keep. Updated
    /// dynamically after pruning to the farthest distance still stored.
    radius: Distance,
    /// The Metrics for tracking performance.
    metrics: StorageMetricsReporter,
}

impl VersionedContentStore for IdIndexedV1Store {
    type Config = IdIndexedV1StoreConfig;

    fn version() -> StoreVersion {
        StoreVersion::IdIndexedV1
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
        maybe_create_table_and_indexes(&content_type, &config.sql_connection_pool)?;

        let protocol_id = config.network;

        let mut store = Self {
            config,
            inserts_until_pruning: 0,
            radius: Distance::MAX,
            metrics: StorageMetricsReporter::new(protocol_id),
        };
        store.init()?;
        Ok(store)
    }
}

impl IdIndexedV1Store {
    /// Initializes variables and metrics, and runs necessary checks.
    fn init(&mut self) -> Result<(), ContentStoreError> {
        self.metrics
            .report_storage_capacity_bytes(self.config.storage_capacity_bytes as f64);

        let usage_stats = self.get_usage_stats()?;

        if usage_stats.is_above_target_capacity(&self.config) {
            debug!(
                Db = %self.config.content_type,
                "Used capacity ({}) is over target capacity ({}) -> Pruning",
                usage_stats.used_storage_bytes,
                self.config.target_capacity()
            );
            self.prune(usage_stats)?;
        } else {
            debug!(
                Db = %self.config.content_type,
                "Used capacity ({}) is under target capacity ({}) -> Using MAX radius",
                usage_stats.used_storage_bytes,
                self.config.target_capacity()
            );
            self.radius = Distance::MAX;
            self.metrics.report_radius(self.radius);
            self.update_inserts_until_pruning(&usage_stats);
        }

        // Check that distance to the farthest content is what is stored. This is a simple check
        // that the NodeId didn't change.
        let farthest = self.lookup_farthest()?;
        if let Some(farthest) = farthest {
            let distance = self.distance_to_content_id(&farthest.content_id);
            if farthest.distance_u32 != distance.big_endian_u32() {
                return Err(ContentStoreError::Database(format!(
                    "Distance to the farthest (short: 0x{:08X}) didn't match expected distance ({distance})!",
                    farthest.distance_u32
                )));
            }
        }

        Ok(())
    }

    // PUBLIC FUNCTIONS

    /// Returns radius that it will accept to store.
    pub fn radius(&self) -> Distance {
        self.radius
    }

    /// Returns distance to the content id.
    pub fn distance_to_content_id(&self, content_id: &ContentId) -> Distance {
        self.config
            .distance_fn
            .distance(&self.config.node_id, content_id.as_fixed_bytes())
    }

    /// Returns whether data associated with the content id is already stored.
    pub fn has_content(&self, content_id: &ContentId) -> Result<bool, ContentStoreError> {
        let timer = self.metrics.start_process_timer("has_content");

        let has_content = self
            .config
            .sql_connection_pool
            .get()?
            .prepare(&sql::lookup_key(&self.config.content_type))?
            .exists(named_params! {
                ":content_id": content_id.as_fixed_bytes().to_vec(),
            })?;

        self.metrics.stop_process_timer(timer);
        Ok(has_content)
    }

    /// Returns content key data is stored.
    pub fn lookup_content_key<K: ethportal_api::OverlayContentKey>(
        &self,
        content_id: &ContentId,
    ) -> Result<Option<K>, ContentStoreError> {
        let timer = self.metrics.start_process_timer("lookup_content_key");

        let key = self
            .config
            .sql_connection_pool
            .get()?
            .query_row(
                &sql::lookup_key(&self.config.content_type),
                named_params! {
                    ":content_id": content_id.as_fixed_bytes().to_vec(),
                },
                |row| {
                    let bytes: Vec<u8> = row.get("content_key")?;
                    K::try_from(bytes).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(0, Type::Blob, e.into())
                    })
                },
            )
            .optional()?;

        self.metrics.stop_process_timer(timer);
        Ok(key)
    }

    /// Returns content value data is stored.
    pub fn lookup_content_value(
        &self,
        content_id: &ContentId,
    ) -> Result<Option<Vec<u8>>, ContentStoreError> {
        let timer = self.metrics.start_process_timer("lookup_content_value");

        let value = self
            .config
            .sql_connection_pool
            .get()?
            .query_row(
                &sql::lookup_value(&self.config.content_type),
                named_params! {
                    ":content_id": content_id.as_fixed_bytes().to_vec(),
                },
                |row| row.get::<&str, Vec<u8>>("content_value"),
            )
            .optional()?;

        self.metrics.stop_process_timer(timer);
        Ok(value)
    }

    /// Inserts content key/value pair into storage and prunes the db if necessary. It will return
    /// `InsufficientRadius` error if content is outside radius.
    pub fn insert<K: ethportal_api::OverlayContentKey>(
        &mut self,
        content_key: &K,
        content_value: Vec<u8>,
    ) -> Result<(), ContentStoreError> {
        let insert_with_pruning_timer = self.metrics.start_process_timer("insert_with_pruning");

        let content_id = content_key.content_id();

        let distance = self.distance_to_content_id(&content_id.into());
        if self.radius < distance {
            return Err(ContentStoreError::InsufficientRadius {
                radius: self.radius,
                distance,
            });
        }

        let content_id = content_id.to_vec();
        let content_key = content_key.to_bytes();
        let content_size = content_id.len() + content_key.len() + content_value.len();

        let insert_timer = self.metrics.start_process_timer("insert");
        self.config.sql_connection_pool.get()?.execute(
            &sql::insert(&self.config.content_type),
            named_params! {
                ":content_id": content_id,
                ":content_key": content_key,
                ":content_value": content_value,
                ":distance_short": distance.big_endian_u32(),
                ":content_size": content_size,
            },
        )?;
        self.metrics.stop_process_timer(insert_timer);
        self.metrics.increase_entry_count();

        if self.inserts_until_pruning > 1 {
            self.inserts_until_pruning -= 1;
        } else {
            let usage_stats = self.get_usage_stats()?;
            if usage_stats.is_above_pruning_capacity_threshold(&self.config) {
                self.prune(usage_stats)?
            } else {
                self.update_inserts_until_pruning(&usage_stats);
            }
        }

        self.metrics.stop_process_timer(insert_with_pruning_timer);
        Ok(())
    }

    /// Deletes content with the given content id.
    pub fn delete(&mut self, content_id: &ContentId) -> Result<(), ContentStoreError> {
        let timer = self.metrics.start_process_timer("delete");
        self.config.sql_connection_pool.get()?.execute(
            &sql::delete(&self.config.content_type),
            named_params! {
                ":content_id": content_id.as_fixed_bytes().to_vec(),
            },
        )?;
        self.metrics.decrease_entry_count();

        self.metrics.stop_process_timer(timer);
        Ok(())
    }

    /// Updates metrics and returns summary.
    pub fn get_summary_info(&self) -> String {
        // Call `get_usage_stats` to update metrics.
        if let Err(err) = self.get_usage_stats() {
            warn!(Db = %self.config.content_type, "Error while getting summary info: {err}");
        }
        self.metrics.get_summary()
    }

    // INTERNAL FUNCTIONS

    /// Returns usage stats and updates relevant metrics.
    fn get_usage_stats(&self) -> Result<UsageStats, ContentStoreError> {
        let timer = self.metrics.start_process_timer("get_usage_stats");

        let conn = self.config.sql_connection_pool.get()?;
        let usage_stats = conn.query_row(
            &sql::entry_count_and_size(&self.config.content_type),
            [],
            |row| {
                let used_capacity: f64 = row.get("used_capacity")?;
                Ok(UsageStats {
                    content_count: row.get("count")?,
                    used_storage_bytes: used_capacity.round() as u64,
                })
            },
        )?;

        self.metrics.report_entry_count(usage_stats.content_count);
        self.metrics
            .report_content_data_storage_bytes(usage_stats.used_storage_bytes as f64);

        // This reports size of the entire database.
        self.metrics
            .report_total_storage_usage_bytes(get_total_size_of_directory_in_bytes(
                &self.config.node_data_dir,
            )? as f64);

        self.metrics.stop_process_timer(timer);
        Ok(usage_stats)
    }

    /// Returns the farthest content in the table.
    fn lookup_farthest(&self) -> Result<Option<FarthestQueryResult>, ContentStoreError> {
        let timer = self.metrics.start_process_timer("lookup_farthest");
        let farthest = self
            .config
            .sql_connection_pool
            .get()?
            .query_row(
                &sql::lookup_farthest(&self.config.content_type),
                named_params! {
                    ":limit": 1,
                },
                |row| {
                    Ok(FarthestQueryResult {
                        content_id: row.get("content_id")?,
                        distance_u32: row.get("distance_short")?,
                    })
                },
            )
            .optional()?;

        self.metrics.stop_process_timer(timer);
        Ok(farthest)
    }

    /// Prunes database, and updates radius and inserts_until_pruning.
    fn prune(&mut self, usage_stats: UsageStats) -> Result<(), ContentStoreError> {
        let timer = self.metrics.start_process_timer("prune");

        if !usage_stats.is_above_target_capacity(&self.config) {
            warn!(Db = %self.config.content_type, "Pruning requested but we are below target capacity. Skipping");
            return Ok(());
        }

        let conn = self.config.sql_connection_pool.get()?;
        let mut delete_query = conn.prepare(&sql::delete_farthest(&self.config.content_type))?;

        let mut usage_stats = usage_stats;
        while usage_stats.is_above_pruning_capacity_threshold(&self.config) {
            let to_delete = usage_stats.delete_until_target(&self.config);

            if to_delete == 0 {
                warn!(Db = %self.config.content_type, "Should delete 0. This is not expected to happen (we should be above pruning capacity).");
                return Ok(());
            }

            let deleted = delete_query.execute(named_params! {
               ":limit": to_delete
            })? as u64;

            if to_delete != deleted {
                error!(Db = %self.config.content_type, "Attempted to delete {to_delete} but deleted {deleted}");
                break;
            }

            usage_stats = self.get_usage_stats()?;
        }
        // Free connection.
        drop(delete_query);
        drop(conn);

        self.update_inserts_until_pruning(&usage_stats);

        // Update radius to the current farthest content
        match self.lookup_farthest()? {
            None => {
                error!(Db = %self.config.content_type, "Farthest not found after pruning!");
            }
            Some(farthest) => {
                self.radius = self.distance_to_content_id(&farthest.content_id);
            }
        }
        self.metrics.report_radius(self.radius);

        self.metrics.stop_process_timer(timer);
        Ok(())
    }

    /// Updated `inserts_until_pruning` based on current usage stats. We aim to prune once we reach
    /// full capacity, but in reality we will prune if we are above `pruning_capacity_threshold()`.
    fn update_inserts_until_pruning(&mut self, usage_stats: &UsageStats) {
        self.inserts_until_pruning = usage_stats.estimate_insert_until_full(&self.config);
    }
}

/// Creates table and indexes if they don't already exist.
fn maybe_create_table_and_indexes(
    content_type: &ContentType,
    pool: &Pool<SqliteConnectionManager>,
) -> Result<(), ContentStoreError> {
    let conn = pool.get()?;
    conn.execute_batch(&sql::create_table(content_type))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use discv5::enr::NodeId;
    use ethportal_api::{types::portal_wire::ProtocolId, IdentityContentKey, OverlayContentKey};
    use tempfile::TempDir;

    use crate::{test_utils::generate_random_bytes, utils::setup_sql, DistanceFunction};

    use super::*;

    const STORAGE_CAPACITY_10KB_IN_BYTES: u64 = 10_000;
    const CONTENT_SIZE_100_BYTES: u64 = STORAGE_CAPACITY_10KB_IN_BYTES / 100;

    fn create_config(temp_dir: &TempDir) -> IdIndexedV1StoreConfig {
        IdIndexedV1StoreConfig {
            content_type: ContentType::State,
            network: ProtocolId::State,
            node_id: NodeId::random(),
            node_data_dir: temp_dir.path().to_path_buf(),
            distance_fn: DistanceFunction::Xor,
            sql_connection_pool: setup_sql(temp_dir.path()).unwrap(),
            storage_capacity_bytes: STORAGE_CAPACITY_10KB_IN_BYTES,
        }
    }

    /// Creates content key/value pair that are exactly 1% of the Storage capacity.
    fn generate_key_value(
        config: &IdIndexedV1StoreConfig,
        distance: u8,
    ) -> (IdentityContentKey, Vec<u8>) {
        generate_key_value_with_content_size(config, distance, STORAGE_CAPACITY_10KB_IN_BYTES / 100)
    }

    fn generate_key_value_with_content_size(
        config: &IdIndexedV1StoreConfig,
        distance: u8,
        content_size: u64,
    ) -> (IdentityContentKey, Vec<u8>) {
        let mut key = rand::random::<[u8; 32]>();
        key[0] = config.node_id.raw()[0] ^ distance;
        let key = IdentityContentKey::new(key);

        if content_size < 2 * 32 {
            panic!("Content size of at least 64 bytes is required (32 for id + 32 for key)")
        }
        let value = generate_random_bytes((content_size - 2 * 32) as usize);
        (key, value)
    }

    // Creates table and content at approximate middle distance (first byte distance is 0.80).
    fn create_and_populate_table(config: &IdIndexedV1StoreConfig, count: u64) -> Result<()> {
        maybe_create_table_and_indexes(&config.content_type, &config.sql_connection_pool)?;
        for _ in 0..count {
            let (key, value) = generate_key_value(config, 0x80);
            let id = key.content_id();
            let content_size = id.len() + key.to_bytes().len() + value.len();
            config
                .sql_connection_pool
                .get()?
                .execute(&sql::insert(&config.content_type), named_params! {
                    ":content_id": id.as_slice(),
                    ":content_key": key.to_bytes(),
                    ":content_value": value,
                    ":distance_short": config.distance_fn.distance(&config.node_id, &id).big_endian_u32(),
                    ":content_size": content_size,
                })?;
        }
        Ok(())
    }

    #[test]
    fn create_empty() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir);
        let store = IdIndexedV1Store::create(ContentType::State, config)?;
        assert_eq!(store.radius(), Distance::MAX);
        assert_eq!(store.inserts_until_pruning, 0);
        Ok(())
    }

    #[test]
    fn create_low_usage_full() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir);

        let item_count = 20;
        create_and_populate_table(&config, item_count)?;

        let store = IdIndexedV1Store::create(ContentType::State, config)?;
        let usage_stats = store.get_usage_stats()?;

        assert_eq!(usage_stats.content_count, item_count);
        assert_eq!(
            usage_stats.used_storage_bytes,
            item_count * CONTENT_SIZE_100_BYTES
        );
        assert_eq!(store.radius(), Distance::MAX);
        assert_eq!(store.inserts_until_pruning, item_count);
        Ok(())
    }

    #[test]
    fn create_half_full() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir);

        let item_count = 50;
        create_and_populate_table(&config, item_count)?;

        let store = IdIndexedV1Store::create(ContentType::State, config)?;
        let usage_stats = store.get_usage_stats()?;

        assert_eq!(usage_stats.content_count, item_count);
        assert_eq!(
            usage_stats.used_storage_bytes,
            item_count * CONTENT_SIZE_100_BYTES
        );
        assert_eq!(store.radius(), Distance::MAX);
        assert_eq!(store.inserts_until_pruning, 100 - item_count);
        Ok(())
    }

    #[test]
    fn create_at_target_capacity() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir);

        let target_capacity_count = config.target_capacity() / CONTENT_SIZE_100_BYTES;
        create_and_populate_table(&config, target_capacity_count)?;

        let store = IdIndexedV1Store::create(ContentType::State, config)?;
        let usage_stats = store.get_usage_stats()?;
        assert_eq!(usage_stats.content_count, target_capacity_count);
        assert_eq!(
            usage_stats.used_storage_bytes,
            target_capacity_count * CONTENT_SIZE_100_BYTES
        );
        assert_eq!(store.radius(), Distance::MAX);
        assert_eq!(store.inserts_until_pruning, 100 - target_capacity_count);
        Ok(())
    }

    #[test]
    fn create_at_pruning_capacity() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir);

        let pruning_capacity_count = config.pruning_capacity_threshold() / CONTENT_SIZE_100_BYTES;
        create_and_populate_table(&config, pruning_capacity_count)?;

        let store = IdIndexedV1Store::create(ContentType::State, config)?;
        let usage_stats = store.get_usage_stats()?;

        // no pruning should happen
        assert_eq!(usage_stats.content_count, pruning_capacity_count);
        assert_eq!(
            usage_stats.used_storage_bytes,
            pruning_capacity_count * CONTENT_SIZE_100_BYTES
        );
        assert!(store.radius() < Distance::MAX);
        assert_eq!(store.inserts_until_pruning, 100 - pruning_capacity_count);
        Ok(())
    }

    #[test]
    fn create_above_pruning_capacity() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir);

        let above_pruning_capacity_count =
            1 + config.pruning_capacity_threshold() / CONTENT_SIZE_100_BYTES;
        let target_capacity_count = config.target_capacity() / CONTENT_SIZE_100_BYTES;

        create_and_populate_table(&config, above_pruning_capacity_count)?;

        let store = IdIndexedV1Store::create(ContentType::State, config)?;
        let usage_stats = store.get_usage_stats()?;

        // should prune until target capacity
        assert_eq!(usage_stats.content_count, target_capacity_count);
        assert_eq!(
            usage_stats.used_storage_bytes,
            target_capacity_count * CONTENT_SIZE_100_BYTES
        );
        assert!(store.radius() < Distance::MAX);
        assert_eq!(store.inserts_until_pruning, 100 - target_capacity_count);
        Ok(())
    }

    #[test]
    fn create_above_full_capacity() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir);

        let above_full_capacity_count = 10 + config.storage_capacity_bytes / CONTENT_SIZE_100_BYTES;
        let target_capacity_count = config.target_capacity() / CONTENT_SIZE_100_BYTES;

        create_and_populate_table(&config, above_full_capacity_count)?;

        let store = IdIndexedV1Store::create(ContentType::State, config)?;
        let usage_stats = store.get_usage_stats()?;

        // should prune until target capacity
        assert_eq!(usage_stats.content_count, target_capacity_count);
        assert_eq!(
            usage_stats.used_storage_bytes,
            target_capacity_count * CONTENT_SIZE_100_BYTES
        );
        assert!(store.radius() < Distance::MAX);
        assert_eq!(store.inserts_until_pruning, 100 - target_capacity_count);
        Ok(())
    }

    #[test]
    fn simple_insert_and_lookup() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir);
        let mut store = IdIndexedV1Store::create(ContentType::State, config.clone())?;

        let (key, value) = generate_key_value(&config, 0);
        let id = ContentId::from(key.content_id());

        assert!(!store.has_content(&id)?);

        store.insert(&key, value.clone())?;

        assert!(store.has_content(&id)?);
        assert_eq!(store.lookup_content_key(&id)?, Some(key));
        assert_eq!(store.lookup_content_value(&id)?, Some(value));

        Ok(())
    }

    #[test]
    fn simple_insert_and_delete() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir);
        let mut store = IdIndexedV1Store::create(ContentType::State, config.clone())?;

        let (key, value) = generate_key_value(&config, 0);
        let id = ContentId::from(key.content_id());

        assert!(!store.has_content(&id)?);

        store.insert(&key, value)?;
        assert!(store.has_content(&id)?);

        store.delete(&id)?;
        assert!(!store.has_content(&id)?);

        Ok(())
    }

    #[test]
    fn inserts_until_pruning_from_empty_to_full() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir);
        let mut store = IdIndexedV1Store::create(ContentType::State, config.clone())?;

        assert_eq!(store.inserts_until_pruning, 0);

        let mut insert_and_check =
            |insert_count: u64, expected_count: u64, expected_inserts_until_pruning: u64| {
                for _ in 0..insert_count {
                    let (key, value) = generate_key_value(&config, 0);
                    store.insert(&key, value).unwrap();
                }
                let usage_stats = store.get_usage_stats().unwrap();
                assert_eq!(
                    usage_stats.content_count, expected_count,
                    "UsageStats: {usage_stats:?}. Testing count"
                );
                assert_eq!(
                    store.inserts_until_pruning, expected_inserts_until_pruning,
                    "UsageStats: {usage_stats:?}. Testing inserts_until_pruning"
                );
            };

        // The inserts_until_pruning shouldn't be bigger that stored count
        insert_and_check(
            /* insert_count= */ 1, /* expected_count= */ 1,
            /* expected_inserts_until_pruning= */ 1,
        );
        insert_and_check(
            /* insert_count= */ 1, /* expected_count= */ 2,
            /* expected_inserts_until_pruning= */ 2,
        );
        insert_and_check(
            /* insert_count= */ 2, /* expected_count= */ 4,
            /* expected_inserts_until_pruning= */ 4,
        );
        insert_and_check(
            /* insert_count= */ 4, /* expected_count= */ 8,
            /* expected_inserts_until_pruning= */ 8,
        );
        insert_and_check(
            /* insert_count= */ 8, /* expected_count= */ 16,
            /* expected_inserts_until_pruning= */ 16,
        );
        insert_and_check(
            /* insert_count= */ 16, /* expected_count= */ 32,
            /* expected_inserts_until_pruning= */ 32,
        );

        // The inserts_until_pruning should estimate when we reach full capacity
        insert_and_check(
            /* insert_count= */ 32, /* expected_count= */ 64,
            /* expected_inserts_until_pruning= */ 36,
        );

        // We shouldn't trigger pruning for next `inserts_until_pruning - 1` inserts.
        insert_and_check(
            /* insert_count= */ 35, /* expected_count= */ 99,
            /* expected_inserts_until_pruning= */ 1,
        );

        // Inserting one more should trigger pruning and we should be down to target capacity.
        insert_and_check(
            /* insert_count= */ 1, /* expected_count= */ 90,
            /* expected_inserts_until_pruning= */ 10,
        );

        Ok(())
    }

    #[test]
    fn pruning_with_one_large_item() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir);

        // fill 50% of storage with 50 items, 1% each
        create_and_populate_table(&config, 50)?;
        let mut store = IdIndexedV1Store::create(ContentType::State, config.clone())?;
        assert_eq!(store.inserts_until_pruning, 50);

        // Insert key/value such that:
        // - key shouldn't be pruned (close distance)
        // - value takes 50% of the storage
        let (big_value_key, value) = generate_key_value_with_content_size(
            &config,
            /* distance = */ 0,
            STORAGE_CAPACITY_10KB_IN_BYTES / 2,
        );
        store.insert(&big_value_key, value)?;

        // Add another 48 small items (1% each) and check that:
        // - we didn't prune
        // - we are at 148% total capacity
        for _ in 0..48 {
            let (key, value) = generate_key_value(&config, 0x80);
            store.insert(&key, value).unwrap();
        }
        assert_eq!(store.inserts_until_pruning, 1);
        assert_eq!(
            store.get_usage_stats()?.used_storage_bytes,
            STORAGE_CAPACITY_10KB_IN_BYTES * 148 / 100
        );

        // Add one more and check that:
        // - we pruned enough to be under pruning capacity
        // - the big_value_key is still stored
        // - inserts_until_pruning is set to correct value
        let (key, value) = generate_key_value(&config, 1);
        store.insert(&key, value).unwrap();
        assert!(store.get_usage_stats()?.used_storage_bytes <= config.pruning_capacity_threshold());
        assert!(store.has_content(&big_value_key.content_id().into())?);
        assert_eq!(store.inserts_until_pruning, 2);

        Ok(())
    }

    #[test]
    fn pruning_with_many_close_large_item() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir);

        // Fill 50% of storage with 50 items, 1% each
        create_and_populate_table(&config, 50)?;
        let mut store = IdIndexedV1Store::create(ContentType::State, config.clone())?;
        assert_eq!(store.inserts_until_pruning, 50);

        // Add 49 items with small distance and large size (50% total storage each) and check that:
        // - pruning didn't happen
        // - we exceed storage capacity 25 times at this point
        for _ in 0..49 {
            let (key, value) = generate_key_value_with_content_size(
                &config,
                /* distance = */ 0,
                STORAGE_CAPACITY_10KB_IN_BYTES / 2,
            );
            store.insert(&key, value)?;
        }
        assert_eq!(store.inserts_until_pruning, 1);
        assert_eq!(
            store.get_usage_stats()?.used_storage_bytes,
            25 * STORAGE_CAPACITY_10KB_IN_BYTES
        );

        // Add one more big item and check that:
        // - we pruned all but one big one
        // - inserts_until_pruning is set to 1
        let (key, value) = generate_key_value_with_content_size(
            &config,
            /* distance = */ 0,
            STORAGE_CAPACITY_10KB_IN_BYTES / 2,
        );
        store.insert(&key, value)?;
        assert_eq!(
            store.get_usage_stats()?,
            UsageStats {
                content_count: 1,
                used_storage_bytes: STORAGE_CAPACITY_10KB_IN_BYTES / 2
            }
        );
        assert_eq!(store.inserts_until_pruning, 1);

        Ok(())
    }
}
