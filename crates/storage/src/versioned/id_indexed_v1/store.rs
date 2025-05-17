use std::{cmp::min, marker::PhantomData};

use ethportal_api::{types::distance::Distance, OverlayContentKey, RawContentValue};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{named_params, types::Type, OptionalExtension};
use tracing::{debug, error, warn};
use trin_metrics::storage::StorageMetricsReporter;

use super::{pruning_strategy::PruningStrategy, sql, IdIndexedV1StoreConfig};
use crate::{
    error::ContentStoreError,
    utils::get_total_size_of_directory_in_bytes,
    versioned::{usage_stats::UsageStats, ContentType, StoreVersion, VersionedContentStore},
    ContentId,
};

/// The result of looking for the farthest content.
struct FarthestQueryResult {
    content_id: ContentId,
    distance_u32: u32,
}

/// The result of the pagination lookup.
#[derive(Debug, PartialEq, Eq)]
pub struct PaginateResult<TContentKey> {
    /// The content keys of the queried page
    pub content_keys: Vec<TContentKey>,
    /// The total count of entries in the database
    pub entry_count: u64,
}

/// The store for storing content key/value pairs.
///
/// Different SQL table is created for each `ContentType`, with content-id as a primary key.
/// It has a configurable capacity and it will prune data that is farthest from the `NodeId` once
/// it uses more than storage capacity.
#[derive(Debug)]
pub struct IdIndexedV1Store<TContentKey: OverlayContentKey> {
    /// The configuration.
    config: IdIndexedV1StoreConfig,
    /// The maximum distance between `NodeId` and content id that store should keep. Updated
    /// dynamically after pruning to the farthest distance still stored.
    radius: Distance,
    /// The strategy for deciding when and how much to prune.
    pruning_strategy: PruningStrategy,
    /// The usage stats tracked manually.
    usage_stats: UsageStats,
    /// The Metrics for tracking performance.
    metrics: StorageMetricsReporter,
    /// Phantom Content Key
    _phantom_content_key: PhantomData<TContentKey>,
}

impl<TContentKey: OverlayContentKey> VersionedContentStore for IdIndexedV1Store<TContentKey> {
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

        let subnetwork = config.subnetwork;

        let pruning_strategy = PruningStrategy::new(config.clone());

        let mut store = Self {
            radius: config.max_radius,
            pruning_strategy,
            usage_stats: UsageStats::new(
                /* entry_count= */ 0,
                /* total_entry_size_bytes= */ 0,
                extra_disk_usage_per_content_bytes(&config.content_type),
            ),
            metrics: StorageMetricsReporter::new(subnetwork),
            _phantom_content_key: PhantomData,
            config,
        };
        store.init()?;
        Ok(store)
    }
}

impl<TContentKey: OverlayContentKey> IdIndexedV1Store<TContentKey> {
    /// Initializes variables and metrics, and runs necessary checks.
    fn init(&mut self) -> Result<(), ContentStoreError> {
        self.metrics
            .report_storage_capacity_bytes(self.config.storage_capacity_bytes as f64);

        self.init_usage_stats()?;

        if self.pruning_strategy.should_prune(&self.usage_stats) {
            debug!(
                Db = %self.config.content_type,
                "High storage usage ({}) -> Pruning",
                self.usage_stats.estimated_disk_usage_bytes(),
            );
            // ignore dropped content...
            self.prune()?;
        } else if self
            .pruning_strategy
            .is_usage_above_target_capacity(&self.usage_stats)
        {
            debug!(
                Db = %self.config.content_type,
                "Used capacity ({}) is above target capacity ({}) -> Using distance to farthest for radius",
                self.usage_stats.estimated_disk_usage_bytes(),
                self.pruning_strategy.target_capacity_bytes(),
            );
            self.set_radius_to_farthest()?;
        } else if self.config.storage_capacity_bytes == 0 {
            debug!(
                Db = %self.config.content_type,
                "Storage capacity is 0 -> Using ZERO radius",
            );
            self.radius = Distance::ZERO;
            self.metrics.report_radius(self.radius);
        } else {
            debug!(
                Db = %self.config.content_type,
                "Used capacity ({}) is below target capacity ({}) -> Using MAX radius ({})",
                self.usage_stats.estimated_disk_usage_bytes(),
                self.pruning_strategy.target_capacity_bytes(),
                self.config.max_radius,
            );
            self.radius = self.config.max_radius;
            self.metrics.report_radius(self.radius);
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
            .distance(&self.config.node_id, &content_id.0)
    }

    /// Returns whether data associated with the content id is already stored.
    pub fn has_content(&self, content_id: &ContentId) -> Result<bool, ContentStoreError> {
        let timer = self.metrics.start_process_timer("has_content");

        let has_content = self
            .config
            .sql_connection_pool
            .get()?
            .prepare(&sql::lookup_key(&self.config.content_type))?
            .exists(named_params! { ":content_id": content_id.to_vec() })?;

        self.metrics.stop_process_timer(timer);
        Ok(has_content)
    }

    /// Returns content key data is stored.
    pub fn lookup_content_key(
        &self,
        content_id: &ContentId,
    ) -> Result<Option<TContentKey>, ContentStoreError> {
        let timer = self.metrics.start_process_timer("lookup_content_key");

        let key = self
            .config
            .sql_connection_pool
            .get()?
            .query_row(
                &sql::lookup_key(&self.config.content_type),
                named_params! { ":content_id": content_id.to_vec() },
                |row| {
                    let bytes: Vec<u8> = row.get("content_key")?;
                    TContentKey::try_from_bytes(bytes).map_err(|e| {
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
    ) -> Result<Option<RawContentValue>, ContentStoreError> {
        let timer = self.metrics.start_process_timer("lookup_content_value");

        let value = self
            .config
            .sql_connection_pool
            .get()?
            .query_row(
                &sql::lookup_value(&self.config.content_type),
                named_params! { ":content_id": content_id.to_vec() },
                |row| row.get::<&str, Vec<u8>>("content_value"),
            )
            .optional()?;

        self.metrics.stop_process_timer(timer);
        Ok(value.map(RawContentValue::from))
    }

    /// Inserts content key/value pair into storage and prunes the db if necessary.
    /// Returns any content items that were pruned.
    /// It returns `InsufficientRadius` error if content is outside radius.
    pub fn insert(
        &mut self,
        content_key: &TContentKey,
        content_value: RawContentValue,
    ) -> Result<Vec<(TContentKey, RawContentValue)>, ContentStoreError> {
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
        let content_key = content_key.to_bytes().to_vec();
        let content_size = Self::calculate_content_size(&content_id, &content_key, &content_value);

        let insert_timer = self.metrics.start_process_timer("insert");
        self.config.sql_connection_pool.get()?.execute(
            &sql::insert(&self.config.content_type),
            named_params! {
                ":content_id": content_id,
                ":content_key": content_key,
                ":content_value": content_value.as_ref(),
                ":distance_short": distance.big_endian_u32(),
                ":content_size": content_size,
            },
        )?;
        self.metrics.stop_process_timer(insert_timer);

        self.usage_stats.on_store(content_size);
        self.usage_stats.report_metrics(&self.metrics);

        let dropped_content = if self.pruning_strategy.should_prune(&self.usage_stats) {
            self.prune()?
        } else {
            vec![]
        };

        self.metrics.stop_process_timer(insert_with_pruning_timer);
        Ok(dropped_content)
    }

    /// Deletes content with the given content id.
    pub fn delete(&mut self, content_id: &ContentId) -> Result<(), ContentStoreError> {
        let timer = self.metrics.start_process_timer("delete");

        let content_size = self
            .config
            .sql_connection_pool
            .get()?
            .query_row(
                &sql::delete(&self.config.content_type),
                named_params! { ":content_id": content_id.to_vec() },
                |row| row.get::<_, u64>("content_size"),
            )
            .optional()?;

        match content_size {
            Some(content_size) => {
                self.usage_stats.on_delete(content_size);
                self.usage_stats.report_metrics(&self.metrics);
            }
            None => {
                debug!(Db = %self.config.content_type,
                    "Didn't delete content with id: {content_id:?}",
                );
            }
        }

        self.metrics.stop_process_timer(timer);
        Ok(())
    }

    /// Returns a paginated list of all locally available content keys, according to the provided
    /// offset and limit.
    pub fn paginate(
        &self,
        offset: u64,
        limit: u64,
    ) -> Result<PaginateResult<TContentKey>, ContentStoreError> {
        let timer = self.metrics.start_process_timer("paginate");

        let conn = self.config.sql_connection_pool.get()?;
        let content_keys = conn
            .prepare(&sql::paginate(&self.config.content_type))?
            .query_map(
                named_params! {
                    ":limit": limit,
                    ":offset": offset,
                },
                |row| {
                    let bytes = row.get::<&str, Vec<u8>>("content_key")?;
                    TContentKey::try_from_bytes(bytes).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(0, Type::Blob, e.into())
                    })
                },
            )?
            .collect::<Result<Vec<TContentKey>, rusqlite::Error>>()?;

        self.metrics.stop_process_timer(timer);
        Ok(PaginateResult {
            content_keys,
            entry_count: self.usage_stats.entry_count(),
        })
    }

    pub fn usage_stats(&self) -> UsageStats {
        self.usage_stats.clone()
    }

    /// Returns metrics summary.
    pub fn get_summary_info(&self) -> String {
        let timer = self.metrics.start_process_timer("get_summary_info");

        // Reports size of the entire database.
        match get_total_size_of_directory_in_bytes(&self.config.node_data_dir) {
            Ok(entire_db_size) => self
                .metrics
                .report_total_storage_usage_bytes(entire_db_size as f64),
            Err(err) => warn!(Db = %self.config.content_type, "Error getting db size: {err}"),
        }

        self.metrics.stop_process_timer(timer);
        self.metrics.get_summary()
    }

    // INTERNAL FUNCTIONS

    /// Lookup and set `usage_stats`.
    ///
    /// This should be called only during initialization or when error occurs. Otherwise,
    /// `usage_stats` should be updated manually when entries are inserted/deleted.
    fn init_usage_stats(&mut self) -> Result<(), ContentStoreError> {
        let timer = self.metrics.start_process_timer("init_usage_stats");

        self.usage_stats = self.config.sql_connection_pool.get()?.query_row(
            &sql::entry_count_and_size(&self.config.content_type),
            [],
            |row| {
                let entry_count = row.get("count")?;
                let used_capacity: f64 = row.get("used_capacity")?;
                Ok(UsageStats::new(
                    entry_count,
                    used_capacity.round() as u64,
                    extra_disk_usage_per_content_bytes(&self.config.content_type),
                ))
            },
        )?;
        self.usage_stats.report_metrics(&self.metrics);

        self.metrics.stop_process_timer(timer);
        Ok(())
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
                named_params! { ":limit": 1 },
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

    /// Sets `self.radius` to the distance to the farthest stored content.
    ///
    /// If no content is found, it sets radius to `config.max_radius`.
    fn set_radius_to_farthest(&mut self) -> Result<(), ContentStoreError> {
        match self.lookup_farthest()? {
            None => {
                if self.config.storage_capacity_bytes == 0 {
                    debug!(
                        Db = %self.config.content_type,
                        "Farthest not found and storage capacity is 0",
                    );
                    self.radius = Distance::ZERO;
                } else {
                    error!(Db = %self.config.content_type, "Farthest not found!");
                    self.radius = self.config.max_radius;
                }
            }
            Some(farthest) => {
                self.radius = min(
                    self.distance_to_content_id(&farthest.content_id),
                    self.config.max_radius,
                );
            }
        }
        self.metrics.report_radius(self.radius);
        Ok(())
    }

    /// Prunes database and updates `radius`.
    /// Returns any content items that were pruned.
    fn prune(&mut self) -> Result<Vec<(TContentKey, RawContentValue)>, ContentStoreError> {
        let mut deleted_content: Vec<(TContentKey, RawContentValue)> = Vec::new();
        if !self.pruning_strategy.should_prune(&self.usage_stats) {
            warn!(Db = %self.config.content_type,
                "Pruning requested but not needed. Skipping");
            return Ok(deleted_content);
        }

        let pruning_timer = self.metrics.start_process_timer("prune");
        debug!(Db = %self.config.content_type,
            "Pruning start: count={} disk_usage={} capacity={}",
            self.usage_stats.entry_count(),
            self.usage_stats.estimated_disk_usage_bytes(),
            self.pruning_strategy.target_capacity_bytes(),
        );

        let conn = self.config.sql_connection_pool.get()?;
        let mut delete_query = conn.prepare(&sql::delete_farthest(&self.config.content_type))?;

        while self.pruning_strategy.should_prune(&self.usage_stats) {
            let to_delete = self.pruning_strategy.get_pruning_count(&self.usage_stats);

            if to_delete == 0 {
                error!(
                    Db = %self.config.content_type,
                    "Entries to prune is 0. This is not supposed to happen (we should be above storage capacity)."
                );
                return Ok(deleted_content);
            }

            let delete_timer = self.metrics.start_process_timer("prune_delete");
            let deleted_content_result = delete_query
                .query_map(named_params! { ":limit": to_delete }, |row| {
                    let key_bytes: Vec<u8> = row.get("content_key")?;
                    let value_bytes: Vec<u8> = row.get("content_value")?;
                    let value = RawContentValue::from(value_bytes);
                    let size: u64 = row.get("content_size")?;
                    TContentKey::try_from_bytes(key_bytes)
                        .map(|key| (key, value, size))
                        .map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(0, Type::Blob, e.into())
                        })
                })?
                .collect::<Result<Vec<(TContentKey, RawContentValue, u64)>, rusqlite::Error>>()?;
            let pruning_duration = self.metrics.stop_process_timer(delete_timer);
            self.pruning_strategy
                .observe_pruning_duration(pruning_duration);

            let deleted_content_count = deleted_content_result.len() as u64;
            if to_delete != deleted_content_count {
                error!(Db = %self.config.content_type,
                    "Attempted to delete {to_delete} but deleted {deleted_content_count}");
                self.init_usage_stats()?;
                break;
            }

            let deleted_content_values = deleted_content_result
                .iter()
                .map(|(key, value, _)| (key.clone(), value.clone()))
                .collect::<Vec<(TContentKey, RawContentValue)>>();
            let deleted_content_size = deleted_content_result
                .iter()
                .map(|(_, _, size)| size)
                .sum::<u64>();
            self.usage_stats
                .on_multi_delete(to_delete, deleted_content_size);
            self.usage_stats.report_metrics(&self.metrics);
            deleted_content.extend(deleted_content_values);
        }
        // Free connection.
        drop(delete_query);
        drop(conn);

        // Update radius to the current farthest content
        self.set_radius_to_farthest()?;

        debug!(Db = %self.config.content_type,
            "Pruning end: count={} disk_usage={} capacity={}",
            self.usage_stats.entry_count(),
            self.usage_stats.estimated_disk_usage_bytes(),
            self.pruning_strategy.target_capacity_bytes(),
        );
        self.metrics.stop_process_timer(pruning_timer);
        Ok(deleted_content)
    }

    /// Calculates the raw content size, that is stored in `content_size` column.
    ///
    /// Represents the raw size (in bytes) of the content id, key and value. This is used in
    /// combination with [extra_disk_usage_per_content_bytes]  to estimate disk usage.
    fn calculate_content_size(
        raw_content_id: &[u8],
        raw_content_key: &[u8],
        raw_content_value: &[u8],
    ) -> u64 {
        (raw_content_id.len() + raw_content_key.len() + raw_content_value.len()) as u64
    }
}

/// Returns estimated additional disk usage per content.
/// See https://github.com/ethereum/trin/issues/1653 for details.
const fn extra_disk_usage_per_content_bytes(content_type: &ContentType) -> u64 {
    match content_type {
        ContentType::HistoryEternal => 750,
        ContentType::State => 500,
        ContentType::HistoryEphemeral => panic!("HistoryEphemeral is not supported"),
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
    use ethportal_api::{types::network::Subnetwork, IdentityContentKey};
    use rand::{rng, Rng};
    use tempfile::TempDir;

    use super::*;
    use crate::{
        test_utils::generate_random_bytes, utils::setup_sql,
        versioned::id_indexed_v1::pruning_strategy::PruningConfig, DistanceFunction,
    };

    const CONTENT_DEFAULT_SIZE_BYTES: u64 = 100;

    const EXTRA_DISK_USAGE_PER_CONTENT_BYTES: u64 =
        extra_disk_usage_per_content_bytes(&ContentType::State);

    const DISK_USAGE_PER_CONTENT_BYTES: u64 =
        CONTENT_DEFAULT_SIZE_BYTES + EXTRA_DISK_USAGE_PER_CONTENT_BYTES;

    // Storage capacity that stores 100 items of default size
    const STORAGE_CAPACITY_100_ITEMS: u64 = 100 * DISK_USAGE_PER_CONTENT_BYTES;

    // Storage capacity that stores 10000 items of default size
    const STORAGE_CAPACITY_10000_ITEMS: u64 = 10000 * DISK_USAGE_PER_CONTENT_BYTES;

    fn create_config(temp_dir: &TempDir, storage_capacity_bytes: u64) -> IdIndexedV1StoreConfig {
        IdIndexedV1StoreConfig {
            content_type: ContentType::State,
            subnetwork: Subnetwork::State,
            node_id: NodeId::random(),
            node_data_dir: temp_dir.path().to_path_buf(),
            distance_fn: DistanceFunction::Xor,
            sql_connection_pool: setup_sql(temp_dir.path()).unwrap(),
            storage_capacity_bytes,
            pruning_config: PruningConfig::default(),
            max_radius: Distance::MAX,
        }
    }

    /// Creates content key/value pair with the default size.
    fn generate_key_value(
        config: &IdIndexedV1StoreConfig,
        distance: u8,
    ) -> (IdentityContentKey, RawContentValue) {
        generate_key_value_with_content_size(config, distance, CONTENT_DEFAULT_SIZE_BYTES)
    }

    fn generate_key_value_with_content_size(
        config: &IdIndexedV1StoreConfig,
        distance: u8,
        content_size: u64,
    ) -> (IdentityContentKey, RawContentValue) {
        let mut key = rand::random::<[u8; 32]>();
        key[0] = config.node_id.raw()[0] ^ distance;
        let key = IdentityContentKey::new(key);

        if content_size < 2 * 32 {
            panic!("Content size of at least 64 bytes is required (32 for id + 32 for key)")
        }
        let value = generate_random_bytes((content_size - 2 * 32) as usize);
        (key, RawContentValue::copy_from_slice(value.as_ref()))
    }

    // Creates table and content at approximate middle distance (first byte distance is 0.80).
    fn create_and_populate_table(config: &IdIndexedV1StoreConfig, count: u64) -> Result<()> {
        maybe_create_table_and_indexes(&config.content_type, &config.sql_connection_pool)?;
        for _ in 0..count {
            let (key, value) = generate_key_value(config, 0x80);
            let id = key.content_id();
            let content_size = IdIndexedV1Store::<IdentityContentKey>::calculate_content_size(
                &id,
                &key.to_bytes(),
                &value,
            );
            config
                .sql_connection_pool
                .get()?
                .execute(&sql::insert(&config.content_type), named_params! {
                    ":content_id": id.as_slice(),
                    ":content_key": key.to_bytes().to_vec(),
                    ":content_value": value.to_vec(),
                    ":distance_short": config.distance_fn.distance(&config.node_id, &id).big_endian_u32(),
                    ":content_size": content_size,
                })?;
        }
        Ok(())
    }

    #[test]
    fn create_empty() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir, STORAGE_CAPACITY_100_ITEMS);
        let store =
            IdIndexedV1Store::<IdentityContentKey>::create(ContentType::State, config.clone())?;
        assert_eq!(store.usage_stats.entry_count(), 0);
        assert_eq!(store.usage_stats.estimated_disk_usage_bytes(), 0);
        assert_eq!(store.radius(), Distance::MAX);
        Ok(())
    }

    #[test]
    fn create_low_usage() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir, STORAGE_CAPACITY_100_ITEMS);

        let item_count = 20; // 20%
        create_and_populate_table(&config, item_count)?;

        let store =
            IdIndexedV1Store::<IdentityContentKey>::create(ContentType::State, config.clone())?;

        assert_eq!(store.usage_stats.entry_count(), item_count);
        assert_eq!(
            store.usage_stats.estimated_disk_usage_bytes(),
            item_count * DISK_USAGE_PER_CONTENT_BYTES
        );
        assert_eq!(store.radius(), Distance::MAX);
        Ok(())
    }

    #[test]
    fn create_half_full() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir, STORAGE_CAPACITY_100_ITEMS);

        let item_count = 50; // 50%
        create_and_populate_table(&config, item_count)?;

        let store =
            IdIndexedV1Store::<IdentityContentKey>::create(ContentType::State, config.clone())?;

        assert_eq!(store.usage_stats.entry_count(), item_count);
        assert_eq!(
            store.usage_stats.estimated_disk_usage_bytes(),
            item_count * DISK_USAGE_PER_CONTENT_BYTES
        );
        assert_eq!(store.radius(), Distance::MAX);
        Ok(())
    }

    #[test]
    fn create_at_target_capacity() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir, STORAGE_CAPACITY_100_ITEMS);

        let target_capacity_bytes = PruningStrategy::new(config.clone()).target_capacity_bytes();
        let target_capacity_count = target_capacity_bytes / DISK_USAGE_PER_CONTENT_BYTES;
        create_and_populate_table(&config, target_capacity_count)?;

        let store =
            IdIndexedV1Store::<IdentityContentKey>::create(ContentType::State, config.clone())?;
        assert_eq!(store.usage_stats.entry_count(), target_capacity_count);
        assert_eq!(
            store.usage_stats.estimated_disk_usage_bytes(),
            target_capacity_count * DISK_USAGE_PER_CONTENT_BYTES
        );
        assert_eq!(store.radius(), Distance::MAX);
        Ok(())
    }

    #[test]
    fn create_above_target_capacity() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir, STORAGE_CAPACITY_100_ITEMS);

        let target_capacity_bytes = PruningStrategy::new(config.clone()).target_capacity_bytes();
        let above_target_capacity_count = 1 + target_capacity_bytes / DISK_USAGE_PER_CONTENT_BYTES;

        create_and_populate_table(&config, above_target_capacity_count)?;

        let store =
            IdIndexedV1Store::<IdentityContentKey>::create(ContentType::State, config.clone())?;

        // Should not prune
        assert_eq!(store.usage_stats.entry_count(), above_target_capacity_count);
        assert_eq!(
            store.usage_stats.estimated_disk_usage_bytes(),
            above_target_capacity_count * DISK_USAGE_PER_CONTENT_BYTES
        );

        // Radius should not be MAX
        assert!(store.radius() < Distance::MAX);
        Ok(())
    }

    #[test]
    fn create_at_full_capacity() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir, STORAGE_CAPACITY_100_ITEMS);

        let full_capacity_count = config.storage_capacity_bytes / DISK_USAGE_PER_CONTENT_BYTES;

        create_and_populate_table(&config, full_capacity_count)?;

        let store =
            IdIndexedV1Store::<IdentityContentKey>::create(ContentType::State, config.clone())?;

        // Should not prune
        assert_eq!(store.usage_stats.entry_count(), full_capacity_count);
        assert_eq!(
            store.usage_stats.estimated_disk_usage_bytes(),
            config.storage_capacity_bytes,
        );

        // Radius should not be MAX
        assert!(store.radius() < Distance::MAX);
        Ok(())
    }

    #[test]
    fn create_above_full_capacity() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir, STORAGE_CAPACITY_100_ITEMS);

        let above_full_capacity_count =
            10 + config.storage_capacity_bytes / DISK_USAGE_PER_CONTENT_BYTES;

        create_and_populate_table(&config, above_full_capacity_count)?;

        let store =
            IdIndexedV1Store::<IdentityContentKey>::create(ContentType::State, config.clone())?;

        // should prune until target capacity
        assert_eq!(
            store.usage_stats.entry_count(),
            store.pruning_strategy.target_capacity_bytes() / DISK_USAGE_PER_CONTENT_BYTES
        );
        assert_eq!(
            store.usage_stats.estimated_disk_usage_bytes(),
            store.pruning_strategy.target_capacity_bytes()
        );
        assert!(store.radius() < Distance::MAX);
        Ok(())
    }

    #[test]
    fn create_zero_storage_empty() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir, /* storage_capacity_bytes= */ 0);

        let store = IdIndexedV1Store::<IdentityContentKey>::create(ContentType::State, config)?;

        // Check that db is empty and radius is ZERO.
        assert_eq!(store.usage_stats.entry_count(), 0);
        assert_eq!(store.usage_stats.estimated_disk_usage_bytes(), 0);
        assert_eq!(store.radius(), Distance::ZERO);
        Ok(())
    }

    #[test]
    fn create_zero_storage_non_empty() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir, /* storage_capacity_bytes= */ 0);

        // Add 1K entries, more than we would normally prune.
        create_and_populate_table(&config, 1_000)?;
        let store = IdIndexedV1Store::<IdentityContentKey>::create(ContentType::State, config)?;

        // Check that db is empty and radius is ZERO.
        assert_eq!(store.usage_stats.entry_count(), 0);
        assert_eq!(store.usage_stats.estimated_disk_usage_bytes(), 0);
        assert_eq!(store.radius(), Distance::ZERO);
        Ok(())
    }

    #[test]
    fn simple_insert_and_lookup() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir, STORAGE_CAPACITY_100_ITEMS);

        // fill 50% of storage with 50 items, 1% each
        create_and_populate_table(&config, 50)?;
        let mut store =
            IdIndexedV1Store::<IdentityContentKey>::create(ContentType::State, config.clone())?;

        let (key, value) = generate_key_value(&config, 0);
        let id = ContentId::from(key.content_id());

        // Check that content is not stored and save usage stats.
        assert!(!store.has_content(&id)?);
        let usage_stats = store.usage_stats();

        store.insert(&key, value.clone())?;

        // Check that lookup works
        assert!(store.has_content(&id)?);
        assert_eq!(store.lookup_content_key(&id)?, Some(key));
        assert_eq!(
            store.lookup_content_value(&id)?,
            Some(RawContentValue::from(value))
        );

        // Check that usage stats are updated
        assert_eq!(
            store.usage_stats.entry_count(),
            usage_stats.entry_count() + 1
        );
        assert!(
            store.usage_stats.estimated_disk_usage_bytes()
                > usage_stats.estimated_disk_usage_bytes()
        );

        Ok(())
    }

    #[test]
    fn simple_insert_and_delete() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir, STORAGE_CAPACITY_100_ITEMS);

        // fill 50% of storage with 50 items, 1% each
        create_and_populate_table(&config, 50)?;
        let mut store =
            IdIndexedV1Store::<IdentityContentKey>::create(ContentType::State, config.clone())?;

        let (key, value) = generate_key_value(&config, 0);
        let id = ContentId::from(key.content_id());

        // Check that content is not stored and save usage stats.
        assert!(!store.has_content(&id)?);
        let usage_stats = store.usage_stats();

        store.insert(&key, value)?;
        // Check that content is stored and usage stats are updated.
        assert!(store.has_content(&id)?);
        assert_eq!(
            store.usage_stats.entry_count(),
            usage_stats.entry_count() + 1
        );
        assert!(
            store.usage_stats.estimated_disk_usage_bytes()
                > usage_stats.estimated_disk_usage_bytes()
        );

        store.delete(&id)?;
        // Check that content is deleted and usage stats are same as before insert.
        assert!(!store.has_content(&id)?);
        assert_eq!(store.usage_stats(), usage_stats);

        Ok(())
    }

    #[test]
    fn prune_simple() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir, STORAGE_CAPACITY_100_ITEMS);
        let mut store =
            IdIndexedV1Store::<IdentityContentKey>::create(ContentType::State, config.clone())?;

        assert_eq!(store.radius(), Distance::MAX);

        // Insert 80 keys that shouldn't be pruned (close distance)
        let mut important_keys = vec![];
        for _ in 0..80 {
            let (key, value) = generate_key_value(&config, 0);
            store.insert(&key, value)?;
            important_keys.push(key);
        }

        // Insert 20 keys and check that nothing is pruned
        for _ in 0..20 {
            let (key, value) = generate_key_value(&config, 0xFF);
            store.insert(&key, value)?;
        }
        assert_eq!(store.usage_stats.entry_count(), 100);

        // Insert 1 more and check that:
        // - we pruned down to 95 elements (target capacity)
        // - radius is no longer MAX
        let (key, value) = generate_key_value(&config, 0xFF);
        store.insert(&key, value)?;
        assert_eq!(store.usage_stats.entry_count(), 95);
        assert_eq!(
            store.usage_stats.estimated_disk_usage_bytes(),
            store.pruning_strategy.target_capacity_bytes()
        );
        assert!(store.radius() < Distance::MAX);
        assert!(store.radius().big_endian()[0] == 0xFF);

        // Insert 100 more keys and check that:
        // - we never got above storage capacity
        // - radius never increases
        let mut last_radius = store.radius();
        for i in 1..=100 {
            // Use `0xFF-i` for distance so we are sure they will be accepted
            // (radius will decrease over time)
            let (key, value) = generate_key_value(&config, 0xFF - i);
            store.insert(&key, value)?;
            assert!(
                store.usage_stats.estimated_disk_usage_bytes() <= config.storage_capacity_bytes
            );

            assert!(store.radius() <= last_radius);
            last_radius = store.radius();
        }

        // Radius should be below 0xB0
        assert!(store.radius().big_endian()[0] < 0xB0);

        // Check that important keys are still present
        for key in important_keys {
            assert!(store.has_content(&key.content_id().into())?);
        }

        Ok(())
    }

    #[test]
    fn prune_different_sizes_elements() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir, STORAGE_CAPACITY_100_ITEMS);

        // fill 50% of storage with 50 items, 1% each
        create_and_populate_table(&config, 50)?;
        let mut store =
            IdIndexedV1Store::<IdentityContentKey>::create(ContentType::State, config.clone())?;

        let mut rng = rng();

        // Insert 10 keys that shouldn't be pruned (close distance)
        // Each has a size in range 1-4%
        let mut important_keys = vec![];
        for _ in 0..10 {
            let (key, value) = generate_key_value_with_content_size(
                &config,
                0,
                rng.random_range((CONTENT_DEFAULT_SIZE_BYTES)..(4 * CONTENT_DEFAULT_SIZE_BYTES)),
            );
            store.insert(&key, value)?;
            important_keys.push(key);
        }

        // Insert 100 more keys (each has a size in range 1-3%) and check that:
        // - we never got above storage capacity
        // - radius never increases
        let mut last_radius = store.radius();
        for i in 0..100 {
            // Use `0xFF-i` for distance so we are sure they will be accepted
            // (radius will decrease over time)
            let (key, value) = generate_key_value_with_content_size(
                &config,
                0xFF - i,
                rng.random_range((CONTENT_DEFAULT_SIZE_BYTES)..(3 * CONTENT_DEFAULT_SIZE_BYTES)),
            );
            store.insert(&key, value)?;
            assert!(
                store.usage_stats.estimated_disk_usage_bytes() <= config.storage_capacity_bytes
            );

            assert!(store.radius() <= last_radius);
            last_radius = store.radius();
        }
        assert!(last_radius < Distance::MAX);

        // Check that important keys are still present
        for key in important_keys {
            assert!(store.has_content(&key.content_id().into())?);
        }

        Ok(())
    }

    #[test]
    fn prune_with_one_large_item() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir, STORAGE_CAPACITY_100_ITEMS);

        // fill 50% of storage with 50 items, 1% each
        create_and_populate_table(&config, 50)?;
        let mut store =
            IdIndexedV1Store::<IdentityContentKey>::create(ContentType::State, config.clone())?;
        assert_eq!(store.usage_stats.entry_count(), 50);

        // Insert key/value such that:
        // - key shouldn't be pruned (close distance)
        // - value takes 50% of the storage
        // We will have 51 elements be at 100% capacity
        let (big_value_key, value) = generate_key_value_with_content_size(
            &config,
            /* distance = */ 0,
            store.config.storage_capacity_bytes / 2 - EXTRA_DISK_USAGE_PER_CONTENT_BYTES,
        );
        store.insert(&big_value_key, value)?;
        assert_eq!(store.usage_stats.entry_count(), 51);
        assert_eq!(
            store.usage_stats.estimated_disk_usage_bytes(),
            store.config.storage_capacity_bytes
        );

        // Insert one more key/value that is 1%.
        // We should be have 52 elements and be at 101% capacity and trigger pruning.
        let (key, value) = generate_key_value(&config, 0x80);
        store.insert(&key, value)?;

        // Prune should deleted 6% (rounded to 4 elements),
        // leaving us with 48 elements and between target and full capacity.
        assert_eq!(store.usage_stats.entry_count(), 48);
        assert!(
            store.usage_stats.estimated_disk_usage_bytes() <= store.config.storage_capacity_bytes
        );
        assert!(
            store.usage_stats.estimated_disk_usage_bytes()
                > store.pruning_strategy.target_capacity_bytes()
        );

        // Check that the big_value_key is still stored
        assert!(store.has_content(&big_value_key.content_id().into())?);

        Ok(())
    }

    #[test]
    fn prune_big_db() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir, STORAGE_CAPACITY_10000_ITEMS);

        let mut store =
            IdIndexedV1Store::<IdentityContentKey>::create(ContentType::State, config.clone())?;

        // insert 10_000 entries, each 0x01% of storage size -> storage fully used
        for _ in 0..10_000 {
            let (key, value) = generate_key_value(&config, 0x80);
            store.insert(&key, value)?;
        }
        assert_eq!(store.radius(), Distance::MAX);
        assert_eq!(store.usage_stats.entry_count(), 10_000);
        assert_eq!(
            store.usage_stats.estimated_disk_usage_bytes(),
            STORAGE_CAPACITY_10000_ITEMS
        );

        // insert one more entry
        let (key, value) = generate_key_value(&config, 0x80);
        store.insert(&key, value)?;

        // radius should be smaller than MAX
        assert!(store.radius() < Distance::MAX);

        // we should have deleted exactly MAX_TO_PRUNE_PER_QUERY entries
        assert_eq!(
            store.usage_stats.entry_count(),
            10_001 - PruningStrategy::STARTING_MAX_PRUNING_COUNT
        );

        // used capacity should be below storage capacity but above 99%
        assert!(store.usage_stats.estimated_disk_usage_bytes() < STORAGE_CAPACITY_10000_ITEMS);
        assert!(
            store.usage_stats.estimated_disk_usage_bytes()
                > STORAGE_CAPACITY_10000_ITEMS * 99 / 100
        );

        Ok(())
    }

    #[test]
    fn prune_big_db_with_big_entry() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir, STORAGE_CAPACITY_10000_ITEMS);

        let mut store =
            IdIndexedV1Store::<IdentityContentKey>::create(ContentType::State, config.clone())?;

        // insert 10_000 entries, each 0x01% of storage size -> storage fully used
        for _ in 0..10_000 {
            let (key, value) = generate_key_value(&config, 0x80);
            store.insert(&key, value)?;
        }
        assert_eq!(store.radius(), Distance::MAX);
        assert_eq!(store.usage_stats.entry_count(), 10_000);
        assert_eq!(
            store.usage_stats.estimated_disk_usage_bytes(),
            STORAGE_CAPACITY_10000_ITEMS
        );

        // insert key/value such that:
        // - key shouldn't be pruned (close distance)
        // - value takes 50% of the storage
        // We will have 51 elements be at 100% capacity
        let (big_value_key, value) = generate_key_value_with_content_size(
            &config,
            /* distance = */ 0,
            store.config.storage_capacity_bytes / 2,
        );
        store.insert(&big_value_key, value)?;

        // big_value_key should still be stored
        assert!(store.has_content(&big_value_key.content_id().into())?);

        // radius should be smaller than MAX
        assert!(store.radius() < Distance::MAX);

        // we should have deleted more than MAX_TO_PRUNE_PER_QUERY entries
        assert!(
            store.usage_stats.entry_count() < 10_001 - PruningStrategy::STARTING_MAX_PRUNING_COUNT
        );

        // used capacity should not be above storage capacity
        assert!(store.usage_stats.estimated_disk_usage_bytes() <= STORAGE_CAPACITY_10000_ITEMS);

        Ok(())
    }

    #[test]
    fn pagination_empty() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir, STORAGE_CAPACITY_100_ITEMS);
        let store = IdIndexedV1Store::<IdentityContentKey>::create(ContentType::State, config)?;

        assert_eq!(
            store.paginate(/* offset= */ 0, /* limit= */ 10)?,
            PaginateResult {
                content_keys: vec![],
                entry_count: 0,
            }
        );
        Ok(())
    }

    #[test]
    fn pagination() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir, STORAGE_CAPACITY_100_ITEMS);
        let mut store =
            IdIndexedV1Store::<IdentityContentKey>::create(ContentType::State, config.clone())?;

        let entry_count = 12;

        let mut content_keys = vec![];
        for _ in 0..entry_count {
            let (key, value) = generate_key_value(&config, 0);
            store.insert(&key, value).unwrap();
            content_keys.push(key);
        }
        content_keys.sort_by_key(|key| key.to_vec());

        // Paginate in steps of 4, there should be exactly 3 pages
        assert_eq!(
            store.paginate(/* offset= */ 0, /* limit= */ 4)?,
            PaginateResult {
                content_keys: content_keys[0..4].into(),
                entry_count,
            }
        );
        assert_eq!(
            store.paginate(/* offset= */ 4, /* limit= */ 4)?,
            PaginateResult {
                content_keys: content_keys[4..8].into(),
                entry_count,
            }
        );
        assert_eq!(
            store.paginate(/* offset= */ 8, /* limit= */ 4)?,
            PaginateResult {
                content_keys: content_keys[8..].into(),
                entry_count,
            }
        );
        assert_eq!(
            store.paginate(/* offset= */ 12, /* limit= */ 4)?,
            PaginateResult {
                content_keys: vec![],
                entry_count,
            }
        );

        // Paginate in steps of 5, last page should have only 2
        assert_eq!(
            store.paginate(/* offset= */ 0, /* limit= */ 5)?,
            PaginateResult {
                content_keys: content_keys[0..5].into(),
                entry_count,
            }
        );
        assert_eq!(
            store.paginate(/* offset= */ 5, /* limit= */ 5)?,
            PaginateResult {
                content_keys: content_keys[5..10].into(),
                entry_count,
            }
        );
        assert_eq!(
            store.paginate(/* offset= */ 10, /* limit= */ 5)?,
            PaginateResult {
                content_keys: content_keys[10..].into(),
                entry_count,
            }
        );

        Ok(())
    }
}
