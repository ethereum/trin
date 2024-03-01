use ethportal_api::types::distance::Distance;
use sqlx::{query, sqlite::SqliteRow, Row, SqlitePool};
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

    async fn create(
        content_type: ContentType,
        config: Self::Config,
    ) -> Result<Self, ContentStoreError> {
        maybe_create_table_and_indexes(&content_type, &config.sql_connection_pool).await?;

        let protocol_id = config.network;

        let mut store: IdIndexedV1Store = Self {
            config,
            inserts_until_pruning: 0,
            radius: Distance::MAX,
            metrics: StorageMetricsReporter::new(protocol_id),
        };
        store.init().await?;
        Ok(store)
    }
}

impl IdIndexedV1Store {
    /// Initializes variables and metrics, and runs necessary checks.
    async fn init(&mut self) -> Result<(), ContentStoreError> {
        self.metrics
            .report_storage_capacity_bytes(self.config.storage_capacity_bytes as f64);

        let usage_stats = self.get_usage_stats().await?;

        if usage_stats.is_above_target_capacity(&self.config) {
            debug!(
                Db = %self.config.content_type,
                "Used capacity ({}) is over target capacity ({}) -> Pruning",
                usage_stats.used_storage_bytes,
                self.config.target_capacity()
            );
            self.prune(usage_stats).await?;
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
        let farthest = self.lookup_farthest().await?;
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
    pub async fn has_content(&self, content_id: &ContentId) -> Result<bool, ContentStoreError> {
        let timer = self.metrics.start_process_timer("has_content");

        let has_content = query(&sql::lookup_key(&self.config.content_type))
            .bind(content_id.as_fixed_bytes().as_slice())
            .fetch_optional(&self.config.sql_connection_pool)
            .await?
            .map_or(false, |_| true);

        self.metrics.stop_process_timer(timer);
        Ok(has_content)
    }

    /// Returns content key data is stored.
    pub async fn lookup_content_key<K: ethportal_api::OverlayContentKey>(
        &self,
        content_id: &ContentId,
    ) -> Result<Option<K>, ContentStoreError> {
        let timer = self.metrics.start_process_timer("lookup_content_key");

        let bytes = query(&sql::lookup_key(&self.config.content_type))
            .bind(content_id.as_fixed_bytes().as_slice())
            .map(|row: SqliteRow| {
                let bytes: Vec<u8> = row.get("content_key");
                bytes
            })
            .fetch_optional(&self.config.sql_connection_pool)
            .await?;
        let key = match bytes {
            Some(bytes) => match K::try_from(bytes) {
                Ok(key) => Ok(Some(key)),
                Err(err) => Err(ContentStoreError::ContentKey(err)),
            },
            None => Ok(None),
        };

        self.metrics.stop_process_timer(timer);
        key
    }

    /// Returns content value data is stored.
    pub async fn lookup_content_value(
        &self,
        content_id: &ContentId,
    ) -> Result<Option<Vec<u8>>, ContentStoreError> {
        let timer = self.metrics.start_process_timer("lookup_content_value");
        let value = query(&sql::lookup_value(&self.config.content_type))
            .bind(content_id.as_fixed_bytes().as_slice())
            .map(|row: SqliteRow| {
                let value: Vec<u8> = row.get("content_value");
                value
            })
            .fetch_optional(&self.config.sql_connection_pool)
            .await?;

        self.metrics.stop_process_timer(timer);
        Ok(value)
    }

    /// Inserts content key/value pair into storage and prunes the db if necessary. It will return
    /// `InsufficientRadius` error if content is outside radius.
    pub async fn insert<K: ethportal_api::OverlayContentKey>(
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

        let content_id = content_id.as_slice();
        let content_key = content_key.to_bytes();
        let content_size = (content_id.len() + content_key.len() + content_value.len()) as i64;

        let insert_timer = self.metrics.start_process_timer("insert");
        query(&sql::insert(&self.config.content_type))
            .bind(content_id)
            .bind(content_key)
            .bind(content_value)
            .bind(distance.big_endian_u32())
            .bind(content_size)
            .execute(&self.config.sql_connection_pool)
            .await?;
        self.metrics.stop_process_timer(insert_timer);
        self.metrics.increase_entry_count();

        if self.inserts_until_pruning > 1 {
            self.inserts_until_pruning -= 1;
        } else {
            let usage_stats = self.get_usage_stats().await?;
            if usage_stats.is_above_pruning_capacity_threshold(&self.config) {
                self.prune(usage_stats).await?
            } else {
                self.update_inserts_until_pruning(&usage_stats);
            }
        }

        self.metrics.stop_process_timer(insert_with_pruning_timer);
        Ok(())
    }

    /// Deletes content with the given content id.
    pub async fn delete(&mut self, content_id: &ContentId) -> Result<(), ContentStoreError> {
        let timer = self.metrics.start_process_timer("delete");
        query(&sql::delete(&self.config.content_type))
            .bind(content_id.as_fixed_bytes().as_slice())
            .execute(&self.config.sql_connection_pool)
            .await?;
        self.metrics.decrease_entry_count();

        self.metrics.stop_process_timer(timer);
        Ok(())
    }

    /// Updates metrics and returns summary.
    pub async fn get_summary_info(&self) -> String {
        // Call `get_usage_stats` to update metrics.
        if let Err(err) = self.get_usage_stats().await {
            warn!(Db = %self.config.content_type, "Error while getting summary info: {err}");
        }
        self.metrics.get_summary()
    }

    // INTERNAL FUNCTIONS

    /// Returns usage stats and updates relevant metrics.
    async fn get_usage_stats(&self) -> Result<UsageStats, ContentStoreError> {
        let timer = self.metrics.start_process_timer("get_usage_stats");

        let usage_stats = query(&sql::entry_count_and_size(&self.config.content_type))
            .map(|row: SqliteRow| {
                let used_capacity: f64 = row.get("used_capacity");
                let count: i64 = row.get("count");
                UsageStats {
                    content_count: count as u64,
                    used_storage_bytes: used_capacity.round() as u64,
                }
            })
            .fetch_one(&self.config.sql_connection_pool)
            .await?;

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
    async fn lookup_farthest(&self) -> Result<Option<FarthestQueryResult>, ContentStoreError> {
        let timer = self.metrics.start_process_timer("lookup_farthest");
        let farthest: Option<FarthestQueryResult> =
            query(&sql::lookup_farthest(&self.config.content_type))
                .bind(1)
                .map(|row: SqliteRow| FarthestQueryResult {
                    content_id: row.get("content_id"),
                    distance_u32: row.get("distance_short"),
                })
                .fetch_optional(&self.config.sql_connection_pool)
                .await?;

        self.metrics.stop_process_timer(timer);
        Ok(farthest)
    }

    /// Prunes database, and updates radius and inserts_until_pruning.
    async fn prune(&mut self, usage_stats: UsageStats) -> Result<(), ContentStoreError> {
        let timer = self.metrics.start_process_timer("prune");

        if !usage_stats.is_above_target_capacity(&self.config) {
            warn!(Db = %self.config.content_type, "Pruning requested but we are below target capacity. Skipping");
            return Ok(());
        }

        let delete_query = sql::delete_farthest(&self.config.content_type);

        let mut usage_stats = usage_stats;
        while usage_stats.is_above_pruning_capacity_threshold(&self.config) {
            let to_delete = usage_stats.delete_until_target(&self.config);

            if to_delete == 0 {
                warn!(Db = %self.config.content_type, "Should delete 0. This is not expected to happen (we should be above pruning capacity).");
                return Ok(());
            }

            let deleted = query(&delete_query)
                .bind(to_delete as i64)
                .execute(&self.config.sql_connection_pool)
                .await?
                .rows_affected();

            if to_delete != deleted {
                error!(Db = %self.config.content_type, "Attempted to delete {to_delete} but deleted {}", deleted);
                break;
            }

            usage_stats = self.get_usage_stats().await?;
        }
        // Free connection.
        drop(delete_query);

        self.update_inserts_until_pruning(&usage_stats);

        // Update radius to the current farthest content
        match self.lookup_farthest().await? {
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
async fn maybe_create_table_and_indexes(
    content_type: &ContentType,
    pool: &SqlitePool,
) -> Result<(), ContentStoreError> {
    query(&sql::create_table(content_type))
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use discv5::enr::NodeId;
    use ethportal_api::{
        jsonrpsee::tokio, types::portal_wire::ProtocolId, IdentityContentKey, OverlayContentKey,
    };
    use tempfile::TempDir;

    use crate::{test_utils::generate_random_bytes, utils::setup_sql, DistanceFunction};

    use super::*;

    const STORAGE_CAPACITY_10KB_IN_BYTES: u64 = 10_000;
    const CONTENT_SIZE_100_BYTES: u64 = STORAGE_CAPACITY_10KB_IN_BYTES / 100;

    async fn create_config(temp_dir: &TempDir) -> IdIndexedV1StoreConfig {
        IdIndexedV1StoreConfig {
            content_type: ContentType::State,
            network: ProtocolId::State,
            node_id: NodeId::random(),
            node_data_dir: temp_dir.path().to_path_buf(),
            distance_fn: DistanceFunction::Xor,
            sql_connection_pool: setup_sql(temp_dir.path()).await.unwrap(),
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
    async fn create_and_populate_table(config: &IdIndexedV1StoreConfig, count: u64) -> Result<()> {
        maybe_create_table_and_indexes(&config.content_type, &config.sql_connection_pool).await?;
        for _ in 0..count {
            let (key, value) = generate_key_value(config, 0x80);
            let id = key.content_id();
            let content_size = id.len() + key.to_bytes().len() + value.len();
            query(&sql::insert(&config.content_type))
                .bind(id.as_slice())
                .bind(key.to_bytes())
                .bind(value)
                .bind(
                    config
                        .distance_fn
                        .distance(&config.node_id, &id)
                        .big_endian_u32(),
                )
                .bind(content_size as i64)
                .execute(&config.sql_connection_pool)
                .await?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn create_empty() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir).await;
        let store = IdIndexedV1Store::create(ContentType::State, config).await?;
        assert_eq!(store.radius(), Distance::MAX);
        assert_eq!(store.inserts_until_pruning, 0);
        Ok(())
    }

    #[tokio::test]
    async fn create_low_usage_full() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir).await;

        let item_count = 20;
        create_and_populate_table(&config, item_count).await?;

        let store = IdIndexedV1Store::create(ContentType::State, config).await?;
        let usage_stats = store.get_usage_stats().await?;

        assert_eq!(usage_stats.content_count, item_count);
        assert_eq!(
            usage_stats.used_storage_bytes,
            item_count * CONTENT_SIZE_100_BYTES
        );
        assert_eq!(store.radius(), Distance::MAX);
        assert_eq!(store.inserts_until_pruning, item_count);
        Ok(())
    }

    #[tokio::test]
    async fn create_half_full() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir).await;

        let item_count = 50;
        create_and_populate_table(&config, item_count).await?;

        let store = IdIndexedV1Store::create(ContentType::State, config).await?;
        let usage_stats = store.get_usage_stats().await?;

        assert_eq!(usage_stats.content_count, item_count);
        assert_eq!(
            usage_stats.used_storage_bytes,
            item_count * CONTENT_SIZE_100_BYTES
        );
        assert_eq!(store.radius(), Distance::MAX);
        assert_eq!(store.inserts_until_pruning, 100 - item_count);
        Ok(())
    }

    #[tokio::test]
    async fn create_at_target_capacity() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir).await;

        let target_capacity_count = config.target_capacity() / CONTENT_SIZE_100_BYTES;
        create_and_populate_table(&config, target_capacity_count).await?;

        let store = IdIndexedV1Store::create(ContentType::State, config).await?;
        let usage_stats = store.get_usage_stats().await?;
        assert_eq!(usage_stats.content_count, target_capacity_count);
        assert_eq!(
            usage_stats.used_storage_bytes,
            target_capacity_count * CONTENT_SIZE_100_BYTES
        );
        assert_eq!(store.radius(), Distance::MAX);
        assert_eq!(store.inserts_until_pruning, 100 - target_capacity_count);
        Ok(())
    }

    #[tokio::test]
    async fn create_at_pruning_capacity() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir).await;

        let pruning_capacity_count = config.pruning_capacity_threshold() / CONTENT_SIZE_100_BYTES;
        create_and_populate_table(&config, pruning_capacity_count).await?;

        let store = IdIndexedV1Store::create(ContentType::State, config).await?;
        let usage_stats = store.get_usage_stats().await?;

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

    #[tokio::test]
    async fn create_above_pruning_capacity() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir).await;

        let above_pruning_capacity_count =
            1 + config.pruning_capacity_threshold() / CONTENT_SIZE_100_BYTES;
        let target_capacity_count = config.target_capacity() / CONTENT_SIZE_100_BYTES;

        create_and_populate_table(&config, above_pruning_capacity_count).await?;

        let store = IdIndexedV1Store::create(ContentType::State, config).await?;
        let usage_stats = store.get_usage_stats().await?;

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

    #[tokio::test]
    async fn create_above_full_capacity() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir).await;

        let above_full_capacity_count = 10 + config.storage_capacity_bytes / CONTENT_SIZE_100_BYTES;
        let target_capacity_count = config.target_capacity() / CONTENT_SIZE_100_BYTES;

        create_and_populate_table(&config, above_full_capacity_count).await?;

        let store = IdIndexedV1Store::create(ContentType::State, config).await?;
        let usage_stats = store.get_usage_stats().await?;

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

    #[tokio::test]
    async fn simple_insert_and_lookup() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir).await;
        let mut store = IdIndexedV1Store::create(ContentType::State, config.clone()).await?;

        let (key, value) = generate_key_value(&config, 0);
        let id = ContentId::from(key.content_id());

        assert!(!store.has_content(&id).await?);

        store.insert(&key, value.clone()).await?;

        assert!(store.has_content(&id).await?);
        assert_eq!(store.lookup_content_key(&id).await?, Some(key));
        assert_eq!(store.lookup_content_value(&id).await?, Some(value));

        Ok(())
    }

    #[tokio::test]
    async fn simple_insert_and_delete() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir).await;
        let mut store = IdIndexedV1Store::create(ContentType::State, config.clone()).await?;

        let (key, value) = generate_key_value(&config, 0);
        let id = ContentId::from(key.content_id());

        assert!(!store.has_content(&id).await?);

        store.insert(&key, value).await?;
        assert!(store.has_content(&id).await?);

        store.delete(&id).await?;
        assert!(!store.has_content(&id).await?);

        Ok(())
    }

    async fn insert_and_check(
        insert_count: u64,
        expected_count: u64,
        expected_inserts_until_pruning: u64,
        mut store: IdIndexedV1Store,
        config: &IdIndexedV1StoreConfig,
    ) -> IdIndexedV1Store {
        for _ in 0..insert_count {
            let (key, value) = generate_key_value(config, 0);
            store.insert(&key, value).await.unwrap();
        }
        let usage_stats = store.get_usage_stats().await.unwrap();
        assert_eq!(
            usage_stats.content_count, expected_count,
            "UsageStats: {usage_stats:?}. Testing count"
        );
        assert_eq!(
            store.inserts_until_pruning, expected_inserts_until_pruning,
            "UsageStats: {usage_stats:?}. Testing inserts_until_pruning"
        );
        store
    }

    #[tokio::test]
    async fn inserts_until_pruning_from_empty_to_full() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir).await;
        let store = IdIndexedV1Store::create(ContentType::State, config.clone()).await?;

        assert_eq!(store.inserts_until_pruning, 0);

        // The inserts_until_pruning shouldn't be bigger that stored count
        let store = insert_and_check(
            /* insert_count= */ 1, /* expected_count= */ 1,
            /* expected_inserts_until_pruning= */ 1, store, &config,
        )
        .await;
        let store = insert_and_check(
            /* insert_count= */ 1, /* expected_count= */ 2,
            /* expected_inserts_until_pruning= */ 2, store, &config,
        )
        .await;
        let store = insert_and_check(
            /* insert_count= */ 2, /* expected_count= */ 4,
            /* expected_inserts_until_pruning= */ 4, store, &config,
        )
        .await;
        let store = insert_and_check(
            /* insert_count= */ 4, /* expected_count= */ 8,
            /* expected_inserts_until_pruning= */ 8, store, &config,
        )
        .await;
        let store = insert_and_check(
            /* insert_count= */ 8, /* expected_count= */ 16,
            /* expected_inserts_until_pruning= */ 16, store, &config,
        )
        .await;
        let store = insert_and_check(
            /* insert_count= */ 16, /* expected_count= */ 32,
            /* expected_inserts_until_pruning= */ 32, store, &config,
        )
        .await;

        // The inserts_until_pruning should estimate when we reach full capacity
        let store = insert_and_check(
            /* insert_count= */ 32, /* expected_count= */ 64,
            /* expected_inserts_until_pruning= */ 36, store, &config,
        )
        .await;

        // We shouldn't trigger pruning for next `inserts_until_pruning - 1` inserts.
        let store = insert_and_check(
            /* insert_count= */ 35, /* expected_count= */ 99,
            /* expected_inserts_until_pruning= */ 1, store, &config,
        )
        .await;

        // Inserting one more should trigger pruning and we should be down to target capacity.
        let _ = insert_and_check(
            /* insert_count= */ 1, /* expected_count= */ 90,
            /* expected_inserts_until_pruning= */ 10, store, &config,
        )
        .await;

        Ok(())
    }

    #[tokio::test]
    async fn pruning_with_one_large_item() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir).await;

        // fill 50% of storage with 50 items, 1% each
        create_and_populate_table(&config, 50).await?;
        let mut store = IdIndexedV1Store::create(ContentType::State, config.clone()).await?;
        assert_eq!(store.inserts_until_pruning, 50);

        // Insert key/value such that:
        // - key shouldn't be pruned (close distance)
        // - value takes 50% of the storage
        let (big_value_key, value) = generate_key_value_with_content_size(
            &config,
            /* distance = */ 0,
            STORAGE_CAPACITY_10KB_IN_BYTES / 2,
        );
        store.insert(&big_value_key, value).await?;

        // Add another 48 small items (1% each) and check that:
        // - we didn't prune
        // - we are at 148% total capacity
        for _ in 0..48 {
            let (key, value) = generate_key_value(&config, 0x80);
            store.insert(&key, value).await.unwrap();
        }
        assert_eq!(store.inserts_until_pruning, 1);
        assert_eq!(
            store.get_usage_stats().await?.used_storage_bytes,
            STORAGE_CAPACITY_10KB_IN_BYTES * 148 / 100
        );

        // Add one more and check that:
        // - we pruned enough to be under pruning capacity
        // - the big_value_key is still stored
        // - inserts_until_pruning is set to correct value
        let (key, value) = generate_key_value(&config, 1);
        store.insert(&key, value).await.unwrap();
        assert!(
            store.get_usage_stats().await?.used_storage_bytes
                <= config.pruning_capacity_threshold()
        );
        assert!(
            store
                .has_content(&big_value_key.content_id().into())
                .await?
        );
        assert_eq!(store.inserts_until_pruning, 2);

        Ok(())
    }

    #[tokio::test]
    async fn pruning_with_many_close_large_item() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir).await;

        // Fill 50% of storage with 50 items, 1% each
        create_and_populate_table(&config, 50).await?;
        let mut store = IdIndexedV1Store::create(ContentType::State, config.clone()).await?;
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
            store.insert(&key, value).await?;
        }
        assert_eq!(store.inserts_until_pruning, 1);
        assert_eq!(
            store.get_usage_stats().await?.used_storage_bytes,
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
        store.insert(&key, value).await?;
        assert_eq!(
            store.get_usage_stats().await?,
            UsageStats {
                content_count: 1,
                used_storage_bytes: STORAGE_CAPACITY_10KB_IN_BYTES / 2
            }
        );
        assert_eq!(store.inserts_until_pruning, 1);

        Ok(())
    }
}
