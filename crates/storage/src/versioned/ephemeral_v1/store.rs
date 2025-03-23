use std::{
    marker::PhantomData,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy::eips::merge::EPOCH_SLOTS;
use ethportal_api::{jsonrpsee::tokio, OverlayContentKey, RawContentValue};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{named_params, types::Type, OptionalExtension};
use tokio::task::JoinHandle;
use tracing::{debug, warn};
use trin_metrics::storage::StorageMetricsReporter;

use super::{sql, EphemeralV1StoreConfig};
use crate::{
    error::ContentStoreError,
    utils::get_total_size_of_directory_in_bytes,
    versioned::{usage_stats::UsageStats, ContentType, StoreVersion, VersionedContentStore},
    ContentId,
};

pub const BEACON_GENESIS_TIME: u64 = 1606824023;
pub const SLOTS_PER_HISTORICAL_ROOT: u64 = 8192;

/// The store for storing ephemeral headers, bodies, and receipts.
#[allow(unused)]
#[derive(Debug)]
pub struct EphemeralV1Store<TContentKey: OverlayContentKey> {
    /// The configuration.
    config: EphemeralV1StoreConfig,
    /// The usage stats tracked manually.
    usage_stats: UsageStats,
    /// The Metrics for tracking performance.
    metrics: StorageMetricsReporter,
    /// Phantom Content Key
    _phantom_content_key: PhantomData<TContentKey>,
    /// Background task handle for periodic purging
    background_purge_task: Option<JoinHandle<()>>,
}

impl<TContentKey: OverlayContentKey> VersionedContentStore for EphemeralV1Store<TContentKey> {
    type Config = EphemeralV1StoreConfig;

    fn version() -> StoreVersion {
        StoreVersion::EphemeralV1
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

        let mut store = Self {
            usage_stats: UsageStats::new(
                /* entry_count= */ 0, /* total_entry_size_bytes= */ 0, 0,
            ),
            metrics: StorageMetricsReporter::new(subnetwork),
            _phantom_content_key: PhantomData,
            config,
            background_purge_task: None,
        };
        store.init()?;
        Ok(store)
    }
}

#[allow(unused)]
impl<TContentKey: OverlayContentKey> EphemeralV1Store<TContentKey> {
    /// Initializes variables and metrics, and runs necessary checks.
    fn init(&mut self) -> Result<(), ContentStoreError> {
        self.init_usage_stats()?;

        // Purge content based on the last historical summaries update slot
        let rows_deleted =
            Self::purge_content_before_last_summary_internal(&Arc::new(self.config.clone()))?;

        if rows_deleted > 0 {
            debug!(
                "Purged {} ephemeral content with during initialization",
                rows_deleted
            );
        }

        Ok(())
    }

    // PUBLIC FUNCTIONS

    /// Starts the background task for periodic purging.
    /// This can be called explicitly after initialization if needed.
    pub fn start_background_purge_task(&mut self) -> Result<(), ContentStoreError> {
        let config = Arc::new(self.config.clone());

        let handle = tokio::spawn(async move {
            // Run purge immediately when task starts
            if let Err(e) = Self::purge_content_before_last_summary_internal(&config) {
                warn!("Error purging content in background task: {}", e);
            }

            let mut interval = tokio::time::interval(Duration::from_secs(12 * EPOCH_SLOTS)); // One epoch duration
            loop {
                interval.tick().await;

                // Check if we're at a historical summaries update boundary
                let current_epoch = Self::expected_current_epoch();
                let next_epoch = current_epoch + 1;
                let period = SLOTS_PER_HISTORICAL_ROOT / EPOCH_SLOTS;

                if next_epoch % period == 0 {
                    if let Err(e) = Self::purge_content_before_last_summary_internal(&config) {
                        warn!("Error purging content in background task: {}", e);
                    }
                }
            }
        });

        self.background_purge_task = Some(handle);
        Ok(())
    }

    /// Stops the background purge task if it's running.
    pub fn stop_background_purge_task(&mut self) {
        if let Some(handle) = self.background_purge_task.take() {
            handle.abort();
        }
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

    /// Returns the stored content key if it is stored.
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

    /// Returns the content value data if it is stored.
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

    /// Inserts content key/value pair into storage.
    pub fn insert(
        &mut self,
        content_key: &TContentKey,
        content_value: RawContentValue,
        type_: u8,
        slot: u64,
    ) -> Result<(), ContentStoreError> {
        let content_id = content_key.content_id().to_vec();
        let content_key = content_key.to_bytes().to_vec();
        let content_size = Self::calculate_content_size(&content_id, &content_key, &content_value);

        let insert_timer = self.metrics.start_process_timer("insert");
        self.config.sql_connection_pool.get()?.execute(
            &sql::insert(&self.config.content_type),
            named_params! {
                ":content_id": content_id,
                ":content_key": content_key,
                ":content_value": content_value.as_ref(),
                ":type": type_,
                ":slot": slot,
                ":content_size": content_size,
            },
        )?;
        self.metrics.stop_process_timer(insert_timer);

        self.usage_stats.on_store(content_size);
        self.usage_stats.report_metrics(&self.metrics);

        Ok(())
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

    /// Manually triggers a purge of content before the last historical summary.
    /// This can be used to manually control when content is purged, independent of the background
    /// task.
    ///
    /// Returns the number of rows deleted.
    pub fn trigger_content_purge(&self) -> Result<usize, ContentStoreError> {
        Self::purge_content_before_last_summary_internal(&Arc::new(self.config.clone()))
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
                    0,
                ))
            },
        )?;
        self.usage_stats.report_metrics(&self.metrics);

        self.metrics.stop_process_timer(timer);
        Ok(())
    }

    /// Calculates the raw content size, that is stored in `content_size` column.
    ///
    /// Represents the raw size (in bytes) of the content id, key and value.
    fn calculate_content_size(
        raw_content_id: &[u8],
        raw_content_key: &[u8],
        raw_content_value: &[u8],
    ) -> u64 {
        (raw_content_id.len() + raw_content_key.len() + raw_content_value.len()) as u64
    }

    fn expected_current_epoch() -> u64 {
        let now = SystemTime::now();
        let now = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
        let since_genesis = now - Duration::from_secs(BEACON_GENESIS_TIME);

        since_genesis.as_secs() / 12 / EPOCH_SLOTS
    }

    /// Internal method to purge content, used by both the main thread and background task
    fn purge_content_before_last_summary_internal(
        config: &Arc<EphemeralV1StoreConfig>,
    ) -> Result<usize, ContentStoreError> {
        let current_epoch = Self::expected_current_epoch();
        let cutoff_slot = Self::last_summaries_slot(current_epoch);

        let conn = config.sql_connection_pool.get()?;
        let query = sql::purge_by_slot(&config.content_type);

        let rows_deleted = conn.execute(&query, named_params! { ":slot": cutoff_slot })?;
        Ok(rows_deleted)
    }

    /// Computes the slot at which the last historical summary event occurred.
    /// Historical summary events are appended when the next epoch is a multiple
    /// of `period = SLOTS_PER_HISTORICAL_ROOT / EPOCH_SLOTS`.
    ///
    /// If the current_epoch is less than the first event boundary (and assuming a genesis event
    /// at epoch 0), then this function returns 0.
    fn last_summaries_slot(current_epoch: u64) -> u64 {
        // Calculate the period (in epochs) at which events are appended.
        let period = SLOTS_PER_HISTORICAL_ROOT / EPOCH_SLOTS;
        // Compute candidate event epoch:
        // This candidate is based on (current_epoch + 1) because events are appended
        // when transitioning to the next epoch.
        let candidate = ((current_epoch + 1) / period) * period;
        // If candidate is greater than current_epoch, then that event is in the future,
        // so the last event occurred one period earlier.
        let last_summaries_epoch = if candidate > current_epoch {
            candidate.saturating_sub(period)
        } else {
            candidate
        };

        last_summaries_epoch * EPOCH_SLOTS
    }
}

impl<TContentKey: OverlayContentKey> Drop for EphemeralV1Store<TContentKey> {
    fn drop(&mut self) {
        // Cancel the background task when the store is dropped
        if let Some(handle) = self.background_purge_task.take() {
            handle.abort();
        }
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
    use ethportal_api::{types::network::Subnetwork, IdentityContentKey};
    use tempfile::TempDir;
    use tokio::time::{sleep, Duration};

    use super::*;
    use crate::{test_utils::generate_random_bytes, utils::setup_sql};

    const CONTENT_DEFAULT_SIZE_BYTES: u64 = 100;

    fn create_config(temp_dir: &TempDir) -> EphemeralV1StoreConfig {
        EphemeralV1StoreConfig {
            content_type: ContentType::HistoryEphemeral,
            subnetwork: Subnetwork::History,
            node_data_dir: temp_dir.path().to_path_buf(),
            sql_connection_pool: setup_sql(temp_dir.path()).unwrap(),
        }
    }

    /// Creates content key/value pair with the default size.
    fn generate_key_value() -> (IdentityContentKey, RawContentValue) {
        generate_key_value_with_content_size(CONTENT_DEFAULT_SIZE_BYTES)
    }

    fn generate_key_value_with_content_size(
        content_size: u64,
    ) -> (IdentityContentKey, RawContentValue) {
        let key = rand::random::<[u8; 32]>();
        let key = IdentityContentKey::new(key);

        if content_size < 2 * 32 {
            panic!("Content size of at least 64 bytes is required (32 for id + 32 for key)")
        }
        let value = generate_random_bytes((content_size - 2 * 32) as usize);
        (key, RawContentValue::copy_from_slice(value.as_ref()))
    }

    // Creates table and content
    fn create_and_populate_table(config: &EphemeralV1StoreConfig, count: u64) -> Result<()> {
        maybe_create_table_and_indexes(&config.content_type, &config.sql_connection_pool)?;
        for _ in 0..count {
            let (key, value) = generate_key_value();
            let id = key.content_id();
            let content_size = EphemeralV1Store::<IdentityContentKey>::calculate_content_size(
                &id,
                &key.to_bytes(),
                &value,
            );
            config.sql_connection_pool.get()?.execute(
                &sql::insert(&config.content_type),
                named_params! {
                    ":content_id": id.as_slice(),
                    ":content_key": key.to_bytes().to_vec(),
                    ":content_value": value.to_vec(),
                    ":type": 0,
                    ":slot": 100,
                    ":content_size": content_size,
                },
            )?;
        }
        Ok(())
    }

    #[test]
    fn create_empty() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir);
        let store = EphemeralV1Store::<IdentityContentKey>::create(
            ContentType::HistoryEphemeral,
            config.clone(),
        )?;
        assert_eq!(store.usage_stats.entry_count(), 0);
        assert_eq!(store.usage_stats.estimated_disk_usage_bytes(), 0);
        Ok(())
    }

    #[test]
    fn create() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir);

        let item_count = 50;
        create_and_populate_table(&config, item_count)?;

        let store = EphemeralV1Store::<IdentityContentKey>::create(
            ContentType::HistoryEphemeral,
            config.clone(),
        )?;

        assert_eq!(store.usage_stats.entry_count(), item_count);
        assert_eq!(
            store.usage_stats.estimated_disk_usage_bytes(),
            item_count * CONTENT_DEFAULT_SIZE_BYTES
        );
        Ok(())
    }

    #[test]
    fn simple_insert_and_lookup() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir);

        create_and_populate_table(&config, 50)?;
        let mut store = EphemeralV1Store::<IdentityContentKey>::create(
            ContentType::HistoryEphemeral,
            config.clone(),
        )?;

        let (key, value) = generate_key_value();
        let id = ContentId::from(key.content_id());

        // Check that content is not stored and save usage stats.
        assert!(!store.has_content(&id)?);
        let usage_stats = store.usage_stats();

        store.insert(&key, value.clone(), 0, 100)?;

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
        let config = create_config(&temp_dir);

        create_and_populate_table(&config, 50)?;
        let mut store = EphemeralV1Store::<IdentityContentKey>::create(
            ContentType::HistoryEphemeral,
            config.clone(),
        )?;

        let (key, value) = generate_key_value();
        let id = ContentId::from(key.content_id());

        // Check that content is not stored and save usage stats.
        assert!(!store.has_content(&id)?);
        let usage_stats = store.usage_stats();

        store.insert(&key, value, 0, 100)?;
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

    #[tokio::test]
    async fn test_background_purge_task() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir);

        // Create store without starting background task
        let mut store = EphemeralV1Store::<IdentityContentKey>::create(
            ContentType::HistoryEphemeral,
            config.clone(),
        )?;

        // Verify background task is not running initially
        assert!(store.background_purge_task.is_none());

        // Insert test data with slots before and after the cutoff
        let current_epoch = EphemeralV1Store::<IdentityContentKey>::expected_current_epoch();
        let cutoff_slot =
            EphemeralV1Store::<IdentityContentKey>::last_summaries_slot(current_epoch);

        let (key1, value1) = generate_key_value();
        let (key2, value2) = generate_key_value();
        let (key3, value3) = generate_key_value();

        // Insert data with slots before cutoff
        store.insert(&key1, value1, 0, cutoff_slot.saturating_sub(100))?;
        store.insert(&key2, value2, 0, cutoff_slot.saturating_sub(50))?;

        // Insert data with slot after cutoff
        store.insert(&key3, value3, 0, cutoff_slot + 100)?;

        // Verify data is present before starting background task
        assert!(store.has_content(&ContentId::from(key1.content_id()))?);
        assert!(store.has_content(&ContentId::from(key2.content_id()))?);
        assert!(store.has_content(&ContentId::from(key3.content_id()))?);

        // Start the background task
        store.start_background_purge_task()?;
        // Wait for the background task to run and purge data
        sleep(Duration::from_secs(1)).await;
        assert!(store.background_purge_task.is_some());

        // Verify that content before cutoff was purged
        assert!(
            !store.has_content(&ContentId::from(key1.content_id()))?,
            "key1 should be purged"
        );
        assert!(
            !store.has_content(&ContentId::from(key2.content_id()))?,
            "key2 should be purged"
        );
        assert!(
            store.has_content(&ContentId::from(key3.content_id()))?,
            "key3 should not be purged"
        );

        // Stop the background task
        store.stop_background_purge_task();
        assert!(store.background_purge_task.is_none());

        Ok(())
    }

    #[test]
    fn test_purge_content_during_init() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config = create_config(&temp_dir);

        // Create and populate store with test data
        let mut store = EphemeralV1Store::<IdentityContentKey>::create(
            ContentType::HistoryEphemeral,
            config.clone(),
        )?;

        // Insert test data with slots before and after the cutoff
        let current_epoch = EphemeralV1Store::<IdentityContentKey>::expected_current_epoch();
        let cutoff_slot =
            EphemeralV1Store::<IdentityContentKey>::last_summaries_slot(current_epoch);

        let (key1, value1) = generate_key_value();
        let (key2, value2) = generate_key_value();
        let (key3, value3) = generate_key_value();

        // Insert data with slots before cutoff
        store.insert(&key1, value1, 0, cutoff_slot.saturating_sub(100))?;
        store.insert(&key2, value2, 0, cutoff_slot.saturating_sub(50))?;

        // Insert data with slot after cutoff
        store.insert(&key3, value3, 0, cutoff_slot + 100)?;

        // Create a new store instance to trigger init and purge
        let new_store =
            EphemeralV1Store::<IdentityContentKey>::create(ContentType::HistoryEphemeral, config)?;

        // Verify that content before cutoff was purged
        assert!(!new_store.has_content(&ContentId::from(key1.content_id()))?);
        assert!(!new_store.has_content(&ContentId::from(key2.content_id()))?);
        assert!(new_store.has_content(&ContentId::from(key3.content_id()))?);

        Ok(())
    }
}
