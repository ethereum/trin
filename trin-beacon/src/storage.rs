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
        distance::Distance,
        portal_wire::ProtocolId,
    },
    BeaconContentKey, OverlayContentKey,
};
use sqlx::{query, sqlite::SqliteRow, Row, SqlitePool};
use ssz::{Decode, Encode};
use ssz_types::{typenum::U128, VariableList};
use std::path::PathBuf;
use tracing::debug;
use trin_metrics::storage::StorageMetricsReporter;
use trin_storage::{
    error::ContentStoreError,
    sql::{
        CONTENT_KEY_LOOKUP_QUERY_BEACON, CONTENT_VALUE_LOOKUP_QUERY_BEACON, INSERT_LC_UPDATE_QUERY,
        INSERT_QUERY_BEACON, LC_UPDATE_LOOKUP_QUERY, LC_UPDATE_PERIOD_LOOKUP_QUERY,
        LC_UPDATE_TOTAL_SIZE_QUERY, TOTAL_DATA_SIZE_QUERY_BEACON,
    },
    utils::get_total_size_of_directory_in_bytes,
    ContentStore, PortalStorageConfig, ShouldWeStoreContent, BYTES_IN_MB_U64,
};

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
        if let Some(optimistic_update) = &self.optimistic_update {
            if optimistic_update.update.signature_slot() == &signature_slot {
                return Some(optimistic_update.clone());
            }
        }

        None
    }

    /// Returns the finality update if it exists and matches the given finalized slot.
    pub fn get_finality_update(
        &self,
        finalized_slot: u64,
    ) -> Option<ForkVersionedLightClientFinalityUpdate> {
        if let Some(finality_update) = &self.finality_update {
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
                return Some(finality_update.clone());
            }
        }

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

/// Storage layer for the state network. Encapsulates beacon network specific data and logic.
#[derive(Debug)]
pub struct BeaconStorage {
    node_data_dir: PathBuf,
    sql_connection_pool: SqlitePool,
    storage_capacity_in_bytes: u64,
    metrics: StorageMetricsReporter,
    cache: BeaconStorageCache,
}

impl ContentStore for BeaconStorage {
    async fn get<K: OverlayContentKey>(
        &self,
        key: &K,
    ) -> Result<Option<Vec<u8>>, ContentStoreError> {
        let content_key: Vec<u8> = key.clone().into();
        let beacon_content_key = BeaconContentKey::try_from(content_key).map_err(|err| {
            ContentStoreError::InvalidData {
                message: format!("Error deserializing BeaconContentKey value: {err:?}"),
            }
        })?;

        match beacon_content_key {
            BeaconContentKey::LightClientBootstrap(_) => {
                let content_id = key.content_id();
                self.lookup_content_value(content_id).await.map_err(|err| {
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
                    let result = self.lookup_lc_update_value(period).await.map_err(|err| {
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

    async fn put<K: OverlayContentKey>(
        &mut self,
        key: K,
        value: Vec<u8>,
    ) -> Result<(), ContentStoreError> {
        self.store(&key, &value).await
    }

    /// The "radius" concept is not applicable for Beacon network
    async fn is_key_within_radius_and_unavailable<K: OverlayContentKey>(
        &self,
        key: &K,
    ) -> Result<ShouldWeStoreContent, ContentStoreError> {
        let content_key: Vec<u8> = key.clone().into();
        let beacon_content_key = BeaconContentKey::try_from(content_key).map_err(|err| {
            ContentStoreError::InvalidData {
                message: format!("Error deserializing BeaconContentKey value: {err:?}"),
            }
        })?;

        match beacon_content_key {
            BeaconContentKey::LightClientBootstrap(_) => {
                let key = key.content_id();
                let is_key_available = self
                    .lookup_content_key(key)
                    .await
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
                        .await
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

    /// The "radius" concept is not applicable for Beacon network, this is why we always return the
    /// max radius.
    fn radius(&self) -> Distance {
        Distance::MAX
    }
}

impl BeaconStorage {
    pub async fn new(config: PortalStorageConfig) -> Result<Self, ContentStoreError> {
        let storage = Self {
            node_data_dir: config.node_data_dir,
            sql_connection_pool: config.sql_connection_pool,
            storage_capacity_in_bytes: config.storage_capacity_mb * BYTES_IN_MB_U64,
            metrics: StorageMetricsReporter::new(ProtocolId::Beacon),
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
        let network_content_storage_usage = storage
            .get_total_storage_usage_in_bytes_from_network()
            .await?;
        storage
            .metrics
            .report_content_data_storage_bytes(network_content_storage_usage as f64);

        Ok(storage)
    }

    async fn db_insert(
        &self,
        content_id: &[u8; 32],
        content_key: &Vec<u8>,
        value: &Vec<u8>,
    ) -> Result<u64, ContentStoreError> {
        Ok(query(INSERT_QUERY_BEACON)
            .bind(content_id.as_slice())
            .bind(content_key)
            .bind(value)
            .bind((32 + content_key.len() + value.len()) as i64)
            .execute(&self.sql_connection_pool)
            .await?
            .rows_affected())
    }

    async fn db_insert_lc_update(
        &self,
        period: u64,
        value: &Vec<u8>,
    ) -> Result<(), ContentStoreError> {
        query(INSERT_LC_UPDATE_QUERY)
            .bind(period as i64)
            .bind(value)
            .bind(0)
            .bind(value.len() as i64)
            .execute(&self.sql_connection_pool)
            .await?;
        Ok(())
    }

    pub async fn store(
        &mut self,
        key: &impl OverlayContentKey,
        value: &Vec<u8>,
    ) -> Result<(), ContentStoreError> {
        let content_id = key.content_id();
        let content_key: Vec<u8> = key.clone().into();

        match content_key.first() {
            Some(&LIGHT_CLIENT_BOOTSTRAP_KEY_PREFIX) => {
                if let Err(err) = self.db_insert(&content_id, &content_key, value).await {
                    debug!("Error writing light client bootstrap content ID {content_id:?} to beacon network db: {err:?}");
                    return Err(err);
                } else {
                    self.metrics.increase_entry_count();
                }
            }
            Some(&LIGHT_CLIENT_UPDATES_BY_RANGE_KEY_PREFIX) => {
                if let Ok(update) = BeaconContentKey::try_from(content_key) {
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
                                if let Err(err) =
                                    self.db_insert_lc_update(period, &value.encode()).await
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
    async fn get_total_storage_usage_in_bytes_from_network(
        &self,
    ) -> Result<u64, ContentStoreError> {
        let content_data_result = query(TOTAL_DATA_SIZE_QUERY_BEACON)
            .map(|row: SqliteRow| {
                let num_bytes: f32 = row.get(0);
                num_bytes
            })
            .fetch_optional(&self.sql_connection_pool)
            .await?;
        let content_data_sum = match content_data_result {
            Some(total) => total,
            None => {
                let err = "Unable to compute sum over content item sizes".to_string();
                return Err(ContentStoreError::Database(err));
            }
        };

        let lc_update_result = query(LC_UPDATE_TOTAL_SIZE_QUERY)
            .map(|row: SqliteRow| {
                let num_bytes: f32 = row.get(0);
                num_bytes
            })
            .fetch_optional(&self.sql_connection_pool)
            .await?;
        let lc_update_sum = match lc_update_result {
            Some(total) => total,
            None => {
                let err = "Unable to compute sum over lc update item sizes".to_string();
                return Err(ContentStoreError::Database(err));
            }
        };

        let sum = content_data_sum + lc_update_sum;
        self.metrics.report_content_data_storage_bytes(sum.into());

        Ok(sum as u64)
    }

    /// Public method for looking up a content key by its content id
    pub async fn lookup_content_key(&self, id: [u8; 32]) -> anyhow::Result<Option<Vec<u8>>> {
        let result = query(CONTENT_KEY_LOOKUP_QUERY_BEACON)
            .bind(id.as_slice())
            .map(|row: SqliteRow| {
                let row: Vec<u8> = row.get(0);
                row
            })
            .fetch_optional(&self.sql_connection_pool)
            .await?;
        let key = match result {
            Some(bytes) => match BeaconContentKey::try_from(bytes) {
                Ok(key) => Ok(Some(key.into())),
                Err(err) => Err(ContentStoreError::ContentKey(err)),
            },
            None => Ok(None),
        };
        Ok(key?)
    }

    /// Public method for looking up a light client update by period number
    pub async fn lookup_lc_update_period(&self, period: u64) -> anyhow::Result<Option<u64>> {
        Ok(query(LC_UPDATE_PERIOD_LOOKUP_QUERY)
            .bind(period as i64)
            .map(|row: SqliteRow| {
                let bytes: i64 = row.get(0);
                bytes as u64
            })
            .fetch_optional(&self.sql_connection_pool)
            .await?)
    }

    /// Public method for looking up a content value by its content id
    pub async fn lookup_content_value(&self, id: [u8; 32]) -> anyhow::Result<Option<Vec<u8>>> {
        let result = query(CONTENT_VALUE_LOOKUP_QUERY_BEACON)
            .bind(id.as_slice())
            .map(|row: SqliteRow| {
                let bytes: Vec<u8> = row.get(0);
                bytes
            })
            .fetch_optional(&self.sql_connection_pool)
            .await?;
        Ok(result)
    }

    /// Public method for looking up a  light client update value by period number
    pub async fn lookup_lc_update_value(&self, period: u64) -> anyhow::Result<Option<Vec<u8>>> {
        let result = query(LC_UPDATE_LOOKUP_QUERY)
            .bind(period as i64)
            .map(|row: SqliteRow| {
                let bytes: Vec<u8> = row.get(0);
                bytes
            })
            .fetch_optional(&self.sql_connection_pool)
            .await?;
        Ok(result)
    }

    /// Get a summary of the current state of storage
    pub fn get_summary_info(&self) -> String {
        self.metrics.get_summary()
    }
}
