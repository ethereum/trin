use ethportal_api::{
    types::{
        content_key::beacon::{
            HISTORICAL_SUMMARIES_WITH_PROOF_KEY_PREFIX, LIGHT_CLIENT_BOOTSTRAP_KEY_PREFIX,
            LIGHT_CLIENT_FINALITY_UPDATE_KEY_PREFIX, LIGHT_CLIENT_OPTIMISTIC_UPDATE_KEY_PREFIX,
            LIGHT_CLIENT_UPDATES_BY_RANGE_KEY_PREFIX,
        },
        content_value::beacon::{
            ForkVersionedHistoricalSummariesWithProof, ForkVersionedLightClientFinalityUpdate,
            ForkVersionedLightClientOptimisticUpdate, ForkVersionedLightClientUpdate,
            LightClientUpdatesByRange,
        },
        distance::Distance,
        portal_wire::ProtocolId,
    },
    BeaconContentKey, OverlayContentKey,
};
use r2d2::Pool;
use r2d2_sqlite::{rusqlite, SqliteConnectionManager};
use rusqlite::params;
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
    ContentStore, DataSize, PortalStorageConfig, ShouldWeStoreContent, BYTES_IN_MB_U64,
};

/// Store ephemeral light client data in memory
#[derive(Debug)]
pub struct BeaconStorageCache {
    optimistic_update: Option<ForkVersionedLightClientOptimisticUpdate>,
    finality_update: Option<ForkVersionedLightClientFinalityUpdate>,
    historical_summaries: Option<ForkVersionedHistoricalSummariesWithProof>,
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
            historical_summaries: None,
        }
    }

    /// Returns the optimistic update if it exists and matches the given signature slot.
    pub fn get_optimistic_update(
        &self,
        signature_slot: u64,
    ) -> Option<ForkVersionedLightClientOptimisticUpdate> {
        if let Some(optimistic_update) = &self.optimistic_update {
            if optimistic_update.update.signature_slot() >= &signature_slot {
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
                .finalized_header_deneb()
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

    /// Returns the historical summaries with proof if it exists and matches the given epoch.
    pub fn get_historical_summaries_with_proof(
        &self,
        epoch: u64,
    ) -> Option<ForkVersionedHistoricalSummariesWithProof> {
        if let Some(historical_summaries) = &self.historical_summaries {
            // Returns the current historical summaries with proof if it's epoch is bigger or equal
            // to the requested epoch.
            if historical_summaries.historical_summaries_with_proof.epoch >= epoch {
                return Some(historical_summaries.clone());
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

    /// Sets the historical summaries with proof
    pub fn set_historical_summaries_with_proof(
        &mut self,
        historical_summaries: ForkVersionedHistoricalSummariesWithProof,
    ) {
        self.historical_summaries = Some(historical_summaries);
    }
}

/// Storage layer for the state network. Encapsulates beacon network specific data and logic.
#[derive(Debug)]
pub struct BeaconStorage {
    node_data_dir: PathBuf,
    sql_connection_pool: Pool<SqliteConnectionManager>,
    storage_capacity_in_bytes: u64,
    metrics: StorageMetricsReporter,
    cache: BeaconStorageCache,
}

impl ContentStore for BeaconStorage {
    type Key = BeaconContentKey;

    fn get(&self, key: &Self::Key) -> Result<Option<Vec<u8>>, ContentStoreError> {
        let content_key: Vec<u8> = key.clone().into();
        let beacon_content_key = BeaconContentKey::try_from(content_key).map_err(|err| {
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
            BeaconContentKey::HistoricalSummariesWithProof(content_key) => {
                match self
                    .cache
                    .get_historical_summaries_with_proof(content_key.epoch)
                {
                    Some(historical_summaries_with_proof) => {
                        Ok(Some(historical_summaries_with_proof.as_ssz_bytes()))
                    }
                    None => Ok(None),
                }
            }
        }
    }

    fn put<V: AsRef<[u8]>>(&mut self, key: Self::Key, value: V) -> Result<(), ContentStoreError> {
        self.store(&key, &value.as_ref().to_vec())
    }

    /// The "radius" concept is not applicable for Beacon network
    fn is_key_within_radius_and_unavailable(
        &self,
        key: &Self::Key,
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
                    Some(content) => {
                        if content.update.signature_slot() >= &content_key.signature_slot {
                            Ok(ShouldWeStoreContent::AlreadyStored)
                        } else {
                            Ok(ShouldWeStoreContent::Store)
                        }
                    }
                    None => Ok(ShouldWeStoreContent::Store),
                }
            }
            BeaconContentKey::HistoricalSummariesWithProof(content_key) => {
                match self
                    .cache
                    .get_historical_summaries_with_proof(content_key.epoch)
                {
                    Some(content) => {
                        if content.historical_summaries_with_proof.epoch >= content_key.epoch {
                            Ok(ShouldWeStoreContent::AlreadyStored)
                        } else {
                            Ok(ShouldWeStoreContent::Store)
                        }
                    }
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
    pub fn new(config: PortalStorageConfig) -> Result<Self, ContentStoreError> {
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
        content_key: &Vec<u8>,
        value: &Vec<u8>,
    ) -> Result<usize, ContentStoreError> {
        let conn = self.sql_connection_pool.get()?;
        Ok(conn.execute(
            INSERT_QUERY_BEACON,
            params![
                content_id.as_slice(),
                content_key,
                value,
                32 + content_key.len() + value.len()
            ],
        )?)
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
                if let Err(err) = self.db_insert(&content_id, &content_key, value) {
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
            Some(&HISTORICAL_SUMMARIES_WITH_PROOF_KEY_PREFIX) => {
                self.cache.set_historical_summaries_with_proof(
                    ForkVersionedHistoricalSummariesWithProof::from_ssz_bytes(value.as_slice())
                        .map_err(|err| ContentStoreError::InvalidData {
                            message: format!(
                                "Error deserializing HistoricalSummariesWithProof value: {err:?}"
                            ),
                        })?,
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

        let mut content_data_stmt = conn.prepare(TOTAL_DATA_SIZE_QUERY_BEACON)?;
        let content_data_result = content_data_stmt.query_map([], |row| {
            Ok(DataSize {
                num_bytes: row.get(0)?,
            })
        });
        let content_data_sum = match content_data_result?.next() {
            Some(total) => total,
            None => {
                let err = "Unable to compute sum over content item sizes".to_string();
                return Err(ContentStoreError::Database(err));
            }
        }?
        .num_bytes;

        let mut lc_update_stmt = conn.prepare(LC_UPDATE_TOTAL_SIZE_QUERY)?;
        let lc_update_result = lc_update_stmt.query_map([], |row| {
            Ok(DataSize {
                num_bytes: row.get(0)?,
            })
        });
        let lc_update_sum = match lc_update_result?.next() {
            Some(total) => total,
            None => {
                let err = "Unable to compute sum over lc update item sizes".to_string();
                return Err(ContentStoreError::Database(err));
            }
        }?
        .num_bytes;

        let sum = content_data_sum + lc_update_sum;
        self.metrics.report_content_data_storage_bytes(sum);

        Ok(sum as u64)
    }

    /// Public method for looking up a content key by its content id
    pub fn lookup_content_key(&self, id: [u8; 32]) -> anyhow::Result<Option<Vec<u8>>> {
        let conn = self.sql_connection_pool.get()?;
        let mut query = conn.prepare(CONTENT_KEY_LOOKUP_QUERY_BEACON)?;
        let result: Result<Vec<BeaconContentKey>, ContentStoreError> = query
            .query_map([id.as_slice()], |row| {
                let row: Vec<u8> = row.get(0)?;
                Ok(row)
            })?
            .map(|row| BeaconContentKey::try_from(row?).map_err(ContentStoreError::ContentKey))
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
        let mut query = conn.prepare(CONTENT_VALUE_LOOKUP_QUERY_BEACON)?;
        let result: Result<Vec<Vec<u8>>, ContentStoreError> = query
            .query_map([id.as_slice()], |row| {
                let row: Vec<u8> = row.get(0)?;
                Ok(row)
            })?
            .map(|row| row.map_err(ContentStoreError::Rusqlite))
            .collect();

        Ok(result?.first().map(|val| val.to_vec()))
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use crate::test_utils;
    use ethportal_api::{
        types::content_key::beacon::{
            HistoricalSummariesWithProofKey, LightClientFinalityUpdateKey,
            LightClientOptimisticUpdateKey,
        },
        LightClientBootstrapKey, LightClientUpdatesByRangeKey,
    };
    use trin_storage::test_utils::create_test_portal_storage_config_with_capacity;

    #[test]
    fn test_beacon_storage_get_put_bootstrap() {
        let (_temp_dir, config) = create_test_portal_storage_config_with_capacity(10).unwrap();
        let mut storage = BeaconStorage::new(config).unwrap();
        let key = BeaconContentKey::LightClientBootstrap(LightClientBootstrapKey {
            block_hash: [1; 32],
        });
        let value = vec![1, 2, 3, 4, 5];
        storage.put(key.clone(), &value).unwrap();
        let result = storage.get(&key).unwrap().unwrap();
        assert_eq!(result, value);
    }

    #[test]
    fn test_beacon_storage_get_put_updates_by_range() {
        let (_temp_dir, config) = create_test_portal_storage_config_with_capacity(10).unwrap();
        let mut storage = BeaconStorage::new(config).unwrap();
        let key = BeaconContentKey::LightClientUpdatesByRange(LightClientUpdatesByRangeKey {
            start_period: 1,
            count: 2,
        });
        let lc_update_0 = test_utils::get_light_client_update(0);
        let lc_update_1 = test_utils::get_light_client_update(1);
        let value = VariableList::<ForkVersionedLightClientUpdate, U128>::new(vec![
            lc_update_0.clone(),
            lc_update_1.clone(),
        ])
        .unwrap();
        storage.put(key.clone(), &value.as_ssz_bytes()).unwrap();
        let result = storage.get(&key).unwrap().unwrap();

        assert_eq!(result, value.as_ssz_bytes());

        // Test getting the first individual updates
        let key_0 = BeaconContentKey::LightClientUpdatesByRange(LightClientUpdatesByRangeKey {
            start_period: 1,
            count: 1,
        });
        let expected_value_0 =
            VariableList::<ForkVersionedLightClientUpdate, U128>::new(vec![lc_update_0.clone()])
                .unwrap();
        let result_0 = storage.get(&key_0).unwrap().unwrap();
        assert_eq!(result_0, expected_value_0.as_ssz_bytes());

        // Test getting the second individual updates. The start period must be 2,
        let key_1 = BeaconContentKey::LightClientUpdatesByRange(LightClientUpdatesByRangeKey {
            start_period: 2,
            count: 1,
        });
        let expected_value_1 =
            VariableList::<ForkVersionedLightClientUpdate, U128>::new(vec![lc_update_1]).unwrap();
        let result_1 = storage.get(&key_1).unwrap().unwrap();
        assert_eq!(result_1, expected_value_1.as_ssz_bytes());
    }

    #[test]
    fn test_beacon_storage_get_put_finality_update() {
        let (_temp_dir, config) = create_test_portal_storage_config_with_capacity(10).unwrap();
        let mut storage = BeaconStorage::new(config).unwrap();
        let value = test_utils::get_light_client_finality_update(0);
        let finalized_slot = value.update.finalized_header_capella().unwrap().beacon.slot;
        let key = BeaconContentKey::LightClientFinalityUpdate(LightClientFinalityUpdateKey {
            finalized_slot,
        });
        storage.put(key.clone(), &value.as_ssz_bytes()).unwrap();
        let result = storage.get(&key).unwrap().unwrap();
        assert_eq!(result, value.as_ssz_bytes());

        // Test is_key_within_radius_and_unavailable for the same finalized slot
        let should_store_content = storage.is_key_within_radius_and_unavailable(&key).unwrap();
        assert_eq!(should_store_content, ShouldWeStoreContent::AlreadyStored);

        // Test is_key_within_radius_and_unavailable for older finalized slot
        let key = BeaconContentKey::LightClientFinalityUpdate(LightClientFinalityUpdateKey {
            finalized_slot: finalized_slot - 1,
        });
        let should_store_content = storage.is_key_within_radius_and_unavailable(&key).unwrap();
        assert_eq!(should_store_content, ShouldWeStoreContent::AlreadyStored);

        // Test is_key_within_radius_and_unavailable for newer finalized slot
        let key = BeaconContentKey::LightClientFinalityUpdate(LightClientFinalityUpdateKey {
            finalized_slot: finalized_slot + 1,
        });
        let should_store_content = storage.is_key_within_radius_and_unavailable(&key).unwrap();
        assert_eq!(should_store_content, ShouldWeStoreContent::Store);

        // Test getting the latest finality update
        let key = BeaconContentKey::LightClientFinalityUpdate(LightClientFinalityUpdateKey {
            finalized_slot: 0,
        });
        let result = storage.get(&key).unwrap().unwrap();
        assert_eq!(result, value.as_ssz_bytes());
    }

    #[test]
    fn test_beacon_storage_get_put_optimistic_update() {
        let (_temp_dir, config) = create_test_portal_storage_config_with_capacity(10).unwrap();
        let mut storage = BeaconStorage::new(config).unwrap();
        let value = test_utils::get_light_client_optimistic_update(0);
        let signature_slot = *value.update.signature_slot();
        let key = BeaconContentKey::LightClientOptimisticUpdate(LightClientOptimisticUpdateKey {
            signature_slot,
        });
        storage.put(key.clone(), &value.as_ssz_bytes()).unwrap();
        let result = storage.get(&key).unwrap().unwrap();
        assert_eq!(result, value.as_ssz_bytes());

        // Test is_key_within_radius_and_unavailable for the same signature slot
        let should_store_content = storage.is_key_within_radius_and_unavailable(&key).unwrap();
        assert_eq!(should_store_content, ShouldWeStoreContent::AlreadyStored);

        // Test is_key_within_radius_and_unavailable for older signature slot
        let key = BeaconContentKey::LightClientOptimisticUpdate(LightClientOptimisticUpdateKey {
            signature_slot: signature_slot - 1,
        });
        let should_store_content = storage.is_key_within_radius_and_unavailable(&key).unwrap();
        assert_eq!(should_store_content, ShouldWeStoreContent::AlreadyStored);

        // Test is_key_within_radius_and_unavailable for newer signature slot
        let key = BeaconContentKey::LightClientOptimisticUpdate(LightClientOptimisticUpdateKey {
            signature_slot: signature_slot + 1,
        });
        let should_store_content = storage.is_key_within_radius_and_unavailable(&key).unwrap();
        assert_eq!(should_store_content, ShouldWeStoreContent::Store);

        // Test getting unavailable optimistic update
        let key = BeaconContentKey::LightClientOptimisticUpdate(LightClientOptimisticUpdateKey {
            signature_slot: signature_slot + 1,
        });
        let result = storage.get(&key).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_beacon_storage_get_put_historical_summaries() {
        let (_temp_dir, config) = create_test_portal_storage_config_with_capacity(10).unwrap();
        let mut storage = BeaconStorage::new(config).unwrap();
        let value = test_utils::get_history_summaries_with_proof();
        let epoch = value.historical_summaries_with_proof.epoch;
        let key = BeaconContentKey::HistoricalSummariesWithProof(HistoricalSummariesWithProofKey {
            epoch,
        });
        storage.put(key.clone(), &value.as_ssz_bytes()).unwrap();
        let result = storage.get(&key).unwrap().unwrap();
        assert_eq!(result, value.as_ssz_bytes());

        // Test is_key_within_radius_and_unavailable for the same epoch
        let should_store_content = storage.is_key_within_radius_and_unavailable(&key).unwrap();
        assert_eq!(should_store_content, ShouldWeStoreContent::AlreadyStored);

        // Test is_key_within_radius_and_unavailable for older epoch
        let key = BeaconContentKey::HistoricalSummariesWithProof(HistoricalSummariesWithProofKey {
            epoch: epoch - 1,
        });
        let should_store_content = storage.is_key_within_radius_and_unavailable(&key).unwrap();
        assert_eq!(should_store_content, ShouldWeStoreContent::AlreadyStored);

        // Test is_key_within_radius_and_unavailable for newer epoch
        let key = BeaconContentKey::HistoricalSummariesWithProof(HistoricalSummariesWithProofKey {
            epoch: epoch + 1,
        });
        let should_store_content = storage.is_key_within_radius_and_unavailable(&key).unwrap();
        assert_eq!(should_store_content, ShouldWeStoreContent::Store);

        // Test getting unavailable historical summaries with proof
        let key = BeaconContentKey::HistoricalSummariesWithProof(HistoricalSummariesWithProofKey {
            epoch: epoch + 1,
        });
        let result = storage.get(&key).unwrap();
        assert_eq!(result, None);

        // Test getting the latest historical summaries with proof
        let key = BeaconContentKey::HistoricalSummariesWithProof(HistoricalSummariesWithProofKey {
            epoch: 0,
        });
        let result = storage.get(&key).unwrap().unwrap();
        assert_eq!(result, value.as_ssz_bytes());
    }
}
