use discv5::enr::NodeId;
use ethportal_api::{
    types::{distance::Distance, portal_wire::ProtocolId},
    OverlayContentKey,
};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use std::path::PathBuf;
use trin_metrics::{portalnet::PORTALNET_METRICS, storage::StorageMetricsReporter};
use trin_storage::{
    error::ContentStoreError, ContentStore, DistanceFunction, PortalStorageConfig,
    ShouldWeStoreContent, BYTES_IN_MB_U64,
};

/// Storage layer for the state network. Encapsulates state network specific data and logic.
#[allow(dead_code)] // Remove this once we have implemented the state network.
#[derive(Debug)]
pub struct StateStorage {
    node_id: NodeId,
    node_data_dir: PathBuf,
    storage_capacity_in_bytes: u64,
    radius: Distance,
    sql_connection_pool: Pool<SqliteConnectionManager>,
    distance_fn: DistanceFunction,
    metrics: StorageMetricsReporter,
    network: ProtocolId,
}

impl ContentStore for StateStorage {
    fn get<K: OverlayContentKey>(&self, _key: &K) -> Result<Option<Vec<u8>>, ContentStoreError> {
        unimplemented!()
    }

    fn put<K: OverlayContentKey, V: AsRef<[u8]>>(
        &mut self,
        _key: K,
        _value: V,
    ) -> Result<(), ContentStoreError> {
        unimplemented!()
    }

    fn is_key_within_radius_and_unavailable<K: OverlayContentKey>(
        &self,
        _key: &K,
    ) -> Result<ShouldWeStoreContent, ContentStoreError> {
        unimplemented!()
    }

    fn radius(&self) -> Distance {
        self.radius
    }
}

impl StateStorage {
    pub fn new(config: PortalStorageConfig) -> Result<Self, ContentStoreError> {
        let metrics = StorageMetricsReporter {
            storage_metrics: PORTALNET_METRICS.storage(),
            protocol: ProtocolId::State.to_string(),
        };

        Ok(Self {
            node_id: config.node_id,
            node_data_dir: config.node_data_dir,
            storage_capacity_in_bytes: config.storage_capacity_mb * BYTES_IN_MB_U64,
            radius: Distance::MAX,
            sql_connection_pool: config.sql_connection_pool,
            distance_fn: config.distance_fn,
            metrics,
            network: ProtocolId::State,
        })
    }

    /// Get a summary of the current state of storage
    pub fn get_summary_info(&self) -> String {
        self.metrics.get_summary()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub mod test {
    use discv5::{enr::CombinedKey, Enr};
    use ethportal_api::types::distance::Distance;
    use portalnet::utils::db::{configure_node_data_dir, setup_temp_dir};
    use serial_test::serial;

    use super::*;

    const CAPACITY_MB: u64 = 2;

    fn get_active_node_id(temp_dir: PathBuf) -> NodeId {
        let (_, mut pk) = configure_node_data_dir(temp_dir, None).unwrap();
        let pk = CombinedKey::secp256k1_from_bytes(pk.0.as_mut_slice()).unwrap();
        Enr::empty(&pk).unwrap().node_id()
    }

    #[test_log::test(tokio::test)]
    #[serial]
    async fn test_new() -> Result<(), ContentStoreError> {
        let temp_dir = setup_temp_dir().unwrap();
        let node_id = get_active_node_id(temp_dir.path().to_path_buf());

        let storage_config =
            PortalStorageConfig::new(CAPACITY_MB, temp_dir.path().to_path_buf(), node_id).unwrap();
        let storage = StateStorage::new(storage_config)?;

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
}
