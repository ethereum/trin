use std::path::PathBuf;

use discv5::enr::NodeId;
use ethportal_api::types::network::Subnetwork;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use crate::{versioned::ContentType, DistanceFunction, PortalStorageConfig};

use super::pruning_strategy::PruningConfig;

/// The config for the IdIndexedV1Store
#[derive(Clone, Debug)]
pub struct IdIndexedV1StoreConfig {
    pub content_type: ContentType,
    pub subnetwork: Subnetwork,
    pub node_id: NodeId,
    pub node_data_dir: PathBuf,
    pub storage_capacity_bytes: u64,
    pub sql_connection_pool: Pool<SqliteConnectionManager>,
    pub distance_fn: DistanceFunction,
    pub pruning_config: PruningConfig,
}

impl IdIndexedV1StoreConfig {
    pub fn new(
        content_type: ContentType,
        subnetwork: Subnetwork,
        config: PortalStorageConfig,
    ) -> Self {
        Self {
            content_type,
            subnetwork,
            node_id: config.node_id,
            node_data_dir: config.node_data_dir,
            storage_capacity_bytes: config.storage_capacity_bytes,
            sql_connection_pool: config.sql_connection_pool,
            distance_fn: config.distance_fn,
            // consider making this a parameter if we start using non-default value
            pruning_config: PruningConfig::default(),
        }
    }
}
