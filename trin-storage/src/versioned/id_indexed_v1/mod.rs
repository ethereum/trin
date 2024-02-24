mod sql;
mod store;
mod usage_stats;

use std::path::PathBuf;

use discv5::enr::NodeId;
use ethportal_api::types::portal_wire::ProtocolId;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

pub use store::IdIndexedV1Store;

use crate::DistanceFunction;

use super::ContentType;

/// The fraction of the storage capacity that we should aim for when pruning.
const TARGET_CAPACITY_FRACTION: f64 = 0.9;

/// The fraction of the storage capacity that we need to pass in order to start pruning.
const PRUNING_CAPACITY_THRESHOLD_FRACTION: f64 = 0.95;

/// The config for the IdIndexedV1Store
#[derive(Debug, Clone)]
pub struct IdIndexedV1StoreConfig {
    pub content_type: ContentType,
    pub network: ProtocolId,
    pub node_id: NodeId,
    pub node_data_dir: PathBuf,
    pub storage_capacity_bytes: u64,
    pub sql_connection_pool: Pool<SqliteConnectionManager>,
    pub distance_fn: DistanceFunction,
}

impl IdIndexedV1StoreConfig {
    fn target_capacity(&self) -> u64 {
        (self.storage_capacity_bytes as f64 * TARGET_CAPACITY_FRACTION).round() as u64
    }

    fn pruning_capacity_threshold(&self) -> u64 {
        (self.storage_capacity_bytes as f64 * PRUNING_CAPACITY_THRESHOLD_FRACTION).round() as u64
    }
}
