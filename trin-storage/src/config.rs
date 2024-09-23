use std::path::PathBuf;

use discv5::enr::NodeId;
use ethportal_api::types::network::Subnetwork;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use crate::{error::ContentStoreError, utils::setup_sql, DistanceFunction};

const BYTES_IN_MB_U64: u64 = 1000 * 1000;

/// Factory for creating [PortalStorageConfig] instances
pub struct PortalStorageConfigFactory {
    node_id: NodeId,
    node_data_dir: PathBuf,
    total_capacity_mb: u64,
    total_capacity_weight: u64,
    sql_connection_pool: Pool<SqliteConnectionManager>,
}

impl PortalStorageConfigFactory {
    const HISTORY_CAPACITY_WEIGHT: u64 = 1;
    const STATE_CAPACITY_WEIGHT: u64 = 99;
    const BEACON_CAPACITY_WEIGHT: u64 = 0; // Beacon doesn't care about given capacity

    pub fn new(
        total_capacity_mb: u64,
        subnetworks: &[Subnetwork],
        node_id: NodeId,
        node_data_dir: PathBuf,
    ) -> Result<Self, ContentStoreError> {
        let total_capacity_weight = subnetworks.iter().map(Self::get_capacity_weight).sum();

        let sql_connection_pool = setup_sql(&node_data_dir)?;

        Ok(Self {
            node_data_dir,
            node_id,
            total_capacity_mb,
            total_capacity_weight,
            sql_connection_pool,
        })
    }

    pub fn create(&self, subnetwork: &Subnetwork) -> PortalStorageConfig {
        let capacity_weight = Self::get_capacity_weight(subnetwork);
        let capacity_bytes = if self.total_capacity_weight == 0 {
            0
        } else {
            BYTES_IN_MB_U64 * self.total_capacity_mb * capacity_weight / self.total_capacity_weight
        };
        PortalStorageConfig {
            storage_capacity_bytes: capacity_bytes,
            node_id: self.node_id,
            node_data_dir: self.node_data_dir.clone(),
            distance_fn: DistanceFunction::Xor,
            sql_connection_pool: self.sql_connection_pool.clone(),
        }
    }

    fn get_capacity_weight(subnetwork: &Subnetwork) -> u64 {
        match subnetwork {
            Subnetwork::History => Self::HISTORY_CAPACITY_WEIGHT,
            Subnetwork::State => Self::STATE_CAPACITY_WEIGHT,
            Subnetwork::Beacon => Self::BEACON_CAPACITY_WEIGHT,
            _ => unreachable!("Subnetwork not activated: {subnetwork:?}"),
        }
    }
}

#[derive(Clone)]
pub struct PortalStorageConfig {
    pub storage_capacity_bytes: u64,
    pub node_id: NodeId,
    pub node_data_dir: PathBuf,
    pub distance_fn: DistanceFunction,
    pub sql_connection_pool: Pool<SqliteConnectionManager>,
}
