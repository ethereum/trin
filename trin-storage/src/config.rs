use std::path::PathBuf;

use discv5::enr::NodeId;
use ethportal_api::types::{cli::StorageCapacityConfig, network::Subnetwork};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use crate::{error::ContentStoreError, utils::setup_sql, DistanceFunction};

const BYTES_IN_MB_U64: u64 = 1000 * 1000;

/// Factory for creating [PortalStorageConfig] instances
pub struct PortalStorageConfigFactory {
    node_id: NodeId,
    node_data_dir: PathBuf,
    capacity_config: StorageCapacityConfig,
    sql_connection_pool: Pool<SqliteConnectionManager>,
}

impl PortalStorageConfigFactory {
    const HISTORY_CAPACITY_WEIGHT: u64 = 1;
    const STATE_CAPACITY_WEIGHT: u64 = 1;
    const BEACON_CAPACITY_WEIGHT: u64 = 0; // Beacon doesn't care about given capacity

    pub fn new(
        capacity_config: StorageCapacityConfig,
        node_id: NodeId,
        node_data_dir: PathBuf,
    ) -> Result<Self, ContentStoreError> {
        let sql_connection_pool = setup_sql(&node_data_dir)?;

        Ok(Self {
            node_data_dir,
            node_id,
            capacity_config,
            sql_connection_pool,
        })
    }

    pub fn create(
        &self,
        subnetwork: &Subnetwork,
    ) -> Result<PortalStorageConfig, ContentStoreError> {
        let capacity_bytes = match &self.capacity_config {
            StorageCapacityConfig::Combined {
                total_mb,
                subnetworks,
            } => {
                if !subnetworks.contains(subnetwork) {
                    return Err(ContentStoreError::Database(format!(
                        "Can't create storage config: subnetwork {subnetwork} is not enabled."
                    )));
                }
                let capacity_weight = Self::get_capacity_weight(subnetwork);
                let total_capacity_weight = subnetworks
                    .iter()
                    .map(Self::get_capacity_weight)
                    .sum::<u64>();
                if total_capacity_weight == 0 {
                    0
                } else {
                    BYTES_IN_MB_U64 * (*total_mb as u64) * capacity_weight / total_capacity_weight
                }
            }
            StorageCapacityConfig::Specific {
                beacon_mb,
                history_mb,
                state_mb,
            } => {
                let capacity_mb = match subnetwork {
                    Subnetwork::Beacon => *beacon_mb,
                    Subnetwork::History => *history_mb,
                    Subnetwork::State => *state_mb,
                    _ => None,
                };
                match capacity_mb {
                    Some(capacity_mb) => capacity_mb as u64 * BYTES_IN_MB_U64,
                    None => {
                        return Err(ContentStoreError::Database(format!(
                            "Can't create storage config: subnetwork {subnetwork} doesn't have capacity specified"
                        )));
                    }
                }
            }
        };

        Ok(PortalStorageConfig {
            storage_capacity_bytes: capacity_bytes,
            node_id: self.node_id,
            node_data_dir: self.node_data_dir.clone(),
            distance_fn: DistanceFunction::Xor,
            sql_connection_pool: self.sql_connection_pool.clone(),
        })
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

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use tempfile::TempDir;

    use super::*;

    #[rstest]
    #[case::none_beacon(vec![], 100, Subnetwork::Beacon, None)]
    #[case::none_history(vec![], 100, Subnetwork::History, None)]
    #[case::none_state(vec![], 100, Subnetwork::State, None)]
    #[case::historystate_zero_capacity_beacon(vec![Subnetwork::History, Subnetwork::State], 0, Subnetwork::Beacon, None)]
    #[case::historystate_zero_capacity_history(vec![Subnetwork::History, Subnetwork::State], 0, Subnetwork::History, Some(0))]
    #[case::historystate_zero_capacity_state(vec![Subnetwork::History, Subnetwork::State], 0, Subnetwork::State, Some(0))]
    #[case::history_beacon(vec![Subnetwork::History], 100, Subnetwork::Beacon, None)]
    #[case::history_history(vec![Subnetwork::History], 100, Subnetwork::History, Some(100_000_000))]
    #[case::history_state(vec![Subnetwork::History], 100, Subnetwork::State, None)]
    #[case::historystate_beacon(vec![Subnetwork::History, Subnetwork::State], 100, Subnetwork::Beacon, None)]
    #[case::historystate_history(vec![Subnetwork::History, Subnetwork::State], 100, Subnetwork::History, Some(1_000_000))]
    #[case::historystate_state(vec![Subnetwork::History, Subnetwork::State], 100, Subnetwork::State, Some(99_000_000))]
    #[case::beaconhistorystate_beacon(vec![Subnetwork::Beacon, Subnetwork::History, Subnetwork::State], 100, Subnetwork::Beacon, Some(0))]
    #[case::beaconhistorystate_history(vec![Subnetwork::Beacon, Subnetwork::History, Subnetwork::State], 100, Subnetwork::History, Some(1_000_000))]
    #[case::beaconhistorystate_state(vec![Subnetwork::Beacon, Subnetwork::History, Subnetwork::State], 100, Subnetwork::State, Some(99_000_000))]
    fn combined_capacity_config(
        #[case] subnetworks: Vec<Subnetwork>,
        #[case] total_mb: u32,
        #[case] subnetwork: Subnetwork,
        #[case] expected_capacity_bytes: Option<u64>,
    ) {
        let temp_dir = TempDir::new().unwrap();
        let factory = PortalStorageConfigFactory::new(
            StorageCapacityConfig::Combined {
                total_mb,
                subnetworks,
            },
            NodeId::random(),
            temp_dir.path().to_path_buf(),
        )
        .unwrap();
        match expected_capacity_bytes {
            Some(expected_capacity_bytes) => {
                let config = factory.create(&subnetwork).unwrap();
                assert_eq!(config.storage_capacity_bytes, expected_capacity_bytes);
            }
            None => assert!(
                factory.create(&subnetwork).is_err(),
                "Storage config is expected to fail"
            ),
        }
        temp_dir.close().unwrap();
    }

    #[test]
    fn specific_capacity_config_all() {
        let temp_dir = TempDir::new().unwrap();
        let factory = PortalStorageConfigFactory::new(
            StorageCapacityConfig::Specific {
                beacon_mb: Some(100),
                history_mb: Some(200),
                state_mb: Some(300),
            },
            NodeId::random(),
            temp_dir.path().to_path_buf(),
        )
        .unwrap();
        assert_eq!(
            factory
                .create(&Subnetwork::Beacon)
                .unwrap()
                .storage_capacity_bytes,
            100_000_000,
        );
        assert_eq!(
            factory
                .create(&Subnetwork::History)
                .unwrap()
                .storage_capacity_bytes,
            200_000_000,
        );
        assert_eq!(
            factory
                .create(&Subnetwork::State)
                .unwrap()
                .storage_capacity_bytes,
            300_000_000,
        );
        temp_dir.close().unwrap();
    }

    #[test]
    fn specific_capacity_config_just_history() {
        let temp_dir = TempDir::new().unwrap();
        let factory = PortalStorageConfigFactory::new(
            StorageCapacityConfig::Specific {
                beacon_mb: None,
                history_mb: Some(100),
                state_mb: None,
            },
            NodeId::random(),
            temp_dir.path().to_path_buf(),
        )
        .unwrap();
        assert_eq!(
            factory
                .create(&Subnetwork::History)
                .unwrap()
                .storage_capacity_bytes,
            100_000_000,
        );
        assert!(
            factory.create(&Subnetwork::Beacon).is_err(),
            "Creating for Beacon should fail"
        );
        assert!(
            factory.create(&Subnetwork::State).is_err(),
            "Creating for State should fail"
        );
        temp_dir.close().unwrap();
    }

    #[test]
    fn specific_capacity_zero() {
        let temp_dir = TempDir::new().unwrap();
        let factory = PortalStorageConfigFactory::new(
            StorageCapacityConfig::Specific {
                beacon_mb: Some(0),
                history_mb: Some(100),
                state_mb: None,
            },
            NodeId::random(),
            temp_dir.path().to_path_buf(),
        )
        .unwrap();
        assert_eq!(
            factory
                .create(&Subnetwork::Beacon)
                .unwrap()
                .storage_capacity_bytes,
            0,
        );
        assert_eq!(
            factory
                .create(&Subnetwork::History)
                .unwrap()
                .storage_capacity_bytes,
            100_000_000,
        );
        assert!(factory.create(&Subnetwork::State).is_err());
        temp_dir.close().unwrap();
    }
}
