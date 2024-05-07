use std::path::PathBuf;

use discv5::enr::NodeId;
use ethportal_api::types::portal_wire::ProtocolId;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use crate::{
    versioned::{usage_stats::UsageStats, ContentType},
    DistanceFunction, PortalStorageConfig, BYTES_IN_MB_U64,
};

/// The fraction of the storage capacity that we should aim for when pruning.
const TARGET_CAPACITY_FRACTION: f64 = 0.95;

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
    pub fn new(
        content_type: ContentType,
        network: ProtocolId,
        config: PortalStorageConfig,
    ) -> Self {
        Self {
            content_type,
            network,
            node_id: config.node_id,
            node_data_dir: config.node_data_dir,
            storage_capacity_bytes: config.storage_capacity_mb * BYTES_IN_MB_U64,
            sql_connection_pool: config.sql_connection_pool,
            distance_fn: config.distance_fn,
        }
    }

    /// The capacity that we aim for when pruning.
    pub fn target_capacity_bytes(&self) -> u64 {
        (self.storage_capacity_bytes as f64 * TARGET_CAPACITY_FRACTION).round() as u64
    }

    /// Returns the estimated number of items to delete to reach target capacity. It returns 0 if
    /// already below target capacity.
    pub fn estimate_to_delete_until_target(&self, usage_stats: &UsageStats) -> u64 {
        self.estimated_target_capacity_count(usage_stats)
            .map(|target_capacity_count| {
                if usage_stats.entry_count > target_capacity_count {
                    usage_stats.entry_count - target_capacity_count
                } else {
                    0
                }
            })
            .unwrap_or(0)
    }

    fn estimated_target_capacity_count(&self, usage_stats: &UsageStats) -> Option<u64> {
        usage_stats
            .average_entry_size_bytes()
            .map(|average_entry_size_bytes| {
                (self.target_capacity_bytes() as f64 / average_entry_size_bytes).floor() as u64
            })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use discv5::enr::NodeId;
    use ethportal_api::types::portal_wire::ProtocolId;
    use r2d2::Pool;
    use r2d2_sqlite::SqliteConnectionManager;
    use rstest::rstest;

    use crate::{versioned::ContentType, DistanceFunction};

    use super::*;

    const STORAGE_CAPACITY_BYTES: u64 = 1000;

    fn create_config() -> IdIndexedV1StoreConfig {
        IdIndexedV1StoreConfig {
            content_type: ContentType::State,
            network: ProtocolId::State,
            node_id: NodeId::random(),
            node_data_dir: PathBuf::default(),
            storage_capacity_bytes: STORAGE_CAPACITY_BYTES,
            sql_connection_pool: Pool::new(SqliteConnectionManager::memory()).unwrap(),
            distance_fn: DistanceFunction::Xor,
        }
    }

    #[rstest]
    #[case::no_usage(0, 0, false)]
    #[case::low_usage(10, 100, false)]
    #[case::just_below_target_capacity(89, 890, false)]
    #[case::target_capacity(90, 900, false)]
    #[case::between_target_and_pruning(92, 920, false)]
    #[case::pruning(95, 950, false)]
    #[case::between_pruning_and_full(97, 970, true)]
    #[case::full(100, 1000, true)]
    #[case::above_full(110, 1100, true)]
    fn is_above_target_capacity(
        #[case] entry_count: u64,
        #[case] total_entry_size_bytes: u64,
        #[case] expected: bool,
    ) {
        let config = create_config();
        let usage_stats = UsageStats {
            entry_count,
            total_entry_size_bytes,
        };

        assert_eq!(
            usage_stats.is_above(config.target_capacity_bytes()),
            expected
        );
    }

    #[test]
    fn estimate_capacity_count_no_usage() {
        let config = create_config();
        let usage_stats = UsageStats {
            entry_count: 0,
            total_entry_size_bytes: 0,
        };
        assert_eq!(
            config.estimated_target_capacity_count(&usage_stats),
            None,
            "testing estimated_target_capacity_count"
        );
    }

    #[rstest]
    #[case::low_usage_1(10, 100, 95)]
    #[case::low_usage_2(20, 100, 190)]
    #[case::low_usage_3(50, 100, 475)]
    #[case::mid_usage_1(10, 500, 19)]
    #[case::mid_usage_2(20, 500, 38)]
    #[case::mid_usage_3(50, 500, 95)]
    #[case::between_target_and_full_1(10, 970, 9)]
    #[case::between_target_and_full_2(20, 970, 19)]
    #[case::between_target_and_full_3(50, 970, 48)]
    #[case::between_target_and_full_4(100, 970, 97)]
    #[case::above_full_1(10, 1050, 9)]
    #[case::above_full_2(20, 1050, 18)]
    #[case::above_full_3(50, 1050, 45)]
    fn estimate_target_capacity_count(
        #[case] entry_count: u64,
        #[case] total_entry_size_bytes: u64,
        #[case] estimated_target_capacity_count: u64,
    ) {
        let config = create_config();
        let usage_stats = UsageStats {
            entry_count,
            total_entry_size_bytes,
        };
        assert_eq!(
            config.estimated_target_capacity_count(&usage_stats),
            Some(estimated_target_capacity_count),
            "testing estimated_target_capacity_count"
        );
    }

    #[rstest]
    #[case::low_usage_1(10, 100, 0)]
    #[case::low_usage_2(20, 100, 0)]
    #[case::low_usage_3(50, 100, 0)]
    #[case::mid_usage_1(10, 500, 0)]
    #[case::mid_usage_2(25, 500, 0)]
    #[case::mid_usage_3(50, 500, 0)]
    #[case::between_target_and_full_1(10, 970, 1)]
    #[case::between_target_and_full_2(20, 970, 1)]
    #[case::between_target_and_full_3(50, 970, 2)]
    #[case::between_target_and_full_4(100, 970, 3)]
    #[case::above_full_1(10, 1050, 1)]
    #[case::above_full_2(20, 1050, 2)]
    #[case::above_full_3(50, 1050, 5)]
    fn to_delete_until_target(
        #[case] entry_count: u64,
        #[case] total_entry_size_bytes: u64,
        #[case] expected_to_delete_until_target: u64,
    ) {
        let config = create_config();
        let usage_stats = UsageStats {
            entry_count,
            total_entry_size_bytes,
        };

        assert_eq!(
            config.estimate_to_delete_until_target(&usage_stats),
            expected_to_delete_until_target
        );
    }
}
