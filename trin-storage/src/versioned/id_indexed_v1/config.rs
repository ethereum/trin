use std::path::PathBuf;

use discv5::enr::NodeId;
use ethportal_api::types::portal_wire::ProtocolId;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

use crate::{
    versioned::{usage_stats::UsageStats, ContentType},
    DistanceFunction,
};

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
    pub fn target_capacity(&self) -> u64 {
        (self.storage_capacity_bytes as f64 * TARGET_CAPACITY_FRACTION).round() as u64
    }

    pub fn pruning_capacity_threshold(&self) -> u64 {
        (self.storage_capacity_bytes as f64 * PRUNING_CAPACITY_THRESHOLD_FRACTION).round() as u64
    }

    /// Returns the estimated number of items to insert to reach full capacity. This value will not
    /// exceed the number of currently stored items.
    pub fn estimate_to_insert_until_full(&self, usage_stats: &UsageStats) -> u64 {
        self.estimated_full_capacity_count(usage_stats)
            .map(|full_capacity_count| {
                if full_capacity_count > usage_stats.entry_count {
                    (full_capacity_count - usage_stats.entry_count).min(usage_stats.entry_count)
                } else {
                    0
                }
            })
            .unwrap_or(0)
    }

    fn estimated_full_capacity_count(&self, usage_stats: &UsageStats) -> Option<u64> {
        usage_stats
            .average_entry_size_bytes()
            .map(|average_entry_size_bytes| {
                (self.storage_capacity_bytes as f64 / average_entry_size_bytes).floor() as u64
            })
    }

    /// Returns the estimated number of items to delete to reach target capacity. If we are below
    /// target capacity, it will return 0.
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
                (self.target_capacity() as f64 / average_entry_size_bytes).floor() as u64
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
    #[case::no_usage(0, 0, false, false)]
    #[case::low_usage(10, 100, false, false)]
    #[case::just_below_target_capacity(89, 890, false, false)]
    #[case::target_capacity(90, 900, false, false)]
    #[case::between_target_and_pruning(92, 920, false, true)]
    #[case::pruning(95, 950, false, true)]
    #[case::between_pruning_and_full(97, 970, true, true)]
    #[case::full(100, 1000, true, true)]
    #[case::above_full(110, 1100, true, true)]
    fn is_above_capacity(
        #[case] entry_count: u64,
        #[case] total_entry_size_bytes: u64,
        #[case] is_above_pruning_capacity_threshold: bool,
        #[case] is_above_target_capacity: bool,
    ) {
        let config = create_config();
        let usage_stats = UsageStats {
            entry_count,
            total_entry_size_bytes,
        };

        assert_eq!(
            usage_stats.is_above(config.pruning_capacity_threshold()),
            is_above_pruning_capacity_threshold,
            "testing is_above_pruning_capacity_threshold"
        );
        assert_eq!(
            usage_stats.is_above(config.target_capacity()),
            is_above_target_capacity,
            "testing is_above_target_capacity"
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
            config.estimated_full_capacity_count(&usage_stats),
            None,
            "testing estimated_full_capacity_count"
        );
        assert_eq!(
            config.estimated_target_capacity_count(&usage_stats),
            None,
            "testing estimated_target_capacity_count"
        );
    }

    #[rstest]
    #[case::low_usage_1(10, 100, 100, 90)]
    #[case::low_usage_2(20, 100, 200, 180)]
    #[case::low_usage_3(50, 100, 500, 450)]
    #[case::mid_usage_1(10, 500, 20, 18)]
    #[case::mid_usage_2(25, 500, 50, 45)]
    #[case::mid_usage_3(50, 500, 100, 90)]
    #[case::between_target_and_pruning_1(10, 920, 10, 9)]
    #[case::between_target_and_pruning_2(20, 920, 21, 19)]
    #[case::between_target_and_pruning_3(50, 920, 54, 48)]
    #[case::between_pruning_and_full_1(10, 970, 10, 9)]
    #[case::between_pruning_and_full_2(20, 970, 20, 18)]
    #[case::between_pruning_and_full_3(50, 970, 51, 46)]
    #[case::above_full_1(10, 1050, 9, 8)]
    #[case::above_full_2(20, 1050, 19, 17)]
    #[case::above_full_3(50, 1050, 47, 42)]
    fn estimate_capacity_count(
        #[case] entry_count: u64,
        #[case] total_entry_size_bytes: u64,
        #[case] estimated_full_capacity_count: u64,
        #[case] estimated_target_capacity_count: u64,
    ) {
        let config = create_config();
        let usage_stats = UsageStats {
            entry_count,
            total_entry_size_bytes,
        };

        assert_eq!(
            config.estimated_full_capacity_count(&usage_stats),
            Some(estimated_full_capacity_count),
            "testing estimated_full_capacity_count"
        );
        assert_eq!(
            config.estimated_target_capacity_count(&usage_stats),
            Some(estimated_target_capacity_count),
            "testing estimated_target_capacity_count"
        );
    }

    #[rstest]
    #[case::low_usage_1(0, 0, 0)]
    #[case::low_usage_1(10, 100, 10)]
    #[case::low_usage_2(20, 100, 20)]
    #[case::low_usage_3(50, 100, 50)]
    #[case::mid_usage_1(10, 500, 10)]
    #[case::mid_usage_2(25, 500, 25)]
    #[case::mid_usage_3(50, 500, 50)]
    #[case::between_target_and_pruning_1(10, 920, 0)]
    #[case::between_target_and_pruning_2(20, 920, 1)]
    #[case::between_target_and_pruning_3(50, 920, 4)]
    #[case::between_target_and_pruning_4(100, 920, 8)]
    #[case::between_pruning_and_full_1(10, 970, 0)]
    #[case::between_pruning_and_full_2(20, 970, 0)]
    #[case::between_pruning_and_full_3(50, 970, 1)]
    #[case::between_pruning_and_full_4(100, 970, 3)]
    #[case::above_full_1(10, 1050, 0)]
    #[case::above_full_2(20, 1050, 0)]
    #[case::above_full_3(50, 1050, 0)]
    fn to_insert_until_full(
        #[case] entry_count: u64,
        #[case] total_entry_size_bytes: u64,
        #[case] expected_to_insert_until_full: u64,
    ) {
        let config = create_config();
        let usage_stats = UsageStats {
            entry_count,
            total_entry_size_bytes,
        };

        assert_eq!(
            config.estimate_to_insert_until_full(&usage_stats),
            expected_to_insert_until_full
        );
    }

    #[rstest]
    #[case::low_usage_1(10, 100, 0)]
    #[case::low_usage_2(20, 100, 0)]
    #[case::low_usage_3(50, 100, 0)]
    #[case::mid_usage_1(10, 500, 0)]
    #[case::mid_usage_2(25, 500, 0)]
    #[case::mid_usage_3(50, 500, 0)]
    #[case::between_target_and_pruning_1(10, 920, 1)]
    #[case::between_target_and_pruning_2(20, 920, 1)]
    #[case::between_target_and_pruning_3(50, 920, 2)]
    #[case::between_target_and_pruning_4(100, 920, 3)]
    #[case::between_pruning_and_full_1(10, 970, 1)]
    #[case::between_pruning_and_full_2(20, 970, 2)]
    #[case::between_pruning_and_full_3(50, 970, 4)]
    #[case::between_pruning_and_full_4(100, 970, 8)]
    #[case::above_full_1(10, 1050, 2)]
    #[case::above_full_2(20, 1050, 3)]
    #[case::above_full_3(50, 1050, 8)]
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
