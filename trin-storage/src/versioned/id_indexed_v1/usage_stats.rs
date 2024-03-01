use super::IdIndexedV1StoreConfig;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsageStats {
    /// The total count of the content items stored.
    pub content_count: u64,
    /// The sum of the `content_size` of all stored content items.
    pub used_storage_bytes: u64,
}

impl UsageStats {
    pub fn is_above_pruning_capacity_threshold(&self, config: &IdIndexedV1StoreConfig) -> bool {
        self.used_storage_bytes > config.pruning_capacity_threshold()
    }

    pub fn is_above_target_capacity(&self, config: &IdIndexedV1StoreConfig) -> bool {
        self.used_storage_bytes > config.target_capacity()
    }

    pub fn estimated_full_capacity_count(&self, config: &IdIndexedV1StoreConfig) -> Option<u64> {
        self.average_content_size_bytes()
            .map(|average_content_size_bytes| {
                (config.storage_capacity_bytes as f64 / average_content_size_bytes).floor() as u64
            })
    }

    pub fn estimated_target_capacity_count(&self, config: &IdIndexedV1StoreConfig) -> Option<u64> {
        self.average_content_size_bytes()
            .map(|average_content_size_bytes| {
                (config.target_capacity() as f64 / average_content_size_bytes).floor() as u64
            })
    }

    /// Returns the estimated number of items to insert to reach full capacity. This value will not
    /// exceed the number of currently stored items.
    pub fn estimate_insert_until_full(&self, config: &IdIndexedV1StoreConfig) -> u64 {
        self.estimated_full_capacity_count(config)
            .map(|full_capacity_count| {
                if full_capacity_count > self.content_count {
                    (full_capacity_count - self.content_count).min(self.content_count)
                } else {
                    0
                }
            })
            .unwrap_or(0)
    }

    /// Returns the estimated number of items to delete to reach target capacity. If we are below
    /// target capacity, it will return 0.
    pub fn delete_until_target(&self, config: &IdIndexedV1StoreConfig) -> u64 {
        self.estimated_target_capacity_count(config)
            .map(|target_capacity_count| {
                if self.content_count > target_capacity_count {
                    self.content_count - target_capacity_count
                } else {
                    0
                }
            })
            .unwrap_or(0)
    }

    fn average_content_size_bytes(&self) -> Option<f64> {
        if self.content_count == 0 {
            Option::None
        } else {
            Option::Some(self.used_storage_bytes as f64 / self.content_count as f64)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use discv5::enr::NodeId;
    use ethportal_api::{jsonrpsee::tokio, types::portal_wire::ProtocolId};
    use rstest::rstest;
    use sqlx::sqlite::SqlitePoolOptions;

    use crate::{versioned::ContentType, DistanceFunction};

    use super::*;

    const STORAGE_CAPACITY_BYTES: u64 = 1000;

    async fn create_config() -> IdIndexedV1StoreConfig {
        IdIndexedV1StoreConfig {
            content_type: ContentType::State,
            network: ProtocolId::State,
            node_id: NodeId::random(),
            node_data_dir: PathBuf::default(),
            storage_capacity_bytes: STORAGE_CAPACITY_BYTES,
            sql_connection_pool: SqlitePoolOptions::new()
                .connect("sqlite::memory:")
                .await
                .unwrap(),
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
    #[tokio::test]
    async fn is_above_capacity(
        #[case] content_count: u64,
        #[case] used_storage_bytes: u64,
        #[case] is_above_pruning_capacity_threshold: bool,
        #[case] is_above_target_capacity: bool,
    ) {
        let config = create_config().await;
        let usage_stats = UsageStats {
            content_count,
            used_storage_bytes,
        };

        assert_eq!(
            usage_stats.is_above_pruning_capacity_threshold(&config),
            is_above_pruning_capacity_threshold,
            "testing is_above_pruning_capacity_threshold"
        );
        assert_eq!(
            usage_stats.is_above_target_capacity(&config),
            is_above_target_capacity,
            "is_above_target_capacity"
        );
    }

    #[tokio::test]
    async fn estimate_capacity_count_no_usage() {
        let config = create_config().await;
        let usage_stats = UsageStats {
            content_count: 0,
            used_storage_bytes: 0,
        };

        assert_eq!(
            usage_stats.estimated_full_capacity_count(&config),
            None,
            "testing estimated_full_capacity_count"
        );
        assert_eq!(
            usage_stats.estimated_target_capacity_count(&config),
            None,
            "estimated_target_capacity_count"
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
    #[tokio::test]
    async fn estimate_capacity_count(
        #[case] content_count: u64,
        #[case] used_storage_bytes: u64,
        #[case] estimated_full_capacity_count: u64,
        #[case] estimated_target_capacity_count: u64,
    ) {
        let config = create_config().await;
        let usage_stats = UsageStats {
            content_count,
            used_storage_bytes,
        };

        assert_eq!(
            usage_stats.estimated_full_capacity_count(&config),
            Some(estimated_full_capacity_count),
            "testing estimated_full_capacity_count"
        );
        assert_eq!(
            usage_stats.estimated_target_capacity_count(&config),
            Some(estimated_target_capacity_count),
            "estimated_target_capacity_count"
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
    #[tokio::test]
    async fn insert_until_full(
        #[case] content_count: u64,
        #[case] used_storage_bytes: u64,
        #[case] expected_insert_until_full: u64,
    ) {
        let config = create_config().await;
        let usage_stats = UsageStats {
            content_count,
            used_storage_bytes,
        };

        assert_eq!(
            usage_stats.estimate_insert_until_full(&config),
            expected_insert_until_full
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
    #[tokio::test]
    async fn delete_until_target(
        #[case] content_count: u64,
        #[case] used_storage_bytes: u64,
        #[case] expected_delete_until_target: u64,
    ) {
        let config = create_config().await;
        let usage_stats = UsageStats {
            content_count,
            used_storage_bytes,
        };

        assert_eq!(
            usage_stats.delete_until_target(&config),
            expected_delete_until_target
        );
    }
}
