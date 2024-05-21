use std::{fmt::Debug, ops::Range, time::Duration};

use tracing::debug;

use crate::versioned::usage_stats::UsageStats;

use super::IdIndexedV1StoreConfig;

/// The configuration parameters used by [PruningStrategy].
#[derive(Clone, Debug)]
pub struct PruningConfig {
    /// The fraction of storage capacity that we aim for when pruning.
    pub target_capacity_fraction: f64,
    /// The fraction by which we increase/decrease the `max_pruning_count` when pruning duration is
    /// outside `optimal_pruning_duration_range`.
    ///
    /// For example, let's assume that value is `0.1`. If pruning is too slow, the
    /// `max_pruning_count` will decrease by 10%, while if pruning is too fast, the
    /// `max_pruning_count` will increase by 10%. Note that increase and decrease don't cancel out.
    pub max_pruning_count_change_fraction: f64,
    /// The range of pruning durations that we consider optimal.
    pub optimal_pruning_duration_range: Range<Duration>,
}

impl PruningConfig {
    /// By default, we aim to prune down to 95% of storage capacity.
    pub const DEFAULT_TARGET_CAPACITY_FRACTION: f64 = 0.95;
    /// By default, we increase/decrease `max_pruning_count` by 20%.
    pub const DEFAULT_CHANGE_FRACTION: f64 = 0.2;
    /// By default, we consider optimal pruning duration between 0.1 and 0.3 seconds.
    pub const DEFAULT_OPTIMAL_PRUNING_DURATION_RANGE: Range<Duration> =
        Duration::from_millis(100)..Duration::from_millis(300);

    pub fn new(
        target_capacity_fraction: f64,
        max_pruning_count_change_fraction: f64,
        optimal_pruning_duration_range: Range<Duration>,
    ) -> Self {
        if !(0.0..=1.0).contains(&target_capacity_fraction) {
            panic!(
                "Invalid pruning strategy parameters: target_capacity_fraction={}",
                target_capacity_fraction
            )
        }
        if !(0.0..1.0).contains(&max_pruning_count_change_fraction) {
            panic!(
                "Invalid pruning strategy parameters: change_fraction={}",
                max_pruning_count_change_fraction
            )
        }
        if optimal_pruning_duration_range.is_empty() {
            panic!(
                "Invalid pruning strategy parameters: optimal_pruning_duration_range: {:?}",
                optimal_pruning_duration_range
            )
        }
        Self {
            target_capacity_fraction,
            max_pruning_count_change_fraction,
            optimal_pruning_duration_range,
        }
    }
}

impl Default for PruningConfig {
    fn default() -> Self {
        Self::new(
            Self::DEFAULT_TARGET_CAPACITY_FRACTION,
            Self::DEFAULT_CHANGE_FRACTION,
            Self::DEFAULT_OPTIMAL_PRUNING_DURATION_RANGE,
        )
    }
}

/// The dynamic pruning strategy that adjusts the number of entries to prune based on duration.
///
/// Ideally, we would want to prune down to `target_capacity_bytes`, but this would usually be too
/// slow. The `max_pruning_count` represents the maximum number of entries that we will prune at
/// one point, and it will be updated based on how long it takes in comparison to
/// `optimal_pruning_duration_range`:
/// - it will not change if pruning duration falls within `optimal_pruning_duration_range`
/// - it will increase by `max_pruning_count_change_fraction` if pruning duration is below the
/// `optimal_pruning_duration_range`
/// - it will decrease by `max_pruning_count_change_fraction` if pruning duration is above the
/// `optimal_pruning_duration_range`
pub struct PruningStrategy {
    /// The store configuration.
    config: IdIndexedV1StoreConfig,
    /// The maximum number of entries to prune at the time.
    max_pruning_count: u64,
}

impl PruningStrategy {
    /// The starting value for `max_pruning_count`.
    pub const STARTING_MAX_PRUNING_COUNT: u64 = 100;

    pub fn new(config: IdIndexedV1StoreConfig) -> Self {
        Self {
            config,
            max_pruning_count: Self::STARTING_MAX_PRUNING_COUNT,
        }
    }

    /// The capacity that we aim for when pruning.
    pub fn target_capacity_bytes(&self) -> u64 {
        (self.config.storage_capacity_bytes as f64
            * self.config.pruning_config.target_capacity_fraction)
            .round() as u64
    }

    /// Returns `true` when used capacity is above target capacity.
    pub fn is_usage_above_target_capacity(&self, usage_stats: &UsageStats) -> bool {
        usage_stats.is_above(self.target_capacity_bytes())
    }

    /// Returns `true` when used capacity is above storage capacity.
    pub fn should_prune(&self, usage_stats: &UsageStats) -> bool {
        usage_stats.is_above(self.config.storage_capacity_bytes)
    }

    /// Returns the number of entries to prune.
    pub fn get_pruning_count(&self, usage_stats: &UsageStats) -> u64 {
        if !self.should_prune(usage_stats) {
            return 0;
        }

        // If storage capacity is 0, prune everything.
        if self.config.storage_capacity_bytes == 0 {
            debug!(
                Db = %self.config.content_type,
                "Storage capacity is 0. Pruning everything ({})",
                usage_stats.entry_count
            );
            return usage_stats.entry_count;
        }

        self.estimate_to_delete_until_target(usage_stats)
            .min(self.max_pruning_count)
    }

    /// Should be called after pruning in order to update `max_pruning_count` based on pruning
    /// duration.
    pub fn observe_pruning_duration(&mut self, pruning_duration: Duration) {
        let pruning_config = &self.config.pruning_config;
        let optimal_pruning_duration = &pruning_config.optimal_pruning_duration_range;

        let change_ratio = if pruning_duration < optimal_pruning_duration.start {
            debug!(
                Db = %self.config.content_type,
                "Pruning was too fast. Increasing max_pruning_count",
            );
            1. + pruning_config.max_pruning_count_change_fraction
        } else if pruning_duration > optimal_pruning_duration.end {
            debug!(
                Db = %self.config.content_type,
                "Pruning was too slow. Decreasing max_pruning_count",
            );
            1. - pruning_config.max_pruning_count_change_fraction
        } else {
            // no change needed
            return;
        };

        self.max_pruning_count = (change_ratio * self.max_pruning_count as f64).round() as u64;
        self.max_pruning_count = self.max_pruning_count.max(1); // make sure it's at least one.
    }

    /// Returns the estimated number of items to delete to reach target capacity. It returns 0 if
    /// already below target capacity.
    fn estimate_to_delete_until_target(&self, usage_stats: &UsageStats) -> u64 {
        let Some(average_entry_size_bytes) = usage_stats.average_entry_size_bytes() else {
            // Means that storage is empty and nothing can be deleted.
            return 0;
        };

        // The estimated number of entries at the target capacity.
        let estimated_target_capacity_count =
            (self.target_capacity_bytes() as f64 / average_entry_size_bytes).floor() as u64;
        if usage_stats.entry_count > estimated_target_capacity_count {
            usage_stats.entry_count - estimated_target_capacity_count
        } else {
            0
        }
    }
}

impl Debug for PruningStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PruningStrategy")
            .field("max_pruning_count", &self.max_pruning_count)
            .finish()
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

    const DEFAULT_STORAGE_CAPACITY_BYTES: u64 = 1_000_000;

    fn create_default_pruning_strategy() -> PruningStrategy {
        create_pruning_strategy(DEFAULT_STORAGE_CAPACITY_BYTES)
    }

    fn create_pruning_strategy(storage_capacity_bytes: u64) -> PruningStrategy {
        let config = IdIndexedV1StoreConfig {
            content_type: ContentType::State,
            network: ProtocolId::State,
            node_id: NodeId::random(),
            node_data_dir: PathBuf::default(),
            storage_capacity_bytes,
            sql_connection_pool: Pool::new(SqliteConnectionManager::memory()).unwrap(),
            distance_fn: DistanceFunction::Xor,
            pruning_config: PruningConfig::default(),
        };
        PruningStrategy::new(config)
    }

    #[rstest]
    #[case::no_usage(0, 0, false)]
    #[case::low_usage(10, 100_000, false)]
    #[case::just_below_target_capacity(89, 890_000, false)]
    #[case::target_capacity(90, 900_000, false)]
    #[case::between_target_and_pruning(92, 920_000, false)]
    #[case::pruning(95, 950_000, false)]
    #[case::between_pruning_and_full(97, 970_000, true)]
    #[case::full(100, 1_000_000, true)]
    #[case::above_full(110, 1_100_000, true)]
    fn is_usage_above_target_capacity(
        #[case] entry_count: u64,
        #[case] total_entry_size_bytes: u64,
        #[case] expected: bool,
    ) {
        let pruning_strategy = create_default_pruning_strategy();
        let usage_stats = UsageStats {
            entry_count,
            total_entry_size_bytes,
        };

        assert_eq!(
            pruning_strategy.is_usage_above_target_capacity(&usage_stats),
            expected
        );
    }

    #[rstest]
    #[case::low_usage(50, 100_000, false, 0)]
    #[case::mid_usage(50, 500_000, false, 0)]
    #[case::between_target_and_full(50, 970_000, false, 0)]
    #[case::above_full_1(10, 1_050_000, true, 1)]
    #[case::above_full_2(20, 1_050_000, true, 2)]
    #[case::above_full_3(50, 1_050_000, true, 5)]
    #[case::above_full_4(500, 1_050_000, true, 48)]
    #[case::above_full_5(1000, 1_050_000, true, 96)]
    #[case::above_full_6(2000, 1_050_000, true, 100)]
    fn should_prune_and_pruning_count(
        #[case] entry_count: u64,
        #[case] total_entry_size_bytes: u64,
        #[case] should_prune: bool,
        #[case] pruning_count: u64,
    ) {
        let pruning_strategy = create_default_pruning_strategy();
        let usage_stats = UsageStats {
            entry_count,
            total_entry_size_bytes,
        };
        assert_eq!(
            pruning_strategy.should_prune(&usage_stats),
            should_prune,
            "testing should_prune"
        );
        assert_eq!(
            pruning_strategy.get_pruning_count(&usage_stats),
            pruning_count,
            "testing pruning_count"
        );
    }

    #[rstest]
    #[case::empty(0, 0, false, false, 0)]
    #[case::few_entries(100, 20_000, true, true, 100)]
    #[case::many_entries(10_000, 1_000_000, true, true, 10_000)]
    fn zero_storage_capacity(
        #[case] entry_count: u64,
        #[case] total_entry_size_bytes: u64,
        #[case] is_usage_above_target_capacity: bool,
        #[case] should_prune: bool,
        #[case] pruning_count: u64,
    ) {
        let pruning_strategy = create_pruning_strategy(/* storage_capacity_bytes= */ 0);
        let usage_stats = UsageStats {
            entry_count,
            total_entry_size_bytes,
        };
        assert_eq!(
            pruning_strategy.is_usage_above_target_capacity(&usage_stats),
            is_usage_above_target_capacity,
            "testing is_usage_above_target_capacity"
        );
        assert_eq!(
            pruning_strategy.should_prune(&usage_stats),
            should_prune,
            "testing should_prune"
        );
        assert_eq!(
            pruning_strategy.get_pruning_count(&usage_stats),
            pruning_count,
            "testing pruning_count"
        );
    }

    #[test]
    fn observe_pruning_duration_optimal() {
        let mut pruning_strategy = create_default_pruning_strategy();

        assert_eq!(pruning_strategy.max_pruning_count, 100);

        // Slightly slower than lower optimal bound -> max_pruning_count shouldn't change
        pruning_strategy.observe_pruning_duration(
            PruningConfig::DEFAULT_OPTIMAL_PRUNING_DURATION_RANGE.start + Duration::from_millis(1),
        );
        assert_eq!(pruning_strategy.max_pruning_count, 100);

        // Slightly faster than upper optimal bound -> max_pruning_count shouldn't change
        pruning_strategy.observe_pruning_duration(
            PruningConfig::DEFAULT_OPTIMAL_PRUNING_DURATION_RANGE.end - Duration::from_millis(1),
        );
        assert_eq!(pruning_strategy.max_pruning_count, 100);
    }

    #[test]
    fn observe_pruning_duration_too_fast() {
        let mut pruning_strategy = create_default_pruning_strategy();

        assert_eq!(pruning_strategy.max_pruning_count, 100);
        pruning_strategy.observe_pruning_duration(
            PruningConfig::DEFAULT_OPTIMAL_PRUNING_DURATION_RANGE.start - Duration::from_millis(1),
        );
        // max_pruning_count should have increased by DEFAULT_CHANGE_FRACTION (20%)
        assert_eq!(pruning_strategy.max_pruning_count, 120);
    }

    #[test]
    fn observe_pruning_duration_too_slow() {
        let mut pruning_strategy = create_default_pruning_strategy();

        assert_eq!(pruning_strategy.max_pruning_count, 100);
        pruning_strategy.observe_pruning_duration(
            PruningConfig::DEFAULT_OPTIMAL_PRUNING_DURATION_RANGE.end + Duration::from_millis(1),
        );
        // max_pruning_count should have decreased by DEFAULT_CHANGE_FRACTION (20%)
        assert_eq!(pruning_strategy.max_pruning_count, 80);
    }
}
