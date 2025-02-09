use trin_metrics::storage::StorageMetricsReporter;

/// Contains information about number and size of entries that is stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsageStats {
    /// The total count of stored entries
    entry_count: u64,
    /// The total sum of sizes of stored entries
    total_entry_size_bytes: u64,
    /// The estimated additional disk usage per content. There is always some extra disk usage on
    /// top of entry size that should be taken into consideration when estimating total disk usage.
    extra_disk_usage_per_content: u64,
}

impl UsageStats {
    pub fn new(
        entry_count: u64,
        total_entry_size_bytes: u64,
        extra_disk_usage_per_content: u64,
    ) -> Self {
        Self {
            entry_count,
            total_entry_size_bytes,
            extra_disk_usage_per_content,
        }
    }

    /// Returns the total count of stored entries
    pub fn entry_count(&self) -> u64 {
        self.entry_count
    }

    /// Returns the sum of sizes of stored entries. For estimated disk usage,
    /// [UsageStats::estimated_disk_usage_bytes] should be used instead.
    pub fn total_entry_size_bytes(&self) -> u64 {
        self.total_entry_size_bytes
    }

    /// Returns the estimated total disk usage
    pub fn estimated_disk_usage_bytes(&self) -> u64 {
        self.total_entry_size_bytes + self.entry_count * self.extra_disk_usage_per_content
    }

    /// Returns the average disk usage per entry, or `None` when empty.
    pub fn average_entry_disk_usage_bytes(&self) -> Option<f64> {
        if self.entry_count == 0 {
            Option::None
        } else {
            let average_entry_size = self.total_entry_size_bytes as f64 / self.entry_count as f64;
            Option::Some(average_entry_size + self.extra_disk_usage_per_content as f64)
        }
    }

    /// Returns whether total entry size is above provided value
    pub fn is_estimated_disk_usage_above(&self, size_bytes: u64) -> bool {
        self.estimated_disk_usage_bytes() > size_bytes
    }

    /// Should be called when new entry is stored
    pub fn on_store(&mut self, entry_size_bytes: u64) {
        self.entry_count += 1;
        self.total_entry_size_bytes += entry_size_bytes;
    }

    /// Should be called when entry is deleted
    pub fn on_delete(&mut self, entry_size_bytes: u64) {
        self.on_multi_delete(1, entry_size_bytes);
    }

    /// Should be called when multiple entries are deleted
    pub fn on_multi_delete(
        &mut self,
        deleted_entry_count: u64,
        deleted_total_entry_size_bytes: u64,
    ) {
        self.entry_count -= deleted_entry_count;
        self.total_entry_size_bytes -= deleted_total_entry_size_bytes;
    }

    /// Reports entry count and content data storage to the metrics reporter
    pub fn report_metrics(&self, metrics: &StorageMetricsReporter) {
        metrics.report_entry_count(self.entry_count);
        metrics.report_content_data_storage_bytes(self.estimated_disk_usage_bytes() as f64);
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[test]
    fn average_entry_disk_usage_bytes_no_usage() {
        assert_eq!(
            UsageStats::new(0, 0, 100).average_entry_disk_usage_bytes(),
            None
        );
    }

    #[rstest]
    #[case::single_content_no_extra(1, 100, 0, 100.0)]
    #[case::single_content_with_extra(1, 100, 100, 200.0)]
    #[case::multi_content_no_extra(1_000, 123456, 0, 123.456)]
    #[case::multi_content_with_extra(1_000, 123456, 100, 223.456)]
    fn average_entry_disk_usage_bytes(
        #[case] entry_count: u64,
        #[case] total_entry_size: u64,
        #[case] extra_disk_usage_per_content: u64,
        #[case] expected_average_entry_disk_usage_bytes: f64,
    ) {
        let usage_stats =
            UsageStats::new(entry_count, total_entry_size, extra_disk_usage_per_content);
        let average_entry_disk_usage_bytes = usage_stats.average_entry_disk_usage_bytes().unwrap();
        assert!(
            (average_entry_disk_usage_bytes - expected_average_entry_disk_usage_bytes).abs()
                < 0.000001
        );
    }

    #[rstest]
    #[case::no_usage_no_extra(0, 0, 0, 0)]
    #[case::no_usage_with_extra(0, 0, 100, 0)]
    #[case::single_content_no_extra(1, 100, 0, 100)]
    #[case::single_content_with_extra(1, 100, 100, 200)]
    #[case::multi_content_no_extra(1_000, 123456, 0, 123456)]
    #[case::multi_content_with_extra(1_000, 123456, 100, 223456)]
    fn estimated_disk_usage_bytes(
        #[case] entry_count: u64,
        #[case] total_entry_size: u64,
        #[case] extra_disk_usage_per_content: u64,
        #[case] expected_estimated_disk_usage_bytes: u64,
    ) {
        let usage_stats =
            UsageStats::new(entry_count, total_entry_size, extra_disk_usage_per_content);
        assert_eq!(
            usage_stats.estimated_disk_usage_bytes(),
            expected_estimated_disk_usage_bytes,
        )
    }
}
