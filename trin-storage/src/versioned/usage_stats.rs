use trin_metrics::storage::StorageMetricsReporter;

/// Contains information about number and size of entries that is stored.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UsageStats {
    /// The total count of stored entries
    pub entry_count: u64,
    /// The total sum of sizes of stored entries
    pub total_entry_size_bytes: u64,
}

impl UsageStats {
    pub fn new(entry_count: u64, total_entry_size_bytes: u64) -> Self {
        Self {
            entry_count,
            total_entry_size_bytes,
        }
    }

    /// Returns the average entry size, or `None` when empty.
    pub fn average_entry_size_bytes(&self) -> Option<f64> {
        if self.entry_count == 0 {
            Option::None
        } else {
            Option::Some(self.total_entry_size_bytes as f64 / self.entry_count as f64)
        }
    }

    /// Returns whether total entry size is above provided value
    pub fn is_above(&self, size_bytes: u64) -> bool {
        self.total_entry_size_bytes > size_bytes
    }

    /// Reports entry count and content data storage to the metrics reporter
    pub fn report_metrics(&self, metrics: &StorageMetricsReporter) {
        metrics.report_entry_count(self.entry_count);
        metrics.report_content_data_storage_bytes(self.total_entry_size_bytes as f64);
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::*;

    #[test]
    fn average_entry_size_bytes() -> Result<()> {
        assert_eq!(UsageStats::default().average_entry_size_bytes(), None);

        assert_eq!(
            UsageStats::new(/* entry_count= */ 1, /* total_entry_size= */ 100)
                .average_entry_size_bytes(),
            Some(100.0)
        );

        assert_eq!(
            UsageStats::new(/* entry_count= */ 2, /* total_entry_size= */ 300)
                .average_entry_size_bytes(),
            Some(150.0)
        );

        assert_eq!(
            UsageStats::new(/* entry_count= */ 3, /* total_entry_size= */ 600)
                .average_entry_size_bytes(),
            Some(200.0)
        );

        assert_eq!(
            UsageStats::new(/* entry_count= */ 1_200, /* total_entry_size= */ 98_070)
                .average_entry_size_bytes(),
            Some(81.725)
        );

        Ok(())
    }
}
