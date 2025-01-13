use prometheus_exporter::prometheus::{
    opts, register_int_gauge_vec_with_registry, IntGaugeVec, Registry,
};

use crate::portalnet::PORTALNET_METRICS;

/// Contains metrics reporters for portalnet bridge.
#[derive(Clone, Debug)]
pub struct DownloaderMetrics {
    pub current_block: IntGaugeVec,
}

impl DownloaderMetrics {
    pub fn new(registry: &Registry) -> anyhow::Result<Self> {
        let current_block = register_int_gauge_vec_with_registry!(
            opts!(
                "downloader_current_block",
                "the current block number the downloader is on"
            ),
            &["downloader"],
            registry
        )?;
        Ok(Self { current_block })
    }
}

#[derive(Clone, Debug)]
pub struct DownloaderMetricsReporter {
    metrics: DownloaderMetrics,
}

impl Default for DownloaderMetricsReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl DownloaderMetricsReporter {
    pub fn new() -> Self {
        Self {
            metrics: PORTALNET_METRICS.downloader(),
        }
    }

    pub fn report_current_block(&self, block_number: u64) {
        self.metrics
            .current_block
            .with_label_values(&["downloader"])
            .set(block_number as i64);
    }
}
