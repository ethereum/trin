use prometheus_exporter::prometheus::{
    histogram_opts, opts, register_histogram_vec_with_registry,
    register_int_gauge_vec_with_registry, HistogramTimer, HistogramVec, IntGaugeVec, Registry,
};

use crate::portalnet::PORTALNET_METRICS;

/// Contains metrics reporters for portalnet bridge.
#[derive(Clone, Debug)]
pub struct DownloaderMetrics {
    pub current_block: IntGaugeVec,
    pub find_content_timer: HistogramVec,
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
        let find_content_timer = register_histogram_vec_with_registry!(
            histogram_opts!(
                "downloader_find_content_timer",
                "the time it takes for find content query to complete"
            ),
            &["downloader"],
            registry
        )?;
        Ok(Self {
            current_block,
            find_content_timer,
        })
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

    pub fn start_find_content_timer(&self) -> HistogramTimer {
        self.metrics
            .find_content_timer
            .with_label_values(&["downloader"])
            .start_timer()
    }

    pub fn stop_find_content_timer(&self, timer: HistogramTimer) {
        timer.observe_duration()
    }
}
