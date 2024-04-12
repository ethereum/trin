use prometheus_exporter::{
    self,
    prometheus::{
        histogram_opts, opts, register_histogram_vec_with_registry,
        register_int_counter_vec_with_registry, register_int_gauge_vec_with_registry,
        HistogramTimer, HistogramVec, IntCounterVec, IntGaugeVec, Registry,
    },
};

use crate::portalnet::PORTALNET_METRICS;

/// Contains metrics reporters for portalnet bridge.
#[derive(Clone, Debug)]
pub struct BridgeMetrics {
    pub process_timer: HistogramVec,
    pub bridge_info: IntGaugeVec,
    pub gossip_total: IntCounterVec,
    pub current_block: IntGaugeVec,
}

impl BridgeMetrics {
    pub fn new(registry: &Registry) -> anyhow::Result<Self> {
        let process_timer = register_histogram_vec_with_registry!(
            histogram_opts!(
                "bridge_process_timer",
                "the process time of various bridge functions"
            ),
            &["bridge", "function"],
            registry
        )?;
        let bridge_info = register_int_gauge_vec_with_registry!(
            opts!("bridge_info", "total number of storage entries"),
            &["bridge", "bridge_mode"],
            registry
        )?;
        let gossip_total = register_int_counter_vec_with_registry!(
            opts!(
                "bridge_gossip_total",
                "count all content validations successful and failed"
            ),
            &["bridge", "success", "type"],
            registry
        )?;
        let current_block = register_int_gauge_vec_with_registry!(
            opts!(
                "bridge_current_block",
                "the current block number the bridge is on"
            ),
            &["bridge"],
            registry
        )?;
        Ok(Self {
            process_timer,
            bridge_info,
            gossip_total,
            current_block,
        })
    }
}

#[derive(Clone, Debug)]
pub struct BridgeMetricsReporter {
    pub bridge: String,
    pub bridge_metrics: BridgeMetrics,
}

impl BridgeMetricsReporter {
    pub fn new(bridge: String, bridge_mode: &str) -> Self {
        let bridge_metrics_reporter = Self {
            bridge_metrics: PORTALNET_METRICS.bridge(),
            bridge,
        };

        bridge_metrics_reporter.report_bridge_info(bridge_mode);
        bridge_metrics_reporter
    }

    pub fn start_process_timer(&self, bridge_function: &str) -> HistogramTimer {
        self.bridge_metrics
            .process_timer
            .with_label_values(&[&self.bridge, bridge_function])
            .start_timer()
    }

    pub fn stop_process_timer(&self, timer: HistogramTimer) {
        timer.observe_duration()
    }

    pub fn report_gossip_success(&self, success: bool, content_type: &str) {
        let labels: [&str; 3] = [&self.bridge, &success.to_string(), content_type];
        self.bridge_metrics
            .gossip_total
            .with_label_values(&labels)
            .inc();
    }

    fn report_bridge_info(&self, bridge_mode: &str) {
        let labels: [&str; 2] = [&self.bridge, bridge_mode];
        self.bridge_metrics
            .bridge_info
            .with_label_values(&labels)
            .inc();
    }

    pub fn report_current_block(&self, block_number: i64) {
        let labels: [&str; 1] = [&self.bridge];
        self.bridge_metrics
            .current_block
            .with_label_values(&labels)
            .set(block_number);
    }
}
