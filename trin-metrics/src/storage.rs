use std::time::Duration;

use ethportal_api::types::{distance::Distance, portal_wire::ProtocolId};
use prometheus_exporter::{
    self,
    prometheus::{
        histogram_opts, opts, register_gauge_vec_with_registry,
        register_histogram_vec_with_registry, register_int_gauge_vec_with_registry, GaugeVec,
        HistogramVec, IntGaugeVec, Registry,
    },
};

use crate::{portalnet::PORTALNET_METRICS, timer::DiscardOnDropHistogramTimer};

/// Contains metrics reporters for portalnet storage.
#[derive(Clone, Debug)]
pub struct StorageMetrics {
    pub process_timer: HistogramVec,
    pub content_storage_usage_bytes: GaugeVec,
    pub total_storage_usage_bytes: GaugeVec,
    pub storage_capacity_bytes: GaugeVec,
    pub radius_ratio: GaugeVec,
    pub entry_count: IntGaugeVec,
}

const BYTES_IN_MB_F64: f64 = 1000.0 * 1000.0;

impl StorageMetrics {
    pub fn new(registry: &Registry) -> anyhow::Result<Self> {
        let process_timer = register_histogram_vec_with_registry!(
            histogram_opts!(
                "trin_storage_process_timer",
                "the process time of various storage functions"
            ),
            &["protocol", "function"],
            registry
        )?;
        let content_storage_usage_bytes = register_gauge_vec_with_registry!(
            opts!(
                "trin_content_storage_usage_bytes",
                "sum of size of individual content stored, in bytes"
            ),
            &["protocol"],
            registry
        )?;
        let total_storage_usage_bytes = register_gauge_vec_with_registry!(
            opts!(
                "trin_total_storage_usage_bytes",
                "full on-disk database size, in bytes"
            ),
            &["protocol"],
            registry
        )?;
        let storage_capacity_bytes = register_gauge_vec_with_registry!(
            opts!(
                "trin_storage_capacity_bytes",
                "user-defined limit on storage usage, in bytes"
            ),
            &["protocol"],
            registry
        )?;
        let radius_ratio = register_gauge_vec_with_registry!(
            opts!(
                "trin_radius_ratio",
                "the fraction of the whole data ring covered by the data radius"
            ),
            &["protocol"],
            registry
        )?;
        let entry_count = register_int_gauge_vec_with_registry!(
            opts!("trin_entry_count", "total number of storage entries"),
            &["protocol"],
            registry
        )?;
        Ok(Self {
            process_timer,
            content_storage_usage_bytes,
            total_storage_usage_bytes,
            storage_capacity_bytes,
            radius_ratio,
            entry_count,
        })
    }
}

#[derive(Clone, Debug)]
pub struct StorageMetricsReporter {
    pub protocol: String,
    pub storage_metrics: StorageMetrics,
}

impl StorageMetricsReporter {
    pub fn new(protocol_id: ProtocolId) -> Self {
        Self {
            storage_metrics: PORTALNET_METRICS.storage(),
            protocol: protocol_id.to_string(),
        }
    }

    pub fn start_process_timer(&self, storage_function: &str) -> DiscardOnDropHistogramTimer {
        DiscardOnDropHistogramTimer::new(
            self.storage_metrics
                .process_timer
                .with_label_values(&[&self.protocol, storage_function])
                .clone(),
        )
    }

    pub fn stop_process_timer(&self, timer: DiscardOnDropHistogramTimer) -> Duration {
        Duration::from_secs_f64(timer.stop_and_record())
    }

    pub fn report_content_data_storage_bytes(&self, bytes: f64) {
        self.storage_metrics
            .content_storage_usage_bytes
            .with_label_values(&[&self.protocol])
            .set(bytes);
    }

    pub fn report_total_storage_usage_bytes(&self, bytes: f64) {
        self.storage_metrics
            .total_storage_usage_bytes
            .with_label_values(&[&self.protocol])
            .set(bytes);
    }

    pub fn report_storage_capacity_bytes(&self, bytes: f64) {
        self.storage_metrics
            .storage_capacity_bytes
            .with_label_values(&[&self.protocol])
            .set(bytes);
    }

    pub fn report_radius(&self, radius: Distance) {
        let radius_high_bytes = [
            radius.byte(31),
            radius.byte(30),
            radius.byte(29),
            radius.byte(28),
        ];
        let radius_int = u32::from_be_bytes(radius_high_bytes);
        let coverage_ratio = radius_int as f64 / u32::MAX as f64;
        self.storage_metrics
            .radius_ratio
            .with_label_values(&[&self.protocol])
            .set(coverage_ratio);
    }

    pub fn report_entry_count(&self, count: u64) {
        let count: i64 = count
            .try_into()
            .expect("Number of db entries will be small enough to fit in i64");
        self.storage_metrics
            .entry_count
            .with_label_values(&[&self.protocol])
            .set(count);
    }

    pub fn increase_entry_count(&self) {
        self.storage_metrics
            .entry_count
            .with_label_values(&[&self.protocol])
            .inc();
    }

    pub fn decrease_entry_count(&self) {
        self.storage_metrics
            .entry_count
            .with_label_values(&[&self.protocol])
            .dec();
    }

    pub fn get_summary(&self) -> String {
        let radius_percent = self
            .storage_metrics
            .radius_ratio
            .with_label_values(&[&self.protocol])
            .get()
            * 100.0;
        format!(
            "radius={:.*}% content={:.1}/{}mb #={} disk={:.1}mb",
            Self::precision_for_percentage(radius_percent),
            radius_percent,
            self.storage_metrics
                .content_storage_usage_bytes
                .with_label_values(&[&self.protocol])
                .get()
                / BYTES_IN_MB_F64,
            self.storage_metrics
                .storage_capacity_bytes
                .with_label_values(&[&self.protocol])
                .get()
                / BYTES_IN_MB_F64,
            self.storage_metrics
                .entry_count
                .with_label_values(&[&self.protocol])
                .get(),
            self.storage_metrics
                .total_storage_usage_bytes
                .with_label_values(&[&self.protocol])
                .get()
                / BYTES_IN_MB_F64,
        )
    }

    pub fn precision_for_percentage(percent: f64) -> usize {
        match percent {
            x if x >= 10.0 => 0,
            x if x >= 1.0 => 1,
            x if x >= 0.1 => 2,
            x if x >= 0.01 => 3,
            _ => 4,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub mod test {
    use super::*;

    #[test]
    fn test_precision_for_percentage() {
        fn formatted_percent(ratio: f64) -> String {
            let precision = StorageMetricsReporter::precision_for_percentage(ratio * 100.0);
            format!("{:.*}%", precision, ratio * 100.0)
        }
        assert_eq!(formatted_percent(1.0), "100%");
        assert_eq!(formatted_percent(0.9999), "100%");
        assert_eq!(formatted_percent(0.9949), "99%");

        assert_eq!(formatted_percent(0.10001), "10%");
        assert_eq!(formatted_percent(0.1), "10%");
        assert_eq!(formatted_percent(0.09949), "9.9%");

        assert_eq!(formatted_percent(0.010001), "1.0%");
        assert_eq!(formatted_percent(0.01), "1.0%");
        assert_eq!(formatted_percent(0.009949), "0.99%");

        assert_eq!(formatted_percent(0.0010001), "0.10%");
        assert_eq!(formatted_percent(0.001), "0.10%");
        assert_eq!(formatted_percent(0.0009949), "0.099%");

        assert_eq!(formatted_percent(0.00010001), "0.010%");
        assert_eq!(formatted_percent(0.0001), "0.010%");
        assert_eq!(formatted_percent(0.00009949), "0.0099%");

        assert_eq!(formatted_percent(0.000010001), "0.0010%");
        assert_eq!(formatted_percent(0.00001), "0.0010%");
        assert_eq!(formatted_percent(0.0000095), "0.0010%");
        assert_eq!(formatted_percent(0.00000949), "0.0009%");

        assert_eq!(formatted_percent(0.0000010001), "0.0001%");
        assert_eq!(formatted_percent(0.000001), "0.0001%");
        assert_eq!(formatted_percent(0.0000009949), "0.0001%");
        assert_eq!(formatted_percent(0.0000005001), "0.0001%");
        assert_eq!(formatted_percent(0.0000004999), "0.0000%");
        assert_eq!(formatted_percent(0.0), "0.0000%");

        // We mostly care that values outside of [0.0, 1.0] do not crash, but
        // for now we also check that they pin to 0 or 4.
        assert_eq!(StorageMetricsReporter::precision_for_percentage(101.0), 0);
        assert_eq!(StorageMetricsReporter::precision_for_percentage(-0.001), 4);
        assert_eq!(StorageMetricsReporter::precision_for_percentage(-1000.0), 4);
    }
}
