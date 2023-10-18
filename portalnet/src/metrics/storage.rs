use ethportal_api::types::distance::Distance;
use prometheus_exporter::{
    self,
    prometheus::{
        opts, register_gauge_vec_with_registry, register_int_gauge_vec_with_registry, GaugeVec,
        IntGaugeVec, Registry,
    },
};

/// Contains metrics reporters for portalnet storage.
#[derive(Clone, Debug)]
pub struct StorageMetrics {
    pub content_storage_usage_bytes: GaugeVec,
    pub total_storage_usage_bytes: GaugeVec,
    pub storage_capacity_bytes: GaugeVec,
    pub radius_ratio: GaugeVec,
    pub entry_count: IntGaugeVec,
}

const BYTES_IN_MB_F64: f64 = 1000.0 * 1000.0;

impl StorageMetrics {
    pub fn new(registry: &Registry) -> anyhow::Result<Self> {
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
use ethportal_api::types::distance::Metric;
use ethportal_api::OverlayContentKey;
use ethportal_api::types::distance::XorMetric;
#[test]
fn hi () {
    let bob = "0x978e003e087fb7f21833fd43136d126ba97e0fffb90b6c04ebea9ba55c877fee";
    let bob = ethereum_types::U256::from(bob);
    let ff = Distance::from(ethereum_types::U256::from("0xa8921df06cd85226122df115066de3b7f58e86e745be5dab824546920041c698"));
    let bob = Distance::from(bob);
    let radius_high_bytes = [
        bob.byte(31),
        bob.byte(30),
        bob.byte(29),
        bob.byte(28),
    ];
    let radius_int = u32::from_be_bytes(radius_high_bytes);
    let coverage_ratio = radius_int as f64 / u32::MAX as f64;
    let distance = ethportal_api::types::distance::XorMetric::distance(&bob.big_endian(), &ff.big_endian());
    let radius_high_bytes = [
        distance.byte(31),
        distance.byte(30),
        distance.byte(29),
        distance.byte(28),
    ];
    let radius_int = u32::from_be_bytes(radius_high_bytes);
    let coverage_ratio = radius_int as f64 / u32::MAX as f64;

    let content_key: ethportal_api::HistoryContentKey =
        serde_json::from_value(serde_json::json!("0x01823def5821988f866db5d2e9400ec9c9df613f299677aa577a0ff9c0ee631c35")).unwrap();
    let radius = Distance::from(ethereum_types::U256::from("0xcb878505d1ab04003cfcc57c142da04c66d71f8a52401722a870fdf07f181772"));
    let node_id = Distance::from(ethereum_types::U256::from("0x8c51e87021ff95f7af423a09d002a2b5448dca2fb5423929881db1cef7419c64"));
    if XorMetric::distance(&content_key.content_id(), &node_id.big_endian()) > radius {
        panic!("hi");
    }
    panic!("{}", ethportal_api::utils::bytes::hex_encode(content_key.content_id()));
    // panic!("{}", ethportal_api::utils::bytes::hex_encode(content_key.big_endian()));
}

use ssz_types::{typenum, BitList};

#[test]
fn hi2 () {
    let hi: BitList<typenum::U8> = BitList::with_capacity(5).unwrap();
    panic!("{}", hi.is_zero());
    // panic!("{}", ethportal_api::utils::bytes::hex_encode(content_key.big_endian()));
}


impl StorageMetricsReporter {
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
