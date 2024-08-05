use prometheus_exporter::prometheus::{
    default_registry, register_histogram_vec_with_registry, register_int_gauge_vec_with_registry,
    HistogramTimer, HistogramVec, IntGaugeVec,
};

pub fn create_int_gauge_vec(name: &str, help: &str, label_names: &[&str]) -> IntGaugeVec {
    let registry = default_registry();
    register_int_gauge_vec_with_registry!(name, help, label_names, registry)
        .expect("failed to create int gauge vec")
}

pub fn set_int_gauge_vec(gauge_vec: &IntGaugeVec, value: i64, label_values: &[&str]) {
    gauge_vec.with_label_values(label_values).set(value);
}

pub fn create_histogram_vec(name: &str, help: &str, label_names: &[&str]) -> HistogramVec {
    let registry = default_registry();
    register_histogram_vec_with_registry!(name, help, label_names, registry)
        .expect("failed to create histogram")
}

pub fn start_timer_vec(histogram_vec: &HistogramVec, label_values: &[&str]) -> HistogramTimer {
    histogram_vec.with_label_values(label_values).start_timer()
}

pub fn stop_timer(timer: HistogramTimer) {
    timer.observe_duration()
}

lazy_static::lazy_static! {
    pub static ref BLOCK_PROCESSING_TIMES: HistogramVec = create_histogram_vec(
        "trin_execution_processing_times",
        "Duration of the sections it takes to execute a block",
        &["section"]
    );

    pub static ref TRANSACTION_PROCESSING_TIMES: HistogramVec = create_histogram_vec(
        "trin_execution_transaction_processing_times",
        "Duration of the sections it takes to execute sections of a transaction",
        &["section"]
    );

    pub static ref BUNDLE_COMMIT_PROCESSING_TIMES: HistogramVec = create_histogram_vec(
        "trin_execution_bundle_commit_processing_times",
        "Duration of the sections it takes for a bundle to be committed",
        &["section"]
    );

    pub static ref BLOCK_HEIGHT: IntGaugeVec = create_int_gauge_vec(
        "trin_execution_block_height",
        "The current block height",
        &[]
    );
}
