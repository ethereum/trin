use prometheus_exporter::prometheus::{
    default_registry, register_histogram_vec_with_registry, HistogramTimer, HistogramVec,
};

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
}
