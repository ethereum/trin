use std::time::Instant;

use prometheus_exporter::prometheus::Histogram;

/// Timer to measure and record the duration of an event.
///
/// This timer can be stopped and observed at most once manually.
/// Alternatively, if it isn't manually stopped it will be discarded in order to not record its
/// value.
#[must_use = "Timer should be kept in a variable otherwise it cannot observe duration"]
#[derive(Debug)]
pub struct CustomHistogramTimer {
    /// A histogram for automatic recording of observations.
    histogram: Histogram,
    /// Whether the timer has already been observed once.
    observed: bool,
    /// Starting instant for the timer.
    start: Instant,
}

impl CustomHistogramTimer {
    pub fn new(histogram: Histogram) -> Self {
        Self {
            histogram,
            observed: false,
            start: Instant::now(),
        }
    }

    /// Observe and record timer duration (in seconds).
    ///
    /// It observes the floating-point number of seconds elapsed since the timer
    /// started, and it records that value to the attached histogram.
    pub fn observe_duration(self) {
        self.stop_and_record();
    }

    /// Observe, record and return timer duration (in seconds).
    ///
    /// It observes and returns a floating-point number for seconds elapsed since
    /// the timer started, recording that value to the attached histogram.
    pub fn stop_and_record(self) -> f64 {
        let mut timer = self;
        timer.observe(true)
    }

    /// Observe and return timer duration (in seconds).
    ///
    /// It returns a floating-point number of seconds elapsed since the timer started,
    /// without recording to any histogram.
    pub fn stop_and_discard(self) -> f64 {
        let mut timer = self;
        timer.observe(false)
    }

    fn observe(&mut self, record: bool) -> f64 {
        let v = Instant::now().saturating_duration_since(self.start);
        let nanos = f64::from(v.subsec_nanos()) / 1e9;
        let v = v.as_secs() as f64 + nanos;
        self.observed = true;
        if record {
            self.histogram.observe(v);
        }
        v
    }
}

impl Drop for CustomHistogramTimer {
    fn drop(&mut self) {
        if !self.observed {
            self.observe(false);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{f64::EPSILON, thread, time::Duration};

    use prometheus_exporter::prometheus::{
        core::Collector, Histogram, HistogramOpts, DEFAULT_BUCKETS,
    };

    use crate::utils::CustomHistogramTimer;

    /// Test taken from https://docs.rs/prometheus/0.13.3/src/prometheus/histogram.rs.html#1217-1260
    /// Modified to work with CustomHistogramTimer
    #[test]
    fn test_histogram() {
        let opts = HistogramOpts::new("test1", "test help")
            .const_label("a", "1")
            .const_label("b", "2");
        let histogram = Histogram::with_opts(opts).unwrap();
        histogram.observe(1.0);

        let timer = CustomHistogramTimer::new(histogram.clone());
        thread::sleep(Duration::from_millis(100));
        timer.observe_duration();

        // In this thread the timer isn't manually closed so its result will be dropped
        let timer = CustomHistogramTimer::new(histogram.clone());
        let handler = thread::spawn(move || {
            let _timer = timer;
            thread::sleep(Duration::from_millis(400));
        });
        assert!(handler.join().is_ok());

        let mut mfs = histogram.collect();
        assert_eq!(mfs.len(), 1);

        let mf = mfs.pop().unwrap();
        let m = mf.get_metric().first().unwrap();
        // result is 2 because the 3rd timer was dropped and hence not counted
        assert_eq!(m.get_label().len(), 2);
        let proto_histogram = m.get_histogram();
        assert_eq!(proto_histogram.get_sample_count(), 2);
        // only 1.1+ seconds was observed because the 3rd timer was dropped and hence not counted
        assert!(proto_histogram.get_sample_sum() >= 1.1);
        assert_eq!(proto_histogram.get_bucket().len(), DEFAULT_BUCKETS.len());

        let buckets = vec![1.0, 2.0, 3.0];
        let opts = HistogramOpts::new("test2", "test help").buckets(buckets.clone());
        let histogram = Histogram::with_opts(opts).unwrap();
        let mut mfs = histogram.collect();
        assert_eq!(mfs.len(), 1);

        let mf = mfs.pop().unwrap();
        let m = mf.get_metric().first().unwrap();
        assert_eq!(m.get_label().len(), 0);
        let proto_histogram = m.get_histogram();
        assert_eq!(proto_histogram.get_sample_count(), 0);
        assert!((proto_histogram.get_sample_sum() - 0.0) < EPSILON);
        assert_eq!(proto_histogram.get_bucket().len(), buckets.len())
    }
}
