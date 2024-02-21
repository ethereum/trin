use std::time::Instant;

use prometheus_exporter::prometheus::Histogram;

/// Timer to measure and record the duration of an event.
///
/// This timer can be stopped and observed at most once manually.
/// Alternatively, if it isn't manually stopped it will be discarded in order to not record its
/// value.
#[must_use = "Timer should be kept in a variable otherwise it cannot observe duration"]
#[derive(Debug)]
pub struct DiscardOnDropHistogramTimer {
    /// A histogram for automatic recording of observations.
    histogram: Histogram,
    /// Whether the timer has already been observed once.
    observed: bool,
    /// Starting instant for the timer.
    start: Instant,
}

impl DiscardOnDropHistogramTimer {
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
        let duration_eclipsed_since_start = Instant::now().saturating_duration_since(self.start);
        let nanos = f64::from(duration_eclipsed_since_start.subsec_nanos()) / 1e9;
        let seconds_eclipsed_since_start = duration_eclipsed_since_start.as_secs() as f64 + nanos;
        self.observed = true;
        if record {
            self.histogram.observe(seconds_eclipsed_since_start);
        }
        seconds_eclipsed_since_start
    }
}

impl Drop for DiscardOnDropHistogramTimer {
    fn drop(&mut self) {
        if !self.observed {
            self.observe(false);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{thread, time::Duration};

    use prometheus_exporter::prometheus::{core::Collector, Histogram, HistogramOpts};

    use crate::timer::DiscardOnDropHistogramTimer;

    #[test]
    fn test_observe_duration() {
        let opts =
            HistogramOpts::new("test_observe_duration", "testing").const_label("defense", "1");
        let histogram = Histogram::with_opts(opts).unwrap();

        let timer = DiscardOnDropHistogramTimer::new(histogram.clone());
        thread::sleep(Duration::from_millis(100));
        timer.observe_duration();

        let mut metric_families = histogram.collect();
        assert_eq!(metric_families.len(), 1);

        let metric_family = metric_families.pop().unwrap();
        let metric = metric_family.get_metric().first().unwrap();
        assert_eq!(metric.get_label().len(), 1);
        let proto_histogram = metric.get_histogram();
        assert_eq!(proto_histogram.get_sample_count(), 1);
        assert!(proto_histogram.get_sample_sum() >= 0.1);
    }

    #[test]
    fn test_observe_duration_in_thread() {
        let opts = HistogramOpts::new("test_observe_duration_in_thread", "testing")
            .const_label("defense", "1");
        let histogram = Histogram::with_opts(opts).unwrap();

        let timer = DiscardOnDropHistogramTimer::new(histogram.clone());
        let handler = thread::spawn(move || {
            let timer = timer;
            thread::sleep(Duration::from_millis(100));
            timer.observe_duration();
        });
        assert!(handler.join().is_ok());

        let mut metric_families = histogram.collect();
        assert_eq!(metric_families.len(), 1);

        let metric_family = metric_families.pop().unwrap();
        let metric = metric_family.get_metric().first().unwrap();
        assert_eq!(metric.get_label().len(), 1);
        let proto_histogram = metric.get_histogram();
        assert_eq!(proto_histogram.get_sample_count(), 1);
        assert!(proto_histogram.get_sample_sum() >= 0.1);
    }

    #[test]
    fn test_stop_and_record_in_thread() {
        let opts = HistogramOpts::new("test_stop_and_record_in_thread", "testing")
            .const_label("defense", "1");
        let histogram = Histogram::with_opts(opts).unwrap();

        let timer = DiscardOnDropHistogramTimer::new(histogram.clone());
        let handler = thread::spawn(move || {
            let timer = timer;
            thread::sleep(Duration::from_millis(100));
            let time = timer.stop_and_record();
            assert!(time >= 0.1);
        });
        assert!(handler.join().is_ok());

        let mut metric_families = histogram.collect();
        assert_eq!(metric_families.len(), 1);

        let metric_family = metric_families.pop().unwrap();
        let metric = metric_family.get_metric().first().unwrap();
        assert_eq!(metric.get_label().len(), 1);
        let proto_histogram = metric.get_histogram();
        assert_eq!(proto_histogram.get_sample_count(), 1);
        assert!(proto_histogram.get_sample_sum() >= 0.1);
    }

    #[test]
    fn test_stop_and_record() {
        let opts =
            HistogramOpts::new("test_stop_and_record", "testing").const_label("defense", "1");
        let histogram = Histogram::with_opts(opts).unwrap();

        let timer = DiscardOnDropHistogramTimer::new(histogram.clone());
        thread::sleep(Duration::from_millis(100));
        let time = timer.stop_and_record();
        assert!(time >= 0.1);

        let mut metric_families = histogram.collect();
        assert_eq!(metric_families.len(), 1);

        let metric_family = metric_families.pop().unwrap();
        let metric = metric_family.get_metric().first().unwrap();
        assert_eq!(metric.get_label().len(), 1);
        let proto_histogram = metric.get_histogram();
        assert_eq!(proto_histogram.get_sample_count(), 1);
        assert!(proto_histogram.get_sample_sum() >= 0.1);
    }

    #[test]
    fn test_stop_and_discard() {
        let opts =
            HistogramOpts::new("test_stop_and_discard", "testing").const_label("defense", "1");
        let histogram = Histogram::with_opts(opts).unwrap();

        let timer = DiscardOnDropHistogramTimer::new(histogram.clone());
        thread::sleep(Duration::from_millis(100));
        let time = timer.stop_and_discard();
        assert!(time >= 0.1);

        let mut metric_families = histogram.collect();
        assert_eq!(metric_families.len(), 1);

        let metric_family = metric_families.pop().unwrap();
        let metric = metric_family.get_metric().first().unwrap();
        assert_eq!(metric.get_label().len(), 1);
        let proto_histogram = metric.get_histogram();
        assert_eq!(proto_histogram.get_sample_count(), 0);
        assert!(proto_histogram.get_sample_sum() >= 0.0);
    }

    #[test]
    fn test_discard_through_explicit_drop() {
        let opts = HistogramOpts::new("test_discard_through_explicit_drop", "testing")
            .const_label("defense", "1");
        let histogram = Histogram::with_opts(opts).unwrap();

        let timer = DiscardOnDropHistogramTimer::new(histogram.clone());
        thread::sleep(Duration::from_millis(100));
        drop(timer);

        let mut metric_families = histogram.collect();
        assert_eq!(metric_families.len(), 1);

        let metric_family = metric_families.pop().unwrap();
        let metric = metric_family.get_metric().first().unwrap();
        assert_eq!(metric.get_label().len(), 1);
        let proto_histogram = metric.get_histogram();
        assert_eq!(proto_histogram.get_sample_count(), 0);
        assert!(proto_histogram.get_sample_sum() >= 0.0);
    }

    #[test]
    fn test_discard_through_implicit_drop() {
        let opts = HistogramOpts::new("test_discard_through_implicit_drop", "testing")
            .const_label("defense", "1");
        let histogram = Histogram::with_opts(opts).unwrap();

        {
            let _timer = DiscardOnDropHistogramTimer::new(histogram.clone());
            thread::sleep(Duration::from_millis(100));
        }

        let mut metric_families = histogram.collect();
        assert_eq!(metric_families.len(), 1);

        let metric_family = metric_families.pop().unwrap();
        let metric = metric_family.get_metric().first().unwrap();
        assert_eq!(metric.get_label().len(), 1);
        let proto_histogram = metric.get_histogram();
        assert_eq!(proto_histogram.get_sample_count(), 0);
        assert!(proto_histogram.get_sample_sum() >= 0.0);
    }

    #[test]
    fn test_discard_through_implicit_drop_in_thread() {
        let opts = HistogramOpts::new("test_discard_through_implicit_drop_in_thread", "testing")
            .const_label("defense", "1");
        let histogram = Histogram::with_opts(opts).unwrap();

        let timer = DiscardOnDropHistogramTimer::new(histogram.clone());
        let handler = thread::spawn(move || {
            let _timer = timer;
            thread::sleep(Duration::from_millis(100));
        });
        assert!(handler.join().is_ok());

        let mut metric_families = histogram.collect();
        assert_eq!(metric_families.len(), 1);

        let metric_family = metric_families.pop().unwrap();
        let metric = metric_family.get_metric().first().unwrap();
        assert_eq!(metric.get_label().len(), 1);
        let proto_histogram = metric.get_histogram();
        assert_eq!(proto_histogram.get_sample_count(), 0);
        assert!(proto_histogram.get_sample_sum() >= 0.0);
    }
}
