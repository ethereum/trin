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
