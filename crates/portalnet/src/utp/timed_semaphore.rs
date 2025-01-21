use tokio::sync::OwnedSemaphorePermit;
use trin_metrics::timer::DiscardOnDropHistogramTimer;

/// A owned semaphore which records the time it has been alive from initialization to when drop() is
/// called.
#[derive(Debug)]
pub struct OwnedTimedSemaphorePermit {
    pub permit: OwnedSemaphorePermit,
    pub histogram_timer: DiscardOnDropHistogramTimer,
}

impl OwnedTimedSemaphorePermit {
    pub fn drop(self) {
        self.histogram_timer.stop_and_record();
        drop(self.permit);
    }
}
