use prometheus_exporter::prometheus::{
    register_histogram_with_registry, register_int_gauge_with_registry, Histogram, IntGauge,
    Registry,
};

use crate::portalnet::PORTALNET_METRICS;

/// Contains metrics reporters related to following the head of the chain.
#[derive(Clone)]
pub struct ChainHeadMetrics {
    pub optimistic_slot: IntGauge,
    pub finalized_slot: IntGauge,
    pub optimistic_slot_lag: IntGauge,
    pub finalized_slot_lag: IntGauge,
    pub optimistic_slot_update_delay: Histogram,
    pub finalized_slot_update_delay: Histogram,
}

impl ChainHeadMetrics {
    pub fn new(registry: &Registry) -> anyhow::Result<Self> {
        let optimistic_slot = register_int_gauge_with_registry!(
            "optimistic_slot",
            "The slot of the known optimistic header",
            registry,
        )?;
        let finalized_slot = register_int_gauge_with_registry!(
            "finalized_slot",
            "The slot of the known finalized header",
            registry,
        )?;

        let optimistic_slot_lag = register_int_gauge_with_registry!(
            "optimistic_slot_lag",
            "The number of slots that optimistic header is behind the head of the chain",
            registry,
        )?;
        let finalized_slot_lag = register_int_gauge_with_registry!(
            "finalized_slot_lag",
            "The number of slots that finalized header is behind the head of the chain",
            registry,
        )?;

        let optimistic_slot_update_delay = register_histogram_with_registry!(
            "optimistic_slot_update_delay",
            "The number of slots that passed between optimistic slot update",
            registry,
        )?;
        let finalized_slot_update_delay = register_histogram_with_registry!(
            "finalized_slot_update_delay",
            "The number of slots that passed between finalized slot update",
            registry,
        )?;

        Ok(Self {
            optimistic_slot,
            finalized_slot,
            optimistic_slot_lag,
            finalized_slot_lag,
            optimistic_slot_update_delay,
            finalized_slot_update_delay,
        })
    }
}

#[derive(Clone)]
pub struct ChainHeadMetricsReporter {
    metrics: ChainHeadMetrics,
}

impl ChainHeadMetricsReporter {
    pub fn new() -> Self {
        Self {
            metrics: PORTALNET_METRICS.chain_head(),
        }
    }

    /// Should be called once every 12 seconds, in order to properly update the lag metrics
    pub fn on_slot(&self, current_slot: u64) {
        let current_slot = current_slot as i64;
        if self.metrics.optimistic_slot.get() > 0 {
            self.metrics
                .optimistic_slot_lag
                .set(current_slot - self.metrics.optimistic_slot.get());
        }
        if self.metrics.finalized_slot.get() > 0 {
            self.metrics
                .finalized_slot_lag
                .set(current_slot - self.metrics.finalized_slot.get());
        }
    }

    pub fn report_optimistic_slot_update(&self, optimistic_slot: u64) {
        if self.metrics.optimistic_slot.get() > 0 {
            self.metrics
                .optimistic_slot_update_delay
                .observe(optimistic_slot as f64 - self.metrics.optimistic_slot.get() as f64);
        }
        self.metrics.optimistic_slot.set(optimistic_slot as i64);
    }

    pub fn report_finalized_slot_update(&self, finalized_slot: u64) {
        if self.metrics.finalized_slot.get() > 0 {
            self.metrics
                .finalized_slot_update_delay
                .observe(finalized_slot as f64 - self.metrics.finalized_slot.get() as f64);
        }
        self.metrics.finalized_slot.set(finalized_slot as i64);
    }
}

impl Default for ChainHeadMetricsReporter {
    fn default() -> Self {
        Self::new()
    }
}
