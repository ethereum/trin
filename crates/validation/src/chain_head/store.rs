use ethportal_api::{
    consensus::historical_summaries::{
        historical_summary_index, HistoricalSummaries, HistoricalSummary,
    },
    light_client::header::LightClientHeader,
};
use trin_metrics::chain_head::ChainHeadMetricsReporter;

/// Responsible for holding the head of the chain data.
///
/// Most of the logic for updating and maintaing this data should be in [super::ChainHead], and
/// only the low level functionality should be done here.
pub(super) struct ChainHeadStore {
    pub latest: LightClientHeader,
    pub finalized: LightClientHeader,
    pub historical_summaries: HistoricalSummaries,
    metrics: ChainHeadMetricsReporter,
}

impl ChainHeadStore {
    pub fn new(
        latest: LightClientHeader,
        finalized: LightClientHeader,
        historical_summaries: HistoricalSummaries,
    ) -> Self {
        Self {
            latest,
            finalized,
            historical_summaries,
            metrics: ChainHeadMetricsReporter::new(),
        }
    }

    pub fn update_latest_if_newer(&mut self, header: LightClientHeader) {
        if self.latest.beacon().slot < header.beacon().slot {
            self.latest = header;
            self.metrics
                .report_optimistic_slot_update(self.latest.beacon().slot);
        }
    }

    pub fn update_finalized_if_newer(&mut self, header: LightClientHeader) {
        if self.finalized.beacon().slot < header.beacon().slot {
            self.finalized = header;
            self.metrics
                .report_finalized_slot_update(self.finalized.beacon().slot);
        }
    }

    pub fn historical_summary(&self, slot: u64) -> Option<HistoricalSummary> {
        let historical_summary_index = historical_summary_index(slot)?;
        self.historical_summaries
            .get(historical_summary_index)
            .cloned()
    }

    pub fn update_historical_summaries_if_newer(
        &mut self,
        historical_summaries: HistoricalSummaries,
    ) {
        if self.historical_summaries.len() < historical_summaries.len() {
            self.historical_summaries = historical_summaries
        }
    }
}
