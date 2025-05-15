use std::sync::Arc;

use anyhow::{anyhow, bail};
use ethportal_api::consensus::{
    constants::SLOTS_PER_EPOCH,
    historical_summaries::{historical_summary_index, HistoricalSummaries, HistoricalSummary},
};
use tokio::sync::RwLock;

use crate::oracle::HeaderOracle;

#[derive(Debug, Clone)]
pub enum HistoricalSummariesSource {
    /// The historical summaries are provided by the header oracle.
    HeaderOracle(Arc<RwLock<HeaderOracle>>),
    /// The historical summaries are provided by passed historical summaries.
    HistoricalSummaries(HistoricalSummaries),
}

#[derive(Debug, Clone)]
pub struct HistoricalSummariesProvider {
    cache: Arc<RwLock<HistoricalSummaries>>,
    source: HistoricalSummariesSource,
}

impl HistoricalSummariesProvider {
    pub fn new(source: HistoricalSummariesSource) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HistoricalSummaries::default())),
            source,
        }
    }

    pub async fn get_historical_summary(&self, slot: u64) -> anyhow::Result<HistoricalSummary> {
        let epoch = slot / SLOTS_PER_EPOCH;
        let historical_summary_index = historical_summary_index(slot).ok_or(anyhow!(
            "Can't provide Historical Summary for slot before Capella"
        ))?;

        // Check to see if we have the historical summaries in cache
        if let Some(historical_summary) = self.cache.read().await.get(historical_summary_index) {
            return Ok(historical_summary.clone());
        }

        let historical_summaries = match &self.source {
            HistoricalSummariesSource::HeaderOracle(header_oracle) => {
                &header_oracle
                    .read()
                    .await
                    .get_historical_summary(epoch)
                    .await?
            }
            HistoricalSummariesSource::HistoricalSummaries(historical_summaries) => {
                historical_summaries
            }
        };

        match historical_summaries.get(historical_summary_index) {
            Some(historical_summary) => {
                // Update the cache with the historical summary
                *self.cache.write().await = historical_summaries.clone();
                Ok(historical_summary.clone())
            }
            None => {
                bail!("Historical summary index out of bounds: {historical_summary_index}")
            }
        }
    }
}
