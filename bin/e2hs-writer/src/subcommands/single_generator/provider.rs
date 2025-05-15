use std::sync::Arc;

use alloy_hardforks::EthereumHardforks;
use anyhow::{anyhow, bail, ensure};
use e2store::{
    e2hs::BLOCKS_PER_E2HS,
    era::{CompressedSignedBeaconBlock, Era},
    era1::{BlockTuple, Era1},
    utils::{get_era1_files, get_era_files},
};
use ethportal_api::{
    consensus::{
        beacon_block::SignedBeaconBlock, beacon_state::HistoricalBatch,
        constants::SLOTS_PER_HISTORICAL_ROOT, historical_summaries::HistoricalSummaries,
    },
    types::network_spec::network_spec,
};
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client,
};
use tracing::info;
use trin_execution::era::binary_search::EraBinarySearch;

pub enum EraSource {
    // processed era1 file
    PreMerge(Arc<Era1>),
    // processed era file
    PostMerge(Arc<MinimalEra>),
}

impl EraSource {
    pub fn last_block(&self) -> u64 {
        match self {
            EraSource::PreMerge(era1) => {
                era1.block_tuples[era1.block_tuples.len() - 1]
                    .header
                    .header
                    .number
            }
            EraSource::PostMerge(era) => era.blocks[era.blocks.len() - 1]
                .block
                .execution_block_number(),
        }
    }
}

/// Decompressed Era files are really big, so we only want to keep in memory what we need.
pub struct MinimalEra {
    pub blocks: Vec<CompressedSignedBeaconBlock>,
    pub historical_batch: HistoricalBatch,
    pub historical_summaries: Option<HistoricalSummaries>,
}

impl MinimalEra {
    pub fn get_block(&self, block_number: u64) -> Option<&SignedBeaconBlock> {
        let first_block_number = self.blocks[0].block.execution_block_number();
        let last_block_number = self.blocks[self.blocks.len() - 1]
            .block
            .execution_block_number();
        if (first_block_number..=last_block_number).contains(&block_number) {
            if let Some(block) = self
                .blocks
                .iter()
                .find(|block| block.block.execution_block_number() == block_number)
            {
                return Some(&block.block);
            }
        }
        None
    }
}

impl From<Era> for MinimalEra {
    fn from(era: Era) -> Self {
        Self {
            blocks: era.blocks,
            historical_batch: HistoricalBatch {
                block_roots: era.era_state.state.block_roots().clone(),
                state_roots: era.era_state.state.state_roots().clone(),
            },
            historical_summaries: era.era_state.state.historical_summaries().cloned().ok(),
        }
    }
}

// This struct provides various era files based on the index and makes
// them accessible via a specific block number from that index.
// - pre-merge: all indices will correspond 1:1 with era1 files
// - merge-boundary: will have an era1 & 2 era files
// - post-merge: all indices will likely have 2 era files
pub struct EraProvider {
    pub sources: Vec<EraSource>,
}

impl EraProvider {
    pub async fn new(index: u64) -> anyhow::Result<Self> {
        info!("Fetching e2store files for index: {index}");
        let starting_block = index * BLOCKS_PER_E2HS as u64;
        let ending_block = starting_block + BLOCKS_PER_E2HS as u64;
        let http_client = Client::builder()
            .default_headers(HeaderMap::from_iter([(
                CONTENT_TYPE,
                HeaderValue::from_static("application/xml"),
            )]))
            .build()?;

        let mut next_block = starting_block;
        let mut sources = vec![];

        let mut previous_era_index = None;
        let era_links = get_era_files(&http_client).await?;
        while next_block < ending_block {
            let source = if !network_spec().is_paris_active_at_block(next_block) {
                let era1_paths = get_era1_files(&http_client).await?;
                let era1_index = next_block / SLOTS_PER_HISTORICAL_ROOT;
                let era1_path = era1_paths
                    .get(&era1_index)
                    .ok_or(anyhow!("Era1 file not found for index: {era1_index}",))?;
                let raw_era1 = fetch_bytes(http_client.clone(), era1_path).await?;
                EraSource::PreMerge(Arc::new(Era1::deserialize(&raw_era1)?))
            } else {
                let era = Arc::new(match previous_era_index {
                    Some(previous_index) => {
                        let era_path = era_links
                            .get(&(previous_index + 1))
                            .ok_or(anyhow!("Era file not found for block number: {next_block}"))?;
                        info!(
                            "Downloading era file for block number: {next_block}, path: {era_path}"
                        );
                        let raw_era = fetch_bytes(http_client.clone(), era_path).await?;
                        info!(
                            "Downloaded era file for block number: {next_block}, path: {era_path}"
                        );
                        let era = Era::deserialize(&raw_era)?;
                        previous_era_index = Some(era.epoch_index());
                        MinimalEra::from(era)
                    }
                    None => {
                        let era = EraBinarySearch::fetch_era_file(
                            http_client.clone(),
                            &era_links,
                            next_block,
                        )
                        .await?;
                        previous_era_index = Some(era.epoch_index());
                        MinimalEra::from(era)
                    }
                });
                EraSource::PostMerge(era)
            };
            next_block = source.last_block() + 1;
            sources.push(source);
        }

        ensure!(
            sources.len() <= 3,
            "Provider should never download more then 3 e2store files"
        );
        Ok(Self { sources })
    }

    pub fn get_pre_merge(&self, block_number: u64) -> anyhow::Result<BlockTuple> {
        ensure!(
            !network_spec().is_paris_active_at_block(block_number),
            "Invalid logic, tried to lookup era1 file for post-merge block"
        );
        Ok(match &self.sources[0] {
            EraSource::PreMerge(era1) => {
                let block_tuple =
                    era1.block_tuples[(block_number % SLOTS_PER_HISTORICAL_ROOT) as usize].clone();
                ensure!(
                    block_tuple.header.header.number == block_number,
                    "Block number mismatch",
                );
                block_tuple
            }
            EraSource::PostMerge(_) => {
                bail!("Era1 file not found for block number: {block_number}")
            }
        })
    }

    pub fn get_post_merge(
        &self,
        block_number: u64,
    ) -> anyhow::Result<(&SignedBeaconBlock, &HistoricalBatch)> {
        ensure!(
            network_spec().is_paris_active_at_block(block_number),
            "Invalid logic, tried to lookup era file for pre-merge block"
        );
        for sources in self.sources.iter() {
            if let EraSource::PostMerge(era) = sources {
                if let Some(block) = era.get_block(block_number) {
                    return Ok((block, &era.historical_batch));
                }
            }
        }
        bail!("Couldn't find error file not found for block number: {block_number}");
    }

    /// Tries to find the historical summaries for the last era file, which would contain the latest
    /// historical summaries to prove against.
    ///
    /// Returns `None` if the last era file is not a post-merge era file.
    pub fn get_historical_summaries(&self) -> Option<HistoricalSummaries> {
        self.sources.last().and_then(|source| {
            if let EraSource::PostMerge(era) = source {
                era.historical_summaries.clone()
            } else {
                None
            }
        })
    }
}

async fn fetch_bytes(http_client: Client, path: &str) -> anyhow::Result<Vec<u8>> {
    Ok(http_client.get(path).send().await?.bytes().await?.to_vec())
}
