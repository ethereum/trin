use std::sync::Arc;

use anyhow::{anyhow, bail, ensure};
use e2store::{
    era::{CompressedSignedBeaconBlock, Era},
    era1::Era1,
    utils::{get_era1_files, get_era_files},
};
use ethportal_api::consensus::beacon_state::HistoricalBatch;
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client,
};
use tracing::info;
use trin_execution::era::binary_search::EraBinarySearch;
use trin_validation::constants::{EPOCH_SIZE, MERGE_BLOCK_NUMBER};

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
}

impl From<Era> for MinimalEra {
    fn from(era: Era) -> Self {
        Self {
            blocks: era.blocks,
            historical_batch: HistoricalBatch {
                block_roots: era.era_state.state.block_roots().clone(),
                state_roots: era.era_state.state.state_roots().clone(),
            },
        }
    }
}

// This struct provides various era files based on the epoch and makes
// them accessible via a specific block number from that epoch.
// - pre-merge: all epochs will correspond 1:1 with era1 files
// - merge-boundary: will have an era1 & 2 era files
// - post-merge: all epochs will likely have 2 era files
pub struct EraProvider {
    pub sources: Vec<EraSource>,
}

impl EraProvider {
    pub async fn new(epoch: u64) -> anyhow::Result<Self> {
        info!("Fetching e2store files for epoch: {epoch}");
        let starting_block = epoch * EPOCH_SIZE;
        let ending_block = starting_block + EPOCH_SIZE;
        let http_client = Client::builder()
            .default_headers(HeaderMap::from_iter([(
                CONTENT_TYPE,
                HeaderValue::from_static("application/xml"),
            )]))
            .build()?;

        let mut next_block = starting_block;
        let mut sources = vec![];

        let mut previous_era_epoch_index = None;
        let era_links = get_era_files(&http_client).await?;
        while next_block < ending_block {
            let source = if next_block < MERGE_BLOCK_NUMBER {
                let era1_paths = get_era1_files(&http_client).await?;
                let epoch_index = next_block / EPOCH_SIZE;
                let era1_path = era1_paths.get(&epoch_index).ok_or(anyhow!(
                    "Era1 file not found for epoch index: {epoch_index}",
                ))?;
                let raw_era1 = fetch_bytes(http_client.clone(), era1_path).await?;
                EraSource::PreMerge(Arc::new(Era1::deserialize(&raw_era1)?))
            } else {
                let era = Arc::new(match previous_era_epoch_index {
                    Some(previous_epoch_index) => {
                        let era_path = era_links
                            .get(&(previous_epoch_index + 1))
                            .ok_or(anyhow!("Era file not found for block number: {next_block}",))?;
                        info!(
                            "Downloading era file for block number: {next_block}, path: {era_path}"
                        );
                        let raw_era = fetch_bytes(http_client.clone(), era_path).await?;
                        info!(
                            "Downloaded era file for block number: {next_block}, path: {era_path}"
                        );
                        let era = Era::deserialize(&raw_era)?;
                        previous_era_epoch_index = Some(era.epoch_index());
                        MinimalEra::from(era)
                    }
                    None => {
                        let era = EraBinarySearch::fetch_era_file(
                            http_client.clone(),
                            &era_links,
                            next_block,
                        )
                        .await?;
                        previous_era_epoch_index = Some(era.epoch_index());
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

    pub fn get_era1_for_block(&self, block_number: u64) -> anyhow::Result<Arc<Era1>> {
        ensure!(
            block_number < MERGE_BLOCK_NUMBER,
            "Invalid logic, tried to lookup era1 file for post-merge block"
        );
        Ok(match &self.sources[0] {
            EraSource::PreMerge(era1) => era1.clone(),
            EraSource::PostMerge(_) => {
                bail!("Era1 file not found for block number: {block_number}",)
            }
        })
    }

    pub fn get_block(
        &self,
        block_number: u64,
    ) -> anyhow::Result<(CompressedSignedBeaconBlock, &MinimalEra)> {
        ensure!(
            block_number >= MERGE_BLOCK_NUMBER,
            "Invalid logic, tried to lookup era file for pre-merge block"
        );
        for sources in self.sources.iter() {
            if let EraSource::PostMerge(era) = sources {
                let first_block_number = era.blocks[0].block.execution_block_number();
                let last_block_number = era.blocks[era.blocks.len() - 1]
                    .block
                    .execution_block_number();
                if (first_block_number..=last_block_number).contains(&block_number) {
                    if let Some(block) = era
                        .blocks
                        .iter()
                        .find(|block| block.block.execution_block_number() == block_number)
                    {
                        return Ok((block.clone(), era));
                    }
                }
            }
        }
        bail!("Couldn't find error file not found for block number: {block_number}");
    }
}

async fn fetch_bytes(http_client: Client, path: &str) -> anyhow::Result<Vec<u8>> {
    Ok(http_client.get(path).send().await?.bytes().await?.to_vec())
}
