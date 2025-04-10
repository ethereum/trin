use std::sync::Arc;

use anyhow::{anyhow, bail, ensure};
use e2store::{
    era::Era,
    utils::{get_era1_files, get_era_files},
};
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client,
};
use tracing::info;
use trin_execution::era::binary_search::EraBinarySearch;
use trin_validation::constants::{EPOCH_SIZE, MERGE_BLOCK_NUMBER};

// This struct provides various era files based on the epoch and makes
// them accessible via a specific block number from that epoch.
// - pre-merge: all epochs will correspond 1:1 with era1 files
// - merge-boundary: will have an era1 & era file
// - post-merge: all epochs will likely have 2 era files
pub struct EraProvider {
    first_source: EraSource,
    second_source: Option<EraSource>,
}

pub enum EraSource {
    // raw era1 file
    PreMerge(Arc<Vec<u8>>),
    // processed era file
    PostMerge(Arc<Era>),
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

        let first_source = match starting_block < MERGE_BLOCK_NUMBER {
            true => {
                let era1_paths = get_era1_files(&http_client).await?;
                let epoch_index = starting_block / EPOCH_SIZE;
                let era1_path = era1_paths.get(&epoch_index).ok_or(anyhow!(
                    "Era1 file not found for epoch index: {epoch_index}",
                ))?;
                let raw_era1 = fetch_bytes(http_client.clone(), era1_path).await?;
                EraSource::PreMerge(Arc::new(raw_era1))
            }
            false => {
                let era = fetch_era_file_for_block(http_client.clone(), starting_block).await?;
                EraSource::PostMerge(era)
            }
        };
        info!("First e2store file fetched for epoch: {epoch}");

        let second_source = match ending_block < MERGE_BLOCK_NUMBER {
            true => {
                info!("No second e2store file required for epoch: {epoch}");
                None
            }
            false => {
                // todo: if first source is era1, we know the era for next range
                let era = fetch_era_file_for_block(http_client.clone(), ending_block).await?;
                info!("Second e2store file fetched for epoch: {epoch}");
                Some(EraSource::PostMerge(era))
            }
        };
        Ok(Self {
            first_source,
            second_source,
        })
    }

    pub fn get_era1_for_block(&self, block_number: u64) -> anyhow::Result<Arc<Vec<u8>>> {
        ensure!(
            block_number < MERGE_BLOCK_NUMBER,
            "Invalid logic, tried to lookup era1 file for post-merge block"
        );
        Ok(match &self.first_source {
            EraSource::PreMerge(era1) => era1.clone(),
            EraSource::PostMerge(_) => {
                bail!("Era1 file not found for block number: {block_number}",)
            }
        })
    }

    pub fn get_era_for_block(&self, block_number: u64) -> anyhow::Result<Arc<Era>> {
        ensure!(
            block_number >= MERGE_BLOCK_NUMBER,
            "Invalid logic, tried to lookup era file for pre-merge block"
        );
        if let EraSource::PostMerge(era) = &self.first_source {
            if era.contains(block_number) {
                return Ok(era.clone());
            }
        }
        if let Some(EraSource::PostMerge(era)) = &self.second_source {
            if era.contains(block_number) {
                return Ok(era.clone());
            }
        }
        bail!("Era file not found for block number: {block_number}");
    }
}

async fn fetch_era_file_for_block(
    http_client: Client,
    block_number: u64,
) -> anyhow::Result<Arc<Era>> {
    ensure!(
        block_number >= MERGE_BLOCK_NUMBER,
        "Invalid logic, tried to fetch era file for pre-merge block"
    );
    info!("Starting binary search for era file for block number: {block_number}");
    let era = EraBinarySearch::find_era_file(http_client.clone(), block_number).await?;
    let era_links = get_era_files(&http_client).await?;
    let era_path = era_links.get(&era.epoch_index).ok_or(anyhow!(
        "Era file not found for block number: {block_number}",
    ))?;
    let raw_era = fetch_bytes(http_client.clone(), era_path).await?;
    Ok(Arc::new(Era::deserialize(&raw_era)?))
}

async fn fetch_bytes(http_client: Client, path: &str) -> anyhow::Result<Vec<u8>> {
    Ok(http_client.get(path).send().await?.bytes().await?.to_vec())
}
