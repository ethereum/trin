use std::collections::HashMap;

use anyhow::{bail, ensure};
use e2store::{
    era1::Era1,
    utils::{get_era1_files, get_era_files, ERA1_FILE_COUNT},
};
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client,
};
use tokio::task::JoinHandle;
use tracing::info;

use super::{
    binary_search::EraBinarySearch,
    types::{EraType, ProcessedBlock, ProcessedEra},
};
use crate::era::{
    constants::FIRST_ERA_EPOCH_WITH_EXECUTION_PAYLOAD,
    utils::{download_raw_era, process_era1_file, process_era_file},
};

pub struct EraManager {
    next_block_number: u64,
    current_era: Option<ProcessedEra>,
    next_era: Option<JoinHandle<anyhow::Result<ProcessedEra>>>,
    http_client: Client,
    era1_files: HashMap<u64, String>,
    era_files: HashMap<u64, String>,
}

impl EraManager {
    pub async fn new(next_block_number: u64) -> anyhow::Result<Self> {
        let http_client = Client::builder()
            .default_headers(HeaderMap::from_iter([(
                CONTENT_TYPE,
                HeaderValue::from_static("application/xml"),
            )]))
            .build()?;
        let era1_files = get_era1_files(&http_client).await?;
        let era_files = get_era_files(&http_client).await?;

        let mut era_manager = Self {
            next_block_number,
            current_era: None,
            next_era: None,
            http_client,
            era1_files,
            era_files,
        };

        // initialize the next era file
        // The first time using era_manager we need to find the current era file we are starting
        // from If the block is from a era file we will need to binary search to find which
        // era file contains the block we want
        let era1_files = era_manager.era1_files.clone();
        let http_client = era_manager.http_client.clone();
        era_manager.next_era = Some(tokio::spawn(async move {
            Self::fetch_processed_era_by_block_number(era1_files, http_client, next_block_number)
                .await
        }));

        Ok(era_manager)
    }

    pub fn next_block_number(&self) -> u64 {
        self.next_block_number
    }

    pub async fn last_fetched_block(&self) -> anyhow::Result<&ProcessedBlock> {
        let Some(current_era) = &self.current_era else {
            panic!("current_era should be initialized in EraManager::new");
        };
        ensure!(
            self.next_block_number > 0,
            "next_block_number should be greater than 0"
        );
        Ok(current_era.get_block(self.next_block_number - 1))
    }

    pub async fn get_next_block(&mut self) -> anyhow::Result<&ProcessedBlock> {
        let processed_era = match &self.current_era {
            Some(processed_era) if processed_era.contains_block(self.next_block_number) => {
                self.current_era.as_ref().expect("current_era to be some")
            }
            _ => {
                let current_era = self.get_next_processed_era().await?;
                self.current_era.insert(current_era)
            }
        };
        ensure!(
            processed_era.contains_block(self.next_block_number),
            "Block not found in era file"
        );
        let block = processed_era.get_block(self.next_block_number);
        self.next_block_number += 1;

        Ok(block)
    }

    /// gets the next era file and processes it, and starts fetching the next one in the background
    async fn get_next_processed_era(&mut self) -> anyhow::Result<ProcessedEra> {
        info!("Fetching the next era file");

        // Since EraManager is initialized in new(), next_era should never be none
        let new_current_era = match self.next_era.take() {
            Some(era_handle) => era_handle.await??,
            None => bail!("The next_era handle can't be None"),
        };

        // Download the next era file
        let mut next_era_type = new_current_era.era_type;
        let mut next_epoch_index = new_current_era.epoch_index + 1;
        // Handle transition from era1 to era
        if next_era_type == EraType::Era1 && next_epoch_index == ERA1_FILE_COUNT as u64 {
            next_era_type = EraType::Era;
            next_epoch_index = FIRST_ERA_EPOCH_WITH_EXECUTION_PAYLOAD;
        }
        let next_era_path = match next_era_type {
            EraType::Era1 => self.era1_files.get(&next_epoch_index).cloned(),
            EraType::Era => self.era_files.get(&next_epoch_index).cloned(),
        };
        let http_client = self.http_client.clone();
        let join_handle = tokio::spawn(async move {
            let Some(next_era_path) = next_era_path else {
                bail!("Unable to find next era file's path: index {next_epoch_index} type {next_era_type:?}");
            };
            let raw_era = download_raw_era(next_era_path, http_client.clone()).await?;
            match next_era_type {
                EraType::Era1 => process_era1_file(&raw_era, next_epoch_index),
                EraType::Era => process_era_file(&raw_era, next_epoch_index),
            }
        });
        self.next_era = Some(join_handle);

        Ok(new_current_era)
    }

    async fn fetch_processed_era_by_block_number(
        era1_files: HashMap<u64, String>,
        http_client: Client,
        block_number: u64,
    ) -> anyhow::Result<ProcessedEra> {
        if let EraType::Era1 = EraType::for_block_number(block_number) {
            let epoch_index = Era1::epoch_number_from_block_number(block_number);
            let Some(era1_path) = era1_files.get(&epoch_index).cloned() else {
                bail!("Unable to find era1 file's path during initialization: index {epoch_index}");
            };
            let raw_era1 = download_raw_era(era1_path, http_client.clone()).await?;

            return process_era1_file(&raw_era1, epoch_index);
        }

        EraBinarySearch::find_era_file(http_client.clone(), block_number).await
    }
}
