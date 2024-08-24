use e2store::{
    era1::Era1,
    utils::{get_era_file_download_links, get_shuffled_era1_files, ERA1_FILE_COUNT},
};
use surf::{Client, Config};
use tokio::task::JoinHandle;
use tracing::info;

use crate::era::{
    constants::FIRST_ERA_EPOCH_WITH_EXECUTION_PAYLOAD,
    utils::{download_raw_era, process_era1_file, process_era_file},
};

use super::{
    binary_search::EraBinarySearch,
    types::{EraType, ProcessedBlock, ProcessedEra},
};

pub struct EraManager {
    current_era: Option<ProcessedEra>,
    next_era: Option<JoinHandle<ProcessedEra>>,
    http_client: Client,
    era1_files: Vec<String>,
}

impl EraManager {
    pub async fn new() -> anyhow::Result<Self> {
        let http_client: Client = Config::new()
            .add_header("Content-Type", "application/xml")
            .expect("to be able to add header")
            .try_into()?;
        let era1_files = get_shuffled_era1_files(&http_client).await?;
        Ok(Self {
            current_era: None,
            next_era: None,
            http_client,
            era1_files,
        })
    }

    pub async fn get_block_by_number(
        &mut self,
        block_number: u64,
    ) -> anyhow::Result<&ProcessedBlock> {
        let processed_era = match &self.current_era {
            Some(processed_era) if processed_era.contains_block(block_number) => {
                self.current_era.as_ref().expect("current_era to be some")
            }
            _ => {
                let current_era = self.fetch_era_file(block_number).await?;
                self.current_era.insert(current_era)
            }
        };

        Ok(processed_era.get_block(block_number))
    }

    async fn fetch_era_file_link(
        &self,
        block_number: u64,
        epoch_index: u64,
    ) -> anyhow::Result<String> {
        match EraType::for_block_number(block_number) {
            EraType::Era1 => {
                let era1_file = self
                    .era1_files
                    .iter()
                    .find(|file| file.contains(&format!("mainnet-{epoch_index:05}-")))
                    .expect("to be able to find era file")
                    .clone();
                Ok(era1_file)
            }
            EraType::Era => {
                let era_files = get_era_file_download_links(&self.http_client).await?;
                let era_file = era_files[&(epoch_index)].clone();
                Ok(era_file)
            }
        }
    }

    async fn fetch_era_file(&mut self, block_number: u64) -> anyhow::Result<ProcessedEra> {
        info!("Fetching the next era file");

        // If next_era is none we must initial EraManager, with the first era file
        let current_era = self.next_era.take();
        let current_era = match current_era {
            Some(block) => block
                .await
                .expect("to be able to download and process era1"),
            None => self.init_current_era(block_number).await?,
        };

        // Download the next era file
        let mut next_epoch_index = current_era.epoch_index + 1;
        // Handle transition from era1 to era
        if next_epoch_index == ERA1_FILE_COUNT as u64 {
            next_epoch_index = FIRST_ERA_EPOCH_WITH_EXECUTION_PAYLOAD;
        }
        let next_block_number = current_era.first_block_number + current_era.len() as u64;
        let next_era_path = self
            .fetch_era_file_link(next_block_number, next_epoch_index)
            .await?;
        let era_type = EraType::for_block_number(next_block_number);
        let http_client = self.http_client.clone();
        let join_handle = tokio::spawn(async move {
            let raw_era = download_raw_era(next_era_path, http_client.clone())
                .await
                .expect("to be able to download raw era");
            match era_type {
                EraType::Era1 => process_era1_file(raw_era, next_epoch_index)
                    .expect("to be able to process era1 file"),
                EraType::Era => process_era_file(raw_era, next_epoch_index)
                    .expect("to be able to process era file"),
            }
        });
        self.next_era = Some(join_handle);

        Ok(current_era)
    }

    /// The first time using era_manager we need to find the current era file we are starting from
    /// If the block is from a era file we will need to binary search to find which era file
    /// contains the block we want
    async fn init_current_era(&mut self, block_number: u64) -> anyhow::Result<ProcessedEra> {
        if let EraType::Era1 = EraType::for_block_number(block_number) {
            let epoch_index = Era1::epoch_number_from_block_number(block_number);
            let era_path = self.fetch_era_file_link(block_number, epoch_index).await?;
            let raw_era1 = download_raw_era(era_path, self.http_client.clone()).await?;

            return process_era1_file(raw_era1, epoch_index);
        }

        EraBinarySearch::find_era_file(self.http_client.clone(), block_number).await
    }
}
