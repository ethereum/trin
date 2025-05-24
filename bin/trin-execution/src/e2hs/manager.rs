use std::collections::HashMap;

use anyhow::{bail, ensure};
use e2store::{e2hs::E2HSMemory, utils::get_e2hs_files};
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client,
};
use tokio::task::JoinHandle;
use tracing::info;

use super::types::{ProcessedBlock, ProcessedE2HS};
use crate::e2hs::utils::{download_raw_e2store_file, process_e2hs_file};

pub struct E2HSManager {
    next_block_number: u64,
    current_e2hs: Option<ProcessedE2HS>,
    next_e2hs: Option<JoinHandle<anyhow::Result<ProcessedE2HS>>>,
    http_client: Client,
    e2hs_files: HashMap<u64, String>,
}

impl E2HSManager {
    pub async fn new(next_block_number: u64) -> anyhow::Result<Self> {
        let http_client = Client::builder()
            .default_headers(HeaderMap::from_iter([(
                CONTENT_TYPE,
                HeaderValue::from_static("application/xml"),
            )]))
            .build()?;
        let e2hs_files = get_e2hs_files(&http_client).await?;

        let mut e2hs_manager = Self {
            next_block_number,
            current_e2hs: None,
            next_e2hs: None,
            http_client,
            e2hs_files,
        };

        // initialize the next e2hs file
        // The first time using e2hs_manager we need to find the current e2hs file we are starting
        // from If the block is from a e2hs file we will need to binary search to find which
        // e2hs file contains the block we want
        let e2hs_files = e2hs_manager.e2hs_files.clone();
        let http_client = e2hs_manager.http_client.clone();
        e2hs_manager.next_e2hs = Some(tokio::spawn(async move {
            Self::fetch_processed_e2hs_by_block_number(e2hs_files, http_client, next_block_number)
                .await
        }));

        Ok(e2hs_manager)
    }

    pub fn next_block_number(&self) -> u64 {
        self.next_block_number
    }

    pub async fn last_fetched_block(&self) -> anyhow::Result<&ProcessedBlock> {
        let Some(current_e2hs) = &self.current_e2hs else {
            panic!("current_e2hs should be initialized in E2HSManager::new");
        };
        ensure!(
            self.next_block_number > 0,
            "next_block_number should be greater than 0"
        );
        Ok(current_e2hs.get_block(self.next_block_number - 1))
    }

    pub async fn get_next_block(&mut self) -> anyhow::Result<&ProcessedBlock> {
        let processed_e2hs = match &self.current_e2hs {
            Some(processed_e2hs) if processed_e2hs.contains_block(self.next_block_number) => {
                self.current_e2hs.as_ref().expect("current_e2hs to be some")
            }
            _ => {
                let current_e2hs = self.get_next_processed_e2hs().await?;
                self.current_e2hs.insert(current_e2hs)
            }
        };
        ensure!(
            processed_e2hs.contains_block(self.next_block_number),
            "Block not found in e2hs file"
        );
        let block = processed_e2hs.get_block(self.next_block_number);
        self.next_block_number += 1;

        Ok(block)
    }

    /// gets the next e2hs file and processes it, and starts fetching the next one in the background
    async fn get_next_processed_e2hs(&mut self) -> anyhow::Result<ProcessedE2HS> {
        info!("Fetching the next e2hs file");

        // Since E2HSManager is initialized in new(), next_e2hs should never be none
        let new_current_e2hs = match self.next_e2hs.take() {
            Some(e2hs_handle) => e2hs_handle.await??,
            None => bail!("The next_e2hs handle can't be None"),
        };

        // Download the next e2hs file
        let next_e2hs_index = new_current_e2hs.index + 1;
        let next_e2hs_path = self.e2hs_files.get(&next_e2hs_index).cloned();
        let http_client = self.http_client.clone();
        let join_handle = tokio::spawn(async move {
            let Some(next_e2hs_path) = next_e2hs_path else {
                bail!("Unable to find next e2hs file's path: index {next_e2hs_index}");
            };
            let raw_e2hs = download_raw_e2store_file(next_e2hs_path, http_client.clone()).await?;
            process_e2hs_file(&raw_e2hs)
        });
        self.next_e2hs = Some(join_handle);

        Ok(new_current_e2hs)
    }

    async fn fetch_processed_e2hs_by_block_number(
        e2hs_files: HashMap<u64, String>,
        http_client: Client,
        block_number: u64,
    ) -> anyhow::Result<ProcessedE2HS> {
        let e2hs_index = E2HSMemory::index_from_block_number(block_number);
        let Some(e2hs_path) = e2hs_files.get(&e2hs_index).cloned() else {
            bail!("Unable to find e2hs file's path during initialization: index {e2hs_index}");
        };
        let raw_e2hs = download_raw_e2store_file(e2hs_path, http_client.clone()).await?;
        process_e2hs_file(&raw_e2hs)
    }
}
