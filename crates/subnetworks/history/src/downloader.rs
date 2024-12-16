/// Downloader struct that load a data CSV file from disk with block number and block hashes
/// and do FIndContent queries in batches to download all the content from the csv file.
/// We don't save the content to disk, we just download it and drop
/// it. But we need to measure the time it takes to download all the content, the number of
/// queries and the number of bytes downloaded, the data ingress rate and the query rate.
use std::fs::File;
use std::{
    io::{self, BufRead},
    path::Path,
};

use anyhow::anyhow;
use ethportal_api::{
    utils::bytes::hex_decode, BlockBodyKey, BlockReceiptsKey, ContentValue, HistoryContentKey,
    HistoryContentValue,
};
use futures::{channel::oneshot, future::join_all};
use portalnet::overlay::command::OverlayCommand;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{error, info, warn};

/// The number of blocks to download in a single batch.
const BATCH_SIZE: usize = 40;
/// The path to the CSV file with block numbers and block hashes.
const CSV_PATH: &str = "ethereum_blocks_14000000_merge.csv";

#[derive(Clone)]
pub struct Downloader {
    pub overlay_tx: UnboundedSender<OverlayCommand<HistoryContentKey>>,
}

impl Downloader {
    pub fn new(overlay_tx: UnboundedSender<OverlayCommand<HistoryContentKey>>) -> Self {
        Self { overlay_tx }
    }

    pub async fn start(self) -> io::Result<()> {
        // set the csv path to a file in the root trin-history directory
        info!("Opening CSV file");
        let csv_path = Path::new(CSV_PATH);
        let file = File::open(csv_path)?;
        let reader = io::BufReader::new(file);
        info!("Reading CSV file");
        let lines: Vec<_> = reader.lines().collect::<Result<_, _>>()?;
        // Create a hash table in memory with all the block hashes and block numbers
        info!("Parsing CSV file");
        // skip the header of the csv file
        let lines = &lines[1..];
        let blocks: Vec<(u64, String)> = lines.iter().map(|line| parse_line(line)).collect();
        info!("Processing blocks");
        let batches = blocks.chunks(BATCH_SIZE);

        for batch in batches {
            self.clone().process_batches(batch.to_vec()).await;
        }

        tokio::signal::ctrl_c()
            .await
            .expect("failed to pause until ctrl-c");

        Ok(())
    }

    async fn process_batches(self, batch: Vec<(u64, String)>) {
        let mut futures = Vec::new();

        for (block_number, block_hash) in batch {
            let block_body_content_key = generate_block_body_content_key(block_hash.clone());
            futures.push(self.find_content(block_body_content_key, block_number));
            info!(
                block_number = block_number,
                "Sent FindContent query for block body"
            );
            let block_receipts_content_key = generate_block_receipts_content_key(block_hash);
            futures.push(self.find_content(block_receipts_content_key, block_number));
            info!(
                block_number = block_number,
                "Sent FindContent query for block receipts"
            );
        }
        join_all(futures).await;
    }

    async fn find_content(
        &self,
        content_key: HistoryContentKey,
        block_number: u64,
    ) -> anyhow::Result<()> {
        let (tx, rx) = oneshot::channel();

        let overlay_command = OverlayCommand::FindContentQuery {
            target: content_key.clone(),
            callback: tx,
            config: Default::default(),
        };

        if let Err(err) = self.overlay_tx.send(overlay_command) {
            warn!(
                error = %err,
                "Error submitting FindContent query to service"
            );
        }
        match rx.await {
            Ok(result) => match result {
                Ok(result) => {
                    HistoryContentValue::decode(&content_key, &result.0)?;
                    info!(block_number = block_number, "Downloaded content for block");
                    Ok(())
                }
                Err(err) => {
                    error!(
                        block_number = block_number,
                        error = %err,
                        "Error in FindContent query"
                    );
                    Err(anyhow!("Error in FindContent query: {:?}", err))
                }
            },
            Err(err) => {
                error!(
                    block_number = block_number,
                    error = %err,
                    "Error receiving FindContent query response"
                );
                Err(err.into())
            }
        }
    }
}

fn parse_line(line: &str) -> (u64, String) {
    let parts: Vec<&str> = line.split(',').collect();
    let block_number = parts[0].parse().expect("Failed to parse block number");
    let block_hash = parts[1].to_string();
    (block_number, block_hash)
}

fn generate_block_body_content_key(block_hash: String) -> HistoryContentKey {
    HistoryContentKey::BlockBody(BlockBodyKey {
        block_hash: <[u8; 32]>::try_from(
            hex_decode(&block_hash).expect("Failed to decode block hash"),
        )
        .expect("Failed to convert block hash to byte array"),
    })
}

fn generate_block_receipts_content_key(block_hash: String) -> HistoryContentKey {
    HistoryContentKey::BlockReceipts(BlockReceiptsKey {
        block_hash: <[u8; 32]>::try_from(
            hex_decode(&block_hash).expect("Failed to decode block hash"),
        )
        .expect("Failed to convert block hash to byte array"),
    })
}
