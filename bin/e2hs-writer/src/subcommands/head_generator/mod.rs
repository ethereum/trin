mod e2hs_builder;
mod ethereum_api;
mod s3_bucket;

use std::{
    fs,
    future::Future,
    time::{Duration, Instant},
};

use anyhow::{bail, ensure};
use e2hs_builder::E2HSBuilder;
use e2store::e2hs::BLOCKS_PER_E2HS;
use ethereum_api::first_slot_in_a_period;
use humanize_duration::{prelude::DurationExt, Truncate};
use s3_bucket::S3Bucket;
use tokio::time::sleep;
use tracing::{error, info};
use trin_validation::constants::SLOTS_PER_EPOCH;

use crate::cli::HeadGeneratorConfig;

/// We won't backfill further then 3 months of blocks back
///
/// Since CL clients are only required to serve 4-5 months of history
/// 3 months of backfill is a reasonable limit.
///
/// If we need to generate files older then that, we can always
/// use the single generator to generate them.
const MAX_ALLOWED_BLOCK_BACKFILL_SIZE: u64 = (3 * 30 * 24 * 60 * 60) / 12;

pub struct HeadGenerator {
    s3_bucket: S3Bucket,
    e2hs_builder: E2HSBuilder,
}

impl HeadGenerator {
    pub async fn new(config: HeadGeneratorConfig) -> anyhow::Result<Self> {
        let s3_bucket = S3Bucket::new(config.bucket_name.clone()).await;
        let last_file_name = s3_bucket.last_file_name().await?;
        let last_processed_index = extract_index_from_file_name(&last_file_name)?;

        Ok(Self {
            s3_bucket,
            e2hs_builder: E2HSBuilder::new(config, last_processed_index + 1).await?,
        })
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        info!("Starting E2HS file generation and upload process");
        ensure!(
            self.amount_of_blocks_that_can_be_backfilled().await? < MAX_ALLOWED_BLOCK_BACKFILL_SIZE,
            "Backfill size is too large"
        );

        loop {
            let amount_of_blocks_that_can_be_backfilled =
                self.amount_of_blocks_that_can_be_backfilled().await?;
            if amount_of_blocks_that_can_be_backfilled >= BLOCKS_PER_E2HS as u64 {
                if let Err(err) = run_with_shutdown(self.build_and_upload_e2hs_file()).await {
                    error!("Failed to process E2HS file: {err:?}");
                    break;
                }
            } else {
                let seconds_of_epoch = 12 * SLOTS_PER_EPOCH;
                let sleep_duration = Duration::from_secs(seconds_of_epoch);

                info!(
                    "Not enough provable blocks to build next E2HS file {}/{}. Waiting for next finalized block. Sleeping for {}",
                    amount_of_blocks_that_can_be_backfilled, BLOCKS_PER_E2HS,
                    sleep_duration.human(Truncate::Second),
                );
                sleep(sleep_duration).await;
            }
        }

        Ok(())
    }

    async fn build_and_upload_e2hs_file(&mut self) -> anyhow::Result<()> {
        let start = Instant::now();

        let index = self.e2hs_builder.index;
        let e2hs_path = self.e2hs_builder.build_e2hs_file().await?;
        self.s3_bucket.upload_file_from_path(&e2hs_path).await?;

        info!("Deleting local E2HS file for index {index}");
        fs::remove_file(e2hs_path)?;
        info!("Deleted local E2HS file for index {index}");

        info!(
            "Time taken to finished building and uploading e2hs file {index} {}",
            start.elapsed().human(Truncate::Second)
        );
        Ok(())
    }

    async fn amount_of_blocks_that_can_be_backfilled(&self) -> anyhow::Result<u64> {
        let latest_finalized_slot = self
            .e2hs_builder
            .ethereum_api
            .consensus_api
            .get_beacon_block("finalized")
            .await?
            .message
            .slot;

        let latest_provable_slot = first_slot_in_a_period(latest_finalized_slot);
        let first_execution_number_after_latest_finalized_period = self
            .e2hs_builder
            .ethereum_api
            .fetch_beacon_block_retry(latest_provable_slot)
            .await?
            .message
            .body
            .execution_payload
            .block_number;

        Ok(first_execution_number_after_latest_finalized_period
            - self.e2hs_builder.index * BLOCKS_PER_E2HS as u64)
    }
}

fn extract_index_from_file_name(filename: &str) -> anyhow::Result<u64> {
    let parts: Vec<&str> = filename.split('-').collect();
    ensure!(parts.len() == 3, "Invalid filename format");
    parts[1]
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("Failed to parse index number from filename: {filename}"))
}

pub async fn run_with_shutdown<F>(future: F) -> anyhow::Result<()>
where
    F: Future<Output = anyhow::Result<()>>,
{
    let shutdown_handle = tokio::spawn(async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for Ctrl+C");
        info!("Ctrl+C received. Initiating shutdown...");
    });

    tokio::select! {
        result = future  => {
            info!("Finished all tasks");
            result
        }
        _ = shutdown_handle => {
            bail!("Shutdown signal received during execution.");
        }
    }
}
