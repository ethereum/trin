pub mod constants;
pub mod e2hs_builder;
pub mod ethereum_api;
pub mod s3_bucket;

use std::{
    fs,
    future::Future,
    time::{Duration, Instant},
};

use anyhow::{bail, ensure};
use constants::MAX_ALLOWED_BLOCK_BACKFILL_SIZE;
use e2hs_builder::E2HSBuilder;
use humanize_duration::{prelude::DurationExt, Truncate};
use s3_bucket::S3Bucket;
use tokio::time;
use tracing::{error, info};
use trin_validation::constants::SLOTS_PER_HISTORICAL_ROOT;

use crate::cli::HeadGeneratorConfig;

pub struct HeadGenerator {
    s3_bucket: S3Bucket,
    e2hs_builder: E2HSBuilder,
    last_processed_period: u64,
}

impl HeadGenerator {
    pub async fn new(config: HeadGeneratorConfig) -> anyhow::Result<Self> {
        let s3_bucket = S3Bucket::new(config.bucket_name.clone()).await;
        let last_file_name = s3_bucket.last_file_name().await?;
        let last_processed_period = extract_period_from_file_name(&last_file_name)?;

        Ok(Self {
            s3_bucket,
            last_processed_period,
            e2hs_builder: E2HSBuilder::new(config, last_processed_period).await?,
        })
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        info!("Starting E2HS file generation and upload process");
        ensure!(
            self.amount_of_blocks_that_can_be_backfilled().await? < MAX_ALLOWED_BLOCK_BACKFILL_SIZE,
            "Backfill size is too large"
        );

        let mut interval = time::interval(Duration::from_secs(5));

        loop {
            interval.tick().await;

            if self.amount_of_blocks_that_can_be_backfilled().await? >= SLOTS_PER_HISTORICAL_ROOT {
                let next_period = self.next_execution_period_to_process();
                if let Err(err) =
                    run_with_shutdown(self.build_and_upload_e2hs_file(next_period)).await
                {
                    error!("Failed to process E2HS file: {err:?}");
                    break;
                }
                self.last_processed_period = next_period;
            }
        }

        Ok(())
    }

    async fn build_and_upload_e2hs_file(&mut self, period: u64) -> anyhow::Result<()> {
        let start = Instant::now();

        let e2hs_path = self.e2hs_builder.build_e2hs_file(period).await?;
        self.s3_bucket.upload_file_from_path(&e2hs_path).await?;

        info!("Deleting local E2HS file for period {period}");
        fs::remove_file(e2hs_path)?;
        info!("Deleted local E2HS file for period {period}");

        info!(
            "Time taken to finished building and uploading e2hs file {period} {}",
            start.elapsed().human(Truncate::Second)
        );
        Ok(())
    }

    async fn amount_of_blocks_that_can_be_backfilled(&self) -> anyhow::Result<u64> {
        Ok(self
            .e2hs_builder
            .ethereum_api
            .latest_provable_execution_number()
            .await?
            - self.next_execution_period_to_process() * SLOTS_PER_HISTORICAL_ROOT)
    }

    fn next_execution_period_to_process(&self) -> u64 {
        self.last_processed_period + 1
    }
}

fn extract_period_from_file_name(filename: &str) -> anyhow::Result<u64> {
    let parts: Vec<&str> = filename.split('-').collect();
    ensure!(parts.len() == 3, "Invalid filename format");
    parts[1]
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("Failed to parse period number from filename: {filename}"))
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
