use std::time::Duration;

use e2store::{
    era1::{BlockTuple, Era1, BLOCK_TUPLE_COUNT},
    utils::get_shuffled_era1_files,
};
use surf::{Client, Config};
use tokio::time::sleep;
use tracing::warn;

pub struct EraManager {
    current_era: Option<Era1>,
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
            http_client,
            era1_files,
        })
    }

    pub async fn get_block_by_number(&mut self, block_number: u64) -> anyhow::Result<&BlockTuple> {
        let epoch_number = Era1::epoch_number_from_block_number(block_number);
        let era1 = match &self.current_era {
            Some(era1) if era1.epoch_number() == epoch_number => {
                self.current_era.as_ref().expect("current_era to be some")
            }
            _ => self
                .current_era
                .insert(self.download_era1_file(epoch_number).await?),
        };
        Ok(&era1.block_tuples[(block_number as usize) % BLOCK_TUPLE_COUNT])
    }

    async fn download_era1_file(&self, epoch_index: u64) -> anyhow::Result<Era1> {
        let era1_path = self
            .era1_files
            .iter()
            .find(|file| file.contains(&format!("mainnet-{epoch_index:05}-")))
            .expect("to be able to find era1 file");

        let mut attempts = 1u32;
        let raw_era1 = loop {
            match self.http_client.get(era1_path.clone()).recv_bytes().await {
                Ok(raw_era1) => break raw_era1,
                Err(err) => {
                    warn!("Failed to download era1 file {attempts} times | Error: {err}");
                    attempts += 1;
                    if attempts > 10 {
                        anyhow::bail!("Failed to download era1 file after {attempts} attempts");
                    }
                    sleep(Duration::from_secs_f64((attempts as f64).log2())).await;
                }
            }
        };
        Era1::deserialize(&raw_era1)
    }
}
