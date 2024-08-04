use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use e2store::{
    era1::{BlockTuple, Era1, BLOCK_TUPLE_COUNT},
    utils::get_shuffled_era1_files,
};
use ethportal_api::{
    types::execution::{header::Header, transaction::Transaction},
    BlockBody,
};
use parking_lot::Mutex;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use revm_primitives::Address;
use surf::{Client, Config};
use tokio::time::sleep;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct TransactionsWithSenders {
    pub transaction: Transaction,
    pub senders_address: Address,
}

#[derive(Debug, Clone)]
pub struct BlockWithRecoveredSenders {
    pub header: Header,
    pub uncles: Option<Vec<Header>>,
    pub transactions: Vec<TransactionsWithSenders>,
}

pub struct EraManager {
    current_era: Option<Vec<BlockWithRecoveredSenders>>,
    next_era: Arc<Mutex<Option<Vec<BlockWithRecoveredSenders>>>>,
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
            next_era: Arc::new(Mutex::new(None)),
            http_client,
            era1_files,
        })
    }

    pub async fn get_block_by_number(
        &mut self,
        block_number: u64,
    ) -> anyhow::Result<&BlockWithRecoveredSenders> {
        let epoch_number = Era1::epoch_number_from_block_number(block_number);
        let blocks = match &self.current_era {
            Some(era1) if era1[0].header.number / (BLOCK_TUPLE_COUNT as u64) == epoch_number => {
                self.current_era.as_ref().expect("current_era to be some")
            }
            _ => self
                .current_era
                .insert(self.download_processed_era(epoch_number).await?),
        };
        Ok(&blocks[(block_number as usize) % BLOCK_TUPLE_COUNT])
    }

    async fn download_processed_era(
        &self,
        epoch_index: u64,
    ) -> anyhow::Result<Vec<BlockWithRecoveredSenders>> {
        info!("Fetching the next era file");
        let start = Instant::now();
        while self.current_era.is_some() && self.next_era.lock().is_none() {
            if start.elapsed() > Duration::from_secs(60 * 20) {
                anyhow::bail!("Failed to download era1 file after 20 minutes seconds");
            }
            sleep(Duration::from_micros(10)).await;
        }

        let current_era = self.next_era.lock().take();
        let current_era = match current_era {
            Some(block) => block,
            None => {
                let era1_path = self
                    .era1_files
                    .iter()
                    .find(|file| file.contains(&format!("mainnet-{epoch_index:05}-",)))
                    .expect("to be able to find era1 file")
                    .clone();
                EraManager::download_and_process_era1(era1_path, self.http_client.clone())
                    .await
                    .expect("to be able to download and process era1")
            }
        };

        let era1_path = self
            .era1_files
            .iter()
            .find(|file| file.contains(&format!("mainnet-{:05}-", epoch_index + 1)))
            .expect("to be able to find era1 file")
            .clone();
        let next_era = self.next_era.clone();
        let http_client = self.http_client.clone();
        tokio::spawn(async move {
            let blocks = EraManager::download_and_process_era1(era1_path, http_client)
                .await
                .expect("to be able to download and process era1");
            *next_era.lock() = Some(blocks);
        });

        Ok(current_era)
    }

    pub async fn download_and_process_era1(
        era_path: String,
        http_client: Client,
    ) -> anyhow::Result<Vec<BlockWithRecoveredSenders>> {
        info!("Downloading era file {era_path}");
        let mut attempts = 1u32;
        let raw_era1 = loop {
            match http_client.get(&era_path).recv_bytes().await {
                Ok(raw_era1) => break raw_era1,
                Err(err) => {
                    warn!("Failed to download era1 file {attempts} times | Error: {err} | Path {era_path}");
                    attempts += 1;
                    if attempts > 10 {
                        anyhow::bail!("Failed to download era1 file after {attempts} attempts");
                    }
                    sleep(Duration::from_secs_f64((attempts as f64).log2())).await;
                }
            }
        };

        info!("Done downloading era file {era_path}, now processing it");

        let mut blocks = Vec::with_capacity(BLOCK_TUPLE_COUNT);
        for BlockTuple { header, body, .. } in Era1::iter_tuples(raw_era1) {
            let transactions_with_recovered_senders = body
                .body
                .transactions()?
                .into_par_iter()
                .map(|tx| TransactionsWithSenders {
                    senders_address: tx.get_transaction_sender_address().expect(
                        "We should always be able to get the sender address of a transaction",
                    ),
                    transaction: tx,
                })
                .collect();
            let uncles = match body.body {
                BlockBody::Legacy(legacy_body) => Some(legacy_body.uncles.clone()),
                _ => None,
            };
            blocks.push(BlockWithRecoveredSenders {
                header: header.header,
                uncles,
                transactions: transactions_with_recovered_senders,
            });
        }

        info!("Done processing era file {era_path}");

        Ok(blocks)
    }
}
