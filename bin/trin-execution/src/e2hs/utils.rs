use std::time::Duration;

use alloy::primitives::bytes::Bytes;
use e2store::e2hs::{BlockTuple, E2HSMemory, BLOCKS_PER_E2HS};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use reqwest::Client;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::e2hs::types::{ProcessedBlock, ProcessedE2HS, TransactionsWithSender};

pub fn process_e2hs_file(raw_e2hs: &[u8]) -> anyhow::Result<ProcessedE2HS> {
    let mut blocks = Vec::with_capacity(BLOCKS_PER_E2HS);
    for BlockTuple {
        header_with_proof,
        body,
        ..
    } in E2HSMemory::iter_tuples(raw_e2hs)?
    {
        let transactions_with_recovered_senders = body
            .body
            .transactions
            .par_iter()
            .map(|tx| {
                tx.recover_signer()
                    .map(|sender_address| TransactionsWithSender {
                        transaction: tx.clone(),
                        sender_address,
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        blocks.push(ProcessedBlock {
            header: header_with_proof.header_with_proof.header,
            uncles: Some(body.body.0.ommers),
            withdrawals: None,
            transactions: transactions_with_recovered_senders,
        });
    }

    let index = blocks[0].header.number / BLOCKS_PER_E2HS as u64;
    info!("Done processing e2hs file {index}");

    Ok(ProcessedE2HS { blocks, index })
}

pub async fn download_raw_e2store_file(
    e2store_path: String,
    http_client: Client,
) -> anyhow::Result<Bytes> {
    info!("Downloading e2store file {e2store_path}");
    let mut attempts = 1u32;
    let raw_e2store = loop {
        match http_client.get(&e2store_path).send().await?.bytes().await {
            Ok(raw_e2store) => break raw_e2store,
            Err(err) => {
                warn!("Failed to download e2store file {attempts} times | Error: {err} | Path {e2store_path}");
                if attempts >= 10 {
                    anyhow::bail!("Failed to download e2store file after {attempts} attempts");
                }
                attempts += 1;
                sleep(Duration::from_secs_f64((attempts as f64).log2())).await;
            }
        }
    };

    info!("Done downloading e2store file {e2store_path}");
    Ok(raw_e2store)
}

pub async fn download_and_processed_e2hs_file(
    e2hs_path: String,
    http_client: Client,
) -> anyhow::Result<ProcessedE2HS> {
    process_e2hs_file(&download_raw_e2store_file(e2hs_path, http_client.clone()).await?)
}
