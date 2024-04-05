use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};

use alloy_primitives::B256;
use anyhow::Result;
use clap::Parser;
use ethers::prelude::*;
use ethers_providers::Http;
use rand::seq::SliceRandom;
use tracing::{debug, info, warn};
use url::Url;

use ethportal_api::{
    jsonrpsee::http_client::{HttpClient, HttpClientBuilder},
    BlockBodyKey, BlockHeaderKey, BlockReceiptsKey, HistoryContentKey, HistoryNetworkApiClient,
};
use trin_utils::log::init_tracing_logger;
use trin_validation::constants::MERGE_BLOCK_NUMBER;

// tldr
// to sample 5 blocks from the shanghai fork:
// cargo run --bin sample_range -- --sample-size 5 --range shanghai
// to sample 50 blocks from the since block #100000:
// cargo run --bin sample_range -- --sample-size 50 --range since:100000
// to sample 5 blocks from the latest 500 blocks:
// cargo run --bin sample_range -- --sample-size 5 --range latest:500
// with a custom node ip:
// cargo run --bin sample_range -- --sample-size 1 --range range:1-2 --node-ip http://127.0.0.1:50933

#[derive(Default)]
struct Metrics {
    header: Details,
    block_body: Details,
    receipts: Details,
}

impl Metrics {
    fn display_stats(&self) {
        info!(
            "Headers {:?}% // Bodies {:?}% // Receipts {:?}%",
            self.header.success_rate(),
            self.block_body.success_rate(),
            self.receipts.success_rate(),
        );
        debug!(
            "Headers: {:?}/{:?} // Bodies: {:?}/{:?} // Receipts: {:?}/{:?}",
            self.header.success_count,
            self.header.total_count(),
            self.block_body.success_count,
            self.block_body.total_count(),
            self.receipts.success_count,
            self.receipts.total_count()
        );
    }
}

const FUTURES_BUFFER_SIZE: usize = 8;
const SHANGHAI_BLOCK_NUMBER: u64 = 17034870;
const DEFAULT_NODE_IP: &str = "http://127.0.0.1:8545";

#[derive(Debug, Default)]
struct Details {
    success_count: u32,
    failure_count: u32,
}

impl Details {
    fn total_count(&self) -> u32 {
        self.success_count + self.failure_count
    }

    fn success_rate(&self) -> u32 {
        if self.total_count() == 0 {
            0
        } else {
            (self.success_count * 100) / self.total_count()
        }
    }
}

#[tokio::main]
pub async fn main() -> Result<()> {
    init_tracing_logger();
    let audit_config = SampleConfig::parse();
    info!("Running Sample Range Audit: {:?}", audit_config.range);
    let infura_project_id = std::env::var("TRIN_INFURA_PROJECT_ID")?;
    let provider =
        Provider::<Http>::connect(&format!("https://mainnet.infura.io/v3/{infura_project_id}"))
            .await;
    let client = HttpClientBuilder::default().build(audit_config.node_ip)?;
    let latest_block: u64 = provider.get_block_number().await?.try_into().unwrap();
    let (start, end) = match audit_config.range {
        SampleRange::Shanghai => (SHANGHAI_BLOCK_NUMBER, latest_block),
        SampleRange::FourFours => (0, MERGE_BLOCK_NUMBER),
        SampleRange::Since(since) => (since, latest_block),
        SampleRange::Latest(latest) => (latest_block - latest, latest_block),
        SampleRange::Range(start, end) => (start, end),
    };
    let mut blocks: Vec<u64> = (start..end).collect();
    let sample_size = std::cmp::min(audit_config.sample_size, blocks.len());
    info!("Sampling {sample_size} blocks from range: {start:?} - {end:?}");
    blocks.shuffle(&mut rand::thread_rng());
    let blocks_to_sample = blocks[0..sample_size].to_vec();
    let metrics = Arc::new(Mutex::new(Metrics::default()));
    let futures = futures::stream::iter(blocks_to_sample.into_iter().map(|block_number| {
        let client = client.clone();
        let metrics = metrics.clone();
        let provider = provider.clone();
        async move {
            let block_hash = provider
                .get_block(block_number)
                .await
                .unwrap()
                .unwrap()
                .hash
                .unwrap();
            let _ = audit_block(
                block_number,
                B256::from_slice(block_hash.as_bytes()),
                metrics,
                client,
            )
            .await;
        }
    }))
    .buffer_unordered(FUTURES_BUFFER_SIZE)
    .collect::<Vec<()>>();
    futures.await;
    metrics.lock().unwrap().display_stats();
    Ok(())
}

async fn audit_block(
    block_number: u64,
    hash: B256,
    metrics: Arc<Mutex<Metrics>>,
    client: HttpClient,
) -> anyhow::Result<()> {
    let header_ck = HistoryContentKey::BlockHeaderWithProof(BlockHeaderKey { block_hash: hash.0 });
    let body_ck = HistoryContentKey::BlockBody(BlockBodyKey { block_hash: hash.0 });
    let receipts_ck = HistoryContentKey::BlockReceipts(BlockReceiptsKey { block_hash: hash.0 });
    match client.recursive_find_content(header_ck).await {
        Ok(_) => {
            metrics.lock().unwrap().header.success_count += 1;
        }
        Err(_) => {
            warn!("Header not found for block #{block_number} - {hash:?}");
            metrics.lock().unwrap().header.failure_count += 1;
        }
    }
    match client.recursive_find_content(body_ck).await {
        Ok(_) => {
            metrics.lock().unwrap().block_body.success_count += 1;
        }
        Err(_) => {
            warn!("Body not found for block #{block_number} - {hash:?}");
            metrics.lock().unwrap().block_body.failure_count += 1;
        }
    }
    match client.recursive_find_content(receipts_ck).await {
        Ok(_) => {
            metrics.lock().unwrap().receipts.success_count += 1;
        }
        Err(_) => {
            warn!("Receipts not found for block #{block_number} - {hash:?}");
            metrics.lock().unwrap().receipts.failure_count += 1;
        }
    }
    Ok(())
}

// CLI Parameter Handling
#[derive(Parser, Debug, PartialEq)]
#[command(
    name = "Sample Config",
    about = "Script to sample random blocks from a specified range"
)]
pub struct SampleConfig {
    #[arg(
        long,
        help = "Range to sample blocks from (shanghai, fourfours, since:123, latest:123, range:123-456)"
    )]
    pub range: SampleRange,

    #[arg(long, help = "Number of blocks to sample")]
    pub sample_size: usize,

    #[arg(long, help = "ip address of node", default_value = DEFAULT_NODE_IP)]
    pub node_ip: Url,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SampleRange {
    FourFours,
    Shanghai,
    Since(u64),
    Latest(u64),
    Range(u64, u64),
}

type ParseError = &'static str;

impl FromStr for SampleRange {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "fourfours" => Ok(Self::FourFours),
            "shanghai" => Ok(Self::Shanghai),
            val => {
                let index = val.find(':').ok_or("Invalid sample range, missing `:`")?;
                let (mode, val) = val.split_at(index);
                let val = val.trim_start_matches(':');
                match mode {
                    "since" => {
                        let block = val
                            .parse::<u64>()
                            .map_err(|_| "Invalid sample range: unable to parse block number")?;
                        Ok(Self::Since(block))
                    }
                    "latest" => {
                        let block = val
                            .parse::<u64>()
                            .map_err(|_| "Invalid sample range: unable to parse block number")?;
                        Ok(Self::Latest(block))
                    }
                    "range" => {
                        let index = val.find('-').ok_or("Invalid sample range, missing `-`")?;
                        let (start, end) = val.split_at(index);
                        let start = start.parse::<u64>().map_err(|_| {
                            "Invalid sample range: unable to parse start block number"
                        })?;
                        let end = end.trim_start_matches('-').parse::<u64>().map_err(|_| {
                            "Invalid sample range: unable to parse end block number"
                        })?;
                        Ok(Self::Range(start, end))
                    }
                    _ => Err("Invalid sample range: invalid mode"),
                }
            }
        }
    }
}
