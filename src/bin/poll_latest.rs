use alloy_primitives::B256;
use anyhow::{anyhow, Result};
use clap::Parser;
use ethers::prelude::*;
use ethers_providers::Ws;
use ethportal_api::{
    jsonrpsee::http_client::{HttpClient, HttpClientBuilder},
    types::{content_key::overlay::OverlayContentKey, history::ContentInfo},
    BlockBodyKey, BlockHeaderKey, BlockReceiptsKey, HistoryContentKey, HistoryNetworkApiClient,
};
use std::{
    str::FromStr,
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::time::{sleep, Duration};
use tracing::{debug, info, warn};
use url::Url;

use trin_utils::log::init_tracing_logger;

// tldr;
// to poll latest blocks
// cargo run --bin poll_latest
// to poll latest blocks with exponential backoff and give up trying
// to find a piece of data after 240 seconds:
// cargo run --bin poll_latest -- --timeout 240
// to poll latest blocks, and retry every 3 seconds if the data is not found:
// cargo run --bin poll_latest -- --backoff linear:3

const DEFAULT_NODE_IP: &str = "http://127.0.0.1:8545";

#[derive(Default)]
struct Metrics {
    header: Details,
    block_body: Details,
    receipts: Details,
    // the active audit count measures every individual, active, RFC lookup
    active_audit_count: u32,
    // the complete audit count measures the total number of blocks whose audits have completed
    complete_audit_count: u32,
}

impl Metrics {
    fn display_stats(&self) {
        info!(
            "Audits (active/complete): {:?}/{:?} // Headers {:?}% @ {:.2?} // Bodies {:?}% @ {:.2?} // Receipts {:?}% @ {:.2?}",
            self.active_audit_count,
            self.complete_audit_count,
            (self.header.success_count * 100) / self.header.total_count(),
            self.header.average_time,
            (self.block_body.success_count * 100) / self.block_body.total_count(),
            self.block_body.average_time,
            (self.receipts.success_count * 100) / self.receipts.total_count(),
            self.receipts.average_time);
        debug!(
            "Headers: {:?}/{:?} // Bodies: {:?}/{:?} // Receipts: {:?}/{:?}",
            self.header.success_count,
            self.header.total_count(),
            self.block_body.success_count,
            self.block_body.total_count(),
            self.receipts.success_count,
            self.receipts.total_count(),
        );
    }
}

pub const MAX_TIMEOUT: Duration = Duration::from_secs(240);

#[derive(Debug, Default)]
struct Details {
    success_count: u32,
    failure_count: u32,
    average_time: Duration,
}

impl Details {
    fn total_count(&self) -> u32 {
        self.success_count + self.failure_count
    }

    fn report_success(&mut self, new_time: Duration) {
        self.average_time =
            (self.average_time * self.success_count + new_time) / (self.success_count + 1);
        self.success_count += 1;
    }

    fn report_failure(&mut self) {
        // don't update average time on failure
        self.failure_count += 1;
    }
}

#[tokio::main]
pub async fn main() -> Result<()> {
    init_tracing_logger();
    info!("Running Poll Latest script.");
    let audit_config = AuditConfig::parse();
    let timeout = match audit_config.timeout {
        Some(timeout) => Duration::from_secs(timeout),
        None => MAX_TIMEOUT,
    };
    let infura_project_id = std::env::var("TRIN_INFURA_PROJECT_ID")?;
    let ws = Provider::<Ws>::connect(format!("wss://mainnet.infura.io/ws/v3/{infura_project_id}"))
        .await?;
    let mut stream = ws.subscribe_blocks().await?;
    let client = HttpClientBuilder::default().build(audit_config.node_ip)?;
    let metrics = Arc::new(Mutex::new(Metrics::default()));
    while let Some(block) = stream.next().await {
        let block_hash = block.hash.unwrap();
        info!("Found new block {block_hash}");
        let timestamp = Instant::now();
        let metrics = metrics.clone();
        tokio::spawn(audit_block(
            B256::from_slice(block_hash.as_bytes()),
            timestamp,
            timeout,
            audit_config.backoff,
            metrics,
            client.clone(),
        ));
    }
    Ok(())
}

async fn audit_block(
    hash: B256,
    timestamp: Instant,
    timeout: Duration,
    backoff: Backoff,
    metrics: Arc<Mutex<Metrics>>,
    client: HttpClient,
) -> Result<()> {
    metrics.lock().unwrap().active_audit_count += 3;
    let header_handle = tokio::spawn(audit_content_key(
        HistoryContentKey::BlockHeaderWithProof(BlockHeaderKey { block_hash: hash.0 }),
        timestamp,
        timeout,
        backoff,
        client.clone(),
    ));
    let block_body_handle = tokio::spawn(audit_content_key(
        HistoryContentKey::BlockBody(BlockBodyKey { block_hash: hash.0 }),
        timestamp,
        timeout,
        backoff,
        client.clone(),
    ));
    let receipts_handle = tokio::spawn(audit_content_key(
        HistoryContentKey::BlockReceipts(BlockReceiptsKey { block_hash: hash.0 }),
        timestamp,
        timeout,
        backoff,
        client.clone(),
    ));
    match header_handle.await? {
        Ok(found_time) => {
            let mut metrics = metrics.lock().unwrap();
            metrics.active_audit_count -= 1;
            let time_diff = found_time - timestamp;
            metrics.header.report_success(time_diff);
        }
        Err(_) => {
            let mut metrics = metrics.lock().unwrap();
            metrics.active_audit_count -= 1;
            metrics.header.report_failure();
        }
    }
    match block_body_handle.await? {
        Ok(found_time) => {
            let mut metrics = metrics.lock().unwrap();
            metrics.active_audit_count -= 1;
            let time_diff = found_time - timestamp;
            metrics.block_body.report_success(time_diff);
        }
        Err(_) => {
            let mut metrics = metrics.lock().unwrap();
            metrics.block_body.report_failure();
            metrics.active_audit_count -= 1;
        }
    }
    match receipts_handle.await? {
        Ok(found_time) => {
            let mut metrics = metrics.lock().unwrap();
            metrics.active_audit_count -= 1;
            let time_diff = found_time - timestamp;
            metrics.receipts.report_success(time_diff);
        }
        Err(_) => {
            let mut metrics = metrics.lock().unwrap();
            metrics.receipts.report_failure();
            metrics.active_audit_count -= 1;
        }
    }
    let mut metrics = metrics.lock().unwrap();
    metrics.complete_audit_count += 1;
    metrics.display_stats();
    Ok(())
}

async fn audit_content_key(
    content_key: HistoryContentKey,
    timestamp: Instant,
    timeout: Duration,
    backoff: Backoff,
    client: HttpClient,
) -> anyhow::Result<Instant> {
    let mut attempts = 0;
    while Instant::now() - timestamp < timeout {
        match client.recursive_find_content(content_key.clone()).await? {
            ContentInfo::Content { .. } => {
                return Ok(Instant::now());
            }
            _ => {
                attempts += 1;
                let sleep_time = match backoff {
                    Backoff::Exponential => attempts * 2,
                    Backoff::Linear(delay) => delay,
                };
                sleep(Duration::from_secs(sleep_time)).await;
            }
        }
    }
    let err_msg = format!(
        "Unable to find content_key: {:?} within {timeout:?}",
        content_key.to_hex(),
    );
    warn!("{}", err_msg);
    Err(anyhow!("{}", err_msg))
}

// CLI Parameter Handling
#[derive(Parser, Debug, PartialEq)]
#[command(
    name = "Poll Latest Audit Configuration",
    about = "Script to poll availability of latest data"
)]
pub struct AuditConfig {
    #[arg(long, help = "max timeout in seconds")]
    pub timeout: Option<u64>,

    #[arg(
        long,
        help = "mode for backoff (eg. 'exponential' / 'linear:3' for every 3 seconds)",
        default_value = "exponential"
    )]
    pub backoff: Backoff,

    #[arg(long, help = "ip address of node", default_value = DEFAULT_NODE_IP)]
    pub node_ip: Url,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Backoff {
    Linear(u64),
    Exponential,
}

type ParseError = &'static str;

impl FromStr for Backoff {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "exponential" => Ok(Self::Exponential),
            val => {
                let index = val.find(':').ok_or("Invalid backoff: unable to find `:`")?;
                let (mode, val) = val.split_at(index);
                match mode {
                    "linear" => {
                        let val = val.trim_start_matches(':');
                        let val = val
                            .parse::<u64>()
                            .map_err(|_| "Invalid backoff: unable to parse delay")?;
                        Ok(Self::Linear(val))
                    }
                    _ => Err("Invalid backoff: unsupported mode."),
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_detail() {
        let mut details = Details::default();
        assert_eq!(details.total_count(), 0);
        details.report_success(Duration::from_secs(1));
        assert_eq!(details.total_count(), 1);
        assert_eq!(details.average_time, Duration::from_secs(1));
        details.report_failure();
        assert_eq!(details.total_count(), 2);
        details.report_success(Duration::from_secs(3));
        assert_eq!(details.total_count(), 3);
        assert_eq!(details.average_time, Duration::from_secs(2));
        details.report_failure();
        assert_eq!(details.total_count(), 4);
    }
}
