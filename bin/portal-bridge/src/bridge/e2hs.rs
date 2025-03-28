use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};

use alloy::primitives::B256;
use anyhow::{anyhow, ensure};
use clap::Parser;
use e2store::e2hs::{BlockTuple, E2HS};
use ethportal_api::{
    jsonrpsee::http_client::HttpClient,
    types::execution::{
        block_body::BlockBody, header_with_proof::HeaderWithProof, receipts::Receipts,
    },
    HistoryContentKey, HistoryContentValue,
};
use futures::future::join_all;
use rand::seq::SliceRandom;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::{sleep, timeout, Duration},
};
use tracing::{debug, error, info, warn};
use trin_metrics::bridge::BridgeMetricsReporter;
use trin_validation::header_validator::HeaderValidator;

use crate::{
    bridge::history::{HEADER_SATURATION_DELAY, SERVE_BLOCK_TIMEOUT},
    put_content::gossip_history_content,
    stats::{HistoryBlockStats, StatsReporter},
    types::range::block_range_to_epochs,
};

/// Looks for the e2hs file for the given epoch index in a local directory.
/// TODO: this will need to be updated to fetch files from a hosted
/// server once we have a proper source for the files.
fn get_e2hs_file(epoch_index: u64) -> anyhow::Result<String> {
    let e2hs_dir = "./test-e2hs";
    let all_files = std::fs::read_dir(e2hs_dir)?;
    let files: Vec<String> = all_files
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            let path_str = path.to_str()?;
            if path_str.contains(&format!("mainnet-{epoch_index:05}")) {
                Some(path_str.to_string())
            } else {
                None
            }
        })
        .collect();
    let file_count = files.len();
    ensure!(
        file_count == 1,
        "Expected 1 file for epoch {epoch_index}, found {file_count}"
    );
    let file = files.first().expect("to be able to get first file");
    Ok(file.clone())
}

#[derive(Debug)]
pub struct E2HSBridge {
    portal_client: HttpClient,
    metrics: BridgeMetricsReporter,
    gossip_semaphore: Arc<Semaphore>,
    header_validator: HeaderValidator,
    block_range: BlockRange,
    random_fill: bool,
}

impl E2HSBridge {
    pub fn new(
        portal_client: HttpClient,
        gossip_limit: usize,
        block_range: BlockRange,
        random_fill: bool,
    ) -> anyhow::Result<Self> {
        let gossip_semaphore = Arc::new(Semaphore::new(gossip_limit));
        let mode = format!("{}-{}:{}", block_range.start, block_range.end, random_fill);
        let metrics = BridgeMetricsReporter::new("e2hs".to_string(), &mode);
        let header_validator = HeaderValidator::new();
        Ok(Self {
            portal_client,
            metrics,
            gossip_semaphore,
            header_validator,
            block_range,
            random_fill,
        })
    }

    pub async fn launch(&self) {
        info!("Launching E2HS bridge");
        let epochs = block_range_to_epochs(self.block_range.start, self.block_range.end);
        let mut epoch_indexes: Vec<u64> = epochs.keys().cloned().collect();
        if self.random_fill {
            epoch_indexes.shuffle(&mut rand::thread_rng());
        }
        for index in epoch_indexes {
            let block_range = epochs.get(&index).expect("to be able to get block range");
            self.gossip_epoch(index, *block_range).await;
        }
    }

    async fn gossip_epoch(&self, epoch_index: u64, block_range: Option<(u64, u64)>) {
        match block_range {
            Some(_) => {
                info!("Gossiping block range: {block_range:?} from epoch {epoch_index}",);
            }
            None => {
                info!("Gossiping entire epoch {epoch_index}");
            }
        }
        let Ok(e2hs_path) = get_e2hs_file(epoch_index) else {
            panic!("Failed to find e2hs file for epoch {epoch_index}");
        };
        let raw_e2hs = std::fs::read(e2hs_path).expect("Failed to read e2hs file");
        let mut serve_block_tuple_handles = vec![];
        let block_stream = E2HS::iter_tuples(raw_e2hs).expect("to be able to iter tuples");
        for block_tuple in block_stream {
            let block_number = block_tuple
                .header_with_proof
                .header_with_proof
                .header
                .number;
            if let Some((start, end)) = block_range {
                if block_number < start || block_number > end {
                    debug!("Skipping block {block_number} outside of range");
                    continue;
                }
            }
            if let Err(err) = self.validate_block_tuple(&block_tuple) {
                error!("Failed to validate block tuple: {err:?}");
                continue;
            }
            let permit = self
                .gossip_semaphore
                .clone()
                .acquire_owned()
                .await
                .expect("Failed to acquire gossip semaphore");
            self.metrics.report_current_block(block_number as i64);
            let handle = Self::spawn_serve_block_tuple(
                self.portal_client.clone(),
                block_tuple,
                permit,
                self.metrics.clone(),
            );
            serve_block_tuple_handles.push(handle);
        }
        join_all(serve_block_tuple_handles).await;
    }

    fn spawn_serve_block_tuple(
        portal_client: HttpClient,
        block_tuple: BlockTuple,
        permit: OwnedSemaphorePermit,
        metrics: BridgeMetricsReporter,
    ) -> JoinHandle<()> {
        let number = block_tuple
            .header_with_proof
            .header_with_proof
            .header
            .number;
        info!("Spawning serve block tuple for block {number}");
        let block_stats = Arc::new(Mutex::new(HistoryBlockStats::new(number)));
        tokio::spawn(async move {
            let timer = metrics.start_process_timer("spawn_serve_block_tuple");
            match timeout(
                SERVE_BLOCK_TIMEOUT,
                Self::serve_block_tuple(
                    portal_client,
                    block_tuple,
                    block_stats.clone(),
                    metrics.clone(),
                ),
            )
            .await
            {
                Ok(Ok(())) => {
                    info!("Served block {number}");
                }
                Ok(Err(e)) => {
                    error!("Failed to serve block {number}: {e:?}");
                }
                Err(_) => {
                    error!("Timed out serving block {number}");
                }
            }
            metrics.stop_process_timer(timer);
            drop(permit);
        })
    }

    async fn serve_block_tuple(
        portal_client: HttpClient,
        block_tuple: BlockTuple,
        block_stats: Arc<Mutex<HistoryBlockStats>>,
        metrics: BridgeMetricsReporter,
    ) -> anyhow::Result<()> {
        let header_number = block_tuple
            .header_with_proof
            .header_with_proof
            .header
            .number;

        info!("Serving block tuple for block #{header_number}");

        let header_hash = block_tuple
            .header_with_proof
            .header_with_proof
            .header
            .hash_slow();

        // gossip header by hash
        let timer = metrics.start_process_timer("gossip_header_by_hash");
        match Self::gossip_header_by_hash(
            block_tuple.header_with_proof.header_with_proof.clone(),
            portal_client.clone(),
            block_stats.clone(),
        )
        .await
        {
            Ok(_) => {
                metrics.report_gossip_success(true, "header_by_hash");
                info!("Gossiped header by hash: {header_number}");
            }
            Err(e) => {
                metrics.report_gossip_success(false, "header_by_hash");
                warn!("Failed to gossip header by hash: {header_number} - {e:?}");
            }
        }
        metrics.stop_process_timer(timer);
        // Sleep for 10 seconds to allow headers to saturate network,
        // since they must be available for body / receipt validation.
        sleep(Duration::from_secs(HEADER_SATURATION_DELAY)).await;

        // gossip header by number
        let timer = metrics.start_process_timer("gossip_header_by_number");
        match Self::gossip_header_by_number(
            block_tuple.header_with_proof.header_with_proof.clone(),
            portal_client.clone(),
            block_stats.clone(),
        )
        .await
        {
            Ok(_) => {
                metrics.report_gossip_success(true, "header_by_number");
                info!("Gossiped header by number: {header_number}");
            }
            Err(e) => {
                metrics.report_gossip_success(false, "header_by_number");
                warn!("Failed to gossip header by number: {header_number} - {e:?}");
            }
        }
        metrics.stop_process_timer(timer);

        // gossip body
        let timer = metrics.start_process_timer("gossip_block_body");
        match Self::gossip_body(
            block_tuple.body.body.clone(),
            header_hash,
            portal_client.clone(),
            block_stats.clone(),
        )
        .await
        {
            Ok(_) => {
                metrics.report_gossip_success(true, "block_body");
                info!("Gossiped body: {header_number}");
            }
            Err(e) => {
                metrics.report_gossip_success(false, "block_body");
                warn!("Failed to gossip body: {header_number} - {e:?}");
            }
        }
        metrics.stop_process_timer(timer);

        // gossip receipts
        let timer = metrics.start_process_timer("gossip_receipts");
        match Self::gossip_receipts(
            block_tuple.receipts.receipts.clone(),
            header_hash,
            portal_client.clone(),
            block_stats.clone(),
        )
        .await
        {
            Ok(_) => {
                metrics.report_gossip_success(true, "receipts");
                info!("Gossiped receipts: {header_number}");
            }
            Err(e) => {
                metrics.report_gossip_success(false, "receipts");
                warn!("Failed to gossip receipts: {header_number} - {e:?}");
            }
        }
        metrics.stop_process_timer(timer);
        Ok(())
    }

    async fn gossip_header_by_hash(
        header_with_proof: HeaderWithProof,
        portal_client: HttpClient,
        block_stats: Arc<Mutex<HistoryBlockStats>>,
    ) -> anyhow::Result<()> {
        let header_hash = header_with_proof.header.hash_slow();
        let hwp_by_hash_content_key = HistoryContentKey::new_block_header_by_hash(header_hash);
        let hwp_content_value = HistoryContentValue::BlockHeaderWithProof(header_with_proof);
        if let Err(err) = gossip_history_content(
            portal_client,
            hwp_by_hash_content_key.clone(),
            hwp_content_value,
            block_stats,
        )
        .await
        {
            error!(
                "Failed to gossip history content key: {:?} - {:?}",
                hwp_by_hash_content_key, err
            );
        }
        Ok(())
    }

    async fn gossip_header_by_number(
        header_with_proof: HeaderWithProof,
        portal_client: HttpClient,
        block_stats: Arc<Mutex<HistoryBlockStats>>,
    ) -> anyhow::Result<()> {
        let header_number = header_with_proof.header.number;
        let hwp_by_number_content_key =
            HistoryContentKey::new_block_header_by_number(header_number);
        let hwp_content_value = HistoryContentValue::BlockHeaderWithProof(header_with_proof);
        if let Err(err) = gossip_history_content(
            portal_client,
            hwp_by_number_content_key.clone(),
            hwp_content_value,
            block_stats,
        )
        .await
        {
            error!(
                "Failed to gossip history content key: {:?} - {:?}",
                hwp_by_number_content_key, err
            );
        }
        Ok(())
    }

    async fn gossip_body(
        body: BlockBody,
        header_hash: B256,
        portal_client: HttpClient,
        block_stats: Arc<Mutex<HistoryBlockStats>>,
    ) -> anyhow::Result<()> {
        let body_content_key = HistoryContentKey::new_block_body(header_hash);
        let body_content_value = HistoryContentValue::BlockBody(body);
        if let Err(err) = gossip_history_content(
            portal_client,
            body_content_key.clone(),
            body_content_value,
            block_stats,
        )
        .await
        {
            error!(
                "Failed to gossip history content key: {:?} - {:?}",
                body_content_key, err
            );
        }
        Ok(())
    }

    async fn gossip_receipts(
        receipts: Receipts,
        header_hash: B256,
        portal_client: HttpClient,
        block_stats: Arc<Mutex<HistoryBlockStats>>,
    ) -> anyhow::Result<()> {
        let receipts_content_key = HistoryContentKey::new_block_receipts(header_hash);
        let receipts_content_value = HistoryContentValue::Receipts(receipts);
        if let Err(err) = gossip_history_content(
            portal_client,
            receipts_content_key.clone(),
            receipts_content_value,
            block_stats,
        )
        .await
        {
            error!(
                "Failed to gossip history content key: {:?} - {:?}",
                receipts_content_key, err
            );
        }
        Ok(())
    }

    fn validate_block_tuple(&self, block_tuple: &BlockTuple) -> anyhow::Result<()> {
        self.header_validator
            .validate_header_with_proof(&block_tuple.header_with_proof.header_with_proof)?;
        let receipts = &block_tuple.receipts.receipts;
        let receipts_root = receipts.root();
        ensure!(
            receipts_root
                == block_tuple
                    .header_with_proof
                    .header_with_proof
                    .header
                    .receipts_root,
            "Receipts root mismatch"
        );
        let body = &block_tuple.body.body;
        body.validate_against_header(&block_tuple.header_with_proof.header_with_proof.header)?;
        Ok(())
    }
}

/// BlockRange used specifically for the E2HS bridge
#[derive(Parser, Debug, Clone)]
pub struct BlockRange {
    pub start: u64,
    pub end: u64,
}

impl FromStr for BlockRange {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 2 {
            return Err(anyhow!("Invalid block range format"));
        }
        let start = parts[0].parse()?;
        let end = parts[1].parse()?;
        Ok(Self { start, end })
    }
}
