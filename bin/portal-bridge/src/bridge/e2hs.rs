use std::{
    collections::HashMap,
    str::FromStr,
    sync::{Arc, Mutex},
};

use alloy::primitives::B256;
use anyhow::ensure;
use clap::Parser;
use e2store::{
    e2hs::{BlockTuple, E2HS},
    utils::get_e2hs_files,
};
use ethportal_api::{
    jsonrpsee::http_client::HttpClient,
    types::execution::{
        block_body::BlockBody, header_with_proof::HeaderWithProof, receipts::Receipts,
    },
    HistoryContentKey, HistoryContentValue,
};
use futures::future::join_all;
use rand::seq::SliceRandom;
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client,
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::{sleep, timeout, Duration},
};
use tracing::{debug, error, info, warn};
use trin_metrics::bridge::BridgeMetricsReporter;
use trin_validation::header_validator::HeaderValidator;

use crate::{
    bridge::constants::{HEADER_SATURATION_DELAY, SERVE_BLOCK_TIMEOUT},
    put_content::gossip_history_content,
    stats::{HistoryBlockStats, StatsReporter},
    types::range::block_range_to_epochs,
};

#[derive(Debug)]
pub struct E2HSBridge {
    portal_client: HttpClient,
    metrics: BridgeMetricsReporter,
    gossip_semaphore: Arc<Semaphore>,
    header_validator: HeaderValidator,
    block_range: BlockRange,
    random_fill: bool,
    e2hs_files: HashMap<u64, String>,
    http_client: Client,
}

impl E2HSBridge {
    pub async fn new(
        portal_client: HttpClient,
        gossip_limit: usize,
        block_range: BlockRange,
        random_fill: bool,
    ) -> anyhow::Result<Self> {
        let gossip_semaphore = Arc::new(Semaphore::new(gossip_limit));
        let mode = format!("{}-{}:{}", block_range.start, block_range.end, random_fill);
        let metrics = BridgeMetricsReporter::new("e2hs".to_string(), &mode);
        let header_validator = HeaderValidator::new();
        let http_client = Client::builder()
            .default_headers(HeaderMap::from_iter([(
                CONTENT_TYPE,
                HeaderValue::from_static("application/xml"),
            )]))
            .build()?;
        let e2hs_files = get_e2hs_files(&http_client).await?;
        Ok(Self {
            portal_client,
            metrics,
            gossip_semaphore,
            header_validator,
            block_range,
            random_fill,
            e2hs_files,
            http_client,
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
            Some(_) => info!("Gossiping block range: {block_range:?} from epoch {epoch_index}"),
            None => info!("Gossiping entire epoch {epoch_index}"),
        }
        let Some(e2hs_path) = self.e2hs_files.get(&epoch_index) else {
            panic!("Failed to find e2hs file for epoch {epoch_index}");
        };
        let raw_e2hs = self
            .http_client
            .get(e2hs_path.clone())
            .send()
            .await
            .expect("to be able to send request")
            .bytes()
            .await
            .unwrap_or_else(|err| {
                panic!("unable to read e2hs file at path: {e2hs_path:?} : {err}")
            });
        let mut serve_block_tuple_handles = vec![];
        let block_stream = E2HS::iter_tuples(&raw_e2hs).expect("to be able to iter tuples");
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
                block_number,
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
        block_number: u64,
        block_tuple: BlockTuple,
        permit: OwnedSemaphorePermit,
        metrics: BridgeMetricsReporter,
    ) -> JoinHandle<()> {
        info!("Spawning serve block tuple for block {block_number}");
        let block_stats = Arc::new(Mutex::new(HistoryBlockStats::new(block_number)));
        tokio::spawn(async move {
            let timer = metrics.start_process_timer("spawn_serve_block_tuple");
            match timeout(
                SERVE_BLOCK_TIMEOUT,
                Self::serve_block_tuple(
                    portal_client,
                    block_number,
                    block_tuple,
                    block_stats.clone(),
                    metrics.clone(),
                ),
            )
            .await
            {
                Ok(Ok(())) => {
                    info!("Served block {block_number}");
                }
                Ok(Err(e)) => {
                    error!("Failed to serve block {block_number}: {e:?}");
                }
                Err(_) => {
                    error!("Timed out serving block {block_number}");
                }
            }
            metrics.stop_process_timer(timer);
            drop(permit);
        })
    }

    async fn serve_block_tuple(
        portal_client: HttpClient,
        block_number: u64,
        block_tuple: BlockTuple,
        block_stats: Arc<Mutex<HistoryBlockStats>>,
        metrics: BridgeMetricsReporter,
    ) -> anyhow::Result<()> {
        info!("Serving block tuple for block #{block_number}");
        let block_hash = block_tuple
            .header_with_proof
            .header_with_proof
            .header
            .hash_slow();

        // gossip header by hash
        let timer = metrics.start_process_timer("gossip_header_by_hash");
        match Self::gossip_header_by_hash(
            block_tuple.header_with_proof.header_with_proof.clone(),
            block_hash,
            portal_client.clone(),
            block_stats.clone(),
        )
        .await
        {
            Ok(_) => {
                metrics.report_gossip_success(true, "header_by_hash");
                info!("Gossiped header by hash: {block_number}");
            }
            Err(e) => {
                metrics.report_gossip_success(false, "header_by_hash");
                warn!("Failed to gossip header by hash: {block_number} - {e:?}");
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
            block_number,
            portal_client.clone(),
            block_stats.clone(),
        )
        .await
        {
            Ok(_) => {
                metrics.report_gossip_success(true, "header_by_number");
                info!("Gossiped header by number: {block_number}");
            }
            Err(e) => {
                metrics.report_gossip_success(false, "header_by_number");
                warn!("Failed to gossip header by number: {block_number} - {e:?}");
            }
        }
        metrics.stop_process_timer(timer);

        // gossip body
        let timer = metrics.start_process_timer("gossip_block_body");
        match Self::gossip_body(
            block_tuple.body.body.clone(),
            block_hash,
            portal_client.clone(),
            block_stats.clone(),
        )
        .await
        {
            Ok(_) => {
                metrics.report_gossip_success(true, "block_body");
                info!("Gossiped body: {block_number}");
            }
            Err(e) => {
                metrics.report_gossip_success(false, "block_body");
                warn!("Failed to gossip body: {block_number} - {e:?}");
            }
        }
        metrics.stop_process_timer(timer);

        // gossip receipts
        let timer = metrics.start_process_timer("gossip_receipts");
        match Self::gossip_receipts(
            block_tuple.receipts.receipts.clone(),
            block_hash,
            portal_client.clone(),
            block_stats.clone(),
        )
        .await
        {
            Ok(_) => {
                metrics.report_gossip_success(true, "receipts");
                info!("Gossiped receipts: {block_number}");
            }
            Err(e) => {
                metrics.report_gossip_success(false, "receipts");
                warn!("Failed to gossip receipts: {block_number} - {e:?}");
            }
        }
        metrics.stop_process_timer(timer);
        Ok(())
    }

    async fn gossip_header_by_hash(
        header_with_proof: HeaderWithProof,
        block_hash: B256,
        portal_client: HttpClient,
        block_stats: Arc<Mutex<HistoryBlockStats>>,
    ) -> anyhow::Result<()> {
        let hwp_by_hash_content_key = HistoryContentKey::new_block_header_by_hash(block_hash);
        let hwp_content_value = HistoryContentValue::BlockHeaderWithProof(header_with_proof);
        if let Err(err) = gossip_history_content(
            portal_client,
            hwp_by_hash_content_key.clone(),
            hwp_content_value,
            block_stats,
        )
        .await
        {
            error!("Failed to gossip history content key: {hwp_by_hash_content_key:?} - {err:?}");
        }
        Ok(())
    }

    async fn gossip_header_by_number(
        header_with_proof: HeaderWithProof,
        block_number: u64,
        portal_client: HttpClient,
        block_stats: Arc<Mutex<HistoryBlockStats>>,
    ) -> anyhow::Result<()> {
        let hwp_by_number_content_key = HistoryContentKey::new_block_header_by_number(block_number);
        let hwp_content_value = HistoryContentValue::BlockHeaderWithProof(header_with_proof);
        if let Err(err) = gossip_history_content(
            portal_client,
            hwp_by_number_content_key.clone(),
            hwp_content_value,
            block_stats,
        )
        .await
        {
            error!("Failed to gossip history content key: {hwp_by_number_content_key:?} - {err:?}");
        }
        Ok(())
    }

    async fn gossip_body(
        body: BlockBody,
        block_hash: B256,
        portal_client: HttpClient,
        block_stats: Arc<Mutex<HistoryBlockStats>>,
    ) -> anyhow::Result<()> {
        let body_content_key = HistoryContentKey::new_block_body(block_hash);
        let body_content_value = HistoryContentValue::BlockBody(body);
        if let Err(err) = gossip_history_content(
            portal_client,
            body_content_key.clone(),
            body_content_value,
            block_stats,
        )
        .await
        {
            error!("Failed to gossip history content key: {body_content_key:?} - {err:?}");
        }
        Ok(())
    }

    async fn gossip_receipts(
        receipts: Receipts,
        block_hash: B256,
        portal_client: HttpClient,
        block_stats: Arc<Mutex<HistoryBlockStats>>,
    ) -> anyhow::Result<()> {
        let receipts_content_key = HistoryContentKey::new_block_receipts(block_hash);
        let receipts_content_value = HistoryContentValue::Receipts(receipts);
        if let Err(err) = gossip_history_content(
            portal_client,
            receipts_content_key.clone(),
            receipts_content_value,
            block_stats,
        )
        .await
        {
            error!("Failed to gossip history content key: {receipts_content_key:?} - {err:?}");
        }
        Ok(())
    }

    fn validate_block_tuple(&self, block_tuple: &BlockTuple) -> anyhow::Result<()> {
        let header_with_proof = &block_tuple.header_with_proof.header_with_proof;
        self.header_validator
            .validate_header_with_proof(header_with_proof)?;
        let body = &block_tuple.body.body;
        body.validate_against_header(&header_with_proof.header)?;
        let receipts = &block_tuple.receipts.receipts;
        ensure!(
            receipts.root() == header_with_proof.header.receipts_root,
            "Receipts root mismatch"
        );
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
        ensure!(parts.len() == 2, "Invalid block range format");
        let start = parts[0].parse()?;
        let end = parts[1].parse()?;
        Ok(Self { start, end })
    }
}
