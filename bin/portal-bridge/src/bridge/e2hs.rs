use std::{
    collections::HashMap,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Instant,
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
    types::{
        execution::header_with_proof::HeaderWithProof, network::Subnetwork, portal_wire::OfferTrace,
    },
    ContentValue, HistoryContentKey, HistoryContentValue, HistoryNetworkApiClient,
    OverlayContentKey,
};
use rand::seq::SliceRandom;
use reqwest::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    Client,
};
use tokio::{
    sync::{oneshot, OwnedSemaphorePermit, Semaphore},
    time::timeout,
};
use tracing::{debug, error, info, warn};
use trin_metrics::bridge::BridgeMetricsReporter;
use trin_validation::header_validator::HeaderValidator;

use super::offer_report::{GlobalOfferReport, OfferReport};
use crate::{
    bridge::constants::SERVE_BLOCK_TIMEOUT, census::Census, types::range::block_range_to_epochs,
};

#[derive(Debug)]
pub struct E2HSBridge {
    portal_client: HttpClient,
    metrics: BridgeMetricsReporter,
    /// Semaphore used to limit the amount of active offer transfers
    /// to make sure we don't overwhelm the trin client
    offer_semaphore: Arc<Semaphore>,
    /// Used to request all interested enrs in the network.
    census: Census,
    /// Global offer report for tallying total performance of history bridge
    global_offer_report: Arc<Mutex<GlobalOfferReport>>,
    header_validator: HeaderValidator,
    block_range: BlockRange,
    random_fill: bool,
    e2hs_files: HashMap<u64, String>,
    http_client: Client,
}

impl E2HSBridge {
    pub async fn new(
        portal_client: HttpClient,
        offer_limit: usize,
        block_range: BlockRange,
        random_fill: bool,
        census: Census,
    ) -> anyhow::Result<Self> {
        let offer_semaphore = Arc::new(Semaphore::new(offer_limit));
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
        let global_offer_report = Arc::new(Mutex::new(GlobalOfferReport::default()));
        Ok(Self {
            portal_client,
            metrics,
            offer_semaphore,
            census,
            global_offer_report,
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
        self.global_offer_report
            .lock()
            .expect("to acquire lock")
            .report();
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
            self.serve_block_tuple(block_number, block_tuple).await;
        }
    }

    async fn serve_block_tuple(&self, block_number: u64, block_tuple: BlockTuple) {
        info!("Serving block tuple for block #{block_number}");
        let block_hash = block_tuple
            .header_with_proof
            .header_with_proof
            .header
            .hash_slow();

        let (is_finished_tx, is_finished_rx) = oneshot::channel();
        self.gossip_header_by_hash(
            block_tuple.header_with_proof.header_with_proof.clone(),
            block_hash,
            is_finished_tx,
        )
        .await;
        self.gossip_header_by_number(
            block_tuple.header_with_proof.header_with_proof,
            block_number,
        )
        .await;

        let census = self.census.clone();
        let portal_client = self.portal_client.clone();
        let metrics = self.metrics.clone();
        let global_offer_report = self.global_offer_report.clone();
        let offer_semaphore = self.offer_semaphore.clone();
        tokio::spawn(async move {
            if let Err(err) = is_finished_rx.await {
                error!("Failed to receive header_by_hash finished response: {err:?}");
                return;
            }

            spawn_offer_tasks(
                HistoryContentKey::new_block_body(block_hash),
                HistoryContentValue::BlockBody(block_tuple.body.body),
                census.clone(),
                portal_client.clone(),
                metrics.clone(),
                global_offer_report.clone(),
                offer_semaphore.clone(),
                None,
            )
            .await;

            spawn_offer_tasks(
                HistoryContentKey::new_block_receipts(block_hash),
                HistoryContentValue::Receipts(block_tuple.receipts.receipts),
                census.clone(),
                portal_client.clone(),
                metrics.clone(),
                global_offer_report.clone(),
                offer_semaphore.clone(),
                None,
            )
            .await;
        });
    }

    async fn gossip_header_by_hash(
        &self,
        header_with_proof: HeaderWithProof,
        block_hash: B256,
        is_finished_tx: oneshot::Sender<()>,
    ) {
        let content_key = HistoryContentKey::new_block_header_by_hash(block_hash);
        let content_value = HistoryContentValue::BlockHeaderWithProof(header_with_proof);
        spawn_offer_tasks(
            content_key,
            content_value,
            self.census.clone(),
            self.portal_client.clone(),
            self.metrics.clone(),
            self.global_offer_report.clone(),
            self.offer_semaphore.clone(),
            Some(is_finished_tx),
        )
        .await;
    }

    async fn gossip_header_by_number(&self, header_with_proof: HeaderWithProof, block_number: u64) {
        let content_key = HistoryContentKey::new_block_header_by_number(block_number);
        let content_value = HistoryContentValue::BlockHeaderWithProof(header_with_proof);
        spawn_offer_tasks(
            content_key,
            content_value,
            self.census.clone(),
            self.portal_client.clone(),
            self.metrics.clone(),
            self.global_offer_report.clone(),
            self.offer_semaphore.clone(),
            None,
        )
        .await;
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

// spawn individual offer tasks of the content key for each interested enr found in Census
#[allow(clippy::too_many_arguments)]
async fn spawn_offer_tasks(
    content_key: HistoryContentKey,
    content_value: HistoryContentValue,
    census: Census,
    portal_client: HttpClient,
    metrics: BridgeMetricsReporter,
    global_offer_report: Arc<Mutex<GlobalOfferReport>>,
    offer_semaphore: Arc<Semaphore>,
    is_finished_tx: Option<oneshot::Sender<()>>,
) {
    let Ok(enrs) = census.select_peers(Subnetwork::History, &content_key.content_id()) else {
        error!("Failed to request enrs for content key, skipping offer: {content_key:?}");
        return;
    };
    let offer_report = Arc::new(Mutex::new(OfferReport::new(
        content_key.clone(),
        enrs.len(),
        is_finished_tx,
    )));
    let encoded_content_value = content_value.encode();
    for enr in enrs.clone() {
        let content_key = content_key.clone();
        let encoded_content_value = encoded_content_value.clone();
        let permit = acquire_offer_permit(offer_semaphore.clone()).await;
        let census = census.clone();
        let portal_client = portal_client.clone();
        let offer_report = offer_report.clone();
        let metrics = metrics.clone();
        let global_offer_report = global_offer_report.clone();
        tokio::spawn(async move {
            let timer = metrics.start_process_timer("spawn_offer_history");

            let start_time = Instant::now();
            let content_value_size = encoded_content_value.len();

            let result = timeout(
                SERVE_BLOCK_TIMEOUT,
                HistoryNetworkApiClient::trace_offer(
                    &portal_client,
                    enr.clone(),
                    content_key.clone(),
                    encoded_content_value,
                ),
            )
            .await;

            let offer_trace = match &result {
                Ok(Ok(result)) => {
                    if matches!(result, &OfferTrace::Failed) {
                        warn!("Internal error offering to: {enr}");
                    }
                    result
                }
                Ok(Err(err)) => {
                    warn!("Error offering to: {enr}, error: {err:?}");
                    &OfferTrace::Failed
                }
                Err(_) => {
                    error!("trace_offer timed out on history {content_key}: indicating a bug is present");
                    &OfferTrace::Failed
                }
            };

            census.record_offer_result(
                Subnetwork::History,
                enr.node_id(),
                content_value_size,
                start_time.elapsed(),
                offer_trace,
            );

            // Update report and metrics
            global_offer_report
                .lock()
                .expect("to acquire lock")
                .update(offer_trace);
            offer_report
                .lock()
                .expect("to acquire lock")
                .update(&enr, offer_trace);

            metrics.report_offer(
                match content_key {
                    HistoryContentKey::BlockHeaderByHash(_) => "header_by_hash",
                    HistoryContentKey::BlockHeaderByNumber(_) => "header_by_number",
                    HistoryContentKey::BlockBody(_) => "block_body",
                    HistoryContentKey::BlockReceipts(_) => "receipts",
                    HistoryContentKey::EphemeralHeadersByFindContent(_) => {
                        "ephemeral_header_by_find_content"
                    }
                    HistoryContentKey::EphemeralHeaderByOffer(_) => "ephemeral_header_by_offer",
                },
                match offer_trace {
                    OfferTrace::Success(_) => "success",
                    OfferTrace::Declined => "declined",
                    OfferTrace::Failed => "failed",
                },
            );

            // Release permit
            drop(permit);
            metrics.stop_process_timer(timer);
        });
    }
}

async fn acquire_offer_permit(offer_semaphore: Arc<Semaphore>) -> OwnedSemaphorePermit {
    offer_semaphore
        .clone()
        .acquire_owned()
        .await
        .expect("to be able to acquire semaphore")
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
